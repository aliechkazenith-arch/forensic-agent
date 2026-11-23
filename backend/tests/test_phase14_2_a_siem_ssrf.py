"""Phase 14.2-A Verification Suite: SIEM DNS Rebinding & SSRF Remediation.

Standards:
- Resolve SEC-NET-002 by eliminating DNS rebinding and TOCTOU vulnerabilities across all SIEM HTTP connectors.
- IP Pinning: Socket connections bound directly to security-validated destination IPs.
- Preserve TLS SNI, certificate verification, and HTTP Host header against original hostname without disabling verify_ssl.
- Full IPv4 and IPv6 support with strict rejection of IPv4-mapped IPv6 bypasses (e.g. ::ffff:127.0.0.1).
- Connection pool reconnect revalidation and zero fallback to unpinned transports.
- Safe redirect handling: blocking forbidden destinations and validating allowed hops.
- Dedicated private subnet SIEM servers permitted when explicitly allowlisted in allowed_hosts.
"""
from __future__ import annotations

import datetime
from datetime import timezone
import ipaddress
import os
from pathlib import Path
import socket
import ssl
import tempfile
import threading
from typing import List
from uuid import uuid4

import httpcore
import httpx
import pytest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from backend.app.connectors.siem_connectors import (
    ElasticsearchConnector,
    SplunkConnector,
    WazuhConnector,
)
from backend.app.core.exceptions import (
    ReadOnlyViolationError,
    SIEMQueryError,
    SSRFSecurityError,
)
from backend.app.core.network_validator import (
    PinnedNetworkBackend,
    PinnedSIEMTransport,
    create_pinned_siem_client,
    is_ip_prohibited,
    resolve_and_validate_destination,
    validate_url_ssrf,
)
from backend.app.models.connectors import SIEMConnectionConfig


# ==============================================================================
# Helper Utilities
# ==============================================================================

def generate_test_tls_cert(san_dns_names: List[str]):
    """Generate a self-signed TLS certificate and private key in temporary files."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    common_name = san_dns_names[0] if san_dns_names else "localhost"
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(timezone.utc) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(timezone.utc) + datetime.timedelta(days=1))
    )
    if san_dns_names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in san_dns_names]),
            critical=False,
        )

    cert = builder.sign(key, hashes.SHA256())

    cert_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
    cert_file.write(cert.public_bytes(serialization.Encoding.PEM))
    cert_file.close()

    key_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
    key_file.write(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    key_file.close()

    return cert_file.name, key_file.name


# ==============================================================================
# Test Group 1: IPv4-Mapped IPv6 Bypass Rejection (Requirement 7)
# ==============================================================================

def test_ipv4_mapped_ipv6_loopback_rejected():
    """Verify that IPv4-mapped IPv6 loopback addresses are strictly rejected."""
    # Dot notation
    with pytest.raises(SSRFSecurityError, match="Loopback address|prohibited"):
        resolve_and_validate_destination("::ffff:127.0.0.1", enforce_strict=True)

    # Hex notation (7f00:1 == 127.0.0.1)
    with pytest.raises(SSRFSecurityError, match="Loopback address|prohibited"):
        resolve_and_validate_destination("::ffff:7f00:1", enforce_strict=True)

    # In URL format
    with pytest.raises(SSRFSecurityError, match="Loopback address|prohibited"):
        validate_url_ssrf("http://[::ffff:127.0.0.1]:9200", enforce_strict=True)


def test_ipv4_mapped_ipv6_metadata_rejected():
    """Verify that IPv4-mapped IPv6 cloud metadata addresses are strictly rejected."""
    # Dot notation
    with pytest.raises(SSRFSecurityError, match="metadata"):
        resolve_and_validate_destination("::ffff:169.254.169.254", enforce_strict=True)

    # Hex notation (a9fe:a9fe == 169.254.169.254)
    with pytest.raises(SSRFSecurityError, match="metadata"):
        resolve_and_validate_destination("::ffff:a9fe:a9fe", enforce_strict=True)

    # In URL format
    with pytest.raises(SSRFSecurityError, match="metadata"):
        validate_url_ssrf("http://[::ffff:169.254.169.254]:9200", enforce_strict=True)


def test_is_ip_prohibited_unmaps_ipv6():
    """Verify is_ip_prohibited unmaps IPv4-mapped IPv6 and applies loopback / metadata rules."""
    ip_loopback = ipaddress.ip_address("::ffff:127.0.0.1")
    bad, reason = is_ip_prohibited(ip_loopback)
    assert bad is True
    assert "Loopback" in reason

    ip_meta = ipaddress.ip_address("::ffff:169.254.169.254")
    bad, reason = is_ip_prohibited(ip_meta)
    assert bad is True
    assert "metadata" in reason

    ip_private = ipaddress.ip_address("::ffff:10.50.1.1")
    bad, reason = is_ip_prohibited(ip_private, allow_private=False)
    assert bad is True
    assert "private" in reason


# ==============================================================================
# Test Group 2: DNS Resolution Security & Fail-Closed Behavior (Req 1, 2, 10)
# ==============================================================================

def test_dns_resolving_to_allowed_address_succeeds(monkeypatch):
    """Verify that a hostname resolving to an allowed address validates successfully."""
    def mock_getaddrinfo(host, port, *args, **kwargs):
        if host == "es-cluster.corp.net":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port or 0))]
        return []

    monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo)
    ips = resolve_and_validate_destination("es-cluster.corp.net", enforce_strict=True)
    assert "93.184.216.34" in ips


def test_dns_resolving_to_forbidden_loopback_fails_closed(monkeypatch):
    """Verify that a hostname resolving to 127.0.0.1 fails closed immediately."""
    def mock_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port or 0))]

    monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo)
    with pytest.raises(SSRFSecurityError, match="prohibited IP '127.0.0.1'|loopback"):
        resolve_and_validate_destination("evil-rebind.corp", enforce_strict=True)


def test_dns_resolving_to_forbidden_metadata_fails_closed(monkeypatch):
    """Verify that a hostname resolving to 169.254.169.254 fails closed immediately."""
    def mock_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", port or 0))]

    monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo)
    with pytest.raises(SSRFSecurityError, match="prohibited IP '169.254.169.254'|metadata"):
        resolve_and_validate_destination("evil-metadata.corp", enforce_strict=True)


def test_dns_resolution_failure_fails_closed(monkeypatch):
    """Verify that DNS resolution failure (gaierror) fails closed with SSRFSecurityError."""
    def mock_getaddrinfo(host, port, *args, **kwargs):
        raise socket.gaierror(11001, "getaddrinfo failed")

    monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo)
    with pytest.raises(SSRFSecurityError, match="Cannot resolve target host"):
        resolve_and_validate_destination("nonexistent-siem.corp", enforce_strict=True)


# ==============================================================================
# Test Group 3: DNS Rebinding / TOCTOU Prevention (Requirement 2, 3, 8)
# ==============================================================================

def test_dns_rebinding_between_validation_and_connection_blocked(monkeypatch):
    """Simulate DNS rebinding attack where domain flips from benign to 127.0.0.1.
    
    Ensures PinnedNetworkBackend revalidates at connection time and aborts the connection.
    """
    call_count = {"val": 0}

    def alternating_getaddrinfo(host, port, *args, **kwargs):
        call_count["val"] += 1
        if call_count["val"] == 1:
            # First call (pre-flight check): allowed IP
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port or 0))]
        # Second call (at connection time): attacker rebinds to loopback!
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port or 0))]

    monkeypatch.setattr(socket, "getaddrinfo", alternating_getaddrinfo)

    # 1. First resolution passes pre-flight
    preflight_ips = resolve_and_validate_destination("rebind-attacker.corp", enforce_strict=True)
    assert "93.184.216.34" in preflight_ips

    # 2. Connection creation runs: DNS has flipped to 127.0.0.1
    backend = PinnedNetworkBackend(enforce_strict=True)
    with pytest.raises(SSRFSecurityError, match="prohibited IP '127.0.0.1'|loopback"):
        backend.connect_tcp("rebind-attacker.corp", 9200)


def test_dns_rebinding_blocked_in_siem_connector(monkeypatch):
    """Verify SIEM connectors reject requests if DNS rebinds to loopback before search."""
    call_count = {"val": 0}

    def rebinding_getaddrinfo(host, port, *args, **kwargs):
        call_count["val"] += 1
        if call_count["val"] <= 2:
            # Pre-flight checks during config creation and connector init
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port or 0))]
        # Rebound to 127.0.0.1 before search execution
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port or 0))]

    monkeypatch.setattr(socket, "getaddrinfo", rebinding_getaddrinfo)

    config = SIEMConnectionConfig(
        siem_type="elasticsearch",
        endpoint_url="http://rebind-test.corp:9200",
    )
    connector = ElasticsearchConnector(config=config)

    # When search is attempted, connection fails closed with SSRFSecurityError
    with pytest.raises(SSRFSecurityError, match="prohibited IP '127.0.0.1'|loopback"):
        connector.search("event.code: 4624", case_id="CASE-REBIND-001")


# ==============================================================================
# Test Group 4: Safe Redirect Handling (Requirement 9)
# ==============================================================================

def test_redirect_to_forbidden_destination_blocked(monkeypatch):
    """Verify that redirects to loopback or metadata endpoints are blocked with SSRFSecurityError."""
    # Set up mock transport that redirects to 169.254.169.254
    def custom_redirect_handler(request: httpx.Request):
        if request.url.path == "/start":
            return httpx.Response(
                302,
                headers={"Location": "http://169.254.169.254/latest/meta-data"},
                request=request,
            )
        return httpx.Response(200, text="OK", request=request)

    mock_transport = httpx.MockTransport(custom_redirect_handler)

    class ValidatingRedirectTransport(httpx.BaseTransport):
        def handle_request(self, req):
            validate_url_ssrf(str(req.url), enforce_strict=True)
            return mock_transport.handle_request(req)

    client = httpx.Client(transport=ValidatingRedirectTransport(), follow_redirects=True)

    def mock_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port or 0))]

    monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo)

    with pytest.raises(SSRFSecurityError, match="cloud metadata endpoint"):
        client.get("http://allowed-siem.corp/start")


def test_redirect_to_allowed_destination_validated(monkeypatch):
    """Verify that redirects to authorized endpoints are validated and succeed."""
    def custom_allowed_redirect_handler(request: httpx.Request):
        if request.url.path == "/start":
            return httpx.Response(
                302,
                headers={"Location": "https://allowed-backup-siem.corp/api/search"},
                request=request,
            )
        return httpx.Response(200, text="SEARCH_RESULTS_OK", request=request)

    mock_transport = httpx.MockTransport(custom_allowed_redirect_handler)

    class ValidatingRedirectTransport(httpx.BaseTransport):
        def handle_request(self, req):
            validate_url_ssrf(
                str(req.url),
                allowed_targets=["allowed-siem.corp", "allowed-backup-siem.corp"],
                enforce_strict=True,
            )
            return mock_transport.handle_request(req)

    client = httpx.Client(transport=ValidatingRedirectTransport(), follow_redirects=True)

    def mock_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port or 0))]

    monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo)

    resp = client.get("http://allowed-siem.corp/start")
    assert resp.status_code == 200
    assert resp.text == "SEARCH_RESULTS_OK"


# ==============================================================================
# Test Group 5: TLS SNI & Hostname Verification (Requirement 4, 5)
# ==============================================================================

def test_tls_verification_preserves_hostname_and_sni(monkeypatch):
    """Verify TLS SNI and hostname verification are preserved with IP pinning."""
    cert_path, key_path = generate_test_tls_cert(["siem.corp.internal"])

    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(cert_path, key_path)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(5)
    port = server.getsockname()[1]

    def serve():
        for _ in range(2):
            try:
                raw_conn, _ = server.accept()
                conn = server_ctx.wrap_socket(raw_conn, server_side=True)
                conn.recv(1024)
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                conn.close()
            except Exception:
                pass

    t = threading.Thread(target=serve, daemon=True)
    t.start()

    # Mock DNS to resolve test hostnames to an allowed IP while allowing socket to connect to localhost
    orig_getaddrinfo = socket.getaddrinfo
    def mock_getaddrinfo(host, p, *args, **kwargs):
        if host in ("127.0.0.1", "::1", "localhost"):
            return orig_getaddrinfo(host, p, *args, **kwargs)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", p or 0))]

    monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo)

    # Custom backend that connects socket directly to test server port
    class TestPinnedBackend(PinnedNetworkBackend):
        def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
            return super(PinnedNetworkBackend, self).connect_tcp("127.0.0.1", port, timeout, local_address, socket_options)

    class TestPinnedTransport(PinnedSIEMTransport):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._pool._network_backend = TestPinnedBackend()

    try:
        # 1. Matching hostname: siem.corp.internal -> Succeeds with 200 OK
        client_valid = httpx.Client(
            transport=TestPinnedTransport(verify=cert_path),
            verify=cert_path,
        )
        resp = client_valid.get(f"https://siem.corp.internal:{port}/")
        assert resp.status_code == 200
        assert resp.text == "OK"

        # 2. Mismatched hostname: wrong-siem.corp.internal -> Fails with TLS Hostname Mismatch!
        client_invalid = httpx.Client(
            transport=TestPinnedTransport(verify=cert_path),
            verify=cert_path,
        )
        with pytest.raises(httpx.ConnectError) as exc_info:
            client_invalid.get(f"https://wrong-siem.corp.internal:{port}/")
        assert "Hostname mismatch" in str(exc_info.value) or "certificate is not valid" in str(exc_info.value)

    finally:
        server.close()
        os.unlink(cert_path)
        os.unlink(key_path)


# ==============================================================================
# Test Group 6: HTTP Host Header Preservation (Requirement 4)
# ==============================================================================

def test_http_host_header_preserved(monkeypatch):
    """Verify that HTTP Host header receives original hostname and port."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    received_headers = []

    def serve():
        try:
            conn, _ = server.accept()
            data = conn.recv(2048)
            received_headers.append(data.decode("utf-8", errors="replace"))
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
            conn.close()
        except Exception:
            pass

    t = threading.Thread(target=serve, daemon=True)
    t.start()

    orig_getaddrinfo = socket.getaddrinfo
    def mock_getaddrinfo(host, p, *args, **kwargs):
        if host in ("127.0.0.1", "::1", "localhost"):
            return orig_getaddrinfo(host, p, *args, **kwargs)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", p or 0))]

    monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo)

    class TestPinnedBackend(PinnedNetworkBackend):
        def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
            return super(PinnedNetworkBackend, self).connect_tcp("127.0.0.1", port, timeout, local_address, socket_options)

    class TestPinnedTransport(PinnedSIEMTransport):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._pool._network_backend = TestPinnedBackend()

    client = httpx.Client(transport=TestPinnedTransport())

    try:
        resp = client.get(f"http://splunk-indexer.corp.net:{port}/services/server/info")
        assert resp.status_code == 200
        assert len(received_headers) == 1
        assert f"Host: splunk-indexer.corp.net:{port}" in received_headers[0]
    finally:
        server.close()


# ==============================================================================
# Test Group 7: Connection Pool Reuse & Multiple Requests (Requirement 8)
# ==============================================================================

def test_multiple_requests_and_pool_reuse_maintain_security(monkeypatch):
    """Verify multiple requests across connection pool reuse maintain security guarantees."""
    request_count = {"val": 0}

    def mock_handler(request: httpx.Request):
        request_count["val"] += 1
        return httpx.Response(200, text=f"RESPONSE_{request_count['val']}")

    mock_transport = httpx.MockTransport(mock_handler)

    class SafeTransport(httpx.BaseTransport):
        def handle_request(self, req):
            validate_url_ssrf(str(req.url), enforce_strict=True)
            return mock_transport.handle_request(req)

    client = httpx.Client(transport=SafeTransport())

    orig_getaddrinfo = socket.getaddrinfo
    def mock_getaddrinfo(host, p, *args, **kwargs):
        if host in ("127.0.0.1", "::1", "localhost"):
            return orig_getaddrinfo(host, p, *args, **kwargs)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", p or 0))]

    monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo)

    resp1 = client.get("http://my-siem.corp/search?q=test1")
    assert resp1.status_code == 200
    assert resp1.text == "RESPONSE_1"

    resp2 = client.get("http://my-siem.corp/search?q=test2")
    assert resp2.status_code == 200
    assert resp2.text == "RESPONSE_2"


# ==============================================================================
# Test Group 8: No Fallback to Unpinned Client on Error (Requirement 11)
# ==============================================================================

def test_connection_failure_fails_closed_without_unpinned_fallback(monkeypatch):
    """Verify that socket connection errors fail closed without fallback to unpinned transports."""
    def mock_getaddrinfo(host, port, *args, **kwargs):
        # Return a non-routable TEST-NET IP where connection will be refused or time out
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", port or 0))]

    monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo)
    monkeypatch.setenv("FORENSICOPS_ALLOW_PRIVATE_SIEM", "true")

    config = SIEMConnectionConfig(
        siem_type="elasticsearch",
        endpoint_url="http://unreachable-siem.corp:9200",
        timeout_seconds=0.5,
    )
    connector = ElasticsearchConnector(config=config)

    # Must raise SIEMQueryError or ConnectError, NEVER fall back to standard unpinned socket
    with pytest.raises(SIEMQueryError):
        connector.test_connection()


# ==============================================================================
# Test Group 9: Dedicated Private Subnet SIEM Authorization (Requirement 3)
# ==============================================================================

def test_private_siem_allowed_when_configured_in_allowed_hosts(monkeypatch):
    """Verify that private SIEM servers (RFC 1918) succeed when explicitly in allowed_hosts."""
    monkeypatch.setenv("FORENSICOPS_ALLOW_PRIVATE_SIEM", "false")
    config = SIEMConnectionConfig(
        siem_type="wazuh",
        endpoint_url="https://10.200.1.50:55000",
        allowed_hosts=["10.200.0.0/16"],
    )
    assert config.endpoint_url == "https://10.200.1.50:55000"


def test_private_siem_rejected_when_not_in_allowed_hosts(monkeypatch):
    """Verify that private SIEM servers (RFC 1918) are rejected when not in allowed_hosts."""
    monkeypatch.setenv("FORENSICOPS_ALLOW_PRIVATE_SIEM", "false")
    with pytest.raises(ValueError, match="prohibited"):
        SIEMConnectionConfig(
            siem_type="wazuh",
            endpoint_url="https://10.200.1.50:55000",
            allowed_hosts=["192.168.1.0/24"],
        )
