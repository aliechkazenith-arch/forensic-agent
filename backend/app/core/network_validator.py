"""Network and SSRF Security Validator for Online Collectors and SIEM Connectors.

Standards:
- Non-Negotiable SSRF Defense (Localhost, 169.254.169.254 metadata, unapproved RFC 1918).
- DNS Rebinding Protection via pre-flight resolution and IP validation.
- Target Allowlist and Case Scope Enforcement.
- Zero Credential Leakage in Logging or Exceptions.
"""
from __future__ import annotations

import ipaddress
import os
import re
import socket
import ssl
import urllib.parse
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, Union

import httpcore
import httpcore._backends.sync
import httpx

from backend.app.core.exceptions import SSRFSecurityError

# Strictly prohibited hostnames regardless of DNS
STRICTLY_PROHIBITED_HOSTNAMES: Set[str] = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "metadata.google.internal",
    "instance-data",
    "metadata.azure.internal",
    "169.254.169.254",
    "127.0.0.1",
    "::1",
    "::ffff:127.0.0.1",
    "::ffff:169.254.169.254",
}

# Cloud metadata and link-local networks
METADATA_NETWORKS = [
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
]

# RFC 1918 and RFC 4193 private networks
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
]

CREDENTIAL_REPLACEMENTS = [
    (re.compile(r"Bearer\s+[a-zA-Z0-9_\-\.=]+", re.IGNORECASE), "Bearer ******"),
    (re.compile(r"ApiKey\s+[a-zA-Z0-9_\-\.=]+", re.IGNORECASE), "ApiKey ******"),
    (re.compile(r"Splunk\s+[a-zA-Z0-9_\-\.=]+", re.IGNORECASE), "Splunk ******"),
    (re.compile(r"(authorization)\s*[:=]\s*['\"]?(?:Bearer\s+|ApiKey\s+|Splunk\s+)?[^'\"&\r\n,]+['\"]?", re.IGNORECASE), r"\1=******"),
    (re.compile(r"(password|passwd|token|api_key|apikey|secret)\s*[:=]\s*['\"]?[^'\"&\s,]+['\"]?", re.IGNORECASE), r"\1=******"),
]

CREDENTIAL_PATTERNS = [item[0] for item in CREDENTIAL_REPLACEMENTS]


def is_ip_prohibited(
    ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address],
    allow_private: bool = False,
    allowed_cidrs: Optional[List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]] = None,
) -> Tuple[bool, str]:
    """Evaluate whether an IP address violates SSRF boundaries.
    
    Returns (is_prohibited, reason).
    """
    # SEC-NET-002: Unmap IPv4-mapped IPv6 address (e.g. ::ffff:127.0.0.1 or ::ffff:169.254.169.254)
    # so that underlying IPv4 address is strictly evaluated against loopback and metadata boundaries.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped

    # 1. Loopback addresses are NEVER permitted
    if ip.is_loopback:
        return True, f"Loopback address '{ip}' is strictly prohibited."

    # 2. Cloud metadata and link-local addresses are NEVER permitted
    for meta_net in METADATA_NETWORKS:
        if ip in meta_net:
            return True, f"Cloud metadata / link-local address '{ip}' is strictly prohibited."

    # 3. Unspecified, multicast, and reserved addresses are NEVER permitted
    if ip.is_unspecified or ip.is_multicast or ip.is_reserved:
        return True, f"Unspecified, multicast or reserved address '{ip}' is strictly prohibited."

    # 4. Check RFC 1918 / RFC 4193 private address space
    if ip.is_private:
        if allow_private:
            return False, ""
        if allowed_cidrs:
            for cidr in allowed_cidrs:
                if ip in cidr:
                    return False, ""
            return True, f"Private address '{ip}' is not in authorized CIDR allowlist."
        return True, f"Unapproved private network address '{ip}' is prohibited without explicit authorization."

    return False, ""


def parse_target_allowlist(
    allowed_targets: Optional[List[str]] = None,
) -> Tuple[Set[str], List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]]:
    """Parse a list of hostnames, IP addresses, and CIDRs into matching structures."""
    hostnames: Set[str] = set()
    cidrs: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []

    if not allowed_targets:
        # Check global environment variable FORENSICOPS_ALLOWED_TARGETS
        env_val = os.getenv("FORENSICOPS_ALLOWED_TARGETS")
        if env_val:
            raw_list = [t.strip() for t in env_val.split(",") if t.strip()]
        else:
            raw_list = []
    else:
        raw_list = [t.strip() for t in allowed_targets if t.strip()]

    for target in raw_list:
        target_lower = target.lower()
        # Try CIDR
        if "/" in target:
            try:
                cidrs.append(ipaddress.ip_network(target, strict=False))
                continue
            except ValueError:
                pass
        # Try single IP
        try:
            ip = ipaddress.ip_address(target)
            cidrs.append(ipaddress.ip_network(f"{ip}/32" if ip.version == 4 else f"{ip}/128"))
            continue
        except ValueError:
            pass
        # Hostname
        hostnames.add(target_lower)

    return hostnames, cidrs


def resolve_and_validate_destination(
    host_or_ip: str,
    allow_private: bool = False,
    allowed_targets: Optional[List[str]] = None,
    enforce_strict: bool = False,
) -> List[str]:
    """Resolve destination hostname and ensure all resulting IP addresses are safe.
    
    Protects against SSRF, internal metadata queries, and DNS rebinding attacks.
    Returns list of validated IP address strings.
    """
    clean_host = host_or_ip.strip().strip("[]")
    if not clean_host:
        raise SSRFSecurityError("Target host cannot be empty.")

    lower_host = clean_host.lower()

    # Cloud metadata is NEVER permitted under any circumstances
    if lower_host in ("169.254.169.254", "metadata.google.internal", "instance-data", "metadata.azure.internal"):
        raise SSRFSecurityError(
            f"SSRF Protection: Access to cloud metadata endpoint '{clean_host}' is strictly prohibited."
        )

    # Global dev/test overrides for private network testing
    allow_private_targets = os.getenv("FORENSICOPS_ALLOW_PRIVATE_TARGETS", "false").lower() in ("true", "1")
    allow_private_siem = os.getenv("FORENSICOPS_ALLOW_PRIVATE_SIEM", "false").lower() in ("true", "1")
    env_allow_dev = not enforce_strict and (allow_private_targets or allow_private_siem)

    # SEC-NET-001: Private targets override must NEVER allow loopback / localhost
    if not allow_private_siem and lower_host in STRICTLY_PROHIBITED_HOSTNAMES:
        raise SSRFSecurityError(
            f"SSRF Protection: Access to restricted host '{clean_host}' is strictly prohibited."
        )

    allowed_hosts, allowed_cidrs = parse_target_allowlist(allowed_targets)

    # Check if literal hostname is explicitly allowed
    hostname_whitelisted = lower_host in allowed_hosts

    # Resolve all addresses (IPv4 and IPv6)
    resolved_ips: List[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]] = []
    try:
        # Check direct IP string first
        direct_ip = ipaddress.ip_address(clean_host)
        resolved_ips.append(direct_ip)
    except ValueError:
        # Perform DNS resolution
        try:
            addr_info = socket.getaddrinfo(clean_host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            for item in addr_info:
                sockaddr = item[4]
                ip_str = sockaddr[0]
                try:
                    resolved_ips.append(ipaddress.ip_address(ip_str))
                except ValueError:
                    pass
        except socket.gaierror as e:
            # If hostname cannot be resolved, check if whitelisted or raise
            if not hostname_whitelisted and not env_allow_dev:
                raise SSRFSecurityError(f"Cannot resolve target host '{clean_host}': {e}") from e
            return [clean_host]

    if not resolved_ips and not hostname_whitelisted and not env_allow_dev:
        raise SSRFSecurityError(f"No valid IP addresses resolved for target host '{clean_host}'.")

    # Validate each resolved IP address
    for ip in resolved_ips:
        eval_ip = ip.ipv4_mapped if (isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped) else ip
        if not env_allow_dev:
            is_bad, reason = is_ip_prohibited(
                eval_ip,
                allow_private=allow_private or hostname_whitelisted,
                allowed_cidrs=allowed_cidrs,
            )
            if is_bad:
                raise SSRFSecurityError(
                    f"SSRF Protection: Destination '{clean_host}' resolves to prohibited IP '{ip}': {reason}"
                )
        else:
            # SEC-NET-001 / SEC-NET-002: Loopback and metadata are NEVER permitted under any circumstances
            if eval_ip.is_loopback:
                raise SSRFSecurityError(
                    f"SSRF Protection: Destination '{clean_host}' resolves to prohibited loopback IP '{eval_ip}'."
                )
            for meta_net in METADATA_NETWORKS:
                if eval_ip in meta_net:
                    raise SSRFSecurityError(
                        f"SSRF Protection: Destination '{clean_host}' resolves to metadata IP '{eval_ip}'."
                    )

    return [str(ip.ipv4_mapped if (isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped) else ip) for ip in resolved_ips]


def validate_url_ssrf(
    url: str,
    allow_private: bool = False,
    allowed_targets: Optional[List[str]] = None,
    enforce_strict: bool = False,
) -> str:
    """Validate that a URL does not target loopback, metadata, or unauthorized networks."""
    if not url:
        raise SSRFSecurityError("URL cannot be empty.")

    parsed = urllib.parse.urlparse(url)
    if parsed.scheme.lower() not in ("http", "https"):
        raise SSRFSecurityError(
            f"Invalid URL scheme '{parsed.scheme}'. Only HTTP and HTTPS are permitted."
        )

    # Reject embedded userinfo (user:pass@host)
    if parsed.username or parsed.password:
        raise SSRFSecurityError(
            "URLs with embedded credentials (user:pass@host) are prohibited for security."
        )

    hostname = parsed.hostname
    if not hostname:
        raise SSRFSecurityError(f"Invalid URL '{url}': missing hostname.")

    resolve_and_validate_destination(
        hostname,
        allow_private=allow_private,
        allowed_targets=allowed_targets,
        enforce_strict=enforce_strict,
    )
    return url


def sanitize_credentials(text: str, custom_secrets: Optional[List[str]] = None) -> str:
    """Scrub sensitive credentials, passwords, tokens and keys from log strings and errors."""
    if not text:
        return ""

    sanitized = text

    # Redact explicit custom secrets
    if custom_secrets:
        for s in custom_secrets:
            if s and len(s) >= 3:
                sanitized = sanitized.replace(s, "******")

    # Redact regex patterns
    for pat, repl in CREDENTIAL_REPLACEMENTS:
        sanitized = pat.sub(repl, sanitized)

    return sanitized


class PinnedNetworkBackend(httpcore.SyncBackend):
    """Network backend that binds TCP connections directly to security-validated IP addresses.
    
    Eliminates DNS rebinding and TOCTOU vulnerabilities (SEC-NET-002) by resolving and
    validating the destination host at connection time and passing raw IP literals
    to socket.create_connection.
    """

    def __init__(
        self,
        allow_private: bool = False,
        allowed_targets: Optional[List[str]] = None,
        enforce_strict: bool = False,
    ):
        super().__init__()
        self.allow_private = allow_private
        self.allowed_targets = allowed_targets
        self.enforce_strict = enforce_strict

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.NetworkStream:
        if socket_options is None:
            socket_options = []

        clean_host = host.strip("[]")

        # Resolve destination and validate all returned IP addresses against SSRF boundaries
        validated_ips = resolve_and_validate_destination(
            clean_host,
            allow_private=self.allow_private,
            allowed_targets=self.allowed_targets,
            enforce_strict=self.enforce_strict,
        )

        if not validated_ips:
            raise SSRFSecurityError(
                f"SSRF Protection: No valid IP addresses resolved for target host '{clean_host}'."
            )

        source_address = None if local_address is None else (local_address, 0)
        exc_map = {
            socket.timeout: httpcore.ConnectTimeout,
            OSError: httpcore.ConnectError,
        }

        # Attempt connection to each validated IP address in order
        last_exc: Optional[Exception] = None
        for ip_str in validated_ips:
            try:
                with httpcore._backends.sync.map_exceptions(exc_map):
                    sock = socket.create_connection(
                        (ip_str, port),
                        timeout,
                        source_address=source_address,
                    )
                    for option in socket_options:
                        sock.setsockopt(*option)
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                return httpcore._backends.sync.SyncStream(sock)
            except (httpcore.ConnectError, httpcore.ConnectTimeout, OSError) as exc:
                last_exc = exc
                continue

        if last_exc is not None:
            raise last_exc
        raise httpcore.ConnectError(f"Failed to connect to '{clean_host}' on port {port}")


class PinnedSIEMTransport(httpx.HTTPTransport):
    """HTTP transport that guarantees IP pinning, SSRF validation, and DNS rebinding immunity.
    
    Subclasses httpx.HTTPTransport to inject PinnedNetworkBackend into the connection pool
    and validate request URLs on each dispatch (including redirect hops).
    """

    def __init__(
        self,
        allow_private: bool = False,
        allowed_targets: Optional[List[str]] = None,
        enforce_strict: bool = False,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.allow_private = allow_private
        self.allowed_targets = allowed_targets
        self.enforce_strict = enforce_strict

        self._pinned_backend = PinnedNetworkBackend(
            allow_private=allow_private,
            allowed_targets=allowed_targets,
            enforce_strict=enforce_strict,
        )
        self._pool._network_backend = self._pinned_backend

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        # Pre-flight URL validation on every request (catches redirect hops to internal / prohibited hosts)
        validate_url_ssrf(
            str(request.url),
            allow_private=self.allow_private,
            allowed_targets=self.allowed_targets,
            enforce_strict=self.enforce_strict,
        )
        return super().handle_request(request)


def create_pinned_siem_client(
    verify_ssl: Union[bool, str, ssl.SSLContext] = True,
    timeout_seconds: float = 30.0,
    allowed_targets: Optional[List[str]] = None,
    allow_private: bool = False,
    enforce_strict: bool = False,
    follow_redirects: bool = False,
) -> httpx.Client:
    """Create an httpx.Client configured with PinnedSIEMTransport."""
    transport = PinnedSIEMTransport(
        verify=verify_ssl,
        allow_private=allow_private,
        allowed_targets=allowed_targets,
        enforce_strict=enforce_strict,
    )
    return httpx.Client(
        transport=transport,
        verify=verify_ssl,
        timeout=timeout_seconds,
        follow_redirects=follow_redirects,
    )
