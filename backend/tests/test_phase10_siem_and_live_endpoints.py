"""Phase 10 Verification Suite: SIEM Connectors and Network Security.

Standards:
- Non-negotiable SSRF defense (Localhost, link-local metadata 169.254.169.254, unapproved RFC 1918).
- DNS rebinding and open redirect protection.
- Zero credential leakage in logs, traces, or errors.
- Read-only SIEM adapters (Elasticsearch, Wazuh, Splunk) with canonical SHA-256 snapshot hashing.
- End-to-end CitationGuard verification of SIEM telemetry findings.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import pytest
import httpx

from backend.app.connectors.siem_connectors import (
    ElasticsearchConnector,
    SplunkConnector,
    WazuhConnector,
    ingest_siem_query_findings,
)
from backend.app.core.citation_guard import CitationGuard
from backend.app.core.custody_engine import CustodyEngine, safe_make_writable
from backend.app.core.exceptions import (
    ReadOnlyViolationError,
    SIEMQueryError,
    SSRFSecurityError,
)
from backend.app.core.network_validator import (
    resolve_and_validate_destination,
    sanitize_credentials,
    validate_url_ssrf,
)
from backend.app.core.storage import ForensicStore
from backend.app.models.connectors import (
    SIEMConnectionConfig,
)
from backend.app.models.findings import CitedClaim


@pytest.fixture(autouse=True)
def mock_dns_resolution(monkeypatch):
    """Fast-mock DNS resolution for synthetic test SIEM endpoints."""
    monkeypatch.setenv("FORENSICOPS_ALLOW_PRIVATE_SIEM", "true")
    import socket
    orig_getaddrinfo = socket.getaddrinfo
    def mock_getaddrinfo(host, port, *args, **kwargs):
        if host in ("elasticsearch", "wazuh-server", "splunk-indexer", "app-server-01.corp"):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('198.51.100.1', port or 0))]
        return orig_getaddrinfo(host, port, *args, **kwargs)
    monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo)


@pytest.fixture
def temp_vault(tmp_path):
    """Provide clean temporary vault directory."""
    vault = tmp_path / "vault"
    vault.mkdir(parents=True, exist_ok=True)
    yield vault
    for root, _, files in os.walk(vault):
        for f in files:
            safe_make_writable(Path(root) / f)


@pytest.fixture
def custody_engine(temp_vault):
    """Provide initialized CustodyEngine."""
    return CustodyEngine(vault_root=temp_vault)


@pytest.fixture
def forensic_store():
    """Provide in-memory DuckDB ForensicStore."""
    with ForensicStore(":memory:") as s:
        yield s


# ==============================================================================
# SECTION 1: SSRF AND DESTINATION DEFENSE
# ==============================================================================

def test_ssrf_rejects_localhost_and_loopback():
    """Verify SSRF defense rejects 127.0.0.1, localhost, and ::1."""
    with pytest.raises(SSRFSecurityError, match="restricted host|Loopback"):
        resolve_and_validate_destination("127.0.0.1", enforce_strict=True)

    with pytest.raises(SSRFSecurityError, match="restricted host|Loopback"):
        resolve_and_validate_destination("localhost", enforce_strict=True)

    with pytest.raises(SSRFSecurityError, match="restricted host|Loopback"):
        resolve_and_validate_destination("::1", enforce_strict=True)


def test_ssrf_rejects_cloud_metadata():
    """Verify SSRF defense unconditionally rejects 169.254.169.254 and metadata domains."""
    with pytest.raises(SSRFSecurityError, match="metadata"):
        resolve_and_validate_destination("169.254.169.254")

    with pytest.raises(SSRFSecurityError, match="metadata"):
        resolve_and_validate_destination("metadata.google.internal")

    with pytest.raises(SSRFSecurityError, match="metadata"):
        resolve_and_validate_destination("instance-data")


def test_ssrf_rejects_unapproved_private_networks():
    """Verify SSRF defense blocks RFC 1918 addresses not explicitly allowlisted."""
    with pytest.raises(SSRFSecurityError, match="private network|allowlist"):
        resolve_and_validate_destination("10.0.5.1", allow_private=False, enforce_strict=True)

    with pytest.raises(SSRFSecurityError, match="private network|allowlist"):
        resolve_and_validate_destination("192.168.1.100", allow_private=False, enforce_strict=True)


def test_ssrf_allows_explicitly_allowlisted_targets():
    """Verify SSRF defense allows target when within authorized CIDR or host allowlist."""
    ips = resolve_and_validate_destination(
        "10.200.1.50",
        allowed_targets=["10.200.1.50"],
        enforce_strict=True,
    )
    assert "10.200.1.50" in ips

    ips = resolve_and_validate_destination(
        "192.168.50.25",
        allowed_targets=["192.168.50.0/24"],
        enforce_strict=True,
    )
    assert "192.168.50.25" in ips


def test_ssrf_url_validation_rejects_invalid_schemes():
    """Verify validate_url_ssrf permits only http and https schemes."""
    with pytest.raises(SSRFSecurityError, match="Only HTTP and HTTPS"):
        validate_url_ssrf("gopher://10.0.0.1:70")

    with pytest.raises(SSRFSecurityError, match="Only HTTP and HTTPS"):
        validate_url_ssrf("file:///etc/passwd")


# ==============================================================================
# SECTION 2: CREDENTIAL SANITIZATION & REDACTION
# ==============================================================================

def test_credential_sanitization_scrubs_secrets_from_strings():
    """Verify sensitive passwords, tokens, and custom secrets are redacted from logs and errors."""
    raw = "Connection failed for user=root with password=SuperSecretP@ss! and Bearer eyJhbGciOi..."
    scrubbed = sanitize_credentials(raw, custom_secrets=["SuperSecretP@ss!"])
    assert "SuperSecretP@ss!" not in scrubbed
    assert "******" in scrubbed
    assert "eyJhbGciOi" not in scrubbed


def test_credential_sanitization_in_siem_error():
    """Verify SIEM connector scrubs API tokens and passwords from exception messages."""
    secret_pass = "P@sswordSensitive123"
    config = SIEMConnectionConfig(
        siem_type="elasticsearch",
        endpoint_url="http://elasticsearch:9200",
        password=secret_pass,
    )

    mock_resp = httpx.Response(
        401,
        text=f"Authentication failed for user admin with password={secret_pass}",
        request=httpx.Request("POST", "http://elasticsearch:9200/_all/_search"),
    )
    client = httpx.Client(transport=httpx.MockTransport(lambda req: mock_resp))
    connector = ElasticsearchConnector(config=config, http_client=client)

    with pytest.raises(SIEMQueryError) as exc_info:
        connector.search(query="*", case_id="CASE-SEC-01")

    assert secret_pass not in str(exc_info.value)
    assert "******" in str(exc_info.value)


# ==============================================================================
# SECTION 3: READ-ONLY SIEM CONNECTORS
# ==============================================================================

def test_elasticsearch_connector_read_only_and_snapshot_hash(custody_engine, forensic_store):
    """Verify Elasticsearch adapter enforces read-only queries, computes snapshot hash, and normalizes findings."""
    mock_hits = [
        {
            "_index": "filebeat-2026.11.01",
            "_id": "hit-auth-901",
            "_source": {
                "@timestamp": "2026-11-01T02:15:00Z",
                "host": {"name": "app-server-01.corp"},
                "event": {"category": "authentication", "action": "ssh_login", "severity": 2},
                "user": {"name": "deployer"},
                "source": {"ip": "198.51.100.42"},
                "message": "Accepted publickey for deployer from 198.51.100.42 port 49210 ssh2",
            },
        }
    ]

    mock_resp = httpx.Response(
        200,
        json={"hits": {"total": {"value": 1}, "hits": mock_hits}},
        request=httpx.Request("POST", "http://elasticsearch:9200/filebeat-*/_search"),
    )
    client = httpx.Client(transport=httpx.MockTransport(lambda req: mock_resp))

    config = SIEMConnectionConfig(
        siem_type="elasticsearch",
        endpoint_url="http://elasticsearch:9200",
        index_pattern="filebeat-*",
    )
    connector = ElasticsearchConnector(config=config, http_client=client)

    findings, snapshot = ingest_siem_query_findings(
        connector=connector,
        query="event.action:ssh_login",
        case_id="CASE-SIEM-P10",
        custody_engine=custody_engine,
        forensic_store=forensic_store,
        actor="soc_analyst_alice",
    )

    assert len(findings) == 1
    f = findings[0]
    assert f.tool_id == "siem_elasticsearch"
    assert f.source_artifact_hash == snapshot.snapshot_sha256
    assert f.host == "app-server-01.corp"
    assert f.user == "deployer"

    chain = custody_engine.get_custody_chain(case_id="CASE-SIEM-P10")
    assert any(c.action == "INGEST_SIEM_QUERY_SNAPSHOT" for c in chain)

    guard = CitationGuard(storage=forensic_store)
    claim = CitedClaim(
        claim_type="observed_fact",
        statement="User deployer logged in via SSH from 198.51.100.42.",
        citing_finding_ids=[f.finding_id],
        source_artifact_hashes=[snapshot.snapshot_sha256],
    )
    is_valid, reasons = guard.validate_claim(claim, case_id="CASE-SIEM-P10")
    assert is_valid is True
    assert reasons == []


def test_wazuh_connector_read_only_and_snapshot_hash(custody_engine, forensic_store):
    """Verify Wazuh adapter enforces read-only alerts, computes snapshot hash, and normalizes findings."""
    mock_alerts = [
        {
            "id": "wazuh-alert-9921",
            "timestamp": "2026-11-01T02:20:00Z",
            "rule": {
                "id": "5501",
                "level": 9,
                "description": "PAM: User login failed.",
                "groups": ["syslog", "pam"],
                "mitre": {"id": "T1110", "tactic": "Credential Access"},
            },
            "agent": {"id": "005", "name": "db-prod-02"},
            "data": {
                "srcip": "203.0.113.19",
                "srcuser": "postgres",
            },
        }
    ]

    mock_resp = httpx.Response(
        200,
        json={"data": {"affected_items": mock_alerts}},
        request=httpx.Request("GET", "https://wazuh-server:55000/alerts"),
    )
    client = httpx.Client(transport=httpx.MockTransport(lambda req: mock_resp))

    config = SIEMConnectionConfig(
        siem_type="wazuh",
        endpoint_url="https://wazuh-server:55000",
        token="wazuh_sample_token",
    )
    connector = WazuhConnector(config=config, http_client=client)

    findings, snapshot = ingest_siem_query_findings(
        connector=connector,
        query="rule.id:5501",
        case_id="CASE-SIEM-WAZUH-P10",
        custody_engine=custody_engine,
        forensic_store=forensic_store,
        actor="soc_analyst_alice",
    )

    assert len(findings) == 1
    f = findings[0]
    assert f.tool_id == "siem_wazuh"
    assert f.event_id == "5501"
    assert f.severity == "high"
    assert f.host == "db-prod-02"
    assert f.user == "postgres"
    assert snapshot.record_count == 1


def test_splunk_connector_read_only_and_snapshot_hash(custody_engine, forensic_store):
    """Verify Splunk adapter enforces read-only SPL export and normalizes findings."""
    splunk_json_line = json.dumps({
        "result": {
            "_time": "2026-11-01T02:25:00Z",
            "EventCode": "4672",
            "host": "DC-PRIMARY.corp.local",
            "user": "Administrator",
            "action": "privilege_assigned",
            "_raw": "2026-11-01T02:25:00Z EventCode=4672 Special privileges assigned to new logon",
        }
    })

    mock_resp = httpx.Response(
        200,
        text=splunk_json_line,
        request=httpx.Request("POST", "https://splunk-indexer:8089/services/search/jobs/export"),
    )
    client = httpx.Client(transport=httpx.MockTransport(lambda req: mock_resp))

    config = SIEMConnectionConfig(
        siem_type="splunk",
        endpoint_url="https://splunk-indexer:8089",
        token="splunk_token_p10",
    )
    connector = SplunkConnector(config=config, http_client=client)

    findings, snapshot = ingest_siem_query_findings(
        connector=connector,
        query="search index=wineventlog EventCode=4672",
        case_id="CASE-SIEM-SPLUNK-P10",
        custody_engine=custody_engine,
        forensic_store=forensic_store,
        actor="soc_analyst_alice",
    )

    assert len(findings) == 1
    f = findings[0]
    assert f.tool_id == "siem_splunk"
    assert f.event_id == "4672"
    assert f.host == "DC-PRIMARY.corp.local"
    assert f.user == "Administrator"


def test_siem_mutating_query_rejection():
    """Verify all mutating queries across Elasticsearch, Wazuh, and Splunk are blocked."""
    cfg_es = SIEMConnectionConfig(siem_type="elasticsearch", endpoint_url="http://elasticsearch:9200")
    es = ElasticsearchConnector(config=cfg_es)
    with pytest.raises(ReadOnlyViolationError):
        es.search("POST /_bulk", case_id="C1")
    with pytest.raises(ReadOnlyViolationError):
        es.search("DELETE /filebeat-*", case_id="C1")

    cfg_wazuh = SIEMConnectionConfig(siem_type="wazuh", endpoint_url="https://wazuh-server:55000")
    wazuh = WazuhConnector(config=cfg_wazuh)
    with pytest.raises(ReadOnlyViolationError):
        wazuh.search("delete from alerts", case_id="C1")

    cfg_splunk = SIEMConnectionConfig(siem_type="splunk", endpoint_url="https://splunk-indexer:8089")
    splunk = SplunkConnector(config=cfg_splunk)
    with pytest.raises(ReadOnlyViolationError):
        splunk.search("search index=main | delete", case_id="C1")
    with pytest.raises(ReadOnlyViolationError):
        splunk.search("search index=main | outputlookup evil.csv", case_id="C1")


def test_siem_client_rejects_open_redirects():
    """Verify SIEM HTTP client is configured with follow_redirects=False to prevent redirect SSRF."""
    config = SIEMConnectionConfig(
        siem_type="elasticsearch",
        endpoint_url="http://elasticsearch:9200",
    )
    connector = ElasticsearchConnector(config=config)
    assert connector._client.follow_redirects is False
    connector.close()
