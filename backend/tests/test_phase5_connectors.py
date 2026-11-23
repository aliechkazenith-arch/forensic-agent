"""Phase 5 Verification Suite: Hybrid SIEM Connectors.

Standards:
- Non-Negotiable Read-Only SIEM Query Adapters
- SHA-256 Query-Snapshot Hashing & CitationGuard Interoperability
- Mutating Query Rejection (ReadOnlyViolationError)
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
        if host in ("elasticsearch", "wazuh.corp", "splunk.corp", "localhost"):
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


# ------------------------------------------------------------------------------
# Test 1: Elasticsearch Read-Only Connector & ECS Normalization
# ------------------------------------------------------------------------------
def test_elasticsearch_connector_read_only_and_normalization():
    """Verify Elasticsearch read-only queries and ECS hit normalization with SHA-256 snapshot."""
    mock_es_hits = [
        {
            "_index": "winlogbeat-7.17-2026.10.31",
            "_id": "es-hit-001",
            "_source": {
                "@timestamp": "2026-10-31T06:30:00.000Z",
                "winlog": {"event_id": "4624", "user": {"name": "Administrator"}},
                "event": {"category": "authentication", "action": "Logon", "severity": 2},
                "host": {"name": "DC-PRIMARY.corp.local"},
                "source": {"ip": "10.0.5.120"},
                "message": "An account was successfully logged on.",
            },
        },
        {
            "_index": "winlogbeat-7.17-2026.10.31",
            "_id": "es-hit-002",
            "_source": {
                "@timestamp": "2026-10-31T06:31:15.000Z",
                "winlog": {"event_id": "1"},
                "event": {"category": "process_creation", "severity": 8},
                "host": {"name": "DC-PRIMARY.corp.local"},
                "user": {"name": "SYSTEM"},
                "process": {
                    "name": "powershell.exe",
                    "command_line": "powershell.exe -enc SQBFAFgA...",
                },
                "message": "Process Create: powershell.exe",
            },
        },
    ]

    mock_response = httpx.Response(
        200,
        json={"hits": {"hits": mock_es_hits}},
        request=httpx.Request("POST", "http://elasticsearch:9200/winlogbeat-*/_search"),
    )
    mock_transport = httpx.MockTransport(lambda req: mock_response)
    client = httpx.Client(transport=mock_transport)

    config = SIEMConnectionConfig(
        siem_type="elasticsearch",
        endpoint_url="http://elasticsearch:9200",
        index_pattern="winlogbeat-*",
    )
    connector = ElasticsearchConnector(config=config, http_client=client)

    findings, snapshot = connector.search(
        query="event.category: process_creation",
        case_id="CASE-SIEM-001",
    )

    assert len(findings) == 2
    assert snapshot.record_count == 2
    assert snapshot.snapshot_sha256 is not None
    assert len(snapshot.snapshot_sha256) == 64

    # Verify normalization into ForensicFinding
    f1 = findings[0]
    assert f1.case_id == "CASE-SIEM-001"
    assert f1.tool_id == "siem_elasticsearch"
    assert f1.user == "Administrator"
    assert f1.source_artifact_hash == snapshot.snapshot_sha256
    assert f1.projected_data["hit_id"] == "es-hit-001"

    f2 = findings[1]
    assert f2.user == "SYSTEM"
    assert f2.process_name == "powershell.exe"
    assert "SQBFAFgA" in (f2.command_line or "")


# ------------------------------------------------------------------------------
# Test 2: Wazuh EDR Connector & Alert Normalization
# ------------------------------------------------------------------------------
def test_wazuh_edr_connector_alerts_normalization():
    """Verify Wazuh alert querying with JSON normalization into ForensicFinding objects."""
    mock_wazuh_alerts = {
        "data": {
            "affected_items": [
                {
                    "id": "1698734000.12345",
                    "timestamp": "2026-10-31T06:45:00.000+0000",
                    "rule": {
                        "id": "550",
                        "level": 12,
                        "description": "Integrity checksum changed in /etc/shadow",
                    },
                    "agent": {"id": "001", "name": "prod-app-server-01"},
                    "full_log": "File '/etc/shadow' checksum changed.",
                }
            ],
            "total_affected_items": 1,
        }
    }

    mock_response = httpx.Response(
        200,
        json=mock_wazuh_alerts,
        request=httpx.Request("GET", "https://wazuh.corp:55000/alerts"),
    )
    mock_transport = httpx.MockTransport(lambda req: mock_response)
    client = httpx.Client(transport=mock_transport)

    config = SIEMConnectionConfig(
        siem_type="wazuh",
        endpoint_url="https://wazuh.corp:55000",
        token="jwt-wazuh-token-xyz",
    )
    connector = WazuhConnector(config=config, http_client=client)

    findings, snapshot = connector.search(
        query="rule.level >= 10",
        case_id="CASE-WAZUH-001",
    )

    assert len(findings) == 1
    assert snapshot.record_count == 1
    assert snapshot.snapshot_sha256 is not None

    f = findings[0]
    assert f.severity == "critical"  # rule level 12 maps to critical
    assert f.tool_id == "siem_wazuh"
    assert "Integrity checksum changed" in f.summary
    assert f.source_artifact_hash == snapshot.snapshot_sha256


# ------------------------------------------------------------------------------
# Test 3: Splunk Enterprise Connector & Search Normalization
# ------------------------------------------------------------------------------
def test_splunk_connector_search_normalization():
    """Verify Splunk search results retrieval and ECS-style extraction."""
    mock_splunk_results = [
        {
            "_time": "2026-10-31T06:50:00.000Z",
            "host": "WKSTN-FINANCE-04",
            "EventCode": "4688",
            "NewProcessName": "C:\\Windows\\System32\\whoami.exe",
            "CommandLine": "whoami /all",
            "AccountName": "victim_user",
            "_raw": "2026-10-31T06:50:00.000Z EventCode=4688 NewProcessName=whoami.exe",
        },
        {
            "_time": "2026-10-31T06:51:00.000Z",
            "host": "WKSTN-FINANCE-04",
            "EventCode": "7045",  # New service installed
            "ServiceName": "BDoorSvc",
            "ImagePath": "C:\\Windows\\Temp\\backdoor.exe",
            "AccountName": "SYSTEM",
            "severity": "critical",
            "_raw": "2026-10-31T06:51:00.000Z EventCode=7045 ServiceName=BDoorSvc",
        },
    ]

    mock_response = httpx.Response(
        200,
        text="\n".join(json.dumps({"result": r}) for r in mock_splunk_results),
        request=httpx.Request("POST", "https://splunk.corp:8089/services/search/jobs/export"),
    )
    mock_transport = httpx.MockTransport(lambda req: mock_response)
    client = httpx.Client(transport=mock_transport)

    config = SIEMConnectionConfig(
        siem_type="splunk",
        endpoint_url="https://splunk.corp:8089",
        token="splunk-auth-bearer-token",
    )
    connector = SplunkConnector(config=config, http_client=client)

    findings, snapshot = connector.search(
        query='index=wineventlog host="WKSTN-FINANCE-04"',
        case_id="CASE-SIEM-SPLUNK-01",
    )

    assert len(findings) == 2
    assert snapshot.record_count == 2
    assert snapshot.snapshot_sha256 is not None
    assert findings[0].tool_id == "siem_splunk"
    assert findings[0].source_artifact_hash == snapshot.snapshot_sha256
    assert findings[0].process_name == "C:\\Windows\\System32\\whoami.exe"
    assert findings[1].severity == "critical"


# ------------------------------------------------------------------------------
# Test 4: Prohibited Mutating Queries Rejection (ReadOnlyViolationError)
# ------------------------------------------------------------------------------
def test_siem_mutation_command_rejection():
    """Verify that all mutating operations across ES, Wazuh, and Splunk are blocked."""
    dummy_config = SIEMConnectionConfig(
        siem_type="elasticsearch",
        endpoint_url="http://localhost:9200",
    )
    es = ElasticsearchConnector(config=dummy_config)
    with pytest.raises(ReadOnlyViolationError):
        es.search("POST /_delete_by_query", case_id="C1")

    with pytest.raises(ReadOnlyViolationError):
        es.search("index._bulk operation", case_id="C1")

    splunk_config = SIEMConnectionConfig(
        siem_type="splunk",
        endpoint_url="http://localhost:8089",
    )
    splunk = SplunkConnector(config=splunk_config)
    with pytest.raises(ReadOnlyViolationError):
        splunk.search("search index=main | delete", case_id="C1")

    with pytest.raises(ReadOnlyViolationError):
        splunk.search("search index=main | outputcsv evil.csv", case_id="C1")

    wazuh_config = SIEMConnectionConfig(
        siem_type="wazuh",
        endpoint_url="http://localhost:55000",
    )
    wazuh = WazuhConnector(config=wazuh_config)
    with pytest.raises(ReadOnlyViolationError):
        wazuh.search("delete agent 001", case_id="C1")


# ------------------------------------------------------------------------------
# Test 5: SIEM Findings Ingestion to Store & CitationGuard Validation
# ------------------------------------------------------------------------------
def test_siem_findings_intake_to_store_and_citation_guard(
    custody_engine, forensic_store
):
    """End-to-End: SIEM hit ingestion anchors in custody, enters store, passes CitationGuard."""
    mock_es_hits = [
        {
            "_index": "winlogbeat-2026",
            "_id": "hit-777",
            "_source": {
                "@timestamp": "2026-10-31T07:00:00Z",
                "winlog": {"event_id": "4720"},  # User account created
                "user": {"name": "evil_backdoor_admin"},
                "host": {"name": "DC-PRIMARY"},
                "message": "A user account was created: evil_backdoor_admin",
            },
        }
    ]

    mock_response = httpx.Response(
        200,
        json={"hits": {"hits": mock_es_hits}},
        request=httpx.Request("POST", "http://elasticsearch:9200/winlogbeat-*/_search"),
    )
    mock_transport = httpx.MockTransport(lambda req: mock_response)
    client = httpx.Client(transport=mock_transport)

    config = SIEMConnectionConfig(
        siem_type="elasticsearch",
        endpoint_url="http://elasticsearch:9200",
    )
    connector = ElasticsearchConnector(config=config, http_client=client)

    # Ingest findings directly with custody logging and store indexing
    findings, snapshot = ingest_siem_query_findings(
        connector=connector,
        query="winlog.event_id:4720",
        case_id="CASE-SIEM-E2E",
        custody_engine=custody_engine,
        forensic_store=forensic_store,
        actor="soc_lead",
    )

    assert len(findings) == 1
    finding_id = findings[0].finding_id
    artifact_hash = findings[0].source_artifact_hash

    # 1. Verify finding is in DuckDB
    stored_finding = forensic_store.get_finding(finding_id)
    assert stored_finding is not None
    assert stored_finding.user == "evil_backdoor_admin"

    # 2. Verify custody chain entry recorded
    chain = custody_engine.get_custody_chain(case_id="CASE-SIEM-E2E")
    actions = [c.action for c in chain]
    assert "INGEST_SIEM_QUERY_SNAPSHOT" in actions

    # 3. Verify CitationGuard accepts claim citing this SIEM finding!
    guard = CitationGuard(storage=forensic_store)
    claim = CitedClaim(
        claim_type="observed_fact",
        statement="Adversary created rogue account 'evil_backdoor_admin' on DC-PRIMARY.",
        citing_finding_ids=[finding_id],
        source_artifact_hashes=[artifact_hash],
    )

    is_valid, reasons = guard.validate_claim(claim, case_id="CASE-SIEM-E2E")
    assert is_valid is True
    assert reasons == []
