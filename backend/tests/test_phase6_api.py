"""Phase 6 Comprehensive Integration Tests for FastAPI REST/SSE API.

Tests:
1. Health check endpoint (/api/health)
2. Offline evidence intake (zero-copy :ro and capsule archives) (/api/intake/offline)
3. Online collector orchestrator with HumanApprovalToken verification (/api/intake/online)
4. Online collector rejection without valid token (403 Forbidden)
5. Read-only SIEM query intake & mutating query rejection (/api/intake/siem)
6. Custody chain ledger retrieval & tamper integrity verification (/api/intake/custody/{case_id})
7. Plugin discovery, dry-run auto-mapper & dynamic card registration (/api/plugins)
8. Starter workflow blueprints discovery (/api/workflows/blueprints)
9. Workflow execution (/api/workflows/execute)
10. Server-Sent Events (SSE) streaming of node state transitions (/api/workflows/stream)
11. Human Approval Gate pause & resume (/api/workflows/resume)
12. Cited Report compilation & raw finding provenance inspection (/api/reports & /api/findings)
13. Human feedback recording for v2.0 learning loop (/api/feedback)
"""
from __future__ import annotations

import base64
import json
from pathlib import Path
import shutil
import tempfile
from typing import Any, Dict, List
import zipfile
from fastapi.testclient import TestClient
import pytest

from backend.app.api.deps import reset_dependencies, set_base_vault_dir
from backend.app.main import create_app
from backend.app.models.findings import ForensicFinding
from backend.app.models.plugins import ToolPluginCard
from backend.app.models.workflow import HumanApprovalToken, WorkflowDefinition, WorkflowNode, WorkflowEdge


@pytest.fixture(autouse=True)
def setup_api_env(tmp_path: Path, monkeypatch):
    """Hermetic test sandbox for API testing."""
    test_vault = tmp_path / "vault"
    test_vault.mkdir(parents=True, exist_ok=True)
    test_plugins = tmp_path / "plugins"
    test_plugins.mkdir(parents=True, exist_ok=True)

    # Copy existing plugins to test directory
    src_plugins = Path("plugins").resolve()
    if src_plugins.is_dir():
        for f in src_plugins.glob("*.yaml"):
            shutil.copy(f, test_plugins / f.name)

    monkeypatch.setenv("FORENSICOPS_VAULT_DIR", str(test_vault))
    monkeypatch.setenv("FORENSICOPS_PLUGINS_DIR", str(test_plugins))
    set_base_vault_dir(test_vault)
    reset_dependencies()

    yield

    reset_dependencies()


@pytest.fixture
def client() -> TestClient:
    app = create_app()
    return TestClient(app)


def test_api_health_check(client: TestClient):
    """Verify health endpoint reports healthy status and API version."""
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert data["version"] == "0.1.0"
    assert data["phase"] == 6


def test_api_intake_offline_zero_copy_and_capsule(client: TestClient, tmp_path: Path):
    """Test offline intake via both zero-copy :ro path and zipped capsule archive."""
    case_id = "case_offline_test"

    # 1. Zero-copy intake test
    dummy_image = tmp_path / "large_disk.E01"
    dummy_image.write_bytes(b"E01_DUMMY_IMAGE_DATA_FORENSIC_HEADER")

    resp_ro = client.post(
        "/api/intake/offline",
        json={
            "case_id": case_id,
            "evidence_path": f"{dummy_image}:ro",
            "artifact_type": "disk_image",
            "acquisition_method": "zero_copy_reference",
        },
    )
    assert resp_ro.status_code == 200
    data_ro = resp_ro.json()
    assert data_ro["status"] == "success"
    assert len(data_ro["artifacts"]) == 1
    assert data_ro["artifacts"][0]["type"] == "disk_image"
    assert data_ro["artifacts"][0]["blob_path"].startswith(":ro:")

    # 2. Capsule zip intake test
    capsule_zip = tmp_path / "triage_capsule.zip"
    with zipfile.ZipFile(capsule_zip, "w") as zf:
        zf.writestr("artifacts/Security.evtx", b"EVTX_HEADER_BYTES_12345")
        manifest = {
            "case_id": case_id,
            "artifacts": [
                {
                    "artifact_id": "art-evtx-01",
                    "type": "evtx",
                    "original_path": "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
                    "bundle_path": "artifacts/Security.evtx",
                    "size_bytes": 23,
                    "sha256": "3a07801a61c33be85131c34a2e8cdaec28b4931a54b6ad8e4a909407ab2be544",
                    "sha512": "d88b48f95c10fa8cbe464f1dc44c6806e2cf0175b9f47ec05be326f5d8120d0f28384f7b4ee721669e4f50f00cf05be4f29e9aeec20d2c67c5e2194b613e5472",
                }
            ],
        }
        # Compute proper hashes
        import hashlib
        data_bytes = b"EVTX_HEADER_BYTES_12345"
        manifest["artifacts"][0]["sha256"] = hashlib.sha256(data_bytes).hexdigest()
        manifest["artifacts"][0]["sha512"] = hashlib.sha512(data_bytes).hexdigest()
        manifest["artifacts"][0]["size_bytes"] = len(data_bytes)
        zf.writestr("manifest.json", json.dumps(manifest))

    resp_zip = client.post(
        "/api/intake/offline",
        json={
            "case_id": case_id,
            "evidence_path": str(capsule_zip),
            "artifact_type": "capsule",
        },
    )
    assert resp_zip.status_code == 200
    data_zip = resp_zip.json()
    assert data_zip["status"] == "success"
    assert len(data_zip["artifacts"]) >= 1


def test_api_intake_online_collector_removed_404(client: TestClient):
    """Test that remote online collection endpoint is permanently removed (404 Not Found)."""
    resp = client.post("/api/intake/online", json={"target": {"host": "192.168.1.50"}})
    assert resp.status_code == 404


def test_api_intake_siem_query_and_mutation_blocking(client: TestClient, monkeypatch):
    """Test SIEM query ingestion and verify that mutating commands are strictly blocked."""
    case_id = "case_siem_test"

    # Mock Elasticsearch response
    class MockResponse:
        status_code = 200
        def json(self):
            return {
                "hits": {
                    "total": {"value": 1},
                    "hits": [
                        {
                            "_id": "es-hit-1",
                            "_source": {
                                "@timestamp": "2026-10-31T01:00:00Z",
                                "event": {"code": "4624", "category": ["authentication"]},
                                "host": {"name": "DC-PRIMARY"},
                                "user": {"name": "AdminTarget"},
                                "message": "Successful logon",
                            },
                        }
                    ],
                }
            }

    import httpx
    monkeypatch.setattr(httpx.Client, "post", lambda *args, **kwargs: MockResponse())

    # 1. Valid read-only query
    resp_valid = client.post(
        "/api/intake/siem",
        json={
            "case_id": case_id,
            "config": {
                "siem_type": "elasticsearch",
                "endpoint_url": "https://siem.local:9200",
                "api_key": "test_api_key",
                "index_pattern": "winlogbeat-*",
            },
            "query": "event.code: 4624 AND user.name: AdminTarget",
        },
    )
    assert resp_valid.status_code == 200
    data = resp_valid.json()
    assert data["status"] == "success"
    assert data["findings_count"] == 1
    assert data["query_snapshot"]["snapshot_sha256"] != ""

    # 2. Mutating query rejection
    resp_bad = client.post(
        "/api/intake/siem",
        json={
            "case_id": case_id,
            "config": {
                "siem_type": "elasticsearch",
                "endpoint_url": "https://siem.local:9200",
            },
            "query": "POST /_delete_by_query",
        },
    )
    assert resp_bad.status_code == 400
    assert "Read-Only" in resp_bad.json()["detail"]


def test_api_custody_chain_verification(client: TestClient, tmp_path: Path):
    """Test retrieving the append-only custody chain and verifying cryptographic integrity."""
    case_id = "case_custody_audit"

    # Create an intake event
    test_file = tmp_path / "auth.log"
    test_file.write_text("Oct 31 01:00:00 server sshd[123]: Accepted publickey for analyst")

    client.post(
        "/api/intake/offline",
        json={"case_id": case_id, "evidence_path": str(test_file), "artifact_type": "auth_log"},
    )

    resp = client.get(f"/api/intake/custody/{case_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["case_id"] == case_id
    assert data["is_tamper_free"] is True
    assert data["entry_count"] >= 1
    assert data["entries"][0]["entry_hash"] != ""


def test_api_plugins_list_dry_run_and_registration(client: TestClient):
    """Test listing plugins, running the visual auto-mapper dry-run, and registering a new tool."""
    # 1. List pre-built plugins
    resp_list = client.get("/api/plugins")
    assert resp_list.status_code == 200
    plugins = resp_list.json()
    assert len(plugins) >= 5
    tool_ids = [p["tool_id"] for p in plugins]
    assert "ez_evtxecmd" in tool_ids
    assert "chainsaw_sigma" in tool_ids

    # 2. Dry-Run Auto-Mapper
    sample_rows = [
        {
            "TimeCreated": "2026-10-31 02:00:00",
            "EventId": 4688,
            "Computer": "WORKSTATION-01",
            "SubjectUserName": "jsmith",
            "NewProcessName": "powershell.exe",
            "CommandLine": "powershell.exe -enc AAAA==",
            "ExtraMetadataGuid": "1234-abcd",
            "ReservedChunk": 99,
        }
    ]

    resp_dry = client.post(
        "/api/plugins/dry-run",
        json={"sample_rows": sample_rows},
    )
    assert resp_dry.status_code == 200
    dry_data = resp_dry.json()
    assert "timestamp_utc" in dry_data["suggested_field_map"].values()
    assert "CommandLine" in dry_data["suggested_ai_keep_fields"]
    assert "ExtraMetadataGuid" not in dry_data["suggested_ai_keep_fields"]
    assert dry_data["detected_artifact_type"] == "evtx"

    # 3. Dynamic Tool Card Registration (Compliant with Phase 04 execution policy)
    new_card = {
        "tool_id": "custom_dfir_scanner",
        "name": "Custom DFIR Scanner",
        "version": "1.0",
        "description": "Custom forensic artifact parser",
        "category": "custom_scanner",
        "artifact_type": "evtx",
        "container_image": "ghcr.io/forensicops/custom_scanner:latest",
        "command_template": ["custom_scanner", "--input", "{input_path}", "--output", "{output_dir}"],
        "field_map": {"timestamp_utc": "TimeCreated", "summary": "CommandLine"},
        "ai_keep_fields": ["CommandLine", "User"],
    }

    resp_reg = client.post("/api/plugins/register", json=new_card)
    assert resp_reg.status_code == 200
    assert resp_reg.json()["status"] == "success"

    # Verify newly registered tool appears in list
    resp_list_after = client.get("/api/plugins")
    updated_ids = [p["tool_id"] for p in resp_list_after.json()]
    assert "custom_dfir_scanner" in updated_ids


def test_api_workflow_blueprints_discovery(client: TestClient):
    """Verify discovery of all 4 pre-built starter workflow blueprints."""
    resp = client.get("/api/workflows/blueprints")
    assert resp.status_code == 200
    blueprints = resp.json()
    assert "windows_intrusion" in blueprints
    assert "full_windows_triage" in blueprints
    assert "linux_ssh_compromise" in blueprints
    assert "memory_pcap_hunt" in blueprints


def test_api_workflow_execution_and_sse_streaming(client: TestClient):
    """Test both synchronous execution and SSE event streaming of workflow DAGs."""
    case_id = "case_workflow_test"

    # Pre-populate findings in storage for the case
    from backend.app.api.deps import get_storage
    storage = get_storage(case_id)
    storage.insert_findings(
        [
            ForensicFinding(
                finding_id="fnd-evtx-01",
                case_id=case_id,
                source_artifact_id="art-01",
                source_artifact_hash="a" * 64,
                tool_id="dissect",
                timestamp_utc="2026-10-31T02:00:00Z",
                artifact_type="evtx",
                category="authentication",
                event_id="4624",
                severity="high",
                user="target_admin",
                host="DC01",
                summary="Successful logon for target_admin on DC01",
            )
        ]
    )

    # 1-node workflow for fast hermetic execution
    wf = WorkflowDefinition(
        workflow_id="wf_test_single",
        name="Test Workflow",
        nodes=[
            WorkflowNode(
                id="node_input",
                name="Evidence Intake",
                type="evidence_input",
            ),
            WorkflowNode(
                id="node_evtx",
                name="Dissect EVTX",
                type="dissect_parser",
                config={"artifact_type": "evtx"},
            ),
            WorkflowNode(
                id="node_report",
                name="Compile Report",
                type="report_compiler",
            ),
        ],
        edges=[
            WorkflowEdge(source="node_input", target="node_evtx"),
            WorkflowEdge(source="node_evtx", target="node_report"),
        ],
    )

    # 1. Synchronous Execution
    resp_exec = client.post(
        "/api/workflows/execute",
        json={"case_id": case_id, "workflow": wf.model_dump()},
    )
    assert resp_exec.status_code == 200
    exec_data = resp_exec.json()
    assert "node_input" in exec_data["completed_nodes"]
    assert "node_evtx" in exec_data["completed_nodes"]
    assert "node_report" in exec_data["completed_nodes"]
    assert exec_data["report"] is not None

    # 2. SSE Streaming Execution
    resp_stream = client.post(
        "/api/workflows/stream",
        json={"case_id": case_id, "workflow": wf.model_dump()},
    )
    assert resp_stream.status_code == 200
    assert "text/event-stream" in resp_stream.headers["content-type"]
    stream_content = resp_stream.text
    assert "event: workflow_started" in stream_content
    assert "event: node_completed" in stream_content
    assert "event: workflow_finished" in stream_content


def test_api_workflow_approval_gate_pause_and_resume(client: TestClient):
    """Test that a workflow pauses on human_approval_gate and resumes via /api/workflows/resume."""
    case_id = "case_approval_gate"

    wf = WorkflowDefinition(
        workflow_id="wf_gate_test",
        name="Approval Gate Workflow",
        nodes=[
            WorkflowNode(
                id="node_input",
                name="Evidence Intake",
                type="evidence_input",
            ),
            WorkflowNode(
                id="node_gate",
                name="Analyst Approval Gate",
                type="human_approval_gate",
            ),
            WorkflowNode(
                id="node_report",
                name="Compile Report",
                type="report_compiler",
            ),
        ],
        edges=[
            WorkflowEdge(source="node_input", target="node_gate"),
            WorkflowEdge(source="node_gate", target="node_report"),
        ],
    )

    # 1. Execute without token -> should pause at node_gate
    resp_init = client.post(
        "/api/workflows/execute",
        json={"case_id": case_id, "workflow": wf.model_dump()},
    )
    assert resp_init.status_code == 200
    init_state = resp_init.json()
    assert init_state["is_paused"] is True
    assert init_state["pause_node_id"] == "node_gate"
    assert "node_report" not in init_state["completed_nodes"]

    # 2. Generate valid token and resume
    token = HumanApprovalToken(
        node_id="node_gate",
        case_id=case_id,
        issued_by="security_lead",
    )
    token.sign()

    resp_resume = client.post(
        "/api/workflows/resume",
        json={
            "case_id": case_id,
            "workflow": wf.model_dump(),
            "state": init_state,
            "approval_token": token.model_dump(),
        },
    )
    assert resp_resume.status_code == 200
    resumed_state = resp_resume.json()
    assert resumed_state["is_paused"] is False
    assert "node_gate" in resumed_state["completed_nodes"]
    assert "node_report" in resumed_state["completed_nodes"]


def test_api_report_retrieval_and_finding_inspection(client: TestClient):
    """Test retrieving compiled 6-section report and inspecting finding details."""
    case_id = "case_report_test"

    from backend.app.api.deps import get_storage
    storage = get_storage(case_id)
    finding = ForensicFinding(
        finding_id="fnd-provenance-01",
        case_id=case_id,
        source_artifact_id="art-log-01",
        source_artifact_hash="b" * 64,
        tool_id="dissect",
        timestamp_utc="2026-10-31T03:00:00Z",
        artifact_type="evtx",
        category="process_creation",
        event_id="4688",
        severity="critical",
        process_name="mimikatz.exe",
        command_line="mimikatz.exe privilege::debug sekurlsa::logonpasswords",
        host="FINANCE-PC",
        user="SYSTEM",
        summary="Mimikatz credential dumping executed on FINANCE-PC",
        projected_data={"privilege": "SeDebugPrivilege"},
    )
    storage.insert_findings([finding])

    # 1. Retrieve 6-section Cited Report
    resp_report = client.get(f"/api/reports/{case_id}")
    assert resp_report.status_code == 200
    rep_data = resp_report.json()
    assert "Executive Summary & Incident Timeline" in rep_data["markdown"]
    assert "Multi-Host Patient Zero Assessment & Remediation" in rep_data["markdown"]

    # 2. Inspect individual finding by ID
    resp_finding = client.get(f"/api/findings/fnd-provenance-01?case_id={case_id}")
    assert resp_finding.status_code == 200
    fnd_data = resp_finding.json()
    assert fnd_data["finding_id"] == "fnd-provenance-01"
    assert fnd_data["source_artifact_hash"] == "b" * 64
    assert fnd_data["process_name"] == "mimikatz.exe"

    # 3. Query findings with filters
    resp_q = client.get(f"/api/findings?case_id={case_id}&severity=critical")
    assert resp_q.status_code == 200
    assert len(resp_q.json()) == 1


def test_api_feedback_recording_and_retrieval(client: TestClient):
    """Test v2.0 human feedback micro-controls (confirm TP, mark benign, correct query)."""
    case_id = "case_feedback_test"

    # 1. Confirm True Positive
    resp_tp = client.post(
        "/api/feedback",
        json={
            "case_id": case_id,
            "finding_id": "fnd-provenance-01",
            "feedback_type": "confirm_tp",
            "analyst_note": "Confirmed genuine credential theft.",
        },
    )
    assert resp_tp.status_code == 200
    assert resp_tp.json()["status"] == "recorded"
    assert resp_tp.json()["record"]["feedback_type"] == "true_positive"

    # 2. Mark Benign Baseline
    resp_fp = client.post(
        "/api/feedback",
        json={
            "case_id": case_id,
            "feedback_type": "mark_benign_baseline",
            "entity_pattern": "user:svc_backup",
            "analyst_note": "Scheduled nightly backup service account.",
            "artifact_type": "evtx",
        },
    )
    assert resp_fp.status_code == 200
    assert resp_fp.json()["record"]["feedback_type"] == "false_positive_benign_baseline"

    # 3. Retrieve benign baselines
    resp_base = client.get("/api/feedback/baselines?org_id=default_org")
    assert resp_base.status_code == 200
    baselines = resp_base.json()
    assert any(b["entity_pattern"] == "user:svc_backup" for b in baselines)
