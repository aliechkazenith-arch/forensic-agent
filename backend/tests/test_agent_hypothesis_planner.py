"""Unit and Integration Tests for Agent Hypothesis Planner (Step 4 of Intake Flow).

Standards:
- Anti-Hallucination Guardrails: All claims must cite real finding_ids and artifact SHA-256 hashes (AGENTS.md Rule 1).
- Nonce-shielded evidence encapsulation against Indirect Prompt Injection (AGENTS.md Rule 3).
- SQLite session persistence of investigation goal and hypothesis draft.
"""
from __future__ import annotations

import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from backend.app.main import create_app
from backend.app.models.findings import ForensicFinding, FindingSeverity
from backend.app.agent.provider_registry import get_provider_registry, reset_provider_registry
from backend.app.db.sqlite_store import get_llm_state_store, reset_llm_state_store


@pytest.fixture
def clean_env():
    """Ensure clean isolated SQLite and provider registry state."""
    reset_llm_state_store()
    reset_provider_registry()
    yield
    reset_llm_state_store()
    reset_provider_registry()


@pytest.fixture
def client(clean_env) -> TestClient:
    app = create_app()
    return TestClient(app)


def test_plan_hypothesis_empty_goal_rejected(client: TestClient):
    """Validation test: empty investigation goal should be rejected by pydantic."""
    resp = client.post(
        "/api/agent/plan-hypothesis",
        json={"case_id": "CASE-TEST-01", "investigation_goal": "ab"},  # min_length is 3
    )
    assert resp.status_code == 422


def test_plan_hypothesis_with_custom_findings(client: TestClient):
    """Test hypothesis planner generates dual hypotheses citing verified evidence findings."""
    f1 = ForensicFinding(
        case_id="CASE-TEST-02",
        source_artifact_id="art-001",
        artifact_type="evtx",
        tool_id="evtx_dump",
        timestamp_utc=datetime.now(timezone.utc).isoformat(),
        finding_id="find-evtx-4624",
        source_artifact_hash="a" * 64,
        category="LateralMovement",
        severity="high",
        summary="Suspicious remote interactive logon Type 10 with PsExec service initiation",
        user="CORP\\compromised_admin",
        host="FINANCE-SRV01",
    )

    f2 = ForensicFinding(
        case_id="CASE-TEST-02",
        source_artifact_id="art-002",
        artifact_type="memory",
        tool_id="volatility_mem",
        timestamp_utc=datetime.now(timezone.utc).isoformat(),
        finding_id="find-mem-lsass",
        source_artifact_hash="b" * 64,
        category="CredentialAccess",
        severity="critical",
        summary="Procdump handle injection into lsass.exe process space",
        user="SYSTEM",
        host="FINANCE-SRV01",
    )


    resp = client.post(
        "/api/agent/plan-hypothesis",
        json={
            "case_id": "CASE-TEST-02",
            "investigation_goal": "Investigate credential theft and lateral movement via PsExec",
            "findings": [f1.model_dump(mode="json"), f2.model_dump(mode="json")],
        },
    )

    assert resp.status_code == 200
    data = resp.json()

    assert data["case_id"] == "CASE-TEST-02"
    assert "credential" in data["investigation_goal"].lower()
    assert len(data["threat_hypothesis"]) > 10
    assert len(data["benign_hypothesis"]) > 10
    assert data["confidence_score"] > 0
    assert len(data["key_questions"]) >= 2
    assert len(data["suggested_steps"]) >= 2

    # Verify citation guard: findings are cited with verified hashes
    assert len(data["cited_findings"]) >= 2
    cited_find_ids = [c["citing_finding_ids"][0] for c in data["cited_findings"]]
    assert "find-evtx-4624" in cited_find_ids
    assert "find-mem-lsass" in cited_find_ids

    # Source hashes must match the ingested SHA-256 hashes exactly
    cited_hashes = [c["source_artifact_hashes"][0] for c in data["cited_findings"]]
    assert "a" * 64 in cited_hashes
    assert "b" * 64 in cited_hashes

    # Recommended blueprint inference
    # Memory was present, so memory_pcap_hunt or windows_intrusion is recommended
    assert data["recommended_blueprint"] in ("memory_pcap_hunt", "windows_intrusion")

    # Verify persistence to SQLite session store
    store = get_llm_state_store()
    session = store.get_investigation_session("CASE-TEST-02")
    assert session is not None
    assert session["wizard_state"]["investigation_goal"] == "Investigate credential theft and lateral movement via PsExec"
    assert session["wizard_state"]["hypothesis_draft"]["threat_hypothesis"] == data["threat_hypothesis"]


def test_plan_hypothesis_linux_ssh_blueprint_inference(client: TestClient):
    """Test that linux ssh compromise goals properly infer linux_ssh_compromise blueprint."""
    resp = client.post(
        "/api/agent/plan-hypothesis",
        json={
            "case_id": "CASE-LINUX-01",
            "investigation_goal": "Investigate unauthorized Linux SSH key injection and root compromise",
            "findings": [],
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["recommended_blueprint"] == "linux_ssh_compromise"


def test_plan_hypothesis_hitl_pause_and_plan_steps(client: TestClient):
    """Scope 3B HITL Pause: verify auto_approve=False returns PAUSED_AWAITING_APPROVAL and planned steps."""
    resp = client.post(
        "/api/agent/plan-hypothesis",
        json={
            "case_id": "CASE-PAUSE-01",
            "investigation_goal": "Detect persistence via registry run keys and scheduled tasks",
            "auto_approve": False,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "PAUSED_AWAITING_APPROVAL"
    assert data["auto_approve"] is False
    assert len(data["plan_steps"]) > 0
    assert any(s["tactic_id"] == "TA0003" for s in data["plan_steps"])
    assert data["report"] is None


def test_plan_hypothesis_scoped_filters_attached(client: TestClient):
    """Scope 4B: verify ScopedFilterParams and SCOPED_IOC_TIMELINE_SWEEP attached for goal queries."""
    resp = client.post(
        "/api/agent/plan-hypothesis",
        json={
            "case_id": "CASE-SCOPED-01",
            "investigation_goal": "Find TeamViewer activity between 02:00 and 04:00 UTC",
            "auto_approve": True,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["scoped_filters"] is not None
    assert "teamviewer" in data["scoped_filters"]["keywords_or_iocs"]
    assert data["scoped_filters"]["time_start_utc"] is not None
    assert data["scoped_filters"]["time_end_utc"] is not None

    # Verify sweep step attached
    step_ids = [s["step_id"] for s in data["plan_steps"]]
    assert "step_scoped_ioc_timeline_sweep" in step_ids

