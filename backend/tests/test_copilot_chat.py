"""Unit & Integration Tests for DFIR Technical Co-Pilot Endpoint.

Standards:
- Context-grounded technical DFIR reasoning using active LLM provider.
- Optional send_system_prompt flag preservation.
- Nonce encapsulation of untrusted telemetry strings.
"""
from __future__ import annotations

import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from backend.app.main import create_app
from backend.app.models.findings import ForensicFinding
from backend.app.api.deps import get_storage
from backend.app.db.sqlite_store import get_llm_state_store, reset_llm_state_store
from backend.app.agent.provider_registry import reset_provider_registry


@pytest.fixture
def clean_env():
    """Ensure clean isolated state."""
    reset_llm_state_store()
    reset_provider_registry()
    yield
    reset_llm_state_store()
    reset_provider_registry()


@pytest.fixture
def client(clean_env) -> TestClient:
    app = create_app()
    return TestClient(app)


def test_copilot_chat_endpoint_with_evidence(client: TestClient):
    """Test DFIR Co-Pilot endpoint responds with evidence context awareness."""
    case_id = "CASE-COPILOT-01"

    # Pre-populate DuckDB finding
    storage = get_storage(case_id)
    storage.insert_findings(
        [
            ForensicFinding(
                case_id=case_id,
                source_artifact_id="art-evtx-01",
                artifact_type="evtx",
                tool_id="evtx_dump",
                timestamp_utc=datetime.now(timezone.utc).isoformat(),
                finding_id="find-evtx-logon",
                source_artifact_hash="c" * 64,
                category="LogonEvent",
                severity="high",
                summary="Type 10 remote interactive logon from untrusted external IP",
                user="admin",
                host="SRV-DC01",
            )
        ]
    )

    # Save a case in SQLite
    store = get_llm_state_store()
    store.create_or_update_case(
        {
            "case_id": case_id,
            "case_name": "Domain Controller Incident",
            "organization_name": "MegaCorp",
            "investigation_goal": "Investigate anomalous logon event on domain controller",
        }
    )

    resp = client.post(
        "/api/copilot/chat",
        json={
            "case_id": case_id,
            "message": "What initial artifacts should I inspect first?",
            "history": [],
            "send_system_prompt": True,
        },
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data["case_id"] == case_id
    assert "reply" in data
    assert len(data["reply"]) > 10
    assert "provider_id" in data


def test_copilot_chat_endpoint_without_system_prompt(client: TestClient):
    """Test Co-Pilot endpoint works when send_system_prompt is False (e.g. LM Studio custom preset)."""
    resp = client.post(
        "/api/copilot/chat",
        json={
            "case_id": "CASE-COPILOT-02",
            "message": "Explain MITRE ATT&CK technique T1059.001 PowerShell execution.",
            "send_system_prompt": False,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["reply"]) > 5


def test_copilot_chat_interactive_investigative_goal_execution(client: TestClient):
    """Test that investigative inquiry in chat actively executes playbooks and returns DFIR next steps."""
    case_id = "CASE-COPILOT-INTERACTIVE-01"

    # Seed finding
    storage = get_storage(case_id)
    storage.insert_findings(
        [
            ForensicFinding(
                case_id=case_id,
                source_artifact_id="art-reg-01",
                artifact_type="registry",
                tool_id="dissect",
                timestamp_utc=datetime.now(timezone.utc).isoformat(),
                finding_id="fnd-reg-run-persist",
                source_artifact_hash="d" * 64,
                category="PersistenceKey",
                severity="critical",
                summary="Run key persistence 'BackdoorService' pointing to C:\\Users\\Public\\updater.exe",
                user="SYSTEM",
                host="WORKSTATION-01",
            )
        ]
    )

    resp = client.post(
        "/api/copilot/chat",
        json={
            "case_id": case_id,
            "message": "Investigate persistence hooks on the endpoint",
            "history": [],
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["case_id"] == case_id
    assert "DFIR Lead Incident Briefing" in data["reply"]
    assert "fnd-reg-run-persist" in data["reply"]
    assert "TA0003" in data["executed_playbooks"]
    assert len(data["suggested_actions"]) >= 2
    assert data["threat_hypothesis"] is not None
    assert data["benign_hypothesis"] is not None


def test_copilot_chat_option_selection_flow(client: TestClient):
    """Test conversational iterative flow where user replies 'Do option 1'."""
    case_id = "CASE-COPILOT-OPTION-01"

    history = [
        {"role": "user", "content": "What should we do?"},
        {
            "role": "assistant",
            "content": (
                "Here are the recommended next steps:\n"
                "1. Audit Registry Run keys and scheduled tasks for persistence\n"
                "2. Correlate PCAP network sessions for C2 traffic\n"
            ),
        },
    ]

    resp = client.post(
        "/api/copilot/chat",
        json={
            "case_id": case_id,
            "message": "Do option 1",
            "history": history,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "DFIR Lead Incident Briefing" in data["reply"]
    assert len(data["suggested_actions"]) >= 1
