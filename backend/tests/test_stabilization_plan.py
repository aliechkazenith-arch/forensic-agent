"""Stabilization Plan Tests - In-Browser Upload, Top-Level SQLite Session Store & POST /api/workflow/run.

Standards:
- Verifies SQLite session store persistence across restarts for wizard and workflow state.
- Verifies GET and POST /api/session/{case_id} REST endpoints.
- Verifies POST /api/workflow/run executes DAG workflows end-to-end and synchronizes execution state to SQLite.
- Verifies in-browser streaming evidence upload without OS desktop dialogs.
"""
from __future__ import annotations

import io
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.app.agent.provider_registry import reset_provider_registry
from backend.app.db.sqlite_store import LLMStateStore, reset_llm_state_store
from backend.app.main import app
from backend.app.models.workflow import (
    WorkflowDefinition,
    WorkflowEdge,
    WorkflowNode,
)


@pytest.fixture(autouse=True)
def clean_state(tmp_path: Path):
    """Ensure clean SQLite session store and provider registry before and after each test."""
    db_file = tmp_path / "test_session_store.db"
    store = LLMStateStore(db_path=db_file)
    reset_llm_state_store(store)
    reset_provider_registry()
    yield store
    reset_llm_state_store()
    reset_provider_registry()


@pytest.fixture
def client() -> TestClient:
    """Create FastAPI test client."""
    return TestClient(app)


def test_sqlite_session_store_lifecycle_and_restart(tmp_path: Path):
    """Verify investigation session persists across database reconnections."""
    db_file = tmp_path / "investigation_lifecycle.db"

    # 1. Save session using store instance 1
    store1 = LLMStateStore(db_path=db_file)
    wiz = {
        "mode": "offline",
        "offline_path": "C:\\evidence\\triage01.zip",
        "artifact_type": "capsule",
        "is_zero_copy": False,
    }
    wf = {
        "selected_blueprint_key": "windows_intrusion",
        "completed_nodes": ["node_1", "node_2"],
    }
    saved = store1.save_investigation_session(
        case_id="CASE-STAB-01",
        wizard_state=wiz,
        workflow_state=wf,
        active_tab="canvas",
    )
    assert saved["case_id"] == "CASE-STAB-01"
    assert saved["active_tab"] == "canvas"
    store1.close()

    # 2. Re-open store instance 2 on the same SQLite database file
    store2 = LLMStateStore(db_path=db_file)
    fetched = store2.get_investigation_session("CASE-STAB-01")
    assert fetched is not None
    assert fetched["case_id"] == "CASE-STAB-01"
    assert fetched["wizard_state"]["mode"] == "offline"
    assert fetched["wizard_state"]["artifact_type"] == "capsule"
    assert fetched["workflow_state"]["completed_nodes"] == ["node_1", "node_2"]
    assert fetched["active_tab"] == "canvas"
    store2.close()


def test_api_session_endpoints(client: TestClient):
    """Verify GET, POST, and LIST /api/session endpoints."""
    case_id = "CASE-SESSION-API-01"

    # 1. GET non-existent session returns initialized default template
    resp_init = client.get(f"/api/session/{case_id}")
    assert resp_init.status_code == 200
    init_data = resp_init.json()
    assert init_data["case_id"] == case_id
    assert init_data["active_tab"] == "wizard"
    assert "offline" in init_data["wizard_state"]["mode"]

    # 2. POST updates session in SQLite
    wiz_payload = {
        "mode": "online",
        "online_host": "10.0.0.50",
        "online_port": 22,
        "is_zero_copy": False,
    }
    wf_payload = {
        "selected_blueprint_key": "linux_ssh_compromise",
        "completed_nodes": ["node_input"],
    }
    resp_save = client.post(
        f"/api/session/{case_id}",
        json={
            "wizard_state": wiz_payload,
            "workflow_state": wf_payload,
            "active_tab": "canvas",
        },
    )
    assert resp_save.status_code == 200
    saved_data = resp_save.json()
    assert saved_data["case_id"] == case_id
    assert saved_data["active_tab"] == "canvas"
    assert saved_data["wizard_state"]["online_host"] == "10.0.0.50"

    # 3. Subsequent GET returns persisted session
    resp_get = client.get(f"/api/session/{case_id}")
    assert resp_get.status_code == 200
    get_data = resp_get.json()
    assert get_data["wizard_state"]["online_host"] == "10.0.0.50"
    assert get_data["workflow_state"]["selected_blueprint_key"] == "linux_ssh_compromise"

    # 4. List sessions
    resp_list = client.get("/api/session")
    assert resp_list.status_code == 200
    all_sessions = resp_list.json()
    case_ids = [s["case_id"] for s in all_sessions]
    assert case_id in case_ids


def test_post_workflow_run_end_to_end_and_sqlite_sync(client: TestClient):
    """Verify POST /api/workflow/run executes DAG and synchronizes execution state to SQLite."""
    case_id = "CASE-WORKFLOW-RUN-01"

    wf = WorkflowDefinition(
        workflow_id="wf_stabilization_run",
        name="Stabilization Run Test",
        nodes=[
            WorkflowNode(
                id="node_input",
                name="Evidence Input",
                type="evidence_input",
            ),
            WorkflowNode(
                id="node_evtx",
                name="Parse EVTX",
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

    # 1. Execute via POST /api/workflow/run (singular)
    resp = client.post(
        "/api/workflow/run",
        json={"case_id": case_id, "workflow": wf.model_dump()},
    )
    assert resp.status_code == 200, resp.text
    run_state = resp.json()
    assert "node_input" in run_state["completed_nodes"]
    assert "node_evtx" in run_state["completed_nodes"]
    assert "node_report" in run_state["completed_nodes"]
    assert run_state["report"] is not None

    # 2. Verify that execution automatically persisted in SQLite session store
    resp_session = client.get(f"/api/session/{case_id}")
    assert resp_session.status_code == 200
    session_data = resp_session.json()
    assert session_data["case_id"] == case_id
    assert session_data["active_tab"] == "canvas"
    wf_saved = session_data["workflow_state"]
    assert "node_report" in wf_saved["completed_nodes"]
    assert wf_saved["last_run_utc"] != ""


def test_post_workflows_run_plural_alias(client: TestClient):
    """Verify POST /api/workflows/run plural alias executes identically."""
    case_id = "CASE-WORKFLOWS-PLURAL-01"

    wf = WorkflowDefinition(
        workflow_id="wf_plural_test",
        name="Plural Run Test",
        nodes=[
            WorkflowNode(
                id="node_input",
                name="Evidence Input",
                type="evidence_input",
            ),
        ],
        edges=[],
    )

    resp = client.post(
        "/api/workflows/run",
        json={"case_id": case_id, "workflow": wf.model_dump()},
    )
    assert resp.status_code == 200
    assert "node_input" in resp.json()["completed_nodes"]


def test_in_browser_file_upload_without_desktop_dialog(client: TestClient):
    """Verify in-browser multipart file upload streams cleanly without desktop dialogs."""
    content = b"FORENSIC_RAW_EVIDENCE_STREAM_DATA_BYTES"
    resp = client.post(
        "/api/intake/upload",
        files={"file": ("incident_triage.evtx", io.BytesIO(content), "application/octet-stream")},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["filename"] == "incident_triage.evtx"
    assert data["detected_artifact_type"] == "evtx"
    assert len(data["sha256"]) == 64
    assert len(data["sha512"]) == 128
    assert Path(data["file_path"]).exists()
