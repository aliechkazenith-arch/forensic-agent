"""Phase 14.1-R1 — Targeted Approval Security Regression & Verification Test Suite.

Directly tests the resolution of:
- AUDIT-P14-01: Two-Person Rule identity representation bypass.
- AUDIT-P14-02: Approval token issuance from incomplete or invalid approval records.
- AUDIT-P14-03: LangGraph bypass of persistent, one-time approval-token consumption.
"""
import os
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from backend.app.agent.graph import (
    ForensicOpsWorkflowEngine,
    WorkflowDefinition,
    WorkflowEdge,
    WorkflowExecutionState,
    WorkflowNode,
)
from backend.app.agent.investigation_controller import InvestigationController
from backend.app.api.deps import (
    get_approval_engine,
    get_workflow_engine,
    reset_dependencies,
    set_base_vault_dir,
)
from backend.app.auth.dependencies import get_user_store, set_user_store
from backend.app.auth.models import UserCreate, UserRead
from backend.app.auth.security import create_access_token, hash_password
from backend.app.auth.store import UserStore
from backend.app.core.approval_engine import (
    ApprovalEngine,
    compute_parameter_digest,
)
from backend.app.core.custody_engine import CustodyEngine
from backend.app.core.exceptions import (
    ForensicOpsError,
    UnauthorizedCollectorExecutionError,
)
from backend.app.core.storage import ForensicStore
from backend.app.db.sqlite_store import LLMStateStore, get_llm_state_store, reset_llm_state_store
from backend.app.main import create_app
from backend.app.models.approval import ApprovalRequest, ApprovalStatus
from backend.app.models.investigation import ToolRequest
from backend.app.models.workflow import HumanApprovalToken


@pytest.fixture
def r1_env(tmp_path: Path):
    """Hermetic test environment for Phase 14.1-R1 verification."""
    vault_dir = tmp_path / "vault"
    vault_dir.mkdir(parents=True, exist_ok=True)
    secret_key = "phase14-1-r1-hmac-secret-secure-32b!!"
    jwt_secret = "phase14-1-r1-jwt-secret-secure-32b!!"

    old_env = {
        "FORENSICOPS_VAULT_DIR": os.environ.get("FORENSICOPS_VAULT_DIR"),
        "FORENSICOPS_JWT_SECRET": os.environ.get("FORENSICOPS_JWT_SECRET"),
        "HUMAN_APPROVAL_HMAC_SECRET": os.environ.get("HUMAN_APPROVAL_HMAC_SECRET"),
        "FORENSICOPS_AUTH_DISABLED": os.environ.get("FORENSICOPS_AUTH_DISABLED"),
        "FORENSICOPS_ALLOW_PRIVATE_TARGETS": os.environ.get("FORENSICOPS_ALLOW_PRIVATE_TARGETS"),
    }

    os.environ["FORENSICOPS_VAULT_DIR"] = str(vault_dir)
    os.environ["FORENSICOPS_JWT_SECRET"] = jwt_secret
    os.environ["HUMAN_APPROVAL_HMAC_SECRET"] = secret_key
    os.environ["FORENSICOPS_AUTH_DISABLED"] = "false"
    os.environ["FORENSICOPS_ALLOW_PRIVATE_TARGETS"] = "true"

    set_base_vault_dir(vault_dir)
    reset_dependencies()
    reset_llm_state_store()

    users_db = vault_dir / "users.db"
    user_store = UserStore(db_path=users_db)
    set_user_store(user_store)

    alice = user_store.create_user(
        UserCreate(
            username="alice",
            password="password123",
            role="lead_investigator",
            badge_id="BADGE-ALICE-01",
            full_name="Alice Lead",
            account_type="human",
        ),
        password_hash=hash_password("password123"),
    )

    bob = user_store.create_user(
        UserCreate(
            username="bob",
            password="password123",
            role="soc_analyst",
            badge_id="BADGE-BOB-02",
            full_name="Bob Analyst",
            account_type="human",
        ),
        password_hash=hash_password("password123"),
    )

    inactive_user = user_store.create_user(
        UserCreate(
            username="charlie_inactive",
            password="password123",
            role="lead_investigator",
            badge_id="BADGE-CHARLIE-03",
            full_name="Charlie Inactive",
            account_type="human",
        ),
        password_hash=hash_password("password123"),
    )
    user_store.update_user_status(inactive_user.id, is_active=False)

    service_bot = user_store.create_user(
        UserCreate(
            username="copilot_daemon",
            password="password123",
            role="lead_investigator",
            badge_id="BADGE-SERVICE-01",
            full_name="Copilot Daemon",
            account_type="service_account",
        ),
        password_hash=hash_password("password123"),
    )

    yield {
        "vault_dir": vault_dir,
        "secret_key": secret_key,
        "jwt_secret": jwt_secret,
        "user_store": user_store,
        "alice": alice,
        "bob": bob,
        "inactive_user": inactive_user,
        "service_bot": service_bot,
    }

    reset_dependencies()
    reset_llm_state_store()
    for k, v in old_env.items():
        if v is not None:
            os.environ[k] = v
        else:
            os.environ.pop(k, None)


# ==============================================================================
# AUDIT-P14-01: Canonical Identity & Two-Person Rule Verification
# ==============================================================================

def test_p14_01_badge_in_username_self_approval_rejected(r1_env):
    """Verify that formatting username as 'alice (BADGE-001)' cannot bypass self-approval."""
    db_path = r1_env["vault_dir"] / "test_approvals.db"
    engine = ApprovalEngine(db_path=db_path, secret_key=r1_env["secret_key"])

    # 1. Request created with badge in investigator string (as InvestigationController previously did)
    req = engine.create_request(
        case_id="case-p14-01",
        requesting_investigator="alice (BADGE-ALICE-01)",
        action_type="containment",
        target="10.0.0.99",
        capability_id="isolate_host",
    )

    # 2. Alice tries to approve using her standard UserRead (username='alice')
    alice = r1_env["alice"]
    with pytest.raises(ForensicOpsError, match="Self-approval rejected"):
        engine.approve_request(req.approval_id, approver=alice)


def test_p14_01_principal_id_self_approval_rejected(r1_env):
    """Verify that canonical principal ID match strictly prevents self-approval."""
    db_path = r1_env["vault_dir"] / "test_approvals.db"
    engine = ApprovalEngine(db_path=db_path, secret_key=r1_env["secret_key"])
    alice = r1_env["alice"]

    req = engine.create_request(
        case_id="case-p14-01b",
        requesting_investigator="custom_display_name",
        requesting_principal_id=alice.id,
        action_type="containment",
        target="10.0.0.99",
        capability_id="isolate_host",
    )

    with pytest.raises(ForensicOpsError, match="Self-approval rejected"):
        engine.approve_request(req.approval_id, approver=alice)


def test_p14_01_service_account_and_daemon_approval_rejected(r1_env):
    """Verify service accounts, daemons, and non-human accounts cannot grant approvals."""
    db_path = r1_env["vault_dir"] / "test_approvals.db"
    engine = ApprovalEngine(db_path=db_path, secret_key=r1_env["secret_key"])
    alice = r1_env["alice"]
    bot = r1_env["service_bot"]

    req = engine.create_request(
        case_id="case-p14-01c",
        requesting_investigator="alice",
        requesting_principal_id=alice.id,
        action_type="containment",
        target="10.0.0.99",
        capability_id="isolate_host",
    )

    # Attempt approval with service account
    with pytest.raises(ForensicOpsError, match="Unauthorized approver"):
        engine.approve_request(req.approval_id, approver=bot)


def test_p14_01_investigation_controller_two_person_enforcement(r1_env):
    """Verify InvestigationController approval requests bind canonical identity and enforce two-person rule."""
    alice = r1_env["alice"]
    bob = r1_env["bob"]
    state_store = get_llm_state_store()

    controller = InvestigationController(
        case_id="case-ctrl-p14",
        investigator=alice.username,
        investigator_id=alice.id,
        investigator_badge=alice.badge_id,
        state_store=state_store,
        secret_key=r1_env["secret_key"],
    )
    from backend.app.models.investigation import InvestigationLifecycleState
    controller.transition_to(InvestigationLifecycleState.EVIDENCE_VALIDATION)
    controller.transition_to(InvestigationLifecycleState.PLANNING)

    # Submit containment action requiring human approval
    req_action = controller.submit_tool_request(
        ToolRequest(
            capability_id="isolate_host",
            arguments={"host": "192.168.1.50"},
            requires_approval=True,
            justification="Isolate infected endpoint",
        )
    )

    assert req_action.approval_id is not None
    appr_engine = controller.approval_engine
    stored_req = appr_engine.get_request(req_action.approval_id)
    assert stored_req is not None
    assert stored_req.requesting_principal_id == alice.id
    assert stored_req.requesting_badge_id == alice.badge_id

    # Alice self-approval MUST FAIL
    with pytest.raises(ForensicOpsError, match="Self-approval rejected"):
        appr_engine.approve_request(stored_req.approval_id, approver=alice)

    # Bob independent approval MUST SUCCEED
    result = appr_engine.approve_request(stored_req.approval_id, approver=bob)
    assert result.token is not None

    # Resuming controller with Bob's approved token MUST SUCCEED
    updated_rec = controller.approve_action(req_action.action_id, result.token)
    assert req_action.status == "approved"
    assert req_action.approval_token.consumed is True


# ==============================================================================
# AUDIT-P14-02: get_approved_token Integrity & Malformed DB Records
# ==============================================================================

def test_p14_02_null_approver_db_record_returns_none(r1_env):
    """Verify get_approved_token returns None when approving_investigator is NULL (no default fallback)."""
    db_path = r1_env["vault_dir"] / "test_approvals.db"
    engine = ApprovalEngine(db_path=db_path, secret_key=r1_env["secret_key"])
    now_dt = datetime.now(timezone.utc)
    exp_dt = now_dt + timedelta(minutes=15)

    with engine.state_store._conn as conn:
        conn.execute(
            """
            INSERT INTO approval_requests (
                approval_id, case_id, requesting_investigator, approving_investigator,
                action_type, target, capability_id, parameters_json, parameter_digest,
                policy_version, risk_level, reason, evidence_scope_json, status,
                created_at_utc, expires_at_utc, resolved_at_utc, token_id,
                consumed_at_utc, rejection_reason, requesting_principal_id, approving_principal_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "appr-null-appr", "case-p14-02", "alice", None,
                "containment", "10.0.0.1", "isolate_host", "{}", "sha256:abc",
                "1.0.0", "high", "test", "[]", "approved",
                now_dt.isoformat(), exp_dt.isoformat(), now_dt.isoformat(), "gate-null-appr",
                None, None, "user-alice", None
            ),
        )

    # Must return None instead of falling back to "lead_investigator"!
    token = engine.get_approved_token("appr-null-appr")
    assert token is None


def test_p14_02_self_approved_db_record_returns_none(r1_env):
    """Verify get_approved_token returns None if DB record has requester == approver."""
    db_path = r1_env["vault_dir"] / "test_approvals.db"
    engine = ApprovalEngine(db_path=db_path, secret_key=r1_env["secret_key"])
    now_dt = datetime.now(timezone.utc)
    exp_dt = now_dt + timedelta(minutes=15)

    with engine.state_store._conn as conn:
        conn.execute(
            """
            INSERT INTO approval_requests (
                approval_id, case_id, requesting_investigator, approving_investigator,
                action_type, target, capability_id, parameters_json, parameter_digest,
                policy_version, risk_level, reason, evidence_scope_json, status,
                created_at_utc, expires_at_utc, resolved_at_utc, token_id,
                consumed_at_utc, rejection_reason, requesting_principal_id, approving_principal_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "appr-self-corrupt", "case-p14-02b", "alice", "alice",
                "containment", "10.0.0.1", "isolate_host", "{}", "sha256:abc",
                "1.0.0", "high", "test", "[]", "approved",
                now_dt.isoformat(), exp_dt.isoformat(), now_dt.isoformat(), "gate-self-corrupt",
                None, None, "user-alice", "user-alice"
            ),
        )

    token = engine.get_approved_token("appr-self-corrupt")
    assert token is None


def test_p14_02_inactive_or_service_approver_returns_none(r1_env):
    """Verify get_approved_token returns None if approver is inactive or a service account in user_store."""
    db_path = r1_env["vault_dir"] / "test_approvals.db"
    engine = ApprovalEngine(db_path=db_path, secret_key=r1_env["secret_key"], user_store=r1_env["user_store"])
    now_dt = datetime.now(timezone.utc)
    exp_dt = now_dt + timedelta(minutes=15)

    # 1. Inactive approver
    with engine.state_store._conn as conn:
        conn.execute(
            """
            INSERT INTO approval_requests (
                approval_id, case_id, requesting_investigator, approving_investigator,
                action_type, target, capability_id, parameters_json, parameter_digest,
                policy_version, risk_level, reason, evidence_scope_json, status,
                created_at_utc, expires_at_utc, resolved_at_utc, token_id,
                consumed_at_utc, rejection_reason, requesting_principal_id, approving_principal_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "appr-inactive", "case-p14-02c", "alice", "charlie_inactive",
                "containment", "10.0.0.1", "isolate_host", "{}", "sha256:abc",
                "1.0.0", "high", "test", "[]", "approved",
                now_dt.isoformat(), exp_dt.isoformat(), now_dt.isoformat(), "gate-inactive",
                None, None, "user-alice", r1_env["inactive_user"].id
            ),
        )

    assert engine.get_approved_token("appr-inactive") is None

    # 2. Service account approver
    with engine.state_store._conn as conn:
        conn.execute(
            """
            INSERT INTO approval_requests (
                approval_id, case_id, requesting_investigator, approving_investigator,
                action_type, target, capability_id, parameters_json, parameter_digest,
                policy_version, risk_level, reason, evidence_scope_json, status,
                created_at_utc, expires_at_utc, resolved_at_utc, token_id,
                consumed_at_utc, rejection_reason, requesting_principal_id, approving_principal_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "appr-service-bot", "case-p14-02d", "alice", "copilot_daemon",
                "containment", "10.0.0.1", "isolate_host", "{}", "sha256:abc",
                "1.0.0", "high", "test", "[]", "approved",
                now_dt.isoformat(), exp_dt.isoformat(), now_dt.isoformat(), "gate-service-bot",
                None, None, "user-alice", r1_env["service_bot"].id
            ),
        )

    assert engine.get_approved_token("appr-service-bot") is None


# ==============================================================================
# AUDIT-P14-03: LangGraph Persistent Consumption & Replay Prevention
# ==============================================================================

def test_p14_03_langgraph_resume_persistently_consumes_token(r1_env):
    """Verify that resuming a LangGraph workflow persistently records the token in SQLite."""
    storage = ForensicStore()
    engine = ApprovalEngine(secret_key=r1_env["secret_key"])
    workflow_engine = ForensicOpsWorkflowEngine(
        storage=storage,
        secret_key=r1_env["secret_key"],
        approval_engine=engine,
    )

    # Simple workflow: evidence_input -> human_approval_gate -> report_compiler
    node1 = WorkflowNode(id="n1", type="evidence_input", name="Input")
    node2 = WorkflowNode(id="n2", type="human_approval_gate", name="Gate", config={"target": "10.0.0.1", "action_type": "containment"})
    node3 = WorkflowNode(id="n3", type="report_compiler", name="Report")

    edges = [
        WorkflowEdge(id="e1", source="n1", target="n2"),
        WorkflowEdge(id="e2", source="n2", target="n3"),
    ]
    workflow_def = WorkflowDefinition(workflow_id="wf-p14-03", name="Test Gate", nodes=[node1, node2, node3], edges=edges)

    # 1. Execute workflow: should pause at node 'n2'
    state = workflow_engine.execute_workflow(workflow_def, case_id="case-p14-03")
    assert state.is_paused is True
    assert state.pause_node_id == "n2"

    # 2. Issue a valid approval token (Alice requested, Bob approved)
    appr_req = engine.create_request(
        case_id="case-p14-03",
        requesting_investigator="alice",
        requesting_principal_id=r1_env["alice"].id,
        action_type="containment",
        target="10.0.0.1",
        capability_id="n2",
    )
    result = engine.approve_request(appr_req.approval_id, approver=r1_env["bob"])
    token = result.token

    # 3. Resume workflow with token
    resumed = workflow_engine.resume_workflow(workflow_def, state, token)
    assert resumed.is_paused is False
    assert "n2" in resumed.completed_nodes
    assert "n3" in resumed.completed_nodes

    # 4. Verify token is PERSISTENTLY recorded in consumed_approval_tokens table in SQLite
    cur = engine.state_store._conn.execute(
        "SELECT token_id, consumed_by FROM consumed_approval_tokens WHERE token_id = ?",
        (token.token_id,),
    )
    row = cur.fetchone()
    assert row is not None
    assert row[0] == token.token_id
    assert "langgraph_resume:n2" in row[1]

    # 5. Verify underlying approval request is marked 'consumed' in SQLite
    db_req = engine.get_request(appr_req.approval_id)
    assert db_req.status == ApprovalStatus.CONSUMED


def test_p14_03_langgraph_replay_rejected_same_workflow(r1_env):
    """Verify that replaying the same approval token in the same workflow is rejected."""
    storage = ForensicStore()
    engine = ApprovalEngine(secret_key=r1_env["secret_key"])
    workflow_engine = ForensicOpsWorkflowEngine(
        storage=storage,
        secret_key=r1_env["secret_key"],
        approval_engine=engine,
    )

    node1 = WorkflowNode(id="n1", type="evidence_input", name="Input")
    node2 = WorkflowNode(id="n2", type="human_approval_gate", name="Gate", config={"target": "10.0.0.1", "action_type": "containment"})
    workflow_def = WorkflowDefinition(workflow_id="wf-replay-1", name="Test Replay", nodes=[node1, node2], edges=[WorkflowEdge(id="e1", source="n1", target="n2")])

    state = workflow_engine.execute_workflow(workflow_def, case_id="case-replay-1")
    assert state.is_paused is True

    appr_req = engine.create_request(
        case_id="case-replay-1",
        requesting_investigator="alice",
        requesting_principal_id=r1_env["alice"].id,
        action_type="containment",
        target="10.0.0.1",
        capability_id="n2",
    )
    result = engine.approve_request(appr_req.approval_id, approver=r1_env["bob"])
    token = result.token

    # First resume: succeeds
    resumed = workflow_engine.resume_workflow(workflow_def, state, token)
    assert resumed.is_paused is False

    # Second resume attempt on a paused state with same token: MUST BE REJECTED
    paused_state_2 = WorkflowExecutionState(
        case_id="case-replay-1",
        workflow_id="wf-replay-1",
        is_paused=True,
        pause_node_id="n2",
    )
    with pytest.raises(ForensicOpsError, match="Replay detected"):
        workflow_engine.resume_workflow(workflow_def, paused_state_2, token)


def test_p14_03_cross_workflow_token_replay_rejected(r1_env):
    """Verify that a token consumed by Workflow A cannot be reused to resume Workflow B."""
    storage = ForensicStore()
    engine = ApprovalEngine(secret_key=r1_env["secret_key"])
    workflow_engine = ForensicOpsWorkflowEngine(
        storage=storage,
        secret_key=r1_env["secret_key"],
        approval_engine=engine,
    )

    node1 = WorkflowNode(id="n1", type="evidence_input", name="Input")
    node2 = WorkflowNode(id="gate_node", type="human_approval_gate", name="Gate", config={"target": "10.0.0.1", "action_type": "containment"})
    wf_a = WorkflowDefinition(workflow_id="wf-a", name="Workflow A", nodes=[node1, node2], edges=[WorkflowEdge(id="e1", source="n1", target="gate_node")])
    wf_b = WorkflowDefinition(workflow_id="wf-b", name="Workflow B", nodes=[node1, node2], edges=[WorkflowEdge(id="e1", source="n1", target="gate_node")])

    state_a = workflow_engine.execute_workflow(wf_a, case_id="case-cross-01")
    state_b = workflow_engine.execute_workflow(wf_b, case_id="case-cross-01")

    appr_req = engine.create_request(
        case_id="case-cross-01",
        requesting_investigator="alice",
        requesting_principal_id=r1_env["alice"].id,
        action_type="containment",
        target="10.0.0.1",
        capability_id="gate_node",
    )
    token = engine.approve_request(appr_req.approval_id, approver=r1_env["bob"]).token

    # Workflow A resumes successfully
    res_a = workflow_engine.resume_workflow(wf_a, state_a, token)
    assert res_a.is_paused is False

    # Workflow B attempts to reuse the same token: MUST BE REJECTED
    with pytest.raises(ForensicOpsError, match="Replay detected"):
        workflow_engine.resume_workflow(wf_b, state_b, token)


def test_p14_03_cross_subsystem_replay_controller_to_langgraph(r1_env):
    """Verify a token consumed by InvestigationController cannot be reused in LangGraph."""
    state_store = get_llm_state_store()
    storage = ForensicStore()
    appr_engine = ApprovalEngine(secret_key=r1_env["secret_key"])
    workflow_engine = ForensicOpsWorkflowEngine(
        storage=storage,
        secret_key=r1_env["secret_key"],
        approval_engine=appr_engine,
    )

    controller = InvestigationController(
        case_id="case-cross-sys",
        investigator="alice",
        investigator_id=r1_env["alice"].id,
        state_store=state_store,
        secret_key=r1_env["secret_key"],
        approval_engine=appr_engine,
    )
    from backend.app.models.investigation import InvestigationLifecycleState
    controller.transition_to(InvestigationLifecycleState.EVIDENCE_VALIDATION)
    controller.transition_to(InvestigationLifecycleState.PLANNING)

    # 1. Controller pauses on containment action
    action = controller.submit_tool_request(
        ToolRequest(
            capability_id="isolate_host",
            arguments={"host": "10.10.10.10"},
            requires_approval=True,
        )
    )

    # 2. Bob approves request
    token = appr_engine.approve_request(action.approval_id, approver=r1_env["bob"]).token

    # 3. Controller consumes token
    controller.approve_action(action.action_id, token)

    # 4. LangGraph attempts to resume with the same token: MUST BE REJECTED
    node1 = WorkflowNode(id="n1", type="evidence_input", name="Input")
    node2 = WorkflowNode(id="isolate_host", type="human_approval_gate", name="Gate", config={"target": "10.10.10.10", "action_type": "containment"})
    wf = WorkflowDefinition(workflow_id="wf-sys", name="Sys", nodes=[node1, node2], edges=[WorkflowEdge(id="e1", source="n1", target="isolate_host")])
    paused_state = WorkflowExecutionState(case_id="case-cross-sys", workflow_id="wf-sys", is_paused=True, pause_node_id="isolate_host")

    with pytest.raises(ForensicOpsError, match="Replay detected"):
        workflow_engine.resume_workflow(wf, paused_state, token)


def test_p14_03_api_resume_workflow_replay_returns_400(r1_env):
    """Verify POST /api/workflows/resume returns HTTP 400 when a replayed token is presented."""
    app = create_app()
    client = TestClient(app)

    token_bob = create_access_token(
        data={"sub": r1_env["bob"].username, "user_id": r1_env["bob"].id, "role": r1_env["bob"].role, "badge_id": r1_env["bob"].badge_id},
    )
    headers = {"Authorization": f"Bearer {token_bob}"}

    # Setup approval engine and request
    engine = get_approval_engine("case-api-resume")
    appr_req = engine.create_request(
        case_id="case-api-resume",
        requesting_investigator="alice",
        requesting_principal_id=r1_env["alice"].id,
        action_type="containment",
        target="10.0.0.55",
        capability_id="gate_api",
    )
    approved_token = engine.approve_request(appr_req.approval_id, approver=r1_env["bob"]).token

    node1 = {"id": "n1", "type": "evidence_input", "name": "In"}
    node2 = {"id": "gate_api", "type": "human_approval_gate", "name": "Gate", "config": {"target": "10.0.0.55", "action_type": "containment"}}
    wf_payload = {
        "workflow_id": "wf-api-resume",
        "name": "API Resume WF",
        "nodes": [node1, node2],
        "edges": [{"id": "e1", "source": "n1", "target": "gate_api"}],
    }
    state_payload = {
        "case_id": "case-api-resume",
        "workflow_id": "wf-api-resume",
        "is_paused": True,
        "pause_node_id": "gate_api",
    }

    # First resume: 200 OK
    resp1 = client.post(
        "/api/workflows/resume",
        json={
            "case_id": "case-api-resume",
            "workflow": wf_payload,
            "state": state_payload,
            "approval_token": approved_token.model_dump(),
        },
        headers=headers,
    )
    assert resp1.status_code == 200

    # Second resume with same token: 400 BAD REQUEST
    resp2 = client.post(
        "/api/workflows/resume",
        json={
            "case_id": "case-api-resume",
            "workflow": wf_payload,
            "state": state_payload,
            "approval_token": approved_token.model_dump(),
        },
        headers=headers,
    )
    assert resp2.status_code == 400
    assert "Replay detected" in resp2.json()["detail"]
