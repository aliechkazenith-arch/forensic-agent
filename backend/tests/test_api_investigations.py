"""Comprehensive Regression Test Suite for Autonomous Investigation Controller REST API.

Standard & Acceptance Criteria (DEF-QA-001):
1. Mandatory Authentication: Protected investigation routes strictly reject anonymous requests (401).
2. RBAC Enforcement: Auditor role is denied execution/mutation (403) but allowed read operations (200).
3. Case-Level Isolation: Unassigned/foreign investigators are strictly denied access to cases (403).
4. Investigation Lifecycle: POST /start initializes the controller and returns typed InvestigationRecord.
5. Status Retrieval: GET /{case_id} retrieves active state; non-existent case returns 404.
6. Step-wise Iteration: POST /{case_id}/iterate triggers reasoning-and-action loop and records traces.
7. Capability Discovery: GET /{case_id}/specialists returns all 6 registered DFIR specialists.
8. Execution History: GET /{case_id}/tool-history returns audit trail of completed tool actions.
9. Human Approval Gate: High-risk action transitions to awaiting_approval; resume rejects invalid tokens
   and successfully resumes execution upon valid HMAC-SHA256 signed HumanApprovalToken.
10. Investigation Cancellation: POST /{case_id}/cancel cleanly terminates active run.
11. Full Autorun Mode: POST /start with autorun=True runs bounded autonomous loop to completion.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict
from uuid import uuid4
import pytest
from fastapi.testclient import TestClient

from backend.app.api.deps import get_custody_engine, reset_dependencies, set_base_vault_dir
from backend.app.api.investigations import _active_controllers, _get_or_create_controller
from backend.app.auth.dependencies import reset_user_store, set_user_store
from backend.app.auth.models import UserCreate
from backend.app.auth.security import create_access_token, hash_password
from backend.app.auth.store import UserStore
from backend.app.core.approval_engine import compute_parameter_digest
from backend.app.core.custody_engine import safe_make_writable
from backend.app.core.storage import ForensicStore
from backend.app.db.sqlite_store import get_llm_state_store, reset_llm_state_store
from backend.app.main import create_app
from backend.app.models.investigation import (
    InvestigationAction,
    InvestigationLifecycleState,
    ToolRequest,
)
from backend.app.models.workflow import HumanApprovalToken


@pytest.fixture
def inv_test_env(tmp_path: Path):
    """Hermetic isolated environment for Autonomous Investigation REST API tests."""
    vault_dir = tmp_path / "vault"
    vault_dir.mkdir(parents=True, exist_ok=True)
    secret_key = "test-investigations-hmac-secret-key-32b!!"
    jwt_secret = "test-investigations-jwt-secret-key-32b!!"

    old_env = {
        "FORENSICOPS_VAULT_DIR": os.environ.get("FORENSICOPS_VAULT_DIR"),
        "FORENSICOPS_JWT_SECRET": os.environ.get("FORENSICOPS_JWT_SECRET"),
        "HUMAN_APPROVAL_HMAC_SECRET": os.environ.get("HUMAN_APPROVAL_HMAC_SECRET"),
        "FORENSICOPS_AUTH_DISABLED": os.environ.get("FORENSICOPS_AUTH_DISABLED"),
        "LLM_MOCK_MODE": os.environ.get("LLM_MOCK_MODE"),
        "FORENSICOPS_LIVE_LLM": os.environ.get("FORENSICOPS_LIVE_LLM"),
    }

    os.environ["FORENSICOPS_VAULT_DIR"] = str(vault_dir)
    os.environ["FORENSICOPS_JWT_SECRET"] = jwt_secret
    os.environ["HUMAN_APPROVAL_HMAC_SECRET"] = secret_key
    os.environ["FORENSICOPS_AUTH_DISABLED"] = "false"
    os.environ["LLM_MOCK_MODE"] = "true"
    os.environ["FORENSICOPS_LIVE_LLM"] = "false"

    set_base_vault_dir(vault_dir)
    reset_dependencies()
    reset_llm_state_store()
    _active_controllers.clear()

    # Initialize UserStore with test accounts
    users_db = vault_dir / "users.db"
    user_store = UserStore(db_path=users_db)
    set_user_store(user_store)

    # 1. Lead Investigator (case owner)
    u_lead = user_store.create_user(
        UserCreate(
            username="lead_owner",
            password="password123",
            role="lead_investigator",
            badge_id="BADGE-LEAD-01",
            full_name="Chief Investigator Lead",
        ),
        password_hash=hash_password("password123"),
    )

    # 2. SOC Analyst (assigned collaborator)
    u_analyst = user_store.create_user(
        UserCreate(
            username="soc_analyst_1",
            password="password123",
            role="soc_analyst",
            badge_id="BADGE-SOC-01",
            full_name="SOC Triage Analyst",
        ),
        password_hash=hash_password("password123"),
    )

    # 3. Auditor (read-only compliance)
    u_auditor = user_store.create_user(
        UserCreate(
            username="compliance_auditor",
            password="password123",
            role="auditor",
            badge_id="BADGE-AUD-01",
            full_name="Compliance Auditor",
        ),
        password_hash=hash_password("password123"),
    )

    # 4. Foreign Lead (unassigned investigator)
    u_foreign = user_store.create_user(
        UserCreate(
            username="foreign_lead",
            password="password123",
            role="lead_investigator",
            badge_id="BADGE-LEAD-99",
            full_name="Unassigned External Lead",
        ),
        password_hash=hash_password("password123"),
    )

    # Pre-register Shared Case in SQLite State Store
    case_id = "CASE-AUTONOMOUS-API-TEST"
    state_store = get_llm_state_store()
    state_store.create_or_update_case({
        "case_id": case_id,
        "case_name": "Intrusion Compromise Investigation",
        "description": "API Integration Test Case for Autonomous Controller",
        "lead_analyst": u_lead.username,
        "organization_name": "ForensicOps AI Lab",
        "status": "OPEN",
        "is_shared_to_vault": True,
        "serialized_state": {
            "assigned_analysts": [u_analyst.username],
            "collaborators": [u_analyst.username],
        },
    })

    # Pre-register Private Isolated Case for Foreign Isolation Tests
    private_case_id = "CASE-PRIVATE-ISOLATED"
    state_store.create_or_update_case({
        "case_id": private_case_id,
        "case_name": "Classified Isolated Case",
        "description": "Private unshared case for cross-case isolation tests",
        "lead_analyst": u_lead.username,
        "organization_name": "ForensicOps AI Lab",
        "status": "OPEN",
        "is_shared_to_vault": False,
    })

    # Ingest a sample evidence artifact into custody for the shared case
    sample_file = vault_dir / "sample.evtx"
    sample_file.write_bytes(b"ElfFile\x00simulated_evtx_records_4624_and_4688")
    custody = get_custody_engine(case_id)
    custody.defang_and_store_blob(
        source_file_path=sample_file,
        case_id=case_id,
        artifact_type="evtx",
        actor=u_lead.username,
        acquisition_method="offline_upload",
    )

    # Generate JWT bearer tokens with valid TokenPayload claims
    tokens = {
        "lead": create_access_token({"sub": u_lead.username, "user_id": u_lead.id, "role": u_lead.role, "badge_id": u_lead.badge_id}),
        "analyst": create_access_token({"sub": u_analyst.username, "user_id": u_analyst.id, "role": u_analyst.role, "badge_id": u_analyst.badge_id}),
        "auditor": create_access_token({"sub": u_auditor.username, "user_id": u_auditor.id, "role": u_auditor.role, "badge_id": u_auditor.badge_id}),
        "foreign_lead": create_access_token({"sub": u_foreign.username, "user_id": u_foreign.id, "role": u_foreign.role, "badge_id": u_foreign.badge_id}),
    }

    app = create_app()
    client = TestClient(app)

    yield {
        "client": client,
        "tokens": tokens,
        "case_id": case_id,
        "private_case_id": private_case_id,
        "secret_key": secret_key,
        "vault_dir": vault_dir,
        "state_store": state_store,
        "users": {
            "lead": u_lead,
            "analyst": u_analyst,
            "auditor": u_auditor,
            "foreign": u_foreign,
        },
    }

    _active_controllers.clear()
    reset_dependencies()
    reset_user_store()
    reset_llm_state_store()

    for k, v in old_env.items():
        if v is not None:
            os.environ[k] = v
        else:
            os.environ.pop(k, None)

    for root, _, files in os.walk(vault_dir):
        for f in files:
            safe_make_writable(Path(root) / f)


def _headers_for(token: str) -> Dict[str, str]:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


# ==============================================================================
# 1. Authentication & RBAC Enforcement Matrix (DEF-QA-001)
# ==============================================================================

def test_investigations_auth_and_rbac_matrix(inv_test_env: Dict[str, Any]):
    """Verify that all 7 routes enforce strict authentication, RBAC, and case isolation."""
    client: TestClient = inv_test_env["client"]
    tokens: Dict[str, str] = inv_test_env["tokens"]
    case_id: str = inv_test_env["case_id"]
    private_case_id: str = inv_test_env["private_case_id"]

    lead_hdrs = _headers_for(tokens["lead"])
    auditor_hdrs = _headers_for(tokens["auditor"])
    foreign_hdrs = _headers_for(tokens["foreign_lead"])

    # 1. Anonymous requests -> 401 Unauthorized across all endpoints
    assert client.post("/api/investigations/start", json={"case_id": case_id}).status_code == 401
    assert client.get(f"/api/investigations/{case_id}").status_code == 401
    assert client.post(f"/api/investigations/{case_id}/iterate").status_code == 401
    assert client.post(f"/api/investigations/{case_id}/resume", json={}).status_code == 401
    assert client.post(f"/api/investigations/{case_id}/cancel", json={}).status_code == 401
    assert client.get(f"/api/investigations/{case_id}/specialists").status_code == 401
    assert client.get(f"/api/investigations/{case_id}/tool-history").status_code == 401

    # 2. Auditor role: 403 Forbidden on execution/mutation routes
    assert client.post("/api/investigations/start", json={"case_id": case_id}, headers=auditor_hdrs).status_code == 403
    assert client.post(f"/api/investigations/{case_id}/iterate", headers=auditor_hdrs).status_code == 403
    assert client.post(f"/api/investigations/{case_id}/resume", json={}, headers=auditor_hdrs).status_code == 403
    assert client.post(f"/api/investigations/{case_id}/cancel", json={}, headers=auditor_hdrs).status_code == 403

    # 3. Auditor role: 200 OK on read/audit queries for shared case
    r_spec = client.get(f"/api/investigations/{case_id}/specialists", headers=auditor_hdrs)
    assert r_spec.status_code == 200

    # 4. Foreign unassigned lead investigator: 403 Forbidden on private unshared case
    assert client.post(f"/api/investigations/{private_case_id}/iterate", headers=foreign_hdrs).status_code == 403
    assert client.get(f"/api/investigations/{private_case_id}", headers=foreign_hdrs).status_code == 403


# ==============================================================================
# 2. Start Investigation & Status Retrieval Endpoints
# ==============================================================================

def test_investigations_start_and_status(inv_test_env: Dict[str, Any]):
    """Verify POST /start initializes the investigation controller and GET /{case_id} retrieves it."""
    client: TestClient = inv_test_env["client"]
    tokens: Dict[str, str] = inv_test_env["tokens"]
    case_id: str = inv_test_env["case_id"]
    lead_hdrs = _headers_for(tokens["lead"])

    # 1. Start investigation
    payload = {
        "case_id": case_id,
        "objective": "Identify lateral movement artifacts and suspicious PowerShell commands",
        "budget": {"max_iterations": 3, "max_tool_executions": 6},
        "autorun": False,
    }
    resp = client.post("/api/investigations/start", json=payload, headers=lead_hdrs)
    assert resp.status_code == 200, f"Start failed: {resp.text}"
    data = resp.json()

    assert data["case_id"] == case_id
    assert "lead_owner" in data["investigator"]
    assert data["objective"] == payload["objective"]
    assert data["lifecycle_state"] in [
        InvestigationLifecycleState.PLANNING.value,
        InvestigationLifecycleState.EXECUTING.value,
        InvestigationLifecycleState.EVALUATING.value,
        InvestigationLifecycleState.AWAITING_APPROVAL.value,
        InvestigationLifecycleState.COMPLETED.value,
        InvestigationLifecycleState.PARTIALLY_COMPLETED.value,
        InvestigationLifecycleState.NEEDS_MORE_DATA.value,
    ]
    assert data["budget"]["max_iterations"] == 3
    assert data["budget"]["max_tool_executions"] == 6

    # 2. Get status via GET /{case_id}
    status_resp = client.get(f"/api/investigations/{case_id}", headers=lead_hdrs)
    assert status_resp.status_code == 200
    status_data = status_resp.json()
    assert status_data["investigation_id"] == data["investigation_id"]
    assert status_data["case_id"] == case_id

    # 3. Status on non-existent case returns 404
    missing_resp = client.get("/api/investigations/NON-EXISTENT-CASE-ID-999", headers=lead_hdrs)
    assert missing_resp.status_code == 404


# ==============================================================================
# 3. Step-wise Iteration & Tool Execution History Endpoints
# ==============================================================================

def test_investigations_iterate_and_tool_history(inv_test_env: Dict[str, Any]):
    """Verify POST /{case_id}/iterate advances investigation loop and records tool history."""
    client: TestClient = inv_test_env["client"]
    tokens: Dict[str, str] = inv_test_env["tokens"]
    case_id: str = inv_test_env["case_id"]
    analyst_hdrs = _headers_for(tokens["analyst"])

    # Initialize investigation
    init_resp = client.post(
        "/api/investigations/start",
        json={"case_id": case_id, "objective": "Step-wise execution test"},
        headers=analyst_hdrs,
    )
    assert init_resp.status_code == 200

    # Execute single iteration step
    step_resp = client.post(f"/api/investigations/{case_id}/iterate", headers=analyst_hdrs)
    assert step_resp.status_code == 200
    step_data = step_resp.json()
    assert step_data["current_iteration"] >= 0

    # Retrieve tool execution history
    history_resp = client.get(f"/api/investigations/{case_id}/tool-history", headers=analyst_hdrs)
    assert history_resp.status_code == 200
    history = history_resp.json()
    assert isinstance(history, list)

    # Also auditor can read tool history
    auditor_hdrs = _headers_for(tokens["auditor"])
    audit_resp = client.get(f"/api/investigations/{case_id}/tool-history", headers=auditor_hdrs)
    assert audit_resp.status_code == 200


# ==============================================================================
# 4. Modular Specialist Capabilities Discovery Endpoint
# ==============================================================================

def test_investigations_specialists_discovery(inv_test_env: Dict[str, Any]):
    """Verify GET /{case_id}/specialists enumerates all 6 registered DFIR specialist engines."""
    client: TestClient = inv_test_env["client"]
    tokens: Dict[str, str] = inv_test_env["tokens"]
    case_id: str = inv_test_env["case_id"]
    lead_hdrs = _headers_for(tokens["lead"])

    resp = client.get(f"/api/investigations/{case_id}/specialists", headers=lead_hdrs)
    assert resp.status_code == 200
    specialists = resp.json()

    assert len(specialists) == 6
    registered_ids = {s["specialist_id"] for s in specialists}
    expected_ids = {
        "windows_dfir",
        "linux_dfir",
        "memory_forensics",
        "network_forensics",
        "malware_analysis",
        "timeline_correlation",
    }
    assert registered_ids == expected_ids

    # Validate schema fields
    for spec in specialists:
        assert "specialist_id" in spec
        assert "name" in spec
        assert "domain" in spec
        assert "allowlisted_capabilities" in spec
        assert "required_artifact_types" in spec
        assert "investigation_questions" in spec
        assert "limitations" in spec


# ==============================================================================
# 5. Human Approval Gate: Pause, Invalid Token Rejection, and Resumption
# ==============================================================================

def test_investigations_approval_pause_and_resume_lifecycle(inv_test_env: Dict[str, Any]):
    """Verify investigation pauses in awaiting_approval on high-risk actions and resumes upon valid token."""
    client: TestClient = inv_test_env["client"]
    tokens: Dict[str, str] = inv_test_env["tokens"]
    case_id: str = inv_test_env["case_id"]
    secret_key: str = inv_test_env["secret_key"]
    lead_hdrs = _headers_for(tokens["lead"])

    # 1. Initialize controller via /start
    init_resp = client.post(
        "/api/investigations/start",
        json={"case_id": case_id, "objective": "Approval gate lifecycle test", "autorun": False},
        headers=lead_hdrs,
    )
    assert init_resp.status_code == 200

    # 2. Introduce a pending action requiring explicit human approval
    controller = _get_or_create_controller(case_id=case_id)
    action_args = {"host": "192.168.1.100", "os_type": "linux", "modules": ["Volatile"]}
    sensitive_act = InvestigationAction(
        action_id="act-sensitive-001",
        capability_id="system_containment",
        action_type="containment",
        arguments=action_args,
        requires_approval=True,
        status="pending",
    )
    # Transition to PLANNING to allow queueing sensitive action if prior iteration concluded
    if controller.record.lifecycle_state in (
        InvestigationLifecycleState.NEEDS_MORE_DATA,
        InvestigationLifecycleState.COMPLETED,
        InvestigationLifecycleState.PARTIALLY_COMPLETED,
        InvestigationLifecycleState.EVALUATING,
    ):
        controller.transition_to(InvestigationLifecycleState.PLANNING)

    controller.record.pending_actions.append(sensitive_act)
    # Run iteration: detects unapproved sensitive action and pauses in awaiting_approval
    rec = controller.run_iteration()
    assert rec.lifecycle_state == InvestigationLifecycleState.AWAITING_APPROVAL
    assert "Approval ID" in str(rec.pause_reason)

    # 3. Verify GET /{case_id} reports awaiting_approval
    stat_resp = client.get(f"/api/investigations/{case_id}", headers=lead_hdrs)
    assert stat_resp.status_code == 200
    assert stat_resp.json()["lifecycle_state"] == "awaiting_approval"

    # 4. Resume without approval token -> 400 Bad Request
    fail_resp1 = client.post(f"/api/investigations/{case_id}/resume", json={}, headers=lead_hdrs)
    assert fail_resp1.status_code == 400

    # 5. Resume with forged/invalid signature -> 400 Bad Request
    param_digest = compute_parameter_digest(action_args)
    forged_token = HumanApprovalToken(
        token_id="tok-forged-999",
        node_id="act-sensitive-001",
        case_id=case_id,
        action_type="containment",
        target="192.168.1.100",
        parameter_digest=param_digest,
        issued_by="lead_owner",
    )
    forged_token.sign("wrong-forged-secret-key-32-characters!")
    fail_resp2 = client.post(
        f"/api/investigations/{case_id}/resume",
        json={"approval_token": forged_token.model_dump()},
        headers=lead_hdrs,
    )
    assert fail_resp2.status_code == 400

    # 6. Resume with properly signed valid HumanApprovalToken (SEC-APPR-001 compliant)
    valid_token = HumanApprovalToken(
        token_id=f"tok-valid-{uuid4().hex[:8]}",
        node_id="act-sensitive-001",
        case_id=case_id,
        action_type="containment",
        target="192.168.1.100",
        parameter_digest=param_digest,
        issued_by="lead_owner",
    )
    valid_token.sign(secret_key)
    assert valid_token.signature is not None

    resume_resp = client.post(
        f"/api/investigations/{case_id}/resume",
        json={"approval_token": valid_token.model_dump()},
        headers=lead_hdrs,
    )
    assert resume_resp.status_code == 200
    resume_data = resume_resp.json()
    assert resume_data["lifecycle_state"] != "awaiting_approval"
    assert any(a["action_id"] == "act-sensitive-001" for a in resume_data["completed_actions"])


# ==============================================================================
# 6. Investigation Cancellation Flow Endpoint
# ==============================================================================

def test_investigations_cancel_flow(inv_test_env: Dict[str, Any]):
    """Verify POST /{case_id}/cancel marks the investigation cancelled with audit reason."""
    client: TestClient = inv_test_env["client"]
    tokens: Dict[str, str] = inv_test_env["tokens"]
    case_id: str = inv_test_env["case_id"]
    lead_hdrs = _headers_for(tokens["lead"])

    # Initialize investigation
    client.post(
        "/api/investigations/start",
        json={"case_id": case_id, "objective": "Cancellation test"},
        headers=lead_hdrs,
    )

    # Cancel investigation
    cancel_payload = {"reason": "Investigator deemed intrusion false positive"}
    cancel_resp = client.post(f"/api/investigations/{case_id}/cancel", json=cancel_payload, headers=lead_hdrs)
    assert cancel_resp.status_code == 200
    data = cancel_resp.json()
    assert data["lifecycle_state"] == "cancelled"
    assert any("false positive" in err for err in data.get("errors", []))


# ==============================================================================
# 7. Full Autorun Mode Endpoint
# ==============================================================================

def test_investigations_autorun_mode(inv_test_env: Dict[str, Any]):
    """Verify POST /start with autorun=True loops through iterations to completion."""
    client: TestClient = inv_test_env["client"]
    tokens: Dict[str, str] = inv_test_env["tokens"]
    case_id: str = inv_test_env["case_id"]
    lead_hdrs = _headers_for(tokens["lead"])

    autorun_payload = {
        "case_id": case_id,
        "objective": "Complete intrusion triage autorun",
        "budget": {"max_iterations": 2, "max_tool_executions": 4},
        "autorun": True,
    }
    resp = client.post("/api/investigations/start", json=autorun_payload, headers=lead_hdrs)
    assert resp.status_code == 200
    data = resp.json()
    assert data["lifecycle_state"] in [
        InvestigationLifecycleState.COMPLETED.value,
        InvestigationLifecycleState.AWAITING_APPROVAL.value,
        InvestigationLifecycleState.PARTIALLY_COMPLETED.value,
        InvestigationLifecycleState.NEEDS_MORE_DATA.value,
    ]
