"""Phase 14.1 — Comprehensive Approval Architecture & Token Security Verification Suite.

Validates:
1. Genuine Pending-Request-to-Independent-Approval Lifecycle (Section 4).
2. Server-side Authenticated Identity Enforcement & Self-Approval Prevention (AUDIT-P13-02 / Section 5).
3. Strict Remote Collection Target Binding & No Conditional Verification (AUDIT-P13-01 / Section 6).
4. Transactional DB Consistency, No Swallowing Exceptions, Fail-Closed Behavior (AUDIT-P13-03 / Section 7).
5. Token Lifecycle, Replay Protection, and Atomic Concurrency Safety (Section 8).
"""
import os
import sqlite3
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from backend.app.api.deps import (
    get_approval_engine,
    reset_dependencies,
    set_base_vault_dir,
)
from backend.app.auth.dependencies import set_user_store
from backend.app.auth.models import UserCreate
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
from backend.app.db.sqlite_store import get_llm_state_store, reset_llm_state_store
from backend.app.main import create_app
from backend.app.models.approval import ApprovalStatus
from backend.app.models.workflow import HumanApprovalToken


@pytest.fixture
def approval_env(tmp_path: Path):
    """Hermetic isolated environment for Phase 14.1 security verification."""
    vault_dir = tmp_path / "vault"
    vault_dir.mkdir(parents=True, exist_ok=True)
    secret_key = "phase14-1-test-hmac-secret-secure-32b!!"
    jwt_secret = "phase14-1-test-jwt-secret-secure-32b!!"

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

    # User Store setup
    users_db = vault_dir / "users.db"
    user_store = UserStore(db_path=users_db)
    set_user_store(user_store)

    alice = user_store.create_user(
        UserCreate(
            username="alice_lead",
            password="password123",
            role="lead_investigator",
            badge_id="BADGE-ALICE-01",
            full_name="Alice Lead Investigator",
        ),
        password_hash=hash_password("password123"),
    )

    bob = user_store.create_user(
        UserCreate(
            username="bob_analyst",
            password="password123",
            role="soc_analyst",
            badge_id="BADGE-BOB-02",
            full_name="Bob SOC Analyst",
        ),
        password_hash=hash_password("password123"),
    )

    auditor = user_store.create_user(
        UserCreate(
            username="charlie_auditor",
            password="password123",
            role="auditor",
            badge_id="BADGE-CHARLIE-03",
            full_name="Charlie Auditor",
        ),
        password_hash=hash_password("password123"),
    )

    tokens = {
        "alice": create_access_token({"sub": alice.username, "user_id": alice.id, "role": alice.role, "badge_id": alice.badge_id}),
        "bob": create_access_token({"sub": bob.username, "user_id": bob.id, "role": bob.role, "badge_id": bob.badge_id}),
        "auditor": create_access_token({"sub": auditor.username, "user_id": auditor.id, "role": auditor.role, "badge_id": auditor.badge_id}),
    }

    app = create_app()
    client = TestClient(app)

    case_id = "case-phase14-sec"
    state_store = get_llm_state_store()
    state_store.create_or_update_case({
        "case_id": case_id,
        "case_name": "Phase 14.1 Security Verification Case",
        "lead_analyst": alice.username,
        "organization_name": "ForensicOps AI Labs",
        "status": "OPEN",
        "serialized_state": {
            "assigned_analysts": [alice.username, bob.username, auditor.username],
            "collaborators": [bob.username],
        },
    })

    yield {
        "client": client,
        "tokens": tokens,
        "case_id": case_id,
        "vault_dir": vault_dir,
        "secret_key": secret_key,
        "alice": alice,
        "bob": bob,
        "auditor": auditor,
    }

    reset_dependencies()
    for k, v in old_env.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


# ==============================================================================
# 1. REQUEST CREATION TESTS
# ==============================================================================

def test_req_creation_authenticated_investigator_a_succeeds(approval_env: Dict[str, Any]):
    """Authenticated Investigator A creates a pending request with server-derived identity."""
    client: TestClient = approval_env["client"]
    token = approval_env["tokens"]["alice"]
    case_id = approval_env["case_id"]
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    resp = client.post(
        "/api/approvals/requests",
        json={
            "case_id": case_id,
            "action_type": "remote_collection",
            "target": "10.0.1.55",
            "capability_id": "node_online_collector",
            "parameters": {"modules": ["Volatile", "SystemInfo"]},
            "reason": "Acquire triage from suspected host",
        },
        headers=headers,
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["approval_id"].startswith("appr-")
    assert data["status"] == "pending"
    assert data["requesting_investigator"] == "alice_lead"
    assert data["target"] == "10.0.1.55"
    assert data["parameter_digest"].startswith("sha256:")


def test_req_creation_unauthenticated_rejected(approval_env: Dict[str, Any]):
    """Unauthenticated request creation is rejected with 401."""
    client: TestClient = approval_env["client"]
    case_id = approval_env["case_id"]

    resp = client.post(
        "/api/approvals/requests",
        json={
            "case_id": case_id,
            "action_type": "remote_collection",
            "target": "10.0.1.55",
            "capability_id": "node_online_collector",
        },
    )
    assert resp.status_code == 401


def test_req_creation_client_cannot_override_authenticated_identity(approval_env: Dict[str, Any]):
    """Client-supplied identity in body cannot override server-derived authenticated identity."""
    client: TestClient = approval_env["client"]
    token = approval_env["tokens"]["alice"]
    case_id = approval_env["case_id"]
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    # Attempt to spoof requesting_investigator as bob_analyst or admin
    resp = client.post(
        "/api/approvals/requests",
        json={
            "case_id": case_id,
            "action_type": "remote_collection",
            "target": "10.0.1.55",
            "capability_id": "node_online_collector",
            "requesting_investigator": "bob_analyst",  # Spoofed field in body
        },
        headers=headers,
    )
    assert resp.status_code == 201
    data = resp.json()
    # Server strictly overrides body with authenticated principal
    assert data["requesting_investigator"] == "alice_lead"
    assert data["requesting_investigator"] != "bob_analyst"


def test_req_creation_deterministic_parameter_digest(approval_env: Dict[str, Any]):
    """Request parameters are bound to a deterministic SHA-256 digest."""
    client: TestClient = approval_env["client"]
    token = approval_env["tokens"]["alice"]
    case_id = approval_env["case_id"]
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    params1 = {"b_key": 2, "a_key": 1}
    params2 = {"a_key": 1, "b_key": 2}  # Different key order, identical semantics

    resp1 = client.post(
        "/api/approvals/requests",
        json={"case_id": case_id, "action_type": "remote_collection", "target": "10.0.1.55", "capability_id": "node_c", "parameters": params1},
        headers=headers,
    )
    resp2 = client.post(
        "/api/approvals/requests",
        json={"case_id": case_id, "action_type": "remote_collection", "target": "10.0.1.55", "capability_id": "node_c", "parameters": params2},
        headers=headers,
    )

    digest1 = resp1.json()["parameter_digest"]
    digest2 = resp2.json()["parameter_digest"]
    assert digest1 == digest2
    assert digest1 == compute_parameter_digest(params1)


# ==============================================================================
# 2. TWO-PERSON APPROVAL TESTS (AUDIT-P13-02)
# ==============================================================================

def test_two_person_approval_investigator_b_approves_investigator_a(approval_env: Dict[str, Any]):
    """Investigator B independently approves Investigator A's pending request."""
    client: TestClient = approval_env["client"]
    alice_headers = {"Authorization": f"Bearer {approval_env['tokens']['alice']}", "Content-Type": "application/json"}
    bob_headers = {"Authorization": f"Bearer {approval_env['tokens']['bob']}", "Content-Type": "application/json"}
    case_id = approval_env["case_id"]

    # 1. Alice creates request
    create_resp = client.post(
        "/api/approvals/requests",
        json={"case_id": case_id, "action_type": "remote_collection", "target": "10.0.1.55", "capability_id": "node_col", "reason": "Triage"},
        headers=alice_headers,
    )
    assert create_resp.status_code == 201
    approval_id = create_resp.json()["approval_id"]

    # 2. Bob approves request
    appr_resp = client.post(
        f"/api/approvals/{approval_id}/approve",
        json={"reason": "Approved by SOC analyst for live incident"},
        headers=bob_headers,
    )
    assert appr_resp.status_code == 200
    res_data = appr_resp.json()
    assert res_data["request"]["status"] == "approved"
    assert res_data["request"]["approving_investigator"] == "bob_analyst"
    assert res_data["token"] is not None
    assert res_data["token"]["target"] == "10.0.1.55"
    assert res_data["token"]["is_valid"] is True


def test_two_person_approval_self_approval_rejected(approval_env: Dict[str, Any]):
    """Investigator A cannot approve their own request (AUDIT-P13-02)."""
    client: TestClient = approval_env["client"]
    alice_headers = {"Authorization": f"Bearer {approval_env['tokens']['alice']}", "Content-Type": "application/json"}
    case_id = approval_env["case_id"]

    # 1. Alice creates request
    create_resp = client.post(
        "/api/approvals/requests",
        json={"case_id": case_id, "action_type": "remote_collection", "target": "10.0.1.55", "capability_id": "node_col"},
        headers=alice_headers,
    )
    approval_id = create_resp.json()["approval_id"]

    # 2. Alice attempts to approve her own request
    appr_resp = client.post(
        f"/api/approvals/{approval_id}/approve",
        headers=alice_headers,
    )
    assert appr_resp.status_code == 400
    assert "Self-approval rejected" in appr_resp.json()["detail"]


def test_two_person_approval_missing_approver_authentication_rejected(approval_env: Dict[str, Any]):
    """Missing approver authentication is rejected with 401."""
    client: TestClient = approval_env["client"]
    alice_headers = {"Authorization": f"Bearer {approval_env['tokens']['alice']}", "Content-Type": "application/json"}
    case_id = approval_env["case_id"]

    create_resp = client.post(
        "/api/approvals/requests",
        json={"case_id": case_id, "action_type": "remote_collection", "target": "10.0.1.55", "capability_id": "node_col"},
        headers=alice_headers,
    )
    approval_id = create_resp.json()["approval_id"]

    resp = client.post(f"/api/approvals/{approval_id}/approve")
    assert resp.status_code == 401


def test_two_person_approval_spoofed_body_identity_cannot_bypass(approval_env: Dict[str, Any]):
    """Client-supplied spoofed identity cannot bypass the two-person rule."""
    client: TestClient = approval_env["client"]
    alice_headers = {"Authorization": f"Bearer {approval_env['tokens']['alice']}", "Content-Type": "application/json"}
    case_id = approval_env["case_id"]

    create_resp = client.post(
        "/api/approvals/requests",
        json={"case_id": case_id, "action_type": "remote_collection", "target": "10.0.1.55", "capability_id": "node_col"},
        headers=alice_headers,
    )
    approval_id = create_resp.json()["approval_id"]

    # Alice tries to approve while passing approver="bob_analyst" or requesting_investigator="different"
    appr_resp = client.post(
        f"/api/approvals/{approval_id}/approve",
        json={"approver": "bob_analyst", "requesting_investigator": "someone_else"},
        headers=alice_headers,
    )
    assert appr_resp.status_code == 400
    assert "Self-approval rejected" in appr_resp.json()["detail"]


def test_two_person_approval_nonexistent_request_returns_404(approval_env: Dict[str, Any]):
    """Approving a nonexistent request returns 404 Not Found."""
    client: TestClient = approval_env["client"]
    bob_headers = {"Authorization": f"Bearer {approval_env['tokens']['bob']}", "Content-Type": "application/json"}

    resp = client.post("/api/approvals/appr-nonexistent-1234/approve", headers=bob_headers)
    assert resp.status_code == 404


def test_two_person_approval_already_approved_cannot_be_approved_again(approval_env: Dict[str, Any]):
    """An already approved request cannot be approved again."""
    client: TestClient = approval_env["client"]
    alice_headers = {"Authorization": f"Bearer {approval_env['tokens']['alice']}", "Content-Type": "application/json"}
    bob_headers = {"Authorization": f"Bearer {approval_env['tokens']['bob']}", "Content-Type": "application/json"}
    case_id = approval_env["case_id"]

    create_resp = client.post(
        "/api/approvals/requests",
        json={"case_id": case_id, "action_type": "remote_collection", "target": "10.0.1.55", "capability_id": "node_col"},
        headers=alice_headers,
    )
    approval_id = create_resp.json()["approval_id"]

    # First approval succeeds
    resp1 = client.post(f"/api/approvals/{approval_id}/approve", headers=bob_headers)
    assert resp1.status_code == 200

    # Second approval attempt must be rejected
    resp2 = client.post(f"/api/approvals/{approval_id}/approve", headers=bob_headers)
    assert resp2.status_code == 400
    assert "cannot be approved" in resp2.json()["detail"].lower()


def test_two_person_approval_expired_and_revoked_cannot_be_approved(approval_env: Dict[str, Any]):
    """Expired and revoked requests cannot be approved."""
    client: TestClient = approval_env["client"]
    alice_headers = {"Authorization": f"Bearer {approval_env['tokens']['alice']}", "Content-Type": "application/json"}
    bob_headers = {"Authorization": f"Bearer {approval_env['tokens']['bob']}", "Content-Type": "application/json"}
    case_id = approval_env["case_id"]

    # 1. Expired request
    engine = get_approval_engine(case_id)
    req_exp = engine.create_request(
        case_id=case_id,
        requesting_investigator="alice_lead",
        action_type="remote_collection",
        target="10.0.1.55",
        capability_id="node_exp",
        expiration_seconds=1,
    )
    # Force expiration in DB
    past_iso = (datetime.now(timezone.utc) - timedelta(seconds=60)).isoformat()
    with engine.state_store._conn as conn:
        conn.execute("UPDATE approval_requests SET expires_at_utc = ? WHERE approval_id = ?", (past_iso, req_exp.approval_id))

    resp_exp = client.post(f"/api/approvals/{req_exp.approval_id}/approve", headers=bob_headers)
    assert resp_exp.status_code == 400
    assert "expired" in resp_exp.json()["detail"].lower()

    # 2. Revoked request
    req_rev = engine.create_request(
        case_id=case_id,
        requesting_investigator="alice_lead",
        action_type="remote_collection",
        target="10.0.1.55",
        capability_id="node_rev",
    )
    engine.approve_request(req_rev.approval_id, approver={"username": "bob_analyst", "role": "soc_analyst"})
    engine.revoke_request(req_rev.approval_id, actor={"username": "alice_lead", "role": "lead_investigator"})

    resp_rev = client.post(f"/api/approvals/{req_rev.approval_id}/approve", headers=bob_headers)
    assert resp_rev.status_code == 400
    assert "cannot be approved" in resp_rev.json()["detail"].lower()


# ==============================================================================
# 3. TOKEN ISSUANCE & WORKFLOW ROUTE TESTS (AUDIT-P13-03)
# ==============================================================================

def test_token_issuance_impossible_before_approval(approval_env: Dict[str, Any]):
    """Token cannot be issued without prior approval or valid pending request."""
    client: TestClient = approval_env["client"]
    bob_headers = {"Authorization": f"Bearer {approval_env['tokens']['bob']}", "Content-Type": "application/json"}
    case_id = approval_env["case_id"]

    # Direct token issuance attempt without prior approval request fails closed
    resp = client.post(
        "/api/workflows/approval-token",
        json={"case_id": case_id, "node_id": "unapproved_node", "target": "10.0.1.55"},
        headers=bob_headers,
    )
    assert resp.status_code == 400
    assert "Approval token cannot be issued without prior approval" in resp.json()["detail"]


def test_token_issuance_impossible_if_database_persistence_fails(approval_env: Dict[str, Any]):
    """Token issuance fails closed if approval state cannot be persisted in SQLite."""
    client: TestClient = approval_env["client"]
    bob_headers = {"Authorization": f"Bearer {approval_env['tokens']['bob']}", "Content-Type": "application/json"}
    case_id = approval_env["case_id"]

    engine = get_approval_engine(case_id)
    req = engine.create_request(
        case_id=case_id,
        requesting_investigator="alice_lead",
        action_type="remote_collection",
        target="10.0.1.55",
        capability_id="node_fail_db",
    )

    # Simulate database failure during approve_request
    with patch.object(engine, "approve_request", side_effect=sqlite3.OperationalError("disk I/O error")):
        resp = client.post(
            "/api/workflows/approval-token",
            json={"case_id": case_id, "node_id": "node_fail_db", "target": "10.0.1.55", "approval_id": req.approval_id},
            headers=bob_headers,
        )
        assert resp.status_code == 500
        # Verify no token was returned
        assert "Failed to record approval" in resp.json()["detail"]


def test_pending_request_cannot_produce_executable_token(approval_env: Dict[str, Any]):
    """A pending request cannot produce an active signed token."""
    case_id = approval_env["case_id"]
    engine = get_approval_engine(case_id)
    req = engine.create_request(
        case_id=case_id,
        requesting_investigator="alice_lead",
        action_type="remote_collection",
        target="10.0.1.55",
        capability_id="node_pending",
    )
    assert req.status == ApprovalStatus.PENDING

    # Attempting to fetch approved token for a pending request must return None
    tok = engine.get_approved_token(req.approval_id)
    assert tok is None


def test_token_cannot_be_generated_by_direct_workflow_shortcut(approval_env: Dict[str, Any]):
    """An approval token cannot be manufactured directly without independent approval."""
    client: TestClient = approval_env["client"]
    alice_headers = {"Authorization": f"Bearer {approval_env['tokens']['alice']}", "Content-Type": "application/json"}
    case_id = approval_env["case_id"]

    resp = client.post(
        "/api/workflows/approval-token",
        json={"case_id": case_id, "node_id": "shortcut_collector", "target": "10.0.1.99"},
        headers=alice_headers,
    )
    assert resp.status_code == 400
    assert "Approval token cannot be issued without prior approval" in resp.json()["detail"]


# ==============================================================================
# 4. REMOTE COLLECTION TOKEN BINDING TESTS (AUDIT-P13-01)
# ==============================================================================

def test_remote_collection_null_target_rejected(approval_env: Dict[str, Any]):
    """Remote collection token request is rejected with 400 Bad Request."""
    client: TestClient = approval_env["client"]
    bob_headers = {"Authorization": f"Bearer {approval_env['tokens']['bob']}", "Content-Type": "application/json"}
    case_id = approval_env["case_id"]

    resp = client.post(
        "/api/workflows/approval-token",
        json={"case_id": case_id, "node_id": "node_collector", "action_type": "remote_collection", "target": None},
        headers=bob_headers,
    )
    assert resp.status_code == 400
    assert "Remote collection has been removed" in resp.json()["detail"]


def test_remote_collection_empty_target_rejected(approval_env: Dict[str, Any]):
    """Remote collection token request with empty target is rejected with 400 Bad Request."""
    client: TestClient = approval_env["client"]
    bob_headers = {"Authorization": f"Bearer {approval_env['tokens']['bob']}", "Content-Type": "application/json"}
    case_id = approval_env["case_id"]

    resp = client.post(
        "/api/workflows/approval-token",
        json={"case_id": case_id, "node_id": "node_collector", "action_type": "remote_collection", "target": "   "},
        headers=bob_headers,
    )
    assert resp.status_code == 400
    assert "Remote collection has been removed" in resp.json()["detail"]


def test_remote_collection_correct_target_succeeds(approval_env: Dict[str, Any]):
    """Approval token with matching target host and parameter digest succeeds."""
    case_id = approval_env["case_id"]
    secret_key = approval_env["secret_key"]
    appr_engine = get_approval_engine(case_id)

    target_host = "10.0.1.55"
    params = {"case_id": case_id, "target": target_host, "node_id": "containment_gate"}
    param_dig = compute_parameter_digest(params)

    token = HumanApprovalToken(
        node_id="containment_gate",
        case_id=case_id,
        issued_by="bob_analyst",
        action_type="containment",
        target=target_host,
        parameter_digest=param_dig,
    )
    token.sign(secret_key)

    success = appr_engine.verify_and_consume_token(
        token=token,
        expected_case_id=case_id,
        expected_action_type="containment",
        expected_target=target_host,
        expected_parameters=params,
        consumed_by="bob_analyst",
    )
    assert success is True
    assert token.consumed is True


def test_remote_collection_target_mismatch_rejected(approval_env: Dict[str, Any]):
    """Approval engine unconditionally rejects token bound to a different target host."""
    case_id = approval_env["case_id"]
    secret_key = approval_env["secret_key"]
    appr_engine = get_approval_engine(case_id)

    token = HumanApprovalToken(
        node_id="containment_gate",
        case_id=case_id,
        issued_by="bob_analyst",
        action_type="containment",
        target="10.0.1.55",  # Bound to 10.0.1.55
        parameter_digest=compute_parameter_digest({"case_id": case_id, "target": "10.0.1.55", "node_id": "containment_gate"}),
    )
    token.sign(secret_key)

    with pytest.raises(UnauthorizedCollectorExecutionError) as exc_info:
        appr_engine.verify_and_consume_token(
            token=token,
            expected_case_id=case_id,
            expected_action_type="containment",
            expected_target="10.0.1.99",
            consumed_by="bob_analyst",
        )

    assert "Target mismatch" in str(exc_info.value)


def test_remote_collection_token_without_target_cannot_authorize_ssh(approval_env: Dict[str, Any]):
    """A token with null target cannot authorize targeted action (AUDIT-P13-01)."""
    case_id = approval_env["case_id"]
    secret_key = approval_env["secret_key"]
    appr_engine = get_approval_engine(case_id)

    token = HumanApprovalToken(
        node_id="containment_gate",
        case_id=case_id,
        issued_by="bob_analyst",
        action_type="containment",
        target=None,  # Null target
        parameter_digest="sha256:abc123",
    )
    token.sign(secret_key)

    with pytest.raises(UnauthorizedCollectorExecutionError) as exc_info:
        appr_engine.verify_and_consume_token(
            token=token,
            expected_case_id=case_id,
            expected_action_type="containment",
            expected_target="10.0.1.55",
            consumed_by="bob_analyst",
        )

    assert "Target mismatch" in str(exc_info.value)


def test_remote_collection_modified_parameter_digest_rejected(approval_env: Dict[str, Any]):
    """A token with modified parameter digest is rejected."""
    case_id = approval_env["case_id"]
    secret_key = approval_env["secret_key"]
    appr_engine = get_approval_engine(case_id)

    token = HumanApprovalToken(
        node_id="containment_gate",
        case_id=case_id,
        issued_by="bob_analyst",
        action_type="containment",
        target="10.0.1.55",
        parameter_digest="sha256:0000000000000000000000000000000000000000000000000000000000000000",
    )
    token.sign(secret_key)

    with pytest.raises(UnauthorizedCollectorExecutionError) as exc_info:
        appr_engine.verify_and_consume_token(
            token=token,
            expected_case_id=case_id,
            expected_action_type="containment",
            expected_target="10.0.1.55",
            expected_parameters={"case_id": case_id, "target": "10.0.1.55", "node_id": "containment_gate"},
            consumed_by="bob_analyst",
        )

    assert "Parameter digest mismatch" in str(exc_info.value)


# ==============================================================================
# 5. REPLAY & CONCURRENCY TESTS
# ==============================================================================

def test_token_single_use_consumption(approval_env: Dict[str, Any]):
    """A token can only be consumed once; subsequent attempts are rejected."""
    case_id = approval_env["case_id"]
    engine = get_approval_engine(case_id)
    token_id = "test-token-single-use-01"

    # First consumption succeeds
    engine.consume_token(token_id=token_id, case_id=case_id, target="10.0.1.55")

    # Second consumption attempt raises replay error
    with pytest.raises(UnauthorizedCollectorExecutionError, match="Replay detected"):
        engine.consume_token(token_id=token_id, case_id=case_id, target="10.0.1.55")


def test_concurrent_consumption_replay_prevention(approval_env: Dict[str, Any]):
    """Concurrent consumption attempts cannot both succeed (atomic primary key constraint)."""
    case_id = approval_env["case_id"]
    engine = get_approval_engine(case_id)
    token_id = "test-token-concurrent-01"

    success_count = 0
    failure_count = 0
    lock = threading.Lock()

    def try_consume():
        nonlocal success_count, failure_count
        try:
            engine.consume_token(token_id=token_id, case_id=case_id, target="10.0.1.55")
            with lock:
                success_count += 1
        except UnauthorizedCollectorExecutionError:
            with lock:
                failure_count += 1

    threads = [threading.Thread(target=try_consume) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert success_count == 1
    assert failure_count == 4


def test_failed_consumption_does_not_corrupt_state(approval_env: Dict[str, Any]):
    """Failed verification does not mark token as consumed or corrupt authorization state."""
    case_id = approval_env["case_id"]
    secret_key = approval_env["secret_key"]
    engine = get_approval_engine(case_id)

    token = HumanApprovalToken(
        node_id="containment_gate",
        case_id=case_id,
        issued_by="bob_analyst",
        action_type="containment",
        target="10.0.1.55",
        parameter_digest="sha256:tampered_digest",
    )
    token.sign(secret_key)

    with pytest.raises(UnauthorizedCollectorExecutionError):
        engine.verify_and_consume_token(
            token=token,
            expected_case_id=case_id,
            expected_action_type="containment",
            expected_target="10.0.1.55",
            expected_parameters={"host": "10.0.1.55"},
            consumed_by="bob_analyst",
        )

    # Verify token is NOT marked consumed
    assert token.consumed is False
    cur = engine.state_store._conn.execute(
        "SELECT consumed_at_utc FROM consumed_approval_tokens WHERE token_id = ?",
        (token.token_id,),
    )
    assert cur.fetchone() is None


# ==============================================================================
# 6. REGRESSION TESTS
# ==============================================================================

def test_regression_existing_approval_lifecycle_intact(approval_env: Dict[str, Any]):
    """Full lifecycle transition: Request -> Approve -> Issue -> Verify -> Consume -> Audit."""
    client: TestClient = approval_env["client"]
    alice_headers = {"Authorization": f"Bearer {approval_env['tokens']['alice']}", "Content-Type": "application/json"}
    bob_headers = {"Authorization": f"Bearer {approval_env['tokens']['bob']}", "Content-Type": "application/json"}
    case_id = approval_env["case_id"]

    # 1. Alice creates request
    create_resp = client.post(
        "/api/approvals/requests",
        json={"case_id": case_id, "action_type": "remote_collection", "target": "10.0.1.55", "capability_id": "collector_full_cycle"},
        headers=alice_headers,
    )
    assert create_resp.status_code == 201
    approval_id = create_resp.json()["approval_id"]

    # 2. Bob approves request
    appr_resp = client.post(f"/api/approvals/{approval_id}/approve", headers=bob_headers)
    assert appr_resp.status_code == 200
    token_dict = appr_resp.json()["token"]

    # 3. Bob issues token via workflow endpoint
    wf_resp = client.post(
        "/api/workflows/approval-token",
        json={"case_id": case_id, "node_id": "collector_full_cycle", "target": "10.0.1.55", "approval_id": approval_id},
        headers=bob_headers,
    )
    assert wf_resp.status_code == 200
    wf_token = wf_resp.json()
    assert wf_token["token_id"] == token_dict["token_id"]

    # 4. Engine consumes token
    engine = get_approval_engine(case_id)
    engine.consume_token(token_id=wf_token["token_id"], case_id=case_id, target="10.0.1.55")

    # 5. Replay must fail
    with pytest.raises(UnauthorizedCollectorExecutionError):
        engine.consume_token(token_id=wf_token["token_id"], case_id=case_id, target="10.0.1.55")
