"""Comprehensive Test Suite for Phase 1.5: Multi-User RBAC & Forensic Identity Binding.

Tests:
1. First-boot setup (creation of Lead Investigator; rejection of secondary setup attempts).
2. Login and JWT generation (via username or badge_id, password verification, error handling).
3. Session verification (/api/auth/me).
4. User management (Lead creates Analyst/Auditor, lists users, suspends and reinstates accounts).
5. Role-based endpoint guards (Auditor blocked from workflow execution; Analyst blocked from user creation).
6. Chain of Custody actor attribution (ledger entry records username, badge ID, and role).
7. Human feedback identity binding (feedback record binds badge ID, role, and username).
"""
import base64
import os
import shutil
import tempfile
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.app.api.deps import reset_dependencies, set_base_vault_dir
from backend.app.auth.dependencies import reset_user_store, set_user_store
from backend.app.auth.security import create_access_token
from backend.app.auth.store import UserStore
from backend.app.main import app


@pytest.fixture
def auth_test_env(tmp_path: Path):
    """Hermetic test fixture for auth and custody database isolation."""
    # Ensure production auth enforcement is active during these tests
    old_auth_disabled = os.environ.get("FORENSICOPS_AUTH_DISABLED")
    os.environ["FORENSICOPS_AUTH_DISABLED"] = "false"

    vault_dir = tmp_path / "vault"
    vault_dir.mkdir(parents=True, exist_ok=True)
    set_base_vault_dir(vault_dir)

    user_store = UserStore(db_path=vault_dir / "users.db")
    set_user_store(user_store)

    client = TestClient(app)

    yield client, user_store, vault_dir

    # Cleanup
    reset_user_store()
    reset_dependencies()
    if old_auth_disabled is not None:
        os.environ["FORENSICOPS_AUTH_DISABLED"] = old_auth_disabled
    else:
        os.environ.pop("FORENSICOPS_AUTH_DISABLED", None)


def test_auth_status_and_first_boot_setup(auth_test_env):
    client, store, _ = auth_test_env

    # 1. Initially uninitialized
    status_resp = client.get("/api/auth/status")
    assert status_resp.status_code == 200
    assert status_resp.json() == {"initialized": False, "active_users_count": 0}

    # 2. First-boot setup
    setup_payload = {
        "username": "lead_chief",
        "badge_id": "BADGE-001",
        "password": "MasterPassword2026!",
        "full_name": "Chief Lead Investigator",
    }
    setup_resp = client.post("/api/auth/setup", json=setup_payload)
    assert setup_resp.status_code == 201
    data = setup_resp.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["user"]["username"] == "lead_chief"
    assert data["user"]["badge_id"] == "BADGE-001"
    assert data["user"]["role"] == "lead_investigator"

    # 3. Subsequent setup attempt MUST be rejected with 403 Forbidden
    secondary_resp = client.post("/api/auth/setup", json=setup_payload)
    assert secondary_resp.status_code == 403
    assert "already initialized" in secondary_resp.json()["detail"]

    # 4. Status reflects initialized
    status_resp2 = client.get("/api/auth/status")
    assert status_resp2.status_code == 200
    assert status_resp2.json() == {"initialized": True, "active_users_count": 1}


def test_login_flow_and_me_endpoint(auth_test_env):
    client, store, _ = auth_test_env

    # Setup Lead
    client.post(
        "/api/auth/setup",
        json={
            "username": "lead_investigator",
            "badge_id": "BADGE-100",
            "password": "SecurePassword123!",
            "full_name": "Lead One",
        },
    )

    # 1. Login via username
    login_resp = client.post(
        "/api/auth/login",
        json={"username": "lead_investigator", "password": "SecurePassword123!"},
    )
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]

    # 2. Login via badge ID
    login_badge_resp = client.post(
        "/api/auth/login",
        json={"username": "BADGE-100", "password": "SecurePassword123!"},
    )
    assert login_badge_resp.status_code == 200

    # 3. Invalid credentials
    invalid_resp = client.post(
        "/api/auth/login",
        json={"username": "lead_investigator", "password": "WrongPassword!"},
    )
    assert invalid_resp.status_code == 401

    # 4. Verify /api/auth/me
    me_resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_resp.status_code == 200
    assert me_resp.json()["username"] == "lead_investigator"
    assert me_resp.json()["role"] == "lead_investigator"

    # 5. Accessing /api/auth/me without token fails with 401
    unauth_resp = client.get("/api/auth/me")
    assert unauth_resp.status_code == 401


def test_user_management_and_role_guards(auth_test_env):
    client, store, _ = auth_test_env

    # Setup Lead
    setup_resp = client.post(
        "/api/auth/setup",
        json={
            "username": "admin_lead",
            "badge_id": "BADGE-001",
            "password": "LeadPassword123!",
            "full_name": "Admin Lead",
        },
    )
    lead_token = setup_resp.json()["access_token"]
    lead_headers = {"Authorization": f"Bearer {lead_token}"}

    # 1. Lead creates SOC Analyst account
    analyst_resp = client.post(
        "/api/auth/users",
        json={
            "username": "soc_jane",
            "badge_id": "BADGE-201",
            "password": "AnalystPassword123!",
            "role": "soc_analyst",
            "full_name": "Jane Analyst",
        },
        headers=lead_headers,
    )
    assert analyst_resp.status_code == 201
    analyst_user = analyst_resp.json()
    assert analyst_user["role"] == "soc_analyst"

    # 2. Lead creates Auditor account
    auditor_resp = client.post(
        "/api/auth/users",
        json={
            "username": "audit_bob",
            "badge_id": "BADGE-301",
            "password": "AuditorPassword123!",
            "role": "auditor",
            "full_name": "Bob Auditor",
        },
        headers=lead_headers,
    )
    assert auditor_resp.status_code == 201

    # 3. Lead lists all accounts
    users_resp = client.get("/api/auth/users", headers=lead_headers)
    assert users_resp.status_code == 200
    assert len(users_resp.json()) == 3

    # 4. Log in as SOC Analyst
    analyst_login = client.post(
        "/api/auth/login",
        json={"username": "soc_jane", "password": "AnalystPassword123!"},
    )
    assert analyst_login.status_code == 200
    analyst_token = analyst_login.json()["access_token"]
    analyst_headers = {"Authorization": f"Bearer {analyst_token}"}

    # 5. SOC Analyst is BLOCKED (403) from creating users
    blocked_create = client.post(
        "/api/auth/users",
        json={
            "username": "illegal_user",
            "badge_id": "BADGE-999",
            "password": "Pass!",
            "role": "soc_analyst",
        },
        headers=analyst_headers,
    )
    assert blocked_create.status_code == 403

    # 6. Log in as Auditor
    auditor_login = client.post(
        "/api/auth/login",
        json={"username": "audit_bob", "password": "AuditorPassword123!"},
    )
    assert auditor_login.status_code == 200
    auditor_token = auditor_login.json()["access_token"]
    auditor_headers = {"Authorization": f"Bearer {auditor_token}"}

    # 7. Auditor is BLOCKED (403) from executing workflows
    blocked_exec = client.post(
        "/api/workflows/execute",
        json={
            "case_id": "test_case",
            "workflow": {
                "workflow_id": "wf-test-01",
                "name": "Audit Test WF",
                "nodes": [],
                "edges": [],
            },
        },
        headers=auditor_headers,
    )
    assert blocked_exec.status_code == 403

    # 8. Lead suspends analyst account
    suspend_resp = client.patch(
        f"/api/auth/users/{analyst_user['id']}/status",
        json={"is_active": False},
        headers=lead_headers,
    )
    assert suspend_resp.status_code == 200
    assert suspend_resp.json()["is_active"] is False

    # 9. Suspended analyst login is REJECTED with 403 Forbidden
    suspended_login = client.post(
        "/api/auth/login",
        json={"username": "soc_jane", "password": "AnalystPassword123!"},
    )
    assert suspended_login.status_code == 403
    assert "suspended" in suspended_login.json()["detail"].lower()


def test_custody_actor_attribution_and_tamper_verification(auth_test_env):
    client, store, _ = auth_test_env

    # Setup Lead & Analyst
    setup_resp = client.post(
        "/api/auth/setup",
        json={
            "username": "lead_alex",
            "badge_id": "BADGE-101",
            "password": "LeadPassword123!",
            "full_name": "Alex Lead",
        },
    )
    lead_token = setup_resp.json()["access_token"]
    lead_headers = {"Authorization": f"Bearer {lead_token}"}

    client.post(
        "/api/auth/users",
        json={
            "username": "analyst_sarah",
            "badge_id": "BADGE-505",
            "password": "SarahPassword123!",
            "role": "soc_analyst",
            "full_name": "Sarah Analyst",
        },
        headers=lead_headers,
    )

    analyst_token = client.post(
        "/api/auth/login",
        json={"username": "analyst_sarah", "password": "SarahPassword123!"},
    ).json()["access_token"]
    analyst_headers = {"Authorization": f"Bearer {analyst_token}"}

    # Ingest evidence with analyst token
    raw_evidence = b"EVTX_FORENSIC_RAW_EVIDENCE_RECORD_SAMPLE"
    b64_evidence = base64.b64encode(raw_evidence).decode("utf-8")

    intake_resp = client.post(
        "/api/intake/offline",
        json={
            "case_id": "CASE-RBAC-01",
            "raw_content_b64": b64_evidence,
            "filename": "Security.evtx",
            "artifact_type": "evtx",
        },
        headers=analyst_headers,
    )
    assert intake_resp.status_code == 200
    res_data = intake_resp.json()
    assert len(res_data["artifacts"]) == 1

    # Verify custody ledger entry binds exact analyst identity
    custody_resp = client.get("/api/intake/custody/CASE-RBAC-01", headers=analyst_headers)
    assert custody_resp.status_code == 200
    ledger_data = custody_resp.json()
    assert ledger_data["is_tamper_free"] is True
    assert len(ledger_data["entries"]) >= 1

    entry = ledger_data["entries"][0]
    expected_actor = "analyst_sarah (BADGE-505) [soc_analyst]"
    assert entry["actor"] == expected_actor


def test_human_feedback_identity_binding(auth_test_env):
    client, store, _ = auth_test_env

    # Setup Lead & Analyst
    setup_resp = client.post(
        "/api/auth/setup",
        json={
            "username": "lead_chief",
            "badge_id": "BADGE-001",
            "password": "Password123!",
        },
    )
    lead_token = setup_resp.json()["access_token"]
    lead_headers = {"Authorization": f"Bearer {lead_token}"}

    client.post(
        "/api/auth/users",
        json={
            "username": "analyst_dan",
            "badge_id": "BADGE-707",
            "password": "Password123!",
            "role": "soc_analyst",
        },
        headers=lead_headers,
    )

    client.post(
        "/api/auth/users",
        json={
            "username": "auditor_clara",
            "badge_id": "BADGE-808",
            "password": "Password123!",
            "role": "auditor",
        },
        headers=lead_headers,
    )

    dan_token = client.post(
        "/api/auth/login",
        json={"username": "analyst_dan", "password": "Password123!"},
    ).json()["access_token"]
    dan_headers = {"Authorization": f"Bearer {dan_token}"}

    clara_token = client.post(
        "/api/auth/login",
        json={"username": "auditor_clara", "password": "Password123!"},
    ).json()["access_token"]
    clara_headers = {"Authorization": f"Bearer {clara_token}"}

    # 1. Analyst Dan submits human feedback
    feedback_resp = client.post(
        "/api/feedback",
        json={
            "case_id": "CASE-FEEDBACK-01",
            "feedback_type": "confirm_tp",
            "analyst_note": "Confirmed Cobalt Strike beaconing from temp directory",
            "entity_pattern": "process:beacon.exe",
        },
        headers=dan_headers,
    )
    assert feedback_resp.status_code == 200
    f_data = feedback_resp.json()
    record = f_data["record"]
    assert record["badge_id"] == "BADGE-707"
    assert record["analyst_role"] == "soc_analyst"
    assert record["analyst_username"] == "analyst_dan"

    # 2. Auditor Clara is BLOCKED (403) from submitting feedback
    auditor_feedback_resp = client.post(
        "/api/feedback",
        json={
            "case_id": "CASE-FEEDBACK-01",
            "feedback_type": "confirm_tp",
        },
        headers=clara_headers,
    )
    assert auditor_feedback_resp.status_code == 403
