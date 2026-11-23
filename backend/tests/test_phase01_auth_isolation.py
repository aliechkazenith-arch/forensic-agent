"""Comprehensive Regression Test Suite for Phase 01: Authentication, Authorization & Case Isolation.

Standards & Acceptance Criteria:
1. Mandatory Authentication: All protected endpoints strictly reject anonymous requests (401).
2. Role-Based Access Control (RBAC): Insufficient roles return 403 Forbidden.
3. Case-Level Authorization & Default-to-Deny: Unassigned investigators (even other leads) are denied (403).
4. Assigned Investigator Access: Lead and assigned analysts/collaborators are authorized (200).
5. Vault Peer Review: Cases with is_shared_to_vault=True grant read-only access to peers, rejecting mutations.
6. Single-Finding Isolation: Cross-case finding queries and case ID mismatches are strictly rejected (404/403).
7. Hypothesis Provenance Validation: Caller-supplied fabricated findings or non-existent finding IDs are rejected.
8. Anonymous LLM & Copilot Protection: Chat, model switching, and smoke testing require authentication.
9. Production Security Boundary: FORENSICOPS_ENVIRONMENT=production strictly rejects test-only bypass headers.
10. Custody Cross-Case Chain Integrity: Tampering with ledger case_id values fails cryptographic verification.
"""
from __future__ import annotations

import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Generator
import pytest
from fastapi.testclient import TestClient

from backend.app.api.deps import (
    get_custody_engine,
    get_storage,
    reset_dependencies,
    set_base_vault_dir,
)
from backend.app.auth.case_authorization import CaseAuthorizationService, get_case_authorization_service
from backend.app.auth.dependencies import reset_user_store, set_user_store
from backend.app.auth.models import UserCreate, UserRead
from backend.app.auth.security import create_access_token, hash_password
from backend.app.auth.store import UserStore
from backend.app.core.custody_engine import CustodyEngine
from backend.app.core.storage import ForensicStore
from backend.app.db.sqlite_store import get_llm_state_store, reset_llm_state_store
from backend.app.main import app
from backend.app.models.findings import ForensicFinding


@pytest.fixture
def auth_isolation_env(tmp_path: Path):
    """Hermetic isolated environment for Phase 01 auth, storage, and SQLite databases."""
    # Enforce strict auth mode (disable test-mode bypass)
    old_env = os.environ.get("FORENSICOPS_ENVIRONMENT")
    old_auth_disabled = os.environ.get("FORENSICOPS_AUTH_DISABLED")
    old_vault_dir = os.environ.get("FORENSICOPS_VAULT_DIR")

    os.environ["FORENSICOPS_AUTH_DISABLED"] = "false"
    vault_dir = tmp_path / "vault"
    vault_dir.mkdir(parents=True, exist_ok=True)
    os.environ["FORENSICOPS_VAULT_DIR"] = str(vault_dir)
    set_base_vault_dir(vault_dir)

    # Initialize isolated UserStore
    users_db = vault_dir / "users.db"
    user_store = UserStore(db_path=users_db)
    set_user_store(user_store)

    # Initialize isolated SQLite state store
    sqlite_db = vault_dir / "llm_state.db"
    from backend.app.db.sqlite_store import LLMStateStore
    llm_store = LLMStateStore(db_path=sqlite_db)
    reset_llm_state_store(llm_store)

    # Create investigators
    users_to_create = [
        UserCreate(username="lead_alice", badge_id="BADGE-L01", role="lead_investigator", password="Password123!", full_name="Alice Lead"),
        UserCreate(username="lead_outsider", badge_id="BADGE-L02", role="lead_investigator", password="Password123!", full_name="Outsider Lead"),
        UserCreate(username="analyst_bob", badge_id="BADGE-S01", role="soc_analyst", password="Password123!", full_name="Bob Analyst"),
        UserCreate(username="auditor_clara", badge_id="BADGE-A01", role="auditor", password="Password123!", full_name="Clara Auditor"),
    ]

    tokens: Dict[str, Dict[str, str]] = {}
    for u in users_to_create:
        user_rec = user_store.create_user(u, hash_password("Password123!"))
        jwt_token = create_access_token({
            "sub": user_rec.username,
            "user_id": user_rec.id,
            "badge_id": user_rec.badge_id,
            "role": user_rec.role,
        })
        tokens[user_rec.username] = {
            "Authorization": f"Bearer {jwt_token}",
            "Content-Type": "application/json",
        }

    client = TestClient(app)

    yield {
        "client": client,
        "tokens": tokens,
        "vault_dir": vault_dir,
        "user_store": user_store,
        "llm_store": llm_store,
    }

    # Teardown
    reset_dependencies()
    reset_user_store()
    reset_llm_state_store()
    if old_env is not None:
        os.environ["FORENSICOPS_ENVIRONMENT"] = old_env
    else:
        os.environ.pop("FORENSICOPS_ENVIRONMENT", None)
    if old_auth_disabled is not None:
        os.environ["FORENSICOPS_AUTH_DISABLED"] = old_auth_disabled
    else:
        os.environ.pop("FORENSICOPS_AUTH_DISABLED", None)
    if old_vault_dir is not None:
        os.environ["FORENSICOPS_VAULT_DIR"] = old_vault_dir
    else:
        os.environ.pop("FORENSICOPS_VAULT_DIR", None)


# ==============================================================================
# 1. Anonymous Requests Return 401 Unauthorized
# ==============================================================================
def test_anonymous_requests_return_401(auth_isolation_env):
    """Verify that all protected routes reject anonymous requests with HTTP 401."""
    client: TestClient = auth_isolation_env["client"]

    endpoints = [
        ("GET", "/api/cases"),
        ("GET", "/api/cases/CASE-TEST-01"),
        ("POST", "/api/cases"),
        ("DELETE", "/api/cases/CASE-TEST-01"),
        ("POST", "/api/copilot/chat"),
        ("GET", "/api/agent/playbooks"),
        ("POST", "/api/agent/plan-hypothesis"),
        ("POST", "/api/agent/compile-plan"),
        ("POST", "/api/agent/execute-plan"),
        ("GET", "/api/llm/providers"),
        ("POST", "/api/llm/select"),
        ("POST", "/api/llm/smoke-test/lm_studio_local"),
        ("GET", "/api/llm/audit-logs"),
        ("GET", "/api/plugins"),
        ("POST", "/api/plugins/dry-run"),
        ("POST", "/api/plugins/register"),
        ("GET", "/api/workflows/blueprints"),
        ("POST", "/api/workflows/run"),
        ("POST", "/api/workflows/execute"),
        ("GET", "/api/feedback/baselines"),
        ("POST", "/api/feedback"),
        ("GET", "/api/session"),
        ("GET", "/api/session/CASE-TEST-01"),
        ("POST", "/api/session/CASE-TEST-01"),
        ("GET", "/api/intake/custody/CASE-TEST-01"),
        ("POST", "/api/intake/upload"),
        ("POST", "/api/intake/offline"),
        ("POST", "/api/intake/siem"),
        ("GET", "/api/findings/find-test-01"),
        ("GET", "/api/reports/CASE-TEST-01"),
    ]

    for method, path in endpoints:
        if method == "GET":
            resp = client.get(path)
        elif method == "POST":
            resp = client.post(path, json={})
        elif method == "DELETE":
            resp = client.delete(path)
        else:
            continue

        assert resp.status_code == 401, f"Expected 401 for anonymous {method} {path}, got {resp.status_code}: {resp.text}"

    # Verify permanently removed remote collection endpoint returns 404
    online_resp = client.post("/api/intake/online", json={})
    assert online_resp.status_code == 404


# ==============================================================================
# 2. Insufficient Roles Return 403 Forbidden
# ==============================================================================
def test_insufficient_roles_return_403(auth_isolation_env):
    """Verify RBAC role checks block unauthorized operations with HTTP 403."""
    client: TestClient = auth_isolation_env["client"]
    tokens: Dict[str, Dict[str, str]] = auth_isolation_env["tokens"]

    clara_headers = tokens["auditor_clara"]
    bob_headers = tokens["analyst_bob"]

    # 1. Auditor cannot register tool plugins (requires lead_investigator)
    card_payload = {
        "tool_id": "test_scanner_plugin",
        "name": "Test Scanner",
        "version": "1.0",
        "description": "Test plugin",
        "supported_artifacts": ["evtx"],
        "command_template": ["echo", "{input_path}"],
        "category": "Execution",
        "requires_docker": False,
        "is_safe_read_only": True,
    }
    resp = client.post("/api/plugins/register", json=card_payload, headers=clara_headers)
    assert resp.status_code == 403

    # 2. SOC Analyst cannot register tool plugins (requires lead_investigator)
    resp = client.post("/api/plugins/register", json=card_payload, headers=bob_headers)
    assert resp.status_code == 403

    # 3. Auditor cannot submit human feedback (requires lead or soc_analyst)
    resp = client.post(
        "/api/feedback",
        json={"case_id": "CASE-RBAC-01", "feedback_type": "confirm_tp"},
        headers=clara_headers,
    )
    assert resp.status_code == 403

    # 4. Auditor cannot select active LLM provider (requires lead_investigator)
    resp = client.post("/api/llm/select", json={"provider_id": "ollama_local"}, headers=clara_headers)
    assert resp.status_code == 403

    # 5. SOC Analyst cannot select active LLM provider (requires lead_investigator)
    resp = client.post("/api/llm/select", json={"provider_id": "ollama_local"}, headers=bob_headers)
    assert resp.status_code == 403


# ==============================================================================
# 3. Case-Level Authorization & Default-to-Deny
# ==============================================================================
def test_unauthorized_investigator_case_access_denied(auth_isolation_env):
    """Verify that an investigator not assigned to a case is denied access (default to deny)."""
    client: TestClient = auth_isolation_env["client"]
    tokens: Dict[str, Dict[str, str]] = auth_isolation_env["tokens"]
    llm_store = auth_isolation_env["llm_store"]

    alice_headers = tokens["lead_alice"]
    bob_headers = tokens["analyst_bob"]
    outsider_headers = tokens["lead_outsider"]

    case_id = "CASE-ALICE-SEC-01"

    # Alice creates a case owned by her
    create_resp = client.post(
        "/api/cases",
        json={
            "case_id": case_id,
            "case_name": "Alice Private Investigation",
            "organization_name": "ACME Defense",
            "investigation_goal": "Investigate APT persistence",
        },
        headers=alice_headers,
    )
    assert create_resp.status_code in (200, 201)

    # 1. Analyst Bob (not assigned) is denied access
    bob_get = client.get(f"/api/cases/{case_id}", headers=bob_headers)
    assert bob_get.status_code == 403
    assert "not authorized" in bob_get.json()["detail"].lower()

    # 2. Lead Outsider (another lead, not assigned) is ALSO denied access (role alone does not grant access)
    outsider_get = client.get(f"/api/cases/{case_id}", headers=outsider_headers)
    assert outsider_get.status_code == 403

    # 3. Unauthorized investigator cannot execute copilot chat on Alice's case
    chat_resp = client.post(
        "/api/copilot/chat",
        json={"case_id": case_id, "message": "List active findings", "send_system_prompt": True},
        headers=bob_headers,
    )
    assert chat_resp.status_code == 403

    # 4. Unauthorized investigator cannot inspect custody ledger
    custody_resp = client.get(f"/api/intake/custody/{case_id}", headers=bob_headers)
    assert custody_resp.status_code == 403

    # 5. Unauthorized investigator cannot retrieve report
    report_resp = client.get(f"/api/reports/{case_id}", headers=bob_headers)
    assert report_resp.status_code == 403


# ==============================================================================
# 4. Assigned Investigator Access Works
# ==============================================================================
def test_assigned_investigator_access_works(auth_isolation_env):
    """Verify that an assigned investigator (collaborator) can access case telemetry."""
    client: TestClient = auth_isolation_env["client"]
    tokens: Dict[str, Dict[str, str]] = auth_isolation_env["tokens"]
    llm_store = auth_isolation_env["llm_store"]

    alice_headers = tokens["lead_alice"]
    bob_headers = tokens["analyst_bob"]
    case_id = "CASE-TEAM-01"

    # Alice creates case and assigns Bob as collaborator
    client.post(
        "/api/cases",
        json={
            "case_id": case_id,
            "case_name": "Team Investigation",
            "organization_name": "ACME Defense",
            "investigation_goal": "Analyze lateral movement",
        },
        headers=alice_headers,
    )

    # Assign Bob in serialized_state
    llm_store.create_or_update_case({
        "case_id": case_id,
        "lead_analyst": "lead_alice",
        "serialized_state": {"assigned_analysts": ["analyst_bob"]},
    })

    # Bob accesses case metadata -> 200 OK
    resp = client.get(f"/api/cases/{case_id}", headers=bob_headers)
    assert resp.status_code == 200
    assert resp.json()["case_id"] == case_id

    # Bob accesses custody ledger -> 200 OK
    resp_custody = client.get(f"/api/intake/custody/{case_id}", headers=bob_headers)
    assert resp_custody.status_code == 200


# ==============================================================================
# 5. Shared Vault Peer Review: Read-Only Access
# ==============================================================================
def test_shared_vault_peer_review_is_read_only(auth_isolation_env):
    """Verify that is_shared_to_vault=True grants peer review read access, but rejects mutations."""
    client: TestClient = auth_isolation_env["client"]
    tokens: Dict[str, Dict[str, str]] = auth_isolation_env["tokens"]
    llm_store = auth_isolation_env["llm_store"]

    alice_headers = tokens["lead_alice"]
    outsider_headers = tokens["lead_outsider"]
    clara_headers = tokens["auditor_clara"]
    case_id = "CASE-PEER-REVIEW-01"

    # Alice creates case and shares it to vault
    client.post(
        "/api/cases",
        json={
            "case_id": case_id,
            "case_name": "Peer Review Case",
            "organization_name": "ACME Defense",
        },
        headers=alice_headers,
    )
    llm_store.create_or_update_case({
        "case_id": case_id,
        "lead_analyst": "lead_alice",
        "is_shared_to_vault": True,
    })

    # Outsider can READ the case for peer review -> 200 OK
    resp_read = client.get(f"/api/cases/{case_id}", headers=outsider_headers)
    assert resp_read.status_code == 200

    # Auditor Clara can READ custody ledger -> 200 OK
    resp_auditor = client.get(f"/api/intake/custody/{case_id}", headers=clara_headers)
    assert resp_auditor.status_code == 200

    # Outsider CANNOT mutate or delete Alice's case -> 403 Forbidden
    resp_delete = client.delete(f"/api/cases/{case_id}", headers=outsider_headers)
    assert resp_delete.status_code == 403


# ==============================================================================
# 6. Single-Finding Isolation & Cross-Case Denial
# ==============================================================================
def test_single_finding_isolation_and_cross_case_denial(auth_isolation_env):
    """Verify single-finding retrieval verifies case boundary and rejects cross-case queries."""
    client: TestClient = auth_isolation_env["client"]
    tokens: Dict[str, Dict[str, str]] = auth_isolation_env["tokens"]
    llm_store = auth_isolation_env["llm_store"]

    alice_headers = tokens["lead_alice"]
    bob_headers = tokens["analyst_bob"]

    case_a = "CASE-ALPHA-01"
    case_b = "CASE-BETA-02"

    # Register Alice's case A and Bob's case B
    llm_store.create_or_update_case({"case_id": case_a, "lead_analyst": "lead_alice"})
    llm_store.create_or_update_case({"case_id": case_b, "lead_analyst": "analyst_bob"})

    # Store finding in Case A
    storage_a = get_storage(case_a)
    finding_a = ForensicFinding(
        case_id=case_a,
        source_artifact_id="art-001",
        artifact_type="evtx",
        tool_id="evtx_dump",
        timestamp_utc=datetime.now(timezone.utc).isoformat(),
        finding_id="find-alice-classified",
        source_artifact_hash="a" * 64,
        category="InitialAccess",
        severity="high",
        summary="Classified threat telemetry for Alpha",
    )
    storage_a.insert_findings([finding_a])

    # 1. Alice can access her own finding -> 200 OK
    resp = client.get(f"/api/findings/find-alice-classified?case_id={case_a}", headers=alice_headers)
    assert resp.status_code == 200
    assert resp.json()["finding_id"] == "find-alice-classified"

    # 2. Bob cannot access Alice's finding under Case A -> 403 Forbidden
    resp_bob = client.get(f"/api/findings/find-alice-classified?case_id={case_a}", headers=bob_headers)
    assert resp_bob.status_code == 403

    # 3. Bob attempts cross-case retrieval querying finding_id under Case B -> 404 Not Found
    resp_cross = client.get(f"/api/findings/find-alice-classified?case_id={case_b}", headers=bob_headers)
    assert resp_cross.status_code == 404


# ==============================================================================
# 7. Hypothesis Provenance Validation & Fabricated Finding Rejection
# ==============================================================================
def test_hypothesis_fabricated_findings_rejected(auth_isolation_env):
    """Verify that caller-supplied fabricated findings or invalid hashes are rejected."""
    client: TestClient = auth_isolation_env["client"]
    tokens: Dict[str, Dict[str, str]] = auth_isolation_env["tokens"]
    llm_store = auth_isolation_env["llm_store"]

    alice_headers = tokens["lead_alice"]
    case_id = "CASE-PROVENANCE-01"
    llm_store.create_or_update_case({"case_id": case_id, "lead_analyst": "lead_alice"})

    # Store one genuine finding in case storage
    storage = get_storage(case_id)
    real_f = ForensicFinding(
        case_id=case_id,
        source_artifact_id="art-real-01",
        artifact_type="evtx",
        tool_id="evtx_dump",
        timestamp_utc=datetime.now(timezone.utc).isoformat(),
        finding_id="find-real-001",
        source_artifact_hash="1" * 64,
        category="CredentialAccess",
        severity="high",
        summary="Verified LSASS handle access from Security EVTX",
        user="SYSTEM",
        host="CORP-DC01",
    )
    storage.insert_findings([real_f])

    # Fabricated finding: wrong case_id (cross-case injection attempt)
    fake_cross_case = ForensicFinding(
        case_id="FOREIGN-CASE-99",
        source_artifact_id="art-fake-01",
        artifact_type="evtx",
        tool_id="evtx_dump",
        timestamp_utc=datetime.now(timezone.utc).isoformat(),
        finding_id="find-fake-cross",
        source_artifact_hash="2" * 64,
        category="LateralMovement",
        severity="critical",
        summary="Fabricated lateral movement injection",
    )

    # Fabricated finding: bogus hash (not 64-hex SHA-256)
    fake_bad_hash = ForensicFinding(
        case_id=case_id,
        source_artifact_id="art-fake-02",
        artifact_type="evtx",
        tool_id="evtx_dump",
        timestamp_utc=datetime.now(timezone.utc).isoformat(),
        finding_id="find-fake-hash",
        source_artifact_hash="short_invalid_hash",
        category="LateralMovement",
        severity="critical",
        summary="Fabricated finding with bogus hash",
    )

    # Non-existent finding ID
    req_payload = {
        "case_id": case_id,
        "investigation_goal": "Investigate credential dumping and lateral movement",
        "finding_ids": ["find-real-001", "find-completely-fake-999"],
        "findings": [fake_cross_case.model_dump(mode="json"), fake_bad_hash.model_dump(mode="json")],
    }

    resp = client.post("/api/agent/plan-hypothesis", json=req_payload, headers=alice_headers)
    assert resp.status_code == 200
    data = resp.json()

    # Verify that only the real finding was cited, and fabricated findings were discarded
    cited = data.get("cited_findings", [])
    assert len(cited) >= 1
    for c in cited:
        assert "find-fake-cross" not in c["citing_finding_ids"]
        assert "find-fake-hash" not in c["citing_finding_ids"]
        assert "find-completely-fake-999" not in c["citing_finding_ids"]
        assert "find-real-001" in c["citing_finding_ids"]


# ==============================================================================
# 8. Production Environment Ignores Test Headers
# ==============================================================================
def test_production_ignores_test_headers(auth_isolation_env, monkeypatch):
    """Verify that when FORENSICOPS_ENVIRONMENT=production, test bypass headers are strictly rejected."""
    client: TestClient = auth_isolation_env["client"]

    # Set production environment
    monkeypatch.setenv("FORENSICOPS_ENVIRONMENT", "production")
    monkeypatch.setenv("FORENSICOPS_AUTH_DISABLED", "true")  # Attempt to disable auth

    # Request with test headers but no JWT Bearer token
    headers = {
        "X-ForensicOps-Test-User": "lead_admin",
        "X-ForensicOps-Test-Role": "lead_investigator",
        "X-ForensicOps-Test-Badge": "BADGE-999",
    }

    resp = client.get("/api/cases", headers=headers)
    assert resp.status_code == 401
    assert "token required" in resp.json()["detail"].lower()


# ==============================================================================
# 9. Custody Chain Integrity Rejects Cross-Case Ledger Tampering
# ==============================================================================
def test_custody_chain_integrity_detects_cross_case_tampering(auth_isolation_env):
    """Verify that CustodyEngine flags entries that do not match the expected case_id."""
    case_id = "CASE-CUSTODY-VERIFY-01"
    custody = get_custody_engine(case_id)

    # Create legitimate record
    rec = custody.store_raw_bytes(
        raw_bytes=b"FORENSIC_EVIDENCE_SAMPLE_001",
        case_id=case_id,
        original_filename="sample.bin",
        artifact_type="binary",
        actor="lead_alice",
    )

    # Verify chain is clean
    assert custody.verify_chain(case_id) is True

    # Tamper with the custody table in SQLite: modify the case_id of an entry to simulate cross-case contamination
    with custody._get_connection() as conn:
        conn.execute("UPDATE custody_chain SET case_id = 'CONTAMINATED_FOREIGN_CASE' WHERE seq_id = 1;")
        conn.commit()

    # verify_chain(case_id) must detect the tamper failure
    assert custody.verify_chain(case_id) is False
    is_valid, errors = custody.verify_chain_integrity(case_id)
    assert is_valid is False
    assert any("cross-case contamination" in e.lower() for e in errors)
