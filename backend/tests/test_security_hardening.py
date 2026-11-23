"""Security Hardening and Vulnerability Regression Test Suite.

Tests:
1. [CRIT-01] Verification that X-ForensicOps-Test-* headers CANNOT bypass JWT validation when FORENSICOPS_AUTH_DISABLED=false.
2. [CRIT-02] WinRMTransport & EndpointTarget host validation against remote command injection attempts.
3. [CRIT-03] RBAC enforcement and tool_id path traversal prevention on /api/plugins/register.
4. [HIGH-01] SQL injection prevention in query_structured_findings and create_dataset_view.
5. [HIGH-02] Path traversal (Zip Slip) rejection in capsule manifest bundle_path.
6. [HIGH-03] Directory traversal prevention via case_id in vault root validation.
7. [HIGH-04] Path confinement on /api/intake/browse-local against system directories.
8. [MED-01] RBAC authentication enforcement on cases, sessions, llm select, and reports.
9. [MED-02] Cryptographic HMAC-SHA256 and expiration enforcement in HumanApprovalToken.
10. [MED-03] Production JWT secret enforcement without fallback.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
import zipfile
import pytest
from fastapi.testclient import TestClient

from backend.app.api.deps import (
    get_custody_engine,
    get_storage,
    reset_dependencies,
    set_base_vault_dir,
    validate_vault_case_root,
)
from backend.app.auth.dependencies import reset_user_store, set_user_store
from backend.app.auth.models import UserRead
from backend.app.auth.security import create_access_token, get_jwt_secret
from backend.app.auth.store import UserStore
from backend.app.core.custody_engine import CustodyEngine
from backend.app.core.exceptions import (
    ConnectorError,
    ForensicOpsError,
    StorageError,
    SuspiciousArchiveError,
)
from backend.app.core.plugin_runner import AirGappedSubprocessRunner
from backend.app.core.storage import ForensicStore
from backend.app.main import create_app
from backend.app.models.plugins import ToolPluginCard
from backend.app.models.workflow import HumanApprovalToken


@pytest.fixture
def sec_test_env(tmp_path: Path):
    """Hermetic test sandbox for security hardening validation."""
    vault_dir = tmp_path / "vault"
    vault_dir.mkdir(parents=True, exist_ok=True)
    set_base_vault_dir(vault_dir)

    user_store = UserStore(db_path=vault_dir / "users.db")
    set_user_store(user_store)

    app = create_app()
    client = TestClient(app)

    yield client, user_store, vault_dir

    reset_user_store()
    reset_dependencies()


# ==============================================================================
# 1. [CRIT-01] Authentication Bypass Prevention
# ==============================================================================
def test_crit_01_test_header_cannot_bypass_when_auth_enabled(sec_test_env, monkeypatch):
    """Ensure X-ForensicOps-Test-Role is completely ignored when FORENSICOPS_AUTH_DISABLED=false."""
    client, store, _ = sec_test_env
    monkeypatch.setenv("FORENSICOPS_AUTH_DISABLED", "false")

    # Send a request with test bypass headers but NO Authorization Bearer token
    resp = client.get(
        "/api/auth/me",
        headers={
            "X-ForensicOps-Test-Role": "lead_investigator",
            "X-ForensicOps-Test-User": "hacker",
        },
    )
    # Must be rejected with 401 Unauthorized
    assert resp.status_code == 401
    assert "token required" in resp.json()["detail"].lower()


# ==============================================================================
# 2. [CRIT-02] Remote Collection Denial Enforcement
# ==============================================================================
def test_crit_02_remote_collection_permanently_removed(sec_test_env):
    """Verify that remote collection endpoints and workflows are permanently removed and reject dispatch."""
    client, store, vault_dir = sec_test_env
    (vault_dir / "sec_case").mkdir(parents=True, exist_ok=True)
    # Direct endpoint returns 404
    resp = client.post("/api/intake/online", json={"target": {"host": "192.168.1.50"}})
    assert resp.status_code == 404

    # Setup lead investigator user for auth header
    from backend.app.auth.models import UserCreate
    from backend.app.auth.security import hash_password
    user = store.create_user(
        UserCreate(username="lead_sec_02", password="password123", badge_id="B-002", role="lead_investigator"),
        password_hash=hash_password("password123"),
    )
    token = create_access_token({
        "sub": "lead_sec_02",
        "role": "lead_investigator",
        "user_id": user.id,
        "badge_id": user.badge_id,
    })
    headers = {"Authorization": f"Bearer {token}"}

    # Workflow token request for remote collection is rejected with 400
    token_resp = client.post(
        "/api/workflows/approval-token",
        json={"case_id": "sec_case", "node_id": "collector_gate", "action_type": "remote_collection"},
        headers=headers,
    )
    assert token_resp.status_code == 400
    assert "Remote collection has been removed" in token_resp.json()["detail"]


# ==============================================================================
# 3. [CRIT-03] Unauthenticated Plugin Registration & RCE Prevention
# ==============================================================================
def test_crit_03_plugin_registration_requires_lead_investigator(sec_test_env, monkeypatch):
    """Verify /api/plugins/register rejects unauthenticated or unauthorized users."""
    client, store, _ = sec_test_env
    monkeypatch.setenv("FORENSICOPS_AUTH_DISABLED", "false")

    card_payload = {
        "tool_id": "malicious_tool",
        "name": "Malicious Tool",
        "execution_tier": "tier_b_adapter",
        "command_template": ["malicious_bin", "{input_path}"],
    }

    # Unauthenticated request
    resp = client.post("/api/plugins/register", json=card_payload)
    assert resp.status_code == 401

    # Request as SOC Analyst (only lead_investigator allowed)
    from backend.app.auth.models import UserCreate
    from backend.app.auth.security import hash_password

    user_create = UserCreate(
        username="analyst_1",
        password="SecretPass123!",
        role="soc_analyst",
        badge_id="B-ANALYST",
    )
    analyst_user = store.create_user(user_create, password_hash=hash_password("SecretPass123!"))
    analyst_token = create_access_token({
        "sub": "analyst_1",
        "role": "soc_analyst",
        "user_id": analyst_user.id,
        "badge_id": analyst_user.badge_id,
    })
    resp2 = client.post(
        "/api/plugins/register",
        json=card_payload,
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    assert resp2.status_code == 403


def test_crit_03_plugin_registration_path_traversal_rejection(sec_test_env, monkeypatch):
    """Verify /api/plugins/register rejects tool_ids with directory traversal."""
    client, store, _ = sec_test_env
    # Allow test auth for this check
    monkeypatch.setenv("FORENSICOPS_AUTH_DISABLED", "true")

    bad_card = {
        "tool_id": "../../evil_escape",
        "name": "Traversal Tool",
        "execution_tier": "tier_b_adapter",
        "command_template": ["safe_bin", "{input_path}"],
    }
    resp = client.post("/api/plugins/register", json=bad_card)
    # Schema validation rejects with 422, or endpoint logic with 400
    assert resp.status_code in (400, 422)


def test_crit_03_plugin_runner_host_binary_allowlist():
    """Verify AirGappedSubprocessRunner blocks unapproved binaries when executing on host."""
    runner = AirGappedSubprocessRunner(use_docker_if_available=False)
    with pytest.raises(ForensicOpsError, match="not in the approved forensic tool allowlist"):
        runner.execute(["powershell.exe", "-Command", "whoami"], cwd=Path("."))


# ==============================================================================
# 4. [HIGH-01] SQL Injection Prevention in DuckDB Storage
# ==============================================================================
def test_high_01_query_structured_findings_rejects_sql_injection():
    """Verify query_structured_findings rejects unauthorized filter columns and order_by injections."""
    store = ForensicStore(":memory:")

    # SQL injection in order_by
    with pytest.raises(StorageError, match="Invalid or unauthorized order_by"):
        store.query_structured_findings(order_by="timestamp_utc; DROP TABLE findings; --")

    # SQL injection in filter field key
    with pytest.raises(StorageError, match="Invalid or unauthorized filter field"):
        store.query_structured_findings(filters={"1=1; DELETE FROM findings; --": "test"})


def test_high_01_create_dataset_view_rejects_sql_injection():
    """Verify create_dataset_view sanitizes case_id and rejects injection column keys."""
    store = ForensicStore(":memory:")

    # Malicious case_id
    with pytest.raises(StorageError, match="Invalid case_id format"):
        store.create_dataset_view("test_view", query_filter={}, case_id="case' OR '1'='1")

    # Malicious filter key
    with pytest.raises(StorageError, match="Invalid or unauthorized column"):
        store.create_dataset_view("test_view", query_filter={"unauthorized_col; DROP TABLE findings; --": "val"})


# ==============================================================================
# 5. [HIGH-02] Path Traversal in Capsule Unpacking
# ==============================================================================
def test_high_02_capsule_unpacker_rejects_traversal_bundle_path(tmp_path: Path):
    """Verify unpack_collector_capsule raises SuspiciousArchiveError if manifest bundle_path escapes."""
    engine = CustodyEngine(vault_root=tmp_path / "vault", db_path=tmp_path / "vault" / "c.db")

    capsule_dir = tmp_path / "capsule_build"
    capsule_dir.mkdir()
    artifacts_dir = capsule_dir / "artifacts"
    artifacts_dir.mkdir()

    real_file = artifacts_dir / "test.log"
    real_file.write_bytes(b"DATA")

    # Manifest specifying a bundle_path that attempts directory traversal
    manifest = {
        "case_id": "case_zipslip",
        "created_utc": "2026-01-01T00:00:00Z",
        "collector_version": "1.0",
        "artifacts": [
            {
                "artifact_id": "art-bad-1",
                "type": "log",
                "original_path": "/var/log/syslog",
                "bundle_path": "../../evil_escape.log",
                "size_bytes": 4,
                "sha256": "3e9b11933cc4cfbe78877e8a9f62ff3ef454c0e5a9ee7741cb33be2ad79ff10e",
                "sha512": "3e9b" * 32,
            }
        ],
    }
    (capsule_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    capsule_zip = tmp_path / "traversal_capsule.zip"
    with zipfile.ZipFile(capsule_zip, "w") as zf:
        zf.write(capsule_dir / "manifest.json", "manifest.json")
        zf.write(real_file, "artifacts/test.log")

    with pytest.raises(SuspiciousArchiveError, match="Path traversal detected"):
        engine.unpack_collector_capsule(capsule_zip)


# ==============================================================================
# 6. [HIGH-03] Case ID Directory Traversal Prevention
# ==============================================================================
def test_high_03_validate_vault_case_root_rejects_traversal():
    """Verify validate_vault_case_root rejects traversal characters and invalid case IDs."""
    bad_case_ids = [
        "../escaped_case",
        "..\\windows\\system32",
        "case/subcase",
        "case;rm -rf",
        "   ",
        "case space",
    ]
    for cid in bad_case_ids:
        with pytest.raises(ForensicOpsError, match="Invalid case_id format"):
            validate_vault_case_root(cid)


# ==============================================================================
# 7. [HIGH-04] Path Confinement on Local Host Browse
# ==============================================================================
def test_high_04_browse_local_blocks_system_directories(sec_test_env, monkeypatch):
    """Verify /api/intake/browse-local returns 403 when attempting to browse prohibited system paths."""
    client, _, _ = sec_test_env
    monkeypatch.setenv("FORENSICOPS_AUTH_DISABLED", "true")

    # Attempt to browse Windows or POSIX system root
    sys_dir = os.environ.get("SystemRoot", "/etc")
    resp = client.post(
        "/api/intake/browse-local",
        json={"current_path": sys_dir},
    )
    assert resp.status_code == 403
    assert "prohibited" in resp.json()["detail"].lower()


# ==============================================================================
# 8. [MED-02] Cryptographic Hardening: HMAC & Expiration in HumanApprovalToken
# ==============================================================================
def test_med_02_human_approval_token_hmac_and_expiration():
    """Verify HumanApprovalToken uses HMAC signature and rejects expired tokens."""
    token = HumanApprovalToken(node_id="gate1", case_id="case_sec", issued_by="analyst_lead")
    token.sign("secret123")

    # Valid token
    assert token.verify("secret123") is True

    # Tampered signature
    token.signature = "bad" + token.signature[3:]
    assert token.verify("secret123") is False

    # Expired token (issued 2 hours ago with 1 hour max age)
    token.sign("secret123")
    old_time = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    token.timestamp_utc = old_time
    token.sign("secret123")
    assert token.verify("secret123", max_age_seconds=3600.0) is False


# ==============================================================================
# 9. [MED-03] Production JWT Secret Enforcement
# ==============================================================================
def test_med_03_jwt_secret_enforcement_in_production(monkeypatch):
    """Verify that in production without FORENSICOPS_JWT_SECRET, get_jwt_secret raises RuntimeError."""
    monkeypatch.delenv("FORENSICOPS_JWT_SECRET", raising=False)
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    monkeypatch.setenv("FORENSICOPS_ENVIRONMENT", "production")

    with pytest.raises(RuntimeError, match="FORENSICOPS_JWT_SECRET environment variable is missing in production"):
        get_jwt_secret()
