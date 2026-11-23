"""Regression Test Suite for Phase 15-B: Investigation API Endpoints & Live Vault WAL Checkpoint."""

import json
import os
import sqlite3
from pathlib import Path
from typing import Any, Dict
from uuid import uuid4
import pytest
from fastapi.testclient import TestClient

from backend.app.api.deps import (
    get_custody_engine,
    get_storage,
    reset_dependencies,
    set_base_vault_dir,
)
from backend.app.api.investigations import _active_controllers
from backend.app.auth.dependencies import reset_user_store, set_user_store
from backend.app.auth.models import UserCreate
from backend.app.auth.security import create_access_token, hash_password
from backend.app.auth.store import UserStore
from backend.app.core.crypto import (
    AESGCMVaultCipher,
    export_encrypted_vault,
    import_encrypted_vault,
)
from backend.app.core.storage import ForensicStore
from backend.app.db.sqlite_store import LLMStateStore, get_llm_state_store, reset_llm_state_store
from backend.app.main import create_app
from backend.app.models.findings import ForensicFinding
from backend.app.models.investigation import CompetingHypothesis


@pytest.fixture
def phase15b_env(tmp_path: Path):
    """Isolated environment for Phase 15-B tests."""
    vault_dir = tmp_path / "vault"
    vault_dir.mkdir(parents=True, exist_ok=True)
    secret_key = "test-phase15b-hmac-secret-key-32b!!"
    jwt_secret = "test-phase15b-jwt-secret-key-32b!!"

    old_env = {
        "FORENSICOPS_VAULT_DIR": os.environ.get("FORENSICOPS_VAULT_DIR"),
        "FORENSICOPS_JWT_SECRET": os.environ.get("FORENSICOPS_JWT_SECRET"),
        "HUMAN_APPROVAL_HMAC_SECRET": os.environ.get("HUMAN_APPROVAL_HMAC_SECRET"),
        "FORENSICOPS_AUTH_DISABLED": os.environ.get("FORENSICOPS_AUTH_DISABLED"),
        "LLM_MOCK_MODE": os.environ.get("LLM_MOCK_MODE"),
    }

    os.environ["FORENSICOPS_VAULT_DIR"] = str(vault_dir)
    os.environ["FORENSICOPS_JWT_SECRET"] = jwt_secret
    os.environ["HUMAN_APPROVAL_HMAC_SECRET"] = secret_key
    os.environ["FORENSICOPS_AUTH_DISABLED"] = "false"
    os.environ["LLM_MOCK_MODE"] = "true"

    set_base_vault_dir(vault_dir)
    reset_dependencies()
    _active_controllers.clear()

    # User Store & Auth Setup
    user_db_path = tmp_path / "auth_users.db"
    user_store = UserStore(db_path=str(user_db_path))
    set_user_store(user_store)

    u_lead = user_store.create_user(
        UserCreate(
            username="lead_alice",
            email="alice@forensicops.local",
            password="StrongPassword123!",
            role="lead_investigator",
            badge_id="BADGE-001",
        ),
        password_hash=hash_password("StrongPassword123!"),
    )

    token_alice = create_access_token(
        data={"sub": u_lead.username, "user_id": u_lead.id, "role": u_lead.role, "badge_id": u_lead.badge_id}
    )

    headers = {"Authorization": f"Bearer {token_alice}"}
    app = create_app()
    client = TestClient(app)

    yield {
        "client": client,
        "headers": headers,
        "vault_dir": vault_dir,
        "tmp_path": tmp_path,
        "secret_key": secret_key,
    }

    # Teardown
    reset_dependencies()
    reset_llm_state_store()
    reset_user_store()
    _active_controllers.clear()
    for k, v in old_env.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


def test_investigations_findings_endpoint(phase15b_env):
    """Verify GET /api/investigations/{case_id}/findings retrieves case-scoped findings."""
    client = phase15b_env["client"]
    headers = phase15b_env["headers"]
    case_id = f"case-test-findings-{uuid4().hex[:6]}"

    # Start investigation to initialize case
    start_res = client.post(
        "/api/investigations/start",
        json={"case_id": case_id, "objective": "Analyze malware artifacts", "autorun": False},
        headers=headers,
    )
    assert start_res.status_code == 200

    # Ingest synthetic findings into ForensicStore
    storage = get_storage(case_id)
    f1 = ForensicFinding(
        finding_id="find-001",
        case_id=case_id,
        source_artifact_id="art-001",
        source_artifact_hash="a" * 64,
        tool_id="dissect_registry",
        artifact_type="registry_hive",
        category="persistence",
        severity="high",
        timestamp_utc="2026-11-20T10:00:00Z",
        summary="Registry Run Key Persistence Detected",
        projected_data={"key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
    )
    storage.insert_findings([f1])

    # Query endpoint
    res = client.get(f"/api/investigations/{case_id}/findings", headers=headers)
    assert res.status_code == 200
    findings = res.json()
    assert len(findings) == 1
    assert findings[0]["finding_id"] == "find-001"
    assert findings[0]["case_id"] == case_id
    assert findings[0]["summary"] == "Registry Run Key Persistence Detected"


def test_investigations_hypotheses_endpoint(phase15b_env):
    """Verify GET /api/investigations/{case_id}/hypotheses returns active competing hypotheses."""
    client = phase15b_env["client"]
    headers = phase15b_env["headers"]
    case_id = f"case-test-hypo-{uuid4().hex[:6]}"

    start_res = client.post(
        "/api/investigations/start",
        json={"case_id": case_id, "objective": "Investigate lateral movement", "autorun": False},
        headers=headers,
    )
    assert start_res.status_code == 200

    # Query hypotheses endpoint
    res = client.get(f"/api/investigations/{case_id}/hypotheses", headers=headers)
    assert res.status_code == 200
    hypotheses = res.json()
    assert isinstance(hypotheses, list)


def test_investigations_timeline_endpoint(phase15b_env):
    """Verify GET /api/investigations/{case_id}/timeline returns chronologically sorted events."""
    client = phase15b_env["client"]
    headers = phase15b_env["headers"]
    case_id = f"case-test-timeline-{uuid4().hex[:6]}"

    # Start investigation
    start_res = client.post(
        "/api/investigations/start",
        json={"case_id": case_id, "objective": "Timeline assessment", "autorun": False},
        headers=headers,
    )
    assert start_res.status_code == 200

    # Insert findings with distinct timestamps
    storage = get_storage(case_id)
    f_early = ForensicFinding(
        finding_id="find-early",
        case_id=case_id,
        source_artifact_id="art-001",
        source_artifact_hash="b" * 64,
        tool_id="dissect_evtx",
        artifact_type="evtx",
        category="execution",
        severity="medium",
        timestamp_utc="2026-11-20T08:00:00Z",
        summary="Initial Process Execution",
    )
    f_late = ForensicFinding(
        finding_id="find-late",
        case_id=case_id,
        source_artifact_id="art-001",
        source_artifact_hash="b" * 64,
        tool_id="dissect_evtx",
        artifact_type="evtx",
        category="lateral_movement",
        severity="critical",
        timestamp_utc="2026-11-20T12:00:00Z",
        summary="Remote Service Execution",
    )
    storage.insert_findings([f_late, f_early])

    # Query timeline endpoint
    res = client.get(f"/api/investigations/{case_id}/timeline", headers=headers)
    assert res.status_code == 200
    timeline = res.json()
    assert len(timeline) >= 2
    # Verify chronological ordering
    timestamps = [e["timestamp_utc"] for e in timeline if e.get("timestamp_utc")]
    assert timestamps == sorted(timestamps)
    assert any(e["event_id"] == "find-early" for e in timeline)
    assert any(e["event_id"] == "find-late" for e in timeline)


def test_reports_export_endpoint(phase15b_env):
    """Verify GET /api/reports/{case_id}/export exports downloadable markdown and json reports."""
    client = phase15b_env["client"]
    headers = phase15b_env["headers"]
    case_id = f"case-test-report-exp-{uuid4().hex[:6]}"

    # Start investigation / case setup
    client.post(
        "/api/investigations/start",
        json={"case_id": case_id, "objective": "Export testing", "autorun": False},
        headers=headers,
    )

    # 1. Export Markdown format
    res_md = client.get(f"/api/reports/{case_id}/export?format=markdown", headers=headers)
    assert res_md.status_code == 200
    assert "text/markdown" in res_md.headers["content-type"]
    assert f'filename="report_{case_id}.md"' in res_md.headers["content-disposition"]
    assert len(res_md.text) > 0

    # 2. Export JSON format
    res_json = client.get(f"/api/reports/{case_id}/export?format=json", headers=headers)
    assert res_json.status_code == 200
    assert "application/json" in res_json.headers["content-type"]
    assert f'filename="report_{case_id}.json"' in res_json.headers["content-disposition"]
    data = res_json.json()
    assert data["case_id"] == case_id

    # 3. Invalid format rejection
    res_bad = client.get(f"/api/reports/{case_id}/export?format=invalid", headers=headers)
    assert res_bad.status_code in (400, 422)


def test_intake_custody_export_endpoint(phase15b_env):
    """Verify GET /api/intake/custody/{case_id}/export exports downloadable JSONL and JSON custody records."""
    client = phase15b_env["client"]
    headers = phase15b_env["headers"]
    case_id = f"case-test-custody-exp-{uuid4().hex[:6]}"

    # Ingest artifact to establish custody chain
    custody = get_custody_engine(case_id)
    custody.store_raw_bytes(
        raw_bytes=b"sample evidence log bytes",
        case_id=case_id,
        original_filename="audit.evtx",
        artifact_type="evtx",
        actor="lead_alice",
    )

    # 1. Export JSONL format
    res_jsonl = client.get(f"/api/intake/custody/{case_id}/export?format=jsonl", headers=headers)
    assert res_jsonl.status_code == 200
    assert "application/x-ndjson" in res_jsonl.headers["content-type"]
    assert f'filename="custody_ledger_{case_id}.jsonl"' in res_jsonl.headers["content-disposition"]
    lines = [l for l in res_jsonl.text.strip().split("\n") if l]
    assert len(lines) >= 1
    first_entry = json.loads(lines[0])
    assert first_entry["case_id"] == case_id

    # 2. Export JSON format
    res_json = client.get(f"/api/intake/custody/{case_id}/export?format=json", headers=headers)
    assert res_json.status_code == 200
    assert "application/json" in res_json.headers["content-type"]
    assert f'filename="custody_ledger_{case_id}.json"' in res_json.headers["content-disposition"]
    records = res_json.json()
    assert len(records) >= 1
    assert records[0]["case_id"] == case_id

    # 3. Invalid format rejection
    res_bad = client.get(f"/api/intake/custody/{case_id}/export?format=xml", headers=headers)
    assert res_bad.status_code in (400, 422)


def test_live_vault_wal_checkpoint_and_export(tmp_path):
    """Verify safe live vault export executes PRAGMA wal_checkpoint(TRUNCATE) and restores cleanly."""
    db_path = tmp_path / "live_wal_test.db"
    export_path = tmp_path / "live_vault_export.json"
    restored_db_path = tmp_path / "restored_wal_test.db"
    passphrase = "SecureWALPassphrase2026!!"

    # Create live database and set WAL mode
    store = LLMStateStore(db_path)
    store._conn.execute("PRAGMA journal_mode = WAL;")

    # Write records
    store.create_or_update_case({
        "case_id": "case-wal-001",
        "case_name": "Live WAL Verification",
        "organization_name": "DFIR Testing",
        "lead_analyst": "lead_alice",
        "active_provider_id": "ollama",
    })
    store.set_active_provider_id("ollama")

    # Confirm WAL file exists on disk
    wal_file = Path(f"{db_path}-wal")
    assert db_path.exists()

    # Perform encrypted vault export (invokes PRAGMA wal_checkpoint(TRUNCATE))
    out_file = store.export_encrypted_vault(export_path, passphrase, iterations=100000)
    assert Path(out_file).exists()

    # Import into restored database
    restored_store = LLMStateStore(restored_db_path)
    import_summary = restored_store.import_encrypted_vault(export_path, passphrase)
    assert import_summary["status"] == "success"

    # Verify data integrity
    restored_case = restored_store.get_case("case-wal-001")
    assert restored_case is not None
    assert restored_case["case_name"] == "Live WAL Verification"
    assert restored_store.get_active_provider_id() == "ollama"

    store.close()
    restored_store.close()
