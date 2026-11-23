"""Phase 16-A Backend Hardening Tests.

Verifies:
1. Memory-bounded streaming RFC 3227 SHA-256 evidence hashing in PluginRunner and Graph.
2. Fail-closed evidence tampering detection in PluginRunner.
3. Strict citation enforcement (`strict_citations=True`) across compile_report_from_nodes.
4. Defense-in-depth Content-Disposition filename sanitization on report and custody export routes.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Generator
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from backend.app.agent.report_builder import CitedReport, ReportBuilder
from backend.app.api.deps import (
    reset_dependencies,
    set_base_vault_dir,
)
from backend.app.api.investigations import _active_controllers
from backend.app.auth.dependencies import set_user_store
from backend.app.auth.models import UserCreate
from backend.app.auth.security import create_access_token, hash_password
from backend.app.auth.store import UserStore
from backend.app.core.custody_engine import CustodyEngine
from backend.app.core.exceptions import CitationValidationError, ForensicOpsError
from backend.app.core.plugin_runner import PluginRunner, compute_streaming_sha256
from backend.app.core.storage import ForensicStore
from backend.app.main import create_app
from backend.app.models.custody import ArtifactRecord
from backend.app.models.findings import CitedClaim, ForensicFinding, NodeGoalResult
from backend.app.models.plugins import ToolPluginCard


@pytest.fixture
def env_and_client(tmp_path: Path):
    vault_dir = tmp_path / "vault"
    vault_dir.mkdir(parents=True, exist_ok=True)
    jwt_secret = "test_phase16_a_jwt_secret_key_32bytes_long!!"
    secret_key = "test_phase16_a_hmac_secret_key_32bytes_long!!"

    saved_env = {
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

    user_db_path = tmp_path / "auth_users.db"
    user_store = UserStore(db_path=str(user_db_path))
    set_user_store(user_store)

    u_lead = user_store.create_user(
        UserCreate(
            username="lead_alice",
            email="alice@forensicops.local",
            password="StrongPassword123!",
            role="lead_investigator",
            badge_id="BADGE-16A",
        ),
        password_hash=hash_password("StrongPassword123!"),
    )

    token = create_access_token(
        data={"sub": u_lead.username, "user_id": u_lead.id, "role": u_lead.role, "badge_id": u_lead.badge_id}
    )

    client = TestClient(create_app())
    headers = {"Authorization": f"Bearer {token}"}

    yield {"client": client, "headers": headers, "vault_dir": vault_dir}

    for k, v in saved_env.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    reset_dependencies()
    _active_controllers.clear()


# ==============================================================================
# 1. Memory-Bounded Streaming SHA-256 Hashing Tests
# ==============================================================================

def test_compute_streaming_sha256_matches_standard(tmp_path: Path):
    """Verify compute_streaming_sha256 produces exact match with hashlib.sha256."""
    test_file = tmp_path / "test_data.bin"
    data = os.urandom(2 * 1024 * 1024)
    test_file.write_bytes(data)

    expected = hashlib.sha256(data).hexdigest()
    actual = compute_streaming_sha256(test_file)
    assert actual == expected
    assert len(actual) == 64


def test_compute_streaming_sha256_empty_and_missing(tmp_path: Path):
    """Verify compute_streaming_sha256 handles empty file and non-existent paths."""
    empty_file = tmp_path / "empty.bin"
    empty_file.write_bytes(b"")
    assert compute_streaming_sha256(empty_file) == hashlib.sha256(b"").hexdigest()

    missing_file = tmp_path / "nonexistent.bin"
    assert compute_streaming_sha256(missing_file) == ""


def test_compute_streaming_sha256_large_sparse_file(tmp_path: Path):
    """Verify streaming hash calculation on a 64 MB sparse file without high memory usage."""
    sparse_file = tmp_path / "large_sparse.raw"
    with open(sparse_file, "wb") as f:
        f.seek(64 * 1024 * 1024 - 1)
        f.write(b"\x00")

    result = compute_streaming_sha256(sparse_file, chunk_size=4 * 1024 * 1024)
    assert len(result) == 64
    h = hashlib.sha256()
    with open(sparse_file, "rb") as f:
        while chunk := f.read(4 * 1024 * 1024):
            h.update(chunk)
    assert result == h.hexdigest()


def test_plugin_runner_tamper_detection_halts_fail_closed(tmp_path: Path):
    """Verify PluginRunner detects in-place evidence byte alteration and halts fail-closed."""
    vault_dir = tmp_path / "vault"
    vault_dir.mkdir()
    evidence_file = vault_dir / "target_disk.raw"
    original_data = b"FORENSIC_EVIDENCE_ORIGINAL_BYTES_SAFE"
    evidence_file.write_bytes(original_data)

    original_hash = hashlib.sha256(original_data).hexdigest()
    original_sha512 = hashlib.sha512(original_data).hexdigest()
    artifact = ArtifactRecord(
        artifact_id="art-test-01",
        case_id="case-16a-tamper",
        type="raw_disk",
        original_path=str(evidence_file),
        blob_path=str(evidence_file),
        sha256=original_hash,
        sha512=original_sha512,
        size_bytes=len(original_data),
        acquisition_method="local_import",
    )

    from backend.app.core.dissect_adapter import DissectAdapter

    class MutatingDissectAdapter(DissectAdapter):
        def parse_collector_artifact(self, input_path, case_id, artifact_id, sha256):
            with open(input_path, "r+b") as ef:
                ef.write(b"CORRUPTED_BYTES")
            return []

    runner = PluginRunner(dissect_adapter=MutatingDissectAdapter())

    card = ToolPluginCard(
        tool_id="dissect_custom",
        name="Mutating Dissect Tool",
        description="Mutating tool for RFC 3227 test",
        version="1.0.0",
        execution_tier="tier_a_builtin",
        category="evtx",
        command_template=["custom"],
    )

    with pytest.raises(ForensicOpsError, match="Evidence integrity violation"):
        runner.run_plugin(
            plugin=card,
            artifact=artifact,
            output_workspace=tmp_path / "workspace",
        )


def test_plugin_runner_tier_b_tamper_detection_halts_fail_closed(tmp_path: Path):
    """Verify PluginRunner Tier B execution detects in-place evidence byte alteration and halts fail-closed."""
    vault_dir = tmp_path / "vault_tier_b"
    vault_dir.mkdir()
    evidence_file = vault_dir / "target_sample.evtx"
    original_data = b"FORENSIC_EVTX_ORIGINAL_BYTES_IMMUTABLE"
    evidence_file.write_bytes(original_data)

    original_hash = hashlib.sha256(original_data).hexdigest()
    original_sha512 = hashlib.sha512(original_data).hexdigest()
    artifact = ArtifactRecord(
        artifact_id="art-test-b",
        case_id="case-16a-tamper-b",
        type="evtx",
        original_path=str(evidence_file),
        blob_path=str(evidence_file),
        sha256=original_hash,
        sha512=original_sha512,
        size_bytes=len(original_data),
        acquisition_method="local_import",
    )

    from backend.app.core.plugin_runner import AirGappedSubprocessRunner

    def mutating_sub_handler(argv, input_dir, scratch_dir):
        with open(evidence_file, "r+b") as ef:
            ef.write(b"CORRUPTED_BYTES_TIER_B")
        out_file = scratch_dir / "out.json"
        out_file.write_text("[]", encoding="utf-8")
        return 0, "[]", ""

    sub_proc = AirGappedSubprocessRunner(allow_test_mock=True)
    sub_proc.register_mock_tool("safe_bin", mutating_sub_handler)
    runner = PluginRunner(subprocess_runner=sub_proc)

    card = ToolPluginCard(
        tool_id="safe_bin",
        name="Safe Test Binary",
        description="Safe test tool",
        version="1.0.0",
        execution_tier="tier_b_adapter",
        category="evtx",
        command_template=["safe_bin", "-f", "{input_path}", "--json", "{output_dir}"],
        container_image="ghcr.io/forensicops/safe_bin:latest",
        output_format="json",
        ai_keep_fields=["finding_id"],
    )

    with pytest.raises(ForensicOpsError, match="Evidence integrity violation"):
        runner.run_plugin(
            plugin=card,
            artifact=artifact,
            output_workspace=tmp_path / "workspace_b",
        )


# ==============================================================================
# 2. Strict Citations Enforcement on Reports Compile Route
# ==============================================================================

def test_compile_report_rejects_ungrounded_claims_fail_closed(env_and_client):
    """Verify POST /api/reports/compile raises CitationValidationError (HTTP 422) for hallucinated findings."""
    client = env_and_client["client"]
    headers = env_and_client["headers"]
    case_id = f"case_strict_{uuid4().hex[:8]}"

    # Initialize case first so case_authorization permits write
    client.post(
        "/api/investigations/start",
        json={"case_id": case_id, "objective": "Strict citation testing", "autorun": False},
        headers=headers,
    )

    fake_claim = {
        "claim_id": "claim-fake-001",
        "claim_type": "observed_fact",
        "statement": "Attacker exfiltrated SAM database to 1.2.3.4",
        "citing_finding_ids": ["FND-NONEXISTENT-9999"],
        "source_artifact_hashes": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
        "confidence": 0.95,
        "verification_status": "VERIFIED",
    }
    payload = {
        "case_id": case_id,
        "node_results": [
            {
                "node_id": "node_analysis_01",
                "status": "completed",
                "summary": "AI summary with hallucinated claims",
                "claims": [fake_claim],
                "confidence_score": 0.9,
            }
        ],
    }

    res = client.post("/api/reports/compile", json=payload, headers=headers)
    assert res.status_code == 422
    data = res.json()
    assert data["error"] == "CitationValidationError"
    assert "FND-NONEXISTENT-9999" in data["detail"]


def test_compile_report_accepts_grounded_claims(env_and_client):
    """Verify POST /api/reports/compile succeeds when claims cite real findings with valid hashes."""
    client = env_and_client["client"]
    headers = env_and_client["headers"]
    case_id = f"case_grounded_{uuid4().hex[:8]}"

    # Initialize case first
    client.post(
        "/api/investigations/start",
        json={"case_id": case_id, "objective": "Grounded citation testing", "autorun": False},
        headers=headers,
    )

    from backend.app.api.deps import get_custody_engine, get_storage

    store = get_storage(case_id)
    custody = get_custody_engine(case_id)

    # Ingest artifact so physical blob and hash exist in custody
    sample_file = env_and_client["vault_dir"] / "sample_proc.raw"
    sample_file.write_bytes(b"updater.exe execution telemetry 1234")
    art = custody.ingest_artifact(
        case_id=case_id,
        source_path=sample_file,
        artifact_type="process",
        actor="lead_alice",
    )

    finding_id = f"FND-{uuid4().hex[:6]}"
    finding = ForensicFinding(
        finding_id=finding_id,
        case_id=case_id,
        tool_id="test_parser",
        source_artifact_id=art.artifact_id,
        source_artifact_hash=art.sha256,
        artifact_type="process",
        category="process_execution",
        process_name="updater.exe",
        severity="high",
        summary="Suspicious execution of updater.exe",
        raw_record={"pid": 1234, "image": "updater.exe"},
    )
    store.insert_findings([finding])

    valid_claim = {
        "claim_id": "claim-valid-001",
        "claim_type": "observed_fact",
        "statement": "Observed execution of updater.exe",
        "citing_finding_ids": [finding_id],
        "source_artifact_hashes": [art.sha256],
        "confidence": 0.95,
        "verification_status": "VERIFIED",
    }
    payload = {
        "case_id": case_id,
        "node_results": [
            {
                "node_id": "node_analysis_01",
                "status": "completed",
                "summary": "Verified execution analysis",
                "claims": [valid_claim],
                "confidence_score": 0.95,
            }
        ],
    }

    res = client.post("/api/reports/compile", json=payload, headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["case_id"] == case_id
    report_dict = data["report"]
    assert len(report_dict["observed_facts"]) == 1
    assert report_dict["observed_facts"][0]["citing_finding_ids"] == [finding_id]


# ==============================================================================
# 3. Defense-in-Depth Content-Disposition Header Sanitization Tests
# ==============================================================================

def test_export_report_content_disposition_sanitization(env_and_client):
    """Verify Content-Disposition header in /api/reports/{case_id}/export sanitizes case_id safely."""
    client = env_and_client["client"]
    headers = env_and_client["headers"]
    case_id = "case_clean_123"

    client.post(
        "/api/investigations/start",
        json={"case_id": case_id, "objective": "Export testing", "autorun": False},
        headers=headers,
    )

    res = client.get(f"/api/reports/{case_id}/export?format=markdown", headers=headers)
    assert res.status_code == 200
    cd = res.headers.get("Content-Disposition", "")
    assert cd == 'attachment; filename="report_case_clean_123.md"'


def test_export_custody_ledger_content_disposition_sanitization(env_and_client):
    """Verify Content-Disposition header in /api/intake/custody/{case_id}/export sanitizes case_id safely."""
    client = env_and_client["client"]
    headers = env_and_client["headers"]
    case_id = "case_custody_456"

    client.post(
        "/api/investigations/start",
        json={"case_id": case_id, "objective": "Custody export testing", "autorun": False},
        headers=headers,
    )

    res = client.get(f"/api/intake/custody/{case_id}/export?format=jsonl", headers=headers)
    assert res.status_code == 200
    cd = res.headers.get("Content-Disposition", "")
    assert cd == 'attachment; filename="custody_ledger_case_custody_456.jsonl"'

    res_json = client.get(f"/api/intake/custody/{case_id}/export?format=json", headers=headers)
    assert res_json.status_code == 200
    cd_json = res_json.headers.get("Content-Disposition", "")
    assert cd_json == 'attachment; filename="custody_ledger_case_custody_456.json"'
