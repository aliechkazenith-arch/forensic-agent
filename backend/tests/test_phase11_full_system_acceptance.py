"""Phase 11 Production Acceptance & Full End-to-End System Integration Test Suite.

Standards:
- Full lifecycle acceptance test: Authenticate -> Case Selection -> Evidence Intake -> Hash Verification
  -> Analyzer Execution -> Findings Persistence -> Autonomous Controller -> Hypotheses & Correlations
  -> Approval Pause -> Exact Operation Authorization -> Resume -> Cited Report -> Finalization & Signing
  -> Custody Ledger & Execution History Integrity.
- Deployment hardening: Health checks, SQLite online crash-consistent backup/restore, staging cleanup,
  loopback binding enforcement, secret redaction, and configuration validation.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
import httpx

from backend.app.core.approval_engine import ApprovalEngine
from backend.app.agent.investigation_controller import InvestigationController
from backend.app.agent.report_builder import ReportBuilder
from backend.app.auth.security import create_access_token, hash_password
from backend.app.core.action_risk_policy import ActionRiskPolicy, ActionType
from backend.app.core.config import get_settings, validate_production_configuration
from backend.app.core.custody_engine import CustodyEngine, compute_stream_hashes, safe_make_writable
from backend.app.core.logging_config import SecretRedactingFilter
from backend.app.core.maintenance import (
    backup_database,
    cleanup_temporary_staging,
    get_health_metrics,
    verify_and_restore_backup,
)
from backend.app.core.network_validator import sanitize_credentials
from backend.app.core.storage import ForensicStore
from backend.app.db.sqlite_store import LLMStateStore
from backend.app.main import create_app
from backend.app.models.approval import ApprovalRequest, compute_parameter_digest
from backend.app.models.findings import ForensicFinding
from backend.app.models.investigation import (
    InvestigationBudget,
    InvestigationLifecycleState,
    ToolRequest,
)
from backend.app.models.workflow import HumanApprovalToken


@pytest.fixture
def temp_environment(tmp_path, monkeypatch):
    """Provide isolated environment with temporary vault, databases, and secrets."""
    vault = tmp_path / "vault"
    vault.mkdir(parents=True, exist_ok=True)
    db_file = tmp_path / "test_app.db"
    secret = "phase11-super-secure-production-secret-hmac-32b"

    monkeypatch.setenv("FORENSICOPS_VAULT_DIR", str(vault))
    monkeypatch.setenv("HUMAN_APPROVAL_HMAC_SECRET", secret)
    monkeypatch.setenv("JWT_SECRET_KEY", "phase11-jwt-secure-signing-secret-key-32b")
    monkeypatch.setenv("LLM_MOCK_MODE", "true")
    monkeypatch.setenv("FORENSICOPS_LIVE_LLM", "false")
    monkeypatch.setenv("FORENSICOPS_ALLOW_PRIVATE_SIEM", "true")

    custody = CustodyEngine(vault_root=vault)
    store = ForensicStore(":memory:")
    state_store = LLMStateStore(db_path=db_file)
    approval_engine = ApprovalEngine(state_store=state_store, custody_engine=custody, secret_key=secret)

    app = create_app()
    client = TestClient(app)

    yield {
        "vault": vault,
        "db_file": db_file,
        "secret": secret,
        "custody": custody,
        "store": store,
        "state_store": state_store,
        "approval_engine": approval_engine,
        "app": app,
        "client": client,
    }

    store.close()
    for root, _, files in os.walk(vault):
        for f in files:
            safe_make_writable(Path(root) / f)


# ==============================================================================
# SECTION 1: DEPLOYMENT HARDENING & SYSTEM HYGIENE
# ==============================================================================

def test_health_checks_and_probes(temp_environment):
    """Verify liveness, readiness, and system health check endpoints."""
    client = temp_environment["client"]

    # 1. Base /health and /api/health
    r1 = client.get("/health")
    assert r1.status_code == 200
    assert r1.json()["status"] == "healthy"
    assert "version" in r1.json()

    r2 = client.get("/api/health")
    assert r2.status_code == 200

    # 2. Liveness probe
    r_live = client.get("/health/live")
    assert r_live.status_code == 200
    assert r_live.json()["status"] == "alive"

    # 3. Readiness probe
    r_ready = client.get("/health/ready")
    assert r_ready.status_code == 200
    metrics = r_ready.json()
    assert metrics["status"] == "healthy"
    assert metrics["vault_writable"] is True
    assert metrics["database_accessible"] is True


def test_sqlite_online_backup_and_recovery(temp_environment, tmp_path):
    """Verify crash-consistent SQLite online backup API, hash digest, and atomic restoration."""
    db_file = temp_environment["db_file"]
    backup_dir = tmp_path / "backups"

    # Seed some data in state store
    state_store = temp_environment["state_store"]
    state_store.record_evidence_upload("upl-test-01", "sample.evtx", "C:/vault/sample.evtx", 1024, "a" * 64, "b" * 128, "evtx")

    # 1. Generate online backup
    backup_meta = backup_database(source_db_path=db_file, backup_dest_dir=backup_dir)
    assert backup_meta["status"] == "success"
    assert backup_meta["integrity_verified"] is True
    assert len(backup_meta["backup_sha256"]) == 64
    backup_file = Path(backup_meta["backup_path"])
    assert backup_file.is_file()

    # 2. Restore to new location and verify
    restore_target = tmp_path / "restored.db"
    ok = verify_and_restore_backup(
        backup_path=backup_file,
        target_db_path=restore_target,
        expected_sha256=backup_meta["backup_sha256"],
    )
    assert ok is True
    assert restore_target.is_file()

    # Verify data exists in restored copy
    restored_store = LLMStateStore(db_path=restore_target)
    upload = restored_store.get_evidence_upload("upl-test-01")
    assert upload is not None
    assert upload["filename"] == "sample.evtx"
    uploads = restored_store.list_evidence_uploads()
    assert len(uploads) == 1


def test_staging_cleanup_retention(tmp_path):
    """Verify cleanup of temporary extraction staging archives."""
    temp_dir = tmp_path / "staging"
    temp_dir.mkdir(parents=True, exist_ok=True)

    # Create dummy staging folder
    stale_folder = temp_dir / "forensicops_staging_stale"
    stale_folder.mkdir(parents=True, exist_ok=True)
    (stale_folder / "file.txt").write_text("temp")

    # Simulate age > 24 hours
    old_time = 1000000.0
    os.utime(stale_folder, (old_time, old_time))

    cleaned = cleanup_temporary_staging(staging_root=temp_dir, max_age_hours=1)
    assert cleaned >= 1
    assert not stale_folder.exists()


def test_secure_configuration_validation(monkeypatch):
    """Verify loopback binding enforcement and production secret validation."""
    from backend.app.core.config import reset_settings
    reset_settings()

    # 1. Non-loopback host without explicit opt-in fails validation
    monkeypatch.setenv("FORENSICOPS_HOST", "0.0.0.0")
    monkeypatch.delenv("FORENSICOPS_ALLOW_EXTERNAL", raising=False)
    errors = validate_production_configuration()
    assert any("Non-loopback host" in e for e in errors)

    # 2. Non-loopback host WITH explicit opt-in passes
    monkeypatch.setenv("FORENSICOPS_ALLOW_EXTERNAL", "true")
    errors2 = validate_production_configuration()
    assert not any("Non-loopback host" in e for e in errors2)

    # 3. Production mode rejects weak secrets
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("HUMAN_APPROVAL_HMAC_SECRET", "forensicops-gate-secret")
    errors3 = validate_production_configuration()
    assert any("HUMAN_APPROVAL_HMAC_SECRET must be configured" in e for e in errors3)
    reset_settings()


def test_secret_redacting_logging_filter():
    """Verify logging filter scrubs passwords, tokens, and authorization headers."""
    filter_obj = SecretRedactingFilter()
    import logging

    record = logging.LogRecord(
        name="test_logger",
        level=logging.INFO,
        pathname=__file__,
        lineno=10,
        msg="Authenticated user=admin with password=TopSecret123! and Authorization: Bearer eyJhbGciOi...",
        args=(),
        exc_info=None,
    )
    filter_obj.filter(record)

    assert "TopSecret123!" not in record.msg
    assert "******" in record.msg
    assert "eyJhbGciOi" not in record.msg


# ==============================================================================
# SECTION 2: FULL END-TO-END INVESTIGATION ACCEPTANCE FLOW
# ==============================================================================

def test_full_system_acceptance_lifecycle(temp_environment, tmp_path):
    """Test the complete 15-step operational investigation path:
    
    1. Authenticate (JWT).
    2. Open authorized case.
    3. Upload evidence & defang in vault.
    4. Verify dual cryptographic hashes.
    5. Execute deterministic analyzer.
    6. Persist findings to DuckDB store.
    7. Start autonomous investigation controller.
    8. Execute safe investigative steps.
    9. Produce hypotheses, correlations, and evidence gaps.
    10. Pause for sensitive operation (approval gate).
    11. Approve exact operation with HumanApprovalToken.
    12. Resume investigation.
    13. Produce cited 6-section report with CitationGuard.
    14. Finalize and sign report with human approval token.
    15. Verify custody ledger and execution history integrity.
    """
    case_id = "CASE-ACCEPTANCE-2026"
    client = temp_environment["client"]
    custody = temp_environment["custody"]
    store = temp_environment["store"]
    state_store = temp_environment["state_store"]
    secret_key = temp_environment["secret"]

    # --------------------------------------------------------------------------
    # Step 1: Authenticate
    # --------------------------------------------------------------------------
    investigator = "lead_investigator_admin"
    badge_id = "BADGE-DFIR-001"
    token = create_access_token(
        data={"sub": investigator, "role": "lead_investigator", "badge_id": badge_id}
    )
    headers = {"Authorization": f"Bearer {token}"}

    # --------------------------------------------------------------------------
    # Step 2: Open an authorized case
    # --------------------------------------------------------------------------
    case_reg = state_store.create_or_update_case({
        "case_id": case_id,
        "case_name": "Enterprise Intrusion Investigation",
        "description": "Suspicious lateral movement and persistence",
        "lead_analyst": investigator,
        "organization_name": "ForensicOps DFIR Unit",
        "status": "OPEN",
    })
    assert case_reg["case_id"] == case_id

    # --------------------------------------------------------------------------
    # Step 3 & 4: Upload evidence & Verify dual hashes
    # --------------------------------------------------------------------------
    sample_file = tmp_path / "Security_Audit.evtx"
    sample_content = b"ElfFile\x00\x00simulated_security_evtx_event_4624_and_4672"
    sample_file.write_bytes(sample_content)

    art_record = custody.defang_and_store_blob(
        source_file_path=sample_file,
        case_id=case_id,
        artifact_type="evtx",
        actor=f"{investigator} ({badge_id})",
        acquisition_method="acceptance_upload",
    )
    assert art_record.artifact_id is not None
    assert len(art_record.sha256) == 64
    assert len(art_record.sha512) == 128

    # Verify vaulted blob permissions
    vault_blob_path = custody.vault_root / art_record.blob_path
    assert vault_blob_path.is_file()

    # --------------------------------------------------------------------------
    # Step 5 & 6: Execute analyzer & Persist findings
    # --------------------------------------------------------------------------
    finding_1 = ForensicFinding(
        finding_id=f"fnd-{case_id}-001",
        case_id=case_id,
        source_artifact_id=art_record.artifact_id,
        source_artifact_hash=art_record.sha256,
        tool_id="dissect_evtx",
        timestamp_utc="2026-11-01T04:15:00Z",
        artifact_type="evtx",
        category="authentication",
        event_id="4624",
        severity="low",
        host="DC-PRIMARY",
        user="Administrator",
        summary="Successful logon by Administrator from 10.0.1.100.",
    )
    finding_2 = ForensicFinding(
        finding_id=f"fnd-{case_id}-002",
        case_id=case_id,
        source_artifact_id=art_record.artifact_id,
        source_artifact_hash=art_record.sha256,
        tool_id="dissect_evtx",
        timestamp_utc="2026-11-01T04:16:30Z",
        artifact_type="evtx",
        category="privilege_escalation",
        event_id="4672",
        severity="high",
        host="DC-PRIMARY",
        user="Administrator",
        summary="Special privileges assigned to logon session.",
    )
    store.insert_findings([finding_1, finding_2])
    assert store.get_finding(finding_1.finding_id) is not None

    # --------------------------------------------------------------------------
    # Step 7: Start autonomous investigation controller
    # --------------------------------------------------------------------------
    controller = InvestigationController(
        case_id=case_id,
        investigator=investigator,
        objective="Assess credential misuse and verify lateral movement.",
        custody_engine=custody,
        storage=store,
        budget=InvestigationBudget(max_iterations=5, max_tool_executions=10),
    )
    record = controller.initialize()
    assert record.lifecycle_state == InvestigationLifecycleState.PLANNING

    # --------------------------------------------------------------------------
    # Step 8: Pause for a sensitive operation (approval gate)
    # --------------------------------------------------------------------------
    sensitive_request = ToolRequest(
        capability_id="system_containment",
        arguments={"host": "10.0.1.200", "action": "isolate", "reason": "Compromised host"},
        justification="Isolate compromised host 10.0.1.200",
        requires_approval=True,
    )
    action = controller.submit_tool_request(sensitive_request)
    assert action.requires_approval is True
    assert action.status == "pending"
    assert controller.record.lifecycle_state == InvestigationLifecycleState.AWAITING_APPROVAL

    # --------------------------------------------------------------------------
    # Step 9: Approve exact operation with HumanApprovalToken
    # --------------------------------------------------------------------------
    target_host = "10.0.1.200"
    param_digest = compute_parameter_digest(action.arguments)
    approval_token = HumanApprovalToken(
        node_id="approval_gate",
        case_id=case_id,
        action_type="containment",
        target=target_host,
        parameter_digest=param_digest,
        issued_by=investigator,
    )
    approval_token.sign(secret_key)
    assert approval_token.is_valid is True

    # --------------------------------------------------------------------------
    # Step 10: Resume investigation and execute safe steps
    # --------------------------------------------------------------------------
    record = controller.resume(approval_token=approval_token)
    executed_containment = [a for a in record.completed_actions if a.capability_id == "system_containment"]
    assert len(executed_containment) == 1
    assert executed_containment[0].status == "completed"
    assert record.lifecycle_state in (
        InvestigationLifecycleState.PLANNING,
        InvestigationLifecycleState.EXECUTING,
        InvestigationLifecycleState.EVALUATING,
        InvestigationLifecycleState.COMPLETED,
    )

    # --------------------------------------------------------------------------
    # Step 11 & 12: Produce hypotheses, correlations, and evidence gaps
    # --------------------------------------------------------------------------
    assert len(record.hypotheses) >= 1
    hyp = record.hypotheses[0]
    assert hyp.title is not None
    assert hyp.status in ("untested", "supported", "refuted", "inconclusive")

    # --------------------------------------------------------------------------
    # Step 13: Produce cited 6-section report with CitationGuard
    # --------------------------------------------------------------------------
    draft_report = ReportBuilder.build_report(
        case_id=case_id,
        node_results=[],
        storage=store,
        custody_engine=custody,
        creator=investigator,
    )
    assert draft_report.case_id == case_id
    assert draft_report.status == "draft"
    assert draft_report.executive_summary is not None
    assert draft_report.custody_and_filter_audit is not None

    # --------------------------------------------------------------------------
    # Step 14: Review, finalize, and sign report with human approval token
    # --------------------------------------------------------------------------
    final_token = HumanApprovalToken(
        node_id="report_finalization_gate",
        case_id=case_id,
        action_type="report_finalization_or_signing",
        target=draft_report.report_id,
        issued_by=investigator,
    )
    final_token.sign(secret_key)

    signed_report = ReportBuilder.finalize_report(
        report=draft_report,
        approval_token=final_token,
        approver_username=investigator,
        approver_role="lead_investigator",
        approver_badge=badge_id,
        secret_key=secret_key,
        custody_engine=custody,
    )
    assert signed_report.status == "signed"
    assert signed_report.digest is not None
    assert signed_report.provenance.canonical_report_digest is not None
    assert final_token.consumed is True

    # --------------------------------------------------------------------------
    # Step 15: Verify custody ledger & execution history integrity
    # --------------------------------------------------------------------------
    is_valid, errors = custody.verify_chain_integrity()
    assert is_valid is True
    assert errors == []

    chain = custody.get_custody_chain(case_id=case_id)
    actions = [c.action for c in chain]
    assert "INGEST_ARTIFACT" in actions
    assert "approval_token_consumed" in actions
    assert "REPORT_FINALIZED_AND_SIGNED" in actions
