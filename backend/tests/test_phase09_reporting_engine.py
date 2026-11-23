"""Phase 09 Regression Tests: Forensic Timeline, Correlation, and Reporting Engine.

Standards:
- RFC 3227, NIST SP 800-86, ISO/IEC 27037
- Verification of:
  1. Evidence-backed timeline preserving timezone, precision, clock uncertainty, and source
  2. Non-invention of timestamps and no silent assumption of UTC for unknown timezones
  3. Deterministic correlation records with entity identifiers, time window, supporting/conflicting observations, limitations
  4. Bounded Patient Zero analysis (no naive earliest-event inference without initial access evidence)
  5. Evidence conflict detection without suppression (inverted timestamps, conflicting users, duplicate observations, missing artifacts)
  6. Independent citation enforcement (rejecting unsupported claims, foreign case IDs, missing hashes)
  7. Custody verification (never defaulting to True; marking tampered/missing custody as blocked/incomplete)
  8. Final report approval and signing gated by Phase 08 Human Approval tokens
  9. Report reproducibility from stored findings, verified citations, and custody ledger
"""
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List
import pytest
from fastapi.testclient import TestClient

from backend.app.agent.report_builder import (
    CitedReport,
    DeterministicCorrelationRecord,
    EvidenceConflict,
    ReportBuilder,
    ReportProvenance,
    ReportStore,
    TimelineEntry,
    get_report_store,
    parse_forensic_timestamp,
    reset_report_store,
)
from backend.app.auth.security import create_access_token, hash_password
from backend.app.core.approval_engine import ApprovalEngine
from backend.app.core.config import get_settings
from backend.app.core.custody_engine import CustodyEngine
from backend.app.core.exceptions import CitationValidationError, ForensicOpsError
from backend.app.core.storage import ForensicStore
from backend.app.main import app
from backend.app.models.approval import compute_parameter_digest
from backend.app.models.findings import CitedClaim, ForensicFinding, NodeGoalResult
from backend.app.models.workflow import HumanApprovalToken


@pytest.fixture(autouse=True)
def clean_report_store(tmp_path: Path):
    """Ensure each test runs with an isolated in-memory or temp report store."""
    db_file = tmp_path / "reports_test.db"
    store = ReportStore(db_file)
    reset_report_store(store)
    yield store
    reset_report_store(None)


@pytest.fixture
def test_env(tmp_path: Path):
    """Set up temporary test environment with vault, custody, and storage."""
    vault_dir = tmp_path / "vault"
    vault_dir.mkdir(parents=True, exist_ok=True)

    custody = CustodyEngine(vault_root=vault_dir)
    storage = ForensicStore(db_path=str(vault_dir / "store.duckdb"))
    approval_engine = ApprovalEngine(custody_engine=custody, db_path=str(vault_dir / "approvals.db"))

    return {
        "vault_dir": vault_dir,
        "custody": custody,
        "storage": storage,
        "approval_engine": approval_engine,
    }


# ==============================================================================
# 1. Evidence-Backed Timeline & Timestamp Provenance
# ==============================================================================
def test_evidence_backed_timeline_provenance_and_precision():
    """Verify timeline preserves original timezone, clock precision, uncertainty, and source."""
    # Explicit UTC with microseconds
    res1 = parse_forensic_timestamp("2026-10-31T01:00:00.123456Z", artifact_type="evtx")
    assert res1["original_timezone"] == "UTC"
    assert res1["timezone_status"] == "EXPLICIT_UTC"
    assert res1["normalized_timestamp_utc"] == "2026-10-31T01:00:00Z"
    assert res1["timestamp_precision"] == "microseconds"
    assert res1["timestamp_source"] == "evtx_TimeCreated"
    assert res1["clock_uncertainty"] == "none"

    # Explicit offset with milliseconds
    res2 = parse_forensic_timestamp("2026-10-31T03:00:00.500+02:00", artifact_type="pcap")
    assert res2["original_timezone"] == "+02:00"
    assert res2["timezone_status"] == "EXPLICIT_OFFSET"
    assert res2["normalized_timestamp_utc"] == "2026-10-31T01:00:00Z"
    assert res2["timestamp_precision"] == "milliseconds"
    assert res2["timestamp_source"] == "packet_capture_header"
    assert res2["clock_uncertainty"] == "offset_normalized"

    # Missing timestamp must not be invented
    res3 = parse_forensic_timestamp(None, artifact_type="registry")
    assert res3["original_timestamp"] is None
    assert res3["normalized_timestamp_utc"] is None
    assert res3["timezone_status"] == "NO_TIMESTAMP"
    assert res3["clock_uncertainty"] == "no_timestamp_present"


def test_unknown_timezone_not_silently_assumed_utc():
    """Verify that a bare/naive timestamp without timezone offset is NOT silently assumed UTC."""
    raw_naive = "2026-10-31 01:00:00"
    res = parse_forensic_timestamp(raw_naive, artifact_type="evtx")

    assert res["original_timestamp"] == raw_naive
    assert res["original_timezone"] == "UNKNOWN"
    assert res["timezone_status"] == "UNKNOWN_AMBIGUOUS"
    assert res["normalized_timestamp_utc"] is None  # Must NOT confirm normalized UTC
    assert "unknown_timezone_offset" in res["clock_uncertainty"]


# ==============================================================================
# 2. Deterministic Correlation Records
# ==============================================================================
def test_deterministic_correlation_records_contain_all_required_fields(test_env):
    """Verify correlation records capture all required relationship, entity, method, and observation fields."""
    storage = test_env["storage"]
    case_id = "case-corr-01"

    f1 = ForensicFinding(
        finding_id="fnd-corr-01",
        case_id=case_id,
        source_artifact_id="art-01",
        source_artifact_hash="a" * 64,
        tool_id="dissect_evtx",
        timestamp_utc="2026-10-31T01:00:00Z",
        artifact_type="evtx",
        category="authentication",
        host="HOST-ALPHA",
        user="analyst_alice",
        summary="User logon session initiated",
    )
    f2 = ForensicFinding(
        finding_id="fnd-corr-02",
        case_id=case_id,
        source_artifact_id="art-02",
        source_artifact_hash="b" * 64,
        tool_id="dissect_evtx",
        timestamp_utc="2026-10-31T01:00:30Z",
        artifact_type="evtx",
        category="process_creation",
        host="HOST-ALPHA",
        user="analyst_alice",
        process_name="powershell.exe",
        summary="PowerShell executed in logon session",
    )
    storage.insert_findings([f1, f2])

    claim = CitedClaim(
        claim_type="derived_correlation",
        statement="Logon session for analyst_alice directly launched PowerShell on HOST-ALPHA",
        citing_finding_ids=[f1.finding_id, f2.finding_id],
        source_artifact_hashes=[f1.source_artifact_hash, f2.source_artifact_hash],
        confidence=0.92,
    )
    node_res = NodeGoalResult(
        node_id="ai_node_corr",
        status="completed",
        summary="Correlated logon to process execution",
        claims=[claim],
    )

    report = ReportBuilder.build_report(
        case_id=case_id,
        node_results=[node_res],
        storage=storage,
    )

    assert len(report.correlation_records) == 1
    corr: DeterministicCorrelationRecord = report.correlation_records[0]
    assert corr.correlation_id is not None
    assert corr.case_id == case_id
    assert corr.relationship_type == "multi_observation_correlation"
    assert corr.source_finding_ids == [f1.finding_id, f2.finding_id]
    assert corr.source_artifact_hashes == [f1.source_artifact_hash, f2.source_artifact_hash]
    assert corr.entity_identifiers["hosts"] == ["HOST-ALPHA"]
    assert corr.entity_identifiers["users"] == ["analyst_alice"]
    assert corr.correlation_method == "deterministic_provenance_binding"
    assert len(corr.supporting_observations) == 2
    assert corr.time_window is not None
    assert corr.time_window["duration_seconds"] == 30.0
    assert len(corr.limitations) > 0


# ==============================================================================
# 3. Patient Zero Assessment (No Naive Earliest-Event Inference)
# ==============================================================================
def test_patient_zero_not_inferred_solely_from_earliest_event(test_env):
    """Verify that patient zero is marked UNDETERMINED if earliest event lacks initial access indicators."""
    storage = test_env["storage"]
    case_id = "case-pz-eval"

    # Routine internal execution on SERVER-A is the earliest event, but has NO initial access evidence
    internal_findings = [
        ForensicFinding(
            finding_id="fnd-pz-01",
            case_id=case_id,
            source_artifact_id="art-01",
            source_artifact_hash="1" * 64,
            tool_id="dissect_evtx",
            timestamp_utc="2026-10-31T01:00:00Z",
            artifact_type="evtx",
            category="process_creation",
            host="SERVER-ALPHA",
            user="SYSTEM",
            process_name="svchost.exe",
            summary="Routine scheduled background service execution",
        ),
        ForensicFinding(
            finding_id="fnd-pz-02",
            case_id=case_id,
            source_artifact_id="art-02",
            source_artifact_hash="2" * 64,
            tool_id="dissect_evtx",
            timestamp_utc="2026-10-31T02:00:00Z",
            artifact_type="evtx",
            category="process_creation",
            host="SERVER-BETA",
            user="SYSTEM",
            process_name="taskhostw.exe",
            summary="Maintenance task executed",
        ),
    ]

    pz_sec = ReportBuilder.correlate_patient_zero(internal_findings)
    assert pz_sec.patient_zero_status == "UNDETERMINED_INSUFFICIENT_EVIDENCE"
    assert pz_sec.patient_zero_host is None
    assert "Earliest recorded activity" in pz_sec.initial_access_vector
    assert len(pz_sec.data_gaps) > 0

    # Conversely, when explicit initial access vector (phishing lure) is present
    compromise_findings = internal_findings + [
        ForensicFinding(
            finding_id="fnd-pz-03",
            case_id=case_id,
            source_artifact_id="art-03",
            source_artifact_hash="3" * 64,
            tool_id="dissect_evtx",
            timestamp_utc="2026-10-31T00:30:00Z",
            artifact_type="evtx",
            category="authentication",
            host="WORKSTATION-99",
            user="user_victim",
            process_name="powershell.exe",
            summary="Phishing lure attachment execution and macro trigger",
        )
    ]

    pz_verified = ReportBuilder.correlate_patient_zero(compromise_findings)
    assert pz_verified.patient_zero_status == "VERIFIED"
    assert pz_verified.patient_zero_host == "WORKSTATION-99"
    assert "WORKSTATION-99" in pz_verified.initial_access_vector


# ==============================================================================
# 4. Evidence Conflict Detection & Non-Suppression
# ==============================================================================
def test_evidence_conflict_detection_preserves_contradictions():
    """Verify detection of conflicting timestamps, conflicting user identities, and duplicate observations."""
    findings = [
        # Causality inversion: process creation before initiating logon
        ForensicFinding(
            finding_id="fnd-conf-01",
            case_id="case-conf",
            source_artifact_id="art-01",
            source_artifact_hash="a" * 64,
            tool_id="tool_a",
            timestamp_utc="2026-10-31T02:00:00Z",
            artifact_type="evtx",
            category="authentication",
            host="DESKTOP-01",
            user="admin_user",
            summary="Interactive logon session",
        ),
        ForensicFinding(
            finding_id="fnd-conf-02",
            case_id="case-conf",
            source_artifact_id="art-01",
            source_artifact_hash="a" * 64,
            tool_id="tool_a",
            timestamp_utc="2026-10-31T01:50:00Z",  # 10 minutes earlier than logon!
            artifact_type="evtx",
            category="process_creation",
            host="DESKTOP-01",
            user="admin_user",
            process_name="cmd.exe",
            summary="Command shell spawned in logon session",
        ),
        # Conflicting user identities on same process & timestamp
        ForensicFinding(
            finding_id="fnd-conf-03",
            case_id="case-conf",
            source_artifact_id="art-02",
            source_artifact_hash="b" * 64,
            tool_id="tool_b",
            timestamp_utc="2026-10-31T03:00:00Z",
            artifact_type="evtx",
            category="process_creation",
            host="DESKTOP-01",
            user="user_alice",
            process_name="malware.exe",
            summary="Malware executed",
        ),
        ForensicFinding(
            finding_id="fnd-conf-04",
            case_id="case-conf",
            source_artifact_id="art-03",
            source_artifact_hash="c" * 64,
            tool_id="tool_c",
            timestamp_utc="2026-10-31T03:00:00Z",
            artifact_type="evtx",
            category="process_creation",
            host="DESKTOP-01",
            user="user_bob",  # Conflicting user for same process & time
            process_name="malware.exe",
            summary="Malware executed",
        ),
    ]

    conflicts = ReportBuilder.detect_evidence_conflicts(findings)
    conflict_types = [c.conflict_type for c in conflicts]

    assert "conflicting_timestamps" in conflict_types
    assert "conflicting_user_identities" in conflict_types

    # Ensure details are fully preserved
    ts_conflict = next(c for c in conflicts if c.conflict_type == "conflicting_timestamps")
    assert "Causality inversion" in ts_conflict.description
    assert set(ts_conflict.affected_finding_ids) == {"fnd-conf-01", "fnd-conf-02"}


def test_missing_artifacts_conflict_detection(test_env):
    """Verify that findings citing non-existent artifacts generate critical conflicts."""
    custody = test_env["custody"]

    findings = [
        ForensicFinding(
            finding_id="fnd-missing-art",
            case_id="case-miss",
            source_artifact_id="art-ghost-id-999",
            source_artifact_hash="9" * 64,
            tool_id="dissect",
            timestamp_utc="2026-10-31T01:00:00Z",
            artifact_type="evtx",
            category="process_creation",
            summary="Ghost artifact finding",
        )
    ]

    conflicts = ReportBuilder.detect_evidence_conflicts(findings, custody_engine=custody)
    missing = [c for c in conflicts if c.conflict_type == "missing_artifacts"]
    assert len(missing) == 1
    assert missing[0].severity == "critical"
    assert "does not exist in custody vault" in missing[0].description


# ==============================================================================
# 5. Citation Enforcement & Anti-Hallucination
# ==============================================================================
def test_citation_enforcement_rejects_unsupported_claims(test_env):
    """Verify that report builder independently validates citations and suppresses unverified claims."""
    storage = test_env["storage"]
    case_id = "case-cite-test"

    valid_f = ForensicFinding(
        finding_id="fnd-valid-01",
        case_id=case_id,
        source_artifact_id="art-01",
        source_artifact_hash="d" * 64,
        tool_id="dissect",
        timestamp_utc="2026-10-31T01:00:00Z",
        artifact_type="evtx",
        category="authentication",
        host="HOST-Z",
        user="admin",
        summary="Administrator logon from 10.0.0.5",
    )
    storage.insert_findings([valid_f])

    valid_claim = CitedClaim(
        claim_type="observed_fact",
        statement="Administrator logged on to HOST-Z",
        citing_finding_ids=[valid_f.finding_id],
        source_artifact_hashes=[valid_f.source_artifact_hash],
        confidence=1.0,
    )
    hallucinated_claim = CitedClaim(
        claim_type="observed_fact",
        statement="Fabricated finding citation",
        citing_finding_ids=["fnd-does-not-exist"],
        source_artifact_hashes=["e" * 64],
        confidence=1.0,
    )

    node_res = NodeGoalResult(
        node_id="ai_node",
        status="completed",
        summary="Summary",
        claims=[valid_claim, hallucinated_claim],
    )

    # 1. Non-strict mode suppresses hallucination into rejected_claims and evidence conflicts
    report = ReportBuilder.build_report(
        case_id=case_id,
        node_results=[node_res],
        storage=storage,
        strict_citations=False,
    )
    assert len(report.observed_facts) == 1
    assert report.observed_facts[0].statement == "Administrator logged on to HOST-Z"
    assert len(report.rejected_claims) == 1
    assert report.rejected_claims[0].statement == "Fabricated finding citation"
    assert any(c.conflict_type in ("missing_artifacts", "incomplete_telemetry") for c in report.evidence_conflicts)

    # 2. Strict mode raises CitationValidationError
    with pytest.raises(CitationValidationError) as exc:
        ReportBuilder.build_report(
            case_id=case_id,
            node_results=[node_res],
            storage=storage,
            strict_citations=True,
        )
    assert "failed citation validation" in str(exc.value)


# ==============================================================================
# 6. Custody Verification & Integrity Fail-Closed
# ==============================================================================
def test_custody_verification_never_defaults_to_true_and_blocks_tampering(test_env):
    """Verify that report is marked incomplete if custody is missing, and blocked if tampered."""
    storage = test_env["storage"]
    custody = test_env["custody"]
    case_id = "case-custody-test"

    # 1. Missing custody engine must NOT default to True
    report_no_custody = ReportBuilder.build_report(
        case_id=case_id,
        node_results=[],
        storage=storage,
        custody_engine=None,
    )
    assert report_no_custody.custody_and_filter_audit.tamper_check_passed is False
    assert report_no_custody.custody_and_filter_audit.verification_status == "INCOMPLETE"
    assert report_no_custody.status == "incomplete"

    # 2. Tampered custody chain must mark report as blocked
    custody.append_custody_entry(case_id=case_id, actor="analyst_alice", action="INTAKE", artifact_sha256="abc1")
    custody.append_custody_entry(case_id=case_id, actor="analyst_bob", action="PARSE", artifact_sha256="abc2")

    # Corrupt SQLite custody hash
    with custody._get_connection() as conn:
        conn.execute("UPDATE custody_chain SET entry_hash = 'TAMPERED_HASH_999' WHERE seq_id = 1;")
        conn.commit()

    report_tampered = ReportBuilder.build_report(
        case_id=case_id,
        node_results=[],
        storage=storage,
        custody_engine=custody,
    )
    assert report_tampered.custody_and_filter_audit.tamper_check_passed is False
    assert report_tampered.custody_and_filter_audit.verification_status == "FAILED"
    assert report_tampered.status == "blocked"
    assert len(report_tampered.custody_and_filter_audit.verification_errors) > 0


# ==============================================================================
# 7. Report Finalization & Phase 08 Human Approval Authorization
# ==============================================================================
def test_report_finalization_requires_phase08_human_approval(test_env):
    """Verify report finalization requires a valid Phase 08 HumanApprovalToken and authorized role."""
    storage = test_env["storage"]
    custody = test_env["custody"]
    approval_engine = test_env["approval_engine"]
    case_id = "case-sign-01"

    # Set up valid custody chain
    custody.append_custody_entry(case_id=case_id, actor="lead_admin", action="INIT_CASE", artifact_sha256="1234")

    report = ReportBuilder.build_report(
        case_id=case_id,
        node_results=[],
        storage=storage,
        custody_engine=custody,
    )
    assert report.status == "draft"
    secret = "SECURE_PHASE09_APPROVAL_SECRET_12345"

    # 1. Non-matching action_type rejected
    bad_token = HumanApprovalToken(
        case_id=case_id,
        action_type="remote_endpoint_collection",  # Wrong action
        approved_by="lead_alice",
        role="lead_investigator",
        target=report.report_id,
    )
    bad_token.sign(secret)

    with pytest.raises(ForensicOpsError) as exc1:
        ReportBuilder.finalize_report(
            report=report,
            approval_token=bad_token,
            approver_username="lead_alice",
            approver_role="lead_investigator",
            secret_key=secret,
        )
    assert "expected 'report_finalization_or_signing'" in str(exc1.value)

    # 2. Unauthorized role rejected
    valid_token = HumanApprovalToken(
        case_id=case_id,
        action_type="report_finalization_or_signing",
        approved_by="auditor_dan",
        role="auditor",  # Auditor cannot sign
        target=report.report_id,
    )
    valid_token.sign(secret)

    with pytest.raises(ForensicOpsError) as exc2:
        ReportBuilder.finalize_report(
            report=report,
            approval_token=valid_token,
            approver_username="auditor_dan",
            approver_role="auditor",
            secret_key=secret,
        )
    assert "not authorized to sign forensic reports" in str(exc2.value)

    # 3. Forged / invalid signature rejected
    forged_token = HumanApprovalToken(
        case_id=case_id,
        action_type="report_finalization_or_signing",
        approved_by="lead_alice",
        role="lead_investigator",
        target=report.report_id,
        signature="FORGED_INVALID_HMAC_SIGNATURE",
    )
    with pytest.raises(ForensicOpsError) as exc3:
        ReportBuilder.finalize_report(
            report=report,
            approval_token=forged_token,
            approver_username="lead_alice",
            approver_role="lead_investigator",
            secret_key=secret,
        )
    assert "cryptographic signature verification failed" in str(exc3.value)

    # 4. Valid lead approval successfully signs report
    lead_token = HumanApprovalToken(
        case_id=case_id,
        action_type="report_finalization_or_signing",
        approved_by="lead_alice",
        role="lead_investigator",
        target=report.report_id,
    )
    lead_token.sign(secret)

    finalized = ReportBuilder.finalize_report(
        report=report,
        approval_token=lead_token,
        approver_username="lead_alice",
        approver_role="lead_investigator",
        approver_badge="BADGE-001",
        secret_key=secret,
        approval_engine=approval_engine,
        custody_engine=custody,
    )

    assert finalized.status == "signed"
    assert finalized.digest is not None
    assert finalized.digest.startswith("sha256:")
    assert finalized.provenance.status == "signed"
    assert finalized.provenance.finalized_by == "lead_alice"
    assert finalized.provenance.approval_token_id == lead_token.token_id
    assert lead_token.consumed is True

    # Custody ledger has recorded the signature
    chain = custody.get_custody_chain(case_id=case_id)
    assert any(e.action == "REPORT_FINALIZED_AND_SIGNED" for e in chain)


# ==============================================================================
# 8. Report Reproducibility
# ==============================================================================
def test_report_reproducibility(test_env):
    """Verify that a report can be reproduced deterministically from stored findings and records."""
    storage = test_env["storage"]
    custody = test_env["custody"]
    case_id = "case-repro-01"

    # Write source artifact blob so disk existence check passes
    blob_hash = "f" * 64
    blob_dir = custody.blobs_dir / blob_hash[:2]
    blob_dir.mkdir(parents=True, exist_ok=True)
    (blob_dir / f"{blob_hash}.blob").write_text("reproducibility evidence payload")

    f1 = ForensicFinding(
        finding_id="fnd-repro-01",
        case_id=case_id,
        source_artifact_id="art-01",
        source_artifact_hash=blob_hash,
        tool_id="dissect",
        timestamp_utc="2026-10-31T01:00:00Z",
        artifact_type="evtx",
        category="authentication",
        host="HOST-1",
        user="user1",
        summary="User authenticated on HOST-1",
    )
    storage.insert_findings([f1])
    custody.append_custody_entry(case_id=case_id, actor="lead_admin", action="INTAKE", artifact_sha256=blob_hash)

    claim = CitedClaim(
        claim_type="observed_fact",
        statement="User authenticated on HOST-1",
        citing_finding_ids=[f1.finding_id],
        source_artifact_hashes=[f1.source_artifact_hash],
        confidence=1.0,
    )
    node_res = NodeGoalResult(
        node_id="ai_node",
        status="completed",
        summary="Auth goal",
        claims=[claim],
    )

    report1 = ReportBuilder.build_report(
        case_id=case_id,
        node_results=[node_res],
        storage=storage,
        custody_engine=custody,
    )
    report2 = ReportBuilder.build_report(
        case_id=case_id,
        node_results=[node_res],
        storage=storage,
        custody_engine=custody,
    )

    # Findings, rubric, and timeline match exactly
    assert len(report1.observed_facts) == len(report2.observed_facts)
    assert report1.observed_facts[0].statement == report2.observed_facts[0].statement
    assert len(report1.executive_summary.timeline) == len(report2.executive_summary.timeline)
    assert report1.executive_summary.timeline[0].timestamp_utc == report2.executive_summary.timeline[0].timestamp_utc
    assert report1.custody_and_filter_audit.tamper_check_passed == report2.custody_and_filter_audit.tamper_check_passed


# ==============================================================================
# 9. Reports REST API Endpoints Lifecycle
# ==============================================================================
def test_reports_api_full_lifecycle(test_env):
    """Verify REST API: GET, POST /compile, GET /history, and POST /finalize."""
    from unittest.mock import MagicMock
    from backend.app.auth.dependencies import get_current_user
    from backend.app.auth.models import UserRead

    storage = test_env["storage"]
    custody = test_env["custody"]
    case_id = "case-api-rep"

    custody.append_custody_entry(case_id=case_id, actor="lead_alice", action="INIT", artifact_sha256="1111")
    f = ForensicFinding(
        finding_id="fnd-api-01",
        case_id=case_id,
        source_artifact_id="art-01",
        source_artifact_hash="a" * 64,
        tool_id="dissect",
        timestamp_utc="2026-10-31T01:00:00Z",
        artifact_type="evtx",
        category="authentication",
        host="FINANCE-01",
        user="alice",
        summary="Logon verified",
    )
    storage.insert_findings([f])

    client = TestClient(app)

    lead_user = UserRead(
        id="user-01",
        username="lead_alice",
        badge_id="BADGE-LEAD",
        role="lead_investigator",
        full_name="Alice Lead",
        is_active=True,
        created_at=datetime.now(timezone.utc).isoformat(),
    )
    mock_case_auth = MagicMock()
    mock_case_auth.verify_case_access.return_value = True

    from backend.app.api import deps
    app.dependency_overrides[get_current_user] = lambda: lead_user
    app.dependency_overrides[deps.get_case_authorization_service] = lambda: mock_case_auth
    app.dependency_overrides[deps.get_storage] = lambda cid=None: storage
    app.dependency_overrides[deps.get_custody_engine] = lambda cid=None: custody
    app.dependency_overrides[deps.get_approval_engine] = lambda cid=None: test_env["approval_engine"]

    try:
        # 1. GET /api/reports/{case_id}
        res_get = client.get(f"/api/reports/{case_id}")
        assert res_get.status_code == 200
        data_get = res_get.json()
        assert data_get["case_id"] == case_id
        assert "executive_summary" in data_get["report"]
        report_id = data_get["report"]["report_id"]

        # 2. GET /api/reports/{case_id}/history
        res_hist = client.get(f"/api/reports/{case_id}/history")
        assert res_hist.status_code == 200
        hist = res_hist.json()
        assert len(hist) >= 1
        assert hist[0]["report_id"] == report_id

        # 3. POST /api/reports/{report_id}/finalize
        secret = test_env["approval_engine"].secret_key
        token = HumanApprovalToken(
            case_id=case_id,
            action_type="report_finalization_or_signing",
            approved_by="lead_alice",
            role="lead_investigator",
            target=report_id,
        )
        token.sign(secret)

        res_fin = client.post(
            f"/api/reports/{report_id}/finalize",
            json={"approval_token": token.model_dump()},
        )
        assert res_fin.status_code == 200
        data_fin = res_fin.json()
        assert data_fin["report"]["status"] == "signed"
        assert data_fin["report"]["provenance"]["finalized_by"] == "lead_alice"
    finally:
        app.dependency_overrides.clear()
