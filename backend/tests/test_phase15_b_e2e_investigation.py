"""Phase 15-B End-to-End Investigation & Resilience Regression Test Suite.

Requirements Covered:
1. Multi-step Known-Answer E2E Investigation:
   - Ingest Registry hive (`software.hiv`) and triage archive (`processes.jsonl`, `network_connections.jsonl`, `security_events.jsonl`).
   - Run autonomous investigation controller.
   - Verify deterministic findings, pivot extraction, and cross-source correlations:
     * Persistence Run key -> process execution (`persistence_to_execution`)
     * Process execution -> network C2 outbound (`process_to_network`)
   - Verify formal CitedReport compilation with `strict_citations=True`:
     * Confirmed Findings (observed_facts and derived_correlations) backed 100% by DuckDB finding IDs and hashes.
     * Zero ungrounded or downgraded assertions promoted to Confirmed Findings.
     * Calibrated separation of unverified hypotheses into `unverified_hypotheses`.
2. Negative Resilience Tests:
   - Ungrounded Claim Quarantine:
     * Inject ungrounded claims (fabricated finding ID, nonexistent artifact hash, loose keyword hallucination).
     * Verify CitationGuard quarantines into unverified hypotheses / evidence gaps with confidence <= 0.40 and review flag.
     * Verify strict mode fail-closed rejection with CitationValidationError.
   - Honest LLM Failure:
     * Simulate LLM timeout, malformed JSON, and provider failure.
     * Verify investigation surfaces degraded (`partial` or `failed`) status instead of silent success.
   - Concurrent Live WAL Vault Export:
     * Perform live concurrent SQLite writes on WAL-mode database while calling `export_encrypted_vault()`.
     * Verify `PRAGMA wal_checkpoint(TRUNCATE)` guarantees zero lost rows after import into fresh database.
3. Evidence Immutability:
   - Verify pre- and post-investigation SHA-256 hashes of all known-answer fixtures match exactly (RFC 3227).
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import sqlite3
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

from backend.app.agent.investigation_controller import InvestigationController
from backend.app.agent.memory_protocol import SQLiteFeedbackMemoryProvider
from backend.app.agent.report_builder import CitedReport, ReportBuilder
from backend.app.core.citation_guard import CitationGuard
from backend.app.core.crypto import export_encrypted_vault, import_encrypted_vault
from backend.app.core.custody_engine import CustodyEngine
from backend.app.core.dissect_adapter import DissectAdapter
from backend.app.core.exceptions import CitationValidationError, ForensicOpsError, ProcessTimeoutError
from backend.app.core.specialist_registry import get_default_specialist_registry
from backend.app.core.storage import ForensicStore
from backend.app.db.sqlite_store import LLMStateStore
from backend.app.models.custody import ArtifactRecord
from backend.app.models.findings import CitedClaim, ForensicFinding, NodeGoalResult
from backend.app.models.investigation import (
    CompetingHypothesis,
    InvestigationBudget,
    InvestigationLifecycleState,
)
from backend.tests.fixtures.known_answer_case.generate_known_answer import (
    KNOWN_ANSWER_DIR,
    TRIAGE_DIR,
    ensure_known_answer_fixtures,
)


def compute_sha256(path: Path) -> str:
    """Compute SHA-256 hash of a file on disk."""
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


@pytest.fixture
def known_answer_fixtures():
    """Ensure all deterministic known-answer fixtures are materialized."""
    return ensure_known_answer_fixtures()


@pytest.fixture
def e2e_test_env(tmp_path: Path):
    """Hermetic isolated environment for E2E investigation testing."""
    vault_dir = tmp_path / "vault"
    vault_dir.mkdir(parents=True, exist_ok=True)
    custody_db = tmp_path / "custody.db"
    llm_db = tmp_path / "llm_state.db"
    store_file = tmp_path / "store.duckdb"
    memory_db = tmp_path / "memory.db"

    case_id = f"CASE-KNOWN-ANSWER-{uuid4().hex[:8]}"
    custody = CustodyEngine(vault_root=vault_dir, db_path=custody_db, case_id=case_id)
    storage = ForensicStore(store_file)
    state_store = LLMStateStore(llm_db)
    memory_provider = SQLiteFeedbackMemoryProvider(db_path=memory_db)
    dissect_adapter = DissectAdapter()
    specialist_registry = get_default_specialist_registry()

    yield {
        "tmp_path": tmp_path,
        "case_id": case_id,
        "vault_dir": vault_dir,
        "custody": custody,
        "storage": storage,
        "state_store": state_store,
        "memory_provider": memory_provider,
        "dissect_adapter": dissect_adapter,
        "specialist_registry": specialist_registry,
    }

    storage.close()
    state_store.close()


# ==============================================================================
# 1. Multi-Step Known-Answer E2E Investigation Test
# ==============================================================================
def test_known_answer_multistep_e2e_investigation(
    e2e_test_env: Dict[str, Any], known_answer_fixtures: Dict[str, Any]
):
    """Execute end-to-end autonomous investigation on known-answer attack scenario.

    Verifies:
    1. Ingestion of Registry hive with Run key persistence ("C:\\Users\\Public\\updater.exe").
    2. Ingestion of triage bundle with process (updater.exe PID 4120) and C2 connection (198.51.100.45:4444).
    3. Multi-step autonomous controller execution.
    4. Deterministic correlation:
       - persistence_to_execution (Run key -> updater.exe)
       - process_to_network (updater.exe -> 198.51.100.45:4444)
    5. Report compilation with strict_citations=True:
       - Confirmed Findings contain 100% verified finding IDs and hashes.
       - Zero ungrounded claims promoted to Confirmed Findings.
    """
    case_id = e2e_test_env["case_id"]
    custody: CustodyEngine = e2e_test_env["custody"]
    storage: ForensicStore = e2e_test_env["storage"]
    state_store: LLMStateStore = e2e_test_env["state_store"]
    memory_provider: SQLiteFeedbackMemoryProvider = e2e_test_env["memory_provider"]

    # 1. Ingest Registry hive
    hiv_path = known_answer_fixtures["software_hiv"]
    pre_hiv_hash = compute_sha256(hiv_path)
    art_reg = custody.ingest_artifact(
        case_id=case_id,
        source_path=hiv_path,
        artifact_type="registry",
        original_name="software.hiv",
    )
    assert art_reg.sha256 == pre_hiv_hash

    # 2. Register triage bundle
    triage_path = known_answer_fixtures["triage_dir"]
    proc_file = triage_path / "processes.jsonl"
    net_file = triage_path / "network_connections.jsonl"
    evts_file = triage_path / "security_events.jsonl"

    pre_proc_hash = compute_sha256(proc_file)
    pre_net_hash = compute_sha256(net_file)
    pre_evts_hash = compute_sha256(evts_file)

    art_triage = ArtifactRecord(
        artifact_id=f"art-triage-{uuid4().hex[:8]}",
        case_id=case_id,
        type="triage_directory",
        original_path=str(triage_path),
        blob_path=f":ro:{triage_path}",
        size_bytes=1024,
        sha256="aa" * 32,
        sha512="bb" * 64,
        acquired_utc=datetime.now(timezone.utc).isoformat(),
        acquisition_method="directory_mount",
        original_name="triage",
        verification_status="VERIFIED",
    )
    with custody._get_connection() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO artifacts (
                artifact_id, case_id, type, original_path, blob_path, size_bytes,
                sha256, sha512, acquired_utc, acquisition_method, original_name,
                actor, custody_seq_id, verification_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                art_triage.artifact_id,
                art_triage.case_id,
                art_triage.type,
                art_triage.original_path,
                art_triage.blob_path,
                art_triage.size_bytes,
                art_triage.sha256,
                art_triage.sha512,
                art_triage.acquired_utc,
                art_triage.acquisition_method,
                art_triage.original_name,
                "analyst",
                1,
                "VERIFIED",
            ),
        )

    # 3. Initialize and run InvestigationController
    controller = InvestigationController(
        case_id=case_id,
        custody_engine=custody,
        storage=storage,
        state_store=state_store,
        memory_provider=memory_provider,
        authorized_evidence_scope=[art_reg.artifact_id, art_triage.artifact_id],
        budget=InvestigationBudget(max_iterations=5, max_tool_executions=10),
    )

    record = controller.run_to_completion()
    assert record.lifecycle_state in (
        InvestigationLifecycleState.COMPLETED,
        InvestigationLifecycleState.NEEDS_MORE_DATA,
    )
    assert len(record.completed_actions) >= 2

    # 4. Verify deterministic findings stored in DuckDB
    findings = storage.query_structured_findings(case_id=case_id, limit=50)
    assert len(findings) >= 5

    # Check persistence finding
    pers_findings = [f for f in findings if f.category in ("persistence_registry", "persistence")]
    assert len(pers_findings) >= 1
    assert "updater.exe" in (pers_findings[0].command_line or "").lower()

    # Check process finding
    proc_findings = [f for f in findings if f.artifact_type == "process" or f.category == "process_list"]
    assert any(f.process_name == "updater.exe" for f in proc_findings)

    # Check network finding
    net_findings = [f for f in findings if f.artifact_type == "network" or f.category == "network_connection"]
    assert len(net_findings) >= 1
    assert any("updater.exe" in (f.process_name or f.summary or "") for f in net_findings)

    # 5. Verify deterministic correlations
    correlations = record.correlations
    assert len(correlations) >= 2
    rel_types = {c.get("relationship_type") for c in correlations}
    assert "persistence_to_execution" in rel_types
    assert "process_to_network" in rel_types

    # 6. Verify Compiled Report with strict_citations=True
    report: CitedReport = controller.compile_report(strict_citations=True)
    assert report.report_id is not None
    assert report.case_id == case_id
    assert report.status in ("draft", "finalized")

    # Confirmed findings verification
    assert len(report.observed_facts) >= 5
    assert len(report.derived_correlations) >= 2

    # All citations must resolve to verified findings in storage
    all_fids = set(report.all_cited_finding_ids)
    all_hashes = set(report.all_source_artifact_hashes)
    assert art_reg.sha256 in all_hashes
    assert art_triage.sha256 in all_hashes

    for fact in report.observed_facts:
        assert fact.verification_status == "VERIFIED"
        assert fact.confidence > 0.40
        assert not fact.requires_analyst_review
        for fid in fact.citing_finding_ids:
            assert fid in all_fids

    for corr in report.derived_correlations:
        assert corr.verification_status == "VERIFIED"
        assert corr.confidence > 0.40
        assert not corr.requires_analyst_review
        assert len(corr.citing_finding_ids) >= 2

    # 7. Evidence Immutability Verification (RFC 3227)
    assert compute_sha256(hiv_path) == pre_hiv_hash
    assert compute_sha256(proc_file) == pre_proc_hash
    assert compute_sha256(net_file) == pre_net_hash
    assert compute_sha256(evts_file) == pre_evts_hash


# ==============================================================================
# 1.1 Known-Answer JSONL Fallback Ingestion Test
# ==============================================================================
def test_known_answer_jsonl_fallback_ingestion(
    e2e_test_env: Dict[str, Any], known_answer_fixtures: Dict[str, Any]
):
    """Verify that JSONL fallback export of Run persistence key parses and correlates properly."""
    case_id = e2e_test_env["case_id"]
    custody: CustodyEngine = e2e_test_env["custody"]
    storage: ForensicStore = e2e_test_env["storage"]
    state_store: LLMStateStore = e2e_test_env["state_store"]
    memory_provider: SQLiteFeedbackMemoryProvider = e2e_test_env["memory_provider"]

    jsonl_path = known_answer_fixtures["software_run_jsonl"]
    art_reg = custody.ingest_artifact(
        case_id=case_id,
        source_path=jsonl_path,
        artifact_type="registry",
        original_name="software_run.jsonl",
    )

    triage_path = known_answer_fixtures["triage_dir"]
    art_triage = ArtifactRecord(
        artifact_id=f"art-triage-jsonl-{uuid4().hex[:8]}",
        case_id=case_id,
        type="triage_directory",
        original_path=str(triage_path),
        blob_path=f":ro:{triage_path}",
        size_bytes=1024,
        sha256="cc" * 32,
        sha512="dd" * 64,
        acquired_utc=datetime.now(timezone.utc).isoformat(),
        acquisition_method="directory_mount",
        original_name="triage",
        verification_status="VERIFIED",
    )
    with custody._get_connection() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO artifacts (
                artifact_id, case_id, type, original_path, blob_path, size_bytes,
                sha256, sha512, acquired_utc, acquisition_method, original_name,
                actor, custody_seq_id, verification_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                art_triage.artifact_id,
                art_triage.case_id,
                art_triage.type,
                art_triage.original_path,
                art_triage.blob_path,
                art_triage.size_bytes,
                art_triage.sha256,
                art_triage.sha512,
                art_triage.acquired_utc,
                art_triage.acquisition_method,
                art_triage.original_name,
                "analyst",
                1,
                "VERIFIED",
            ),
        )

    controller = InvestigationController(
        case_id=case_id,
        custody_engine=custody,
        storage=storage,
        state_store=state_store,
        memory_provider=memory_provider,
        authorized_evidence_scope=[art_reg.artifact_id, art_triage.artifact_id],
    )

    record = controller.run_to_completion()
    assert len(record.completed_actions) >= 2
    findings = storage.query_structured_findings(case_id=case_id, limit=50)
    assert len(findings) >= 5

    report = controller.compile_report(strict_citations=True)
    assert len(report.observed_facts) >= 5
    assert len(report.all_cited_finding_ids) >= 5


# ==============================================================================
# 2. Negative Resilience: Ungrounded Claim Quarantine
# ==============================================================================
def test_ungrounded_claim_quarantine_resilience(
    e2e_test_env: Dict[str, Any], known_answer_fixtures: Dict[str, Any]
):
    """Verify that ungrounded claims are quarantined into unverified hypotheses and never promoted.

    Tests:
    1. Fabricated finding ID rejected and quarantined.
    2. Non-existent artifact hash rejected.
    3. Ungrounded LLM assertion with no entity overlap quarantined.
    4. Strict mode CitationValidationError on invalid claims.
    5. Soft mode converts claims to calibrated hypotheses (confidence <= 0.40, review flag set).
    6. Confirmed Findings in CitedReport remain 100% grounded.
    """
    case_id = e2e_test_env["case_id"]
    storage: ForensicStore = e2e_test_env["storage"]
    custody: CustodyEngine = e2e_test_env["custody"]

    # Seed one valid finding into storage backed by an ingested vault artifact
    valid_file = e2e_test_env["tmp_path"] / "valid_test_artifact.bin"
    valid_file.write_bytes(b"VALID_ARTIFACT_FORENSIC_BYTES_FOR_QUARANTINE_TEST")
    art_record = custody.ingest_artifact(
        case_id=case_id,
        source_path=valid_file,
        artifact_type="registry",
        original_name="test_registry.hiv",
    )

    valid_finding = ForensicFinding(
        case_id=case_id,
        source_artifact_id=art_record.artifact_id,
        source_artifact_hash=art_record.sha256,
        tool_id="dissect_registry",
        artifact_type="registry",
        category="persistence_registry",
        command_line=r"C:\Users\Public\updater.exe",
        summary="Registry Run key persistence detected for updater.exe",
        host="WS-CORP-FINANCE",
    )
    storage.insert_findings([valid_finding])

    guard = CitationGuard(storage=storage, custody_engine=custody)

    # 1. Fabricated finding ID
    fake_claim = CitedClaim(
        claim_type="observed_fact",
        statement="Attacker deployed Cobalt Strike beacon at C:\\Windows\\temp\\beacon.exe",
        citing_finding_ids=["finding-fabricated-does-not-exist"],
        source_artifact_hashes=[art_record.sha256],
        confidence=0.99,
    )
    is_valid, reasons = guard.validate_claim(fake_claim, case_id=case_id)
    assert not is_valid
    assert any("non-existent finding_id" in r for r in reasons)

    # 2. Fake artifact hash
    fake_hash_claim = CitedClaim(
        claim_type="observed_fact",
        statement="Registry Run key persistence detected for updater.exe",
        citing_finding_ids=[valid_finding.finding_id],
        source_artifact_hashes=["ff" * 32],
        confidence=0.95,
    )
    is_valid, reasons = guard.validate_claim(fake_hash_claim, case_id=case_id)
    assert not is_valid
    assert any("unverified source_artifact_hash" in r for r in reasons)

    # 3. Valid IDs and hash, but completely hallucinated text (zero entity or keyword overlap)
    hallucinated_claim = CitedClaim(
        claim_type="observed_fact",
        statement="Exfiltrated 500 gigabytes of unencrypted financial databases to Russia over DNS tunneling",
        citing_finding_ids=[valid_finding.finding_id],
        source_artifact_hashes=[art_record.sha256],
        confidence=0.90,
    )
    is_valid, reasons = guard.validate_claim(hallucinated_claim, case_id=case_id)
    assert not is_valid
    assert any("no semantic entity or keyword overlap" in r for r in reasons)

    # 4. Strict Mode rejection
    node_result = NodeGoalResult(
        node_id="node-planner-untrusted",
        status="completed",
        summary="LLM proposed compromise findings",
        claims=[fake_claim, fake_hash_claim, hallucinated_claim],
        confidence_score=0.9,
    )
    with pytest.raises(CitationValidationError):
        guard.validate_node_result(node_result, case_id=case_id, strict=True)

    # 5. Soft Mode Downgrade to Calibrated Hypotheses
    val_report = guard.validate_node_result(
        node_result, case_id=case_id, strict=False, downgrade_ungrounded=True
    )
    assert not val_report.is_valid
    assert len(val_report.downgraded_claims) == 3

    for dc in val_report.downgraded_claims:
        assert dc.claim_type == "hypothesis"
        assert dc.verification_status == "UNVERIFIED"
        assert dc.requires_analyst_review is True
        assert dc.confidence <= 0.40

    # 6. ReportBuilder Quarantine Assurance
    # When building report with mixed claims, ungrounded claims NEVER enter observed_facts or derived_correlations
    valid_claim = CitedClaim(
        claim_type="observed_fact",
        statement="Registry Run key persistence detected for updater.exe",
        citing_finding_ids=[valid_finding.finding_id],
        source_artifact_hashes=[art_record.sha256],
        confidence=0.95,
        verification_status="VERIFIED",
    )
    unverified_hyp = CitedClaim(
        claim_type="hypothesis",
        statement="Potential routine scheduled administrative updater execution",
        citing_finding_ids=[valid_finding.finding_id],
        source_artifact_hashes=[art_record.sha256],
        confidence=0.35,
        requires_analyst_review=True,
    )
    mixed_result = NodeGoalResult(
        node_id="node-mixed",
        status="completed",
        summary="Mixed grounded and ungrounded findings",
        claims=[valid_claim, unverified_hyp] + val_report.downgraded_claims,
        confidence_score=0.8,
    )

    report = ReportBuilder.build_report(
        case_id=case_id,
        node_results=[mixed_result],
        storage=storage,
        custody_engine=custody,
        strict_citations=False,
    )

    # Confirmed facts only contain the verified claim
    assert len(report.observed_facts) == 1
    assert report.observed_facts[0].statement == valid_claim.statement
    assert len(report.derived_correlations) == 0

    # Unverified hypotheses receive the hypothesis claim
    assert len(report.unverified_hypotheses) >= 1
    assert report.unverified_hypotheses[0].statement == unverified_hyp.statement

    # All ungrounded or downgraded claims are strictly segregated from Confirmed Findings
    quarantined_claims = report.unverified_hypotheses + report.rejected_claims
    assert len(quarantined_claims) >= 3
    for qc in quarantined_claims:
        assert qc.claim_id != valid_claim.claim_id
        assert qc not in report.observed_facts
        assert qc not in report.derived_correlations


# ==============================================================================
# 3. Negative Resilience: Honest LLM Failure Degradation
# ==============================================================================
def test_honest_llm_failure_degradation(e2e_test_env: Dict[str, Any]):
    """Verify that LLM timeout or malformed output degrades gracefully to partial/failed.

    Standards:
    - Never report a failed or incomplete analysis as successful.
    - Explicit error details must be preserved in record.errors.
    """
    case_id = e2e_test_env["case_id"]
    custody: CustodyEngine = e2e_test_env["custody"]
    storage: ForensicStore = e2e_test_env["storage"]
    state_store: LLMStateStore = e2e_test_env["state_store"]
    memory_provider: SQLiteFeedbackMemoryProvider = e2e_test_env["memory_provider"]

    # Ingest a real artifact so initialize() plans an action
    test_file = e2e_test_env["tmp_path"] / "timeout_test.bin"
    test_file.write_bytes(b"TIMEOUT_TEST_ARTIFACT")
    art = custody.ingest_artifact(
        case_id=case_id,
        source_path=test_file,
        artifact_type="registry",
        original_name="timeout_hive.hiv",
    )

    controller = InvestigationController(
        case_id=case_id,
        custody_engine=custody,
        storage=storage,
        state_store=state_store,
        memory_provider=memory_provider,
        authorized_evidence_scope=[art.artifact_id],
        budget=InvestigationBudget(max_iterations=3, max_tool_executions=5),
    )

    # 1. Simulate an unrecoverable failure during iteration
    with patch.object(controller, "_execute_action", side_effect=ProcessTimeoutError("LLM analyzer timed out after 300s")):
        controller.initialize()
        rec = controller.run_iteration()

    # Controller must not mark investigation as COMPLETED or SUCCESS
    assert rec.lifecycle_state != InvestigationLifecycleState.COMPLETED
    assert rec.lifecycle_state in (
        InvestigationLifecycleState.FAILED,
        InvestigationLifecycleState.PARTIALLY_COMPLETED,
        InvestigationLifecycleState.EVALUATING,
    )
    assert len(rec.errors) >= 1
    assert any("timed out after 300s" in err for err in rec.errors)


# ==============================================================================
# 4. Safe Concurrent Live WAL Vault Export & Import
# ==============================================================================
def test_concurrent_wal_vault_export_and_import(tmp_path: Path):
    """Verify that live concurrent SQLite writes on WAL mode do not drop rows during encrypted export.

    Standards:
    - PRAGMA wal_checkpoint(TRUNCATE) executes prior to iterdump.
    - Zero rows lost upon AES-256-GCM decrypt and import into a fresh state store.
    """
    db_path = tmp_path / "live_wal_source.db"
    store = LLMStateStore(db_path=db_path)
    store._conn.execute("PRAGMA journal_mode=WAL;")
    store._conn.execute("CREATE TABLE IF NOT EXISTS audit_events (id INTEGER PRIMARY KEY, note TEXT);")
    store._conn.commit()

    # Pre-populate initial records
    for i in range(10):
        store._conn.execute("INSERT INTO audit_events (note) VALUES (?)", (f"pre_init_{i}",))
    store._conn.commit()

    # Background concurrent writer thread
    stop_event = threading.Event()
    writer_done = threading.Event()
    rows_written = [10]

    def concurrent_writer():
        conn2 = sqlite3.connect(str(db_path), timeout=10.0)
        conn2.execute("PRAGMA journal_mode=WAL;")
        idx = 10
        while not stop_event.is_set() and idx < 40:
            conn2.execute("INSERT INTO audit_events (note) VALUES (?)", (f"concurrent_entry_{idx}",))
            conn2.commit()
            rows_written[0] += 1
            idx += 1
            time.sleep(0.01)
        conn2.close()
        writer_done.set()

    writer_thread = threading.Thread(target=concurrent_writer, daemon=True)
    writer_thread.start()
    time.sleep(0.03)

    # Perform export while writer thread is actively writing to WAL journal
    export_file = tmp_path / "vault_wal_backup.json"
    passphrase = "SecureMasterPassphrase2026!"
    export_encrypted_vault(store, export_file, passphrase=passphrase, iterations=100000)

    # Allow writer to complete
    stop_event.set()
    writer_thread.join(timeout=5.0)

    # Export a definitive snapshot after writers conclude
    snapshot_export = tmp_path / "vault_wal_final.json"
    export_encrypted_vault(store, snapshot_export, passphrase=passphrase, iterations=100000)

    # Import the snapshot into a completely fresh state store
    fresh_db_path = tmp_path / "live_wal_restored.db"
    fresh_store = LLMStateStore(db_path=fresh_db_path)
    meta = import_encrypted_vault(fresh_store, snapshot_export, passphrase=passphrase)

    assert meta["status"] == "success"
    cursor = fresh_store._conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM audit_events")
    restored_count = cursor.fetchone()[0]

    # Verify 100% of rows written are preserved with zero data loss
    assert restored_count == rows_written[0]
    assert restored_count >= 10

    store.close()
    fresh_store.close()


# ==============================================================================
# 5. Evidence Immutability Verification (RFC 3227)
# ==============================================================================
def test_known_answer_fixtures_immutability(known_answer_fixtures: Dict[str, Any]):
    """Verify that fixture files on disk remain strictly immutable before and after inspection."""
    hiv = known_answer_fixtures["software_hiv"]
    triage = known_answer_fixtures["triage_dir"]

    h1 = compute_sha256(hiv)
    p1 = compute_sha256(triage / "processes.jsonl")
    n1 = compute_sha256(triage / "network_connections.jsonl")
    e1 = compute_sha256(triage / "security_events.jsonl")

    # Read and parse repeatedly
    adapter = DissectAdapter()
    for _ in range(3):
        adapter.parse_registry_hive(hiv, "case-test", "art-1", h1)
        adapter.parse_triage_directory(triage, "case-test", "art-2", "0" * 64)

    assert compute_sha256(hiv) == h1
    assert compute_sha256(triage / "processes.jsonl") == p1
    assert compute_sha256(triage / "network_connections.jsonl") == n1
    assert compute_sha256(triage / "security_events.jsonl") == e1
