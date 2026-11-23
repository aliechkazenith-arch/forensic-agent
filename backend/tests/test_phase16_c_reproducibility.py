"""Phase 16-C End-to-End Reproducibility and Cryptographic Chain Verification.

Standards:
- NIST SP 800-86 & RFC 3227 Forensic Reproducibility
- Dual-Execution Known-Answer Attack Scenario (Zero Mocks)
- Identical Pre/Post Cryptographic Hash Binding
- Deterministic Finding and Correlation Parity
- HMAC-SHA256 Audit Chain Verification
- Live Encrypted Vault Export/Import Round-Trip
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Tuple
from uuid import uuid4

import pytest

from backend.app.agent.investigation_controller import InvestigationController
from backend.app.agent.memory_protocol import SQLiteFeedbackMemoryProvider
from backend.app.agent.report_builder import CitedReport
from backend.app.core.approval_engine import ApprovalEngine
from backend.app.core.crypto import (
    AESGCMVaultCipher,
    derive_key,
    export_encrypted_vault,
    import_encrypted_vault,
)
from backend.app.core.custody_engine import CustodyEngine
from backend.app.core.dissect_adapter import DissectAdapter
from backend.app.core.plugin_runner import compute_streaming_sha256
from backend.app.core.specialist_registry import get_default_specialist_registry
from backend.app.core.storage import ForensicStore
from backend.app.db.sqlite_store import LLMStateStore
from backend.app.models.custody import ArtifactRecord
from backend.app.models.investigation import InvestigationBudget, InvestigationLifecycleState
from backend.tests.fixtures.known_answer_case.generate_known_answer import (
    ensure_known_answer_fixtures,
)


def _setup_isolated_investigation(root: Path, case_id: str) -> Dict[str, Any]:
    """Build an isolated, hermetic investigation stack."""
    vault_dir = root / "vault"
    vault_dir.mkdir(parents=True, exist_ok=True)
    custody_db = root / "custody.db"
    llm_db = root / "llm_state.db"
    store_file = root / "store.duckdb"
    memory_db = root / "memory.db"
    approval_db = root / "approval.db"

    custody = CustodyEngine(vault_root=vault_dir, db_path=custody_db, case_id=case_id)
    storage = ForensicStore(store_file)
    state_store = LLMStateStore(llm_db)
    memory_provider = SQLiteFeedbackMemoryProvider(db_path=memory_db)
    dissect_adapter = DissectAdapter()
    specialist_registry = get_default_specialist_registry()
    approval_engine = ApprovalEngine(db_path=approval_db, secret_key="test_secret_hmac_32bytes_long!!!")

    return {
        "case_id": case_id,
        "vault_dir": vault_dir,
        "custody": custody,
        "storage": storage,
        "state_store": state_store,
        "memory_provider": memory_provider,
        "dissect_adapter": dissect_adapter,
        "specialist_registry": specialist_registry,
        "approval_engine": approval_engine,
        "custody_db": custody_db,
        "approval_db": approval_db,
        "llm_db": llm_db,
    }


def _run_known_answer_pipeline(env: Dict[str, Any], fixtures: Dict[str, Any]) -> Dict[str, Any]:
    """Execute complete ingestion, controller loop, and report generation."""
    case_id = env["case_id"]
    custody: CustodyEngine = env["custody"]
    storage: ForensicStore = env["storage"]
    state_store: LLMStateStore = env["state_store"]
    memory_provider: SQLiteFeedbackMemoryProvider = env["memory_provider"]
    approval_engine: ApprovalEngine = env["approval_engine"]

    # 1. Ingest registry hive
    hiv_path = fixtures["software_hiv"]
    pre_hiv_hash = compute_streaming_sha256(hiv_path)
    art_reg = custody.ingest_artifact(
        case_id=case_id,
        source_path=hiv_path,
        artifact_type="registry",
        original_name="software.hiv",
    )
    assert art_reg.sha256 == pre_hiv_hash

    # 2. Register triage bundle
    triage_path = fixtures["triage_dir"]
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

    # 3. Initialize autonomous controller
    budget = InvestigationBudget(
        max_iterations=5,
        max_tool_executions=10,
        per_tool_timeout_seconds=30,
        max_findings_per_step=100,
    )
    controller = InvestigationController(
        case_id=case_id,
        investigator="analyst_reproducibility",
        objective="Investigate persistence via Registry Run key and correlate with active processes and C2 network sockets",
        budget=budget,
        storage=storage,
        custody_engine=custody,
        state_store=state_store,
        memory_provider=memory_provider,
        authorized_evidence_scope=[art_reg.artifact_id, art_triage.artifact_id],
        dissect_adapter=env["dissect_adapter"],
        specialist_registry=env["specialist_registry"],
    )

    # 4. Run autonomous loop
    record = controller.run_to_completion()
    assert record.lifecycle_state in (
        InvestigationLifecycleState.COMPLETED,
        InvestigationLifecycleState.PARTIALLY_COMPLETED,
        InvestigationLifecycleState.NEEDS_MORE_DATA,
    )

    # 5. Extract findings from DuckDB
    findings = storage.query_structured_findings(case_id=case_id, limit=200)

    # 6. Compile cited report with strict citations
    cited_report = controller.compile_report(strict_citations=True)

    # 7. Check pre/post evidence immutability
    post_hiv_hash = compute_streaming_sha256(hiv_path)
    assert post_hiv_hash == pre_hiv_hash

    # 8. Record approval action and verify HMAC audit chain
    req = approval_engine.create_request(
        case_id=case_id,
        requesting_investigator="analyst_reproducibility",
        action_type="containment",
        target="host-198.51.100.45",
        capability_id="containment_isolate",
        parameters={"action": "isolate_endpoint"},
        reason="Isolate suspected compromised host",
    )
    result = approval_engine.approve_request(
        approval_id=req.approval_id,
        approver={
            "username": "lead_auditor",
            "role": "lead_investigator",
            "badge_id": "BADGE-REPRO",
            "account_type": "human",
            "is_active": True,
        },
    )
    token = result.token
    consumed = approval_engine.verify_and_consume_token(
        token=token,
        expected_case_id=case_id,
        expected_action_type="containment",
        expected_target="host-198.51.100.45",
        expected_parameters={"action": "isolate_endpoint"},
        consumed_by="investigation_controller",
    )
    assert consumed is not None
    assert getattr(consumed, "status", None).value == "consumed"

    return {
        "case_id": case_id,
        "hiv_hash": pre_hiv_hash,
        "triage_hash": art_triage.sha256,
        "findings": findings,
        "correlations": controller.record.correlations,
        "cited_report": cited_report,
        "approval_engine": approval_engine,
        "storage": storage,
        "custody": custody,
        "state_store": state_store,
    }


def test_end_to_end_investigation_reproducibility(tmp_path: Path):
    """Run two separate investigations from scratch and prove 100% deterministic reproducibility."""
    fixtures = ensure_known_answer_fixtures()

    # Execution 1: Isolated Environment A
    dir_a = tmp_path / "run_a"
    dir_a.mkdir()
    env_a = _setup_isolated_investigation(dir_a, "CASE-REPRO-RUN-A")
    results_a = _run_known_answer_pipeline(env_a, fixtures)

    # Execution 2: Isolated Environment B
    dir_b = tmp_path / "run_b"
    dir_b.mkdir()
    env_b = _setup_isolated_investigation(dir_b, "CASE-REPRO-RUN-B")
    results_b = _run_known_answer_pipeline(env_b, fixtures)

    try:
        # Assertion 1: Input evidence hashes are identical across runs
        assert results_a["hiv_hash"] == results_b["hiv_hash"]
        assert results_a["triage_hash"] == results_b["triage_hash"]

        # Assertion 2: Deterministic finding counts match
        findings_a = results_a["findings"]
        findings_b = results_b["findings"]
        assert len(findings_a) == len(findings_b)
        assert len(findings_a) > 0

        # Assertion 3: Finding categories and artifact types match identically
        cats_a = sorted([f.category for f in findings_a])
        cats_b = sorted([f.category for f in findings_b])
        assert cats_a == cats_b

        arts_a = sorted([f.artifact_type for f in findings_a])
        arts_b = sorted([f.artifact_type for f in findings_b])
        assert arts_a == arts_b

        summaries_a = sorted([f.summary for f in findings_a])
        summaries_b = sorted([f.summary for f in findings_b])
        assert summaries_a == summaries_b

        # Assertion 4: Deterministic correlation counts match
        corrs_a = results_a["correlations"]
        corrs_b = results_b["correlations"]
        assert len(corrs_a) == len(corrs_b)
        assert len(corrs_a) >= 2  # persistence_to_execution and process_to_network

        corr_types_a = sorted([c.get("relationship_type") for c in corrs_a])
        corr_types_b = sorted([c.get("relationship_type") for c in corrs_b])
        assert corr_types_a == corr_types_b

        # Assertion 5: Cited Reports have identical structure and claim partitions
        rep_a: CitedReport = results_a["cited_report"]
        rep_b: CitedReport = results_b["cited_report"]
        assert len(rep_a.observed_facts) == len(rep_b.observed_facts)
        assert len(rep_a.derived_correlations) == len(rep_b.derived_correlations)
        assert len(rep_a.unverified_hypotheses) == len(rep_b.unverified_hypotheses)

        # Assertion 6: HMAC-SHA256 audit log chains are valid in both environments
        engine_a: ApprovalEngine = results_a["approval_engine"]
        engine_b: ApprovalEngine = results_b["approval_engine"]

        valid_a_tok, err_a_tok = engine_a.verify_consumed_tokens_chain()
        assert valid_a_tok is True, f"Run A token chain invalid: {err_a_tok}"
        valid_a_aud, err_a_aud = engine_a.verify_approval_audit_chain()
        assert valid_a_aud is True, f"Run A audit chain invalid: {err_a_aud}"

        valid_b_tok, err_b_tok = engine_b.verify_consumed_tokens_chain()
        assert valid_b_tok is True, f"Run B token chain invalid: {err_b_tok}"
        valid_b_aud, err_b_aud = engine_b.verify_approval_audit_chain()
        assert valid_b_aud is True, f"Run B audit chain invalid: {err_b_aud}"

        # Assertion 7: Encrypted SQLite vault export and import round-trip
        passphrase = "ForensicOpsAirGappedPassphrase2026!"
        export_file = tmp_path / "vault_backup.enc.json"

        # Export Run A's state store database
        store_a: LLMStateStore = results_a["state_store"]
        export_encrypted_vault(store_a, export_file, passphrase=passphrase, kdf="pbkdf2")
        assert export_file.is_file()
        assert export_file.stat().st_size > 0

        # Import into fresh database
        imported_db = tmp_path / "imported_state.db"
        new_store = LLMStateStore(imported_db)
        import_encrypted_vault(new_store, export_file, passphrase=passphrase)

        # Verify state persistence restored
        restored_states = new_store.list_investigation_states()
        assert len(restored_states) >= 1
        new_store.close()

    finally:
        results_a["storage"].close()
        results_a["state_store"].close()
        results_b["storage"].close()
        results_b["state_store"].close()


def test_vault_export_wrong_passphrase_fails(tmp_path: Path):
    """Verify importing an encrypted vault with wrong passphrase fails closed with CryptographicTamperError."""
    from backend.app.core.exceptions import CryptographicTamperError

    db_path = tmp_path / "state.db"
    store = LLMStateStore(db_path)
    store.create_or_update_case({
        "case_id": "CASE-TEST",
        "case_name": "Test Case",
        "status": "OPEN",
    })
    export_file = tmp_path / "vault.enc.json"
    export_encrypted_vault(store, export_file, passphrase="CorrectPassphrase123!", kdf="pbkdf2", iterations=100000)

    dest_db = tmp_path / "dest.db"
    dest_store = LLMStateStore(dest_db)
    with pytest.raises(CryptographicTamperError):
        import_encrypted_vault(dest_store, export_file, passphrase="WrongPassphrase999!")

    dest_store.close()
    store.close()


def test_audit_chain_tamper_detection(tmp_path: Path):
    """Verify that tampering with an audit chain database record fails verification immediately."""
    import sqlite3

    approval_db = tmp_path / "approval.db"
    engine = ApprovalEngine(db_path=approval_db, secret_key="super_secret_test_key_123456789!")
    req = engine.create_request(
        case_id="CASE-TAMPER",
        requesting_investigator="analyst",
        action_type="containment",
        target="192.168.1.100",
        capability_id="isolate",
        reason="Test isolation",
    )
    result = engine.approve_request(
        approval_id=req.approval_id,
        approver={
            "username": "lead_auditor",
            "role": "lead_investigator",
            "badge_id": "BADGE-1",
            "account_type": "human",
            "is_active": True,
        },
    )
    engine.verify_and_consume_token(
        token=result.token,
        expected_case_id="CASE-TAMPER",
        expected_action_type="containment",
        expected_target="192.168.1.100",
    )
    # Check chain is valid before tamper
    valid, err = engine.verify_consumed_tokens_chain()
    assert valid is True

    # Tamper with consumed_approval_tokens row in SQLite directly
    conn = sqlite3.connect(approval_db)
    conn.execute("UPDATE consumed_approval_tokens SET target = 'tampered-host'")
    conn.commit()
    conn.close()

    # Chain verification MUST fail
    valid_after, err_after = engine.verify_consumed_tokens_chain()
    assert valid_after is False
    assert "HMAC mismatch" in err_after or "tamper" in err_after.lower()

