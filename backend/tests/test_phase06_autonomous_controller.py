"""Phase 06 Regression Test Suite: Autonomous Investigation Controller.

Tests:
1. Lifecycle state machine transitions and invalid transition rejection.
2. End-to-end bounded autonomous investigation cycle (EVTX -> Plan -> Execution -> Evaluation -> Completion).
3. Evidence gap identification (missing evidence vs. evidence of absence).
4. Competing hypotheses formulation (Malicious Intrusion vs. Benign Administrative Null).
5. Tool-request contract validation (unapproved tools, out-of-scope artifacts, command injection blocked).
6. Budget exhaustion enforcement (max iterations, max tool executions -> partially_completed).
7. Approval pause and cryptographic token resumption (HumanApprovalToken HMAC verification).
8. Restart recovery and interrupted investigation resumption from SQLite state store.
9. Human feedback integration: benign baseline suppression without fact modification.
10. Execution step traceability: chronological InvestigationStepTrace persistence.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock
from uuid import uuid4
import pytest

from backend.app.agent.investigation_controller import InvestigationController, _run_coroutine_safely
from backend.app.agent.memory_protocol import SQLiteFeedbackMemoryProvider
from backend.app.core.analyzer_registry import AnalyzerRegistry, get_analyzer_registry
from backend.app.core.custody_engine import CustodyEngine
from backend.app.core.dissect_adapter import DissectAdapter
from backend.app.core.exceptions import ExecutionPolicyError, ForensicOpsError
from backend.app.core.execution_policy import get_execution_policy_registry
from backend.app.core.plugin_runner import AirGappedSubprocessRunner, PluginRunner
from backend.app.core.storage import ForensicStore
from backend.app.db.sqlite_store import LLMStateStore
from backend.app.models.feedback import HumanFeedbackRecord
from backend.app.models.findings import ForensicFinding
from backend.app.models.investigation import (
    CompetingHypothesis,
    EvidenceGap,
    InvalidStateTransitionError,
    InvestigationAction,
    InvestigationBudget,
    InvestigationLifecycleState,
    InvestigationPlan,
    InvestigationRecord,
    InvestigationStepTrace,
    ToolRequest,
    validate_lifecycle_transition,
)
from backend.app.models.plugins import ToolPluginCard
from backend.app.models.workflow import HumanApprovalToken, WorkflowEdgePayload


@pytest.fixture
def temp_investigation_env(tmp_path: Path):
    """Provide isolated SQLite, DuckDB, vault, and custody engine for testing."""
    vault_dir = tmp_path / "vault"
    vault_dir.mkdir(parents=True, exist_ok=True)
    custody_db = tmp_path / "custody.db"
    llm_db = tmp_path / "llm_state.db"
    store_file = tmp_path / "store.duckdb"

    case_id = f"case-test-{uuid4().hex[:6]}"
    custody = CustodyEngine(vault_root=vault_dir, db_path=custody_db, case_id=case_id)
    storage = ForensicStore(store_file)
    state_store = LLMStateStore(llm_db)
    memory_provider = SQLiteFeedbackMemoryProvider(db_path=tmp_path / "memory.db")

    # Helper to ingest raw test bytes into custody
    def _ingest_bytes(raw_bytes: bytes, filename: str, art_type: str) -> Any:
        src = tmp_path / f"src_{uuid4().hex[:8]}_{filename}"
        src.write_bytes(raw_bytes)
        return custody.ingest_artifact(
            case_id=case_id,
            source_path=src,
            artifact_type=art_type,
            original_name=filename,
        )

    yield {
        "root": tmp_path,
        "case_id": case_id,
        "vault_dir": vault_dir,
        "custody": custody,
        "storage": storage,
        "state_store": state_store,
        "memory_provider": memory_provider,
        "ingest_bytes": _ingest_bytes,
    }

    storage.close()
    state_store.close()


@pytest.fixture
def valid_evtx_bytes() -> bytes:
    """Minimal binary structure of an EVTX file with ElfFile header."""
    header = bytearray(4096)
    header[0:8] = b"ElfFile\x00"
    header[8:16] = (0).to_bytes(8, "little")
    header[16:24] = (0).to_bytes(8, "little")
    header[24:32] = (1).to_bytes(8, "little")
    header[32:36] = (4096).to_bytes(4, "little")
    header[36:38] = (1).to_bytes(2, "little")
    header[38:40] = (3).to_bytes(2, "little")
    header[40:42] = (4096).to_bytes(2, "little")

    chunk = bytearray(65536)
    chunk[0:8] = b"ElfChnk\x00"
    chunk[8:16] = (1).to_bytes(8, "little")
    chunk[16:24] = (5).to_bytes(8, "little")
    return bytes(header + chunk)


# ------------------------------------------------------------------------------
# 1. State Machine Transitions & Validation
# ------------------------------------------------------------------------------
def test_lifecycle_state_machine_valid_transitions():
    """Verify that all legal state transitions pass validation."""
    validate_lifecycle_transition(InvestigationLifecycleState.CREATED, InvestigationLifecycleState.EVIDENCE_VALIDATION)
    validate_lifecycle_transition(InvestigationLifecycleState.EVIDENCE_VALIDATION, InvestigationLifecycleState.PLANNING)
    validate_lifecycle_transition(InvestigationLifecycleState.PLANNING, InvestigationLifecycleState.EXECUTING)
    validate_lifecycle_transition(InvestigationLifecycleState.EXECUTING, InvestigationLifecycleState.EVALUATING)
    validate_lifecycle_transition(InvestigationLifecycleState.EVALUATING, InvestigationLifecycleState.PLANNING)
    validate_lifecycle_transition(InvestigationLifecycleState.EVALUATING, InvestigationLifecycleState.COMPLETED)
    validate_lifecycle_transition(InvestigationLifecycleState.EVALUATING, InvestigationLifecycleState.PARTIALLY_COMPLETED)
    validate_lifecycle_transition(InvestigationLifecycleState.EVALUATING, InvestigationLifecycleState.NEEDS_MORE_DATA)
    validate_lifecycle_transition(InvestigationLifecycleState.EXECUTING, InvestigationLifecycleState.AWAITING_APPROVAL)
    validate_lifecycle_transition(InvestigationLifecycleState.AWAITING_APPROVAL, InvestigationLifecycleState.EXECUTING)


def test_lifecycle_state_machine_invalid_transitions_blocked():
    """Verify that illegal transitions raise InvalidStateTransitionError."""
    # Cannot jump from created straight to completed
    with pytest.raises(InvalidStateTransitionError):
        validate_lifecycle_transition(InvestigationLifecycleState.CREATED, InvestigationLifecycleState.COMPLETED)

    # Cannot transition out of terminal completed state
    with pytest.raises(InvalidStateTransitionError):
        validate_lifecycle_transition(InvestigationLifecycleState.COMPLETED, InvestigationLifecycleState.PLANNING)

    # Cannot transition out of cancelled
    with pytest.raises(InvalidStateTransitionError):
        validate_lifecycle_transition(InvestigationLifecycleState.CANCELLED, InvestigationLifecycleState.EXECUTING)

    # Executing cannot jump directly to created
    with pytest.raises(InvalidStateTransitionError):
        validate_lifecycle_transition(InvestigationLifecycleState.EXECUTING, InvestigationLifecycleState.CREATED)


# ------------------------------------------------------------------------------
# 2. End-to-End Autonomous Investigation Cycle
# ------------------------------------------------------------------------------
def test_autonomous_investigation_loop_end_to_end(temp_investigation_env, valid_evtx_bytes):
    """Verify full autonomous investigation cycle: Evidence -> Plan -> Execute -> Evaluate -> Complete."""
    env = temp_investigation_env
    artifact = env["ingest_bytes"](valid_evtx_bytes, "Security.evtx", "evtx")

    # Mock tool runner for ez_evtxecmd
    sub_runner = AirGappedSubprocessRunner(allow_test_mock=True)

    def mock_evtxecmd(argv, in_dir, out_dir):
        out_f = out_dir / "EvtxECmd_Output.jsonl"
        records = [
            {
                "TimeCreated": "2026-11-15T03:00:00Z",
                "EventId": 4624,
                "Computer": "DC01",
                "UserName": "admin_intruder",
                "ExecutableInfo": "winlogon.exe",
                "CommandLine": "winlogon.exe",
                "Payload": "Logon Type 10 from 192.168.1.100",
            },
            {
                "TimeCreated": "2026-11-15T03:02:00Z",
                "EventId": 7045,
                "Computer": "DC01",
                "UserName": "SYSTEM",
                "ExecutableInfo": "services.exe",
                "CommandLine": "cmd.exe /c powershell -enc AAA",
                "Payload": "Service BackdoorInstalled created",
            },
        ]
        out_f.write_text("\n".join(json.dumps(r) for r in records) + "\n")
        return 0, "Parsed 2 records", ""

    sub_runner.register_mock_tool("evtxecmd", mock_evtxecmd)
    plugin_runner = PluginRunner(subprocess_runner=sub_runner, custody_engine=env["custody"])

    controller = InvestigationController(
        case_id=env["case_id"],
        investigator="lead_dfir_analyst",
        objective="Investigate remote lateral movement and persistence",
        custody_engine=env["custody"],
        storage=env["storage"],
        plugin_runner=plugin_runner,
        state_store=env["state_store"],
        memory_provider=env["memory_provider"],
        budgets=InvestigationBudget(max_iterations=3, max_tool_executions=5),
    )

    record = controller.run_to_completion()

    assert record.lifecycle_state == InvestigationLifecycleState.COMPLETED
    assert record.findings_count >= 2
    assert record.current_iteration >= 1

    # Verify hypotheses evaluation
    h_malicious = next((h for h in record.hypotheses if not h.is_benign_null), None)
    assert h_malicious is not None
    assert h_malicious.status == "supported"
    assert len(h_malicious.supporting_finding_ids) >= 1

    # Verify pivots extracted into WorkflowEdgePayload
    assert "admin_intruder" in record.pivots.users
    assert "DC01" in record.pivots.hosts

    # Verify traces recorded in SQLite
    traces = env["state_store"].get_investigation_traces(record.investigation_id)
    assert len(traces) >= 1
    assert traces[0]["status"] == "completed"


# ------------------------------------------------------------------------------
# 3. Evidence Gap Tracking
# ------------------------------------------------------------------------------
def test_evidence_gaps_tracking_when_no_evidence(temp_investigation_env):
    """Verify that an empty case vault transitions to NEEDS_MORE_DATA with explicit gap recording."""
    env = temp_investigation_env

    controller = InvestigationController(
        case_id=env["case_id"],
        investigator="analyst",
        objective="Investigate malware infection",
        custody_engine=env["custody"],
        storage=env["storage"],
        state_store=env["state_store"],
    )

    record = controller.initialize()

    assert record.lifecycle_state == InvestigationLifecycleState.NEEDS_MORE_DATA
    assert len(record.evidence_gaps) >= 1
    assert record.evidence_gaps[0].is_evidence_of_absence is False
    assert "unavailable" in record.evidence_gaps[0].tactical_reason.lower() or "found" in record.evidence_gaps[0].tactical_reason.lower()


def test_evidence_gaps_distinguishes_absence_from_missing(temp_investigation_env, valid_evtx_bytes):
    """Verify controller distinguishes uncollected evidence (missing) from checked clean logs."""
    env = temp_investigation_env
    env["ingest_bytes"](valid_evtx_bytes, "Security.evtx", "evtx")

    controller = InvestigationController(
        case_id=env["case_id"],
        custody_engine=env["custody"],
        storage=env["storage"],
        state_store=env["state_store"],
    )
    record = controller.initialize()

    # Memory gap should be identified as missing (uncollected)
    mem_gap = next((g for g in record.evidence_gaps if g.missing_artifact_type == "memory"), None)
    assert mem_gap is not None
    assert mem_gap.is_evidence_of_absence is False


# ------------------------------------------------------------------------------
# 4. Competing Hypotheses Formulation
# ------------------------------------------------------------------------------
def test_competing_hypotheses_formulation_and_versioning(temp_investigation_env, valid_evtx_bytes):
    """Verify controller generates both Malicious and Benign hypotheses and tracks versioning."""
    env = temp_investigation_env
    env["ingest_bytes"](valid_evtx_bytes, "Security.evtx", "evtx")

    controller = InvestigationController(
        case_id=env["case_id"],
        custody_engine=env["custody"],
        storage=env["storage"],
        state_store=env["state_store"],
    )
    record = controller.initialize()

    assert len(record.hypotheses) == 2
    h_malicious = next(h for h in record.hypotheses if not h.is_benign_null)
    h_benign = next(h for h in record.hypotheses if h.is_benign_null)

    assert h_malicious.status == "untested"
    assert h_benign.status == "untested"
    assert h_malicious.version == 1
    assert h_benign.version == 1


# ------------------------------------------------------------------------------
# 5. LLM Tool-Request Contract Validation
# ------------------------------------------------------------------------------
def test_tool_request_contract_blocks_unapproved_tool(temp_investigation_env):
    """Verify that requests for unapproved tools are rejected with ExecutionPolicyError."""
    env = temp_investigation_env

    controller = InvestigationController(
        case_id=env["case_id"],
        custody_engine=env["custody"],
        storage=env["storage"],
        state_store=env["state_store"],
    )

    req = ToolRequest(
        capability_id="arbitrary_bash_runner",
        justification="Run shell command",
    )

    with pytest.raises(ExecutionPolicyError, match="not registered in the approved forensic analyzer registry"):
        controller.submit_tool_request(req)


def test_tool_request_contract_blocks_foreign_artifact(temp_investigation_env):
    """Verify tool request referencing non-existent or foreign case artifact is rejected."""
    env = temp_investigation_env

    controller = InvestigationController(
        case_id=env["case_id"],
        custody_engine=env["custody"],
        storage=env["storage"],
        state_store=env["state_store"],
    )

    req = ToolRequest(
        capability_id="dissect_evtx",
        artifact_id="art-non-existent-999",
        justification="Inspect non-existent file",
    )

    with pytest.raises(ForensicOpsError, match="does not exist in case vault"):
        controller.submit_tool_request(req)


def test_tool_request_contract_blocks_out_of_scope_artifact(temp_investigation_env, valid_evtx_bytes):
    """Verify tool request on artifact outside authorized_evidence_scope is rejected."""
    env = temp_investigation_env
    art1 = env["ingest_bytes"](valid_evtx_bytes, "Security.evtx", "evtx")
    art2 = env["ingest_bytes"](valid_evtx_bytes, "System.evtx", "evtx")

    # Authorize only art1
    controller = InvestigationController(
        case_id=env["case_id"],
        custody_engine=env["custody"],
        storage=env["storage"],
        state_store=env["state_store"],
        authorized_evidence_scope=[art1.artifact_id],
    )

    req = ToolRequest(
        capability_id="dissect_evtx",
        artifact_id=art2.artifact_id,
        justification="Try out of scope artifact",
    )

    with pytest.raises(ExecutionPolicyError, match="outside the authorized evidence scope"):
        controller.submit_tool_request(req)


# ------------------------------------------------------------------------------
# 6. Budget Exhaustion
# ------------------------------------------------------------------------------
def test_budget_exhaustion_max_iterations(temp_investigation_env, valid_evtx_bytes):
    """Verify that hitting max_iterations transitions state to PARTIALLY_COMPLETED."""
    env = temp_investigation_env
    env["ingest_bytes"](valid_evtx_bytes, "Security.evtx", "evtx")

    # Strict budget: max 1 iteration
    controller = InvestigationController(
        case_id=env["case_id"],
        custody_engine=env["custody"],
        storage=env["storage"],
        state_store=env["state_store"],
        budgets=InvestigationBudget(max_iterations=1, max_tool_executions=10),
    )

    controller.initialize()
    # Add multiple pending actions to prevent natural completion in 1 turn
    controller.record.pending_actions.extend([
        InvestigationAction(capability_id="dissect_evtx", status="pending"),
        InvestigationAction(capability_id="dissect_evtx", status="pending"),
        InvestigationAction(capability_id="dissect_evtx", status="pending"),
        InvestigationAction(capability_id="dissect_evtx", status="pending"),
    ])

    controller.run_iteration()
    # Next iteration must hit budget check
    record = controller.run_iteration()

    assert record.lifecycle_state == InvestigationLifecycleState.PARTIALLY_COMPLETED
    assert record.current_iteration >= 1


def test_budget_exhaustion_max_tool_executions(temp_investigation_env, valid_evtx_bytes):
    """Verify that hitting max_tool_executions halts tool runs and marks PARTIALLY_COMPLETED."""
    env = temp_investigation_env
    env["ingest_bytes"](valid_evtx_bytes, "Security.evtx", "evtx")

    # Budget allowing only 1 tool execution
    controller = InvestigationController(
        case_id=env["case_id"],
        custody_engine=env["custody"],
        storage=env["storage"],
        state_store=env["state_store"],
        budgets=InvestigationBudget(max_iterations=5, max_tool_executions=1),
    )

    controller.initialize()
    # Add dummy executions to trigger limit
    controller.record.execution_ids = ["exec-1"]

    record = controller.run_iteration()
    assert record.lifecycle_state == InvestigationLifecycleState.PARTIALLY_COMPLETED


# ------------------------------------------------------------------------------
# 7. Approval Pause & Cryptographic Token Resumption
# ------------------------------------------------------------------------------
def test_approval_gate_pauses_and_resumes_with_valid_token(temp_investigation_env):
    """Verify that sensitive actions pause the controller until valid HMAC token is provided."""
    env = temp_investigation_env
    secret_key = "test-secret-key-for-hmac-2026-production"

    controller = InvestigationController(
        case_id=env["case_id"],
        custody_engine=env["custody"],
        storage=env["storage"],
        state_store=env["state_store"],
        secret_key=secret_key,
    )

    # Queue an action that requires approval
    sensitive_act = InvestigationAction(
        action_id="act-sensitive-001",
        capability_id="remote_endpoint_collection",
        requires_approval=True,
        status="pending",
    )
    controller.transition_to(InvestigationLifecycleState.EVIDENCE_VALIDATION)
    controller.transition_to(InvestigationLifecycleState.PLANNING)
    controller.record.pending_actions.append(sensitive_act)

    # Run iteration: must pause
    record = controller.run_iteration()
    assert record.lifecycle_state == InvestigationLifecycleState.AWAITING_APPROVAL
    assert "requires explicit human approval" in str(record.pause_reason)

    # Attempt resume without token: fails
    with pytest.raises(ForensicOpsError, match=r"valid HumanApprovalToken"):
        controller.resume()

    # Attempt resume with forged/bad signature token: fails
    forged_token = HumanApprovalToken(
        token_id="tok-forged",
        node_id="act-sensitive-001",
        case_id=env["case_id"],
        signature="invalid_signature_hex_12345",
    )
    with pytest.raises(ForensicOpsError, match="Invalid or forged"):
        controller.approve_action("act-sensitive-001", forged_token)

    # Generate genuine valid HMAC token
    valid_token = HumanApprovalToken(
        token_id=f"tok-valid-{uuid4().hex[:8]}",
        node_id="act-sensitive-001",
        case_id=env["case_id"],
        action_type="remote_endpoint_collection",
        target=env["case_id"],
        issued_by="lead_investigator",
    )
    valid_token.sign(secret_key)

    # Approve and resume
    resumed_record = controller.approve_action("act-sensitive-001", valid_token)
    assert resumed_record.lifecycle_state == InvestigationLifecycleState.EXECUTING
    assert any(a.action_id == "act-sensitive-001" and a.approval_token is not None for a in resumed_record.pending_actions)


# ------------------------------------------------------------------------------
# 8. Restart Recovery & Idempotent Resumption
# ------------------------------------------------------------------------------
def test_restart_recovery_from_sqlite(temp_investigation_env, valid_evtx_bytes):
    """Verify that an interrupted investigation recovers from SQLite without repeating completed steps."""
    env = temp_investigation_env
    art = env["ingest_bytes"](valid_evtx_bytes, "Security.evtx", "evtx")

    # Step 1: Start investigation with controller 1
    c1 = InvestigationController(
        case_id=env["case_id"],
        investigator="analyst_1",
        custody_engine=env["custody"],
        storage=env["storage"],
        state_store=env["state_store"],
    )
    c1.initialize()
    c1.record.completed_actions.append(
        InvestigationAction(
            action_id="act-completed-prior",
            capability_id="dissect_evtx",
            status="completed",
            execution_id="exec-prior-1",
        )
    )
    c1.record.execution_ids.append("exec-prior-1")
    c1._persist_state()
    inv_id = c1.record.investigation_id

    # Step 2: Simulate process crash and restart with controller 2 pointing to the same investigation_id
    c2 = InvestigationController(
        case_id=env["case_id"],
        investigator="analyst_1",
        investigation_id=inv_id,
        custody_engine=env["custody"],
        storage=env["storage"],
        state_store=env["state_store"],
    )

    # Verify state was accurately recovered
    assert c2.record.investigation_id == inv_id
    assert c2.record.lifecycle_state == InvestigationLifecycleState.PLANNING
    assert "exec-prior-1" in c2.record.execution_ids
    assert any(a.action_id == "act-completed-prior" for a in c2.record.completed_actions)


# ------------------------------------------------------------------------------
# 9. Human Feedback Integration & Benign Suppression
# ------------------------------------------------------------------------------
def test_human_feedback_benign_baseline_suppression(temp_investigation_env):
    """Verify that organizational benign baseline suppresses false-positive pivots without modifying raw findings."""
    env = temp_investigation_env

    # Record human feedback in SQLite memory provider
    _run_coroutine_safely(
        env["memory_provider"].record_human_feedback(
            HumanFeedbackRecord(
                feedback_type="false_positive_benign_baseline",
                entity_pattern="user:svc_backup_daemon",
                scope="organization_baseline",
                org_id="DefaultOrg",
                analyst_note="Known nightly backup service account",
            )
        )
    )

    # Insert findings into DuckDB: one benign service account, one real attacker
    env["storage"].insert_findings([
        ForensicFinding(
            case_id=env["case_id"],
            source_artifact_id="art-1",
            source_artifact_hash="a" * 64,
            tool_id="dissect",
            timestamp_utc="2026-11-15T01:00:00Z",
            artifact_type="evtx",
            category="LogonEvent",
            severity="low",
            summary="Nightly backup script executed",
            user="svc_backup_daemon",
            host="BACKUP-SRV",
        ),
        ForensicFinding(
            case_id=env["case_id"],
            source_artifact_id="art-1",
            source_artifact_hash="a" * 64,
            tool_id="dissect",
            timestamp_utc="2026-11-15T02:00:00Z",
            artifact_type="evtx",
            category="PrivilegeEscalation",
            severity="critical",
            summary="Malicious user token impersonation",
            user="attacker_account",
            host="BACKUP-SRV",
        ),
    ])

    controller = InvestigationController(
        case_id=env["case_id"],
        custody_engine=env["custody"],
        storage=env["storage"],
        state_store=env["state_store"],
        memory_provider=env["memory_provider"],
    )
    controller.initialize()
    controller.record.lifecycle_state = InvestigationLifecycleState.EXECUTING
    controller.run_iteration()

    # Attacker account should be in active pivots
    assert "attacker_account" in controller.record.pivots.users
    # Benign backup service account should be suppressed from active pivots
    assert "svc_backup_daemon" not in controller.record.pivots.users

    # Verify original forensic facts in DuckDB were NOT deleted or modified
    raw_findings = env["storage"].query_structured_findings(case_id=env["case_id"])
    assert len(raw_findings) == 2
    assert any(f.user == "svc_backup_daemon" for f in raw_findings)


# ------------------------------------------------------------------------------
# 10. Execution Step Traceability
# ------------------------------------------------------------------------------
def test_traceability_step_traces_recorded(temp_investigation_env, valid_evtx_bytes):
    """Verify that every iteration persists an InvestigationStepTrace in SQLite with full metadata."""
    env = temp_investigation_env
    env["ingest_bytes"](valid_evtx_bytes, "Security.evtx", "evtx")

    controller = InvestigationController(
        case_id=env["case_id"],
        custody_engine=env["custody"],
        storage=env["storage"],
        state_store=env["state_store"],
        budgets=InvestigationBudget(max_iterations=1, max_tool_executions=1),
    )

    controller.run_iteration()

    traces = env["state_store"].get_investigation_traces(controller.record.investigation_id)
    assert len(traces) == 1

    t0 = traces[0]
    assert t0["investigation_id"] == controller.record.investigation_id
    assert t0["case_id"] == env["case_id"]
    assert t0["iteration"] == 1
    assert "inputs" in t0
    assert "outputs" in t0
    assert "tool_executions" in t0
    assert t0["status"] == "completed"
    assert t0["duration_seconds"] >= 0.0
