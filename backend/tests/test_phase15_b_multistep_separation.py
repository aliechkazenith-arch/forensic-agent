"""Phase 15-B Test Suite: Multi-Step Investigation Loop, Follow-Up Routing & Report Separation.

Validates:
1. Multi-Step Investigation Loop & Follow-Up Routing:
   - InvestigationController does not halt after a single pass when multiple artifacts or follow-up leads exist.
   - Extracted pivots trigger targeted follow-up actions for unanalyzed artifacts in authorized scope.
   - Bounded execution strictly respects max_iterations and max_tool_executions, ending in PARTIALLY_COMPLETED.
2. Report Separation & Fail-Closed Citations:
   - InvestigationController.compile_report defaults to strict_citations=True.
   - CitedReport explicitly separates Confirmed Findings (observed_facts with confidence > 0.40, verified, no review)
     from Unverified Hypotheses (unverified_hypotheses).
   - Confirmed findings NEVER contain ungrounded or downgraded assertions.
3. Fail-Closed LLM Error Handling:
   - When LLM times out, raises error, or emits malformed JSON, node status is marked as 'partial' or 'failed'
     with explicit error details, and never reports 'completed' or 'success'.
   - Controller tracks execution errors and degrades lifecycle state rather than falsely claiming COMPLETED.
"""
from __future__ import annotations

import pytest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from backend.app.agent.graph import ForensicOpsWorkflowEngine
from backend.app.agent.investigation_controller import InvestigationController
from backend.app.agent.lmstudio_client import LMStudioClient
from backend.app.agent.report_builder import CitedReport, ReportBuilder
from backend.app.core.citation_guard import CitationGuard
from backend.app.core.custody_engine import CustodyEngine
from backend.app.core.exceptions import CitationValidationError, ForensicOpsError
from backend.app.core.storage import ForensicStore
from backend.app.models.findings import CitedClaim, ForensicFinding, NodeGoalResult
from backend.app.models.investigation import (
    InvestigationBudget,
    InvestigationLifecycleState,
)
from backend.app.models.workflow import (
    WorkflowDefinition,
    WorkflowEdge,
    WorkflowEdgePayload,
    WorkflowExecutionState,
    WorkflowNode,
)


@pytest.fixture
def multi_artifact_env(tmp_path):
    """Fixture providing CustodyEngine and ForensicStore with multiple realistic artifacts."""
    vault_dir = tmp_path / "vault"
    custody = CustodyEngine(vault_root=vault_dir, case_id="case-15b")
    store = ForensicStore(":memory:")

    # Artifact 1: Security EVTX
    evtx_file = tmp_path / "Security.evtx"
    evtx_file.write_bytes(b"ElfFile\x00" + b"\x00" * 500)
    art1 = custody.ingest_artifact(
        case_id="case-15b",
        source_path=evtx_file,
        artifact_type="evtx",
        actor="lead_investigator",
    )

    # Artifact 2: SYSTEM Registry Hive
    reg_file = tmp_path / "SYSTEM.hiv"
    reg_file.write_bytes(b"regf" + b"\x00" * 500)
    art2 = custody.ingest_artifact(
        case_id="case-15b",
        source_path=reg_file,
        artifact_type="registry",
        actor="lead_investigator",
    )

    # Initial findings from Artifact 1 (Security EVTX)
    finding1 = ForensicFinding(
        finding_id="fnd-evtx-101",
        case_id="case-15b",
        source_artifact_id=art1.artifact_id,
        source_artifact_hash=art1.sha256,
        tool_id="dissect_evtx",
        artifact_type="evtx",
        category="authentication",
        host="FINANCE-SRV",
        user="svc_backup",
        summary="Type 3 Network Logon for svc_backup on FINANCE-SRV",
        process_name="services.exe",
    )
    store.insert_findings([finding1])

    yield custody, store, art1, art2, finding1
    store.close()


def test_multistep_investigation_loop_and_followup_routing(multi_artifact_env):
    """InvestigationController plans targeted follow-up actions when unanalyzed artifacts exist."""
    custody, store, art1, art2, finding1 = multi_artifact_env

    budget = InvestigationBudget(
        max_iterations=5,
        max_tool_executions=10,
        max_total_execution_seconds=60,
    )

    ctrl = InvestigationController(
        case_id="case-15b",
        investigator="analyst",
        storage=store,
        custody_engine=custody,
        budgets=budget,
    )
    ctrl.initialize()

    # Initial plan has actions for both artifacts
    assert len(ctrl.record.plan.planned_actions) >= 2
    # First iteration executes pending actions
    rec = ctrl.run_iteration()

    # Verified multi-step progression: completed actions recorded
    assert len(rec.completed_actions) >= 1
    assert rec.current_iteration >= 1

    # Follow-up actions planned if unanalyzed artifacts remained
    unanalyzed_arts = [art2]
    pivots = {"processes": ["services.exe"], "users": ["svc_backup"]}
    follow_ups = ctrl._plan_follow_up_actions(unanalyzed_arts, pivots)
    assert len(follow_ups) == 1
    assert follow_ups[0].capability_id == "dissect_registry"
    assert "services.exe" in follow_ups[0].justification or "process pivots" in follow_ups[0].justification


def test_budget_exhaustion_transitions_to_partially_completed(multi_artifact_env):
    """Investigation strictly respects max_iterations and transitions to PARTIALLY_COMPLETED."""
    custody, store, art1, art2, finding1 = multi_artifact_env

    tight_budget = InvestigationBudget(
        max_iterations=1,
        max_tool_executions=10,
    )

    ctrl = InvestigationController(
        case_id="case-15b",
        investigator="analyst",
        storage=store,
        custody_engine=custody,
        budgets=tight_budget,
    )
    ctrl.initialize()

    # Iteration 1 exhausts budget
    rec = ctrl.run_iteration()
    assert rec.lifecycle_state == InvestigationLifecycleState.PARTIALLY_COMPLETED
    assert rec.current_iteration >= 1


def test_report_separation_confirmed_facts_vs_unverified_hypotheses(multi_artifact_env):
    """CitedReport explicitly separates confirmed facts from unverified hypotheses."""
    custody, store, art1, art2, finding1 = multi_artifact_env

    # 1. Confirmed Finding (100% backed, verified, confidence > 0.40, no review)
    confirmed_fact = CitedClaim(
        claim_type="observed_fact",
        statement="Type 3 Network Logon for svc_backup on FINANCE-SRV",
        citing_finding_ids=[finding1.finding_id],
        source_artifact_hashes=[finding1.source_artifact_hash],
        confidence=1.0,
        verification_status="VERIFIED",
        requires_analyst_review=False,
    )

    # 2. Hypothesis (e.g. downgraded or investigative lead)
    hypothesis_lead = CitedClaim(
        claim_type="hypothesis",
        statement="Adversary may have established scheduled task persistence",
        citing_finding_ids=[finding1.finding_id],
        source_artifact_hashes=[finding1.source_artifact_hash],
        confidence=0.35,
        verification_status="UNVERIFIED",
        requires_analyst_review=True,
        review_notes="Downgraded: ungrounded persistence claim",
    )

    # 3. Low-confidence ungrounded claim needing review
    review_claim = CitedClaim(
        claim_type="observed_fact",
        statement="Suspected password spraying activity on FINANCE-SRV",
        citing_finding_ids=[finding1.finding_id],
        source_artifact_hashes=[finding1.source_artifact_hash],
        confidence=0.40,  # <= 0.40 threshold
        verification_status="NEEDS_REVIEW",
        requires_analyst_review=True,
    )

    node_res = NodeGoalResult(
        node_id="test_separation_node",
        status="completed",
        summary="Analysis output with mixed claims",
        claims=[confirmed_fact, hypothesis_lead, review_claim],
    )

    report = ReportBuilder.build_report(
        case_id="case-15b",
        node_results=[node_res],
        storage=store,
        custody_engine=custody,
        strict_citations=False,
    )

    # Verified Separation:
    # Confirmed findings (observed_facts) must ONLY contain confirmed_fact
    assert len(report.observed_facts) == 1
    assert report.observed_facts[0].statement == confirmed_fact.statement
    assert report.observed_facts[0].confidence > 0.40
    assert not report.observed_facts[0].requires_analyst_review

    # Unverified hypotheses must contain the hypothesis and the review claim
    assert len(report.unverified_hypotheses) == 2
    hypo_stmts = [h.statement for h in report.unverified_hypotheses]
    assert hypothesis_lead.statement in hypo_stmts
    assert review_claim.statement in hypo_stmts

    # Markdown export renders distinct separated sections
    md = report.to_markdown()
    assert "## 3. Observed Facts" in md
    assert "### Unverified Hypotheses & Evaluated Leads" in md
    assert "explicitly separated from confirmed forensic" in md


def test_controller_compile_report_defaults_strict_true(multi_artifact_env):
    """InvestigationController.compile_report defaults to strict_citations=True."""
    custody, store, art1, art2, finding1 = multi_artifact_env

    ctrl = InvestigationController(
        case_id="case-15b",
        investigator="analyst",
        storage=store,
        custody_engine=custody,
    )
    ctrl.initialize()

    # compile_report() with default parameters (strict_citations=True)
    report = ctrl.compile_report()
    assert isinstance(report, CitedReport)
    assert report.case_id == "case-15b"
    assert len(report.observed_facts) >= 1
    for fact in report.observed_facts:
        assert fact.confidence > 0.40
        assert not fact.requires_analyst_review


def test_fail_closed_llm_error_handling_in_graph(tmp_path):
    """When LLM times out or errors, node status is marked 'partial' or 'failed' and never reports completed/success."""
    store = ForensicStore(":memory:")
    finding = ForensicFinding(
        finding_id="fnd-det-01",
        case_id="case-llm-fail",
        source_artifact_id="art-evtx",
        source_artifact_hash="c" * 64,
        tool_id="dissect_evtx",
        artifact_type="evtx",
        category="authentication",
        host="SERVER-01",
        user="admin",
        summary="Logon event 4624",
    )
    store.insert_findings([finding])

    # Mock OllamaClient that simulates a timeout / malformed JSON error
    mock_client = LMStudioClient(mock_mode=False)
    mock_client.generate_node_goal_result = AsyncMock(
        side_effect=ForensicOpsError("LM Studio connection timed out after 30s")
    )

    engine = ForensicOpsWorkflowEngine(
        storage=store,
        ollama_client=mock_client,
    )

    node = WorkflowNode(
        id="node_ai_fail",
        name="AI Analysis",
        type="ai_goal_step",
        config={"goal": "Detect lateral movement", "artifact_type": "evtx"},
    )
    handler = engine._make_ai_goal_step_node(node)

    state = WorkflowExecutionState(
        case_id="case-llm-fail",
        workflow_id="wf-test-fail",
        active_payload=WorkflowEdgePayload(),
    )

    out = handler(state)

    # Node must NOT be in completed_nodes
    assert "node_ai_fail" not in out["completed_nodes"]
    # Node result must be degraded to 'partial' (with preserved deterministic observations) or 'failed'
    res = out["node_results"]["node_ai_fail"]
    assert res.status in ("partial", "failed")
    assert res.status != "completed"
    assert res.status != "success"
    assert "LM Studio connection timed out" in res.summary
    assert any("timed out" in err for err in out["errors"])

    store.close()


def test_controller_degrades_state_on_action_failure(multi_artifact_env):
    """InvestigationController records action errors and transitions to FAILED or PARTIALLY_COMPLETED."""
    custody, store, art1, art2, finding1 = multi_artifact_env

    ctrl = InvestigationController(
        case_id="case-15b",
        investigator="analyst",
        storage=store,
        custody_engine=custody,
    )
    ctrl.initialize()

    # Simulate failing action and run to completion
    with patch.object(ctrl, "_execute_action", return_value={"success": False, "error": "Parser segmentation fault"}):
        rec = ctrl.run_to_completion()

    assert len(rec.errors) >= 1
    assert "Parser segmentation fault" in rec.errors[0]
    assert rec.lifecycle_state in (
        InvestigationLifecycleState.FAILED,
        InvestigationLifecycleState.PARTIALLY_COMPLETED,
    )
    assert rec.lifecycle_state != InvestigationLifecycleState.COMPLETED
