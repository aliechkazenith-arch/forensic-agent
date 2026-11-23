"""Phase 03 Regression Test Suite: LLM Failure Handling, Claim Types, and Citation Verification.

Standards:
- Non-negotiable forensic principle: Deterministic forensic tools produce facts; LLM never manufactures facts.
- Explicit execution states: completed, partial, needs_more_data, failed, blocked, awaiting_approval.
- Removal of false-success fallback: LLM failures must produce failed/partial status with 0.0 confidence.
- Correct claim classification: observed_fact, derived_fact, derived_correlation (requires >=2 findings), hypothesis, recommendation.
- CitationGuard: Strict provenance, structural entity grounding, and explicit review marking.
"""
import pytest
from typing import Any, Dict, List
from unittest.mock import AsyncMock, patch

from backend.app.agent.graph import ForensicOpsWorkflowEngine
from backend.app.agent.hypothesis_planner import HypothesisPlannerService
from backend.app.agent.lmstudio_client import LMStudioClient
from backend.app.agent.memory_protocol import SQLiteFeedbackMemoryProvider
from backend.app.agent.ollama_client import OllamaClient
from backend.app.core.citation_guard import CitationGuard, CitationValidationReport
from backend.app.core.exceptions import CitationValidationError, ForensicOpsError
from backend.app.core.storage import ForensicStore
from backend.app.models.findings import (
    CitedClaim,
    ExecutionState,
    ForensicFinding,
    NodeGoalResult,
)
from backend.app.models.workflow import (
    WorkflowEdgePayload,
    WorkflowExecutionState,
    WorkflowNode,
)


@pytest.fixture
def memory_store():
    store = ForensicStore(":memory:")
    yield store
    store.close()


@pytest.fixture
def sample_findings():
    return [
        ForensicFinding(
            finding_id="fnd-001",
            case_id="case-100",
            source_artifact_id="art-evtx-01",
            source_artifact_hash="a1b2c3d4e5f60102030405060708090a1b2c3d4e5f60718293a4b5c6d7e8f901",
            tool_id="dissect",
            artifact_type="evtx",
            category="authentication",
            event_id="4624",
            severity="high",
            host="WS-CORP-01",
            user="jdoe",
            summary="Interactive logon successful for user jdoe",
        ),
        ForensicFinding(
            finding_id="fnd-002",
            case_id="case-100",
            source_artifact_id="art-evtx-02",
            source_artifact_hash="b2c3d4e5f60102030405060708090a1b2c3d4e5f60718293a4b5c6d7e8f901a1",
            tool_id="dissect",
            artifact_type="evtx",
            category="process_creation",
            event_id="4688",
            severity="critical",
            host="WS-CORP-01",
            user="jdoe",
            process_name="powershell.exe",
            command_line="powershell.exe -Enc aQB3AHIA...",
            summary="Suspicious encoded PowerShell execution by jdoe",
        ),
    ]


# ==============================================================================
# Task 1: Explicit Execution States
# ==============================================================================

def test_execution_state_model_conformance():
    """Verify all explicit execution states are supported and validated."""
    valid_states = [
        "completed",
        "partial",
        "needs_more_data",
        "failed",
        "blocked",
        "awaiting_approval",
    ]
    for st in valid_states:
        res = NodeGoalResult(node_id="test", status=st, summary="Test summary")
        assert res.status == st
        assert res.status in valid_states

    # Backward compatibility: "success" maps to "completed" and equality holds both ways
    compat_res = NodeGoalResult(node_id="test", status="success", summary="Compat")
    assert compat_res.status == "success"
    assert compat_res.status == "completed"
    assert compat_res.status != "failed"

    # Invalid status must be rejected
    with pytest.raises(ValueError, match="Invalid execution status"):
        NodeGoalResult(node_id="test", status="unknown_status", summary="Test")


# ==============================================================================
# Task 2: Removal of False-Success Fallback in Graph
# ==============================================================================

def test_llm_failure_marks_execution_failed_and_preserves_observations(memory_store, sample_findings, tmp_path):
    """When LLM provider fails, status must be failed/partial with 0.0 confidence, preserving deterministic facts."""
    memory_store.insert_findings(sample_findings)
    mem_provider = SQLiteFeedbackMemoryProvider(tmp_path / "mem.db")

    # Mock client that raises an exception simulating provider crash or timeout
    failing_client = OllamaClient(mock_mode=False)
    failing_client.generate_node_goal_result = AsyncMock(
        side_effect=ForensicOpsError("Connection refused to local LLM backend:11434")
    )

    guard = CitationGuard(memory_store)
    engine = ForensicOpsWorkflowEngine(
        storage=memory_store,
        memory_provider=mem_provider,
        ollama_client=failing_client,
        citation_guard=guard,
    )

    node = WorkflowNode(
        id="goal_analyze_auth",
        name="Analyze Authentication Anomaly",
        type="ai_goal_step",
        config={"goal": "Investigate unauthorized credential usage", "artifact_type": "evtx"},
    )

    handler = engine._make_ai_goal_step_node(node)
    init_state = WorkflowExecutionState(
        case_id="case-100",
        workflow_id="wf-test-fail",
        active_payload=WorkflowEdgePayload(pivots={"hosts": ["WS-CORP-01"]}),
    )

    result_dict = handler(init_state)

    # 1. Must NOT pretend goal completed successfully
    assert "goal_analyze_auth" not in result_dict["completed_nodes"]
    assert len(result_dict["errors"]) > 0
    assert "Connection refused" in result_dict["errors"][0]

    # 2. Status must be partial (or failed) and confidence must be 0.0, never 1.0 or 0.95
    node_res: NodeGoalResult = result_dict["node_results"]["goal_analyze_auth"]
    assert node_res.status in ("partial", "failed")
    assert node_res.status != "completed"
    assert node_res.confidence_score == 0.0

    # 3. Deterministic observations are preserved
    assert len(node_res.claims) > 0
    for c in node_res.claims:
        assert c.claim_type == "observed_fact"
        assert c.citing_finding_ids[0] in [f.finding_id for f in sample_findings]
        assert c.confidence == 0.0  # AI confidence is zero


def test_llm_failure_without_evidence_marks_failed(memory_store, tmp_path):
    """When LLM provider fails and no evidence was indexed, status must be failed."""
    mem_provider = SQLiteFeedbackMemoryProvider(tmp_path / "mem.db")

    failing_client = OllamaClient(mock_mode=False)
    failing_client.generate_node_goal_result = AsyncMock(
        side_effect=TimeoutError("Request to LLM timed out after 60s")
    )

    guard = CitationGuard(memory_store)
    engine = ForensicOpsWorkflowEngine(
        storage=memory_store,
        memory_provider=mem_provider,
        ollama_client=failing_client,
        citation_guard=guard,
    )

    node = WorkflowNode(
        id="empty_node",
        name="Analyze Empty Logs",
        type="ai_goal_step",
        config={"goal": "Hunt for non-existent threats"},
    )

    handler = engine._make_ai_goal_step_node(node)
    init_state = WorkflowExecutionState(
        case_id="case-empty",
        workflow_id="wf-test-empty",
    )

    result_dict = handler(init_state)
    node_res: NodeGoalResult = result_dict["node_results"]["empty_node"]
    assert node_res.status == "failed"
    assert node_res.confidence_score == 0.0
    assert len(node_res.claims) == 0
    assert "TimeoutError" in node_res.summary


# ==============================================================================
# Task 3: Claim Types & Correlation Multiplicity
# ==============================================================================

def test_claim_type_distinctions_and_constraints():
    """Verify observed_fact vs derived_fact vs derived_correlation constraints."""
    # 1. observed_fact requires finding ID and hash
    with pytest.raises(ValueError, match="requires at least one non-empty finding_id"):
        CitedClaim(claim_type="observed_fact", statement="Fact", citing_finding_ids=[])

    # 2. derived_fact requires finding ID and hash
    valid_derived_fact = CitedClaim(
        claim_type="derived_fact",
        statement="Time elapsed between logon and script execution is 42 seconds",
        citing_finding_ids=["fnd-001"],
        source_artifact_hashes=["hash1"],
    )
    assert valid_derived_fact.claim_type == "derived_fact"

    # 3. derived_correlation strictly requires >= 2 distinct findings
    with pytest.raises(ValueError, match="requires at least two distinct citing finding IDs"):
        CitedClaim(
            claim_type="derived_correlation",
            statement="Logon correlated to process execution",
            citing_finding_ids=["fnd-001"],
            source_artifact_hashes=["hash1"],
        )

    # 4. derived_correlation with 2 distinct findings succeeds
    valid_corr = CitedClaim(
        claim_type="derived_correlation",
        statement="User jdoe interactive logon at 08:00 correlated with encoded PowerShell spawn at 08:00:42",
        citing_finding_ids=["fnd-001", "fnd-002"],
        source_artifact_hashes=["hash1", "hash2"],
    )
    assert valid_corr.claim_type == "derived_correlation"
    assert len(valid_corr.citing_finding_ids) == 2


# ==============================================================================
# Task 4 & 6: Hypothesis Planner Trusted Resolution & No Modulo-2
# ==============================================================================

@pytest.mark.asyncio
async def test_hypothesis_planner_no_arbitrary_correlation_or_confidence(memory_store, sample_findings):
    """Verify hypothesis planner resolves through trusted store and does NOT use modulo-2 to classify claims."""
    memory_store.insert_findings(sample_findings)
    service = HypothesisPlannerService(storage=memory_store)

    # Pass 1 finding only
    single_finding = [sample_findings[0]]
    draft = await service.plan_hypothesis(
        case_id="case-100",
        investigation_goal="Analyze credential usage on WS-CORP-01",
        findings=single_finding,
        auto_approve=False,
    )

    # With only 1 finding, ALL cited claims must be observed_fact, never derived_correlation
    assert len(draft.cited_findings) == 1
    assert draft.cited_findings[0].claim_type == "observed_fact"
    assert draft.threat_hypothesis != ""
    assert draft.benign_hypothesis != ""
    assert len(draft.key_questions) > 0

    # With 2 findings, verify correlation cites both findings
    multi_draft = await service.plan_hypothesis(
        case_id="case-100",
        investigation_goal="Analyze intrusion chain on WS-CORP-01",
        findings=sample_findings,
        auto_approve=False,
    )
    correlations = [c for c in multi_draft.cited_findings if c.claim_type == "derived_correlation"]
    assert len(correlations) >= 1
    for c in correlations:
        assert len(c.citing_finding_ids) >= 2


@pytest.mark.asyncio
async def test_hypothesis_planner_empty_evidence_gives_zero_confidence(memory_store):
    """When no evidence matches, hypothesis confidence must be 0.0 rather than hardcoded 0.75."""
    service = HypothesisPlannerService(storage=memory_store)
    draft = await service.plan_hypothesis(
        case_id="case-empty",
        investigation_goal="Search for unknown persistence",
        findings=[],
        auto_approve=False,
    )
    assert draft.confidence_score == 0.0
    assert len(draft.cited_findings) == 0


# ==============================================================================
# Task 5: CitationGuard Structural Grounding vs Loose Overlap
# ==============================================================================

def test_citation_guard_exact_structural_grounding(memory_store, sample_findings):
    """Claim with exact structural entities (user, host, process) is verified without review flag."""
    memory_store.insert_findings(sample_findings)
    guard = CitationGuard(memory_store)

    # Strong match: includes host WS-CORP-01 and user jdoe
    strong_claim = CitedClaim(
        claim_type="observed_fact",
        statement="Host WS-CORP-01 recorded interactive logon for user jdoe",
        citing_finding_ids=["fnd-001"],
        source_artifact_hashes=[sample_findings[0].source_artifact_hash],
    )

    is_valid, reasons = guard.validate_claim(strong_claim, case_id="case-100")
    assert is_valid is True
    assert strong_claim.verification_status == "VERIFIED"
    assert strong_claim.requires_analyst_review is False


def test_citation_guard_loose_keyword_overlap_requires_analyst_review(memory_store, sample_findings):
    """A claim with only summary keyword overlap and no exact structural entities must require analyst review."""
    memory_store.insert_findings(sample_findings)
    guard = CitationGuard(memory_store)

    # Loose keyword overlap: mentions 'interactive' and 'logon' from summary, but no host or user
    loose_claim = CitedClaim(
        claim_type="observed_fact",
        statement="A generic interactive session was observed in endpoint authentication logs",
        citing_finding_ids=["fnd-001"],
        source_artifact_hashes=[sample_findings[0].source_artifact_hash],
    )

    is_valid, reasons = guard.validate_claim(loose_claim, case_id="case-100")
    assert is_valid is True
    # Substring match is not proof: flagged for human analyst review
    assert loose_claim.verification_status == "NEEDS_REVIEW"
    assert loose_claim.requires_analyst_review is True
    assert "analyst review" in (loose_claim.review_notes or "").lower()


def test_citation_guard_single_finding_derived_correlation_rejected(memory_store, sample_findings):
    """CitationGuard rejects derived_correlation claims that cite only a single finding."""
    memory_store.insert_findings(sample_findings)
    guard = CitationGuard(memory_store)

    f1 = sample_findings[0]
    # Bypass model validator by constructing through model_construct or similar to test CitationGuard layer
    single_fid_corr = CitedClaim.model_construct(
        claim_id="corr-single",
        claim_type="derived_correlation",
        statement=f"Observed user {f1.user} logon correlated across systems",
        citing_finding_ids=[f1.finding_id],
        source_artifact_hashes=[f1.source_artifact_hash],
        confidence=1.0,
    )

    is_valid, reasons = guard.validate_claim(single_fid_corr, case_id="case-100")
    assert is_valid is False
    assert any("requires at least two distinct citing finding IDs" in r for r in reasons)


# ==============================================================================
# Task 7: Prompt & Response Validation in LMStudioClient
# ==============================================================================

@pytest.mark.asyncio
async def test_lmstudio_client_malformed_json_raises_error():
    """Empty or malformed JSON from LLM must raise ForensicOpsError, never returning empty success."""
    client = LMStudioClient(mock_mode=False)

    # 1. Empty choices array
    client.chat_completion = AsyncMock(return_value={"choices": []})
    with pytest.raises(ForensicOpsError, match="empty choices array"):
        await client.generate_node_goal_result("node1", "goal", [])

    # 2. Empty message content
    client.chat_completion = AsyncMock(return_value={"choices": [{"message": {"content": ""}}]})
    with pytest.raises(ForensicOpsError, match="empty content"):
        await client.generate_node_goal_result("node1", "goal", [])

    # 3. Non-JSON string
    client.chat_completion = AsyncMock(
        return_value={"choices": [{"message": {"content": "I am unable to analyze this evidence because of safety policies."}}]}
    )
    with pytest.raises(ForensicOpsError, match="not a valid JSON object"):
        await client.generate_node_goal_result("node1", "goal", [])
