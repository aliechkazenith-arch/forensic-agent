"""Comprehensive Verification Suite for the Deterministic, Playbook-Constrained Goal Engine.

Standards:
- 1C: Target OS & Artifacts (Windows, Linux, PCAP) & SKIPPED_NO_ARTIFACT handling.
- 2C: Full 14-Tactic MITRE ATT&CK Playbook Registry (TA0001 - TA0043).
- 3B: Auto-Execution (auto_approve=True) & Future HITL Pause (auto_approve=False).
- 4B: ScopedFilterParams (IOCs, regex, time ranges, Event IDs) & Scoped Sweep.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.app.agent.hypothesis_planner import (
    CompiledPlanStep,
    DeterministicGoalPlan,
    HypothesisPlannerService,
    PlanStepStatus,
)
from backend.app.agent.tools import apply_scoped_filters
from backend.app.core.artifact_indexer import CaseArtifactIndex, index_case_artifacts
from backend.app.core.custody_engine import CustodyEngine
from backend.app.core.playbook_registry import (
    MitrePlaybook,
    PlaybookRegistry,
    PlaybookStep,
    ScopedFilterParams,
    get_playbook_registry,
)
from backend.app.core.storage import ForensicStore
from backend.app.db.sqlite_store import get_llm_state_store, reset_llm_state_store
from backend.app.main import create_app
from backend.app.models.findings import ForensicFinding


@pytest.fixture
def clean_env():
    """Ensure clean isolated SQLite and LLM state."""
    reset_llm_state_store()
    yield
    reset_llm_state_store()


@pytest.fixture
def client(clean_env) -> TestClient:
    app = create_app()
    return TestClient(app)


@pytest.fixture
def store():
    """Isolated in-memory DuckDB storage."""
    with ForensicStore(":memory:") as s:
        yield s


@pytest.fixture
def vault_dir(tmp_path):
    """Temporary isolated vault directory for CustodyEngine."""
    v = tmp_path / "test_vault"
    v.mkdir(parents=True, exist_ok=True)
    return v


# ==============================================================================
# 1. Scope 2C: Full 14-Tactic MITRE ATT&CK Playbook Registry Tests
# ==============================================================================

def test_mitre_14_tactics_registry_complete():
    """Verify that all 14 MITRE ATT&CK Enterprise tactics (TA0001 - TA0043) are registered."""
    registry = get_playbook_registry()
    playbooks = registry.list_all_playbooks()
    assert len(playbooks) == 14

    expected_tactics = {
        "TA0043": "Reconnaissance",
        "TA0042": "Resource Development",
        "TA0001": "Initial Access",
        "TA0002": "Execution",
        "TA0003": "Persistence",
        "TA0004": "Privilege Escalation",
        "TA0005": "Defense Evasion",
        "TA0006": "Credential Access",
        "TA0007": "Discovery",
        "TA0008": "Lateral Movement",
        "TA0009": "Collection",
        "TA0011": "Command and Control",
        "TA0010": "Exfiltration",
        "TA0040": "Impact",
    }

    tactic_ids = {p.tactic_id: p.tactic_name for p in playbooks}
    for tid, tname in expected_tactics.items():
        assert tid in tactic_ids, f"Missing MITRE tactic: {tid}"
        assert tactic_ids[tid] == tname
        pb = registry.get_playbook(tid)
        assert pb is not None
        assert len(pb.steps) >= 2, f"Tactic {tid} must contain at least 2 deterministic steps."
        for step in pb.steps:
            assert step.artifact_globs, f"Step {step.step_id} must specify artifact_globs."
            assert step.required_artifact_types, f"Step {step.step_id} must specify required_artifact_types."
            assert step.parser_plugin, f"Step {step.step_id} must reference a parser plugin."


@pytest.mark.parametrize(
    "goal,expected_tactic",
    [
        ("Find TeamViewer remote access activity", "TA0011"),
        ("Detect persistence via registry run keys and scheduled tasks", "TA0003"),
        ("Investigate LSASS memory dumping and credential theft", "TA0006"),
        ("Ransomware shadow copy deletion via vssadmin", "TA0040"),
        ("Event log clearing and defense evasion", "TA0005"),
        ("Investigate unauthorized SSH brute force initial access", "TA0001"),
        ("Suspicious PowerShell command execution", "TA0002"),
        ("Detect privilege escalation and sudo abuse", "TA0004"),
        ("Detect network discovery and whoami enumeration", "TA0007"),
        ("Analyze lateral movement via wmi and psexec", "TA0008"),
        ("Detect staging of zip and tar collections", "TA0009"),
        ("Identify data exfiltration via rclone", "TA0010"),
        ("Active port scanning and network recon", "TA0043"),
        ("Payload download staging via certutil", "TA0042"),
    ],
)
def test_goal_routing_to_mitre_tactics(goal: str, expected_tactic: str):
    """Test deterministic routing of goals to specific MITRE ATT&CK tactics."""
    registry = get_playbook_registry()
    matched = registry.route_goal_to_playbooks(goal)
    matched_ids = [p.tactic_id for p in matched]
    assert expected_tactic in matched_ids, f"Goal '{goal}' failed to route to {expected_tactic}. Got: {matched_ids}"


# ==============================================================================
# 2. Scope 1C: Target OS, Artifact Indexing & SKIPPED_NO_ARTIFACT Tests
# ==============================================================================

def test_scope_1c_windows_and_linux_artifact_matching_and_skipping(store, vault_dir):
    """Verify that steps are marked READY when artifacts exist, and SKIPPED_NO_ARTIFACT when absent."""
    case_id = "CASE-1C-TEST"
    custody = CustodyEngine(vault_root=vault_dir)

    # Ingest only a Windows EVTX artifact
    dummy_evtx = vault_dir / "Security.evtx"
    dummy_evtx.write_bytes(b"ElfFile\x00" + b"\x00" * 500)
    custody.ingest_artifact(
        case_id=case_id,
        source_path=dummy_evtx,
        artifact_type="evtx",
        original_source="C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
    )

    planner = HypothesisPlannerService(storage=store, custody_engine=custody)
    pb_reg = get_playbook_registry()

    # Get playbooks for Persistence (which has both Windows registry/tasks and Linux cron/systemd steps)
    persist_pb = pb_reg.get_playbook("TA0003")
    filters = ScopedFilterParams()

    plan = planner.compile_goal_plan(
        case_id=case_id,
        investigation_goal="Detect persistence mechanisms",
        matched_playbooks=[persist_pb],
        scoped_filters=filters,
        auto_approve=True,
    )

    # Find the steps
    steps_by_id = {s.step_id: s for s in plan.steps}

    # Step for Windows scheduled tasks requires Security.evtx -> must be READY
    win_task_step = steps_by_id.get("step_ta0003_win_scheduled_tasks")
    assert win_task_step is not None
    assert win_task_step.status == PlanStepStatus.READY
    assert len(win_task_step.matched_artifact_ids) > 0

    # Step for Linux cron/systemd requires Linux artifacts which are NOT present -> must be SKIPPED_NO_ARTIFACT
    linux_cron_step = steps_by_id.get("step_ta0003_linux_cron_systemd")
    assert linux_cron_step is not None
    assert linux_cron_step.status == PlanStepStatus.SKIPPED_NO_ARTIFACT
    assert "No matching artifacts found in vault" in (linux_cron_step.skip_reason or "")


def test_scope_1c_pcap_network_artifact_matching(store, vault_dir):
    """Verify that network PCAP files are indexed and trigger network steps as READY."""
    case_id = "CASE-PCAP-TEST"
    custody = CustodyEngine(vault_root=vault_dir)

    # Register a .pcap file
    dummy_pcap = vault_dir / "capture.pcap"
    dummy_pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 200)
    custody.ingest_artifact(
        case_id=case_id,
        source_path=dummy_pcap,
        artifact_type="pcap",
        original_source="/tmp/capture.pcap",
    )

    planner = HypothesisPlannerService(storage=store, custody_engine=custody)
    pb_reg = get_playbook_registry()

    c2_pb = pb_reg.get_playbook("TA0011")
    plan = planner.compile_goal_plan(
        case_id=case_id,
        investigation_goal="Find C2 beaconing in network traffic",
        matched_playbooks=[c2_pb],
        scoped_filters=ScopedFilterParams(keywords_or_iocs=["beacon"]),
        auto_approve=True,
    )

    steps_by_id = {s.step_id: s for s in plan.steps}
    pcap_step = steps_by_id.get("step_ta0011_pcap_c2_beacon")
    assert pcap_step is not None
    assert pcap_step.status == PlanStepStatus.READY
    assert len(pcap_step.matched_artifact_ids) > 0


# ==============================================================================
# 3. Scope 4B: Hybrid Standard Playbooks + Scoped Filters Tests
# ==============================================================================

def test_scope_4b_filter_extraction_and_time_window_normalization():
    """Verify regex, IOCs, Event IDs, and ISO time window normalization."""
    registry = get_playbook_registry()

    goal = "Find TeamViewer activity between 02:00 and 04:00 UTC with event 4688"
    filters = registry.extract_scoped_filter_params(goal)

    assert "teamviewer" in filters.keywords_or_iocs
    assert 4688 in filters.event_ids
    assert filters.time_start_utc is not None
    assert "02:00:00Z" in filters.time_start_utc
    assert filters.time_end_utc is not None
    assert "04:00:00Z" in filters.time_end_utc


def test_scope_4b_scoped_filtering_on_findings():
    """Test deterministic filtering by keywords, event IDs, and timestamps."""
    f1 = ForensicFinding(
        finding_id="fnd-tv-01",
        case_id="case-4b",
        source_artifact_id="art-01",
        source_artifact_hash="a" * 64,
        tool_id="dissect",
        timestamp_utc="2026-11-11T03:00:00Z",
        artifact_type="evtx",
        category="process_creation",
        event_id="4688",
        process_name="TeamViewer.exe",
        summary="Process TeamViewer.exe launched by admin",
    )

    f2 = ForensicFinding(
        finding_id="fnd-other-02",
        case_id="case-4b",
        source_artifact_id="art-01",
        source_artifact_hash="a" * 64,
        tool_id="dissect",
        timestamp_utc="2026-11-11T05:00:00Z",
        artifact_type="evtx",
        category="authentication",
        event_id="4624",
        summary="Routine network logon for user backup",
    )

    all_findings = [f1, f2]

    # Filter with keywords and time window
    filters = ScopedFilterParams(
        keywords_or_iocs=["teamviewer"],
        time_start_utc="2026-11-11T02:00:00Z",
        time_end_utc="2026-11-11T04:00:00Z",
        event_ids=[4688],
    )

    filtered = apply_scoped_filters(all_findings, filters)
    assert len(filtered) == 1
    assert filtered[0].finding_id == "fnd-tv-01"

    # Regex test
    regex_filters = ScopedFilterParams(regex_pattern=r"routine\s+network")
    regex_matched = apply_scoped_filters(all_findings, regex_filters)
    assert len(regex_matched) == 1
    assert regex_matched[0].finding_id == "fnd-other-02"


# ==============================================================================
# 4. Scope 3B: Auto-Execution vs. HITL Pause Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_scope_3b_auto_execution_flow(store, vault_dir):
    """Test auto_approve=True compiles checklist, executes READY parsers, and produces cited report."""
    case_id = "CASE-3B-AUTO"
    custody = CustodyEngine(vault_root=vault_dir)

    # Pre-populate store with verified telemetry
    finding = ForensicFinding(
        finding_id="fnd-auto-01",
        case_id=case_id,
        source_artifact_id="art-auto",
        source_artifact_hash="c" * 64,
        tool_id="dissect_evtx",
        timestamp_utc="2026-11-11T01:00:00Z",
        artifact_type="evtx",
        category="authentication",
        summary="PsExec lateral execution observed",
    )
    store.insert_findings([finding])

    planner = HypothesisPlannerService(storage=store, custody_engine=custody)
    draft = await planner.plan_hypothesis(
        case_id=case_id,
        investigation_goal="Investigate lateral movement via PsExec",
        auto_approve=True,
    )

    assert draft.case_id == case_id
    assert draft.auto_approve is True
    assert draft.status == "COMPLETED"
    assert len(draft.plan_steps) > 0
    # Must have cited real findings without LLM extrapolation
    assert len(draft.cited_findings) >= 1
    assert draft.cited_findings[0].citing_finding_ids == ["fnd-auto-01"]
    # Scope 3B report must be generated
    assert draft.report is not None


@pytest.mark.asyncio
async def test_scope_3b_hitl_pause_flow(store, vault_dir):
    """Test auto_approve=False compiles checklist, pauses execution, and returns PAUSED_AWAITING_APPROVAL."""
    case_id = "CASE-3B-HITL"
    custody = CustodyEngine(vault_root=vault_dir)

    planner = HypothesisPlannerService(storage=store, custody_engine=custody)
    draft = await planner.plan_hypothesis(
        case_id=case_id,
        investigation_goal="Find persistence via scheduled tasks",
        auto_approve=False,
    )

    assert draft.case_id == case_id
    assert draft.auto_approve is False
    assert draft.status == "PAUSED_AWAITING_APPROVAL"
    assert len(draft.plan_steps) > 0
    # In paused mode, parsers were not executed yet, report is None
    assert draft.report is None


def test_api_endpoint_compile_and_execute_plan(client: TestClient):
    """Test /api/agent/compile-plan and /api/agent/execute-plan endpoints."""
    # 1. Compile plan with auto_approve=False
    comp_resp = client.post(
        "/api/agent/compile-plan",
        json={
            "case_id": "CASE-API-01",
            "investigation_goal": "Find TeamViewer activity between 02:00 and 04:00 UTC",
            "auto_approve": False,
        },
    )
    assert comp_resp.status_code == 200
    plan_data = comp_resp.json()
    assert plan_data["status"] == "PAUSED_AWAITING_APPROVAL"
    assert "TA0011" in plan_data["matched_tactics"]
    assert len(plan_data["steps"]) > 0

    # 2. Get playbooks list
    pb_resp = client.get("/api/agent/playbooks")
    assert pb_resp.status_code == 200
    pbs = pb_resp.json()
    assert len(pbs) == 14
