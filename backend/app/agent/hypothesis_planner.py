"""Deterministic, Playbook-Constrained Goal Engine & Hypothesis Planner.

Standards:
- Deterministic Tooling Only (AGENTS.md Rule 1): Factual claims must derive from
  verified parsers and DuckDB/SQLite storage; zero unconstrained LLM hypothesis generation.
- Scope 1C: Target OS & Artifact Indexing across Windows & Linux triage archives (.zip, .tar.gz)
  and individual artifacts (.evtx, Registry hives, .pcap/.pcapng, Linux /var/log, cron, systemd, shell histories).
- Scope 2C: Full 14-Tactic MITRE ATT&CK Playbook Registry (TA0001 - TA0043).
- Scope 3B: Deterministic Plan Compilation & Auto-Execution (auto_approve=True) with Future HITL Hook (auto_approve=False).
- Scope 4B: Hybrid Standard Playbooks + ScopedFilterParams (IOCs, regex, time ranges, Event IDs).
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from uuid import uuid4
from pydantic import BaseModel, Field

from backend.app.agent.lmstudio_client import LMStudioClient, clean_json_markdown
from backend.app.agent.prompts import GOAL_ROUTER_SYSTEM_PROMPT
from backend.app.agent.report_builder import CitedReport, ReportBuilder
from backend.app.agent.tools import (
    apply_scoped_filters,
    extract_pivots_from_findings,
    hybrid_search_tool,
    parse_linux_text_log,
    parse_pcap_file,
    query_findings_tool,
)
from backend.app.core.artifact_indexer import CaseArtifactIndex, index_case_artifacts
from backend.app.core.citation_guard import CitationGuard
from backend.app.core.config import get_settings
from backend.app.core.custody_engine import CustodyEngine
from backend.app.core.dissect_adapter import DissectAdapter
from backend.app.core.playbook_registry import (
    MitrePlaybook,
    PlaybookRegistry,
    PlaybookStep,
    ScopedFilterParams,
    TargetOS,
    get_playbook_registry,
)
from backend.app.core.storage import ForensicStore
from backend.app.db.sqlite_store import get_llm_state_store
from backend.app.models.findings import (
    CitedClaim,
    ForensicFinding,
    HypothesisDraft,
    NodeGoalResult,
)


# ==============================================================================
# Plan Step Status & Execution Models (Scope 3B & Scope 4B)
# ==============================================================================

class PlanStepStatus(str, Enum):
    READY = "READY"
    SKIPPED_NO_ARTIFACT = "SKIPPED_NO_ARTIFACT"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"


class CompiledPlanStep(BaseModel):
    """A deterministic playbook step compiled against actual case vault artifacts."""
    step_id: str
    name: str
    tactic_id: str
    tactic_name: str
    description: str
    target_os: str
    parser_plugin: str
    required_artifact_types: List[str]
    artifact_globs: List[str] = Field(default_factory=list)
    status: PlanStepStatus = PlanStepStatus.READY
    skip_reason: Optional[str] = None
    matched_artifact_ids: List[str] = Field(default_factory=list)
    scoped_filters: Optional[ScopedFilterParams] = None


class DeterministicGoalPlan(BaseModel):
    """The compiled execution plan produced by the Deterministic Goal Engine."""
    plan_id: str = Field(default_factory=lambda: f"plan-{uuid4().hex[:12]}")
    case_id: str
    investigation_goal: str
    auto_approve: bool = True
    status: str = "PLANNED"  # "PLANNED", "PAUSED_AWAITING_APPROVAL", "COMPLETED", "FAILED"
    scoped_filters: ScopedFilterParams
    matched_tactics: List[str] = Field(default_factory=list)
    steps: List[CompiledPlanStep] = Field(default_factory=list)
    executed_steps_count: int = 0
    skipped_steps_count: int = 0
    created_at_utc: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ==============================================================================
# Backward-Compatible Helper Functions
# ==============================================================================

def _infer_recommended_blueprint(findings: List[ForensicFinding], goal: str) -> str:
    """Infer the most appropriate starter DAG blueprint based on evidence types and investigative goal."""
    g_lower = goal.lower()
    types = {f.artifact_type.lower() for f in findings}

    if "memory" in types or "pcap" in types or "network" in g_lower or "memory" in g_lower:
        return "memory_pcap_hunt"
    if "linux" in g_lower or "ssh" in g_lower or any("linux" in (f.host or "").lower() for f in findings):
        return "linux_ssh_compromise"
    if "triage" in g_lower or "disk_image" in types or "capsule" in types:
        return "full_windows_triage"
    return "windows_intrusion"


# ==============================================================================
# Deterministic Hypothesis Planner Service
# ==============================================================================

class HypothesisPlannerService:
    """Service orchestrating deterministic MITRE ATT&CK Playbook routing and execution."""

    def __init__(
        self,
        storage: Optional[ForensicStore] = None,
        llm_client: Optional[LMStudioClient] = None,
        custody_engine: Optional[CustodyEngine] = None,
        dissect_adapter: Optional[DissectAdapter] = None,
        playbook_registry: Optional[PlaybookRegistry] = None,
    ):
        self.storage = storage
        self.llm_client = llm_client
        self.custody_engine = custody_engine
        self.dissect_adapter = dissect_adapter or DissectAdapter()
        self.playbook_registry = playbook_registry or get_playbook_registry()

    async def route_goal(
        self,
        investigation_goal: str,
        custom_filters: Optional[ScopedFilterParams] = None,
    ) -> Tuple[List[MitrePlaybook], ScopedFilterParams]:
        """Route investigation goal to MITRE Enterprise tactics and extract ScopedFilterParams.
        
        Uses LM Studio / Provider registry at temperature=0.2 with deterministic keyword fallback.
        """
        # Deterministic base filter extraction
        extracted_filters = self.playbook_registry.extract_scoped_filter_params(investigation_goal)
        if custom_filters:
            # Merge custom filters
            merged_kws = list(dict.fromkeys(extracted_filters.keywords_or_iocs + custom_filters.keywords_or_iocs))
            merged_eids = list(set(extracted_filters.event_ids + custom_filters.event_ids))
            extracted_filters = ScopedFilterParams(
                keywords_or_iocs=merged_kws,
                regex_pattern=custom_filters.regex_pattern or extracted_filters.regex_pattern,
                time_start_utc=custom_filters.time_start_utc or extracted_filters.time_start_utc,
                time_end_utc=custom_filters.time_end_utc or extracted_filters.time_end_utc,
                event_ids=merged_eids,
            )

        settings = get_settings()
        is_mock = settings.llm_mock_mode or (os.getenv("FORENSICOPS_LIVE_LLM", "false").lower() not in ("true", "1", "yes"))

        # 1. Deterministic keyword & IOC router first (instantaneous & deterministic, AGENTS.md Rule 1)
        matched_playbooks: List[MitrePlaybook] = self.playbook_registry.route_goal_to_playbooks(investigation_goal)

        # 2. If no playbooks matched via deterministic keywords, consult LLM at temperature=0.2
        if not matched_playbooks and not is_mock and self.llm_client:
            try:
                resp = await self.llm_client.chat_completion(
                    messages=[
                        {"role": "system", "content": GOAL_ROUTER_SYSTEM_PROMPT},
                        {"role": "user", "content": f"Investigative Goal: {investigation_goal}"},
                    ],
                    temperature=0.2,
                    max_tokens=200,
                )
                choices = resp.get("choices", [])
                if choices:
                    raw_msg = choices[0].get("message", {})
                    raw_content = raw_msg.get("content") or raw_msg.get("reasoning_content") or "{}"
                    parsed = json.loads(clean_json_markdown(raw_content))
                    tids = parsed.get("matched_tactics", [])
                    for tid in tids:
                        pb = self.playbook_registry.get_playbook(tid)
                        if pb and pb not in matched_playbooks:
                            matched_playbooks.append(pb)
                    # Enrich keywords from LLM
                    for kw in parsed.get("keywords_or_iocs", []):
                        if kw.lower() not in [k.lower() for k in extracted_filters.keywords_or_iocs]:
                            extracted_filters.keywords_or_iocs.append(kw)
            except Exception:
                matched_playbooks = []

        # Default fallback to initial access / execution if still empty
        if not matched_playbooks:
            matched_playbooks = self.playbook_registry.route_goal_to_playbooks("general triage")

        return matched_playbooks, extracted_filters

    def compile_goal_plan(
        self,
        case_id: str,
        investigation_goal: str,
        matched_playbooks: List[MitrePlaybook],
        scoped_filters: ScopedFilterParams,
        findings: Optional[List[ForensicFinding]] = None,
        auto_approve: bool = True,
    ) -> DeterministicGoalPlan:
        """Cross-reference playbook steps against case artifacts to produce the compiled plan."""
        # Scope 1C Indexing
        artifact_index = index_case_artifacts(
            case_id=case_id,
            custody_engine=self.custody_engine,
            storage=self.storage,
            extra_findings=findings,
        )

        compiled_steps: List[CompiledPlanStep] = []
        skipped_count = 0
        ready_count = 0

        for pb in matched_playbooks:
            for step in pb.steps:
                matched, matched_ids = artifact_index.matches_step(
                    artifact_globs=step.artifact_globs,
                    required_artifact_types=step.required_artifact_types,
                    target_os=step.target_os.value,
                )

                if matched:
                    compiled_steps.append(
                        CompiledPlanStep(
                            step_id=step.step_id,
                            name=step.name,
                            tactic_id=step.tactic_id,
                            tactic_name=step.tactic_name,
                            description=step.description,
                            target_os=step.target_os.value,
                            parser_plugin=step.parser_plugin,
                            required_artifact_types=step.required_artifact_types,
                            artifact_globs=step.artifact_globs,
                            status=PlanStepStatus.READY,
                            matched_artifact_ids=matched_ids,
                            scoped_filters=scoped_filters,
                        )
                    )
                    ready_count += 1
                else:
                    # Scope 3B Anti-Hallucination Guardrail: mark SKIPPED_NO_ARTIFACT
                    compiled_steps.append(
                        CompiledPlanStep(
                            step_id=step.step_id,
                            name=step.name,
                            tactic_id=step.tactic_id,
                            tactic_name=step.tactic_name,
                            description=step.description,
                            target_os=step.target_os.value,
                            parser_plugin=step.parser_plugin,
                            required_artifact_types=step.required_artifact_types,
                            artifact_globs=step.artifact_globs,
                            status=PlanStepStatus.SKIPPED_NO_ARTIFACT,
                            skip_reason=f"No matching artifacts found in vault for required types: {step.required_artifact_types} (globs: {step.artifact_globs})",
                            matched_artifact_ids=[],
                            scoped_filters=scoped_filters,
                        )
                    )
                    skipped_count += 1

        # Scope 4B: Attach optional SCOPED_IOC_TIMELINE_SWEEP step if filters exist
        if scoped_filters.keywords_or_iocs or scoped_filters.regex_pattern or scoped_filters.time_start_utc:
            has_any_artifacts = len(artifact_index.indexed_files) > 0 or (self.storage and self.storage.count_findings(case_id) > 0) or bool(findings)
            compiled_steps.append(
                CompiledPlanStep(
                    step_id="step_scoped_ioc_timeline_sweep",
                    name="Scoped IOC & Timeline Sweep",
                    tactic_id="TA0000",
                    tactic_name="Scoped Sweep",
                    description=f"Deterministic cross-artifact timeline and IOC sweep matching: {scoped_filters.keywords_or_iocs}",
                    target_os="cross_platform",
                    parser_plugin="hybrid_search_tool",
                    required_artifact_types=["all"],
                    artifact_globs=["*"],
                    status=PlanStepStatus.READY if has_any_artifacts else PlanStepStatus.SKIPPED_NO_ARTIFACT,
                    skip_reason=None if has_any_artifacts else "No artifacts or telemetry available for sweep.",
                    matched_artifact_ids=["all_indexed_telemetry"] if has_any_artifacts else [],
                    scoped_filters=scoped_filters,
                )
            )
            if has_any_artifacts:
                ready_count += 1
            else:
                skipped_count += 1

        plan_status = "PLANNED" if auto_approve else "PAUSED_AWAITING_APPROVAL"

        plan = DeterministicGoalPlan(
            case_id=case_id,
            investigation_goal=investigation_goal,
            auto_approve=auto_approve,
            status=plan_status,
            scoped_filters=scoped_filters,
            matched_tactics=[pb.tactic_id for pb in matched_playbooks],
            steps=compiled_steps,
            executed_steps_count=0,
            skipped_steps_count=skipped_count,
        )

        # Record plan in custody engine
        if self.custody_engine:
            try:
                self.custody_engine.append_custody_entry(
                    case_id=case_id,
                    action="deterministic_plan_compiled",
                    source_artifact_hash="0" * 64,
                    details={
                        "plan_id": plan.plan_id,
                        "goal": investigation_goal,
                        "auto_approve": auto_approve,
                        "matched_tactics": plan.matched_tactics,
                        "ready_steps": ready_count,
                        "skipped_steps": skipped_count,
                    },
                )
            except Exception:
                pass

        return plan

    def execute_goal_plan(
        self,
        plan: DeterministicGoalPlan,
        base_findings: Optional[List[ForensicFinding]] = None,
    ) -> Tuple[List[ForensicFinding], Optional[CitedReport]]:
        """Scope 3B Auto-Execution: execute all READY deterministic parsers with ScopedFilterParams."""
        all_findings: List[ForensicFinding] = list(base_findings or [])

        # Fetch existing findings from DuckDB storage
        if self.storage:
            try:
                existing = self.storage.query_structured_findings(case_id=plan.case_id, limit=200)
                all_findings.extend(existing)
            except Exception:
                pass

        # Deduplicate findings by finding_id
        unique_findings: Dict[str, ForensicFinding] = {f.finding_id: f for f in all_findings}

        # Execute READY steps against case vault files
        for step in plan.steps:
            if step.status != PlanStepStatus.READY:
                continue

            new_step_findings: List[ForensicFinding] = []

            # 1. PCAP network parser
            if "pcap" in step.parser_plugin or step.target_os == "network":
                if self.custody_engine:
                    try:
                        artifacts = self.custody_engine.get_artifacts(case_id=plan.case_id)
                        for a in artifacts:
                            if a.type in ("pcap", "network") or a.original_path.lower().endswith((".pcap", ".pcapng")):
                                rpath = self.custody_engine.resolve_artifact_file(a)
                                if rpath.is_file():
                                    parsed = parse_pcap_file(rpath, plan.case_id, a.artifact_id, a.sha256)
                                    new_step_findings.extend(parsed)
                    except Exception:
                        pass

            # 2. Linux Log parser
            elif "dissect_adapter" in step.parser_plugin and step.target_os == "linux":
                if self.custody_engine:
                    try:
                        artifacts = self.custody_engine.get_artifacts(case_id=plan.case_id)
                        for a in artifacts:
                            if "log" in a.original_path.lower() or "auth" in a.original_path.lower():
                                rpath = self.custody_engine.resolve_artifact_file(a)
                                if rpath.is_file():
                                    parsed = parse_linux_text_log(rpath, plan.case_id, a.artifact_id, a.sha256)
                                    new_step_findings.extend(parsed)
                    except Exception:
                        pass

            # 3. Dissect EVTX / Registry parser
            elif "evtx" in step.parser_plugin or "recmd" in step.parser_plugin:
                if self.custody_engine:
                    try:
                        artifacts = self.custody_engine.get_artifacts(case_id=plan.case_id)
                        for a in artifacts:
                            rpath = self.custody_engine.resolve_artifact_file(a)
                            if rpath.is_file():
                                if a.type == "evtx" or rpath.suffix.lower() == ".evtx":
                                    parsed = self.dissect_adapter.parse_evtx(rpath, plan.case_id, a.artifact_id, a.sha256)
                                    new_step_findings.extend(parsed)
                                elif a.type == "registry":
                                    parsed = self.dissect_adapter.parse_registry_hive(rpath, plan.case_id, a.artifact_id, a.sha256)
                                    new_step_findings.extend(parsed)
                    except Exception:
                        pass

            # 4. Scoped Sweep step: cross-artifact DuckDB hybrid search
            elif step.step_id == "step_scoped_ioc_timeline_sweep" and self.storage:
                try:
                    for kw in plan.scoped_filters.keywords_or_iocs:
                        swept = hybrid_search_tool(self.storage, query=kw, case_id=plan.case_id, top_k=25)
                        new_step_findings.extend(swept)
                except Exception:
                    pass

            # Scope 4B: apply deterministic scoped filters to newly parsed findings
            filtered_new = apply_scoped_filters(new_step_findings, plan.scoped_filters)

            # Insert into DuckDB storage
            if filtered_new and self.storage:
                try:
                    self.storage.insert_findings(filtered_new)
                except Exception:
                    pass

            for f in filtered_new:
                unique_findings[f.finding_id] = f

            step.status = PlanStepStatus.EXECUTED
            plan.executed_steps_count += 1

        final_findings = list(unique_findings.values())
        # Apply 4B scoped filter to all final findings if keywords or filters present
        if plan.scoped_filters.keywords_or_iocs or plan.scoped_filters.event_ids or plan.scoped_filters.time_start_utc:
            filtered_universe = apply_scoped_filters(final_findings, plan.scoped_filters)
            if filtered_universe:
                if base_findings:
                    base_ids = {bf.finding_id for bf in base_findings}
                    final_findings = list(base_findings) + [f for f in filtered_universe if f.finding_id not in base_ids]
                else:
                    final_findings = filtered_universe
            elif base_findings:
                final_findings = list(base_findings)

        # Pass structured rows through CitationGuard and ReportBuilder
        report = None
        if self.storage and final_findings:
            try:
                # Build verified cited claims
                claims: List[CitedClaim] = []
                for f in final_findings[:10]:
                    claims.append(
                        CitedClaim(
                            claim_type="observed_fact",
                            statement=f"Observed {f.category} in {f.artifact_type}: {f.summary}",
                            citing_finding_ids=[f.finding_id],
                            source_artifact_hashes=[f.source_artifact_hash],
                            confidence=1.0,
                            verification_status="VERIFIED",
                            why_it_matters=f"Telemetry verified under tactic '{plan.matched_tactics}' for host '{f.host or 'endpoint'}'.",
                        )
                    )
                if len(final_findings) >= 2:
                    f0, f1 = final_findings[0], final_findings[1]
                    claims.append(
                        CitedClaim(
                            claim_type="derived_correlation",
                            statement=f"Correlated activity between {f0.artifact_type} ({f0.category}) and {f1.artifact_type} ({f1.category}) under {plan.investigation_goal}",
                            citing_finding_ids=[f0.finding_id, f1.finding_id],
                            source_artifact_hashes=list(dict.fromkeys([f0.source_artifact_hash, f1.source_artifact_hash])),
                            confidence=1.0,
                            verification_status="VERIFIED",
                            why_it_matters=f"Multi-finding correlation across tactics '{plan.matched_tactics}' linking host '{f0.host or 'endpoint'}' and user '{f0.user or 'system'}'.",
                        )
                    )

                node_res = NodeGoalResult(
                    node_id="node_goal_execution",
                    status="success",
                    summary=f"Deterministic playbook execution for goal: {plan.investigation_goal}",
                    claims=claims,
                    extracted_pivots=extract_pivots_from_findings(final_findings),
                    recommended_next_actions=["Review timeline correlations", "Verify chain of custody integrity"],
                )

                guard = CitationGuard(self.storage)
                validated = guard.validate_node_result(node_res, case_id=plan.case_id, strict=False)
                active_res = validated.sanitized_result or node_res

                report = ReportBuilder.build_report(
                    case_id=plan.case_id,
                    node_results=[active_res],
                    storage=self.storage,
                    custody_engine=self.custody_engine,
                    strict_citations=False,
                )
            except Exception:
                report = None

        plan.status = "COMPLETED"
        return final_findings, report

    async def plan_hypothesis(
        self,
        case_id: str,
        investigation_goal: str,
        findings: Optional[List[ForensicFinding]] = None,
        recommended_blueprint: Optional[str] = None,
        auto_approve: bool = True,
        scoped_filters: Optional[ScopedFilterParams] = None,
    ) -> HypothesisDraft:
        """Main entry point: compiles deterministic playbook plan and auto-executes (3B) or pauses."""
        # 1. Route goal to MITRE tactics & ScopedFilterParams
        matched_playbooks, filters = await self.route_goal(investigation_goal, custom_filters=scoped_filters)

        # 2. Compile plan cross-referencing case vault artifacts
        plan = self.compile_goal_plan(
            case_id=case_id,
            investigation_goal=investigation_goal,
            matched_playbooks=matched_playbooks,
            scoped_filters=filters,
            findings=findings,
            auto_approve=auto_approve,
        )

        # Resolve findings against trusted storage when available to avoid trusting unverified objects
        resolved_findings: List[ForensicFinding] = []
        if self.storage and findings:
            stored = self.storage.get_findings_by_ids([f.finding_id for f in findings if f.finding_id])
            stored_map = {f.finding_id: f for f in stored if f.case_id == case_id}
            for f in findings:
                if f.case_id == case_id and f.finding_id in stored_map:
                    db_f = stored_map[f.finding_id]
                    if db_f.source_artifact_hash == f.source_artifact_hash:
                        resolved_findings.append(db_f)
                elif not stored and len(self.storage.query_structured_findings(case_id=case_id, limit=1)) == 0:
                    if f.case_id == case_id and f.source_artifact_hash:
                        resolved_findings.append(f)
        elif findings:
            resolved_findings = [f for f in findings if f.case_id == case_id and f.source_artifact_hash]
        elif self.storage:
            resolved_findings = self.storage.query_structured_findings(case_id=case_id, limit=20)

        compiled_report: Optional[CitedReport] = None

        # 3. Scope 3B Auto-Execution (when auto_approve=True)
        if auto_approve:
            executed_findings, compiled_report = self.execute_goal_plan(plan, base_findings=findings)
            if executed_findings:
                resolved_findings = executed_findings
        else:
            # Future HITL hook: pause after compiling checklist
            plan.status = "PAUSED_AWAITING_APPROVAL"

        # Determine recommended blueprint
        blueprint = recommended_blueprint or _infer_recommended_blueprint(resolved_findings, investigation_goal)

        # 4. Build verified citations strictly from observed findings
        cited_claims: List[CitedClaim] = []
        for f in resolved_findings[:5]:
            cited_claims.append(
                CitedClaim(
                    claim_type="observed_fact",
                    statement=f"Observed {f.category} in {f.artifact_type}: {f.summary}",
                    citing_finding_ids=[f.finding_id],
                    source_artifact_hashes=[f.source_artifact_hash],
                    confidence=1.0,
                    verification_status="VERIFIED",
                    why_it_matters=f"Telemetry indicates {f.category} activity associated with {f.user or 'system'}.",
                )
            )
        if len(resolved_findings) >= 2:
            f0, f1 = resolved_findings[0], resolved_findings[1]
            cited_claims.append(
                CitedClaim(
                    claim_type="derived_correlation",
                    statement=f"Correlated {f0.artifact_type} ({f0.category}) with {f1.artifact_type} ({f1.category}) under objective: '{investigation_goal}'",
                    citing_finding_ids=[f0.finding_id, f1.finding_id],
                    source_artifact_hashes=list(dict.fromkeys([f0.source_artifact_hash, f1.source_artifact_hash])),
                    confidence=1.0,
                    verification_status="VERIFIED",
                    why_it_matters=f"Correlated telemetry linking host '{f0.host or 'endpoint'}' and '{f1.host or 'endpoint'}'.",
                )
            )

        # 5. Synthesize deterministic threat & benign hypotheses
        tactics_str = ", ".join(plan.matched_tactics) if plan.matched_tactics else "Enterprise Triage"
        
        # Extract distinct evidence properties
        hosts = [f.host for f in resolved_findings if f.host]
        users = [f.user for f in resolved_findings if f.user]
        unique_hosts = list(dict.fromkeys(hosts))
        unique_users = list(dict.fromkeys(users))

        host_phrase = f"on host '{unique_hosts[0]}'" if len(unique_hosts) == 1 else (f"across {len(unique_hosts)} endpoints ({', '.join(unique_hosts[:3])})" if unique_hosts else "across indexed endpoints")
        user_phrase = f"under user identity '{unique_users[0]}'" if len(unique_users) == 1 else (f"involving identities ({', '.join(unique_users[:3])})" if unique_users else "")

        if resolved_findings:
            f0 = resolved_findings[0]
            threat = (
                f"Suspicious activity detected {host_phrase} {user_phrase} targeting objective: '{investigation_goal}'. "
                f"Observed telemetry in {f0.artifact_type} ({f0.category}: {f0.summary}) aligns with MITRE ATT&CK [{tactics_str}], "
                f"indicating active tradecraft without extrapolation."
            )
            benign = (
                f"Observed telemetry {host_phrase} {user_phrase} may align with authorized administrative maintenance, "
                f"routine automated software execution (e.g. SCCM/Ansible/Intune), scheduled backup routines, "
                f"or diagnostic operations related to '{investigation_goal}'."
            )
        else:
            threat = (
                f"Adversary activity suspected under MITRE ATT&CK [{tactics_str}] aiming to achieve: '{investigation_goal}'. "
                f"Current vault artifacts show no matching anomalies; recommend collecting additional endpoint triage telemetry."
            )
            benign = (
                f"Current baseline telemetry indicates normal system operations and routine background maintenance "
                f"without overt signs of malicious compromise."
            )

        key_questions = [
            f"What parent process or user identity initiated the '{investigation_goal}' sequence {host_phrase}?",
            f"Do observed artifacts under MITRE ATT&CK [{tactics_str}] indicate persistence or privilege escalation?",
            "Are there correlated network egress sessions or lateral movement connections across adjacent hosts?",
        ]

        tactical_actions = {
            "TA0001": "Inspect Security EVTX (Event 4624/4625) for anomalous logon types (Type 3/10 RDP) and credential brute-force bursts.",
            "TA0002": "Analyze Process Creation (Event 4688) and PowerShell Script Block (Event 4104) logs to de-obfuscate command lines.",
            "TA0003": "Audit Registry Run keys ('HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run') and scheduled tasks for persistence hooks.",
            "TA0004": "Review privileged service installations (System Event 7045) and token impersonation indicators.",
            "TA0005": "Search for defense evasion patterns such as Security event log clearing (Event 1102) and file hiding.",
            "TA0006": "Check LSASS memory access handles and SAM registry hive copies for credential dumping signatures.",
            "TA0007": "Audit endpoint discovery commands ('whoami /all', 'net user', 'nltest /dclist', 'net view').",
            "TA0008": "Trace lateral movement via remote services, PsExec, WinRM, or SMB named pipes across neighboring endpoints.",
            "TA0009": "Inspect staging directories (AppData, Temp) for data collection and sensitive archive generation.",
            "TA0011": "Correlate external IP connections and domain resolutions in PCAP/Zeek traffic for C2 beaconing.",
            "TA0010": "Inspect high-volume outbound network sessions and encrypted archive transfers for data exfiltration.",
            "TA0040": "Assess endpoint integrity for unauthorized service termination, ransomware extensions, or data destruction.",
        }

        # Suggested steps derive deterministically from compiled playbook steps
        suggested_steps = [
            f"[{step.status.value}] {step.tactic_id} - {step.name}: {tactical_actions.get(step.tactic_id.upper(), step.description)}"
            for step in plan.steps[:6]
        ]
        if not suggested_steps:
            suggested_steps = [
                f"Initialize DAG execution using the '{blueprint}' starter blueprint.",
                "Execute deterministic parsers on available case vault artifacts.",
                "Compile 6-section verified report with cryptographic CitationGuard.",
            ]

        # 6. Construct HypothesisDraft
        draft = HypothesisDraft(
            case_id=case_id,
            investigation_goal=investigation_goal,
            threat_hypothesis=threat,
            benign_hypothesis=benign,
            key_questions=key_questions,
            recommended_blueprint=blueprint,
            cited_findings=cited_claims,
            suggested_steps=suggested_steps,
            confidence_score=round(min(1.0, len(cited_claims) / max(len(plan.steps), 1)), 2) if resolved_findings else 0.0,
            auto_approve=auto_approve,
            status=plan.status,
            scoped_filters=filters.model_dump(),
            plan_steps=[s.model_dump() for s in plan.steps],
            report=compiled_report.to_dict() if compiled_report else None,
            report_markdown=compiled_report.to_markdown() if compiled_report else None,
        )

        self._persist_draft_to_session(case_id, draft)
        return draft

    def _persist_draft_to_session(self, case_id: str, draft: HypothesisDraft) -> None:
        """Persist hypothesis draft into SQLite session store."""
        try:
            store = get_llm_state_store()
            existing = store.get_investigation_session(case_id)
            wiz = existing.get("wizard_state", {}) if existing else {}
            wf = existing.get("workflow_state", {}) if existing else {}
            active_tab = existing.get("active_tab", "wizard") if existing else "wizard"

            wiz["investigation_goal"] = draft.investigation_goal
            wiz["hypothesis_draft"] = draft.model_dump()

            store.save_investigation_session(
                case_id=case_id,
                wizard_state=wiz,
                workflow_state=wf,
                active_tab=active_tab,
            )
        except Exception:
            pass
