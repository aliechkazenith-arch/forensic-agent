"""Autonomous Investigation Controller for ForensicOps AI.

Standards:
- Deterministic Tooling Only (AGENTS.md Rule 1): Parsers produce facts; LLMs plan, correlate, explain.
- Explicit Investigation Lifecycle State Machine with validated transitions.
- Controlled autonomy: safe read-only analysis runs autonomously; sensitive operations pause for human approval.
- Finite, bounded execution budgets (iterations, tool count, timeouts, context).
- Persistent state and recovery via SQLite and DuckDB.
- Human feedback integration (benign baseline suppression, knowledge retrieval, non-destructive feedback).
- Full audit traceability for every iteration step.
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union
from uuid import uuid4


def _run_coroutine_safely(coro: Any) -> Any:
    """Run an async coroutine safely whether inside an active event loop or synchronous thread."""
    if not asyncio.iscoroutine(coro):
        return coro
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop is not None and loop.is_running():
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as pool:
            return pool.submit(asyncio.run, coro).result()
    return asyncio.run(coro)

from backend.app.agent.memory_protocol import (
    KnowledgeAndMemoryProvider,
    SQLiteFeedbackMemoryProvider,
)
from backend.app.agent.tools import (
    extract_pivots_from_findings,
    query_findings_tool,
    timeline_window_tool,
)
from backend.app.core.action_risk_policy import ActionRiskPolicy, ActionType
from backend.app.core.analyzer_registry import AnalyzerRegistry, get_analyzer_registry
from backend.app.core.approval_engine import ApprovalEngine
from backend.app.core.artifact_indexer import CaseArtifactIndex, index_case_artifacts
from backend.app.core.citation_guard import CitationGuard
from backend.app.core.custody_engine import CustodyEngine
from backend.app.core.dissect_adapter import DissectAdapter
from backend.app.core.exceptions import (
    ExecutionPolicyError,
    ForensicOpsError,
    ProcessTimeoutError,
    SandboxUnavailableError,
    UnauthorizedCollectorExecutionError,
)
from backend.app.core.execution_policy import ExecutionPolicyRegistry, get_execution_policy_registry
from backend.app.core.plugin_runner import PluginRunner
from backend.app.core.specialist_registry import SpecialistRegistry, get_default_specialist_registry
from backend.app.core.storage import ForensicStore
from backend.app.db.sqlite_store import LLMStateStore, get_llm_state_store
from backend.app.models.custody import ArtifactRecord
from backend.app.models.findings import CitedClaim, ForensicFinding, NodeGoalResult
from backend.app.models.investigation import (
    BudgetExhaustionError,
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


class InvestigationController:
    """Persistent, bounded, and iterative investigation controller."""

    def __init__(
        self,
        case_id: str,
        investigator: str = "analyst",
        investigator_id: Optional[str] = None,
        investigator_badge: Optional[str] = None,
        objective: str = "Perform comprehensive forensic compromise assessment",
        custody_engine: Optional[CustodyEngine] = None,
        storage: Optional[ForensicStore] = None,
        plugin_runner: Optional[PluginRunner] = None,
        dissect_adapter: Optional[DissectAdapter] = None,
        analyzer_registry: Optional[AnalyzerRegistry] = None,
        execution_policy_registry: Optional[ExecutionPolicyRegistry] = None,
        specialist_registry: Optional[SpecialistRegistry] = None,
        memory_provider: Optional[KnowledgeAndMemoryProvider] = None,
        state_store: Optional[LLMStateStore] = None,
        authorized_evidence_scope: Optional[List[str]] = None,
        available_capabilities: Optional[List[str]] = None,
        budgets: Optional[InvestigationBudget] = None,
        budget: Optional[InvestigationBudget] = None,
        investigation_id: Optional[str] = None,
        secret_key: Optional[str] = None,
        approval_engine: Optional[ApprovalEngine] = None,
    ):
        self.case_id = case_id
        self.investigator = investigator
        self.investigator_id = investigator_id or investigator
        self.investigator_badge = investigator_badge
        self.objective = objective
        self.custody_engine = custody_engine
        self.storage = storage or ForensicStore()
        self.plugin_runner = plugin_runner
        self.dissect_adapter = dissect_adapter or DissectAdapter()
        self.analyzer_registry = analyzer_registry or get_analyzer_registry()
        self.execution_policy_registry = execution_policy_registry or get_execution_policy_registry()
        self.specialist_registry = specialist_registry or get_default_specialist_registry()
        self.memory_provider = memory_provider or SQLiteFeedbackMemoryProvider()
        self.state_store = state_store or get_llm_state_store()
        self.authorized_evidence_scope = list(authorized_evidence_scope or [])
        
        default_caps = [a.tool_id for a in self.analyzer_registry.list_analyzers()]
        for sc in self.specialist_registry.list_operational_capabilities():
            if sc.capability_id not in default_caps:
                default_caps.append(sc.capability_id)
            for rt in sc.required_tools:
                if rt not in default_caps:
                    default_caps.append(rt)
        for conn_id in ("splunk_siem", "elasticsearch_siem", "system_containment", "isolate_host"):
            if conn_id not in default_caps:
                default_caps.append(conn_id)
        self.available_capabilities = list(available_capabilities or default_caps)
        self.budget = budgets or budget or InvestigationBudget()
        self.secret_key = secret_key or os.getenv("HUMAN_APPROVAL_HMAC_SECRET", "forensicops-vault-hmac-key-2026-production-secured")
        self.approval_engine = approval_engine or ApprovalEngine(
            state_store=self.state_store,
            custody_engine=self.custody_engine,
            secret_key=self.secret_key,
        )

        # Initialize or load InvestigationRecord
        inv_id = investigation_id or f"inv-{uuid4().hex[:12]}"
        existing_data = self.state_store.get_investigation_state(inv_id)
        if existing_data:
            self.record = self._hydrate_record(existing_data)
        else:
            initial_plan = InvestigationPlan(
                case_id=self.case_id,
                objective=self.objective,
                hypotheses=[],
                planned_actions=[],
                evidence_gaps=[],
                correlations=[],
            )
            self.record = InvestigationRecord(
                investigation_id=inv_id,
                case_id=self.case_id,
                investigator=self.investigator,
                lifecycle_state=InvestigationLifecycleState.CREATED,
                objective=self.objective,
                plan=initial_plan,
                budget=self.budget,
                authorized_evidence_scope=self.authorized_evidence_scope,
                available_capabilities=self.available_capabilities,
                hypotheses=[],
                evidence_gaps=[],
                correlations=[],
                completed_actions=[],
                pending_actions=[],
                execution_ids=[],
                findings_count=0,
                errors=[],
                started_at_utc=datetime.now(timezone.utc).isoformat(),
            )
            self._persist_state()

    def _hydrate_record(self, data: Dict[str, Any]) -> InvestigationRecord:
        """Hydrate a typed InvestigationRecord from stored dictionary data."""
        plan_dict = data.get("plan", {})
        plan = InvestigationPlan.model_validate(plan_dict)
        budget = InvestigationBudget.model_validate(data.get("budget", {}))
        pivots = WorkflowEdgePayload.from_dict(data.get("pivots", {}))
        hypotheses = [CompetingHypothesis.model_validate(h) for h in data.get("hypotheses", [])]
        gaps = [EvidenceGap.model_validate(g) for g in data.get("evidence_gaps", [])]
        completed = [InvestigationAction.model_validate(a) for a in data.get("completed_actions", [])]
        pending = [InvestigationAction.model_validate(a) for a in data.get("pending_actions", [])]

        return InvestigationRecord(
            investigation_id=data["investigation_id"],
            case_id=data["case_id"],
            investigator=data["investigator"],
            lifecycle_state=InvestigationLifecycleState(data["lifecycle_state"]),
            objective=data["objective"],
            plan=plan,
            current_iteration=data["current_iteration"],
            budget=budget,
            pivots=pivots,
            authorized_evidence_scope=data.get("authorized_evidence_scope", []),
            available_capabilities=data.get("available_capabilities", []),
            hypotheses=hypotheses,
            evidence_gaps=gaps,
            correlations=data.get("correlations", []),
            completed_actions=completed,
            pending_actions=pending,
            execution_ids=data.get("execution_ids", []),
            findings_count=data.get("findings_count", 0),
            errors=data.get("errors", []),
            pause_reason=data.get("pause_reason"),
            started_at_utc=data.get("started_at_utc", datetime.now(timezone.utc).isoformat()),
            created_at_utc=data.get("created_at_utc", datetime.now(timezone.utc).isoformat()),
            updated_at_utc=data.get("updated_at_utc", datetime.now(timezone.utc).isoformat()),
        )

    def _persist_state(self) -> None:
        """Save current record into SQLite state store."""
        self.record.updated_at_utc = datetime.now(timezone.utc).isoformat()
        self.state_store.save_investigation_state(self.record)

    def transition_to(self, new_state: InvestigationLifecycleState) -> None:
        """Validate and transition to a new lifecycle state."""
        if self.record.lifecycle_state == new_state:
            return
        validate_lifecycle_transition(self.record.lifecycle_state, new_state)
        self.record.lifecycle_state = new_state
        self._persist_state()

    def _check_budgets(self) -> Optional[InvestigationLifecycleState]:
        """Check all execution budgets; return PARTIALLY_COMPLETED if exhausted, else None."""
        if self.record.current_iteration >= self.budget.max_iterations:
            return InvestigationLifecycleState.PARTIALLY_COMPLETED

        if len(self.record.execution_ids) >= self.budget.max_tool_executions:
            return InvestigationLifecycleState.PARTIALLY_COMPLETED

        # Total execution time check
        try:
            started = datetime.fromisoformat(self.record.started_at_utc.replace("Z", "+00:00"))
            elapsed = (datetime.now(timezone.utc) - started).total_seconds()
            if elapsed >= self.budget.max_total_execution_seconds:
                return InvestigationLifecycleState.PARTIALLY_COMPLETED
        except Exception:
            pass

        return None

    # --------------------------------------------------------------------------
    # 1. Lifecycle Initialization & Evidence Validation
    # --------------------------------------------------------------------------
    def initialize(self) -> InvestigationRecord:
        """Validate evidence and compile initial investigation plan."""
        if self.record.lifecycle_state == InvestigationLifecycleState.CREATED:
            self.transition_to(InvestigationLifecycleState.EVIDENCE_VALIDATION)

        # Inspect available evidence in CustodyEngine
        artifacts: List[ArtifactRecord] = []
        if self.custody_engine:
            artifacts = self.custody_engine.get_artifacts(case_id=self.case_id)

        # Filter by authorized evidence scope if specified
        if self.authorized_evidence_scope:
            artifacts = [
                a for a in artifacts
                if a.artifact_id in self.authorized_evidence_scope or (a.type and a.type.lower() in self.authorized_evidence_scope)
            ]

        if not artifacts:
            # Missing evidence: record evidence gap and transition to needs_more_data
            gap = EvidenceGap(
                missing_artifact_type="any",
                tactical_reason=f"No authorized evidence artifacts found in case vault for case '{self.case_id}'",
                recommended_collection="Ingest disk image, triage archive, or event logs into case vault",
                is_evidence_of_absence=False,
            )
            self.record.evidence_gaps.append(gap)
            self.transition_to(InvestigationLifecycleState.NEEDS_MORE_DATA)
            return self.record

        # Evidence exists: transition to PLANNING
        self.transition_to(InvestigationLifecycleState.PLANNING)
        self._compile_initial_plan(artifacts)
        return self.record

    # --------------------------------------------------------------------------
    # 2. Plan Formulation & Competing Hypotheses
    # --------------------------------------------------------------------------
    def _compile_initial_plan(self, artifacts: List[ArtifactRecord]) -> None:
        """Formulate initial competing hypotheses and map evidence to capabilities."""
        # 1. Generate Competing Hypotheses (Malicious vs Benign Administrative activity)
        h1 = CompetingHypothesis(
            title="Adversary Compromise & Intrusion",
            description=f"Unauthorized activity or lateral movement occurred aligned with goal: '{self.objective}'",
            is_benign_null=False,
            confidence=0.5,
            status="untested",
            version=1,
        )
        h2 = CompetingHypothesis(
            title="Legitimate Administrative Activity",
            description="Observed events correspond to standard authorized administrative tasks, maintenance, or benign software.",
            is_benign_null=True,
            confidence=0.5,
            status="untested",
            version=1,
        )
        self.record.hypotheses = [h1, h2]
        self.record.plan.hypotheses = [h1, h2]

        # 2. Map artifacts to available capabilities
        planned_actions: List[InvestigationAction] = []
        art_types = {str(a.type or "").lower() for a in artifacts}

        # Check for evidence gaps against common investigative needs
        if "evtx" not in art_types and "event_log" not in art_types:
            self.record.evidence_gaps.append(
                EvidenceGap(
                    missing_artifact_type="evtx",
                    tactical_reason="Windows Security & System event logs unavailable for logon and process auditing",
                    recommended_collection="Collect C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
                    is_evidence_of_absence=False,
                )
            )

        if "memory" not in art_types:
            self.record.evidence_gaps.append(
                EvidenceGap(
                    missing_artifact_type="memory",
                    tactical_reason="Volatile RAM memory image unavailable for in-memory code injection analysis",
                    recommended_collection="Acquire live memory dump via WinPmem / LiME",
                    is_evidence_of_absence=False,
                )
            )

        step_idx = 1
        for a in artifacts:
            a_type = (a.type or "").lower()
            # Tier A userspace analyzers
            if a_type in ("evtx", "event_log") and "dissect_evtx" in self.available_capabilities:
                planned_actions.append(
                    InvestigationAction(
                        action_id=f"act-dissect-evtx-{step_idx}",
                        step_index=step_idx,
                        action_type="tier_a_parser",
                        capability_id="dissect_evtx",
                        artifact_id=a.artifact_id,
                        justification=f"Parse {a.original_path or a.artifact_id} for authentication and process anomalies",
                        status="pending",
                    )
                )
                step_idx += 1
            elif a_type in ("registry", "reg") and "dissect_registry" in self.available_capabilities:
                planned_actions.append(
                    InvestigationAction(
                        action_id=f"act-dissect-reg-{step_idx}",
                        step_index=step_idx,
                        action_type="tier_a_parser",
                        capability_id="dissect_registry",
                        artifact_id=a.artifact_id,
                        justification=f"Parse Registry hive {a.original_path or a.artifact_id} for persistence keys",
                        status="pending",
                    )
                )
                step_idx += 1
            elif a_type in ("raw_disk_stream", "raw", "img", "dd") and "dissect_disk_stream" in self.available_capabilities:
                planned_actions.append(
                    InvestigationAction(
                        action_id=f"act-dissect-disk-{step_idx}",
                        step_index=step_idx,
                        action_type="tier_a_parser",
                        capability_id="dissect_disk_stream",
                        artifact_id=a.artifact_id,
                        justification=f"Parse partition table from raw disk stream {a.artifact_id}",
                        status="pending",
                    )
                )
                step_idx += 1

            # Tier B declarative tools
            if a_type in ("evtx", "event_log") and "ez_evtxecmd" in self.available_capabilities:
                planned_actions.append(
                    InvestigationAction(
                        action_id=f"act-ez-evtx-{step_idx}",
                        step_index=step_idx,
                        action_type="tier_b_tool",
                        capability_id="ez_evtxecmd",
                        artifact_id=a.artifact_id,
                        justification="Sandboxed Eric Zimmerman EvtxECmd parsing of security events",
                        status="pending",
                    )
                )
                step_idx += 1
            if a_type in ("evtx", "event_log") and "chainsaw_sigma" in self.available_capabilities:
                planned_actions.append(
                    InvestigationAction(
                        action_id=f"act-chainsaw-{step_idx}",
                        step_index=step_idx,
                        action_type="tier_b_tool",
                        capability_id="chainsaw_sigma",
                        artifact_id=a.artifact_id,
                        justification="Chainsaw Sigma rule matching for known intrusion tradecraft",
                        status="pending",
                    )
                )
                step_idx += 1

            # Linux authentication and text logs
            if a_type in ("linux_log", "auth_log", "syslog", "shell_history") and any(c in self.available_capabilities for c in ("native_log_parser", "linux_auth_logs")):
                planned_actions.append(
                    InvestigationAction(
                        action_id=f"act-linux-log-{step_idx}",
                        step_index=step_idx,
                        action_type="tier_a_parser",
                        capability_id="native_log_parser",
                        artifact_id=a.artifact_id,
                        justification=f"Parse Linux log {a.original_path or a.artifact_id} for authentication and privilege escalation",
                        status="pending",
                    )
                )
                step_idx += 1

            # Network PCAP packet captures
            if a_type in ("pcap", "pcapng", "network") and any(c in self.available_capabilities for c in ("native_pcap_parser", "pcap_flow_analysis")):
                planned_actions.append(
                    InvestigationAction(
                        action_id=f"act-pcap-{step_idx}",
                        step_index=step_idx,
                        action_type="tier_a_parser",
                        capability_id="native_pcap_parser",
                        artifact_id=a.artifact_id,
                        justification=f"Parse packet capture {a.original_path or a.artifact_id} for network flows and C2 beaconing",
                        status="pending",
                    )
                )
                step_idx += 1

            # Executable & malware samples
            if a_type in ("executable", "pe", "binary", "sample", "file") and any(c in self.available_capabilities for c in ("native_static_pe", "static_pe_metadata")):
                planned_actions.append(
                    InvestigationAction(
                        action_id=f"act-static-pe-{step_idx}",
                        step_index=step_idx,
                        action_type="tier_a_parser",
                        capability_id="native_static_pe",
                        artifact_id=a.artifact_id,
                        justification=f"Perform safe static PE and hash analysis on {a.original_path or a.artifact_id}",
                        status="pending",
                    )
                )
                step_idx += 1

            # Memory image pslist
            if a_type in ("memory", "raw_memory", "vmem", "dmp") and any(c in self.available_capabilities for c in ("volatility3_pslist", "memory_process_listing")):
                planned_actions.append(
                    InvestigationAction(
                        action_id=f"act-vol-pslist-{step_idx}",
                        step_index=step_idx,
                        action_type="tier_b_tool",
                        capability_id="volatility3_pslist",
                        artifact_id=a.artifact_id,
                        justification="Sandboxed Volatility 3 process listing from memory image",
                        status="pending",
                    )
                )
                step_idx += 1

        self.record.pending_actions = list(planned_actions)
        self.record.plan.planned_actions = list(planned_actions)
        self.record.plan.evidence_gaps = self.record.evidence_gaps
        self._persist_state()

    # --------------------------------------------------------------------------
    # 3. LLM Tool-Request Contract Validation
    # --------------------------------------------------------------------------
    def validate_tool_request(self, request: ToolRequest) -> InvestigationAction:
        """Validate an autonomous tool request against registries and policies.
        
        Never executes arbitrary shell commands.
        """
        # 1. Strict security rule: reject dynamic malware execution and evidence modification
        if request.capability_id in ("dynamic_sandbox_execution", "dynamic_malware_detonation", "cuckoo_sandbox"):
            raise ExecutionPolicyError(
                "Dynamic malware execution is strictly prohibited under ForensicOps AI safety policy."
            )
        if request.capability_id in ("local_evidence_modification", "modify_evidence", "overwrite_evidence", "write_vault_blob"):
            raise ExecutionPolicyError(
                "Local evidence modification is strictly prohibited under RFC 3227 and ForensicOps AI safety policy."
            )

        # 2. Check specialist registry for capability definition and operational status
        spec_cap = None
        for c in self.specialist_registry.list_all_capabilities():
            if c.capability_id == request.capability_id:
                spec_cap = c
                break

        if spec_cap and not spec_cap.operational:
            lims = "; ".join(spec_cap.limitations) if spec_cap.limitations else "analyzer not implemented"
            raise ExecutionPolicyError(
                f"Requested capability '{request.capability_id}' is currently non-operational ({lims})."
            )

        is_connector = request.capability_id in ("splunk_siem", "elasticsearch_siem")
        is_approval_action = request.capability_id in ("system_containment", "isolate_host")
        analyzer = self.analyzer_registry.get_analyzer(request.capability_id)
        if not analyzer and not spec_cap and not is_connector and not is_approval_action:
            raise ExecutionPolicyError(
                f"Requested tool capability '{request.capability_id}' is not registered in the approved forensic analyzer registry."
            )

        # 3. Check action risk policy
        policy_eval = ActionRiskPolicy.evaluate("tool_request", request.capability_id, request.arguments)
        if not policy_eval.is_allowed:
            raise ExecutionPolicyError(policy_eval.policy_reason)

        if request.capability_id not in self.available_capabilities:
            raise ExecutionPolicyError(
                f"Tool capability '{request.capability_id}' is not authorized for this investigation scope."
            )

        # Artifact validation
        if request.artifact_id:
            if not self.custody_engine:
                raise ForensicOpsError("Custody engine unavailable to verify requested artifact.")
            artifact = self.custody_engine.get_artifact(request.artifact_id)
            if not artifact:
                raise ForensicOpsError(f"Requested artifact '{request.artifact_id}' does not exist in case vault.")
            if self.authorized_evidence_scope and artifact.artifact_id not in self.authorized_evidence_scope and (artifact.type or "").lower() not in self.authorized_evidence_scope:
                raise ExecutionPolicyError(f"Artifact '{request.artifact_id}' is outside the authorized evidence scope.")

        # Require human approval for dangerous / external / remediation operations
        requires_approval = (
            request.requires_approval
            or policy_eval.requires_approval
            or "containment" in request.capability_id
            or "remote" in request.capability_id
            or "remediation" in request.capability_id
            or "external" in request.capability_id
        )

        action_type = "containment" if is_approval_action else ("tier_b_tool" if (analyzer and analyzer.execution_tier == "tier_b_adapter") else ("siem_connector" if is_connector else "tier_a_parser"))

        action = InvestigationAction(
            action_id=f"act-req-{uuid4().hex[:8]}",
            step_index=len(self.record.completed_actions) + len(self.record.pending_actions) + 1,
            action_type=action_type,
            capability_id=request.capability_id,
            artifact_id=request.artifact_id,
            arguments=request.arguments,
            justification=request.justification,
            requires_approval=requires_approval,
            status="pending",
        )
        return action

    def _resolve_action_target(self, action: InvestigationAction) -> str:
        """Resolve the effective target for an action consistently across request and approval."""
        return (
            getattr(action, "target", None)
            or (action.arguments.get("host") if isinstance(action.arguments, dict) else None)
            or (action.arguments.get("target") if isinstance(action.arguments, dict) else None)
            or action.artifact_id
            or self.case_id
        )

    def submit_tool_request(self, request: ToolRequest) -> InvestigationAction:
        """Submit a validated tool request to the pending actions queue."""
        action = self.validate_tool_request(request)
        self.record.pending_actions.append(action)
        self.record.plan.planned_actions.append(action)
        if action.requires_approval and not action.approval_token:
            if not action.approval_id:
                appr_req = self.approval_engine.create_request(
                    case_id=self.case_id,
                    requesting_investigator=self.investigator,
                    requesting_principal_id=self.investigator_id,
                    requesting_badge_id=self.investigator_badge,
                    action_type=action.capability_id,
                    target=self._resolve_action_target(action),
                    capability_id=action.capability_id,
                    parameters=action.arguments,
                    reason=action.justification or f"Execution of '{action.capability_id}' requires explicit human approval.",
                    evidence_scope=self.authorized_evidence_scope,
                )
                action.approval_id = appr_req.approval_id
            self.record.pause_reason = f"Action '{action.action_id}' ({action.capability_id}) requires explicit human approval. Approval ID: {action.approval_id}"
            self.transition_to(InvestigationLifecycleState.AWAITING_APPROVAL)
        elif self.record.lifecycle_state == InvestigationLifecycleState.COMPLETED:
            self.transition_to(InvestigationLifecycleState.EXECUTING)
        self._persist_state()
        return action

    # --------------------------------------------------------------------------
    # 4. Autonomous Investigation Loop Iteration
    # --------------------------------------------------------------------------
    def run_iteration(self) -> InvestigationRecord:
        """Execute one bounded cycle of the autonomous investigation loop."""
        start_t = time.perf_counter()

        if self.record.lifecycle_state in (
            InvestigationLifecycleState.COMPLETED,
            InvestigationLifecycleState.PARTIALLY_COMPLETED,
            InvestigationLifecycleState.FAILED,
            InvestigationLifecycleState.CANCELLED,
            InvestigationLifecycleState.AWAITING_APPROVAL,
        ):
            return self.record

        # Check for budget exhaustion first
        budget_state = self._check_budgets()
        if budget_state:
            self.transition_to(budget_state)
            return self.record

        if self.record.lifecycle_state in (
            InvestigationLifecycleState.CREATED,
            InvestigationLifecycleState.EVIDENCE_VALIDATION,
        ):
            self.initialize()
            if self.record.lifecycle_state in (
                InvestigationLifecycleState.NEEDS_MORE_DATA,
                InvestigationLifecycleState.FAILED,
            ):
                return self.record

        # Check for pending approval actions
        for act in self.record.pending_actions:
            if act.requires_approval and not act.approval_token:
                if not act.approval_id:
                    appr_req = self.approval_engine.create_request(
                        case_id=self.case_id,
                        requesting_investigator=self.investigator,
                        requesting_principal_id=self.investigator_id,
                        requesting_badge_id=self.investigator_badge,
                        action_type=act.capability_id,
                        target=self._resolve_action_target(act),
                        capability_id=act.capability_id,
                        parameters=act.arguments,
                        reason=act.justification or f"Execution of '{act.capability_id}' requires explicit human approval.",
                        evidence_scope=self.authorized_evidence_scope,
                    )
                    act.approval_id = appr_req.approval_id
                self.record.pause_reason = f"Action '{act.action_id}' ({act.capability_id}) requires explicit human approval. Approval ID: {act.approval_id}"
                self.transition_to(InvestigationLifecycleState.AWAITING_APPROVAL)
                return self.record

        # Transition to EXECUTING
        if self.record.lifecycle_state == InvestigationLifecycleState.PLANNING:
            self.transition_to(InvestigationLifecycleState.EXECUTING)
        elif self.record.lifecycle_state == InvestigationLifecycleState.EVALUATING:
            self.transition_to(InvestigationLifecycleState.EXECUTING)

        step_traces: List[Dict[str, Any]] = []
        executed_queries: List[str] = []
        cited_fids: List[str] = []
        executed_this_turn: List[InvestigationAction] = []

        # Execute safe actions
        budget_halted = False
        while self.record.pending_actions:
            # Check budgets before each execution
            if len(self.record.execution_ids) >= self.budget.max_tool_executions:
                budget_halted = True
                break

            action = self.record.pending_actions.pop(0)

            # Check approval gate
            if action.requires_approval and not action.approval_token:
                if not action.approval_id:
                    appr_req = self.approval_engine.create_request(
                        case_id=self.case_id,
                        requesting_investigator=self.investigator,
                        requesting_principal_id=self.investigator_id,
                        requesting_badge_id=self.investigator_badge,
                        action_type=action.capability_id,
                        target=self._resolve_action_target(action),
                        capability_id=action.capability_id,
                        parameters=action.arguments,
                        reason=action.justification or f"Execution of '{action.capability_id}' requires explicit human approval.",
                        evidence_scope=self.authorized_evidence_scope,
                    )
                    action.approval_id = appr_req.approval_id
                self.record.pending_actions.insert(0, action)
                self.record.pause_reason = f"Action '{action.action_id}' ({action.capability_id}) requires explicit human approval. Approval ID: {action.approval_id}"
                self.transition_to(InvestigationLifecycleState.AWAITING_APPROVAL)
                return self.record

            action.status = "executing"
            try:
                exec_res = self._execute_action(action)
            except Exception as ex:
                exec_res = {
                    "success": False,
                    "execution_id": str(uuid4()),
                    "error": str(ex),
                    "findings_count": 0,
                }
            action.status = "completed" if exec_res["success"] else "failed"
            action.execution_id = exec_res.get("execution_id")
            action.findings_count = exec_res.get("findings_count", 0)
            action.raw_output_ref = exec_res.get("raw_output_ref")
            action.error = exec_res.get("error")

            if not exec_res["success"] and action.error:
                self.record.errors.append(
                    f"Action '{action.action_id}' ({action.capability_id}) failed: {action.error}"
                )

            if exec_res.get("execution_id"):
                self.record.execution_ids.append(exec_res["execution_id"])

            self.record.completed_actions.append(action)
            executed_this_turn.append(action)

            step_traces.append({
                "action_id": action.action_id,
                "capability_id": action.capability_id,
                "artifact_id": action.artifact_id,
                "execution_id": action.execution_id,
                "findings_count": action.findings_count,
                "success": exec_res["success"],
            })

            # Check step limit
            if len(executed_this_turn) >= 3:
                break

        # Transition to EVALUATING
        self.transition_to(InvestigationLifecycleState.EVALUATING)

        # 5. Evaluate New Findings & Pivots
        all_findings = self.storage.query_structured_findings(case_id=self.case_id, limit=self.budget.max_findings_per_step)
        self.record.findings_count = len(all_findings)
        cited_fids = [f.finding_id for f in all_findings[:20]]

        # Consult KnowledgeAndMemoryProvider for benign baselines
        benign_entities: Set[str] = set()
        try:
            baselines = _run_coroutine_safely(self.memory_provider.get_benign_baselines(org_id="DefaultOrg", artifact_type="all")) or []
            for b in baselines:
                if b.get("entity_pattern"):
                    benign_entities.add(b["entity_pattern"].lower())
        except Exception:
            pass

        # Update pivots from empirical findings
        extracted_pivots = extract_pivots_from_findings(all_findings)
        for cat, vals in extracted_pivots.items():
            for v in vals:
                # Suppress benign baselines
                if f"user:{v.lower()}" not in benign_entities and f"process:{v.lower()}" not in benign_entities:
                    self.record.pivots.add_pivot(cat, v)

        # 6. Correlate findings across timeline and sources
        corr_spec = self.specialist_registry.get_specialist("timeline_correlation")
        if corr_spec and all_findings:
            corr_rels = corr_spec.correlate_findings(findings=all_findings, case_id=self.case_id)
            self.record.correlations = [c.model_dump() for c in corr_rels]
            self.record.plan.correlations = self.record.correlations

        # 7. Test Competing Hypotheses against empirical findings
        self._evaluate_hypotheses(all_findings, benign_entities)

        # Conclude iteration
        self.record.current_iteration += 1
        duration = time.perf_counter() - start_t

        trace = InvestigationStepTrace(
            investigation_id=self.record.investigation_id,
            case_id=self.case_id,
            iteration=self.record.current_iteration,
            step_name=f"iteration_{self.record.current_iteration}",
            inputs={
                "objective": self.objective,
                "authorized_scope": self.authorized_evidence_scope,
                "pivots": self.record.pivots.pivots,
            },
            outputs={
                "lifecycle_state": self.record.lifecycle_state.value,
                "findings_count": self.record.findings_count,
                "executed_actions_count": len(executed_this_turn),
            },
            executed_queries=executed_queries,
            cited_finding_ids=cited_fids,
            tool_executions=step_traces,
            status="completed",
            duration_seconds=duration,
        )
        self.state_store.save_investigation_trace(trace)

        if budget_halted or self.record.current_iteration >= self.budget.max_iterations:
            self.transition_to(InvestigationLifecycleState.PARTIALLY_COMPLETED)
            self._persist_state()
            return self.record

        # Check if follow-up actions should be planned for unanalyzed artifacts matching pivots or scope
        if not self.record.pending_actions and not budget_halted:
            if (
                self.custody_engine
                and (self.record.current_iteration < self.budget.max_iterations)
                and (len(self.record.execution_ids) < self.budget.max_tool_executions)
            ):
                all_arts = self.custody_engine.get_artifacts(case_id=self.case_id)
                if self.authorized_evidence_scope:
                    all_arts = [
                        a for a in all_arts
                        if a.artifact_id in self.authorized_evidence_scope or (a.type and a.type.lower() in self.authorized_evidence_scope)
                    ]
                analyzed_art_ids = {a.artifact_id for a in self.record.completed_actions if a.artifact_id}
                unanalyzed = [a for a in all_arts if a.artifact_id not in analyzed_art_ids]
                if unanalyzed:
                    new_actions = self._plan_follow_up_actions(unanalyzed, self.record.pivots.pivots)
                    if new_actions:
                        self.record.pending_actions.extend(new_actions)
                        self.record.plan.planned_actions.extend(new_actions)

        # Check convergence or conclusion
        if not self.record.pending_actions:
            # All planned actions executed
            if not any(a.status == "completed" for a in self.record.completed_actions) and self.record.errors:
                self.transition_to(InvestigationLifecycleState.FAILED)
            else:
                h_malicious = next((h for h in self.record.hypotheses if not h.is_benign_null), None)
                if h_malicious and h_malicious.status == "supported":
                    self.transition_to(InvestigationLifecycleState.COMPLETED)
                elif any(g.missing_artifact_type != "none" for g in self.record.evidence_gaps):
                    self.transition_to(InvestigationLifecycleState.NEEDS_MORE_DATA)
                else:
                    self.transition_to(InvestigationLifecycleState.COMPLETED)

        self._persist_state()
        return self.record

    def _plan_follow_up_actions(
        self,
        unanalyzed_artifacts: List[ArtifactRecord],
        pivots: Dict[str, List[str]],
    ) -> List[InvestigationAction]:
        """Plan targeted follow-up actions for unanalyzed artifacts matching pivots or scope."""
        follow_ups: List[InvestigationAction] = []
        step_base = len(self.record.completed_actions) + len(self.record.pending_actions) + 1

        for idx, art in enumerate(unanalyzed_artifacts):
            a_type = (art.type or "").lower()
            orig_name = (art.original_path or "").lower()

            relevance_reasons: List[str] = []
            if "processes" in pivots or "process" in pivots:
                relevance_reasons.append("correlating process pivots")
            if "users" in pivots or "user" in pivots:
                relevance_reasons.append("tracing user accounts")
            if "ips" in pivots or "network" in pivots:
                relevance_reasons.append("investigating network communication")

            justification_suffix = f" (Pivot follow-up: {', '.join(relevance_reasons)})" if relevance_reasons else ""

            cap_id: Optional[str] = None
            action_type = "tier_a_parser"
            if a_type in ("registry", "hive", "reg") or orig_name.endswith((".hiv", ".dat", ".hive")):
                if "dissect_registry" in self.available_capabilities:
                    cap_id = "dissect_registry"
            elif a_type in ("evtx", "event_log") or orig_name.endswith(".evtx"):
                if "dissect_evtx" in self.available_capabilities:
                    cap_id = "dissect_evtx"
            elif a_type in ("raw_disk_stream", "raw", "img", "dd") or orig_name.endswith((".raw", ".dd", ".img")):
                if "dissect_disk_stream" in self.available_capabilities:
                    cap_id = "dissect_disk_stream"
            elif a_type in ("triage", "triage_directory", "directory") or Path(art.original_path or "").is_dir():
                if "dissect_triage" in self.available_capabilities:
                    cap_id = "dissect_triage"
            elif a_type in ("pcap", "pcapng", "network") or orig_name.endswith((".pcap", ".pcapng")):
                if "native_pcap_parser" in self.available_capabilities:
                    cap_id = "native_pcap_parser"
            elif a_type in ("linux_log", "auth_log", "syslog") or "auth" in orig_name:
                if "native_log_parser" in self.available_capabilities:
                    cap_id = "native_log_parser"
            elif a_type in ("executable", "pe", "binary", "sample") or orig_name.endswith((".exe", ".dll")):
                if "native_static_pe" in self.available_capabilities:
                    cap_id = "native_static_pe"

            if cap_id:
                follow_ups.append(
                    InvestigationAction(
                        action_id=f"act-followup-{step_base + idx}",
                        step_index=step_base + idx,
                        action_type=action_type,
                        capability_id=cap_id,
                        artifact_id=art.artifact_id,
                        justification=f"Follow-up analysis on {art.original_path or art.artifact_id}{justification_suffix}",
                        status="pending",
                    )
                )

        return follow_ups

    def _execute_action(self, action: InvestigationAction) -> Dict[str, Any]:
        """Execute a single investigation action safely and return execution details."""
        execution_id = str(uuid4())
        if not self.custody_engine:
            return {"success": False, "execution_id": execution_id, "error": "CustodyEngine not available."}

        artifact: Optional[ArtifactRecord] = None
        if action.artifact_id:
            artifact = self.custody_engine.get_artifact(action.artifact_id)
            if not artifact:
                return {"success": False, "execution_id": execution_id, "error": f"Artifact '{action.artifact_id}' missing."}

        # Tier A Built-in Userspace Parser
        if action.action_type == "tier_a_parser":
            if not artifact:
                return {"success": False, "execution_id": execution_id, "error": "No artifact specified for Tier A parser."}
            rpath = self.custody_engine.resolve_artifact_file(artifact)
            if not rpath.exists():
                return {"success": False, "execution_id": execution_id, "error": f"Artifact file missing: {rpath}"}

            a_type = (artifact.type or "").lower()
            findings: List[ForensicFinding] = []
            try:
                if action.capability_id in ("dissect_evtx", "windows_event_logs") or a_type in ("evtx", "event_log"):
                    findings = self.dissect_adapter.parse_evtx_stream(rpath, self.case_id, artifact.artifact_id, artifact.sha256)
                elif action.capability_id in ("dissect_registry", "windows_registry") or a_type in ("registry", "reg"):
                    findings = self.dissect_adapter.parse_registry_hive_stream(rpath, self.case_id, artifact.artifact_id, artifact.sha256)
                elif action.capability_id == "dissect_disk_stream" or a_type in ("raw_disk_stream", "raw", "img", "dd"):
                    findings = self.dissect_adapter.parse_disk_image_stream(rpath, self.case_id, artifact.artifact_id, artifact.sha256)
                elif action.capability_id in ("dissect_triage", "triage_directory", "endpoint_triage") or a_type in ("triage", "triage_directory") or rpath.is_dir():
                    findings = self.dissect_adapter.parse_triage_directory(rpath, self.case_id, artifact.artifact_id, artifact.sha256)
                elif action.capability_id in ("native_log_parser", "linux_auth_logs", "linux_ssh_activity", "linux_sudo_privilege", "linux_cron_persistence") or a_type in ("linux_log", "auth_log", "syslog", "shell_history"):
                    spec = self.specialist_registry.get_specialist("linux_dfir")
                    if spec:
                        res = spec.execute(self.case_id, [artifact], self.storage, self.custody_engine)
                        findings = res.findings
                elif action.capability_id in ("native_pcap_parser", "pcap_flow_analysis", "beaconing_detection", "suspicious_destination_detection") or a_type in ("pcap", "pcapng", "network"):
                    spec = self.specialist_registry.get_specialist("network_forensics")
                    if spec:
                        res = spec.execute(self.case_id, [artifact], self.storage, self.custody_engine)
                        findings = res.findings
                elif action.capability_id in ("native_static_pe", "static_file_hashes", "static_file_metadata", "static_pe_metadata", "static_strings_extraction") or a_type in ("executable", "pe", "binary", "sample", "file"):
                    spec = self.specialist_registry.get_specialist("malware_analysis")
                    if spec:
                        res = spec.execute(self.case_id, [artifact], self.storage, self.custody_engine)
                        findings = res.findings

                if findings:
                    self.storage.insert_findings(findings)

                return {
                    "success": True,
                    "execution_id": execution_id,
                    "findings_count": len(findings),
                    "raw_output_ref": str(rpath),
                }
            except Exception as e:
                return {"success": False, "execution_id": execution_id, "error": str(e)}

        # Tier B Declarative Sandboxed Tool
        elif action.action_type == "tier_b_tool":
            plugins_dir = Path(os.environ.get("FORENSICOPS_PLUGINS_DIR", "plugins")).resolve()
            card_path = plugins_dir / f"{action.capability_id}.yaml"
            if not card_path.is_file():
                return {"success": False, "execution_id": execution_id, "error": f"Plugin card not found: {card_path}"}

            card = ToolPluginCard.from_yaml_file(card_path)
            runner = self.plugin_runner or PluginRunner(custody_engine=self.custody_engine)
            workspace = self.custody_engine.vault_root / self.case_id
            workspace.mkdir(parents=True, exist_ok=True)

            if not artifact:
                # Find matching artifact in custody
                all_arts = self.custody_engine.get_artifacts(case_id=self.case_id)
                for a in all_arts:
                    if (a.type or "").lower() in card.supported_artifact_types:
                        artifact = a
                        break

            if not artifact:
                return {"success": False, "execution_id": execution_id, "error": "No matching artifact in case vault for tool."}

            try:
                res = runner.run_plugin(plugin=card, artifact=artifact, output_workspace=workspace)
                if res.findings:
                    self.storage.insert_findings(res.findings)
                return {
                    "success": res.success,
                    "execution_id": execution_id,
                    "findings_count": res.findings_count,
                    "raw_output_ref": res.raw_output_path,
                    "error": res.errors[0] if res.errors else None,
                }
            except Exception as e:
                return {"success": False, "execution_id": execution_id, "error": str(e)}

        elif action.action_type in ("containment", "system_containment") or action.capability_id in ("system_containment", "isolate_host"):
            target_ref = (action.arguments or {}).get("host") or "target_host"
            return {
                "success": True,
                "execution_id": execution_id,
                "findings_count": 0,
                "raw_output_ref": f"containment://{target_ref}",
            }

        elif action.action_type in ("siem_connector", "connector") or action.capability_id in ("splunk_siem", "elasticsearch_siem"):
            target_ref = (action.arguments or {}).get("host") or (action.arguments or {}).get("url") or "remote_target"
            return {
                "success": True,
                "execution_id": execution_id,
                "findings_count": 0,
                "raw_output_ref": f"remote://{target_ref}",
            }

        return {"success": False, "execution_id": execution_id, "error": f"Unknown action type '{action.action_type}'."}

    # --------------------------------------------------------------------------
    # 5. Competing Hypotheses Evaluation
    # --------------------------------------------------------------------------
    def _evaluate_hypotheses(self, findings: List[ForensicFinding], benign_baselines: Set[str]) -> None:
        """Evaluate competing hypotheses against empirical findings."""
        if not self.record.hypotheses:
            return

        suspicious_findings: List[ForensicFinding] = []
        benign_findings: List[ForensicFinding] = []

        for f in findings:
            is_benign = False
            if f.user and f"user:{f.user.lower()}" in benign_baselines:
                is_benign = True
            if f.process_name and f"process:{f.process_name.lower()}" in benign_baselines:
                is_benign = True

            if is_benign:
                benign_findings.append(f)
            elif f.severity in ("high", "critical"):
                suspicious_findings.append(f)
            elif f.category in ("PrivilegeEscalation", "Persistence", "CredentialDumping", "LateralMovement"):
                suspicious_findings.append(f)
            else:
                benign_findings.append(f)

        for h in self.record.hypotheses:
            if not h.is_benign_null:
                # Intrusion hypothesis
                h.supporting_finding_ids = [f.finding_id for f in suspicious_findings]
                h.contradicting_finding_ids = [f.finding_id for f in benign_findings if f.severity == "low"]
                total = len(h.supporting_finding_ids) + len(h.contradicting_finding_ids)
                if total > 0:
                    h.confidence = round(len(h.supporting_finding_ids) / total, 2)
                else:
                    h.confidence = 0.5
                h.status = "supported" if len(suspicious_findings) > 0 else "untested"
            else:
                # Benign null hypothesis
                h.supporting_finding_ids = [f.finding_id for f in benign_findings]
                h.contradicting_finding_ids = [f.finding_id for f in suspicious_findings]
                total = len(h.supporting_finding_ids) + len(h.contradicting_finding_ids)
                if total > 0:
                    h.confidence = round(len(h.supporting_finding_ids) / total, 2)
                else:
                    h.confidence = 0.5
                h.status = "supported" if len(suspicious_findings) == 0 and len(benign_findings) > 0 else "refuted" if len(suspicious_findings) > 0 else "untested"

            h.version += 1

    # --------------------------------------------------------------------------
    # 6. Autonomous Loop Runner to Completion
    # --------------------------------------------------------------------------
    def run_to_completion(self) -> InvestigationRecord:
        """Run the autonomous investigation loop until terminal state or approval pause."""
        while self.record.lifecycle_state not in (
            InvestigationLifecycleState.COMPLETED,
            InvestigationLifecycleState.PARTIALLY_COMPLETED,
            InvestigationLifecycleState.FAILED,
            InvestigationLifecycleState.CANCELLED,
            InvestigationLifecycleState.AWAITING_APPROVAL,
            InvestigationLifecycleState.NEEDS_MORE_DATA,
        ):
            self.run_iteration()
        return self.record

    # --------------------------------------------------------------------------
    # 7. Persistence Recovery & Human Approval Resume
    # --------------------------------------------------------------------------
    def approve_action(self, action_id: str, token: HumanApprovalToken) -> InvestigationRecord:
        """Approve a paused action using a valid HumanApprovalToken."""
        # Find action
        target_action = None
        for a in self.record.pending_actions:
            if a.action_id == action_id or token.node_id == action_id or token.node_id == a.capability_id:
                target_action = a
                break

        if not target_action:
            raise ForensicOpsError(f"Action '{action_id}' not found in pending actions.")

        target = self._resolve_action_target(target_action)
        try:
            self.approval_engine.verify_and_consume_token(
                token=token,
                expected_case_id=self.case_id,
                expected_action_type=token.action_type or target_action.capability_id,
                expected_target=target,
                expected_parameters=target_action.arguments if token.parameter_digest else None,
                consumed_by=f"investigation_controller:{self.investigator}",
            )
        except UnauthorizedCollectorExecutionError as ue:
            raise ForensicOpsError(f"Approval verification failed: Invalid or forged HumanApprovalToken: {ue}") from ue
        except Exception as e:
            raise ForensicOpsError(f"Invalid or forged HumanApprovalToken: {e}") from e

        target_action.approval_token = token
        target_action.status = "approved"

        if self.record.lifecycle_state == InvestigationLifecycleState.AWAITING_APPROVAL:
            self.record.pause_reason = None
            self.transition_to(InvestigationLifecycleState.EXECUTING)

        self._persist_state()
        return self.record

    def resume(self, approval_token: Optional[HumanApprovalToken] = None) -> InvestigationRecord:
        """Resume an interrupted or paused investigation."""
        # Reload state from store to ensure latest state
        latest = self.state_store.get_investigation_state(self.record.investigation_id)
        if latest:
            self.record = self._hydrate_record(latest)

        if self.record.lifecycle_state == InvestigationLifecycleState.AWAITING_APPROVAL:
            if not approval_token:
                raise ForensicOpsError("Cannot resume investigation awaiting approval without a valid HumanApprovalToken.")
            # Approve first awaiting action
            for a in self.record.pending_actions:
                if a.requires_approval and not a.approval_token:
                    self.approve_action(a.action_id, approval_token)
                    break

        return self.run_to_completion()

    def cancel(self, reason: str = "User cancelled investigation") -> InvestigationRecord:
        """Cancel an in-progress investigation."""
        self.record.errors.append(f"Cancelled: {reason}")
        self.transition_to(InvestigationLifecycleState.CANCELLED)
        return self.record

    def compile_report(self, strict_citations: bool = True) -> Any:
        """Compile verified findings and hypotheses into a formal CitedReport using CitationGuard."""
        all_findings = self.storage.query_structured_findings(case_id=self.case_id, limit=200)

        # Build node results from completed actions and evaluated hypotheses
        claims: List[CitedClaim] = []
        for f in all_findings:
            claims.append(
                CitedClaim(
                    claim_type="observed_fact",
                    statement=f"Observed forensic artifact on host {f.host or 'unknown'}: {f.summary}",
                    citing_finding_ids=[f.finding_id],
                    source_artifact_hashes=[f.source_artifact_hash],
                    confidence=1.0,
                    verification_status="VERIFIED",
                )
            )

        # Include correlations
        for c_dict in getattr(self.record, "correlations", []):
            fids = c_dict.get("correlated_finding_ids") or (
                list(c_dict.get("source_finding_ids", [])) + list(c_dict.get("target_finding_ids", []))
            )
            fids = list(dict.fromkeys(fids))
            if len(fids) >= 2:
                hashes = list({f.source_artifact_hash for f in all_findings if f.finding_id in fids})
                claims.append(
                    CitedClaim(
                        claim_type="derived_correlation",
                        statement=c_dict.get("description", "Correlated activity detected across multiple findings"),
                        citing_finding_ids=fids,
                        source_artifact_hashes=hashes or ([all_findings[0].source_artifact_hash] if all_findings else []),
                        confidence=0.9,
                        verification_status="VERIFIED",
                    )
                )

        # Include hypotheses as hypothesis claims
        for h in self.record.hypotheses:
            if h.status == "supported":
                supp_hashes = [f.source_artifact_hash for f in all_findings if f.finding_id in h.supporting_finding_ids][:5]
                stmt = getattr(h, "statement", None) or getattr(h, "description", None) or getattr(h, "title", "Hypothesis")
                claims.append(
                    CitedClaim(
                        claim_type="hypothesis",
                        statement=stmt,
                        citing_finding_ids=h.supporting_finding_ids[:5],
                        source_artifact_hashes=supp_hashes,
                        confidence=h.confidence,
                        verification_status="UNVERIFIED",
                        requires_analyst_review=True,
                    )
                )

        # Format pivots as Dict[str, List[str]] for NodeGoalResult schema
        extracted_pivots_dict: Dict[str, List[str]] = {}
        if hasattr(self.record, "pivots"):
            raw_piv = getattr(self.record.pivots, "pivots", None)
            if isinstance(raw_piv, dict):
                for k, v in raw_piv.items():
                    if isinstance(v, (list, tuple, set)):
                        extracted_pivots_dict[k] = [str(item) for item in v]
                    elif v is not None:
                        extracted_pivots_dict[k] = [str(v)]

        node_status = "completed" if (self.record.lifecycle_state == InvestigationLifecycleState.COMPLETED and not self.record.errors) else "partial"
        if not claims and not all_findings:
            node_status = "failed" if self.record.errors else "partial"

        node_result = NodeGoalResult(
            node_id=f"controller_{self.record.investigation_id[:8]}",
            status=node_status,
            summary=f"Autonomous investigation summary for case '{self.case_id}': {self.objective}",
            claims=claims,
            extracted_pivots=extracted_pivots_dict,
            confidence_score=0.9 if all_findings else 0.0,
        )

        guard = CitationGuard(storage=self.storage, custody_engine=self.custody_engine)
        val_report = guard.validate_node_result(
            node_result,
            case_id=self.case_id,
            strict=False,
            downgrade_ungrounded=True,
        )
        sanitized_res = val_report.sanitized_result or node_result

        from backend.app.agent.report_builder import ReportBuilder
        return ReportBuilder.build_report(
            case_id=self.case_id,
            node_results=[sanitized_res],
            storage=self.storage,
            custody_engine=self.custody_engine,
            strict_citations=strict_citations,
            creator=f"InvestigationController:{self.investigator}",
        )
