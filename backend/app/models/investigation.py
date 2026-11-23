"""Pydantic v2 Models for Autonomous Investigation Controller Lifecycle & State Machine.

Standards:
- Explicit Investigation State Machine (NIST SP 800-86, RFC 3227, AGENTS.md).
- Finite, bounded execution budgets (iterations, tool count, timeouts, context).
- Competing hypotheses generation and evidence gap tracking.
- Typed LLM tool-request contracts with strict allowlist validation.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Literal, Optional, Set
from uuid import uuid4
from pydantic import BaseModel, ConfigDict, Field

from backend.app.core.exceptions import ForensicOpsError
from backend.app.models.workflow import HumanApprovalToken, WorkflowEdgePayload


class InvalidStateTransitionError(ForensicOpsError):
    """Raised when an invalid lifecycle state transition is attempted."""
    pass


class BudgetExhaustionError(ForensicOpsError):
    """Raised when an investigation budget is fully exhausted."""
    pass


class InvestigationLifecycleState(str, Enum):
    """Explicit lifecycle states for an autonomous forensic investigation."""
    CREATED = "created"
    EVIDENCE_VALIDATION = "evidence_validation"
    PLANNING = "planning"
    EXECUTING = "executing"
    EVALUATING = "evaluating"
    AWAITING_APPROVAL = "awaiting_approval"
    NEEDS_MORE_DATA = "needs_more_data"
    COMPLETED = "completed"
    PARTIALLY_COMPLETED = "partially_completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


VALID_TRANSITIONS: Dict[InvestigationLifecycleState, Set[InvestigationLifecycleState]] = {
    InvestigationLifecycleState.CREATED: {
        InvestigationLifecycleState.EVIDENCE_VALIDATION,
        InvestigationLifecycleState.CANCELLED,
    },
    InvestigationLifecycleState.EVIDENCE_VALIDATION: {
        InvestigationLifecycleState.PLANNING,
        InvestigationLifecycleState.NEEDS_MORE_DATA,
        InvestigationLifecycleState.FAILED,
        InvestigationLifecycleState.CANCELLED,
    },
    InvestigationLifecycleState.PLANNING: {
        InvestigationLifecycleState.EXECUTING,
        InvestigationLifecycleState.AWAITING_APPROVAL,
        InvestigationLifecycleState.NEEDS_MORE_DATA,
        InvestigationLifecycleState.COMPLETED,
        InvestigationLifecycleState.PARTIALLY_COMPLETED,
        InvestigationLifecycleState.FAILED,
        InvestigationLifecycleState.CANCELLED,
    },
    InvestigationLifecycleState.EXECUTING: {
        InvestigationLifecycleState.EVALUATING,
        InvestigationLifecycleState.AWAITING_APPROVAL,
        InvestigationLifecycleState.PARTIALLY_COMPLETED,
        InvestigationLifecycleState.FAILED,
        InvestigationLifecycleState.CANCELLED,
    },
    InvestigationLifecycleState.EVALUATING: {
        InvestigationLifecycleState.PLANNING,
        InvestigationLifecycleState.EXECUTING,
        InvestigationLifecycleState.AWAITING_APPROVAL,
        InvestigationLifecycleState.NEEDS_MORE_DATA,
        InvestigationLifecycleState.COMPLETED,
        InvestigationLifecycleState.PARTIALLY_COMPLETED,
        InvestigationLifecycleState.FAILED,
        InvestigationLifecycleState.CANCELLED,
    },
    InvestigationLifecycleState.AWAITING_APPROVAL: {
        InvestigationLifecycleState.EXECUTING,
        InvestigationLifecycleState.PLANNING,
        InvestigationLifecycleState.CANCELLED,
    },
    InvestigationLifecycleState.NEEDS_MORE_DATA: {
        InvestigationLifecycleState.EVIDENCE_VALIDATION,
        InvestigationLifecycleState.PLANNING,
        InvestigationLifecycleState.COMPLETED,
        InvestigationLifecycleState.PARTIALLY_COMPLETED,
        InvestigationLifecycleState.CANCELLED,
    },
    InvestigationLifecycleState.COMPLETED: set(),
    InvestigationLifecycleState.PARTIALLY_COMPLETED: {
        InvestigationLifecycleState.PLANNING,
        InvestigationLifecycleState.CANCELLED,
    },
    InvestigationLifecycleState.FAILED: set(),
    InvestigationLifecycleState.CANCELLED: set(),
}


def validate_lifecycle_transition(
    current: InvestigationLifecycleState,
    target: InvestigationLifecycleState,
) -> None:
    """Validate that moving from `current` to `target` state is legal in the state machine."""
    allowed = VALID_TRANSITIONS.get(current, set())
    if target not in allowed:
        raise InvalidStateTransitionError(
            f"Illegal state transition from '{current.value}' to '{target.value}'. "
            f"Allowed target states: {[s.value for s in allowed]}"
        )


class InvestigationBudget(BaseModel):
    """Configurable resource and iteration boundaries for autonomous investigations."""
    model_config = ConfigDict(extra="ignore")

    max_iterations: int = Field(default=5, ge=1, le=50, description="Max outer reasoning/action loops")
    max_tool_executions: int = Field(default=10, ge=1, le=100, description="Max cumulative tool invocations")
    per_tool_timeout_seconds: int = Field(default=300, ge=5, le=3600, description="Per-tool execution timeout")
    max_total_execution_seconds: float = Field(default=1800.0, ge=10.0, description="Overall investigation deadline")
    max_findings_per_step: int = Field(default=500, ge=1, le=5000, description="Findings limit per tool run")
    max_context_tokens: int = Field(default=8192, ge=1024, le=131072, description="Max prompt/context tokens")
    max_retries_per_step: int = Field(default=2, ge=0, le=5, description="Allowed retry attempts per failed action")


class ToolRequest(BaseModel):
    """Typed tool request contract emitted by LLM or autonomous planner."""
    model_config = ConfigDict(extra="ignore")

    capability_id: str
    artifact_id: Optional[str] = None
    arguments: Dict[str, Any] = Field(default_factory=dict)
    justification: str = ""
    requires_approval: bool = False


class InvestigationAction(BaseModel):
    """An individual forensic tool or query action within an investigation iteration."""
    model_config = ConfigDict(extra="ignore")

    action_id: str = Field(default_factory=lambda: f"act-{uuid4().hex[:10]}")
    step_index: int = 0
    action_type: Literal["tier_a_parser", "tier_b_tool", "store_query", "pivot_search", "containment"] = "tier_b_tool"
    capability_id: str
    artifact_id: Optional[str] = None
    arguments: Dict[str, Any] = Field(default_factory=dict)
    justification: str = ""
    requires_approval: bool = False
    approval_id: Optional[str] = None
    approval_token: Optional[HumanApprovalToken] = None
    status: Literal["pending", "approved", "executing", "completed", "failed", "skipped"] = "pending"
    execution_id: Optional[str] = None
    findings_count: int = 0
    raw_output_ref: Optional[str] = None
    error: Optional[str] = None
    retries: int = 0


class EvidenceGap(BaseModel):
    """Tracks missing forensic evidence vs. investigative objectives."""
    model_config = ConfigDict(extra="ignore")

    gap_id: str = Field(default_factory=lambda: f"gap-{uuid4().hex[:8]}")
    missing_artifact_type: str
    tactical_reason: str
    recommended_collection: str
    is_evidence_of_absence: bool = False  # False = data unavailable; True = examined and no anomaly present


class CompetingHypothesis(BaseModel):
    """Formal competing hypothesis grounded in empirical forensic facts."""
    model_config = ConfigDict(extra="ignore")

    hypothesis_id: str = Field(default_factory=lambda: f"hyp-{uuid4().hex[:8]}")
    title: str
    description: str
    is_benign_null: bool = False  # True = legitimate administrative activity
    supporting_finding_ids: List[str] = Field(default_factory=list)
    contradicting_finding_ids: List[str] = Field(default_factory=list)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    status: Literal["untested", "supported", "refuted", "inconclusive"] = "untested"
    version: int = 1


class InvestigationStepTrace(BaseModel):
    """Trace record capturing full provenance of an investigation step."""
    model_config = ConfigDict(extra="ignore")

    trace_id: str = Field(default_factory=lambda: f"trc-{uuid4().hex[:12]}")
    investigation_id: str
    case_id: str
    iteration: int
    step_name: str
    inputs: Dict[str, Any] = Field(default_factory=dict)
    outputs: Dict[str, Any] = Field(default_factory=dict)
    executed_queries: List[str] = Field(default_factory=list)
    cited_finding_ids: List[str] = Field(default_factory=list)
    tool_executions: List[Dict[str, Any]] = Field(default_factory=list)
    status: str
    duration_seconds: float = 0.0
    created_at_utc: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class InvestigationPlan(BaseModel):
    """Typed investigation plan outlining current objective, hypotheses, and actions."""
    model_config = ConfigDict(extra="ignore")

    plan_id: str = Field(default_factory=lambda: f"plan-{uuid4().hex[:10]}")
    case_id: str
    objective: str
    hypotheses: List[CompetingHypothesis] = Field(default_factory=list)
    planned_actions: List[InvestigationAction] = Field(default_factory=list)
    evidence_gaps: List[EvidenceGap] = Field(default_factory=list)
    correlations: List[Dict[str, Any]] = Field(default_factory=list)
    created_at_utc: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class InvestigationRecord(BaseModel):
    """Persistent, fully-serializable record of an autonomous investigation."""
    model_config = ConfigDict(extra="ignore")

    investigation_id: str = Field(default_factory=lambda: f"inv-{uuid4().hex[:12]}")
    case_id: str
    investigator: str = "analyst"
    lifecycle_state: InvestigationLifecycleState = InvestigationLifecycleState.CREATED
    objective: str
    plan: InvestigationPlan
    current_iteration: int = 0
    budget: InvestigationBudget = Field(default_factory=InvestigationBudget)
    pivots: WorkflowEdgePayload = Field(default_factory=WorkflowEdgePayload)
    authorized_evidence_scope: List[str] = Field(default_factory=list)  # Allowed artifact IDs or empty for all
    available_capabilities: List[str] = Field(default_factory=list)
    hypotheses: List[CompetingHypothesis] = Field(default_factory=list)
    evidence_gaps: List[EvidenceGap] = Field(default_factory=list)
    correlations: List[Dict[str, Any]] = Field(default_factory=list)
    completed_actions: List[InvestigationAction] = Field(default_factory=list)
    pending_actions: List[InvestigationAction] = Field(default_factory=list)
    execution_ids: List[str] = Field(default_factory=list)
    findings_count: int = 0
    errors: List[str] = Field(default_factory=list)
    pause_reason: Optional[str] = None
    started_at_utc: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    created_at_utc: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at_utc: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
