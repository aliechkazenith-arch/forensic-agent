"""Autonomous Investigation Controller REST API Endpoints.

Standards:
- Explicit Investigation Lifecycle State Machine (AGENTS.md / Phase 06).
- Controlled Autonomy & Operation-Specific Approval Gate Integration (Phase 08).
- Specialist Capabilities & Evidence Gap Visibility (Phase 07).
- Full Audit Logging & State Persistence in SQLite and DuckDB.
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from backend.app.agent.investigation_controller import InvestigationController
from backend.app.api.deps import (
    get_case_authorization_service,
    get_custody_engine,
    get_storage,
)
from backend.app.auth.dependencies import require_roles
from backend.app.auth.models import UserRead
from backend.app.core.specialist_registry import get_default_specialist_registry
from backend.app.db.sqlite_store import get_llm_state_store
from backend.app.models.investigation import (
    InvestigationBudget,
    InvestigationLifecycleState,
    InvestigationRecord,
)
from backend.app.models.workflow import HumanApprovalToken

router = APIRouter(prefix="/api/investigations", tags=["Autonomous Investigations"])

# In-memory controller registry per case_id for active sessions
_active_controllers: Dict[str, InvestigationController] = {}


def _get_or_create_controller(
    case_id: str,
    investigator: str = "analyst",
    investigator_id: Optional[str] = None,
    investigator_badge: Optional[str] = None,
    objective: str = "Perform comprehensive forensic compromise assessment",
    budget: Optional[InvestigationBudget] = None,
) -> InvestigationController:
    """Retrieve or initialize the active InvestigationController for a case."""
    if case_id in _active_controllers:
        return _active_controllers[case_id]

    custody = get_custody_engine(case_id)
    storage = get_storage(case_id)

    controller = InvestigationController(
        case_id=case_id,
        investigator=investigator,
        investigator_id=investigator_id,
        investigator_badge=investigator_badge,
        objective=objective,
        custody_engine=custody,
        storage=storage,
        budget=budget,
    )
    _active_controllers[case_id] = controller
    return controller


class StartInvestigationRequest(BaseModel):
    case_id: str
    objective: str = "Perform comprehensive forensic compromise assessment"
    budget: Optional[InvestigationBudget] = None
    autorun: bool = False


class ResumeInvestigationRequest(BaseModel):
    approval_token: Optional[HumanApprovalToken] = None
    autorun: bool = False


class CancelInvestigationRequest(BaseModel):
    reason: str = "Investigator cancelled autonomous investigation"


@router.post("/start", response_model=InvestigationRecord)
def start_investigation(
    req: StartInvestigationRequest,
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst")),
) -> InvestigationRecord:
    """Initialize and start an autonomous investigation for an authorized case."""
    case_auth = get_case_authorization_service()
    sqlite_store = get_llm_state_store()

    if sqlite_store.get_case(req.case_id):
        case_auth.verify_case_access(current_user, req.case_id, action="execute")
    else:
        case_auth.ensure_case_registered(req.case_id, current_user.username)

    controller = _get_or_create_controller(
        case_id=req.case_id,
        investigator=current_user.username,
        investigator_id=current_user.id,
        investigator_badge=current_user.badge_id,
        objective=req.objective,
        budget=req.budget,
    )

    # Initialize investigation lifecycle state machine
    record = controller.initialize()

    if req.autorun:
        record = controller.run_to_completion()
    elif record.lifecycle_state not in (
        InvestigationLifecycleState.NEEDS_MORE_DATA,
        InvestigationLifecycleState.AWAITING_APPROVAL,
        InvestigationLifecycleState.COMPLETED,
        InvestigationLifecycleState.PARTIALLY_COMPLETED,
        InvestigationLifecycleState.CANCELLED,
        InvestigationLifecycleState.FAILED,
    ):
        # Run first iteration
        record = controller.run_iteration()

    return record


@router.get("/{case_id}", response_model=InvestigationRecord)
def get_investigation_status(
    case_id: str,
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst", "auditor")),
) -> InvestigationRecord:
    """Retrieve current autonomous investigation state, hypotheses, evidence gaps, and step traces."""
    case_auth = get_case_authorization_service()
    case_auth.verify_case_access(current_user, case_id, action="read")

    if case_id in _active_controllers:
        return _active_controllers[case_id].record

    # Retrieve from persistent SQLite state
    store = get_llm_state_store()
    raw = store.get_investigation(case_id)
    if not raw:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No active or persisted investigation found for case '{case_id}'.",
        )

    # Reconstruct controller and record
    controller = _get_or_create_controller(case_id=case_id)
    return controller.record


@router.post("/{case_id}/iterate", response_model=InvestigationRecord)
def iterate_investigation(
    case_id: str,
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst")),
) -> InvestigationRecord:
    """Execute a single outer reasoning-and-action loop of the autonomous controller."""
    case_auth = get_case_authorization_service()
    case_auth.verify_case_access(current_user, case_id, action="execute")

    controller = _get_or_create_controller(case_id=case_id)
    if controller.record.lifecycle_state in (
        InvestigationLifecycleState.NEEDS_MORE_DATA,
        InvestigationLifecycleState.AWAITING_APPROVAL,
        InvestigationLifecycleState.COMPLETED,
        InvestigationLifecycleState.PARTIALLY_COMPLETED,
        InvestigationLifecycleState.CANCELLED,
        InvestigationLifecycleState.FAILED,
    ):
        return controller.record
    record = controller.run_iteration()
    return record


@router.post("/{case_id}/resume", response_model=InvestigationRecord)
def resume_investigation(
    case_id: str,
    req: ResumeInvestigationRequest,
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst")),
) -> InvestigationRecord:
    """Resume an autonomous investigation paused in awaiting_approval after human authorization."""
    case_auth = get_case_authorization_service()
    case_auth.verify_case_access(current_user, case_id, action="execute")

    controller = _get_or_create_controller(case_id=case_id)
    record = controller.resume(approval_token=req.approval_token)

    if req.autorun and record.lifecycle_state not in (
        InvestigationLifecycleState.COMPLETED,
        InvestigationLifecycleState.PARTIALLY_COMPLETED,
        InvestigationLifecycleState.CANCELLED,
        InvestigationLifecycleState.FAILED,
        InvestigationLifecycleState.AWAITING_APPROVAL,
    ):
        record = controller.run_to_completion()

    return record


@router.post("/{case_id}/cancel", response_model=InvestigationRecord)
def cancel_investigation(
    case_id: str,
    req: CancelInvestigationRequest,
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst")),
) -> InvestigationRecord:
    """Cancel an active autonomous investigation."""
    case_auth = get_case_authorization_service()
    case_auth.verify_case_access(current_user, case_id, action="execute")

    controller = _get_or_create_controller(case_id=case_id)
    record = controller.cancel(reason=req.reason)
    return record


@router.get("/{case_id}/specialists", response_model=List[Dict[str, Any]])
def list_active_specialists(
    case_id: str,
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst", "auditor")),
) -> List[Dict[str, Any]]:
    """List registered DFIR specialist capabilities, objectives, and tool allowlists."""
    case_auth = get_case_authorization_service()
    case_auth.verify_case_access(current_user, case_id, action="read")

    registry = get_default_specialist_registry()
    specialists = []
    for spec in registry.list_specialists():
        specialists.append({
            "specialist_id": spec.specialist_id,
            "name": spec.name,
            "domain": spec.domain,
            "objective_definition": getattr(spec, "objective_definition", getattr(spec, "description", "")),
            "required_artifact_types": getattr(spec, "required_artifact_types", getattr(spec, "supported_artifact_types", [])),
            "allowlisted_capabilities": getattr(spec, "allowlisted_capabilities", getattr(spec, "tool_allowlist", [])),
            "investigation_questions": spec.investigation_questions,
            "limitations": spec.limitations,
        })
    return specialists


@router.get("/{case_id}/tool-history", response_model=List[Dict[str, Any]])
def get_tool_execution_history(
    case_id: str,
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst", "auditor")),
) -> List[Dict[str, Any]]:
    """Retrieve full audit history of executed forensic tools, artifact inputs, and finding counts."""
    case_auth = get_case_authorization_service()
    case_auth.verify_case_access(current_user, case_id, action="read")

    controller = _get_or_create_controller(case_id=case_id)
    history = []
    for action in controller.record.completed_actions:
        history.append({
            "action_id": action.action_id,
            "step_index": action.step_index,
            "capability_id": action.capability_id,
            "artifact_id": action.artifact_id,
            "justification": action.justification,
            "status": action.status,
            "findings_count": action.findings_count,
            "raw_output_ref": action.raw_output_ref,
            "retries": action.retries,
            "arguments": action.arguments,
            "error": action.error,
        })
    return history


@router.get("/{case_id}/timeline", response_model=List[Dict[str, Any]])
def get_investigation_timeline(
    case_id: str,
    limit: int = Query(default=200, ge=1, le=2000),
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst", "auditor")),
) -> List[Dict[str, Any]]:
    """Retrieve chronological timeline constructed from findings and tool execution traces."""
    case_auth = get_case_authorization_service()
    case_auth.verify_case_access(current_user, case_id, action="read")

    timeline: List[Dict[str, Any]] = []

    # 1. Findings from ForensicStore
    storage = get_storage(case_id)
    findings = storage.query_structured_findings(
        case_id=case_id,
        limit=limit,
        order_by="timestamp_utc",
        ascending=True,
    )
    for f in findings:
        timeline.append({
            "timestamp_utc": f.timestamp_utc,
            "event_type": "finding",
            "event_id": f.finding_id,
            "title": getattr(f, "title", getattr(f, "summary", "")),
            "artifact_id": getattr(f, "source_artifact_id", getattr(f, "artifact_id", None)),
            "artifact_hash": getattr(f, "source_artifact_hash", getattr(f, "artifact_hash", None)),
            "category": f.category.value if hasattr(f.category, "value") else str(f.category),
            "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
            "details": getattr(f, "projected_data", None) or getattr(f, "details", {}),
        })

    # 2. Tool executions from controller completed actions
    controller = _get_or_create_controller(case_id=case_id)
    for action in controller.record.completed_actions:
        ts = getattr(action, "timestamp_utc", None) or controller.record.updated_at_utc
        timeline.append({
            "timestamp_utc": ts,
            "event_type": "tool_execution",
            "event_id": action.action_id,
            "title": f"Tool Execution: {action.capability_id}",
            "artifact_id": action.artifact_id,
            "artifact_hash": None,
            "category": "investigation_action",
            "severity": "INFO",
            "details": {
                "capability_id": action.capability_id,
                "status": action.status,
                "findings_count": action.findings_count,
                "justification": action.justification,
            },
        })

    timeline.sort(key=lambda x: str(x.get("timestamp_utc", "")))
    return timeline[:limit]


@router.get("/{case_id}/hypotheses", response_model=List[Dict[str, Any]])
def get_investigation_hypotheses(
    case_id: str,
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst", "auditor")),
) -> List[Dict[str, Any]]:
    """Retrieve active competing hypotheses with status and confidence."""
    case_auth = get_case_authorization_service()
    case_auth.verify_case_access(current_user, case_id, action="read")

    controller = _get_or_create_controller(case_id=case_id)
    return [h.model_dump() for h in controller.record.hypotheses]


@router.get("/{case_id}/findings", response_model=List[Dict[str, Any]])
def get_investigation_findings(
    case_id: str,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst", "auditor")),
) -> List[Dict[str, Any]]:
    """Retrieve structured findings discovered for the case."""
    case_auth = get_case_authorization_service()
    case_auth.verify_case_access(current_user, case_id, action="read")

    storage = get_storage(case_id)
    findings = storage.query_structured_findings(
        case_id=case_id,
        limit=limit,
        offset=offset,
        order_by="timestamp_utc",
        ascending=True,
    )
    return [f.model_dump() for f in findings]

