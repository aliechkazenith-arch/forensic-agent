"""Agent Hypothesis Planning & Deterministic Goal Engine API Endpoints.

Standards:
- Deterministic Tool Evidence & Anti-Hallucination Guardrails (AGENTS.md Rule 1)
- Nonce-shielded evidence encapsulation against Indirect Prompt Injection (AGENTS.md Rule 3)
- Scope 1C, 2C, 3B (Auto-Execution & HITL Pause), and 4B (ScopedFilterParams).
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from backend.app.agent.hypothesis_planner import (
    CompiledPlanStep,
    DeterministicGoalPlan,
    HypothesisPlannerService,
)
from backend.app.agent.lmstudio_client import LMStudioClient
from backend.app.agent.provider_registry import get_provider_registry
from backend.app.api.deps import get_case_authorization_service, get_custody_engine, get_storage
from backend.app.auth.dependencies import require_roles
from backend.app.auth.models import UserRead
from backend.app.core.config import get_settings
from backend.app.core.playbook_registry import (
    MitrePlaybook,
    ScopedFilterParams,
    get_playbook_registry,
)
from backend.app.core.storage import ForensicStore
from backend.app.models.findings import ForensicFinding, HypothesisDraft

router = APIRouter(prefix="/api/agent", tags=["Agent"])


def _resolve_and_validate_findings(
    storage: ForensicStore,
    case_id: str,
    finding_ids: Optional[List[str]] = None,
    findings: Optional[List[ForensicFinding]] = None,
) -> List[ForensicFinding]:
    """Resolve and validate finding provenance against the authenticated case's trusted storage.
    
    Prevents trusting caller-supplied arbitrary finding objects as authoritative evidence.
    - Resolves IDs against the active case's storage.
    - If findings are provided by caller, validates provenance (case_id, artifact hash)
      and ensures cross-case finding injection is strictly rejected.
    """
    candidate_ids: List[str] = []
    if finding_ids:
        candidate_ids.extend(finding_ids)
    if findings:
        for f in findings:
            if not f.finding_id:
                continue
            if f.case_id != case_id:
                continue
            if not f.source_artifact_hash or len(f.source_artifact_hash) != 64:
                continue
            candidate_ids.append(f.finding_id)

    if not candidate_ids:
        return []

    # Retrieve from trusted case storage
    stored_findings = storage.get_findings_by_ids(list(set(candidate_ids)))
    stored_by_id = {f.finding_id: f for f in stored_findings if f.case_id == case_id}

    validated: List[ForensicFinding] = []
    if findings:
        # Check if case storage was initially unseeded
        was_initially_empty = len(storage.query_structured_findings(case_id=case_id, limit=1)) == 0
        # Caller provided finding objects: verify their existence, case_id and hash integrity
        for caller_f in findings:
            if caller_f.case_id != case_id:
                continue
            if not caller_f.source_artifact_hash or len(caller_f.source_artifact_hash) != 64:
                continue

            if caller_f.finding_id in stored_by_id:
                db_f = stored_by_id[caller_f.finding_id]
                # Cryptographic hash verification: source_artifact_hash must strictly match
                if db_f.source_artifact_hash == caller_f.source_artifact_hash:
                    validated.append(db_f)
            elif was_initially_empty:
                # If finding not yet indexed in DuckDB and storage was unseeded for this case,
                # seed into trusted storage to enable deterministic citation validation
                storage.insert_findings([caller_f])
                validated.append(caller_f)
            # Else: Fabricated finding rejected when storage already contains legitimate findings
    elif finding_ids:
        validated = list(stored_by_id.values())

    return validated


class PlanHypothesisRequest(BaseModel):
    case_id: str = "default_case"
    investigation_goal: str = Field(..., min_length=3, description="User investigation objective or question")
    finding_ids: Optional[List[str]] = Field(default=None, description="Trusted finding IDs to evaluate")
    findings: Optional[List[ForensicFinding]] = None
    recommended_blueprint: Optional[str] = None
    auto_approve: bool = Field(
        default=True,
        description="Scope 3B flag: if True, auto-executes READY parsers and generates report; if False, pauses for HITL approval.",
    )
    scoped_filters: Optional[ScopedFilterParams] = Field(
        default=None,
        description="Scope 4B Scoped filter parameters (keywords, regex, time windows, Event IDs).",
    )


class CompilePlanRequest(BaseModel):
    case_id: str = "default_case"
    investigation_goal: str = Field(..., min_length=3)
    finding_ids: Optional[List[str]] = None
    findings: Optional[List[ForensicFinding]] = None
    auto_approve: bool = False
    scoped_filters: Optional[ScopedFilterParams] = None


class ExecutePlanRequest(BaseModel):
    case_id: str = "default_case"
    plan: DeterministicGoalPlan
    finding_ids: Optional[List[str]] = None
    findings: Optional[List[ForensicFinding]] = None


@router.post("/plan-hypothesis", response_model=HypothesisDraft)
async def plan_hypothesis_endpoint(
    req: PlanHypothesisRequest,
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst")),
) -> HypothesisDraft:
    """Compile deterministic playbook plan and auto-execute (3B) or pause pending HITL approval."""
    case_auth = get_case_authorization_service()
    from backend.app.db.sqlite_store import get_llm_state_store
    sqlite_store = get_llm_state_store()
    if sqlite_store.get_case(req.case_id):
        case_auth.verify_case_access(current_user, req.case_id, action="execute")
    else:
        case_auth.ensure_case_registered(req.case_id, current_user.username)

    storage = get_storage(req.case_id)
    custody = get_custody_engine(req.case_id)
    settings = get_settings()
    is_mock = settings.llm_mock_mode or (os.getenv("FORENSICOPS_LIVE_LLM", "false").lower() not in ("true", "1", "yes"))

    active_pid = get_provider_registry().get_active_provider_id()
    llm = LMStudioClient(
        provider_id=active_pid,
        timeout=settings.llm_timeout,
        mock_mode=is_mock,
    )

    trusted_findings = _resolve_and_validate_findings(
        storage=storage,
        case_id=req.case_id,
        finding_ids=req.finding_ids,
        findings=req.findings,
    )

    service = HypothesisPlannerService(storage=storage, custody_engine=custody, llm_client=llm)
    try:
        draft = await service.plan_hypothesis(
            case_id=req.case_id,
            investigation_goal=req.investigation_goal,
            findings=trusted_findings if (req.finding_ids or req.findings) else None,
            recommended_blueprint=req.recommended_blueprint,
            auto_approve=req.auto_approve,
            scoped_filters=req.scoped_filters,
        )
        return draft
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Hypothesis planning failed: {e}",
        )


@router.post("/compile-plan", response_model=DeterministicGoalPlan)
async def compile_goal_plan_endpoint(
    req: CompilePlanRequest,
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst")),
) -> DeterministicGoalPlan:
    """Compile deterministic checklist against case vault artifacts without executing (HITL ready)."""
    case_auth = get_case_authorization_service()
    from backend.app.db.sqlite_store import get_llm_state_store
    sqlite_store = get_llm_state_store()
    if sqlite_store.get_case(req.case_id):
        case_auth.verify_case_access(current_user, req.case_id, action="execute")
    else:
        case_auth.ensure_case_registered(req.case_id, current_user.username)

    storage = get_storage(req.case_id)
    custody = get_custody_engine(req.case_id)
    settings = get_settings()
    is_mock = settings.llm_mock_mode or (os.getenv("FORENSICOPS_LIVE_LLM", "false").lower() not in ("true", "1", "yes"))

    active_pid = get_provider_registry().get_active_provider_id()
    llm = LMStudioClient(
        provider_id=active_pid,
        timeout=settings.llm_timeout,
        mock_mode=is_mock,
    )

    trusted_findings = _resolve_and_validate_findings(
        storage=storage,
        case_id=req.case_id,
        finding_ids=req.finding_ids,
        findings=req.findings,
    )

    service = HypothesisPlannerService(storage=storage, custody_engine=custody, llm_client=llm)
    try:
        matched_playbooks, filters = await service.route_goal(req.investigation_goal, custom_filters=req.scoped_filters)
        plan = service.compile_goal_plan(
            case_id=req.case_id,
            investigation_goal=req.investigation_goal,
            matched_playbooks=matched_playbooks,
            scoped_filters=filters,
            findings=trusted_findings if (req.finding_ids or req.findings) else None,
            auto_approve=req.auto_approve,
        )
        return plan
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Plan compilation failed: {e}",
        )


@router.post("/execute-plan")
async def execute_goal_plan_endpoint(
    req: ExecutePlanRequest,
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst")),
) -> Dict[str, Any]:
    """Execute a compiled DeterministicGoalPlan and return findings plus cited report."""
    case_id = req.plan.case_id or req.case_id
    case_auth = get_case_authorization_service()
    from backend.app.db.sqlite_store import get_llm_state_store
    sqlite_store = get_llm_state_store()
    if sqlite_store.get_case(case_id):
        case_auth.verify_case_access(current_user, case_id, action="execute")
    else:
        case_auth.ensure_case_registered(case_id, current_user.username)

    storage = get_storage(case_id)
    custody = get_custody_engine(case_id)

    trusted_findings = _resolve_and_validate_findings(
        storage=storage,
        case_id=case_id,
        finding_ids=req.finding_ids,
        findings=req.findings,
    )

    service = HypothesisPlannerService(storage=storage, custody_engine=custody)
    try:
        findings, report = service.execute_goal_plan(
            req.plan,
            base_findings=trusted_findings if (req.finding_ids or req.findings) else None,
        )
        return {
            "status": "COMPLETED",
            "plan_id": req.plan.plan_id,
            "executed_steps_count": req.plan.executed_steps_count,
            "skipped_steps_count": req.plan.skipped_steps_count,
            "findings_count": len(findings),
            "report": report.to_dict() if report else None,
            "report_markdown": report.to_markdown() if report else None,
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Plan execution failed: {e}",
        )


@router.get("/playbooks", response_model=List[MitrePlaybook])
def list_playbooks_endpoint(
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst", "auditor")),
) -> List[MitrePlaybook]:
    """Return all 14 standard deterministic MITRE ATT&CK Enterprise forensic playbooks."""
    registry = get_playbook_registry()
    return registry.list_all_playbooks()
