"""Human Feedback & v2.0 Learning Loop API Endpoints.

Standards:
- v2.0 RAG & Episodic Memory Protocol
- Micro-Controls: Confirm True Positive, Mark Benign Baseline, Correct Query
- Organizational Baseline Suppression & Few-Shot Learning
"""
from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from backend.app.api.deps import get_memory_provider, get_storage
from backend.app.auth.dependencies import get_current_user, require_roles
from backend.app.auth.case_authorization import get_case_authorization_service
from backend.app.auth.models import UserRead
from backend.app.models.feedback import FeedbackScope, FeedbackType, HumanFeedbackRecord

router = APIRouter(prefix="/api/feedback", tags=["Human Feedback & Learning"])


class FeedbackSubmissionRequest(BaseModel):
    case_id: Optional[str] = "default_case"
    finding_id: Optional[str] = None
    feedback_type: str = "true_positive"  # Supports aliases: confirm_tp, mark_benign_baseline, correct_query
    analyst_note: Optional[str] = None
    entity_pattern: Optional[str] = None
    scope: FeedbackScope = "organization_baseline"
    org_id: Optional[str] = "default_org"
    artifact_type: Optional[str] = None
    corrected_query: Optional[str] = None


class FeedbackSubmissionResponse(BaseModel):
    status: str = "recorded"
    feedback_id: str
    record: HumanFeedbackRecord


def _normalize_feedback_type(raw_type: str) -> FeedbackType:
    cleaned = raw_type.lower().strip()
    if cleaned in ("true_positive", "confirm_tp", "tp", "confirm"):
        return "true_positive"
    elif cleaned in (
        "false_positive_benign_baseline",
        "mark_benign_baseline",
        "benign",
        "baseline",
        "fp",
    ):
        return "false_positive_benign_baseline"
    elif cleaned in ("query_correction", "correct_query", "correction", "fix_query"):
        return "query_correction"
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid feedback_type '{raw_type}'. Supported: 'true_positive', 'false_positive_benign_baseline', 'query_correction'.",
        )


@router.post("", response_model=FeedbackSubmissionResponse)
async def submit_feedback(
    req: FeedbackSubmissionRequest,
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst")),
) -> FeedbackSubmissionResponse:
    """Submit human feedback (confirm TP, mark benign org baseline, or correct query) for continuous learning.

    Restricted to Lead Investigators and SOC Analysts. Automatically bound to the investigator's badge ID and role.
    """
    if req.case_id:
        case_auth = get_case_authorization_service()
        from backend.app.db.sqlite_store import get_llm_state_store
        sqlite_store = get_llm_state_store()
        if sqlite_store.get_case(req.case_id):
            case_auth.verify_case_access(current_user, req.case_id, "write")
        else:
            case_auth.ensure_case_registered(req.case_id, current_user.username)

    memory = get_memory_provider()
    storage = get_storage(req.case_id or "default_case")

    normalized_type = _normalize_feedback_type(req.feedback_type)

    # If finding_id is provided, auto-enrich entity pattern or artifact type if not set
    entity_pattern = req.entity_pattern
    artifact_type = req.artifact_type
    if req.finding_id:
        fnd = storage.get_finding(req.finding_id, case_id=req.case_id)
        if fnd:
            if not artifact_type:
                artifact_type = fnd.artifact_type
            if not entity_pattern:
                if fnd.user:
                    entity_pattern = f"user:{fnd.user}"
                elif fnd.process_name:
                    entity_pattern = f"process:{fnd.process_name}"
                elif fnd.host:
                    entity_pattern = f"host:{fnd.host}"

    record = HumanFeedbackRecord(
        case_id=req.case_id,
        finding_id=req.finding_id,
        feedback_type=normalized_type,
        analyst_note=req.analyst_note,
        entity_pattern=entity_pattern,
        scope=req.scope,
        org_id=req.org_id,
        artifact_type=artifact_type,
        corrected_query=req.corrected_query,
        badge_id=current_user.badge_id,
        analyst_role=current_user.role,
        analyst_username=current_user.username,
    )

    await memory.record_human_feedback(record)

    return FeedbackSubmissionResponse(
        status="recorded",
        feedback_id=record.feedback_id,
        record=record,
    )


@router.get("/baselines", response_model=List[Dict[str, Any]])
async def get_benign_baselines(
    org_id: str = "default_org",
    artifact_type: Optional[str] = None,
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst", "auditor")),
) -> List[Dict[str, Any]]:
    """Query established false-positive benign baselines for an organization."""
    memory = get_memory_provider()
    baselines = await memory.get_benign_baselines(org_id=org_id, artifact_type=artifact_type)
    return baselines
