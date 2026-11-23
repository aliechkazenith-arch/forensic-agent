"""Human Approval & Action Authorization API Endpoints.

Standards:
- Operation-Specific Human Approval Gate (AGENTS.md Rule 7, RFC 3227, ISO/IEC 27037).
- Mandatory Authentication & Case-Level Access Verification.
- Agent Self-Approval Prevention: The agent or requesting investigator cannot approve its own action.
- Replay Protection & One-Time Token Consumption.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel

from backend.app.api.deps import (
    get_approval_engine,
    get_case_authorization_service,
)
from backend.app.auth.dependencies import get_current_user, require_roles
from backend.app.auth.models import UserRead
from backend.app.core.approval_engine import ApprovalEngine
from backend.app.core.exceptions import ForensicOpsError
from backend.app.models.approval import (
    ApprovalRequest,
    ApprovalStatus,
    CreateApprovalRequestBody,
    ResolveApprovalBody,
)
from backend.app.models.workflow import HumanApprovalToken

router = APIRouter(prefix="/api/approvals", tags=["Approvals"])


class ApprovalResponse(BaseModel):
    request: ApprovalRequest
    token: Optional[HumanApprovalToken] = None


@router.post("/requests", response_model=ApprovalRequest, status_code=status.HTTP_201_CREATED)
def create_approval_request(
    body: CreateApprovalRequestBody,
    current_user: UserRead = Depends(get_current_user),
    engine: ApprovalEngine = Depends(get_approval_engine),
    case_auth: Any = Depends(get_case_authorization_service),
) -> ApprovalRequest:
    """Create an operation-specific approval request for a sensitive forensic action."""
    case_auth.verify_case_access(current_user, body.case_id, action="write")

    try:
        req = engine.create_request(
            case_id=body.case_id,
            requesting_investigator=current_user.username,
            requesting_principal_id=current_user.id,
            requesting_badge_id=current_user.badge_id,
            action_type=body.action_type,
            target=body.target,
            capability_id=body.capability_id,
            parameters=body.parameters,
            reason=body.reason,
            evidence_scope=body.evidence_scope,
            expiration_seconds=body.expiration_seconds,
        )
        return req
    except ForensicOpsError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create approval request: {e}",
        )


@router.get("", response_model=List[ApprovalRequest])
def list_approval_requests(
    case_id: Optional[str] = Query(None, description="Filter by case ID"),
    status_filter: Optional[ApprovalStatus] = Query(None, alias="status", description="Filter by status"),
    current_user: UserRead = Depends(get_current_user),
    engine: ApprovalEngine = Depends(get_approval_engine),
    case_auth: Any = Depends(get_case_authorization_service),
) -> List[ApprovalRequest]:
    """List approval requests matching optional case ID or status."""
    if case_id:
        case_auth.verify_case_access(current_user, case_id, action="read")

    requests = engine.list_requests(case_id=case_id, status=status_filter)
    return requests


@router.get("/{approval_id}", response_model=ApprovalRequest)
def get_approval_request(
    approval_id: str,
    case_id: Optional[str] = Query("default_case"),
    current_user: UserRead = Depends(get_current_user),
    engine: ApprovalEngine = Depends(get_approval_engine),
    case_auth: Any = Depends(get_case_authorization_service),
) -> ApprovalRequest:
    """Retrieve full details of an operation-specific approval request."""
    req = engine.get_request(approval_id)
    if not req:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Approval request '{approval_id}' not found.")

    case_auth.verify_case_access(current_user, req.case_id, action="read")
    return req


@router.post("/{approval_id}/approve", response_model=ApprovalResponse)
def approve_request(
    approval_id: str,
    body: Optional[ResolveApprovalBody] = None,
    case_id: Optional[str] = Query("default_case"),
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst")),
    engine: ApprovalEngine = Depends(get_approval_engine),
    case_auth: Any = Depends(get_case_authorization_service),
) -> ApprovalResponse:
    """Approve a sensitive forensic action and issue a cryptographically signed HumanApprovalToken."""
    req = engine.get_request(approval_id)
    if not req:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Approval request '{approval_id}' not found.")

    case_auth.verify_case_access(current_user, req.case_id, action="write")

    exp_sec = body.expiration_seconds if body else 900
    try:
        updated_req, token = engine.approve_request(
            approval_id=approval_id,
            approver=current_user,
            expiration_seconds=exp_sec,
            reason=body.reason if body else None,
        )
        return ApprovalResponse(request=updated_req, token=token)
    except ForensicOpsError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to approve request: {e}",
        )


@router.post("/{approval_id}/reject", response_model=ApprovalRequest)
def reject_request(
    approval_id: str,
    body: Optional[ResolveApprovalBody] = None,
    case_id: Optional[str] = Query("default_case"),
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst")),
    engine: ApprovalEngine = Depends(get_approval_engine),
    case_auth: Any = Depends(get_case_authorization_service),
) -> ApprovalRequest:
    """Reject an approval request with mandatory audit recording."""
    req = engine.get_request(approval_id)
    if not req:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Approval request '{approval_id}' not found.")

    case_auth.verify_case_access(current_user, req.case_id, action="write")

    reason = body.reason if body and body.reason else "Investigator rejected action."
    try:
        updated_req = engine.reject_request(
            approval_id=approval_id,
            approver=current_user,
            reason=reason,
        )
        return updated_req
    except ForensicOpsError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to reject request: {e}",
        )


@router.post("/{approval_id}/revoke", response_model=ApprovalRequest)
def revoke_request(
    approval_id: str,
    body: Optional[ResolveApprovalBody] = None,
    case_id: Optional[str] = Query("default_case"),
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst")),
    engine: ApprovalEngine = Depends(get_approval_engine),
    case_auth: Any = Depends(get_case_authorization_service),
) -> ApprovalRequest:
    """Revoke a previously approved action before it is consumed."""
    req = engine.get_request(approval_id)
    if not req:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Approval request '{approval_id}' not found.")

    case_auth.verify_case_access(current_user, req.case_id, action="write")

    reason = body.reason if body and body.reason else "Investigator revoked approval."
    try:
        updated_req = engine.revoke_request(
            approval_id=approval_id,
            actor=current_user,
            reason=reason,
        )
        return updated_req
    except ForensicOpsError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to revoke request: {e}",
        )
