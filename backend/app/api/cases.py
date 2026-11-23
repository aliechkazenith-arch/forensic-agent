"""Forensic Case Management and Peer Review Case Vault Endpoints.

Standards:
- Local-first SQLite store for case records and investigation state.
- Lifecycle tracking: OPEN -> IN_REVIEW -> COMPLETED.
- Forensic Case Vault sharing for peer review (is_shared_to_vault).
- RBAC authorization via optional current user binding.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query, status

from backend.app.auth.case_authorization import get_case_authorization_service
from backend.app.auth.dependencies import require_roles
from backend.app.auth.models import UserRead
from backend.app.db.sqlite_store import get_llm_state_store
from backend.app.models.cases import (
    CaseCreatePayload,
    CaseReadDTO,
    CaseShareResponse,
    CaseStatus,
    CaseUpdatePayload,
)

router = APIRouter(prefix="/api/cases", tags=["Case Management"])


@router.get("", response_model=List[CaseReadDTO])
def list_cases_endpoint(
    search: Optional[str] = Query(None, description="Search term for case ID, name, org, or goal"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status (OPEN, IN_REVIEW, COMPLETED)"),
    limit: int = Query(50, ge=1, le=200),
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst", "external_auditor")),
) -> List[CaseReadDTO]:
    """List forensic cases with optional search and status filtering, restricted to authorized cases."""
    store = get_llm_state_store()
    raw = store.list_cases(search=search, status=status_filter, vault_only=False, limit=limit)
    case_auth = get_case_authorization_service()
    authorized_cases = [c for c in raw if case_auth.is_user_authorized(current_user, c, action="read")]
    return [CaseReadDTO(**c) for c in authorized_cases]


@router.get("/vault/shared", response_model=List[CaseReadDTO])
def list_vault_cases_endpoint(
    limit: int = Query(50, ge=1, le=200),
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst", "external_auditor")),
) -> List[CaseReadDTO]:
    """Retrieve all cases shared to the Forensic Case Vault for peer review."""
    store = get_llm_state_store()
    raw = store.list_cases(vault_only=True, limit=limit)
    return [CaseReadDTO(**c) for c in raw]


@router.get("/{case_id}", response_model=CaseReadDTO)
def get_case_endpoint(
    case_id: str,
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst", "external_auditor")),
) -> CaseReadDTO:
    """Retrieve detailed metadata and serialized state for a specific case with access verification."""
    case_auth = get_case_authorization_service()
    case = case_auth.verify_case_access(current_user, case_id, action="read")
    return CaseReadDTO(**case)


@router.post("", response_model=CaseReadDTO, status_code=status.HTTP_201_CREATED)
def create_or_update_case_endpoint(
    payload: CaseCreatePayload,
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst")),
) -> CaseReadDTO:
    """Create or update a case in the SQLite case registry."""
    store = get_llm_state_store()
    case_auth = get_case_authorization_service()
    existing = store.get_case(payload.case_id)
    if existing:
        case_auth.verify_case_access(current_user, payload.case_id, action="write")

    analyst = payload.lead_analyst or (current_user.username if current_user else "analyst_lead")
    data = payload.model_dump()
    data["lead_analyst"] = analyst

    created = store.create_or_update_case(data)
    return CaseReadDTO(**created)


@router.patch("/{case_id}", response_model=CaseReadDTO)
def update_case_endpoint(
    case_id: str,
    payload: CaseUpdatePayload,
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst")),
) -> CaseReadDTO:
    """Update fields on an existing case."""
    store = get_llm_state_store()
    case_auth = get_case_authorization_service()
    existing = case_auth.verify_case_access(current_user, case_id, action="write")

    updates = payload.model_dump(exclude_unset=True)
    merged = {**existing, **updates, "case_id": case_id}
    updated = store.create_or_update_case(merged)
    return CaseReadDTO(**updated)


@router.post("/{case_id}/share", response_model=CaseShareResponse)
def toggle_case_vault_share_endpoint(
    case_id: str,
    payload: Dict[str, Any],
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst")),
) -> CaseShareResponse:
    """Toggle sharing a case into the Forensic Case Vault for peer review."""
    store = get_llm_state_store()
    case_auth = get_case_authorization_service()
    existing = case_auth.verify_case_access(current_user, case_id, action="share")

    is_shared = bool(payload.get("is_shared_to_vault", not existing["is_shared_to_vault"]))
    ok = store.toggle_case_vault_share(case_id, is_shared)
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update vault sharing status for case '{case_id}'.",
        )

    return CaseShareResponse(
        status="success",
        case_id=case_id,
        is_shared_to_vault=is_shared,
        updated_at_utc=datetime.now(timezone.utc).isoformat(),
    )


@router.delete("/{case_id}", status_code=status.HTTP_200_OK)
def delete_case_endpoint(
    case_id: str,
    current_user: UserRead = Depends(require_roles("lead_investigator")),
) -> Dict[str, Any]:
    """Delete a case from SQLite."""
    store = get_llm_state_store()
    case_auth = get_case_authorization_service()
    case_auth.verify_case_access(current_user, case_id, action="delete")

    deleted = store.delete_case(case_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found.",
        )
    return {"status": "success", "message": f"Case '{case_id}' removed from registry."}
