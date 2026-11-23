"""Investigation Session State Persistence API Endpoints.

Standards:
- Local-first SQLite persistence for wizard and workflow state (AGENTS.md)
- Enables tab switching, browser refresh, and cross-session resume without state loss
- Automatic synchronization with the top-level InvestigationContext
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from backend.app.auth.dependencies import require_roles
from backend.app.auth.case_authorization import get_case_authorization_service
from backend.app.auth.models import UserRead
from backend.app.db.sqlite_store import get_llm_state_store

router = APIRouter(prefix="/api/session", tags=["Investigation Session"])


class InvestigationSessionSaveRequest(BaseModel):
    wizard_state: Dict[str, Any] = Field(default_factory=dict)
    workflow_state: Dict[str, Any] = Field(default_factory=dict)
    active_tab: str = "wizard"


class InvestigationSessionResponse(BaseModel):
    case_id: str
    wizard_state: Dict[str, Any] = Field(default_factory=dict)
    workflow_state: Dict[str, Any] = Field(default_factory=dict)
    active_tab: str = "wizard"
    updated_at_utc: str


@router.get("", response_model=List[InvestigationSessionResponse])
@router.get("/", response_model=List[InvestigationSessionResponse])
def list_sessions(
    limit: int = 50,
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst", "auditor")),
) -> List[InvestigationSessionResponse]:
    """List all persisted investigation sessions in SQLite authorized for current user."""
    store = get_llm_state_store()
    case_auth = get_case_authorization_service()
    raw_sessions = store.list_investigation_sessions(limit=limit)
    authorized = []
    for s in raw_sessions:
        cid = s.get("case_id")
        case = store.get_case(cid)
        if case:
            if case_auth.is_user_authorized(current_user, case, "read"):
                authorized.append(InvestigationSessionResponse(**s))
        else:
            if current_user.role in ("lead_investigator", "soc_analyst", "external_auditor", "auditor"):
                authorized.append(InvestigationSessionResponse(**s))
    return authorized


@router.get("/{case_id}", response_model=InvestigationSessionResponse)
def get_session(
    case_id: str,
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst", "auditor")),
) -> InvestigationSessionResponse:
    """Retrieve the persisted wizard and workflow session for a case.

    If not found, returns an initialized default session structure.
    """
    store = get_llm_state_store()
    case = store.get_case(case_id)
    if case:
        case_auth = get_case_authorization_service()
        case_auth.verify_case_access(current_user, case_id, "read")

    session = store.get_investigation_session(case_id)
    if not session:
        return InvestigationSessionResponse(
            case_id=case_id,
            wizard_state={
                "mode": "offline",
                "offline_path": "C:\\evidence\\triage_case01.zip",
                "artifact_type": "evtx",
                "is_zero_copy": False,
            },
            workflow_state={
                "selected_blueprint_key": "windows_intrusion",
                "completed_nodes": [],
            },
            active_tab="wizard",
            updated_at_utc="",
        )
    return InvestigationSessionResponse(**session)


@router.post("/{case_id}", response_model=InvestigationSessionResponse)
def save_session(
    case_id: str,
    req: InvestigationSessionSaveRequest,
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst")),
) -> InvestigationSessionResponse:
    """Persist wizard and workflow state into the SQLite session store."""
    store = get_llm_state_store()
    case_auth = get_case_authorization_service()
    if store.get_case(case_id):
        case_auth.verify_case_access(current_user, case_id, "write")
    else:
        case_auth.ensure_case_registered(case_id, current_user.username)

    clean_wizard_state = {
        k: v for k, v in req.wizard_state.items()
        if str(k).lower().replace("_", "").replace("-", "") not in {
            "siemapikey", "apikey", "password", "passwd", "token", "secret", "credentials"
        }
    }

    saved = store.save_investigation_session(
        case_id=case_id,
        wizard_state=clean_wizard_state,
        workflow_state=req.workflow_state,
        active_tab=req.active_tab,
    )
    return InvestigationSessionResponse(**saved)


@router.delete("/{case_id}")
def delete_session(
    case_id: str,
    current_user: UserRead = Depends(require_roles("lead_investigator")),
) -> Dict[str, Any]:
    """Delete an investigation session from SQLite."""
    store = get_llm_state_store()
    case = store.get_case(case_id)
    if case:
        case_auth = get_case_authorization_service()
        case_auth.verify_case_access(current_user, case_id, "delete")
    deleted = store.delete_investigation_session(case_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No session found for case_id '{case_id}'",
        )
    return {"status": "deleted", "case_id": case_id}
