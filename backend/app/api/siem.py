"""SIEM Connection & Credential Management API (SEC-UI-001).

Standards:
- Zero Secret Leakage: API responses NEVER expose passwords, API keys, tokens, or ciphertexts.
- Only boolean presence indicators (has_password, has_api_key, has_token) are returned.
- Server-side encrypted storage using Fernet with fail-closed key management.
- Multi-User RBAC & Case Authorization checks on all connection operations.
- Blank updates preserve existing credentials; deletion requires explicit removal flags.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status

from backend.app.auth.case_authorization import get_case_authorization_service
from backend.app.auth.dependencies import require_roles
from backend.app.auth.models import UserRead
from backend.app.core.credential_store import get_credential_store
from backend.app.core.network_validator import sanitize_credentials
from backend.app.db.sqlite_store import get_llm_state_store
from backend.app.models.connectors import (
    SIEMConnectionCreateRequest,
    SIEMConnectionResponse,
    SIEMConnectionTestResponse,
    SIEMConnectionUpdateRequest,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/siem", tags=["SIEM Management"])


@router.post("/connections", response_model=SIEMConnectionResponse, status_code=status.HTTP_201_CREATED)
def create_siem_connection(
    req: SIEMConnectionCreateRequest,
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst")),
) -> SIEMConnectionResponse:
    """Create a new managed SIEM connection with server-side encrypted credentials."""
    case_auth = get_case_authorization_service()
    sqlite_store = get_llm_state_store()
    if sqlite_store.get_case(req.case_id):
        case_auth.verify_case_access(current_user, req.case_id, "write")
    else:
        case_auth.ensure_case_registered(req.case_id, current_user.username)

    cred_store = get_credential_store()

    credentials: Dict[str, Any] = {}
    if req.password:
        credentials["password"] = req.password
    if req.api_key:
        credentials["api_key"] = req.api_key
    if req.token:
        credentials["token"] = req.token
    if req.username:
        credentials["username"] = req.username

    effective_actor = f"{current_user.username} ({current_user.badge_id})"

    try:
        conn = cred_store.create_connection(
            case_id=req.case_id,
            siem_type=req.siem_type,
            endpoint_url=req.endpoint_url,
            credentials=credentials,
            index_pattern=req.index_pattern,
            allowed_hosts=req.allowed_hosts,
            headers=req.headers,
            verify_ssl=req.verify_ssl,
            timeout_seconds=req.timeout_seconds,
            username=req.username,
            created_by=effective_actor,
        )
        return SIEMConnectionResponse(**conn)
    except HTTPException:
        raise
    except Exception as e:
        clean_err = sanitize_credentials(str(e))
        logger.error("Failed to create SIEM connection: %s", clean_err)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create SIEM connection: {clean_err}",
        )


@router.get("/connections", response_model=List[SIEMConnectionResponse])
def list_siem_connections(
    case_id: str = Query(..., description="Case identifier to filter connections"),
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst", "external_auditor", "auditor")),
) -> List[SIEMConnectionResponse]:
    """List all managed SIEM connections for a case.
    
    Zero Secret Leakage: Returns only configuration metadata and credential presence flags.
    """
    case_auth = get_case_authorization_service()
    sqlite_store = get_llm_state_store()
    if sqlite_store.get_case(case_id):
        case_auth.verify_case_access(current_user, case_id, "read")

    cred_store = get_credential_store()
    connections = cred_store.list_connections(case_id=case_id)
    return [SIEMConnectionResponse(**c) for c in connections]


@router.get("/connections/{connection_id}", response_model=SIEMConnectionResponse)
def get_siem_connection(
    connection_id: str,
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst", "external_auditor", "auditor")),
) -> SIEMConnectionResponse:
    """Retrieve details of a managed SIEM connection.
    
    Zero Secret Leakage: Plaintext credentials and ciphertexts are never returned.
    """
    cred_store = get_credential_store()
    conn = cred_store.get_connection(connection_id, include_credentials=False)
    if not conn:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"SIEM connection '{connection_id}' not found.",
        )

    case_auth = get_case_authorization_service()
    sqlite_store = get_llm_state_store()
    if sqlite_store.get_case(conn["case_id"]):
        case_auth.verify_case_access(current_user, conn["case_id"], "read")

    return SIEMConnectionResponse(**conn)


@router.patch("/connections/{connection_id}", response_model=SIEMConnectionResponse)
def update_siem_connection(
    connection_id: str,
    req: SIEMConnectionUpdateRequest,
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst")),
) -> SIEMConnectionResponse:
    """Update SIEM connection metadata or credentials.
    
    Blank password/api_key/token fields preserve existing stored secrets.
    Explicit removal requires remove_* flags or clear_credentials=True.
    """
    cred_store = get_credential_store()
    existing = cred_store.get_connection(connection_id, include_credentials=False)
    if not existing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"SIEM connection '{connection_id}' not found.",
        )

    case_auth = get_case_authorization_service()
    sqlite_store = get_llm_state_store()
    if sqlite_store.get_case(existing["case_id"]):
        case_auth.verify_case_access(current_user, existing["case_id"], "write")

    updated_creds: Dict[str, Any] = {}
    if req.password is not None:
        updated_creds["password"] = req.password
    if req.api_key is not None:
        updated_creds["api_key"] = req.api_key
    if req.token is not None:
        updated_creds["token"] = req.token

    try:
        updated = cred_store.update_connection(
            connection_id=connection_id,
            siem_type=req.siem_type,
            endpoint_url=req.endpoint_url,
            index_pattern=req.index_pattern,
            allowed_hosts=req.allowed_hosts,
            headers=req.headers,
            verify_ssl=req.verify_ssl,
            timeout_seconds=req.timeout_seconds,
            username=req.username,
            updated_credentials=updated_creds,
            remove_password=req.remove_password,
            remove_api_key=req.remove_api_key,
            remove_token=req.remove_token,
            clear_credentials=req.clear_credentials,
        )
        if not updated:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"SIEM connection '{connection_id}' not found.",
            )
        return SIEMConnectionResponse(**updated)
    except HTTPException:
        raise
    except Exception as e:
        clean_err = sanitize_credentials(str(e))
        logger.error("Failed to update SIEM connection: %s", clean_err)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update SIEM connection: {clean_err}",
        )


@router.delete("/connections/{connection_id}")
def delete_siem_connection(
    connection_id: str,
    current_user: UserRead = Depends(require_roles("lead_investigator")),
) -> Dict[str, Any]:
    """Permanently delete a SIEM connection and its stored credentials."""
    cred_store = get_credential_store()
    existing = cred_store.get_connection(connection_id, include_credentials=False)
    if not existing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"SIEM connection '{connection_id}' not found.",
        )

    case_auth = get_case_authorization_service()
    sqlite_store = get_llm_state_store()
    if sqlite_store.get_case(existing["case_id"]):
        case_auth.verify_case_access(current_user, existing["case_id"], "delete")

    deleted = cred_store.delete_connection(connection_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"SIEM connection '{connection_id}' not found.",
        )
    return {"status": "deleted", "connection_id": connection_id}


@router.post("/connections/{connection_id}/test", response_model=SIEMConnectionTestResponse)
def test_siem_connection_endpoint(
    connection_id: str,
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst")),
) -> SIEMConnectionTestResponse:
    """Test reachability and authentication to target SIEM endpoint.
    
    Zero Secret Leakage: Test results never include credentials or leak secrets in error messages.
    """
    cred_store = get_credential_store()
    existing = cred_store.get_connection(connection_id, include_credentials=False)
    if not existing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"SIEM connection '{connection_id}' not found.",
        )

    case_auth = get_case_authorization_service()
    sqlite_store = get_llm_state_store()
    if sqlite_store.get_case(existing["case_id"]):
        case_auth.verify_case_access(current_user, existing["case_id"], "write")

    result = cred_store.test_connection(connection_id)
    return SIEMConnectionTestResponse(**result)
