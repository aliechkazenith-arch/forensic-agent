"""Centralized Case Authorization and Access Control Service.

Standards:
- Multi-User RBAC & Least Privilege (AGENTS.md Rule 2, NIST SP 800-86)
- Case-Level Authorization & Multi-Tenant Data Isolation
- Defense-in-Depth: Default to Deny access if authorization cannot be established
- Preserves per-case storage architecture (vault/<case_id>/forensic_store.duckdb)
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import HTTPException, status

from backend.app.auth.models import UserRead, UserRole
from backend.app.db.sqlite_store import LLMStateStore, get_llm_state_store

CASE_ID_REGEX = re.compile(r"^[a-zA-Z0-9_-]+$")


class CaseAuthorizationService:
    """Centralized service governing access to investigation cases and case-scoped assets."""

    def __init__(self, state_store: Optional[LLMStateStore] = None):
        self._store = state_store

    def _get_store(self) -> LLMStateStore:
        if self._store:
            return self._store
        return get_llm_state_store()

    def get_case_or_404(
        self,
        case_id: str,
        auto_register_vault: bool = True,
        initial_owner: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Verify that a case exists in the SQLite registry or vault, returning its metadata.
        
        Raises HTTPException 400 on invalid format, 404 if case does not exist.
        """
        if not case_id or not CASE_ID_REGEX.match(case_id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid case_id format: '{case_id}'. Must strictly match ^[a-zA-Z0-9_-]+$",
            )

        store = self._get_store()
        case = store.get_case(case_id)
        if case:
            return case

        # Check if case vault directory exists on disk (e.g., initialized via storage or intake)
        vault_env = os.environ.get("FORENSICOPS_VAULT_DIR", "vault")
        base_dir = Path(vault_env).resolve()
        vault_root = (base_dir / case_id).resolve()

        if auto_register_vault and vault_root.exists() and vault_root.is_relative_to(base_dir):
            created = store.create_or_update_case({
                "case_id": case_id,
                "case_name": case_id,
                "organization_name": "Default Organization",
                "lead_analyst": initial_owner or "lead_admin",
                "status": "OPEN",
            })
            return created

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID '{case_id}' was not found in the case registry.",
        )

    def is_user_authorized(
        self,
        user: UserRead,
        case: Dict[str, Any],
        action: str = "read",  # "read", "write", "execute", "delete", "share"
    ) -> bool:
        """Determine whether the investigator is authorized for the given case and action.
        
        Default to Deny:
        - A user's role alone does NOT grant access to all cases.
        - Must be assigned as lead_analyst or collaborator.
        - Auditor role only permitted "read" actions.
        - "delete" action strictly reserved for lead_investigator role on owned cases.
        - If a case is shared to vault (is_shared_to_vault=True), "read" action is permitted
          for peer review to all authenticated investigators.
        """
        # Role action constraints
        if user.role == "auditor" and action != "read":
            return False
        if action == "delete" and user.role != "lead_investigator":
            return False

        lead_analyst = case.get("lead_analyst")
        # Check ownership match against username, badge_id, or user id
        default_leads = ("analyst_lead", "lead_admin", "admin", "lead_chief")
        if lead_analyst and (
            lead_analyst in (user.username, user.badge_id, user.id)
            or (
                lead_analyst in default_leads
                and user.username in default_leads
                and user.role == "lead_investigator"
            )
        ):
            return True

        # If case is unassigned, lead investigators can access and triage it
        if not lead_analyst and user.role == "lead_investigator":
            return True

        # Check assigned collaborators in serialized_state
        state = case.get("serialized_state") or {}
        assigned = state.get("assigned_analysts", [])
        if not isinstance(assigned, list):
            assigned = []
        collaborators = state.get("collaborators", [])
        if not isinstance(collaborators, list):
            collaborators = []
        authorized_users = state.get("authorized_users", [])
        if not isinstance(authorized_users, list):
            authorized_users = []

        all_assigned = set(
            str(x).lower().strip() for x in (assigned + collaborators + authorized_users)
        )
        if (
            user.username.lower() in all_assigned
            or user.badge_id.lower() in all_assigned
            or user.id.lower() in all_assigned
        ):
            return True

        # Peer review vault sharing: allows read-only inspection for peer review
        if action == "read" and case.get("is_shared_to_vault"):
            return True

        # Default to deny
        return False

    def verify_case_access(
        self,
        user: UserRead,
        case_id: str,
        action: str = "read",
        auto_register_vault: bool = True,
    ) -> Dict[str, Any]:
        """Verify case existence and investigator authorization.
        
        Raises:
            HTTPException(400): If case_id is malformed.
            HTTPException(404): If case does not exist.
            HTTPException(403): If investigator is not authorized for the case or action.
        """
        case = self.get_case_or_404(
            case_id,
            auto_register_vault=auto_register_vault,
            initial_owner=user.username,
        )
        if not self.is_user_authorized(user, case, action=action):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: Investigator '{user.username}' is not authorized for case '{case_id}'.",
            )
        return case

    def ensure_case_registered(
        self,
        case_id: str,
        owner_username: str,
        case_name: Optional[str] = None,
        organization: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Ensure a case is registered in SQLite with the specified owner if not already present."""
        if not case_id or not CASE_ID_REGEX.match(case_id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid case_id format: '{case_id}'. Must strictly match ^[a-zA-Z0-9_-]+$",
            )
        store = self._get_store()
        existing = store.get_case(case_id)
        if existing:
            return existing
        return store.create_or_update_case({
            "case_id": case_id,
            "case_name": case_name or case_id,
            "organization_name": organization or "Default Organization",
            "lead_analyst": owner_username,
            "status": "OPEN",
        })


_GLOBAL_CASE_AUTH_SERVICE: Optional[CaseAuthorizationService] = None


def get_case_authorization_service() -> CaseAuthorizationService:
    """Retrieve or initialize the global CaseAuthorizationService singleton."""
    global _GLOBAL_CASE_AUTH_SERVICE
    if _GLOBAL_CASE_AUTH_SERVICE is None:
        _GLOBAL_CASE_AUTH_SERVICE = CaseAuthorizationService()
    return _GLOBAL_CASE_AUTH_SERVICE


def set_case_authorization_service(service: CaseAuthorizationService) -> None:
    """Override singleton service for testing isolation."""
    global _GLOBAL_CASE_AUTH_SERVICE
    _GLOBAL_CASE_AUTH_SERVICE = service


def reset_case_authorization_service() -> None:
    """Reset the singleton instance."""
    global _GLOBAL_CASE_AUTH_SERVICE
    _GLOBAL_CASE_AUTH_SERVICE = None
