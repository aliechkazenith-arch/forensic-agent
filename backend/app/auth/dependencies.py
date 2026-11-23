"""FastAPI Authentication & RBAC Dependencies.

Standards:
- OAuth2 Bearer Token Extraction (RFC 6750)
- Role Enforcement: require_roles("lead_investigator", "soc_analyst")
- Hermetic Testing Support: Fallback test mode via FORENSICOPS_AUTH_DISABLED or X-ForensicOps-Test-Role
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Callable, Optional
from fastapi import Depends, Header, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from backend.app.auth.models import UserRead, UserRole
from backend.app.auth.security import decode_access_token
from backend.app.auth.store import UserStore

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)

_GLOBAL_USER_STORE: Optional[UserStore] = None


def get_user_store() -> UserStore:
    """Retrieve or initialize the global UserStore singleton."""
    global _GLOBAL_USER_STORE
    if _GLOBAL_USER_STORE is None:
        vault_env = os.environ.get("FORENSICOPS_VAULT_DIR", "vault")
        vault_path = Path(vault_env).resolve()
        vault_path.mkdir(parents=True, exist_ok=True)
        db_path = vault_path / "users.db"
        _GLOBAL_USER_STORE = UserStore(db_path=db_path)
    return _GLOBAL_USER_STORE


def set_user_store(store: UserStore) -> None:
    """Override user store (used in testing)."""
    global _GLOBAL_USER_STORE
    _GLOBAL_USER_STORE = store


def reset_user_store() -> None:
    """Reset user store singleton."""
    global _GLOBAL_USER_STORE
    if _GLOBAL_USER_STORE is not None:
        try:
            _GLOBAL_USER_STORE.close()
        except Exception:
            pass
        _GLOBAL_USER_STORE = None


async def get_current_user(
    token: Optional[str] = Depends(oauth2_scheme),
    x_test_role: Optional[str] = Header(None, alias="X-ForensicOps-Test-Role"),
    x_test_username: Optional[str] = Header(None, alias="X-ForensicOps-Test-User"),
    x_test_badge: Optional[str] = Header(None, alias="X-ForensicOps-Test-Badge"),
    store: UserStore = Depends(get_user_store),
) -> UserRead:
    """Validate JWT bearer token and return the authenticated investigator.

    Supports test mode bypass when FORENSICOPS_AUTH_DISABLED=true or test headers are provided.
    """
    # 1. If an explicit Bearer token is provided, validate it first
    if token:
        payload = decode_access_token(token)
        if not payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired access token.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        user = store.get_by_id(payload.user_id) if payload.user_id else None
        if not user:
            res = store.get_by_username(payload.sub)
            if res:
                user = res if isinstance(res, UserRead) else res[0]

        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Investigator account no longer exists.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Investigator account has been suspended by Lead.",
            )

        return user

    # 2. Check test-mode bypass ONLY when no token is provided
    env_name = os.getenv("FORENSICOPS_ENVIRONMENT", "").lower().strip()
    is_production = env_name == "production"
    is_test_env = (
        not is_production
        and (bool(os.getenv("PYTEST_CURRENT_TEST")) or env_name == "test")
    )
    auth_disabled_env = os.getenv("FORENSICOPS_AUTH_DISABLED", "").lower().strip()

    if is_test_env:
        auth_disabled = auth_disabled_env in ("true", "1", "yes") or (auth_disabled_env != "false")
    else:
        auth_disabled = False

    if is_test_env and auth_disabled:
        role_val: UserRole = "lead_investigator"
        if x_test_role in ("lead_investigator", "soc_analyst", "auditor", "external_auditor"):
            role_val = "auditor" if x_test_role == "external_auditor" else x_test_role  # type: ignore

        return UserRead(
            id="test-investigator-01",
            username=x_test_username or "lead_admin",
            badge_id=x_test_badge or "BADGE-001",
            role=role_val,
            full_name="Automated Test Investigator",
            is_active=True,
            created_at="2026-01-01T00:00:00Z",
        )

    # 3. Token required in production mode or when auth is enabled in tests
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication token required. Sign in at /api/auth/login.",
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_roles(*allowed_roles: str) -> Callable[[UserRead], UserRead]:
    """Dependency factory restricting route access to specified investigator roles."""

    async def _role_checker(user: UserRead = Depends(get_current_user)) -> UserRead:
        normalized_allowed = set()
        for r in allowed_roles:
            normalized_allowed.add(r)
            if r == "auditor":
                normalized_allowed.add("external_auditor")
            elif r == "external_auditor":
                normalized_allowed.add("auditor")

        if user.role not in normalized_allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Access denied: Requires role in {allowed_roles}. "
                    f"Current investigator role: '{user.role}'."
                ),
            )
        return user

    return _role_checker


async def get_current_user_optional(
    token: Optional[str] = Depends(oauth2_scheme),
    x_test_role: Optional[str] = Header(None, alias="X-ForensicOps-Test-Role"),
    x_test_username: Optional[str] = Header(None, alias="X-ForensicOps-Test-User"),
    x_test_badge: Optional[str] = Header(None, alias="X-ForensicOps-Test-Badge"),
    store: UserStore = Depends(get_user_store),
) -> Optional[UserRead]:
    """Optionally validate user, returning None if unauthenticated instead of raising 401."""
    try:
        return await get_current_user(token, x_test_role, x_test_username, x_test_badge, store)
    except HTTPException:
        return None
