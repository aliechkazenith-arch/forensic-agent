"""Authentication & User Management API Endpoints.

Standards:
- NIST SP 800-86 / SP 800-63B Identity & Custody Verification
- Multi-User RBAC (lead_investigator, soc_analyst, auditor)
- Single-use First-Boot Lead Account Provisioning
"""
from __future__ import annotations

from typing import List
from fastapi import APIRouter, Depends, HTTPException, status

from backend.app.auth.dependencies import (
    get_current_user,
    get_user_store,
    require_roles,
)
from backend.app.auth.models import (
    AuthStatus,
    LoginRequest,
    Token,
    UserCreate,
    UserRead,
    UserSetupRequest,
    UserStatusUpdate,
)
from backend.app.auth.security import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    create_access_token,
    hash_password,
    verify_password,
)
from backend.app.auth.store import UserStore

router = APIRouter(prefix="/api/auth", tags=["Authentication & RBAC"])


@router.get("/status", response_model=AuthStatus)
async def get_auth_status(store: UserStore = Depends(get_user_store)) -> AuthStatus:
    """Check if the system has been initialized with a Lead Investigator account."""
    total_users = store.count_users()
    active_users = store.count_active_users()
    return AuthStatus(
        initialized=total_users > 0,
        active_users_count=active_users,
    )


@router.post("/setup", response_model=Token, status_code=status.HTTP_201_CREATED)
async def setup_first_boot(
    req: UserSetupRequest,
    store: UserStore = Depends(get_user_store),
) -> Token:
    """One-time first-boot setup to create the initial Lead Investigator account.

    Permanently locked once the first account is registered.
    """
    if store.count_users() > 0:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="System is already initialized. Additional accounts must be created by a Lead Investigator.",
        )

    # Validate non-duplicate username/badge
    if store.get_by_username(req.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Username '{req.username}' is already in use.",
        )
    if store.get_by_badge_id(req.badge_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Badge ID '{req.badge_id}' is already registered.",
        )

    pwd_hash = hash_password(req.password)
    user_in = UserCreate(
        username=req.username,
        badge_id=req.badge_id,
        role="lead_investigator",
        full_name=req.full_name or "Chief Lead Investigator",
        password=req.password,
        is_active=True,
    )
    user = store.create_user(user_in=user_in, password_hash=pwd_hash)

    token_claims = {
        "sub": user.username,
        "user_id": user.id,
        "badge_id": user.badge_id,
        "role": user.role,
    }
    jwt_token = create_access_token(token_claims)

    return Token(
        access_token=jwt_token,
        token_type="bearer",
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=user,
    )


@router.post("/login", response_model=Token)
async def login(
    req: LoginRequest,
    store: UserStore = Depends(get_user_store),
) -> Token:
    """Authenticate an investigator via Username or Badge ID + Password."""
    # Lookup by username first, then fallback to badge ID
    lookup = store.get_by_username(req.username)
    if not lookup:
        lookup = store.get_by_badge_id(req.username)

    if not lookup:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials. Check username/badge ID and password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user, stored_hash = lookup

    if not verify_password(req.password, stored_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials. Check username/badge ID and password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is suspended. Contact a Lead Investigator for access reinstatement.",
        )

    token_claims = {
        "sub": user.username,
        "user_id": user.id,
        "badge_id": user.badge_id,
        "role": user.role,
    }
    jwt_token = create_access_token(token_claims)

    return Token(
        access_token=jwt_token,
        token_type="bearer",
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=user,
    )


@router.get("/me", response_model=UserRead)
async def get_me(current_user: UserRead = Depends(get_current_user)) -> UserRead:
    """Retrieve the profile and role badge of the currently authenticated investigator."""
    return current_user


@router.get(
    "/users",
    response_model=List[UserRead],
    dependencies=[Depends(require_roles("lead_investigator"))],
)
async def list_users(store: UserStore = Depends(get_user_store)) -> List[UserRead]:
    """List all registered investigator accounts (Lead Investigator only)."""
    return store.list_users()


@router.post(
    "/users",
    response_model=UserRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_roles("lead_investigator"))],
)
async def create_user(
    req: UserCreate,
    store: UserStore = Depends(get_user_store),
) -> UserRead:
    """Register a new SOC Analyst or Auditor account (Lead Investigator only)."""
    if store.get_by_username(req.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Username '{req.username}' is already in use.",
        )
    if store.get_by_badge_id(req.badge_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Badge ID '{req.badge_id}' is already registered.",
        )

    pwd_hash = hash_password(req.password)
    return store.create_user(user_in=req, password_hash=pwd_hash)


@router.patch(
    "/users/{user_id}/status",
    response_model=UserRead,
    dependencies=[Depends(require_roles("lead_investigator"))],
)
async def update_user_status(
    user_id: str,
    req: UserStatusUpdate,
    store: UserStore = Depends(get_user_store),
    current_user: UserRead = Depends(get_current_user),
) -> UserRead:
    """Activate or suspend an investigator account (Lead Investigator only)."""
    if user_id == current_user.id and not req.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Lead Investigators cannot suspend their own active session.",
        )

    updated = store.update_user_status(user_id=user_id, is_active=req.is_active)
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID '{user_id}' not found.",
        )
    return updated
