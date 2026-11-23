"""Authentication & Role-Based Access Control (RBAC) Module for ForensicOps AI."""
from backend.app.auth.models import (
    Token,
    TokenPayload,
    UserBase,
    UserCreate,
    UserRead,
    UserRole,
    UserSetupRequest,
    UserStatusUpdate,
)
from backend.app.auth.security import (
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)
from backend.app.auth.store import UserStore
from backend.app.auth.case_authorization import (
    CaseAuthorizationService,
    get_case_authorization_service,
    reset_case_authorization_service,
    set_case_authorization_service,
)

__all__ = [
    "UserRole",
    "UserBase",
    "UserCreate",
    "UserSetupRequest",
    "UserRead",
    "UserStatusUpdate",
    "Token",
    "TokenPayload",
    "hash_password",
    "verify_password",
    "create_access_token",
    "decode_access_token",
    "UserStore",
    "CaseAuthorizationService",
    "get_case_authorization_service",
    "reset_case_authorization_service",
    "set_case_authorization_service",
]
