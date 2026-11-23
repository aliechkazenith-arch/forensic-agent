"""Pydantic v2 Models for RBAC Authentication, User Accounts, and JWT Tokens.

Roles:
- lead_investigator: Administrative & forensic lead (creates accounts, approves online collection, runs workflows).
- soc_analyst: Investigative analyst (evidence intake, running workflows, submitting continuous learning feedback).
- auditor: Read-only compliance & chain-of-custody verification (views reports, inspects cryptographic ledgers).
"""
from __future__ import annotations

from typing import Literal, Optional
from pydantic import BaseModel, Field

UserRole = Literal["lead_investigator", "soc_analyst", "auditor"]
AccountType = Literal["human", "service_account", "agent"]


class UserBase(BaseModel):
    """Base user attributes."""
    username: str = Field(..., min_length=3, max_length=50)
    badge_id: str = Field(..., min_length=2, max_length=50)
    role: UserRole
    account_type: AccountType = "human"
    full_name: Optional[str] = None
    is_active: bool = True


class UserCreate(UserBase):
    """Payload to register a new investigator account (Lead only)."""
    password: str = Field(..., min_length=6, max_length=128)


class UserSetupRequest(BaseModel):
    """First-boot initialization request to configure the Lead Investigator."""
    username: str = Field(..., min_length=3, max_length=50)
    badge_id: str = Field(..., min_length=2, max_length=50)
    password: str = Field(..., min_length=6, max_length=128)
    full_name: Optional[str] = "Chief Lead Investigator"


class UserRead(UserBase):
    """Publicly safe representation of an investigator profile."""
    id: str
    created_at: str

    @property
    def is_human(self) -> bool:
        """Verify whether this principal is an authenticated human investigator."""
        return self.account_type == "human"


class UserStatusUpdate(BaseModel):
    """Request to activate or suspend an investigator account."""
    is_active: bool


class LoginRequest(BaseModel):
    """Investigator credentials for session establishment (accepts username or badge_id)."""
    username: str
    password: str


class Token(BaseModel):
    """OAuth2 / JWT bearer access token response."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserRead


class TokenPayload(BaseModel):
    """Cryptographic claims extracted from the JWT access token."""
    sub: str  # username
    user_id: str
    badge_id: str
    role: UserRole
    exp: int


class AuthStatus(BaseModel):
    """Publicly queryable status indicating whether the system has been initialized."""
    initialized: bool
    active_users_count: int
