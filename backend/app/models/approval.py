"""Data Models for Operation-Specific Human Approvals and Action Authorization.

Standards:
- Operation-Specific Binding (AGENTS.md Rule 7, NIST SP 800-86, ISO/IEC 27037).
- Changing any bound parameter (case, action, target, tool, parameters) invalidates approval.
- Enforces explicit approval lifecycle: pending, approved, rejected, expired, revoked, consumed.
- The agent cannot approve its own requested action.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4
from pydantic import BaseModel, ConfigDict, Field

from backend.app.core.action_risk_policy import ActionRiskLevel, ActionType


class ApprovalStatus(str, Enum):
    """Lifecycle states of an operation approval request."""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    REVOKED = "revoked"
    CONSUMED = "consumed"


def compute_parameter_digest(parameters: Optional[Dict[str, Any]]) -> str:
    """Compute deterministic SHA-256 digest of normalized JSON parameters.
    
    Uses canonical JSON sorting to guarantee parameter changes change the digest.
    """
    if not parameters:
        return f"sha256:{hashlib.sha256(b'{}').hexdigest()}"
    canonical_bytes = json.dumps(
        parameters,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(canonical_bytes).hexdigest()}"


class ApprovalRequest(BaseModel):
    """Cryptographically-grounded approval request binding an exact forensic operation."""
    model_config = ConfigDict(extra="ignore")

    approval_id: str = Field(default_factory=lambda: f"appr-{uuid4().hex[:12]}")
    case_id: str
    requesting_investigator: str
    approving_investigator: Optional[str] = None
    requesting_principal_id: str = Field(default="")
    approving_principal_id: Optional[str] = None
    requesting_badge_id: Optional[str] = None
    approving_badge_id: Optional[str] = None
    action_type: ActionType
    target: str  # Hostname, IP, artifact ID, or file path
    capability_id: str  # Specific tool or analyzer ID
    parameters: Dict[str, Any] = Field(default_factory=dict)
    parameter_digest: str = Field(default="")
    policy_version: str = "1.0.0"
    risk_level: ActionRiskLevel = ActionRiskLevel.HIGH
    reason: str = ""
    evidence_scope: List[str] = Field(default_factory=list)
    status: ApprovalStatus = ApprovalStatus.PENDING
    created_at_utc: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    expires_at_utc: str = Field(default="")
    resolved_at_utc: Optional[str] = None
    token_id: Optional[str] = None
    consumed_at_utc: Optional[str] = None
    rejection_reason: Optional[str] = None

    def model_post_init(self, __context: Any) -> None:
        """Ensure parameter_digest is computed if missing and canonical principal ID initialized."""
        if not self.requesting_principal_id and self.requesting_investigator:
            object.__setattr__(self, "requesting_principal_id", self.requesting_investigator)
        if not self.parameter_digest:
            object.__setattr__(self, "parameter_digest", compute_parameter_digest(self.parameters))
        if not self.expires_at_utc:
            # Default 15 minutes expiration (900 seconds)
            from datetime import timedelta
            try:
                dt = datetime.fromisoformat(self.created_at_utc.replace("Z", "+00:00"))
            except Exception:
                dt = datetime.now(timezone.utc)
            object.__setattr__(self, "expires_at_utc", (dt + timedelta(seconds=900)).isoformat())

    def verify_parameters(self, target_params: Dict[str, Any]) -> bool:
        """Verify that incoming parameters match the exact digest bound at approval time."""
        current_digest = compute_parameter_digest(target_params)
        return self.parameter_digest.lower() == current_digest.lower()

    def is_expired(self, current_time: Optional[datetime] = None) -> bool:
        """Check whether approval has expired."""
        now = current_time or datetime.now(timezone.utc)
        try:
            exp = datetime.fromisoformat(self.expires_at_utc.replace("Z", "+00:00"))
            return now > exp
        except Exception:
            return True

    @property
    def decision_reason(self) -> Optional[str]:
        return self.rejection_reason or self.reason

    @property
    def justification(self) -> str:
        return self.reason


class CreateApprovalRequestBody(BaseModel):
    """Payload to request human authorization for an action."""
    model_config = ConfigDict(extra="ignore")

    case_id: str
    action_type: str
    target: str
    capability_id: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    reason: str = ""
    justification: Optional[str] = None
    evidence_scope: List[str] = Field(default_factory=list)
    expiration_seconds: int = 900  # Default 15 mins

    def model_post_init(self, __context: Any) -> None:
        if not self.reason and self.justification:
            object.__setattr__(self, "reason", self.justification)


class ResolveApprovalBody(BaseModel):
    """Payload to approve, reject, or revoke an action."""
    model_config = ConfigDict(extra="ignore")

    reason: Optional[str] = None
    expiration_seconds: int = 900
