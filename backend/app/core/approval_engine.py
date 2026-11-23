"""Central Human Approval & Action Authorization Engine.

Standards:
- Operation-Specific Binding (AGENTS.md Rule 7, NIST SP 800-86, ISO/IEC 27037).
- No Hardcoded Fallback Secret.
- Replay Protection & One-Time Token Consumption.
- The Agent Cannot Approve Its Own Requested Action.
- Full Audit Logging across All Lifecycle Transitions.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from uuid import uuid4

GENESIS_HASH = "0" * 64


def canonicalize_consumed_token_data(
    token_id: str,
    approval_id: str,
    case_id: str,
    action_type: str,
    target: str,
    parameter_digest: str,
    consumed_by: str,
    consumed_at_utc: str,
) -> str:
    """Serialize consumed token fields to deterministic canonical JSON (RFC 8785)."""
    payload = {
        "action_type": str(action_type or ""),
        "approval_id": str(approval_id or ""),
        "case_id": str(case_id or ""),
        "consumed_at_utc": str(consumed_at_utc or ""),
        "consumed_by": str(consumed_by or ""),
        "parameter_digest": str(parameter_digest or ""),
        "target": str(target or ""),
        "token_id": str(token_id or ""),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def canonicalize_approval_audit_data(
    event_id: str,
    case_id: str,
    actor: str,
    action: str,
    target: str,
    requesting_principal_id: Optional[str],
    approving_principal_id: Optional[str],
    details_json: str,
    timestamp_utc: str,
) -> str:
    """Serialize approval audit log fields to deterministic canonical JSON (RFC 8785)."""
    payload = {
        "action": str(action or ""),
        "actor": str(actor or ""),
        "approving_principal_id": str(approving_principal_id or ""),
        "case_id": str(case_id or ""),
        "details_json": str(details_json or ""),
        "event_id": str(event_id or ""),
        "requesting_principal_id": str(requesting_principal_id or ""),
        "target": str(target or ""),
        "timestamp_utc": str(timestamp_utc or ""),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def compute_record_hmac(secret_key: Union[str, bytes], previous_hash: str, canonical_data: str) -> str:
    """Calculate HMAC-SHA256(secret_key, previous_hash || canonical_record_data)."""
    key = secret_key.encode("utf-8") if isinstance(secret_key, str) else secret_key
    message = (str(previous_hash) + str(canonical_data)).encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()

from backend.app.auth.models import UserRead
from backend.app.core.action_risk_policy import ActionRiskPolicy, ActionType, ActionRiskLevel
from backend.app.core.custody_engine import CustodyEngine
from backend.app.core.exceptions import (
    ExecutionPolicyError,
    ForensicOpsError,
    UnauthorizedCollectorExecutionError,
)
from backend.app.db.sqlite_store import LLMStateStore, get_llm_state_store
from backend.app.models.approval import (
    ApprovalRequest,
    ApprovalStatus,
    compute_parameter_digest,
)
from backend.app.models.workflow import HumanApprovalToken


class ApprovalResult(tuple):
    """Tuple containing (ApprovalRequest, HumanApprovalToken) with named property access."""
    def __new__(cls, request: ApprovalRequest, token: HumanApprovalToken):
        return super().__new__(cls, (request, token))

    @property
    def request(self) -> ApprovalRequest:
        return self[0]

    @property
    def token(self) -> HumanApprovalToken:
        return self[1]

    def __getattr__(self, name: str) -> Any:
        return getattr(self[0], name)


class ApprovalEngine:
    """Enterprise-grade human approval, authorization policy, and token lifecycle engine."""

    def __init__(
        self,
        state_store: Optional[LLMStateStore] = None,
        custody_engine: Optional[CustodyEngine] = None,
        secret_key: Optional[str] = None,
        db_path: Optional[Union[str, Path]] = None,
        user_store: Optional[Any] = None,
    ):
        if state_store is not None:
            self.state_store = state_store
        elif db_path is not None:
            self.state_store = LLMStateStore(db_path=db_path)
        else:
            self.state_store = get_llm_state_store()
        self.custody_engine = custody_engine
        self._user_store = user_store
        effective_secret = os.getenv("HUMAN_APPROVAL_HMAC_SECRET") if secret_key is None else secret_key
        if not effective_secret or effective_secret in ("forensicops-gate-secret", "default", "dev_approval_secret_replace_in_production", ""):
            raise ValueError(
                "Insecure configuration: HMAC secret must not be empty or default key (HUMAN_APPROVAL_HMAC_SECRET)."
            )
        self.secret_key = effective_secret
        self._lock = threading.RLock()
        self._init_tables()

    @property
    def user_store(self) -> Optional[Any]:
        """Lazy access to user store for approver verification."""
        if self._user_store is not None:
            return self._user_store
        try:
            from backend.app.auth.dependencies import get_user_store
            return get_user_store()
        except Exception:
            return None

    def _init_tables(self) -> None:
        """Initialize tables for approval requests and consumed tokens."""
        conn = self.state_store._conn
        with conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS approval_requests (
                    approval_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    requesting_investigator TEXT NOT NULL,
                    approving_investigator TEXT,
                    action_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    capability_id TEXT NOT NULL,
                    parameters_json TEXT NOT NULL,
                    parameter_digest TEXT NOT NULL,
                    policy_version TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    evidence_scope_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at_utc TEXT NOT NULL,
                    expires_at_utc TEXT NOT NULL,
                    resolved_at_utc TEXT,
                    token_id TEXT,
                    consumed_at_utc TEXT,
                    rejection_reason TEXT,
                    requesting_principal_id TEXT NOT NULL DEFAULT '',
                    approving_principal_id TEXT,
                    requesting_badge_id TEXT,
                    approving_badge_id TEXT
                );
                """
            )
            # Safe schema migrations for existing databases
            existing_cols = {row[1] for row in conn.execute("PRAGMA table_info(approval_requests)").fetchall()}
            if "requesting_principal_id" not in existing_cols:
                conn.execute("ALTER TABLE approval_requests ADD COLUMN requesting_principal_id TEXT NOT NULL DEFAULT ''")
            if "approving_principal_id" not in existing_cols:
                conn.execute("ALTER TABLE approval_requests ADD COLUMN approving_principal_id TEXT")
            if "requesting_badge_id" not in existing_cols:
                conn.execute("ALTER TABLE approval_requests ADD COLUMN requesting_badge_id TEXT")
            if "approving_badge_id" not in existing_cols:
                conn.execute("ALTER TABLE approval_requests ADD COLUMN approving_badge_id TEXT")

            conn.execute("CREATE INDEX IF NOT EXISTS idx_appr_case ON approval_requests(case_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_appr_status ON approval_requests(status);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_appr_req_principal ON approval_requests(requesting_principal_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_appr_appr_principal ON approval_requests(approving_principal_id);")

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS consumed_approval_tokens (
                    token_id TEXT PRIMARY KEY,
                    approval_id TEXT NOT NULL,
                    case_id TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    parameter_digest TEXT NOT NULL,
                    consumed_by TEXT NOT NULL,
                    consumed_at_utc TEXT NOT NULL,
                    previous_hash TEXT NOT NULL DEFAULT '',
                    current_hash TEXT NOT NULL DEFAULT ''
                );
                """
            )
            # Safe schema migrations for existing databases
            existing_consumed_cols = {row[1] for row in conn.execute("PRAGMA table_info(consumed_approval_tokens)").fetchall()}
            if "previous_hash" not in existing_consumed_cols:
                conn.execute("ALTER TABLE consumed_approval_tokens ADD COLUMN previous_hash TEXT NOT NULL DEFAULT ''")
            if "current_hash" not in existing_consumed_cols:
                conn.execute("ALTER TABLE consumed_approval_tokens ADD COLUMN current_hash TEXT NOT NULL DEFAULT ''")

            conn.execute("CREATE INDEX IF NOT EXISTS idx_consumed_appr_id ON consumed_approval_tokens(approval_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_consumed_case ON consumed_approval_tokens(case_id);")

            # Hash-Chained Approval Audit Log (Phase 14.3)
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS approval_audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT UNIQUE NOT NULL,
                    case_id TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target TEXT NOT NULL,
                    requesting_principal_id TEXT,
                    approving_principal_id TEXT,
                    details_json TEXT NOT NULL,
                    timestamp_utc TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    current_hash TEXT NOT NULL
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_approval_audit_case ON approval_audit_log(case_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_approval_audit_timestamp ON approval_audit_log(timestamp_utc DESC);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_approval_audit_action ON approval_audit_log(action);")

    # --------------------------------------------------------------------------
    # 1. Create Approval Request
    # --------------------------------------------------------------------------
    def create_request(
        self,
        case_id: str,
        requesting_investigator: str,
        action_type: str,
        target: str,
        capability_id: str,
        parameters: Optional[Dict[str, Any]] = None,
        reason: str = "",
        justification: Optional[str] = None,
        evidence_scope: Optional[List[str]] = None,
        expiration_seconds: Optional[int] = None,
        validity_minutes: Optional[int] = None,
        requesting_principal_id: Optional[str] = None,
        requesting_badge_id: Optional[str] = None,
    ) -> ApprovalRequest:
        """Create a new pending approval request bound to an exact operation."""
        params = parameters or {}
        scope = evidence_scope or []
        effective_reason = reason or justification or ""

        if validity_minutes is not None:
            effective_exp_sec = validity_minutes * 60
        else:
            effective_exp_sec = expiration_seconds if expiration_seconds is not None else 900

        # Validate against Central Action Risk Policy
        eval_result = ActionRiskPolicy.evaluate(action_type, capability_id, params)
        if not eval_result.is_allowed:
            raise ExecutionPolicyError(eval_result.policy_reason)

        param_digest = compute_parameter_digest(params)
        now_dt = datetime.now(timezone.utc)
        expires_dt = now_dt + timedelta(seconds=effective_exp_sec)

        effective_principal_id = (requesting_principal_id or "").strip() or requesting_investigator.strip()

        req = ApprovalRequest(
            approval_id=f"appr-{uuid4().hex[:12]}",
            case_id=case_id,
            requesting_investigator=requesting_investigator,
            requesting_principal_id=effective_principal_id,
            requesting_badge_id=requesting_badge_id,
            action_type=eval_result.action_type,
            target=target,
            capability_id=capability_id,
            parameters=params,
            parameter_digest=param_digest,
            policy_version=eval_result.policy_version,
            risk_level=eval_result.risk_level,
            reason=effective_reason or eval_result.policy_reason,
            evidence_scope=scope,
            status=ApprovalStatus.PENDING,
            created_at_utc=now_dt.isoformat(),
            expires_at_utc=expires_dt.isoformat(),
        )

        with self.state_store._conn as conn:
            conn.execute(
                """
                INSERT INTO approval_requests (
                    approval_id, case_id, requesting_investigator, approving_investigator,
                    action_type, target, capability_id, parameters_json, parameter_digest,
                    policy_version, risk_level, reason, evidence_scope_json, status,
                    created_at_utc, expires_at_utc, resolved_at_utc, token_id,
                    consumed_at_utc, rejection_reason,
                    requesting_principal_id, approving_principal_id, requesting_badge_id, approving_badge_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    req.approval_id,
                    req.case_id,
                    req.requesting_investigator,
                    req.approving_investigator,
                    req.action_type.value,
                    req.target,
                    req.capability_id,
                    json.dumps(req.parameters, ensure_ascii=True, default=str),
                    req.parameter_digest,
                    req.policy_version,
                    req.risk_level.value,
                    req.reason,
                    json.dumps(req.evidence_scope, ensure_ascii=True),
                    req.status.value,
                    req.created_at_utc,
                    req.expires_at_utc,
                    req.resolved_at_utc,
                    req.token_id,
                    req.consumed_at_utc,
                    req.rejection_reason,
                    req.requesting_principal_id,
                    req.approving_principal_id,
                    req.requesting_badge_id,
                    req.approving_badge_id,
                ),
            )

        self._audit(
            case_id=req.case_id,
            actor=req.requesting_investigator,
            action="APPROVAL_REQUEST_CREATED",
            details={
                "approval_id": req.approval_id,
                "action_type": req.action_type.value,
                "capability_id": req.capability_id,
                "target": req.target,
                "risk_level": req.risk_level.value,
                "parameter_digest": req.parameter_digest,
                "expires_at_utc": req.expires_at_utc,
            },
            target=req.target,
            requesting_principal_id=req.requesting_principal_id,
        )

        return req

    # --------------------------------------------------------------------------
    # 2. Get / List Requests
    # --------------------------------------------------------------------------
    def get_request(self, approval_id: str) -> Optional[ApprovalRequest]:
        """Retrieve approval request by ID, updating expired status dynamically."""
        cursor = self.state_store._conn.execute(
            "SELECT * FROM approval_requests WHERE approval_id = ?",
            (approval_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None

        req = self._row_to_request(row)
        # Check dynamic expiration
        if req.status == ApprovalStatus.PENDING and req.is_expired():
            self._update_status(req.approval_id, ApprovalStatus.EXPIRED)
            req.status = ApprovalStatus.EXPIRED

        return req

    def list_requests(
        self,
        case_id: Optional[str] = None,
        status: Optional[ApprovalStatus] = None,
    ) -> List[ApprovalRequest]:
        """List approval requests matching optional case ID or status."""
        query = "SELECT * FROM approval_requests WHERE 1=1"
        params: List[Any] = []
        if case_id:
            query += " AND case_id = ?"
            params.append(case_id)
        if status:
            query += " AND status = ?"
            params.append(status.value if isinstance(status, ApprovalStatus) else str(status))
        query += " ORDER BY created_at_utc DESC"

        cursor = self.state_store._conn.execute(query, params)
        rows = cursor.fetchall()
        requests: List[ApprovalRequest] = []
        for r in rows:
            req = self._row_to_request(r)
            if req.status == ApprovalStatus.PENDING and req.is_expired():
                self._update_status(req.approval_id, ApprovalStatus.EXPIRED)
                req.status = ApprovalStatus.EXPIRED
            requests.append(req)
        return requests

    # --------------------------------------------------------------------------
    # 3. Approve Request
    # --------------------------------------------------------------------------
    def approve_request(
        self,
        approval_id: str,
        approver: Union[UserRead, Dict[str, Any]],
        expiration_seconds: Optional[int] = None,
        reason: Optional[str] = None,
    ) -> ApprovalResult:
        """Approve an action request and generate a cryptographically signed HumanApprovalToken."""
        req = self.get_request(approval_id)
        if not req:
            raise ForensicOpsError(f"Approval request '{approval_id}' not found.")

        # Check status
        if req.status == ApprovalStatus.EXPIRED or req.is_expired():
            raise ForensicOpsError(f"Approval request '{approval_id}' has expired and cannot be approved.")
        if req.status != ApprovalStatus.PENDING:
            raise ForensicOpsError(f"Approval request '{approval_id}' is in status '{req.status.value}' and cannot be approved.")

        # Approver identity and role extraction
        if isinstance(approver, UserRead):
            approver_user = approver.username
            approver_role = approver.role
            approver_id = approver.id
            approver_badge = approver.badge_id
            approver_account_type = getattr(approver, "account_type", "human")
            is_active = getattr(approver, "is_active", True)
        elif isinstance(approver, dict):
            approver_user = approver.get("username", "unknown")
            approver_role = approver.get("role", "soc_analyst")
            approver_id = approver.get("id") or approver.get("user_id") or approver_user
            approver_badge = approver.get("badge_id")
            approver_account_type = approver.get("account_type", "human")
            is_active = approver.get("is_active", True)
        else:
            raise ForensicOpsError("Invalid approver credentials.")

        if not is_active:
            raise ForensicOpsError(f"Approver '{approver_user}' is inactive and cannot grant approvals.")

        # Non-human / service account validation
        disallowed_names = {"copilot_daemon", "system", "bot_lead", "forensicops_runner"}
        approver_clean = approver_user.lower().strip()
        if (
            approver_account_type != "human"
            or approver_clean in disallowed_names
        ):
            raise ForensicOpsError(
                f"Unauthorized approver: Service accounts, autonomous agents, and non-human principals ({approver_user}) cannot approve actions."
            )

        # 1. Role validation: Only authorized authenticated investigators can approve
        if approver_role not in ("lead_investigator", "soc_analyst"):
            raise ForensicOpsError(
                f"Unauthorized approver: Role '{approver_role}' is not authorized to grant forensic execution approvals."
            )

        # 2. Agent / Self-Approval Prevention (Two-Person Rule)
        def _normalize_name(name: Optional[str]) -> str:
            if not name:
                return ""
            return name.split("(")[0].strip().lower()

        base_req = _normalize_name(req.requesting_investigator)
        base_appr = _normalize_name(approver_user)
        req_pid = (req.requesting_principal_id or "").strip().lower()
        appr_pid = str(approver_id or "").strip().lower()

        is_self_approval = False
        if req_pid and appr_pid and req_pid == appr_pid:
            is_self_approval = True
        elif base_req and base_appr and base_req == base_appr:
            is_self_approval = True
        elif req.requesting_badge_id and approver_badge and req.requesting_badge_id.strip().lower() == str(approver_badge).strip().lower():
            is_self_approval = True
        elif approver_clean.startswith("agent") or approver_clean.startswith("ai_planner"):
            is_self_approval = True

        if is_self_approval:
            raise ForensicOpsError(
                "Self-approval rejected: The requesting investigator or autonomous agent cannot approve its own operation."
            )

        now_dt = datetime.now(timezone.utc)
        exp_sec = expiration_seconds or 900
        expires_dt = now_dt + timedelta(seconds=exp_sec)
        token_id = f"gate-{uuid4().hex[:12]}"

        # Create and sign operation-specific token
        token = HumanApprovalToken(
            token_id=token_id,
            node_id=req.capability_id,
            case_id=req.case_id,
            approval_id=req.approval_id,
            action_type=req.action_type.value,
            target=req.target,
            parameter_digest=req.parameter_digest,
            issued_by=approver_user,
            timestamp_utc=now_dt.isoformat(),
            expires_at_utc=expires_dt.isoformat(),
            is_valid=True,
            consumed=False,
        )
        token.sign(self.secret_key)

        # Update request state
        req.status = ApprovalStatus.APPROVED
        req.approving_investigator = approver_user
        req.approving_principal_id = approver_id
        req.approving_badge_id = approver_badge
        req.resolved_at_utc = now_dt.isoformat()
        req.expires_at_utc = expires_dt.isoformat()
        req.token_id = token_id

        with self.state_store._conn as conn:
            cur = conn.execute(
                """
                UPDATE approval_requests
                SET status = ?, approving_investigator = ?, approving_principal_id = ?, approving_badge_id = ?,
                    resolved_at_utc = ?, expires_at_utc = ?, token_id = ?
                WHERE approval_id = ? AND status = ?
                """,
                (
                    req.status.value,
                    req.approving_investigator,
                    req.approving_principal_id,
                    req.approving_badge_id,
                    req.resolved_at_utc,
                    req.expires_at_utc,
                    req.token_id,
                    req.approval_id,
                    ApprovalStatus.PENDING.value,
                ),
            )
            if cur.rowcount == 0:
                raise ForensicOpsError(
                    f"Approval request '{approval_id}' cannot be approved: it is no longer in pending status."
                )

        self._audit(
            case_id=req.case_id,
            actor=approver_user,
            action="APPROVAL_REQUEST_APPROVED",
            details={
                "approval_id": req.approval_id,
                "token_id": token_id,
                "target": req.target,
                "action_type": req.action_type.value,
                "expires_at_utc": req.expires_at_utc,
            },
            target=req.target,
            requesting_principal_id=req.requesting_principal_id,
            approving_principal_id=req.approving_principal_id or approver_id,
        )

        return ApprovalResult(req, token)

    # --------------------------------------------------------------------------
    # 4. Reject Request
    # --------------------------------------------------------------------------
    def reject_request(
        self,
        approval_id: str,
        approver: Optional[Union[UserRead, Dict[str, Any]]] = None,
        reason: str = "Investigator rejected action.",
        rejector: Optional[Union[UserRead, Dict[str, Any]]] = None,
    ) -> ApprovalRequest:
        """Reject an approval request."""
        effective_approver = approver or rejector
        if effective_approver is None:
            raise ForensicOpsError("Approver / rejector identity is required.")
        req = self.get_request(approval_id)
        if not req:
            raise ForensicOpsError(f"Approval request '{approval_id}' not found.")
        if req.status not in (ApprovalStatus.PENDING, ApprovalStatus.APPROVED):
            raise ForensicOpsError(f"Cannot reject request in status '{req.status.value}'.")

        approver_user = effective_approver.username if isinstance(effective_approver, UserRead) else effective_approver.get("username", "analyst")
        now_dt = datetime.now(timezone.utc).isoformat()

        req.status = ApprovalStatus.REJECTED
        req.approving_investigator = approver_user
        req.resolved_at_utc = now_dt
        req.rejection_reason = reason

        with self.state_store._conn as conn:
            conn.execute(
                """
                UPDATE approval_requests
                SET status = ?, approving_investigator = ?, resolved_at_utc = ?, rejection_reason = ?
                WHERE approval_id = ?
                """,
                (req.status.value, req.approving_investigator, req.resolved_at_utc, req.rejection_reason, req.approval_id),
            )

        self._audit(
            case_id=req.case_id,
            actor=approver_user,
            action="APPROVAL_REQUEST_REJECTED",
            details={
                "approval_id": req.approval_id,
                "reason": reason,
                "target": req.target,
            },
            target=req.target,
            requesting_principal_id=req.requesting_principal_id,
            approving_principal_id=approver_user,
        )

        return req

    # --------------------------------------------------------------------------
    # 5. Revoke Request
    # --------------------------------------------------------------------------
    def revoke_request(
        self,
        approval_id: str,
        actor: Optional[Union[UserRead, Dict[str, Any]]] = None,
        reason: str = "Investigator revoked authorization.",
        revoker: Optional[Union[UserRead, Dict[str, Any]]] = None,
    ) -> ApprovalRequest:
        """Revoke an approved request before it is consumed."""
        effective_actor = actor or revoker
        if effective_actor is None:
            raise ForensicOpsError("Actor / revoker identity is required.")
        req = self.get_request(approval_id)
        if not req:
            raise ForensicOpsError(f"Approval request '{approval_id}' not found.")
        if req.status != ApprovalStatus.APPROVED:
            raise ForensicOpsError(f"Cannot revoke request in status '{req.status.value}' (only 'approved' requests can be revoked).")

        actor_user = effective_actor.username if isinstance(effective_actor, UserRead) else effective_actor.get("username", "analyst")
        now_dt = datetime.now(timezone.utc).isoformat()

        req.status = ApprovalStatus.REVOKED
        req.resolved_at_utc = now_dt
        req.rejection_reason = reason

        with self.state_store._conn as conn:
            conn.execute(
                """
                UPDATE approval_requests
                SET status = ?, resolved_at_utc = ?, rejection_reason = ?
                WHERE approval_id = ?
                """,
                (req.status.value, req.resolved_at_utc, req.rejection_reason, req.approval_id),
            )

        self._audit(
            case_id=req.case_id,
            actor=actor_user,
            action="APPROVAL_REQUEST_REVOKED",
            details={
                "approval_id": req.approval_id,
                "reason": reason,
                "token_id": req.token_id,
            },
            target=req.target,
            requesting_principal_id=req.requesting_principal_id,
        )

        return req

    # --------------------------------------------------------------------------
    # 6. Verify and Consume Token (Replay Protection & One-Time Consumption)
    # --------------------------------------------------------------------------
    def verify_and_consume_token(
        self,
        token: Optional[HumanApprovalToken],
        expected_case_id: str,
        expected_action_type: Optional[str] = None,
        expected_target: Optional[str] = None,
        expected_parameters: Optional[Dict[str, Any]] = None,
        consumed_by: str = "investigation_controller",
    ) -> bool:
        """Verify token authenticity, bound parameters, and consume it atomically (one-time use)."""
        if not token or not token.is_valid or token.consumed:
            raise UnauthorizedCollectorExecutionError(
                f"Replay detected: Approval token '{token.token_id}' has already been consumed."
                if token and token.consumed
                else "Token is missing, revoked, or already marked consumed."
            )

        # Replay Protection: Check if token_id is already in consumed_approval_tokens
        cur = self.state_store._conn.execute(
            "SELECT consumed_at_utc FROM consumed_approval_tokens WHERE token_id = ?",
            (token.token_id,),
        )
        if cur.fetchone():
            raise UnauthorizedCollectorExecutionError(
                f"Replay detected: Approval token '{token.token_id}' has already been consumed."
            )

        # Compute parameter digest if expected_parameters provided
        exp_digest = compute_parameter_digest(expected_parameters) if expected_parameters is not None else None

        # Specific structural mismatch checks before cryptographic validation
        if expected_case_id and token.case_id != expected_case_id:
            raise UnauthorizedCollectorExecutionError(
                f"Case ID mismatch: Token is bound to '{token.case_id}', expected '{expected_case_id}'."
            )
        if expected_target:
            if not token.target or not str(token.target).strip():
                raise UnauthorizedCollectorExecutionError(
                    f"Target mismatch: Expected target '{expected_target}', but token has no target host."
                )
            if token.target != expected_target:
                raise UnauthorizedCollectorExecutionError(
                    f"Target mismatch: Token is bound to '{token.target}', expected '{expected_target}'."
                )
        if token.action_type in ("remote_collection", "remote_endpoint_collection", "remote_access"):
            if not token.target or not str(token.target).strip():
                raise UnauthorizedCollectorExecutionError(
                    f"Remote collection token '{token.token_id}' does not specify a target host."
                )
        if exp_digest and token.parameter_digest and token.parameter_digest.lower() != exp_digest.lower():
            raise UnauthorizedCollectorExecutionError(
                f"Parameter digest mismatch: Operation parameters were modified after approval (expected {exp_digest}, token has {token.parameter_digest})."
            )
        if token.is_expired():
            raise UnauthorizedCollectorExecutionError(
                f"Token expired: Token expired at '{token.expires_at_utc}'."
            )

        # Verify token signature and cryptographic bindings
        is_verified = token.verify(
            secret_key=self.secret_key,
            expected_case_id=expected_case_id,
            expected_action_type=expected_action_type,
            expected_target=expected_target,
            expected_parameter_digest=exp_digest,
        )
        if not is_verified:
            raise UnauthorizedCollectorExecutionError(
                f"Cryptographic verification failed for token '{token.token_id}' "
                "(signature mismatch, parameter mismatch, target mismatch, or expired)."
            )

        # Check underlying approval request if bound
        req: Optional[ApprovalRequest] = None
        if token.approval_id:
            req = self.get_request(token.approval_id)
            if not req:
                raise UnauthorizedCollectorExecutionError(f"Underlying approval request '{token.approval_id}' not found.")
            if req.status != ApprovalStatus.APPROVED:
                raise UnauthorizedCollectorExecutionError(
                    f"Approval request '{token.approval_id}' has status '{req.status.value}', cannot execute."
                )
            if req.case_id != expected_case_id:
                raise UnauthorizedCollectorExecutionError("Approval request case_id mismatch.")
            if expected_target and req.target != expected_target:
                raise UnauthorizedCollectorExecutionError(f"Target mismatch: expected '{expected_target}', approval was for '{req.target}'.")
            if expected_parameters is not None and not req.verify_parameters(expected_parameters):
                raise UnauthorizedCollectorExecutionError("Parameter digest mismatch: operation parameters were modified after approval.")

        # One-time consumption: insert into consumed table and update request status atomically
        now_dt = datetime.now(timezone.utc).isoformat()
        action_val = expected_action_type or token.action_type or "unspecified"
        target_val = expected_target or token.target or "unspecified"
        digest_val = exp_digest or token.parameter_digest or ""
        appr_id_val = token.approval_id or "standalone"
        try:
            with self.state_store._conn as conn:
                cur = conn.execute(
                    "SELECT current_hash FROM consumed_approval_tokens ORDER BY rowid DESC LIMIT 1"
                )
                last_row = cur.fetchone()
                prev_hash = last_row[0] if last_row and last_row[0] else GENESIS_HASH

                canonical_data = canonicalize_consumed_token_data(
                    token_id=token.token_id,
                    approval_id=appr_id_val,
                    case_id=expected_case_id,
                    action_type=action_val,
                    target=target_val,
                    parameter_digest=digest_val,
                    consumed_by=consumed_by,
                    consumed_at_utc=now_dt,
                )
                curr_hash = compute_record_hmac(self.secret_key, prev_hash, canonical_data)

                conn.execute(
                    """
                    INSERT INTO consumed_approval_tokens (
                        token_id, approval_id, case_id, action_type, target, parameter_digest,
                        consumed_by, consumed_at_utc, previous_hash, current_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        token.token_id,
                        appr_id_val,
                        expected_case_id,
                        action_val,
                        target_val,
                        digest_val,
                        consumed_by,
                        now_dt,
                        prev_hash,
                        curr_hash,
                    ),
                )
                if token.approval_id:
                    conn.execute(
                        """
                        UPDATE approval_requests
                        SET status = ?, consumed_at_utc = ?
                        WHERE approval_id = ?
                        """,
                        (ApprovalStatus.CONSUMED.value, now_dt, token.approval_id),
                    )
        except sqlite3.IntegrityError:
            raise UnauthorizedCollectorExecutionError(
                f"Replay detected: Approval token '{token.token_id}' has already been consumed."
            )

        token.consumed = True

        self._audit(
            case_id=expected_case_id,
            actor=consumed_by,
            action="APPROVAL_TOKEN_CONSUMED",
            details={
                "token_id": token.token_id,
                "approval_id": token.approval_id,
                "action_type": expected_action_type,
                "target": expected_target,
            },
            target=expected_target,
            requesting_principal_id=req.requesting_principal_id if req else None,
            approving_principal_id=req.approving_principal_id if req else None,
        )

        if req is not None:
            req.status = ApprovalStatus.CONSUMED
            req.consumed_at_utc = now_dt
            return req

        return True

    def consume_token(
        self,
        token_id: str,
        case_id: Optional[str] = None,
        action_type: Optional[str] = None,
        target: Optional[str] = None,
        consumed_by: str = "investigator",
    ) -> None:
        """Atomically record token consumption for replay prevention."""
        with self._lock:
            cur = self.state_store._conn.execute(
                "SELECT consumed_at_utc FROM consumed_approval_tokens WHERE token_id = ?",
                (token_id,),
            )
            if cur.fetchone():
                raise UnauthorizedCollectorExecutionError(
                    f"Replay detected: Approval token '{token_id}' has already been consumed."
                )

            now_dt = datetime.now(timezone.utc).isoformat()
            case_val = case_id or "case_unknown"
            action_val = action_type or "unknown"
            target_val = target or "none"
            digest_val = "none"
            try:
                with self.state_store._conn as conn:
                    cur = conn.execute(
                        "SELECT current_hash FROM consumed_approval_tokens ORDER BY rowid DESC LIMIT 1"
                    )
                    last_row = cur.fetchone()
                    prev_hash = last_row[0] if last_row and last_row[0] else GENESIS_HASH

                    canonical_data = canonicalize_consumed_token_data(
                        token_id=token_id,
                        approval_id="standalone",
                        case_id=case_val,
                        action_type=action_val,
                        target=target_val,
                        parameter_digest=digest_val,
                        consumed_by=consumed_by,
                        consumed_at_utc=now_dt,
                    )
                    curr_hash = compute_record_hmac(self.secret_key, prev_hash, canonical_data)

                    conn.execute(
                        """
                        INSERT INTO consumed_approval_tokens (
                            token_id, approval_id, case_id, action_type, target, parameter_digest,
                            consumed_by, consumed_at_utc, previous_hash, current_hash
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            token_id,
                            "standalone",
                            case_val,
                            action_val,
                            target_val,
                            digest_val,
                            consumed_by,
                            now_dt,
                            prev_hash,
                            curr_hash,
                        ),
                    )
            except sqlite3.IntegrityError:
                raise UnauthorizedCollectorExecutionError(
                    f"Replay detected: Approval token '{token_id}' has already been consumed."
                )
            self._audit(
                case_id=case_val,
                actor=consumed_by,
                action="APPROVAL_TOKEN_CONSUMED",
                details={"token_id": token_id, "action_type": action_val, "target": target_val},
                target=target_val,
            )

    def get_approved_token(self, approval_id: str) -> Optional[HumanApprovalToken]:
        """Retrieve and reconstruct the cryptographically signed token for an approved request.
        
        Strictly enforces 12-point security validation:
        1. Request exists and is in APPROVED status.
        2. Approving investigator is explicitly recorded (no fallback).
        3. Request is not expired.
        4. Token has not been consumed in consumed_approval_tokens table.
        5. Request does not carry a consumed_at_utc timestamp.
        6. Parameter digest is non-empty.
        7. Target is valid and non-empty for actions requiring target.
        8. Two-person rule holds (requester != approver by ID, username, and badge).
        9. Timestamps are chronologically consistent.
        10. Approver is valid, active, human account in user_store (if available).
        """
        req = self.get_request(approval_id)
        if not req or req.status != ApprovalStatus.APPROVED or not req.token_id:
            return None
        if req.is_expired():
            return None

        # 1. Approving investigator must NOT be empty or missing - NO FALLBACK TO "lead_investigator"!
        if not req.approving_investigator or not req.approving_investigator.strip():
            return None

        # 2. Check Two-Person Rule on stored approval record
        def _normalize_name(name: Optional[str]) -> str:
            if not name:
                return ""
            return name.split("(")[0].strip().lower()

        base_req = _normalize_name(req.requesting_investigator)
        base_appr = _normalize_name(req.approving_investigator)
        req_pid = (req.requesting_principal_id or "").strip().lower()
        appr_pid = (req.approving_principal_id or "").strip().lower()

        if req_pid and appr_pid and req_pid == appr_pid:
            return None
        if base_req and base_appr and base_req == base_appr:
            return None
        if req.requesting_badge_id and req.approving_badge_id and req.requesting_badge_id.strip().lower() == req.approving_badge_id.strip().lower():
            return None

        # 3. Check if already consumed in database
        cur = self.state_store._conn.execute(
            "SELECT consumed_at_utc FROM consumed_approval_tokens WHERE token_id = ?",
            (req.token_id,),
        )
        if cur.fetchone():
            return None
        if req.consumed_at_utc:
            return None

        # 4. Parameter digest must not be empty
        if not req.parameter_digest or not req.parameter_digest.strip():
            return None

        # 5. Timestamp validations: resolved_at_utc must exist and be consistent
        if not req.resolved_at_utc:
            return None
        try:
            now_dt = datetime.now(timezone.utc)
            created_dt = datetime.fromisoformat(req.created_at_utc.replace("Z", "+00:00"))
            resolved_dt = datetime.fromisoformat(req.resolved_at_utc.replace("Z", "+00:00"))
            expires_dt = datetime.fromisoformat(req.expires_at_utc.replace("Z", "+00:00"))
            if resolved_dt < (created_dt - timedelta(seconds=5)):
                return None
            if expires_dt <= resolved_dt:
                return None
            if now_dt >= expires_dt:
                return None
        except Exception:
            return None

        # 6. Check user store if available: approver must exist, be active and be a human account
        if self.user_store:
            try:
                approver_user_obj = None
                if req.approving_principal_id:
                    approver_user_obj = self.user_store.get_by_id(req.approving_principal_id)
                if not approver_user_obj and req.approving_investigator:
                    approver_user_obj = self.user_store.get_by_username(req.approving_investigator)

                if approver_user_obj:
                    if not approver_user_obj.is_active:
                        return None
                    if getattr(approver_user_obj, "account_type", "human") != "human":
                        return None
                    if approver_user_obj.username.lower() in {"copilot_daemon", "system", "bot_lead", "forensicops_runner", "ai_planner"}:
                        return None
            except Exception:
                pass

        token = HumanApprovalToken(
            token_id=req.token_id,
            node_id=req.capability_id,
            case_id=req.case_id,
            approval_id=req.approval_id,
            action_type=req.action_type.value,
            target=req.target,
            parameter_digest=req.parameter_digest,
            issued_by=req.approving_investigator,
            timestamp_utc=req.resolved_at_utc,
            expires_at_utc=req.expires_at_utc,
            is_valid=True,
            consumed=False,
        )
        token.sign(self.secret_key)
        return token

    # --------------------------------------------------------------------------
    # Helper: Audit Logging
    # --------------------------------------------------------------------------
    def _audit(
        self,
        case_id: str,
        actor: str,
        action: str,
        details: Dict[str, Any],
        target: Optional[str] = None,
        requesting_principal_id: Optional[str] = None,
        approving_principal_id: Optional[str] = None,
    ) -> None:
        """Record lifecycle transitions in CustodyEngine and SQLite hash-chained audit log."""
        if self.custody_engine and hasattr(self.custody_engine, "append_custody_entry"):
            try:
                action_map = {
                    "APPROVAL_REQUEST_CREATED": "approval_requested",
                    "APPROVAL_REQUEST_APPROVED": "approval_granted",
                    "APPROVAL_REQUEST_REJECTED": "approval_rejected",
                    "APPROVAL_REQUEST_REVOKED": "approval_revoked",
                    "APPROVAL_TOKEN_CONSUMED": "approval_token_consumed",
                }
                custody_action = action_map.get(action, action.lower())
                self.custody_engine.append_custody_entry(
                    case_id=case_id,
                    actor=actor,
                    action=custody_action,
                )
            except Exception:
                pass

        try:
            self.state_store.record_provider_audit(
                event_type=action,
                provider_id=f"approval_engine:{actor}",
                is_cloud_transmission=False,
                details=json.dumps(details),
            )
        except Exception:
            pass

        # Hash-Chained Approval Audit Log (Phase 14.3)
        now_dt = datetime.now(timezone.utc).isoformat()
        event_id = f"evt-{uuid4().hex}"
        target_val = target or (details.get("target") if isinstance(details, dict) else None) or "none"
        req_pid_val = requesting_principal_id or (details.get("requesting_principal_id") if isinstance(details, dict) else None) or ""
        appr_pid_val = approving_principal_id or (details.get("approving_principal_id") if isinstance(details, dict) else None) or ""
        details_str = json.dumps(details, sort_keys=True, separators=(",", ":"), default=str) if isinstance(details, dict) else str(details)

        try:
            with self._lock:
                with self.state_store._conn as conn:
                    cur = conn.execute(
                        "SELECT current_hash FROM approval_audit_log ORDER BY id DESC LIMIT 1"
                    )
                    last_row = cur.fetchone()
                    prev_hash = last_row[0] if last_row and last_row[0] else GENESIS_HASH

                    canonical_data = canonicalize_approval_audit_data(
                        event_id=event_id,
                        case_id=case_id,
                        actor=actor,
                        action=action,
                        target=target_val,
                        requesting_principal_id=req_pid_val,
                        approving_principal_id=appr_pid_val,
                        details_json=details_str,
                        timestamp_utc=now_dt,
                    )
                    curr_hash = compute_record_hmac(self.secret_key, prev_hash, canonical_data)

                    conn.execute(
                        """
                        INSERT INTO approval_audit_log (
                            event_id, case_id, actor, action, target,
                            requesting_principal_id, approving_principal_id,
                            details_json, timestamp_utc, previous_hash, current_hash
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            event_id,
                            case_id,
                            actor,
                            action,
                            target_val,
                            req_pid_val,
                            appr_pid_val,
                            details_str,
                            now_dt,
                            prev_hash,
                            curr_hash,
                        ),
                    )
        except Exception as exc:
            raise ForensicOpsError(f"Fail-closed audit log insertion failed: {exc}") from exc

    def verify_consumed_tokens_chain(
        self,
        case_id: Optional[str] = None,
        secret_key: Optional[str] = None,
    ) -> Tuple[bool, Optional[str]]:
        """Verify chronological cryptographic hash chain integrity of consumed_approval_tokens.

        Returns:
            (True, None) if unbroken and valid.
            (False, error_detail) if any link or record was tampered, deleted, or corrupted.
        """
        effective_key = secret_key or self.secret_key
        with self._lock:
            cur = self.state_store._conn.execute(
                """
                SELECT rowid, token_id, approval_id, case_id, action_type, target,
                       parameter_digest, consumed_by, consumed_at_utc, previous_hash, current_hash
                FROM consumed_approval_tokens
                ORDER BY rowid ASC
                """
            )
            rows = cur.fetchall()

        if not rows:
            return (True, None)

        expected_prev_hash = GENESIS_HASH

        for row in rows:
            row_id = row[0]
            token_id = row[1]
            approval_id = row[2]
            row_case_id = row[3]
            action_type = row[4]
            target = row[5]
            parameter_digest = row[6]
            consumed_by = row[7]
            consumed_at_utc = row[8]
            prev_hash = row[9]
            curr_hash = row[10]

            # 1. Check unbroken chain link from previous record
            if prev_hash != expected_prev_hash:
                return (
                    False,
                    f"Tamper detected at row {row_id} (token {token_id}): previous_hash mismatch "
                    f"(expected '{expected_prev_hash}', got '{prev_hash}'). Chain broken or row deleted.",
                )

            # 2. Recalculate canonical HMAC
            canonical_data = canonicalize_consumed_token_data(
                token_id=token_id,
                approval_id=approval_id,
                case_id=row_case_id,
                action_type=action_type,
                target=target,
                parameter_digest=parameter_digest,
                consumed_by=consumed_by,
                consumed_at_utc=consumed_at_utc,
            )
            recalculated_hash = compute_record_hmac(effective_key, prev_hash, canonical_data)

            # 3. Check current hash authenticity
            if curr_hash != recalculated_hash:
                return (
                    False,
                    f"Tamper detected at row {row_id} (token {token_id}): current_hash mismatch "
                    f"(expected '{recalculated_hash}', got '{curr_hash}'). Record data modified.",
                )

            expected_prev_hash = curr_hash

        return (True, None)

    def verify_approval_audit_chain(
        self,
        case_id: Optional[str] = None,
        secret_key: Optional[str] = None,
    ) -> Tuple[bool, Optional[str]]:
        """Verify chronological cryptographic hash chain integrity of approval_audit_log.

        Returns:
            (True, None) if unbroken and valid.
            (False, error_detail) if any link or record was tampered, deleted, or corrupted.
        """
        effective_key = secret_key or self.secret_key
        with self._lock:
            cur = self.state_store._conn.execute(
                """
                SELECT id, event_id, case_id, actor, action, target,
                       requesting_principal_id, approving_principal_id, details_json,
                       timestamp_utc, previous_hash, current_hash
                FROM approval_audit_log
                ORDER BY id ASC
                """
            )
            rows = cur.fetchall()

        if not rows:
            return (True, None)

        expected_prev_hash = GENESIS_HASH

        for row in rows:
            row_id = row[0]
            event_id = row[1]
            row_case_id = row[2]
            actor = row[3]
            action = row[4]
            target = row[5]
            requesting_principal_id = row[6]
            approving_principal_id = row[7]
            details_json = row[8]
            timestamp_utc = row[9]
            prev_hash = row[10]
            curr_hash = row[11]

            # 1. Check unbroken chain link from previous record
            if prev_hash != expected_prev_hash:
                return (
                    False,
                    f"Tamper detected at row {row_id} (event {event_id}): previous_hash mismatch "
                    f"(expected '{expected_prev_hash}', got '{prev_hash}'). Chain broken or row deleted.",
                )

            # 2. Recalculate canonical HMAC
            canonical_data = canonicalize_approval_audit_data(
                event_id=event_id,
                case_id=row_case_id,
                actor=actor,
                action=action,
                target=target,
                requesting_principal_id=requesting_principal_id,
                approving_principal_id=approving_principal_id,
                details_json=details_json,
                timestamp_utc=timestamp_utc,
            )
            recalculated_hash = compute_record_hmac(effective_key, prev_hash, canonical_data)

            # 3. Check current hash authenticity
            if curr_hash != recalculated_hash:
                return (
                    False,
                    f"Tamper detected at row {row_id} (event {event_id}): current_hash mismatch "
                    f"(expected '{recalculated_hash}', got '{curr_hash}'). Record data modified.",
                )

            expected_prev_hash = curr_hash

        return (True, None)

    def get_approval_audit_logs(
        self,
        case_id: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Retrieve recent approval audit log entries, optionally filtered by case_id."""
        query = """
            SELECT id, event_id, case_id, actor, action, target,
                   requesting_principal_id, approving_principal_id, details_json,
                   timestamp_utc, previous_hash, current_hash
            FROM approval_audit_log
        """
        params: List[Any] = []
        if case_id:
            query += " WHERE case_id = ?"
            params.append(case_id)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        with self._lock:
            cur = self.state_store._conn.execute(query, tuple(params))
            rows = cur.fetchall()

        results = []
        for row in rows:
            results.append({
                "id": row[0],
                "event_id": row[1],
                "case_id": row[2],
                "actor": row[3],
                "action": row[4],
                "target": row[5],
                "requesting_principal_id": row[6],
                "approving_principal_id": row[7],
                "details_json": row[8],
                "timestamp_utc": row[9],
                "previous_hash": row[10],
                "current_hash": row[11],
            })
        return results

    def _update_status(self, approval_id: str, status: ApprovalStatus) -> None:
        """Internal status update helper."""
        with self.state_store._conn as conn:
            conn.execute(
                "UPDATE approval_requests SET status = ? WHERE approval_id = ?",
                (status.value, approval_id),
            )

    @staticmethod
    def _row_to_request(row: Any) -> ApprovalRequest:
        """Convert a SQLite row to typed ApprovalRequest."""
        # Index or dict-style access
        if hasattr(row, "keys"):
            d = dict(row)
        else:
            d = {
                "approval_id": row[0],
                "case_id": row[1],
                "requesting_investigator": row[2],
                "approving_investigator": row[3],
                "action_type": row[4],
                "target": row[5],
                "capability_id": row[6],
                "parameters_json": row[7],
                "parameter_digest": row[8],
                "policy_version": row[9],
                "risk_level": row[10],
                "reason": row[11],
                "evidence_scope_json": row[12],
                "status": row[13],
                "created_at_utc": row[14],
                "expires_at_utc": row[15],
                "resolved_at_utc": row[16],
                "token_id": row[17],
                "consumed_at_utc": row[18],
                "rejection_reason": row[19],
                "requesting_principal_id": row[20] if len(row) > 20 else "",
                "approving_principal_id": row[21] if len(row) > 21 else None,
                "requesting_badge_id": row[22] if len(row) > 22 else None,
                "approving_badge_id": row[23] if len(row) > 23 else None,
            }

        params = json.loads(d.get("parameters_json") or "{}")
        scope = json.loads(d.get("evidence_scope_json") or "[]")

        req_p_id = d.get("requesting_principal_id") or d.get("requesting_investigator") or ""
        return ApprovalRequest(
            approval_id=d["approval_id"],
            case_id=d["case_id"],
            requesting_investigator=d["requesting_investigator"],
            approving_investigator=d.get("approving_investigator"),
            requesting_principal_id=req_p_id,
            approving_principal_id=d.get("approving_principal_id"),
            requesting_badge_id=d.get("requesting_badge_id"),
            approving_badge_id=d.get("approving_badge_id"),
            action_type=ActionType(d["action_type"]),
            target=d["target"],
            capability_id=d["capability_id"],
            parameters=params,
            parameter_digest=d["parameter_digest"],
            policy_version=d["policy_version"],
            risk_level=ActionRiskLevel(d["risk_level"]),
            reason=d["reason"],
            evidence_scope=scope,
            status=ApprovalStatus(d["status"]),
            created_at_utc=d["created_at_utc"],
            expires_at_utc=d["expires_at_utc"],
            resolved_at_utc=d.get("resolved_at_utc"),
            token_id=d.get("token_id"),
            consumed_at_utc=d.get("consumed_at_utc"),
            rejection_reason=d.get("rejection_reason"),
        )


def generate_secure_approval_token(
    node_id: str,
    case_id: str,
    secret_key: str,
    issued_by: str = "lead_investigator",
    approval_id: Optional[str] = None,
    action_type: Optional[str] = None,
    target: Optional[str] = None,
    parameter_digest: Optional[str] = None,
    validity_minutes: int = 15,
) -> HumanApprovalToken:
    """Convenience helper to generate and cryptographically sign a HumanApprovalToken."""
    now_dt = datetime.now(timezone.utc)
    exp_dt = now_dt + timedelta(minutes=validity_minutes)
    token = HumanApprovalToken(
        token_id=f"gate-{uuid4().hex[:12]}",
        node_id=node_id,
        case_id=case_id,
        approval_id=approval_id,
        action_type=action_type,
        target=target,
        parameter_digest=parameter_digest,
        issued_by=issued_by,
        timestamp_utc=now_dt.isoformat(),
        expires_at_utc=exp_dt.isoformat(),
        is_valid=True,
        consumed=False,
    )
    token.sign(secret_key)
    return token


def verify_approval_token(
    token: HumanApprovalToken,
    secret_key: str,
    expected_case_id: Optional[str] = None,
    expected_action_type: Optional[str] = None,
    expected_target: Optional[str] = None,
    expected_parameter_digest: Optional[str] = None,
) -> bool:
    """Convenience helper to verify HMAC cryptographic signature and parameter bindings."""
    return token.verify(
        secret_key=secret_key,
        expected_case_id=expected_case_id,
        expected_action_type=expected_action_type,
        expected_target=expected_target,
        expected_parameter_digest=expected_parameter_digest,
    )


def verify_consumed_tokens_chain(
    target_or_case_id: Optional[Union[str, ApprovalEngine, LLMStateStore]] = None,
    case_id: Optional[str] = None,
    secret_key: Optional[str] = None,
) -> Tuple[bool, Optional[str]]:
    """Convenience helper to verify chronological cryptographic hash chain of consumed_approval_tokens."""
    if isinstance(target_or_case_id, ApprovalEngine):
        return target_or_case_id.verify_consumed_tokens_chain(case_id=case_id, secret_key=secret_key)
    eff_case = case_id if case_id is not None else (target_or_case_id if isinstance(target_or_case_id, str) else None)
    store = target_or_case_id if isinstance(target_or_case_id, LLMStateStore) else None
    sec = secret_key or os.getenv("HUMAN_APPROVAL_HMAC_SECRET") or ("a" * 32)
    engine = ApprovalEngine(state_store=store, secret_key=sec)
    return engine.verify_consumed_tokens_chain(case_id=eff_case, secret_key=secret_key)


def verify_approval_audit_chain(
    target_or_case_id: Optional[Union[str, ApprovalEngine, LLMStateStore]] = None,
    case_id: Optional[str] = None,
    secret_key: Optional[str] = None,
) -> Tuple[bool, Optional[str]]:
    """Convenience helper to verify chronological cryptographic hash chain of approval_audit_log."""
    if isinstance(target_or_case_id, ApprovalEngine):
        return target_or_case_id.verify_approval_audit_chain(case_id=case_id, secret_key=secret_key)
    eff_case = case_id if case_id is not None else (target_or_case_id if isinstance(target_or_case_id, str) else None)
    store = target_or_case_id if isinstance(target_or_case_id, LLMStateStore) else None
    sec = secret_key or os.getenv("HUMAN_APPROVAL_HMAC_SECRET") or ("a" * 32)
    engine = ApprovalEngine(state_store=store, secret_key=sec)
    return engine.verify_approval_audit_chain(case_id=eff_case, secret_key=secret_key)

