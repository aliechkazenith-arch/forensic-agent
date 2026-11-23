"""Pydantic v2 data models for LangGraph Workflows and Edge Payloads.

Standards:
- Lightweight Edge Payloads: Never passes heavy raw row arrays over edges; passes
  DuckDB view pointers and extracted pivot entities (RFC 3227, NIST SP 800-86).
- Deterministic DAG Execution: Strict node and edge schema for n8n-style workflow canvas.
- Human Approval Gate: Verifiable cryptographic HumanApprovalToken for online/high-risk actions.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import hmac
import os
from typing import Any, Dict, List, Literal, Optional, Set, Union
from uuid import uuid4
from pydantic import BaseModel, ConfigDict, Field

from backend.app.models.findings import NodeGoalResult

NodeType = Literal[
    "evidence_input",
    "dissect_parser",
    "tool_runner",
    "ai_goal_step",
    "human_approval_gate",
    "report_compiler",
]


class WorkflowEdgePayload(BaseModel):
    """Lightweight context-passing payload passed along LangGraph DAG edges.
    
    Rather than carrying multi-megabyte raw row arrays, edges pass a queryable DuckDB
    view ID and extracted forensic entities (pivots) for downstream scoping.
    """
    model_config = ConfigDict(extra="ignore")

    dataset_pointer: Optional[str] = None  # DuckDB view name (e.g. 'view_evtx_logons_case123')
    pivots: Dict[str, List[str]] = Field(default_factory=dict)

    @property
    def users(self) -> List[str]:
        return self.pivots.get("compromised_users") or self.pivots.get("users") or []

    @property
    def ips(self) -> List[str]:
        return self.pivots.get("source_ips") or self.pivots.get("ips") or []

    @property
    def timestamps(self) -> List[str]:
        return self.pivots.get("pivot_timestamps_utc") or self.pivots.get("timestamps") or []

    @property
    def processes(self) -> List[str]:
        return self.pivots.get("process_names") or self.pivots.get("processes") or []

    @property
    def files(self) -> List[str]:
        return self.pivots.get("file_paths") or self.pivots.get("files") or []

    @property
    def hosts(self) -> List[str]:
        return self.pivots.get("hosts") or []

    @property
    def finding_ids(self) -> List[str]:
        return self.pivots.get("verified_finding_ids") or self.pivots.get("finding_ids") or []

    def add_pivot(self, entity_type: str, value: Union[str, List[str]]) -> None:
        """Add one or more values to a pivot entity category, deduplicating entries."""
        if not value:
            return
        vals = [value] if isinstance(value, str) else list(value)
        clean_vals = [v.strip() for v in vals if v and str(v).strip()]
        if not clean_vals:
            return

        current = self.pivots.get(entity_type, [])
        combined = list(dict.fromkeys(current + clean_vals))
        self.pivots[entity_type] = combined

    def merge(self, other: WorkflowEdgePayload) -> WorkflowEdgePayload:
        """Create a merged payload combining dataset pointers and union of all pivots."""
        new_pointer = other.dataset_pointer or self.dataset_pointer
        merged_pivots: Dict[str, List[str]] = {}

        all_keys: Set[str] = set(self.pivots.keys()) | set(other.pivots.keys())
        for key in all_keys:
            vals1 = self.pivots.get(key, [])
            vals2 = other.pivots.get(key, [])
            merged_pivots[key] = list(dict.fromkeys(vals1 + vals2))

        return WorkflowEdgePayload(
            dataset_pointer=new_pointer,
            pivots=merged_pivots,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dataset_pointer": self.dataset_pointer,
            "pivots": {k: list(v) for k, v in self.pivots.items()},
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> WorkflowEdgePayload:
        return cls(
            dataset_pointer=data.get("dataset_pointer"),
            pivots=data.get("pivots", {}),
        )


class WorkflowNode(BaseModel):
    """Definition of an individual step in a forensic DAG workflow."""
    id: str
    name: str
    type: NodeType
    config: Dict[str, Any] = Field(default_factory=dict)
    position: Optional[Dict[str, float]] = None  # { "x": float, "y": float } for React Flow


class WorkflowEdge(BaseModel):
    """Directed connection between workflow nodes, carrying WorkflowEdgePayload."""
    id: str = Field(default_factory=lambda: str(uuid4()))
    source: str
    target: str
    payload: Optional[WorkflowEdgePayload] = None


class HumanApprovalToken(BaseModel):
    """Analyst token authorizing high-risk / online collector actions."""
    model_config = ConfigDict(extra="ignore")

    token_id: str = Field(default_factory=lambda: str(uuid4()))
    node_id: str = "approval_gate"
    case_id: str
    approval_id: Optional[str] = None
    action_type: Optional[str] = None
    target: Optional[str] = None
    parameter_digest: Optional[str] = None
    issued_by: str = "analyst"
    timestamp_utc: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    expires_at_utc: Optional[str] = None
    signature: Optional[str] = None
    is_valid: bool = True
    consumed: bool = False

    def calculate_signature(self, secret_key: Optional[str] = None) -> str:
        """Compute standard HMAC-SHA256 signature for token verification."""
        effective_key = os.getenv("HUMAN_APPROVAL_HMAC_SECRET") if secret_key is None else secret_key
        if not effective_key or effective_key in ("forensicops-gate-secret", "default", "dev_approval_secret_replace_in_production", ""):
            raise ValueError(
                "Insecure configuration: HMAC secret must not be empty or default key (HUMAN_APPROVAL_HMAC_SECRET)."
            )
        canonical = f"{self.token_id}:{self.node_id}:{self.case_id}:{self.issued_by}:{self.timestamp_utc}"
        if self.approval_id or self.action_type or self.target or self.parameter_digest or self.expires_at_utc:
            canonical += (
                f":{self.approval_id or ''}:{self.action_type or ''}:{self.target or ''}"
                f":{self.parameter_digest or ''}:{self.expires_at_utc or ''}"
            )
        return hmac.new(effective_key.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()

    def sign(self, secret_key: Optional[str] = None) -> None:
        """Generate and assign signature."""
        self.signature = self.calculate_signature(secret_key)

    def is_expired(self, current_time: Optional[datetime] = None) -> bool:
        """Check whether the token has expired."""
        now = current_time or datetime.now(timezone.utc)
        if self.expires_at_utc:
            try:
                exp_dt = datetime.fromisoformat(self.expires_at_utc.replace("Z", "+00:00"))
                return now > exp_dt
            except Exception:
                return True
        try:
            ts_str = self.timestamp_utc.replace("Z", "+00:00")
            token_time = datetime.fromisoformat(ts_str)
            return (now - token_time).total_seconds() > 3600.0
        except Exception:
            return True

    def verify(
        self,
        secret_key: Optional[str] = None,
        max_age_seconds: float = 3600.0,
        expected_case_id: Optional[str] = None,
        expected_action_type: Optional[str] = None,
        expected_target: Optional[str] = None,
        expected_parameter_digest: Optional[str] = None,
    ) -> bool:
        """Verify token authenticity, expiration, and non-tampered state."""
        if not self.is_valid or self.consumed:
            return False
        if not self.signature:
            return False

        # Operation-specific bindings validation (Fail-Closed: SEC-APPR-001)
        if expected_case_id and self.case_id != expected_case_id:
            return False
        if expected_action_type and (not self.action_type or self.action_type != expected_action_type):
            return False
        if expected_target and (not self.target or self.target != expected_target):
            return False
        if expected_parameter_digest and (not self.parameter_digest or self.parameter_digest.lower() != expected_parameter_digest.lower()):
            return False

        # Expiration check
        now = datetime.now(timezone.utc)
        if self.expires_at_utc:
            try:
                exp_dt = datetime.fromisoformat(self.expires_at_utc.replace("Z", "+00:00"))
                if now > exp_dt:
                    return False
            except Exception:
                return False
        else:
            try:
                ts_str = self.timestamp_utc.replace("Z", "+00:00")
                token_time = datetime.fromisoformat(ts_str)
                diff = (now - token_time).total_seconds()
                if diff > max_age_seconds or diff < -300:
                    return False
            except Exception:
                return False

        try:
            expected = self.calculate_signature(secret_key)
        except ValueError:
            return False
        return secrets_equal(self.signature, expected)


def secrets_equal(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing attacks."""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


class WorkflowDefinition(BaseModel):
    """Specification of an entire workflow DAG."""
    workflow_id: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    description: str = ""
    nodes: List[WorkflowNode] = Field(default_factory=list)
    edges: List[WorkflowEdge] = Field(default_factory=list)
    version: str = "1.0"

    def get_node(self, node_id: str) -> Optional[WorkflowNode]:
        for n in self.nodes:
            if n.id == node_id:
                return n
        return None

    def get_outgoing_edges(self, node_id: str) -> List[WorkflowEdge]:
        return [e for e in self.edges if e.source == node_id]

    def get_incoming_edges(self, node_id: str) -> List[WorkflowEdge]:
        return [e for e in self.edges if e.target == node_id]


class WorkflowExecutionState(BaseModel):
    """Runtime state carried across LangGraph DAG execution."""
    case_id: str
    workflow_id: str
    current_node_id: Optional[str] = None
    completed_nodes: List[str] = Field(default_factory=list)
    node_results: Dict[str, NodeGoalResult] = Field(default_factory=dict)
    node_outputs: Dict[str, Any] = Field(default_factory=dict)
    edge_payloads: Dict[str, WorkflowEdgePayload] = Field(default_factory=dict)
    active_payload: WorkflowEdgePayload = Field(default_factory=WorkflowEdgePayload)
    approval_tokens: Dict[str, HumanApprovalToken] = Field(default_factory=dict)
    is_paused: bool = False
    pause_node_id: Optional[str] = None
    pause_reason: Optional[str] = None
    errors: List[str] = Field(default_factory=list)
    report: Optional[Dict[str, Any]] = None
