"""Pydantic v2 data models for Forensic Findings and Cited Claims.

Standards: RFC 3227, NIST SP 800-86, Anti-Hallucination Guardrails
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional
from uuid import uuid4
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class ExecutionState(str):
    """Execution state string with backwards-compatible equality for 'completed' and 'success'."""

    @classmethod
    def __get_pydantic_core_schema__(cls, source_type: Any, handler: Any) -> Any:
        from pydantic_core import core_schema

        def validate(val: Any) -> "ExecutionState":
            raw = str(val).lower()
            if raw == "success":
                return cls("completed")
            valid = {
                "completed",
                "partial",
                "needs_more_data",
                "failed",
                "blocked",
                "awaiting_approval",
            }
            if raw not in valid:
                raise ValueError(f"Invalid execution status '{val}'. Expected one of: {sorted(list(valid))}")
            return cls(raw)

        return core_schema.no_info_after_validator_function(
            validate,
            core_schema.str_schema(),
        )

    def __eq__(self, other: Any) -> bool:
        if str(self) == "completed" and other == "success":
            return True
        if str(self) == "success" and other == "completed":
            return True
        return super().__eq__(other)

    def __hash__(self) -> int:
        return super().__hash__()


ExecutionStatus = Literal[
    "completed",
    "partial",
    "needs_more_data",
    "failed",
    "blocked",
    "awaiting_approval",
    "success",
]

ClaimType = Literal[
    "observed_fact",
    "derived_fact",
    "derived_correlation",
    "hypothesis",
    "recommendation",
]
FindingSeverity = Literal["critical", "high", "medium", "low", "info"]


class ForensicFinding(BaseModel):
    """Normalized forensic fact produced deterministically by a parser or tool."""
    model_config = ConfigDict(frozen=True)

    finding_id: str = Field(default_factory=lambda: str(uuid4()))
    case_id: str
    source_artifact_id: str
    source_artifact_hash: str  # SHA-256 of the source artifact blob
    tool_id: str
    tool_version: Optional[str] = None
    timestamp_utc: Optional[str] = None
    artifact_type: str  # e.g., "evtx", "registry", "process", "network", "memory", "file", "yara"
    category: str  # e.g., "process_creation", "authentication", "persistence", "network_connection"
    event_id: Optional[str] = None
    severity: FindingSeverity = "info"
    host: Optional[str] = None
    user: Optional[str] = None
    process_name: Optional[str] = None
    command_line: Optional[str] = None
    raw_reference: Optional[str] = None  # record_id, line number, offset, hive path
    summary: str
    projected_data: Dict[str, Any] = Field(default_factory=dict)
    raw_data_path: Optional[str] = None

    def to_evidence_xml(self, nonce: str) -> str:
        """Wrap finding representation in untrusted evidence tags with nonce protection against IPI.

        Neutralizes XML tag breakout and prompt injection by escaping all '<' and '>' characters
        as standard JSON unicode escapes ('\\u003c' and '\\u003e') and redacting nonce occurrences.
        """
        payload = {
            "finding_id": self.finding_id,
            "timestamp_utc": self.timestamp_utc,
            "artifact_type": self.artifact_type,
            "category": self.category,
            "event_id": self.event_id,
            "severity": self.severity,
            "host": self.host,
            "user": self.user,
            "process_name": self.process_name,
            "command_line": self.command_line,
            "summary": self.summary,
            "projected_data": self.projected_data,
            "source_artifact_hash": self.source_artifact_hash,
        }
        json_body = json.dumps(payload, sort_keys=True, ensure_ascii=True)
        if nonce:
            json_body = json_body.replace(nonce, "[REDACTED_NONCE]")
        sanitized_json = (
            json_body.replace("</untrusted_evidence_data>", "&lt;/untrusted_evidence_data&gt;")
            .replace("</untrusted_evidence_data", "&lt;/untrusted_evidence_data")
            .replace("<untrusted_evidence_data", "&lt;untrusted_evidence_data")
            .replace("<", "\\u003c")
            .replace(">", "\\u003e")
        )
        return f'<untrusted_evidence_data nonce="{nonce}">{sanitized_json}</untrusted_evidence_data>'


class CitedClaim(BaseModel):
    """An analytical claim, fact, correlation, or hypothesis produced during investigation."""
    claim_id: str = Field(default_factory=lambda: str(uuid4()))
    claim_type: ClaimType
    statement: str
    citing_finding_ids: List[str] = Field(default_factory=list)
    source_artifact_hashes: List[str] = Field(default_factory=list)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    verification_status: Literal["VERIFIED", "NEEDS_REVIEW", "UNVERIFIED", "REJECTED"] = "UNVERIFIED"
    requires_analyst_review: bool = False
    review_notes: Optional[str] = None
    why_it_matters: Optional[str] = None
    benign_alternative: Optional[str] = None
    verification_steps: List[str] = Field(default_factory=list)
    data_gaps: List[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_citations_for_facts_and_correlations(self) -> CitedClaim:
        """Enforce non-negotiable rule: observed facts, derived facts and correlations must cite evidence."""
        if self.claim_type in ("observed_fact", "derived_fact"):
            if not self.citing_finding_ids:
                raise ValueError(
                    f"Claim type '{self.claim_type}' requires at least one non-empty finding_id in citing_finding_ids."
                )
            if not self.source_artifact_hashes:
                raise ValueError(
                    f"Claim type '{self.claim_type}' requires at least one non-empty source_artifact_hash."
                )
        elif self.claim_type == "derived_correlation":
            if not self.citing_finding_ids:
                raise ValueError(
                    f"Claim type '{self.claim_type}' requires at least one non-empty finding_id in citing_finding_ids."
                )
            if len(self.citing_finding_ids) < 2:
                raise ValueError(
                    "Claim type 'derived_correlation' requires at least two distinct citing finding IDs to correlate."
                )
            if not self.source_artifact_hashes:
                raise ValueError(
                    f"Claim type '{self.claim_type}' requires at least one non-empty source_artifact_hash."
                )
        return self


class NodeGoalResult(BaseModel):
    """Structured output result produced by an AI Goal Node, enforced via JSON Schema."""
    node_id: str
    status: ExecutionState = Field(default_factory=lambda: ExecutionState("completed"))
    summary: str
    claims: List[CitedClaim] = Field(default_factory=list)
    extracted_pivots: Dict[str, List[str]] = Field(default_factory=dict)
    recommended_next_actions: List[str] = Field(default_factory=list)
    confidence_score: float = Field(default=0.0, ge=0.0, le=1.0)


class HypothesisDraft(BaseModel):
    """Initial investigation hypothesis draft and analysis plan generated by LLM."""
    hypothesis_id: str = Field(default_factory=lambda: str(uuid4()))
    case_id: str
    investigation_goal: str
    threat_hypothesis: str
    benign_hypothesis: str
    key_questions: List[str] = Field(default_factory=list)
    recommended_blueprint: str = "windows_intrusion"
    cited_findings: List[CitedClaim] = Field(default_factory=list)
    suggested_steps: List[str] = Field(default_factory=list)
    confidence_score: float = Field(default=0.85, ge=0.0, le=1.0)
    created_at_utc: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    auto_approve: bool = True
    status: str = "COMPLETED"
    scoped_filters: Optional[Dict[str, Any]] = None
    plan_steps: List[Dict[str, Any]] = Field(default_factory=list)
    report: Optional[Dict[str, Any]] = None
    report_markdown: Optional[str] = None

