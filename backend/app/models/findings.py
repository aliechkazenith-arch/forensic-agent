"""Pydantic v2 data models for Forensic Findings and Cited Claims.

Standards: RFC 3227, NIST SP 800-86, Anti-Hallucination Guardrails
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional
from uuid import uuid4
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


ClaimType = Literal["observed_fact", "derived_correlation", "hypothesis", "recommendation"]
FindingSeverity = Literal["critical", "high", "medium", "low", "info"]


class ForensicFinding(BaseModel):
    """Normalized forensic fact produced deterministically by a parser or tool."""
    model_config = ConfigDict(frozen=True)

    finding_id: str = Field(default_factory=lambda: str(uuid4()))
    case_id: str
    source_artifact_id: str
    source_artifact_hash: str  # SHA-256 of the source artifact blob
    tool_id: str
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
        """Wrap finding representation in untrusted evidence tags with nonce protection against IPI."""
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
        return f'<untrusted_evidence_data nonce="{nonce}">{json_body}</untrusted_evidence_data>'


class CitedClaim(BaseModel):
    """An analytical claim, fact, correlation, or hypothesis produced during investigation."""
    claim_id: str = Field(default_factory=lambda: str(uuid4()))
    claim_type: ClaimType
    statement: str
    citing_finding_ids: List[str] = Field(default_factory=list)
    source_artifact_hashes: List[str] = Field(default_factory=list)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    why_it_matters: Optional[str] = None
    benign_alternative: Optional[str] = None
    verification_steps: List[str] = Field(default_factory=list)
    data_gaps: List[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_citations_for_facts_and_correlations(self) -> CitedClaim:
        """Enforce non-negotiable rule: observed facts and derived correlations must cite evidence."""
        if self.claim_type in ("observed_fact", "derived_correlation"):
            if not self.citing_finding_ids:
                raise ValueError(
                    f"Claim type '{self.claim_type}' requires at least one non-empty finding_id in citing_finding_ids."
                )
            if not self.source_artifact_hashes:
                raise ValueError(
                    f"Claim type '{self.claim_type}' requires at least one non-empty source_artifact_hash."
                )
        return self
