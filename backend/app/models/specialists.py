"""Specialized DFIR Investigation Capability Models and Base Interface.

Standards:
- Deterministic Tooling Only (AGENTS.md Rule 1): Deterministic tools produce facts; LLMs plan, correlate, explain.
- Explicit Truth in Advertising: Only capabilities with implemented, tested analyzers are marked operational.
- Retain Source Observations & Provenance: Every correlation preserves source findings and deterministic method.
- Controlled Autonomy: Specialists are modular, typed capability units governed by InvestigationController.
- Safe Static Malware Only: Dynamic malware execution is strictly prohibited in normal forensic workers.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional
from uuid import uuid4
from pydantic import BaseModel, ConfigDict, Field

from backend.app.core.storage import ForensicStore
from backend.app.models.custody import ArtifactRecord
from backend.app.models.findings import ForensicFinding
from backend.app.models.investigation import EvidenceGap


class SpecialistCapabilityDefinition(BaseModel):
    """Specification of an individual investigative capability provided by a specialist."""
    model_config = ConfigDict(extra="ignore")

    capability_id: str
    name: str
    description: str
    operational: bool = False  # Must only be True if an actual analyzer is implemented and tested
    required_artifact_types: List[str] = Field(default_factory=list)
    required_tools: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)


class CorrelationRelationship(BaseModel):
    """Structured correlation relationship between two or more verified forensic observations."""
    model_config = ConfigDict(extra="ignore")

    relationship_id: str = Field(default_factory=lambda: f"rel-{uuid4().hex[:10]}")
    relationship_type: Literal[
        "user_to_process",
        "process_to_network",
        "host_to_host",
        "authentication_to_execution",
        "persistence_to_execution",
        "cross_source_event",
    ]
    source_finding_ids: List[str] = Field(default_factory=list)
    target_finding_ids: List[str] = Field(default_factory=list)
    confidence_score: float = Field(default=0.5, ge=0.0, le=1.0)
    description: str
    method: str  # e.g., "temporal_window_120s_user_match", "ip_port_flow_overlap"
    timestamp_utc: Optional[str] = None
    created_at_utc: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class SpecialistResult(BaseModel):
    """Structured, typed output produced by a specialist execution."""
    model_config = ConfigDict(extra="ignore")

    specialist_id: str
    success: bool = True
    findings: List[ForensicFinding] = Field(default_factory=list)
    correlations: List[CorrelationRelationship] = Field(default_factory=list)
    evidence_gaps: List[EvidenceGap] = Field(default_factory=list)
    pivots: Dict[str, List[str]] = Field(default_factory=dict)
    raw_outputs: List[Dict[str, Any]] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    unsupported_capabilities_requested: List[str] = Field(default_factory=list)


class BaseDFIRSpecialist(ABC):
    """Base class and contract for modular Level 3 DFIR Specialists."""

    specialist_id: str
    name: str
    domain: str
    description: str
    supported_artifact_types: List[str]
    tool_allowlist: List[str]
    capabilities: List[SpecialistCapabilityDefinition]
    investigation_questions: List[str]
    limitations: List[str]
    citation_requirements: List[str]

    def get_operational_capabilities(self) -> List[SpecialistCapabilityDefinition]:
        """Return only capabilities with real, verified, operational analyzers."""
        return [c for c in self.capabilities if c.operational]

    def get_capability(self, capability_id: str) -> Optional[SpecialistCapabilityDefinition]:
        """Find a capability by ID."""
        for c in self.capabilities:
            if c.capability_id == capability_id:
                return c
        return None

    def can_analyze(self, artifact_type: str) -> bool:
        """Check if specialist can analyze a given artifact type."""
        norm_type = (artifact_type or "").lower().strip()
        return norm_type in [t.lower() for t in self.supported_artifact_types]

    @abstractmethod
    def execute(
        self,
        case_id: str,
        artifacts: List[ArtifactRecord],
        storage: ForensicStore,
        custody_engine: Any,
        runner: Optional[Any] = None,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> SpecialistResult:
        """Execute specialist analysis over authorized evidence."""
        pass
