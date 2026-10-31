"""Pydantic v2 data models for chain of custody and artifact tracking.

Standards: RFC 3227, NIST SP 800-86, ISO/IEC 27037
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4
from pydantic import BaseModel, ConfigDict, Field, model_validator


def canonical_json_dump(data: Dict[str, Any]) -> str:
    """Serialize dictionary to canonical JSON representation (RFC 8785)."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class ArtifactRecord(BaseModel):
    """Immutable record of an ingested or referenced evidence artifact."""
    model_config = ConfigDict(frozen=True)

    artifact_id: str = Field(default_factory=lambda: str(uuid4()))
    case_id: str
    type: str
    original_path: str
    blob_path: str
    size_bytes: int
    sha256: str
    sha512: str
    acquired_utc: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    acquisition_method: str


class CustodyChainEntry(BaseModel):
    """Cryptographically chained ledger entry tracking every forensic operation."""
    model_config = ConfigDict(frozen=True)

    seq_id: int
    case_id: str
    timestamp_utc: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    actor: str
    action: str
    artifact_sha256: Optional[str] = None
    tool_id: Optional[str] = None
    prev_hash: str
    entry_hash: str

    def payload_dict(self) -> Dict[str, Any]:
        """Return the canonical payload dictionary excluding entry_hash."""
        return {
            "seq_id": self.seq_id,
            "case_id": self.case_id,
            "timestamp_utc": self.timestamp_utc,
            "actor": self.actor,
            "action": self.action,
            "artifact_sha256": self.artifact_sha256,
            "tool_id": self.tool_id,
        }

    @staticmethod
    def calculate_entry_hash(prev_hash: str, payload: Dict[str, Any]) -> str:
        """Compute entry_hash = sha256(prev_hash + canonical_json(entry))."""
        canonical_payload = canonical_json_dump(payload)
        return hashlib.sha256((prev_hash + canonical_payload).encode("utf-8")).hexdigest()

    def verify_hash(self) -> bool:
        """Verify that entry_hash matches the canonical payload + prev_hash."""
        expected = self.calculate_entry_hash(self.prev_hash, self.payload_dict())
        return self.entry_hash.lower() == expected.lower()


class ManifestArtifactEntry(BaseModel):
    """Artifact metadata item declared inside a collector capsule manifest.json."""
    artifact_id: str = Field(default_factory=lambda: str(uuid4()))
    type: str
    original_path: str
    bundle_path: str
    size_bytes: int
    sha256: str
    sha512: str
    acquired_utc: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    acquisition_method: str = "collector"


class CapsuleManifest(BaseModel):
    """Top-level schema for collector capsule manifest.json."""
    case_id: str
    created_utc: Optional[str] = None
    collector_version: Optional[str] = "4.0"
    artifacts: List[ManifestArtifactEntry] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def normalize_artifacts_key(cls, data: Any) -> Any:
        if isinstance(data, dict):
            # Support both 'artifacts' and 'collected_artifacts'
            if "collected_artifacts" in data and "artifacts" not in data:
                data["artifacts"] = data["collected_artifacts"]
        return data
