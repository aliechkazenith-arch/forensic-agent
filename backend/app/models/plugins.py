"""Pydantic v2 data models for Tool Plugins, Tool Cards, Auto-Mapping, and Execution.

Standards: Declarative Tool Adapters, Air-Gapped Sandboxing, RFC 3227
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Union
import yaml
from pydantic import BaseModel, ConfigDict, Field

from backend.app.models.findings import FindingSeverity, ForensicFinding


ExecutionTier = Literal["tier_a_builtin", "tier_b_adapter"]
InputType = Literal["file", "directory"]
OutputFormat = Literal["json", "jsonl", "csv"]


class ToolPluginCard(BaseModel):
    """Declarative specification for a forensic analysis tool card."""
    model_config = ConfigDict(extra="ignore")

    tool_id: str
    name: str
    version: str
    description: str
    author: Optional[str] = "ForensicOps AI"
    category: str  # e.g., "event_log", "registry", "memory", "sigma_detection", "yara_scan", "disk_triage"
    supported_artifact_types: List[str] = Field(default_factory=list)
    execution_tier: ExecutionTier = "tier_b_adapter"
    command_template: List[str] = Field(default_factory=list)
    container_image: Optional[str] = None
    input_type: InputType = "file"
    output_format: OutputFormat = "json"
    field_map: Dict[str, str] = Field(default_factory=dict)
    ai_keep_fields: List[str] = Field(default_factory=list)
    default_severity: FindingSeverity = "info"
    severity_field: Optional[str] = None
    severity_map: Dict[str, str] = Field(default_factory=dict)
    timeout_seconds: int = 300

    @classmethod
    def from_yaml_file(cls, file_path: Union[str, Path]) -> ToolPluginCard:
        """Load and validate a ToolPluginCard from a YAML file."""
        path = Path(file_path).resolve()
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict):
            raise ValueError(f"Invalid YAML tool card format in {path.name}: expected dictionary.")
        return cls(**data)

    def to_yaml_file(self, file_path: Union[str, Path]) -> None:
        """Export ToolPluginCard to a YAML file."""
        path = Path(file_path).resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        dump_dict = self.model_dump(exclude_none=True)
        with open(path, "w", encoding="utf-8") as f:
            yaml.safe_dump(dump_dict, f, sort_keys=False)


class DryRunAutoMapperResult(BaseModel):
    """Result of analyzing sample rows to auto-suggest field mappings and column projections."""
    suggested_field_map: Dict[str, str] = Field(default_factory=dict)
    suggested_ai_keep_fields: List[str] = Field(default_factory=list)
    confidence_scores: Dict[str, float] = Field(default_factory=dict)
    sample_raw_rows: List[Dict[str, Any]] = Field(default_factory=list)
    sample_projected_rows: List[Dict[str, Any]] = Field(default_factory=list)
    total_columns_inspected: int = 0
    detected_artifact_type: Optional[str] = None


class ToolExecutionResult(BaseModel):
    """Execution telemetry and normalized findings produced by a tool run."""
    tool_id: str
    success: bool
    exit_code: int
    findings_count: int = 0
    raw_rows_count: int = 0
    projected_rows_count: int = 0
    raw_columns_count: int = 0
    projected_columns_count: int = 0
    raw_output_path: Optional[str] = None
    findings: List[ForensicFinding] = Field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    execution_time_seconds: float = 0.0
    source_artifact_hash: str = ""
    tool_version: Optional[str] = None
    binary_digest: Optional[str] = None
    container_image: Optional[str] = None
    container_image_digest: Optional[str] = None
    parameters: List[str] = Field(default_factory=list)
    started_at_utc: Optional[str] = None
    finished_at_utc: Optional[str] = None
    input_artifact_hash: str = ""
    output_hashes: Dict[str, str] = Field(default_factory=dict)
    warnings: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    resource_metrics: Dict[str, Any] = Field(default_factory=dict)
