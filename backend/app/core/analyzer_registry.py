"""Centralized Typed Analyzer Registry for ForensicOps AI.

Standards:
- Typed capability declarations for Tier A (Dissect pure-python) and Tier B (containerized adapters).
- Explicit declaration of: Tool ID, Version, Supported Artifact Types, Execution Tier,
  Input Requirements, Output Schema, Resource Limits, and Capability Permissions.
- Rejection of unknown tools and unsupported artifact types.
- Zero advertisement of unsupported capabilities (e.g. no E01/VMDK userspace parsing).
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Set
from pydantic import BaseModel, ConfigDict, Field

from backend.app.core.exceptions import ExecutionPolicyError
from backend.app.core.execution_policy import ResourceLimits, get_execution_policy_registry
from backend.app.models.plugins import ToolPluginCard

ExecutionTier = Literal["tier_a_dissect", "tier_b_adapter"]


class AnalyzerDefinition(BaseModel):
    """Complete specification of a deterministic forensic analyzer."""
    model_config = ConfigDict(frozen=True)

    tool_id: str
    name: str
    version: str
    supported_artifact_types: List[str] = Field(default_factory=list)
    execution_tier: ExecutionTier
    input_requirements: Dict[str, Any] = Field(default_factory=dict)
    output_schema: Dict[str, Any] = Field(default_factory=dict)
    resource_limits: ResourceLimits = Field(default_factory=ResourceLimits)
    capability_permissions: List[str] = Field(default_factory=list)
    description: str = ""
    category: str = "triage"
    container_image: Optional[str] = None


# ------------------------------------------------------------------------------
# Built-In Tier A Analyzers (Pure-Python Dissect Adapter)
# ------------------------------------------------------------------------------
BUILTIN_TIER_A_ANALYZERS: Dict[str, AnalyzerDefinition] = {
    "dissect_evtx": AnalyzerDefinition(
        tool_id="dissect_evtx",
        name="Dissect Pure-Python EVTX Parser",
        version="1.0.0",
        supported_artifact_types=["evtx", "event_log"],
        execution_tier="tier_a_dissect",
        input_requirements={"type": "file", "magic_bytes": "ElfFile\x00", "extensions": [".evtx"]},
        output_schema={"format": "records", "entity": "ForensicFinding"},
        resource_limits=ResourceLimits(cpu_limit=1.0, memory_limit="1g", pids_limit=50),
        capability_permissions=["userspace_only", "no_network", "read_only_evidence"],
        description="Userspace binary chunk parser for Windows Event Logs (.evtx) without host mounting.",
        category="event_log",
    ),
    "dissect_registry": AnalyzerDefinition(
        tool_id="dissect_registry",
        name="Dissect Pure-Python Registry Hive Parser",
        version="1.0.0",
        supported_artifact_types=["registry", "hive", "system", "software", "sam", "ntuser"],
        execution_tier="tier_a_dissect",
        input_requirements={"type": "file", "magic_bytes": "regf", "extensions": [".hiv", ".dat", ".hive"]},
        output_schema={"format": "records", "entity": "ForensicFinding"},
        resource_limits=ResourceLimits(cpu_limit=1.0, memory_limit="1g", pids_limit=50),
        capability_permissions=["userspace_only", "no_network", "read_only_evidence"],
        description="Userspace hive parser for Windows Registry (SYSTEM, SOFTWARE, SAM, NTUSER.DAT).",
        category="registry",
    ),
    "dissect_disk_stream": AnalyzerDefinition(
        tool_id="dissect_disk_stream",
        name="Dissect Userspace Raw Disk Partition Inspector",
        version="1.0.0",
        supported_artifact_types=["raw_disk_stream", "raw_image", "dd", "raw", "img"],
        execution_tier="tier_a_dissect",
        input_requirements={"type": "file", "extensions": [".raw", ".dd", ".img"]},
        output_schema={"format": "records", "entity": "ForensicFinding"},
        resource_limits=ResourceLimits(cpu_limit=1.0, memory_limit="1g", pids_limit=50),
        capability_permissions=["userspace_only", "no_network", "read_only_evidence"],
        description="Inspects flat MBR and GPT partition tables in raw uncompressed disk streams without kernel mounting. Does NOT parse proprietary E01 or VMDK containers.",
        category="disk_partition",
    ),
    "dissect_collector": AnalyzerDefinition(
        tool_id="dissect_collector",
        name="Dissect Triage Collector Capsule Parser",
        version="1.0.0",
        supported_artifact_types=["collector_log", "collector_artifact", "json", "jsonl"],
        execution_tier="tier_a_dissect",
        input_requirements={"type": "file", "extensions": [".json", ".jsonl", ".txt", ".csv"]},
        output_schema={"format": "records", "entity": "ForensicFinding"},
        resource_limits=ResourceLimits(cpu_limit=1.0, memory_limit="1g", pids_limit=50),
        capability_permissions=["userspace_only", "no_network", "read_only_evidence"],
        description="Parses structured JSON/JSONL triage collector artifacts from Windows and Linux endpoints.",
        category="collector",
    ),
    "dissect_triage": AnalyzerDefinition(
        tool_id="dissect_triage",
        name="Dissect Userspace Triage Directory Extractor",
        version="1.0.0",
        supported_artifact_types=["triage_directory", "directory", "triage", "capsule_extracted", "folder"],
        execution_tier="tier_a_dissect",
        input_requirements={"type": "directory"},
        output_schema={"format": "records", "entity": "ForensicFinding"},
        resource_limits=ResourceLimits(cpu_limit=1.0, memory_limit="1g", pids_limit=50),
        capability_permissions=["userspace_only", "no_network", "read_only_evidence"],
        description="Inspects and recursively parses uncompressed triage folders or extracted capsule directories.",
        category="triage",
    ),
}


class AnalyzerRegistry:
    """Centralized typed registry holding all approved Tier A and Tier B analyzers."""

    def __init__(self, plugins_dir: Optional[Union[str, Path]] = None):
        self._analyzers: Dict[str, AnalyzerDefinition] = dict(BUILTIN_TIER_A_ANALYZERS)
        self.plugins_dir = Path(plugins_dir).resolve() if plugins_dir else Path(
            os.environ.get("FORENSICOPS_PLUGINS_DIR", "plugins")
        ).resolve()
        self._load_tier_b_plugins()

    def _load_tier_b_plugins(self) -> None:
        """Load and register declarative Tier B plugin cards from the plugins directory."""
        if not self.plugins_dir.is_dir():
            return

        policy_reg = get_execution_policy_registry()

        for yf in sorted(self.plugins_dir.glob("*.yaml")):
            try:
                card = ToolPluginCard.from_yaml_file(yf)
                policy = policy_reg.get_policy(card.tool_id)
                res_limits = policy.resource_limits if policy else ResourceLimits()

                analyzer = AnalyzerDefinition(
                    tool_id=card.tool_id,
                    name=card.name,
                    version=card.version or (policy.version if policy else "1.0.0"),
                    supported_artifact_types=list(card.supported_artifact_types),
                    execution_tier="tier_b_adapter",
                    input_requirements={"input_type": card.input_type},
                    output_schema={"format": card.output_format, "field_map": card.field_map},
                    resource_limits=res_limits,
                    capability_permissions=[
                        "sandbox_mandatory",
                        "network_none",
                        "read_only_evidence",
                        "controlled_output",
                        "drop_all_caps",
                    ],
                    description=card.description,
                    category=card.category,
                    container_image=card.container_image,
                )
                self._analyzers[card.tool_id] = analyzer
            except Exception:
                continue

    def get_analyzer(self, tool_id: str) -> Optional[AnalyzerDefinition]:
        """Retrieve analyzer definition by tool_id."""
        return self._analyzers.get(tool_id.lower())

    def list_analyzers(
        self,
        tier: Optional[ExecutionTier] = None,
        artifact_type: Optional[str] = None,
    ) -> List[AnalyzerDefinition]:
        """List all registered analyzers, optionally filtered by tier or artifact type."""
        results = list(self._analyzers.values())
        if tier:
            results = [a for a in results if a.execution_tier == tier]
        if artifact_type:
            atype_clean = artifact_type.lower()
            results = [
                a for a in results
                if "all" in a.supported_artifact_types
                or any(sat.lower() in atype_clean or atype_clean in sat.lower() for sat in a.supported_artifact_types)
            ]
        return results

    def validate_analyzer_request(
        self,
        tool_id: str,
        artifact_type: Optional[str] = None,
    ) -> AnalyzerDefinition:
        """Validate analyzer existence and artifact compatibility.
        
        Raises ExecutionPolicyError on unknown tool or incompatible artifact.
        """
        analyzer = self.get_analyzer(tool_id)
        if not analyzer:
            raise ExecutionPolicyError(
                f"Tool '{tool_id}' is not registered in the approved forensic analyzer registry."
            )

        if artifact_type:
            atype_clean = artifact_type.lower()
            # Explicit rejection of unsupported container formats
            if atype_clean in ("e01", "vmdk", "ewf"):
                raise ExecutionPolicyError(
                    f"Unsupported artifact container '{artifact_type}'. The system does not support "
                    f"userspace decompression of E01 or VMDK images without external kernel mounting."
                )

            if "all" not in analyzer.supported_artifact_types:
                supported = [s.lower() for s in analyzer.supported_artifact_types]
                if not any(sat in atype_clean or atype_clean in sat for sat in supported):
                    raise ExecutionPolicyError(
                        f"Artifact type '{artifact_type}' is not supported by analyzer '{tool_id}'. "
                        f"Supported artifact types: {analyzer.supported_artifact_types}"
                    )

        return analyzer


_default_analyzer_registry: Optional[AnalyzerRegistry] = None


def get_analyzer_registry() -> AnalyzerRegistry:
    """Retrieve global AnalyzerRegistry instance."""
    global _default_analyzer_registry
    if _default_analyzer_registry is None:
        _default_analyzer_registry = AnalyzerRegistry()
    return _default_analyzer_registry
