"""Centralized Forensic Tool Execution Policy & Sandbox Configuration.

Standards:
- AGENTS.md Rule 6: Tool execution must use allowlisted capabilities, validated arguments,
  isolated workers, resource limits, and network denial by default.
- Fail-Closed: Unknown tools, unapproved container images, unvalidated arguments, or missing
  sandboxes are strictly rejected.
- Deterministic Provenance: Classifies tools by ID, binary, digest, version, and resource limits.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Literal, Optional, Set
from pydantic import BaseModel, ConfigDict, Field

from backend.app.core.exceptions import ExecutionPolicyError, UnsafePluginCardError
from backend.app.models.plugins import ToolPluginCard

RiskClassification = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]

DANGEROUS_ARG_PATTERNS = {";", "&", "|", "`", "$(", "${", "\n", "\r", "\x00"}


class ResourceLimits(BaseModel):
    """Resource constraints enforced on containerized tool workers."""
    model_config = ConfigDict(frozen=True)

    cpu_limit: float = 2.0
    memory_limit: str = "2g"
    pids_limit: int = 100
    tmpfs_size: str = "100m"


class ToolExecutionPolicy(BaseModel):
    """Policy specification defining allowed execution parameters for a forensic tool."""
    model_config = ConfigDict(frozen=True)

    tool_id: str
    name: str
    version: str
    approved_binary: str
    binary_digest: Optional[str] = None
    container_image: str
    container_image_digest: Optional[str] = None
    supported_artifact_types: List[str] = Field(default_factory=list)
    allowed_arguments: List[str] = Field(default_factory=list)
    disallowed_arguments: List[str] = Field(default_factory=list)
    max_timeout_seconds: int = 600
    resource_limits: ResourceLimits = Field(default_factory=ResourceLimits)
    network_disabled: bool = True
    read_only_evidence: bool = True
    controlled_output: bool = True
    risk_classification: RiskClassification = "HIGH"


# ==============================================================================
# Canonical Approved Tool Policies Registry
# ==============================================================================

APPROVED_POLICIES: Dict[str, ToolExecutionPolicy] = {
    "chainsaw_sigma": ToolExecutionPolicy(
        tool_id="chainsaw_sigma",
        name="WithSecure Chainsaw Sigma Engine",
        version="2.10.0",
        approved_binary="chainsaw",
        container_image="ghcr.io/forensicops/chainsaw:latest",
        supported_artifact_types=["evtx", "event_log"],
        allowed_arguments=["hunt", "{input_path}", "--rules", "rules/", "--json", "--mapping", "-s", "--output"],
        max_timeout_seconds=600,
        resource_limits=ResourceLimits(cpu_limit=2.0, memory_limit="2g", pids_limit=100),
        risk_classification="HIGH",
    ),
    "ez_evtxecmd": ToolExecutionPolicy(
        tool_id="ez_evtxecmd",
        name="Eric Zimmerman EvtxECmd",
        version="1.5.0",
        approved_binary="evtxecmd",
        container_image="ghcr.io/forensicops/ez-tools:latest",
        supported_artifact_types=["evtx", "event_log"],
        allowed_arguments=["-f", "{input_path}", "--json", "{output_dir}", "--csv", "--xml"],
        max_timeout_seconds=600,
        resource_limits=ResourceLimits(cpu_limit=2.0, memory_limit="2g", pids_limit=100),
        risk_classification="HIGH",
    ),
    "ez_recmd": ToolExecutionPolicy(
        tool_id="ez_recmd",
        name="Eric Zimmerman RECmd",
        version="1.4.0",
        approved_binary="recmd",
        container_image="ghcr.io/forensicops/ez-tools:latest",
        supported_artifact_types=["registry", "hive", "system", "software", "ntuser", "sam"],
        allowed_arguments=["-f", "{input_path}", "--json", "{output_dir}", "--csv", "--bn"],
        max_timeout_seconds=600,
        resource_limits=ResourceLimits(cpu_limit=2.0, memory_limit="2g", pids_limit=100),
        risk_classification="HIGH",
    ),
    "volatility3_pslist": ToolExecutionPolicy(
        tool_id="volatility3_pslist",
        name="Volatility 3 Windows PsList",
        version="2.7.0",
        approved_binary="vol",
        container_image="ghcr.io/forensicops/volatility3:latest",
        supported_artifact_types=["memory_dump", "raw_memory", "dmp", "lime"],
        allowed_arguments=["-f", "{input_path}", "-r", "json", "windows.pslist", "windows.info", "linux.pslist"],
        max_timeout_seconds=1200,
        resource_limits=ResourceLimits(cpu_limit=4.0, memory_limit="4g", pids_limit=100),
        risk_classification="HIGH",
    ),
    "yara_scanner": ToolExecutionPolicy(
        tool_id="yara_scanner",
        name="YARA Signature Scanner",
        version="4.5.0",
        approved_binary="yara",
        container_image="ghcr.io/forensicops/yara:latest",
        supported_artifact_types=["binary", "blob", "file", "memory_dump", "all"],
        allowed_arguments=["-s", "-j", "{rules_path}", "{input_path}", "-r", "-w"],
        max_timeout_seconds=600,
        resource_limits=ResourceLimits(cpu_limit=2.0, memory_limit="2g", pids_limit=100),
        risk_classification="HIGH",
    ),
    "safe_bin": ToolExecutionPolicy(
        tool_id="safe_bin",
        name="Safe Test Binary",
        version="1.0.0",
        approved_binary="safe_bin",
        container_image="ghcr.io/forensicops/safe_bin:latest",
        supported_artifact_types=["test", "evtx", "raw"],
        allowed_arguments=["-f", "{input_path}", "--json", "{output_dir}"],
        max_timeout_seconds=300,
        resource_limits=ResourceLimits(cpu_limit=1.0, memory_limit="512m", pids_limit=50),
        risk_classification="LOW",
    ),
}

# Approved container image registry namespaces
ALLOWED_IMAGE_PREFIXES = (
    "ghcr.io/forensicops/",
    "docker.io/forensicops/",
    "forensicops/",
)

ALLOWED_PATH_SUBSTITUTIONS = {"{input_path}", "{output_dir}", "{rules_path}"}


class ExecutionPolicyRegistry:
    """Manages policy validation for forensic tools, container images, and plugin cards."""

    def __init__(self, custom_policies: Optional[Dict[str, ToolExecutionPolicy]] = None):
        self._policies: Dict[str, ToolExecutionPolicy] = dict(APPROVED_POLICIES)
        if custom_policies:
            self._policies.update(custom_policies)

    def get_policy(self, tool_id: str) -> Optional[ToolExecutionPolicy]:
        return self._policies.get(tool_id.lower())

    def register_policy(self, policy: ToolExecutionPolicy) -> None:
        """Register or update a tool execution policy."""
        self._policies[policy.tool_id.lower()] = policy

    def validate_tool_execution(
        self,
        tool_id: str,
        argv: List[str],
        container_image: Optional[str] = None,
        timeout_seconds: Optional[int] = None,
        artifact_type: Optional[str] = None,
    ) -> ToolExecutionPolicy:
        """Validate execution parameters against the centralized policy.
        
        Raises ExecutionPolicyError on policy violation.
        """
        policy = self.get_policy(tool_id)
        if not policy:
            raise ExecutionPolicyError(
                f"Unknown tool '{tool_id}' is not in the approved forensic tool execution policy."
            )

        # 1. Validate container image
        if container_image:
            image_clean = container_image.strip()
            if image_clean != policy.container_image:
                # Must match approved prefix or exact image
                if not any(image_clean.startswith(prefix) for prefix in ALLOWED_IMAGE_PREFIXES):
                    raise ExecutionPolicyError(
                        f"Unapproved container image '{container_image}' for tool '{tool_id}'. "
                        f"Expected image '{policy.container_image}' or approved namespace {ALLOWED_IMAGE_PREFIXES}."
                    )

        # 2. Validate executable (argv[0])
        if not argv:
            raise ExecutionPolicyError("Empty command array.")

        exec_name = argv[0].lower().replace(".exe", "")
        approved_base = policy.approved_binary.lower().replace(".exe", "")
        if exec_name != approved_base and not exec_name.endswith(f"/{approved_base}"):
            raise ExecutionPolicyError(
                f"Binary '{argv[0]}' does not match approved binary '{policy.approved_binary}' for tool '{tool_id}'."
            )

        # 3. Validate timeout
        if timeout_seconds is not None:
            if timeout_seconds <= 0:
                raise ExecutionPolicyError(f"Timeout must be positive, got {timeout_seconds}s.")
            if timeout_seconds > policy.max_timeout_seconds:
                raise ExecutionPolicyError(
                    f"Requested timeout {timeout_seconds}s exceeds maximum policy limit of {policy.max_timeout_seconds}s for '{tool_id}'."
                )

        # 4. Validate artifact type if provided
        if artifact_type:
            atype_clean = artifact_type.lower()
            if "all" not in policy.supported_artifact_types:
                if not any(sat.lower() in atype_clean or atype_clean in sat.lower() for sat in policy.supported_artifact_types):
                    raise ExecutionPolicyError(
                        f"Artifact type '{artifact_type}' is not supported by tool '{tool_id}'. "
                        f"Supported types: {policy.supported_artifact_types}."
                    )

        # 5. Validate arguments against shell injection, disallowed arguments, and unauthorized flags (SEC-EXEC-003)
        for arg in argv[1:]:
            for danger in DANGEROUS_ARG_PATTERNS:
                if danger in arg:
                    raise ExecutionPolicyError(
                        f"Potentially unsafe shell metacharacter '{danger}' in argument: '{arg}'"
                    )

            if policy.disallowed_arguments:
                arg_clean = arg.strip().lower()
                for disallowed in policy.disallowed_arguments:
                    d_clean = disallowed.strip().lower()
                    if arg_clean == d_clean or arg_clean.startswith(f"{d_clean}=") or arg_clean.startswith(f"{d_clean}:"):
                        raise ExecutionPolicyError(
                            f"Argument '{arg}' is prohibited by execution policy for tool '{tool_id}'."
                        )

            if policy.allowed_arguments:
                if arg.startswith("-"):
                    flag_name = arg.split("=")[0].split(":")[0].strip()
                    allowed_flags = [a.split("=")[0].split(":")[0].strip() for a in policy.allowed_arguments]
                    if flag_name not in allowed_flags:
                        raise ExecutionPolicyError(
                            f"Option flag '{arg}' is not in allowed arguments for tool '{tool_id}'."
                        )

        return policy

    def validate_plugin_card(self, card: ToolPluginCard, allow_new: bool = False) -> None:
        """Validate a declarative YAML ToolPluginCard before registration or execution.
        
        Args:
            card: ToolPluginCard to validate
            allow_new: When True (e.g. during plugin registration by lead investigator),
                       permits new tool IDs provided they strictly comply with container isolation,
                       approved registry prefixes, command template safety, and resource limits.

        Raises UnsafePluginCardError on invalid or unsafe configuration.
        """
        if not card.tool_id or not card.name:
            raise UnsafePluginCardError("Plugin card requires non-empty 'tool_id' and 'name'.")

        if not re.match(r"^[a-zA-Z0-9_-]+$", card.tool_id):
            raise UnsafePluginCardError(
                f"Invalid 'tool_id' format '{card.tool_id}'. Must strictly match ^[a-zA-Z0-9_-]+$"
            )

        if card.execution_tier == "tier_b_adapter":
            # 1. Container image required for Tier B
            if not card.container_image:
                raise UnsafePluginCardError(
                    f"Tier B plugin '{card.tool_id}' requires a valid 'container_image'."
                )
            if not any(card.container_image.startswith(prefix) for prefix in ALLOWED_IMAGE_PREFIXES):
                raise UnsafePluginCardError(
                    f"Unapproved container image '{card.container_image}' in plugin '{card.tool_id}'. "
                    f"Must originate from approved registry: {ALLOWED_IMAGE_PREFIXES}"
                )

            # 2. Command template validation
            if not card.command_template:
                raise UnsafePluginCardError(
                    f"Plugin '{card.tool_id}' command_template cannot be empty."
                )

            # 3. Path substitution validation: only allowed template placeholders
            for token in card.command_template:
                # Find all {var} patterns
                placeholders = re.findall(r"\{[a-zA-Z0-9_]+\}", token)
                for ph in placeholders:
                    if ph not in ALLOWED_PATH_SUBSTITUTIONS:
                        raise UnsafePluginCardError(
                            f"Unsafe or unknown path substitution '{ph}' in command template of plugin '{card.tool_id}'. "
                            f"Allowed placeholders: {ALLOWED_PATH_SUBSTITUTIONS}"
                        )
                for danger in DANGEROUS_ARG_PATTERNS:
                    if danger in token:
                        raise UnsafePluginCardError(
                            f"Unsafe shell metacharacter '{danger}' in command template of plugin '{card.tool_id}'."
                        )

            # 4. Timeout validation: must be bounded
            if card.timeout_seconds <= 0 or card.timeout_seconds > 3600:
                raise UnsafePluginCardError(
                    f"Timeout {card.timeout_seconds}s for plugin '{card.tool_id}' is outside allowable bounds (1-3600s)."
                )

            # 5. Input and output formats
            if card.input_type not in ("file", "directory"):
                raise UnsafePluginCardError(
                    f"Unsupported input_type '{card.input_type}' in plugin '{card.tool_id}'."
                )

            if card.output_format not in ("json", "jsonl", "csv"):
                raise UnsafePluginCardError(
                    f"Unsupported output_format '{card.output_format}' in plugin '{card.tool_id}'."
                )

            # 6. Policy allowlist verification
            policy = self.get_policy(card.tool_id)
            if not policy and not allow_new:
                raise UnsafePluginCardError(
                    f"Tool ID '{card.tool_id}' is not in the approved forensic tool execution policy."
                )


_default_registry: Optional[ExecutionPolicyRegistry] = None


def get_execution_policy_registry() -> ExecutionPolicyRegistry:
    """Retrieve global ExecutionPolicyRegistry instance."""
    global _default_registry
    if _default_registry is None:
        _default_registry = ExecutionPolicyRegistry()
    return _default_registry
