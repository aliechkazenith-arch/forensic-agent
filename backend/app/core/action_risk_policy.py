"""Central Action Risk Policy Engine.

Standards:
- Deterministic Policy Classification (AGENTS.md Rule 6 & 7):
  1. Read-only offline analysis: automatic if allowlisted.
  2. Local evidence modification: denied by default (RFC 3227 / AGENTS.md Rule 3).
  3. Remote collection: approval required.
  4. Remote access: approval required.
  5. Network access: approval required.
  6. Containment: approval required.
  7. Deletion: approval required and subject to retention policy.
  8. External sharing: approval required.
  9. Report finalization/signing: approval required.
  10. Unknown actions: blocked by default.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, ConfigDict, Field


class ActionRiskLevel(str, Enum):
    """Risk tier of a requested forensic or system action."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ActionType(str, Enum):
    """Classified category of forensic operations."""
    READ_ONLY_OFFLINE_ANALYSIS = "read_only_offline_analysis"
    LOCAL_EVIDENCE_MODIFICATION = "local_evidence_modification"
    REMOTE_COLLECTION = "remote_collection"
    REMOTE_ACCESS = "remote_access"
    NETWORK_ACCESS = "network_access"
    CONTAINMENT = "containment"
    DELETION = "deletion"
    EXTERNAL_SHARING = "external_sharing"
    REPORT_SIGNING = "report_signing"
    WORKFLOW_NODE_EXECUTION = "workflow_node_execution"
    UNKNOWN = "unknown"


# Central allowlist of deterministic offline analyzers
APPROVED_OFFLINE_CAPABILITIES: Set[str] = {
    # Tier A Userspace Dissect
    "dissect_evtx",
    "dissect_registry",
    "dissect_disk_stream",
    "dissect_collector",
    # Tier B Sandbox Plugins
    "ez_evtxecmd",
    "chainsaw_sigma",
    "ez_recmd",
    "volatility3_pslist",
    "yara_scanner",
    # Native Userspace Parsers
    "native_pcap_parser",
    "native_log_parser",
    "native_static_pe",
    "deterministic_correlation_engine",
    "timeline_window_tool",
    # Windows DFIR Operational Capabilities
    "windows_event_logs",
    "windows_sysmon",
    "windows_registry",
    "windows_powershell",
    "windows_lateral_movement",
    # Linux DFIR Operational Capabilities
    "linux_auth_logs",
    "linux_ssh_activity",
    "linux_sudo_privilege",
    "linux_cron_persistence",
    "linux_shell_history",
    # Memory Forensics Operational
    "memory_process_listing",
    # Network Forensics Operational
    "pcap_flow_analysis",
    "beaconing_detection",
    "suspicious_destination_detection",
    "host_communication_relationships",
    # Malware Analysis Operational
    "static_file_hashes",
    "static_file_metadata",
    "static_pe_metadata",
    "static_strings_extraction",
    "yara_signature_scan",
    # Timeline Correlation Operational
    "user_to_process_correlation",
    "process_to_network_correlation",
    "host_to_host_correlation",
    "authentication_to_execution_correlation",
    "persistence_to_execution_correlation",
    "cross_source_event_correlation",
}

# Explicitly denied operations
EXPLICITLY_DENIED_CAPABILITIES: Set[str] = {
    "local_evidence_modification",
    "modify_evidence",
    "overwrite_evidence",
    "write_vault_blob",
    "dynamic_sandbox_execution",
    "dynamic_malware_detonation",
    "cuckoo_sandbox",
    "arbitrary_shell_command",
    "host_exec",
}


class ActionPolicyEvaluation(BaseModel):
    """Deterministic evaluation of an action against forensic safety policies."""
    model_config = ConfigDict(extra="ignore")

    action_type: ActionType
    capability_id: str
    risk_level: ActionRiskLevel
    is_allowed: bool
    requires_approval: bool
    policy_reason: str
    policy_version: str = "1.0.0"


class ActionRiskPolicy:
    """Central deterministic policy engine classifying requested operations."""

    VERSION = "1.0.0"

    @classmethod
    def classify_action_type(cls, action_type: str, capability_id: str) -> ActionType:
        """Map raw action strings or capability IDs to standardized ActionType."""
        raw = f"{action_type} {capability_id}".lower()

        # 1. Evidence modification (denied by default)
        if any(k in raw for k in ("modify_evidence", "evidence_modification", "overwrite_blob", "write_blob")):
            return ActionType.LOCAL_EVIDENCE_MODIFICATION

        # 2. Deletion (approval required)
        if any(k in raw for k in ("delete", "purge", "wipe", "unlink", "drop_table")):
            return ActionType.DELETION

        # 3. Containment (approval required)
        if any(k in raw for k in ("containment", "isolate_host", "kill_process", "block_ip", "remediation")):
            return ActionType.CONTAINMENT

        # 4. Remote Collection (approval required)
        if any(k in raw for k in ("remote_collection", "ssh_collector", "winrm_collector", "endpoint_collection")):
            return ActionType.REMOTE_COLLECTION

        # 5. Remote Access (approval required)
        if any(k in raw for k in ("remote_access", "ssh_exec", "winrm_exec", "remote_shell")):
            return ActionType.REMOTE_ACCESS

        # 6. Network Access (approval required)
        if any(k in raw for k in ("network_access", "outbound_network", "external_dns", "download_tool")):
            return ActionType.NETWORK_ACCESS

        # 7. External Sharing (approval required)
        if any(k in raw for k in ("external_sharing", "share_vault", "export_external", "upload_threat_intel")):
            return ActionType.EXTERNAL_SHARING

        # 8. Report Finalization / Signing (approval required)
        if any(k in raw for k in ("report_signing", "finalize_report", "sign_report", "certify_report")):
            return ActionType.REPORT_SIGNING

        # 9. Read-only offline analysis
        if capability_id in APPROVED_OFFLINE_CAPABILITIES or any(
            k in raw for k in ("read_only", "tier_a_parser", "tier_b_tool", "store_query", "pivot_search")
        ):
            return ActionType.READ_ONLY_OFFLINE_ANALYSIS

        # 10. Workflow node execution
        if any(k in raw for k in ("workflow_node_execution", "workflow_execution", "dag_step")):
            return ActionType.WORKFLOW_NODE_EXECUTION

        return ActionType.UNKNOWN

    @classmethod
    def evaluate(
        cls,
        action_type: str,
        capability_id: str,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> ActionPolicyEvaluation:
        """Deterministically evaluate action request against risk policies."""
        cap_id = (capability_id or "").strip()
        classified = cls.classify_action_type(action_type, cap_id)

        # 1. Explicitly denied operations
        if cap_id in EXPLICITLY_DENIED_CAPABILITIES or classified == ActionType.LOCAL_EVIDENCE_MODIFICATION:
            return ActionPolicyEvaluation(
                action_type=ActionType.LOCAL_EVIDENCE_MODIFICATION,
                capability_id=cap_id,
                risk_level=ActionRiskLevel.CRITICAL,
                is_allowed=False,
                requires_approval=False,
                policy_reason="Operation denied: Evidence modification and dynamic malware detonation violate forensic integrity (RFC 3227 / AGENTS.md Rule 3).",
                policy_version=cls.VERSION,
            )

        # 2. Unknown operations (must be blocked)
        if classified == ActionType.UNKNOWN:
            return ActionPolicyEvaluation(
                action_type=ActionType.UNKNOWN,
                capability_id=cap_id,
                risk_level=ActionRiskLevel.CRITICAL,
                is_allowed=False,
                requires_approval=False,
                policy_reason=f"Operation '{cap_id}' blocked: Unknown or unclassified actions are denied by default.",
                policy_version=cls.VERSION,
            )

        # 3. Read-only offline analysis (automatic if allowlisted)
        if classified == ActionType.READ_ONLY_OFFLINE_ANALYSIS:
            if cap_id and cap_id not in APPROVED_OFFLINE_CAPABILITIES and not action_type in ("tier_a_parser", "store_query"):
                return ActionPolicyEvaluation(
                    action_type=ActionType.READ_ONLY_OFFLINE_ANALYSIS,
                    capability_id=cap_id,
                    risk_level=ActionRiskLevel.HIGH,
                    is_allowed=False,
                    requires_approval=False,
                    policy_reason=f"Capability '{cap_id}' is not in the approved offline forensic analyzer allowlist.",
                    policy_version=cls.VERSION,
                )

            return ActionPolicyEvaluation(
                action_type=ActionType.READ_ONLY_OFFLINE_ANALYSIS,
                capability_id=cap_id,
                risk_level=ActionRiskLevel.LOW,
                is_allowed=True,
                requires_approval=False,
                policy_reason="Approved read-only offline forensic analysis executes automatically.",
                policy_version=cls.VERSION,
            )

        # 4. Sensitive Operations requiring explicit human approval
        risk_map = {
            ActionType.REMOTE_COLLECTION: ActionRiskLevel.HIGH,
            ActionType.REMOTE_ACCESS: ActionRiskLevel.HIGH,
            ActionType.NETWORK_ACCESS: ActionRiskLevel.HIGH,
            ActionType.CONTAINMENT: ActionRiskLevel.CRITICAL,
            ActionType.DELETION: ActionRiskLevel.CRITICAL,
            ActionType.EXTERNAL_SHARING: ActionRiskLevel.HIGH,
            ActionType.REPORT_SIGNING: ActionRiskLevel.MEDIUM,
            ActionType.WORKFLOW_NODE_EXECUTION: ActionRiskLevel.MEDIUM,
        }

        reasons = {
            ActionType.REMOTE_COLLECTION: "Remote endpoint collection accesses live network assets and requires human approval.",
            ActionType.REMOTE_ACCESS: "Remote shell access or command execution on endpoints requires explicit human approval.",
            ActionType.NETWORK_ACCESS: "Outbound network transmission breaks air-gap policy and requires explicit human approval.",
            ActionType.CONTAINMENT: "Host containment or process termination alters target state and requires explicit human approval.",
            ActionType.DELETION: "Data or artifact deletion is destructive and requires human approval subject to retention policies.",
            ActionType.EXTERNAL_SHARING: "Transmitting case evidence outside local boundaries requires explicit human approval.",
            ActionType.REPORT_SIGNING: "Final forensic report certification and signing requires investigator approval.",
            ActionType.WORKFLOW_NODE_EXECUTION: "Workflow execution gate step requires investigator approval.",
        }

        return ActionPolicyEvaluation(
            action_type=classified,
            capability_id=cap_id,
            risk_level=risk_map.get(classified, ActionRiskLevel.HIGH),
            is_allowed=True,
            requires_approval=True,
            policy_reason=reasons.get(classified, "Sensitive operation requires explicit human approval."),
            policy_version=cls.VERSION,
        )
