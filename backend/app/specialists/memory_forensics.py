"""Memory Forensics Investigation Specialist.

Standards:
- Deterministic Tooling: Volatility 3 executed exclusively inside isolated container sandbox.
- Explicit Truth in Advertising: Only volatility3_pslist is operational; pstree, netscan, dlllist, malfind are flagged non-operational.
- Fail-Closed: Never assume success merely because a YAML card exists; report runner/sandbox failures honestly.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.app.core.exceptions import SandboxUnavailableError
from backend.app.core.plugin_runner import PluginRunner
from backend.app.core.storage import ForensicStore
from backend.app.models.custody import ArtifactRecord
from backend.app.models.findings import ForensicFinding
from backend.app.models.investigation import EvidenceGap
from backend.app.models.plugins import ToolPluginCard
from backend.app.models.specialists import (
    BaseDFIRSpecialist,
    SpecialistCapabilityDefinition,
    SpecialistResult,
)


class MemoryForensicsSpecialist(BaseDFIRSpecialist):
    """Specialist module for volatile RAM memory analysis via sandboxed Volatility 3."""

    specialist_id = "memory_forensics"
    name = "Memory Forensics Specialist"
    domain = "volatile_memory"
    description = "Specialized volatile RAM analysis for running processes, hidden code injection, and open network sockets."

    supported_artifact_types = [
        "raw_memory",
        "memory",
        "vmem",
        "dmp",
        "lime",
    ]

    tool_allowlist = [
        "volatility3_pslist",
    ]

    capabilities = [
        SpecialistCapabilityDefinition(
            capability_id="memory_process_listing",
            name="Volatility 3 Process Listing (pslist)",
            description="Enumerates running processes from ActiveProcessLinks EPROCESS doubly-linked list.",
            operational=True,
            required_artifact_types=["memory", "raw_memory", "vmem", "dmp"],
            required_tools=["volatility3_pslist"],
            limitations=["Requires matching Volatility symbol tables (ISF) for the target OS build."],
        ),
        SpecialistCapabilityDefinition(
            capability_id="memory_process_tree",
            name="Volatility 3 Process Tree (pstree)",
            description="Reconstructs parent-child process hierarchy to identify orphaned or rogue processes.",
            operational=False,
            required_artifact_types=["memory", "raw_memory"],
            required_tools=["volatility3_pstree"],
            limitations=["Plugin card and container definition pending future release."],
        ),
        SpecialistCapabilityDefinition(
            capability_id="memory_network_connections",
            name="Volatility 3 Network Sockets (netscan)",
            description="Scans physical memory for TCP/UDP socket structures.",
            operational=False,
            required_artifact_types=["memory", "raw_memory"],
            required_tools=["volatility3_netscan"],
            limitations=["netscan plugin card pending integration."],
        ),
        SpecialistCapabilityDefinition(
            capability_id="memory_loaded_modules",
            name="Volatility 3 Module Listing (dlllist)",
            description="Inspects InLoadOrderModuleList for loaded DLLs and base addresses.",
            operational=False,
            required_artifact_types=["memory", "raw_memory"],
            required_tools=["volatility3_dlllist"],
            limitations=["dlllist plugin card pending integration."],
        ),
        SpecialistCapabilityDefinition(
            capability_id="memory_injection_indicators",
            name="Volatility 3 Injected Code Detection (malfind)",
            description="Finds hidden or injected code and memory segments with PAGE_EXECUTE_READWRITE protection.",
            operational=False,
            required_artifact_types=["memory", "raw_memory"],
            required_tools=["volatility3_malfind"],
            limitations=["malfind plugin card pending integration."],
        ),
        SpecialistCapabilityDefinition(
            capability_id="memory_command_line",
            name="Volatility 3 Process Command Lines (cmdline)",
            description="Extracts command-line arguments directly from PEB structures in memory.",
            operational=False,
            required_artifact_types=["memory", "raw_memory"],
            required_tools=["volatility3_cmdline"],
            limitations=["cmdline plugin card pending integration."],
        ),
    ]

    investigation_questions = [
        "What processes were actively executing when volatile memory was acquired?",
        "Are there unlinked or hidden processes not present in standard process listings?",
        "Are there memory segments with PAGE_EXECUTE_READWRITE permissions indicative of shellcode injection?",
        "Which active network connections were open at acquisition time?",
    ]

    limitations = [
        "Memory images represent a single point in time and can degrade if acquisition was delayed.",
        "Volatility 3 execution requires non-root Docker sandbox with network isolation.",
        "Process tree, netscan, dlllist, and malfind plugins are currently non-operational.",
    ]

    citation_requirements = [
        "All claims must cite exact Process IDs (PIDs), Parent PIDs (PPIDs), or Offset pointers in memory.",
        "Cryptographic SHA-256 hash of the memory image must be verified and cited.",
    ]

    def execute(
        self,
        case_id: str,
        artifacts: List[ArtifactRecord],
        storage: ForensicStore,
        custody_engine: Any,
        runner: Optional[Any] = None,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> SpecialistResult:
        """Execute sandboxed Volatility 3 analysis over authorized memory images."""
        params = parameters or {}
        requested_caps = params.get("capabilities", ["memory_process_listing"])

        findings: List[ForensicFinding] = []
        gaps: List[EvidenceGap] = []
        errors: List[str] = []
        unsupported: List[str] = []
        raw_outputs: List[Dict[str, Any]] = []

        # Check for requested capabilities that are not operational
        for cap_id in requested_caps:
            cap = self.get_capability(cap_id)
            if not cap or not cap.operational:
                unsupported.append(cap_id)
                gaps.append(
                    EvidenceGap(
                        missing_artifact_type="memory",
                        tactical_reason=f"Capability '{cap_id}' is not operational in Memory Forensics specialist.",
                        recommended_collection="Collect memory dump and run once analyzer plugin is deployed.",
                        is_evidence_of_absence=False,
                    )
                )

        relevant_artifacts = [a for a in artifacts if self.can_analyze(a.type or "")]
        if not relevant_artifacts:
            gaps.append(
                EvidenceGap(
                    missing_artifact_type="memory",
                    tactical_reason="No physical RAM or volatile memory image found in case vault.",
                    recommended_collection="Acquire live RAM image via WinPmem, LiME, or AVML.",
                    is_evidence_of_absence=False,
                )
            )
            return SpecialistResult(
                specialist_id=self.specialist_id,
                success=True,
                findings=[],
                evidence_gaps=gaps,
                unsupported_capabilities_requested=unsupported,
            )

        # Run operational volatility3_pslist if requested and available
        if "memory_process_listing" in requested_caps:
            for art in relevant_artifacts:
                plugins_dir = Path(os.environ.get("FORENSICOPS_PLUGINS_DIR", "plugins")).resolve()
                card_path = plugins_dir / "volatility3_pslist.yaml"

                if not card_path.is_file():
                    errors.append(f"Volatility plugin card not found: {card_path}")
                    continue

                card = ToolPluginCard.from_yaml_file(card_path)
                p_runner = runner or PluginRunner(custody_engine=custody_engine)

                workspace = Path(custody_engine.vault_root) / case_id if custody_engine else Path("vault") / case_id
                workspace.mkdir(parents=True, exist_ok=True)

                try:
                    res = p_runner.run_plugin(plugin=card, artifact=art, output_workspace=workspace)
                    if res.success:
                        findings.extend(res.findings)
                        raw_outputs.append({"artifact_id": art.artifact_id, "raw_output_path": res.raw_output_path})
                    else:
                        errors.extend(res.errors or [f"Volatility3 pslist failed: {res.exit_code}"])
                except SandboxUnavailableError as se:
                    # Fail-closed: report sandbox unavailability honestly
                    errors.append(f"Sandbox container runtime unavailable for memory analysis: {se}")
                except Exception as e:
                    errors.append(f"Execution error running Volatility 3: {e}")

        # Store findings in DuckDB
        if findings:
            storage.insert_findings(findings)

        return SpecialistResult(
            specialist_id=self.specialist_id,
            success=len(errors) == 0,
            findings=findings,
            evidence_gaps=gaps,
            raw_outputs=raw_outputs,
            errors=errors,
            unsupported_capabilities_requested=unsupported,
        )
