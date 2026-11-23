"""Windows DFIR Investigation Specialist.

Standards:
- Deterministic Tooling: Dissect and EvtxECmd/RECmd/Chainsaw parsers produce facts.
- Explicit Truth in Advertising: Only implemented analyzers are operational.
- Unsupported capabilities (Amcache, Shimcache, Prefetch) are explicitly advertised as non-operational.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

from backend.app.core.dissect_adapter import DissectAdapter
from backend.app.core.storage import ForensicStore
from backend.app.models.custody import ArtifactRecord
from backend.app.models.findings import ForensicFinding
from backend.app.models.investigation import EvidenceGap
from backend.app.models.specialists import (
    BaseDFIRSpecialist,
    SpecialistCapabilityDefinition,
    SpecialistResult,
)


class WindowsDFIRSpecialist(BaseDFIRSpecialist):
    """Specialist module for Windows endpoint investigation."""

    specialist_id = "windows_dfir"
    name = "Windows DFIR Specialist"
    domain = "windows_endpoint"
    description = "Specialized forensic investigation for Windows Event Logs, Registry, and lateral movement tradecraft."

    supported_artifact_types = [
        "evtx",
        "event_log",
        "registry",
        "reg",
        "amcache",
        "shimcache",
        "prefetch",
        "scheduled_tasks",
    ]

    tool_allowlist = [
        "dissect_evtx",
        "dissect_registry",
        "ez_evtxecmd",
        "ez_recmd",
        "chainsaw_sigma",
    ]

    capabilities = [
        SpecialistCapabilityDefinition(
            capability_id="windows_event_logs",
            name="Windows Event Log Analysis",
            description="Extracts logon, authentication, and process events from Security, System, and Application EVTX logs.",
            operational=True,
            required_artifact_types=["evtx", "event_log"],
            required_tools=["dissect_evtx", "ez_evtxecmd"],
        ),
        SpecialistCapabilityDefinition(
            capability_id="windows_sysmon",
            name="Windows Sysmon Intrusion Detection",
            description="Scans Sysmon events (Process Creation, Network Connect, Image Load) via Chainsaw Sigma rules.",
            operational=True,
            required_artifact_types=["evtx", "event_log"],
            required_tools=["chainsaw_sigma"],
        ),
        SpecialistCapabilityDefinition(
            capability_id="windows_registry",
            name="Windows Registry Hive Analysis",
            description="Parses SOFTWARE, SYSTEM, NTUSER.DAT hives for Run keys, UserAssist, and persistence entries.",
            operational=True,
            required_artifact_types=["registry", "reg"],
            required_tools=["dissect_registry", "ez_recmd"],
        ),
        SpecialistCapabilityDefinition(
            capability_id="windows_powershell",
            name="PowerShell Activity Analysis",
            description="Extracts script block execution and pipeline logs (Event IDs 4104, 4103).",
            operational=True,
            required_artifact_types=["evtx", "event_log"],
            required_tools=["dissect_evtx"],
        ),
        SpecialistCapabilityDefinition(
            capability_id="windows_lateral_movement",
            name="Lateral Movement Detection",
            description="Identifies network and RDP logons (Logon Types 3 and 10) from Security EVTX logs.",
            operational=True,
            required_artifact_types=["evtx", "event_log"],
            required_tools=["dissect_evtx"],
        ),
        SpecialistCapabilityDefinition(
            capability_id="windows_amcache",
            name="Amcache Program Execution Cache",
            description="Parses Amcache.hve for application inventory and execution metadata.",
            operational=False,
            required_artifact_types=["amcache"],
            required_tools=["amcache_parser"],
            limitations=["Dedicated standalone amcache analyzer container not yet integrated."],
        ),
        SpecialistCapabilityDefinition(
            capability_id="windows_shimcache",
            name="AppCompatCache (Shimcache)",
            description="Extracts application compatibility execution cache from SYSTEM hive.",
            operational=False,
            required_artifact_types=["registry", "shimcache"],
            required_tools=["appcompat_processor"],
            limitations=["Shimcache dedicated processor not yet containerized."],
        ),
        SpecialistCapabilityDefinition(
            capability_id="windows_prefetch",
            name="Prefetch Execution Artifacts",
            description="Parses .pf files for execution times, run counts, and referenced DLLs.",
            operational=False,
            required_artifact_types=["prefetch"],
            required_tools=["pecmd"],
            limitations=["PECmd container analyzer not yet deployed."],
        ),
        SpecialistCapabilityDefinition(
            capability_id="windows_scheduled_tasks",
            name="Scheduled Tasks Analysis",
            description="Inspects XML and job scheduled task definitions for persistence.",
            operational=False,
            required_artifact_types=["scheduled_tasks"],
            required_tools=["task_scheduler_parser"],
            limitations=["Task parser planned for future release."],
        ),
    ]

    investigation_questions = [
        "Were administrative credentials used for lateral movement (Logon Type 3 or 10)?",
        "Were persistence mechanisms registered in Registry Run keys or Service configurations?",
        "Was suspicious PowerShell script block execution recorded (Event ID 4104)?",
        "Which external hosts or accounts initiated remote logins?",
    ]

    limitations = [
        "Event logs reflect only events that were audited according to system audit policy.",
        "Log tampering or log clearing (Event ID 1102) must be checked before concluding lack of activity.",
        "Amcache, Shimcache, and Prefetch analyzers are currently non-operational.",
    ]

    citation_requirements = [
        "All claims must cite exact Event Record IDs or Registry Hive key paths.",
        "Cryptographic SHA-256 hash of the analyzed EVTX or hive file must be recorded.",
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
        """Execute Windows DFIR analysis over authorized case artifacts."""
        params = parameters or {}
        requested_caps = params.get("capabilities", ["windows_event_logs", "windows_registry"])
        
        findings: List[ForensicFinding] = []
        gaps: List[EvidenceGap] = []
        errors: List[str] = []
        unsupported: List[str] = []
        raw_outputs: List[Dict[str, Any]] = []

        dissect = DissectAdapter()

        # Check for requested capabilities that are not operational
        for cap_id in requested_caps:
            cap = self.get_capability(cap_id)
            if not cap or not cap.operational:
                unsupported.append(cap_id)
                gaps.append(
                    EvidenceGap(
                        missing_artifact_type=cap.required_artifact_types[0] if cap and cap.required_artifact_types else "unknown",
                        tactical_reason=f"Capability '{cap_id}' is not operational in Windows DFIR specialist.",
                        recommended_collection="Collect and ingest artifact once analyzer is deployed.",
                        is_evidence_of_absence=False,
                    )
                )

        # Filter relevant artifacts
        relevant_artifacts = [a for a in artifacts if self.can_analyze(a.type or "")]
        if not relevant_artifacts:
            gaps.append(
                EvidenceGap(
                    missing_artifact_type="evtx",
                    tactical_reason="No Windows Event Logs or Registry hives found in authorized evidence scope.",
                    recommended_collection="Acquire Windows Security.evtx and SYSTEM/SOFTWARE hives.",
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

        for art in relevant_artifacts:
            a_type = (art.type or "").lower()
            if not custody_engine:
                continue

            try:
                rpath = custody_engine.resolve_artifact_file(art)
                if not rpath.exists():
                    errors.append(f"Artifact file missing on disk: {rpath}")
                    continue

                if a_type in ("evtx", "event_log"):
                    evtx_findings = dissect.parse_evtx_stream(
                        rpath, case_id=case_id, artifact_id=art.artifact_id, artifact_hash=art.sha256
                    )
                    # Enrich with lateral movement and PowerShell categories
                    for f in evtx_findings:
                        # Event 4624 Logon Type 3 (Network) or 10 (RemoteInteractive)
                        summary_lower = (f.summary or "").lower()
                        proj = f.projected_data or {}
                        logon_type = str(proj.get("logon_type", ""))
                        if logon_type in ("3", "10") or "logon type 3" in summary_lower or "logon type 10" in summary_lower:
                            enriched_finding = ForensicFinding(
                                finding_id=f.finding_id,
                                case_id=f.case_id,
                                source_artifact_id=f.source_artifact_id,
                                source_artifact_hash=f.source_artifact_hash,
                                tool_id=f.tool_id,
                                tool_version=f.tool_version,
                                timestamp_utc=f.timestamp_utc,
                                artifact_type=f.artifact_type,
                                category="lateral_movement",
                                event_id=f.event_id,
                                severity="high" if logon_type == "10" else "medium",
                                host=f.host,
                                user=f.user,
                                process_name=f.process_name,
                                command_line=f.command_line,
                                raw_reference=f.raw_reference,
                                summary=f"Lateral Movement indicator: {f.summary}",
                                projected_data=f.projected_data,
                            )
                            findings.append(enriched_finding)
                        elif f.event_id == "4104" or "powershell" in summary_lower:
                            enriched_finding = ForensicFinding(
                                finding_id=f.finding_id,
                                case_id=f.case_id,
                                source_artifact_id=f.source_artifact_id,
                                source_artifact_hash=f.source_artifact_hash,
                                tool_id=f.tool_id,
                                tool_version=f.tool_version,
                                timestamp_utc=f.timestamp_utc,
                                artifact_type=f.artifact_type,
                                category="powershell_activity",
                                event_id=f.event_id,
                                severity="medium",
                                host=f.host,
                                user=f.user,
                                process_name=f.process_name,
                                command_line=f.command_line,
                                raw_reference=f.raw_reference,
                                summary=f.summary,
                                projected_data=f.projected_data,
                            )
                            findings.append(enriched_finding)
                        else:
                            findings.append(f)

                    raw_outputs.append({"artifact_id": art.artifact_id, "path": str(rpath), "count": len(evtx_findings)})

                elif a_type in ("registry", "reg", "amcache"):
                    reg_findings = dissect.parse_registry_hive_stream(
                        rpath, case_id=case_id, artifact_id=art.artifact_id, artifact_hash=art.sha256
                    )
                    findings.extend(reg_findings)
                    raw_outputs.append({"artifact_id": art.artifact_id, "path": str(rpath), "count": len(reg_findings)})

            except Exception as e:
                errors.append(f"Error parsing artifact '{art.artifact_id}': {e}")

        # Store findings into DuckDB
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
