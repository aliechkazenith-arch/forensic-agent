"""Linux DFIR Investigation Specialist.

Standards:
- Deterministic Tooling: Native text log parsers and collectors produce facts.
- Explicit Truth in Advertising: Only implemented analyzers are operational.
- Unsupported capabilities (Systemd units, Auditd accounting) are flagged non-operational.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.app.agent.tools import parse_linux_text_log
from backend.app.core.storage import ForensicStore
from backend.app.models.custody import ArtifactRecord
from backend.app.models.findings import ForensicFinding
from backend.app.models.investigation import EvidenceGap
from backend.app.models.specialists import (
    BaseDFIRSpecialist,
    SpecialistCapabilityDefinition,
    SpecialistResult,
)


class LinuxDFIRSpecialist(BaseDFIRSpecialist):
    """Specialist module for Linux endpoint and server investigations."""

    specialist_id = "linux_dfir"
    name = "Linux DFIR Specialist"
    domain = "linux_endpoint"
    description = "Specialized forensic investigation for Linux authentication logs, SSH sessions, cron jobs, and shell history."

    supported_artifact_types = [
        "linux_log",
        "auth_log",
        "syslog",
        "shell_history",
        "cron",
        "systemd",
        "auditd",
    ]

    tool_allowlist = [
        "native_log_parser",
        "dissect_collector",
    ]

    capabilities = [
        SpecialistCapabilityDefinition(
            capability_id="linux_auth_logs",
            name="Linux Authentication Log Analysis",
            description="Parses /var/log/auth.log and /var/log/secure for failed and successful logon attempts.",
            operational=True,
            required_artifact_types=["linux_log", "auth_log", "syslog"],
            required_tools=["native_log_parser"],
        ),
        SpecialistCapabilityDefinition(
            capability_id="linux_ssh_activity",
            name="SSH Session & Key Activity",
            description="Extracts accepted and failed SSH logins, remote source IPs, and target usernames.",
            operational=True,
            required_artifact_types=["linux_log", "auth_log"],
            required_tools=["native_log_parser"],
        ),
        SpecialistCapabilityDefinition(
            capability_id="linux_sudo_privilege",
            name="Sudo Privilege Escalation Tracking",
            description="Identifies sudo command invocations and potential privilege escalation attempts.",
            operational=True,
            required_artifact_types=["linux_log", "auth_log"],
            required_tools=["native_log_parser"],
        ),
        SpecialistCapabilityDefinition(
            capability_id="linux_cron_persistence",
            name="Cron Persistence Detection",
            description="Analyzes cron logs and crontab entries for scheduled persistence jobs.",
            operational=True,
            required_artifact_types=["cron", "linux_log"],
            required_tools=["native_log_parser"],
        ),
        SpecialistCapabilityDefinition(
            capability_id="linux_shell_history",
            name="Shell Command History",
            description="Parses .bash_history and .zsh_history for executed commands and reconnaissance tradecraft.",
            operational=True,
            required_artifact_types=["shell_history"],
            required_tools=["native_log_parser"],
        ),
        SpecialistCapabilityDefinition(
            capability_id="linux_systemd_services",
            name="Systemd Service Unit Inspection",
            description="Parses custom systemd unit files for persistent daemon configurations.",
            operational=False,
            required_artifact_types=["systemd"],
            required_tools=["systemd_parser"],
            limitations=["Systemd unit parser not yet implemented."],
        ),
        SpecialistCapabilityDefinition(
            capability_id="linux_auditd_records",
            name="Auditd Linux Audit System Parsing",
            description="Parses /var/log/audit/audit.log syscall events.",
            operational=False,
            required_artifact_types=["auditd"],
            required_tools=["auditd_parser"],
            limitations=["Auditd syscall normalizer pending future release."],
        ),
    ]

    investigation_questions = [
        "Were there brute-force or successful SSH authentication events from unexpected IPs?",
        "Did unprivileged users escalate to root or administrative privileges via sudo?",
        "Were malicious persistence jobs registered in /etc/cron* or user crontabs?",
        "What interactive commands were executed in user shell histories?",
    ]

    limitations = [
        "Shell histories can be wiped or bypassed by attackers prepending commands with spaces or unsetting HISTFILE.",
        "Systemd unit parsing and auditd syscall tracing are currently non-operational.",
    ]

    citation_requirements = [
        "All claims must cite exact line numbers in the source log files.",
        "Cryptographic SHA-256 hash of the analyzed log must be recorded.",
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
        """Execute Linux DFIR analysis over authorized case artifacts."""
        params = parameters or {}
        requested_caps = params.get("capabilities", ["linux_auth_logs", "linux_ssh_activity"])

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
                        missing_artifact_type=cap.required_artifact_types[0] if cap and cap.required_artifact_types else "linux_log",
                        tactical_reason=f"Capability '{cap_id}' is not operational in Linux DFIR specialist.",
                        recommended_collection="Collect and ingest artifact once analyzer is deployed.",
                        is_evidence_of_absence=False,
                    )
                )

        relevant_artifacts = [a for a in artifacts if self.can_analyze(a.type or "")]
        if not relevant_artifacts:
            gaps.append(
                EvidenceGap(
                    missing_artifact_type="auth_log",
                    tactical_reason="No Linux authentication logs, cron entries, or shell histories found in authorized scope.",
                    recommended_collection="Acquire /var/log/auth.log, /var/log/secure, and /home/*/.bash_history.",
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
            if not custody_engine:
                continue

            try:
                rpath = custody_engine.resolve_artifact_file(art)
                if not rpath.exists():
                    errors.append(f"Artifact file missing on disk: {rpath}")
                    continue

                log_findings = parse_linux_text_log(
                    rpath,
                    case_id=case_id,
                    artifact_id=art.artifact_id,
                    artifact_hash=art.sha256,
                    max_lines=params.get("max_lines", 2000),
                )
                findings.extend(log_findings)
                raw_outputs.append({"artifact_id": art.artifact_id, "path": str(rpath), "count": len(log_findings)})

            except Exception as e:
                errors.append(f"Error parsing Linux log '{art.artifact_id}': {e}")

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
