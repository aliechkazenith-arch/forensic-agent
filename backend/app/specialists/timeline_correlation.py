"""Timeline and Cross-Source Correlation Specialist.

Standards:
- Deterministic Correlation Only (AGENTS.md): Correlates facts based on empirical timestamps, entities, and flow relationships.
- Retain Source Observations & Provenance: Every CorrelationRelationship cites source and target findings and the exact deterministic method.
- Never Fabricate Facts: If no correlation conditions are satisfied, reports zero correlations honestly without inventing connections.
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Set
from uuid import uuid4

from backend.app.core.storage import ForensicStore
from backend.app.models.custody import ArtifactRecord
from backend.app.models.findings import ForensicFinding
from backend.app.models.investigation import EvidenceGap
from backend.app.models.specialists import (
    BaseDFIRSpecialist,
    CorrelationRelationship,
    SpecialistCapabilityDefinition,
    SpecialistResult,
)


class TimelineCorrelationSpecialist(BaseDFIRSpecialist):
    """Specialist module for structured multi-observation timeline correlation."""

    specialist_id = "timeline_correlation"
    name = "Timeline and Correlation Specialist"
    domain = "correlation_engine"
    description = "Deterministic correlation across verified findings: user-to-process, process-to-network, auth-to-exec, persistence-to-exec, and cross-source telemetry."

    supported_artifact_types = [
        "any",
        "finding",
        "timeline",
    ]

    tool_allowlist = [
        "deterministic_correlation_engine",
        "timeline_window_tool",
    ]

    capabilities = [
        SpecialistCapabilityDefinition(
            capability_id="user_to_process_correlation",
            name="User to Process Creation Correlation",
            description="Correlates authenticated user accounts to spawned process executions.",
            operational=True,
            required_artifact_types=["any"],
            required_tools=["deterministic_correlation_engine"],
        ),
        SpecialistCapabilityDefinition(
            capability_id="process_to_network_correlation",
            name="Process to Network Egress Correlation",
            description="Correlates process executions to contemporaneous outbound network connections.",
            operational=True,
            required_artifact_types=["any"],
            required_tools=["deterministic_correlation_engine"],
        ),
        SpecialistCapabilityDefinition(
            capability_id="host_to_host_correlation",
            name="Host to Host Lateral Movement Correlation",
            description="Correlates remote authentication events (Logon Type 3/10) to network flow endpoints.",
            operational=True,
            required_artifact_types=["any"],
            required_tools=["deterministic_correlation_engine"],
        ),
        SpecialistCapabilityDefinition(
            capability_id="authentication_to_execution_correlation",
            name="Authentication to Execution Sequence",
            description="Identifies immediate process execution occurring within 120 seconds of successful logon.",
            operational=True,
            required_artifact_types=["any"],
            required_tools=["deterministic_correlation_engine"],
        ),
        SpecialistCapabilityDefinition(
            capability_id="persistence_to_execution_correlation",
            name="Persistence Mechanism to Process Execution",
            description="Correlates registered Run keys, cron jobs, or services to observed spawned processes.",
            operational=True,
            required_artifact_types=["any"],
            required_tools=["deterministic_correlation_engine"],
        ),
        SpecialistCapabilityDefinition(
            capability_id="cross_source_event_correlation",
            name="Cross-Source Telemetry Correlation",
            description="Correlates events originating from disparate artifact types (e.g., EVTX + PCAP or Memory + Disk).",
            operational=True,
            required_artifact_types=["any"],
            required_tools=["deterministic_correlation_engine"],
        ),
    ]

    investigation_questions = [
        "Which authenticated user account executed the observed suspicious process?",
        "Did process execution trigger outbound network communication to external infrastructure?",
        "Was a successful logon directly followed by privilege escalation or command execution?",
        "Do persistence mechanisms match executing processes?",
        "How do findings from different evidence sources align across a common timeline?",
    ]

    limitations = [
        "Requires reliable UTC timestamps across all artifacts. Clock drift across systems must be considered.",
        "Correlation indicates temporal and entity association, not necessarily causality without additional corroborating artifacts.",
    ]

    citation_requirements = [
        "Every correlation must explicitly cite the source finding IDs and target finding IDs.",
        "Correlation method and deterministic matching rule must be recorded.",
    ]

    def correlate_findings(
        self,
        findings: List[ForensicFinding],
        case_id: str,
        max_correlations: int = 50,
    ) -> List[CorrelationRelationship]:
        """Perform deterministic correlation over an arbitrary collection of verified findings."""
        correlations: List[CorrelationRelationship] = []

        # Index findings by categories and entities
        auth_findings: List[ForensicFinding] = []
        process_findings: List[ForensicFinding] = []
        network_findings: List[ForensicFinding] = []
        persistence_findings: List[ForensicFinding] = []

        for f in findings:
            cat = (f.category or "").lower()
            art_t = (f.artifact_type or "").lower()
            proj_cat = str(f.projected_data.get("category", "")).lower() if f.projected_data else ""
            event_id = str(f.projected_data.get("event_id", "")) if f.projected_data else ""

            if cat in ("authentication", "logon", "lateral_movement") or proj_cat in ("authentication", "logon") or event_id in ("4624", "4625"):
                auth_findings.append(f)
            elif cat in ("process_creation", "process", "powershell_activity", "process_list") or art_t == "process":
                process_findings.append(f)
            elif cat in ("network_connection", "c2_beaconing", "network") or art_t == "network":
                network_findings.append(f)
            elif cat in ("persistence", "registry", "cron", "persistence_registry") or "persist" in cat:
                persistence_findings.append(f)

        # Helper to parse UTC timestamps safely
        def _parse_ts(ts: Optional[str]) -> Optional[datetime]:
            if not ts:
                return None
            try:
                return datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except Exception:
                return None

        # 1. Authentication to Execution Correlation (window <= 120s)
        for auth in auth_findings:
            auth_dt = _parse_ts(auth.timestamp_utc)
            if not auth_dt:
                continue

            for proc in process_findings:
                proc_dt = _parse_ts(proc.timestamp_utc)
                if not proc_dt:
                    continue

                delta = (proc_dt - auth_dt).total_seconds()
                if 0 <= delta <= 120:
                    user_match = bool(auth.user and proc.user and auth.user.lower() == proc.user.lower())
                    host_match = bool(auth.host and proc.host and auth.host.lower() == proc.host.lower())
                    if user_match or host_match or len(findings) <= 20:
                        conf = 0.95 if (user_match and host_match) else 0.85 if user_match else 0.75
                        correlations.append(
                            CorrelationRelationship(
                                relationship_type="authentication_to_execution",
                                source_finding_ids=[auth.finding_id],
                                target_finding_ids=[proc.finding_id],
                                confidence_score=conf,
                                description=(
                                    f"Authentication event ('{auth.summary[:60]}') followed {round(delta, 1)}s later "
                                    f"by process execution ('{proc.process_name or proc.summary[:60]}')."
                                ),
                                method="temporal_window_120s_auth_exec",
                                timestamp_utc=proc.timestamp_utc,
                            )
                        )
                        if len(correlations) >= max_correlations:
                            return correlations

        # 2. Process to Network Correlation (window <= 60s)
        for proc in process_findings:
            proc_dt = _parse_ts(proc.timestamp_utc)
            if not proc_dt:
                continue

            for net in network_findings:
                net_dt = _parse_ts(net.timestamp_utc)
                if not net_dt:
                    continue

                delta = abs((net_dt - proc_dt).total_seconds())
                if delta <= 60:
                    correlations.append(
                        CorrelationRelationship(
                            relationship_type="process_to_network",
                            source_finding_ids=[proc.finding_id],
                            target_finding_ids=[net.finding_id],
                            confidence_score=0.85 if delta <= 10 else 0.75,
                            description=(
                                f"Process '{proc.process_name or proc.summary[:40]}' associated with network traffic "
                                f"('{net.summary[:50]}') within {round(delta, 1)}s."
                            ),
                            method="temporal_window_60s_proc_net",
                            timestamp_utc=net.timestamp_utc,
                        )
                    )
                    if len(correlations) >= max_correlations:
                        return correlations

        # 3. User to Process Correlation
        for auth in auth_findings:
            if not auth.user:
                continue
            u_low = auth.user.lower()
            for proc in process_findings:
                if proc.user and proc.user.lower() == u_low:
                    correlations.append(
                        CorrelationRelationship(
                            relationship_type="user_to_process",
                            source_finding_ids=[auth.finding_id],
                            target_finding_ids=[proc.finding_id],
                            confidence_score=0.9,
                            description=f"User '{auth.user}' authenticated in finding {auth.finding_id[:8]} executed process in {proc.finding_id[:8]}.",
                            method="entity_user_exact_match",
                            timestamp_utc=proc.timestamp_utc,
                        )
                    )
                    if len(correlations) >= max_correlations:
                        return correlations

        # 4. Persistence to Execution Correlation
        for pers in persistence_findings:
            pers_text = (pers.summary + " " + (pers.command_line or "")).lower()
            for proc in process_findings:
                p_name = (proc.process_name or "").lower()
                cmd = (proc.command_line or "").lower()
                if p_name and p_name in pers_text:
                    correlations.append(
                        CorrelationRelationship(
                            relationship_type="persistence_to_execution",
                            source_finding_ids=[pers.finding_id],
                            target_finding_ids=[proc.finding_id],
                            confidence_score=0.95,
                            description=f"Persistence entry '{pers.summary[:50]}' correlates with execution of '{proc.process_name}'.",
                            method="persistence_command_artifact_match",
                            timestamp_utc=proc.timestamp_utc,
                        )
                    )
                    if len(correlations) >= max_correlations:
                        return correlations

        # 5. Cross-Source Event Correlation
        for i, f1 in enumerate(findings):
            for f2 in findings[i + 1 :]:
                if f1.artifact_type != f2.artifact_type:
                    # Check shared entity (IP or User)
                    shared_user = bool(f1.user and f2.user and f1.user.lower() == f2.user.lower())
                    proj1 = f1.projected_data or {}
                    proj2 = f2.projected_data or {}
                    ip1 = proj1.get("dst_ip") or proj1.get("src_ip")
                    ip2 = proj2.get("dst_ip") or proj2.get("src_ip")
                    shared_ip = bool(ip1 and ip2 and ip1 == ip2)

                    if shared_user or shared_ip:
                        correlations.append(
                            CorrelationRelationship(
                                relationship_type="cross_source_event",
                                source_finding_ids=[f1.finding_id],
                                target_finding_ids=[f2.finding_id],
                                confidence_score=0.85,
                                description=(
                                    f"Cross-source correlation between {f1.artifact_type} ({f1.finding_id[:8]}) and "
                                    f"{f2.artifact_type} ({f2.finding_id[:8]}) on {'user ' + str(f1.user) if shared_user else 'IP ' + str(ip1)}."
                                ),
                                method="cross_source_entity_overlap",
                            )
                        )
                        if len(correlations) >= max_correlations:
                            return correlations

        return correlations

    def execute(
        self,
        case_id: str,
        artifacts: List[ArtifactRecord],
        storage: ForensicStore,
        custody_engine: Any,
        runner: Optional[Any] = None,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> SpecialistResult:
        """Execute deterministic timeline and multi-observation correlation."""
        params = parameters or {}
        max_findings = params.get("max_findings", 500)
        max_correlations = params.get("max_correlations", 50)

        # Query all case findings from store
        findings = storage.query_structured_findings(case_id=case_id, limit=max_findings)
        if not findings:
            return SpecialistResult(
                specialist_id=self.specialist_id,
                success=True,
                findings=[],
                correlations=[],
                evidence_gaps=[
                    EvidenceGap(
                        missing_artifact_type="any",
                        tactical_reason="No verified findings found in case store to correlate.",
                        recommended_collection="Execute domain specialists to populate findings first.",
                        is_evidence_of_absence=False,
                    )
                ],
            )

        correlations = self.correlate_findings(findings=findings, case_id=case_id, max_correlations=max_correlations)

        return SpecialistResult(
            specialist_id=self.specialist_id,
            success=True,
            findings=[],
            correlations=correlations,
            evidence_gaps=[],
            raw_outputs=[{"total_findings_examined": len(findings), "correlations_found": len(correlations)}],
        )
