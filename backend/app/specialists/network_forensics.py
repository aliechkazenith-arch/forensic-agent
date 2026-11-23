"""Network Forensics Investigation Specialist.

Standards:
- Deterministic Tooling: Pure-Python deterministic PCAP flow parser with statistical beaconing detection.
- Explicit Truth in Advertising: Pure-Python flow, beaconing, and RAT port detection are operational; deep Zeek/Tshark HTTP/TLS stream reconstruction are non-operational.
- Defensible Correlations: Statistical beaconing calculates timestamp intervals without guessing.
"""
from __future__ import annotations

import math
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

from backend.app.agent.tools import parse_pcap_file
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


class NetworkForensicsSpecialist(BaseDFIRSpecialist):
    """Specialist module for network packet captures, flow telemetry, and beaconing detection."""

    specialist_id = "network_forensics"
    name = "Network Forensics Specialist"
    domain = "network_telemetry"
    description = "Specialized network packet capture analysis, communication flow graphs, and C2 beaconing detection."

    supported_artifact_types = [
        "pcap",
        "pcapng",
        "netflow",
        "zeek_log",
        "network",
    ]

    tool_allowlist = [
        "native_pcap_parser",
        "tshark",
        "zeek",
    ]

    capabilities = [
        SpecialistCapabilityDefinition(
            capability_id="pcap_flow_analysis",
            name="PCAP/PCAPNG Flow Extraction",
            description="Extracts deterministic IPv4, TCP, and UDP communication flows from packet capture streams.",
            operational=True,
            required_artifact_types=["pcap", "pcapng", "network"],
            required_tools=["native_pcap_parser"],
        ),
        SpecialistCapabilityDefinition(
            capability_id="beaconing_detection",
            name="Statistical C2 Beaconing Detection",
            description="Calculates inter-arrival delta variance across repeated connections to identify automated C2 beacon intervals.",
            operational=True,
            required_artifact_types=["pcap", "pcapng", "network"],
            required_tools=["native_pcap_parser"],
        ),
        SpecialistCapabilityDefinition(
            capability_id="suspicious_destination_detection",
            name="Suspicious Destination & Port Detection",
            description="Identifies remote access tool (RAT) ports (e.g., TeamViewer 5938/5939, RDP 3389) and non-standard egress.",
            operational=True,
            required_artifact_types=["pcap", "pcapng", "network"],
            required_tools=["native_pcap_parser"],
        ),
        SpecialistCapabilityDefinition(
            capability_id="host_communication_relationships",
            name="Host-to-Host Communication Mapping",
            description="Generates communication relationships between source and destination IP endpoints.",
            operational=True,
            required_artifact_types=["pcap", "pcapng", "network"],
            required_tools=["native_pcap_parser"],
        ),
        SpecialistCapabilityDefinition(
            capability_id="dns_query_extraction",
            name="Deep DNS Query & Tunneling Inspection",
            description="Extracts DNS requests, response codes, and entropy scores via Zeek or Tshark.",
            operational=False,
            required_artifact_types=["pcap", "zeek_log"],
            required_tools=["zeek", "tshark"],
            limitations=["Zeek container parser pending deployment."],
        ),
        SpecialistCapabilityDefinition(
            capability_id="http_session_reconstruction",
            name="HTTP Session & Payload Reconstruction",
            description="Reassembles HTTP request/response payloads and extracts transferred files.",
            operational=False,
            required_artifact_types=["pcap"],
            required_tools=["zeek", "tshark"],
            limitations=["HTTP stream carver pending container deployment."],
        ),
        SpecialistCapabilityDefinition(
            capability_id="tls_metadata_extraction",
            name="TLS SNI & JA3/JA4 Fingerprinting",
            description="Extracts Server Name Indication and cryptographic handshake fingerprints.",
            operational=False,
            required_artifact_types=["pcap"],
            required_tools=["zeek", "tshark"],
            limitations=["JA3/JA4 fingerprinting engine pending container deployment."],
        ),
    ]

    investigation_questions = [
        "What external endpoints and autonomous systems did internal hosts communicate with?",
        "Are there recurring, periodic connection intervals indicative of Command and Control (C2) beaconing?",
        "Were remote management or tunneling ports utilized (e.g. TeamViewer, RDP, SSH)?",
        "Which internal endpoints initiated the highest volume of egress data?",
    ]

    limitations = [
        "Encrypted TLS payload contents cannot be inspected without SSL/TLS key log files.",
        "Zeek and Tshark deep protocol dissectors are currently non-operational; pure-Python flow parser is active.",
    ]

    citation_requirements = [
        "All claims must cite exact Packet numbers or Timestamp UTC offsets in the PCAP stream.",
        "Cryptographic SHA-256 hash of the packet capture file must be recorded.",
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
        """Execute network forensics analysis over authorized PCAP artifacts."""
        params = parameters or {}
        requested_caps = params.get("capabilities", ["pcap_flow_analysis", "beaconing_detection", "suspicious_destination_detection"])

        findings: List[ForensicFinding] = []
        correlations: List[CorrelationRelationship] = []
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
                        missing_artifact_type="pcap",
                        tactical_reason=f"Capability '{cap_id}' is not operational in Network Forensics specialist.",
                        recommended_collection="Collect PCAP and process once deep Zeek/Tshark analyzers are deployed.",
                        is_evidence_of_absence=False,
                    )
                )

        relevant_artifacts = [a for a in artifacts if self.can_analyze(a.type or "")]
        if not relevant_artifacts:
            gaps.append(
                EvidenceGap(
                    missing_artifact_type="pcap",
                    tactical_reason="No network packet captures (PCAP/PCAPNG) found in authorized scope.",
                    recommended_collection="Collect network telemetry from firewall, TAP, or endpoint packet capture.",
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

        # Process PCAPs
        for art in relevant_artifacts:
            if not custody_engine:
                continue

            try:
                rpath = custody_engine.resolve_artifact_file(art)
                if not rpath.exists():
                    errors.append(f"Artifact file missing on disk: {rpath}")
                    continue

                pcap_findings = parse_pcap_file(
                    rpath,
                    case_id=case_id,
                    artifact_id=art.artifact_id,
                    artifact_hash=art.sha256,
                    max_packets=params.get("max_packets", 2000),
                )
                findings.extend(pcap_findings)
                raw_outputs.append({"artifact_id": art.artifact_id, "path": str(rpath), "count": len(pcap_findings)})

                # 1. Detect Beaconing Indicators (Statistical Interval Analysis)
                if "beaconing_detection" in requested_caps and pcap_findings:
                    flow_times: Dict[str, List[datetime]] = defaultdict(list)
                    flow_finding_ids: Dict[str, List[str]] = defaultdict(list)

                    for f in pcap_findings:
                        proj = f.projected_data or {}
                        src = proj.get("src_ip")
                        dst = proj.get("dst_ip")
                        dport = proj.get("dst_port")
                        if src and dst and dport and f.timestamp_utc:
                            try:
                                dt = datetime.fromisoformat(f.timestamp_utc.replace("Z", "+00:00"))
                                flow_key = f"{src}->{dst}:{dport}"
                                flow_times[flow_key].append(dt)
                                flow_finding_ids[flow_key].append(f.finding_id)
                            except Exception:
                                pass

                    for flow_key, dts in flow_times.items():
                        if len(dts) >= 4:  # At least 4 connections for statistical periodicity
                            dts.sort()
                            deltas = [(dts[i] - dts[i - 1]).total_seconds() for i in range(1, len(dts))]
                            if deltas:
                                mean_delta = sum(deltas) / len(deltas)
                                variance = sum((x - mean_delta) ** 2 for x in deltas) / len(deltas)
                                std_dev = math.sqrt(variance)

                                # If standard deviation is low relative to mean, periodic beaconing detected
                                if mean_delta > 0 and (std_dev / mean_delta < 0.25 or std_dev < 5.0):
                                    src_ip, dst_flow = flow_key.split("->")
                                    dst_ip = dst_flow.split(":")[0]
                                    beacon_finding = ForensicFinding(
                                        case_id=case_id,
                                        source_artifact_id=art.artifact_id,
                                        source_artifact_hash=art.sha256,
                                        tool_id="native_pcap_parser",
                                        artifact_type="network",
                                        category="c2_beaconing",
                                        severity="high",
                                        summary=f"Periodic C2 beaconing detected: {flow_key} (Interval ~{round(mean_delta, 1)}s, std_dev={round(std_dev, 2)}s, count={len(dts)})",
                                        projected_data={
                                            "flow": flow_key,
                                            "src_ip": src_ip,
                                            "dst_ip": dst_ip,
                                            "mean_interval_seconds": round(mean_delta, 2),
                                            "interval_std_dev": round(std_dev, 2),
                                            "connection_count": len(dts),
                                        },
                                    )
                                    findings.append(beacon_finding)

                                    # Correlate flow findings with beaconing finding
                                    correlations.append(
                                        CorrelationRelationship(
                                            relationship_type="process_to_network",
                                            source_finding_ids=flow_finding_ids[flow_key][:10],
                                            target_finding_ids=[beacon_finding.finding_id],
                                            confidence_score=0.85,
                                            description=f"Periodic network communication flow matched C2 beaconing interval of ~{round(mean_delta, 1)}s.",
                                            method="statistical_interval_variance_analysis",
                                        )
                                    )

                # 2. Host-to-Host Communication Mapping
                if "host_communication_relationships" in requested_caps and pcap_findings:
                    host_pairs: Dict[str, List[str]] = defaultdict(list)
                    for f in pcap_findings:
                        proj = f.projected_data or {}
                        src = proj.get("src_ip")
                        dst = proj.get("dst_ip")
                        if src and dst and src != dst:
                            pair_key = f"{src}->{dst}"
                            host_pairs[pair_key].append(f.finding_id)

                    for pair, fids in host_pairs.items():
                        src, dst = pair.split("->")
                        correlations.append(
                            CorrelationRelationship(
                                relationship_type="host_to_host",
                                source_finding_ids=fids[:5],
                                target_finding_ids=fids[-5:] if len(fids) > 5 else fids,
                                confidence_score=0.9,
                                description=f"Host communication relationship observed from {src} to {dst} ({len(fids)} packets).",
                                method="packet_flow_endpoint_aggregation",
                            )
                        )

            except Exception as e:
                errors.append(f"Error parsing network artifact '{art.artifact_id}': {e}")

        # Store findings in DuckDB
        if findings:
            storage.insert_findings(findings)

        return SpecialistResult(
            specialist_id=self.specialist_id,
            success=len(errors) == 0,
            findings=findings,
            correlations=correlations,
            evidence_gaps=gaps,
            raw_outputs=raw_outputs,
            errors=errors,
            unsupported_capabilities_requested=unsupported,
        )
