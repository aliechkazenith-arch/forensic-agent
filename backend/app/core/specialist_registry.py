"""Central Specialist Capability Registry for Modular Level 3 DFIR Capabilities.

Standards:
- Deterministic Tooling Only (AGENTS.md Rule 1): Specialists are typed capability units.
- Explicit Truth in Advertising: Only capabilities with verified, implemented analyzers are advertised as operational.
- Dynamic Discovery: Discovers specialists based on case objectives, evidence artifact types, and hypotheses.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set

from backend.app.models.specialists import (
    BaseDFIRSpecialist,
    SpecialistCapabilityDefinition,
)
from backend.app.specialists.windows_dfir import WindowsDFIRSpecialist
from backend.app.specialists.linux_dfir import LinuxDFIRSpecialist
from backend.app.specialists.memory_forensics import MemoryForensicsSpecialist
from backend.app.specialists.network_forensics import NetworkForensicsSpecialist
from backend.app.specialists.malware_analysis import MalwareAnalysisSpecialist
from backend.app.specialists.timeline_correlation import TimelineCorrelationSpecialist


class SpecialistRegistry:
    """Central registry and discovery engine for DFIR Investigation Specialists."""

    def __init__(self) -> None:
        self._specialists: Dict[str, BaseDFIRSpecialist] = {}

    def register(self, specialist: BaseDFIRSpecialist) -> None:
        """Register a specialist instance."""
        self._specialists[specialist.specialist_id] = specialist

    def get_specialist(self, specialist_id: str) -> Optional[BaseDFIRSpecialist]:
        """Lookup a specialist by unique ID."""
        return self._specialists.get(specialist_id)

    def list_specialists(self) -> List[BaseDFIRSpecialist]:
        """List all registered specialists."""
        return list(self._specialists.values())

    def list_all_capabilities(self) -> List[SpecialistCapabilityDefinition]:
        """List all capabilities advertised across all registered specialists."""
        caps: List[SpecialistCapabilityDefinition] = []
        for s in self._specialists.values():
            caps.extend(s.capabilities)
        return caps

    def list_operational_capabilities(self) -> List[SpecialistCapabilityDefinition]:
        """List ONLY capabilities marked operational across all registered specialists."""
        caps: List[SpecialistCapabilityDefinition] = []
        for s in self._specialists.values():
            caps.extend(s.get_operational_capabilities())
        return caps

    def discover_for_evidence(self, artifact_types: List[str]) -> List[BaseDFIRSpecialist]:
        """Discover specialists that can analyze at least one of the provided artifact types."""
        norm_types = {str(t or "").lower().strip() for t in artifact_types}
        matched: List[BaseDFIRSpecialist] = []

        for s in self._specialists.values():
            s_types = {str(t).lower().strip() for t in s.supported_artifact_types}
            # "any" means specialist can operate on any evidence or findings (e.g. timeline_correlation)
            if "any" in s_types or bool(s_types & norm_types):
                matched.append(s)

        return matched

    def discover_for_objective(self, objective: str) -> List[BaseDFIRSpecialist]:
        """Discover specialists relevant to an investigative objective text."""
        obj_lower = (objective or "").lower()
        matched: List[BaseDFIRSpecialist] = []

        keywords = {
            "windows_dfir": ["windows", "active directory", "logon", "rdp", "evtx", "registry", "powershell", "event log"],
            "linux_dfir": ["linux", "ssh", "auth.log", "sudo", "cron", "bash", "unix", "syslog"],
            "memory_forensics": ["memory", "ram", "volatility", "injection", "pslist", "process tree", "vmem"],
            "network_forensics": ["network", "pcap", "c2", "beaconing", "packet", "flow", "traffic", "dns", "egress"],
            "malware_analysis": ["malware", "sample", "pe", "binary", "executable", "yara", "reverse", "payload", "hashes"],
            "timeline_correlation": ["timeline", "correlation", "sequence", "pivot", "chronology", "cross-source"],
        }

        for s_id, s in self._specialists.items():
            s_kws = keywords.get(s_id, [])
            if any(kw in obj_lower for kw in s_kws):
                matched.append(s)

        # If no specific keyword matched, return all specialists (broad compromise assessment)
        if not matched:
            matched = list(self._specialists.values())

        return matched


_GLOBAL_SPECIALIST_REGISTRY: Optional[SpecialistRegistry] = None


def get_default_specialist_registry() -> SpecialistRegistry:
    """Return singleton SpecialistRegistry populated with all 6 modular specialists."""
    global _GLOBAL_SPECIALIST_REGISTRY
    if _GLOBAL_SPECIALIST_REGISTRY is None:
        reg = SpecialistRegistry()
        reg.register(WindowsDFIRSpecialist())
        reg.register(LinuxDFIRSpecialist())
        reg.register(MemoryForensicsSpecialist())
        reg.register(NetworkForensicsSpecialist())
        reg.register(MalwareAnalysisSpecialist())
        reg.register(TimelineCorrelationSpecialist())
        _GLOBAL_SPECIALIST_REGISTRY = reg
    return _GLOBAL_SPECIALIST_REGISTRY
