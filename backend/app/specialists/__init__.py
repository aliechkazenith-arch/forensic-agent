"""Specialized DFIR Investigation Modules.

Exposes the 6 modular specialist capabilities:
1. Windows DFIR Specialist
2. Linux DFIR Specialist
3. Memory Forensics Specialist
4. Network Forensics Specialist
5. Malware Analysis Specialist
6. Timeline and Correlation Specialist
"""
from backend.app.specialists.windows_dfir import WindowsDFIRSpecialist
from backend.app.specialists.linux_dfir import LinuxDFIRSpecialist
from backend.app.specialists.memory_forensics import MemoryForensicsSpecialist
from backend.app.specialists.network_forensics import NetworkForensicsSpecialist
from backend.app.specialists.malware_analysis import MalwareAnalysisSpecialist
from backend.app.specialists.timeline_correlation import TimelineCorrelationSpecialist

__all__ = [
    "WindowsDFIRSpecialist",
    "LinuxDFIRSpecialist",
    "MemoryForensicsSpecialist",
    "NetworkForensicsSpecialist",
    "MalwareAnalysisSpecialist",
    "TimelineCorrelationSpecialist",
]
