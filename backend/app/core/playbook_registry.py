"""Deterministic MITRE ATT&CK 14-Tactic Forensic Playbook Registry.

Standards:
- Deterministic Tooling Only (AGENTS.md Rule 1): Factual claims must derive from
  verified parsers and DuckDB/SQLite storage; no unconstrained LLM hypothesis generation.
- Scope 1C: Target OS & Artifact Globs covering Windows, Linux, and Network artifacts.
- Scope 2C: Complete coverage of all 14 MITRE ATT&CK Enterprise Tactics (TA0001 - TA0043).
- Scope 4B: Hybrid standard playbooks with ScopedFilterParams (IOCs, regex, time ranges, Event IDs).
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Literal, Optional, Set
from pydantic import BaseModel, Field, field_validator


# ==============================================================================
# 4B Strict Scoped Filter Parameters Model
# ==============================================================================

class ScopedFilterParams(BaseModel):
    """Scope 4B Scoped filter parameters attached to deterministic playbook execution."""
    keywords_or_iocs: List[str] = Field(
        default_factory=list,
        description="List of keyword tokens, IPs, domains, hashes, or tool names to hunt for.",
    )
    regex_pattern: Optional[str] = Field(
        default=None,
        description="Optional pre-validated regular expression pattern for content matching.",
    )
    time_start_utc: Optional[str] = Field(
        default=None,
        description="Optional ISO-8601 start timestamp filter in UTC.",
    )
    time_end_utc: Optional[str] = Field(
        default=None,
        description="Optional ISO-8601 end timestamp filter in UTC.",
    )
    event_ids: List[int] = Field(
        default_factory=list,
        description="Specific Event IDs to filter on (e.g. 4624, 7045, 1102).",
    )

    @field_validator("regex_pattern")
    @classmethod
    def validate_regex_pattern(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v.strip():
            try:
                re.compile(v)
            except re.error as e:
                raise ValueError(f"Invalid regex pattern '{v}': {e}")
            return v
        return None

    @field_validator("time_start_utc", "time_end_utc")
    @classmethod
    def validate_iso_timestamps(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v.strip():
            val = v.strip()
            # Allow partial time-of-day strings (e.g. 02:00 or 02:00:00) by qualifying them
            if re.match(r"^\d{2}:\d{2}(?::\d{2})?(?:Z)?$", val):
                # Standardize to current date or valid time format
                now_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
                clean_time = val.rstrip("Z")
                if len(clean_time) == 5:
                    clean_time = f"{clean_time}:00"
                return f"{now_date}T{clean_time}Z"
            try:
                # Handle standard ISO-8601
                dt = datetime.fromisoformat(val.replace("Z", "+00:00"))
                return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            except Exception as e:
                raise ValueError(f"Invalid timestamp format '{v}': {e}")
        return None


# ==============================================================================
# Playbook Step & Definition Models
# ==============================================================================

class TargetOS(str, Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    NETWORK = "network"
    CROSS_PLATFORM = "cross_platform"


class PlaybookStep(BaseModel):
    """Atomic forensic analysis step mapped to specific artifact globs and deterministic parsers."""
    step_id: str
    name: str
    tactic_id: str
    tactic_name: str
    description: str
    target_os: TargetOS
    artifact_globs: List[str] = Field(
        default_factory=list,
        description="Glob patterns for target artifact files (e.g., Security.evtx, *cron*, *.pcap).",
    )
    required_artifact_types: List[str] = Field(
        default_factory=list,
        description="Artifact types required (e.g., evtx, registry, pcap, collector_log, file).",
    )
    parser_plugin: str = Field(
        description="Deterministic tool YAML or adapter (e.g., ez_evtxecmd.yaml, dissect_adapter.py, chainsaw_sigma.yaml).",
    )
    default_event_ids: List[int] = Field(default_factory=list)
    suggested_commands: List[str] = Field(default_factory=list)


class MitrePlaybook(BaseModel):
    """Standardized deterministic forensic investigation playbook for a MITRE ATT&CK tactic."""
    tactic_id: str
    tactic_name: str
    description: str
    keywords: List[str] = Field(default_factory=list)
    steps: List[PlaybookStep] = Field(default_factory=list)


# ==============================================================================
# Full 14-Tactic MITRE ATT&CK Enterprise Playbook Registry (Scope 2C)
# ==============================================================================

def _build_playbook_ta0043_recon() -> MitrePlaybook:
    return MitrePlaybook(
        tactic_id="TA0043",
        tactic_name="Reconnaissance",
        description="Detect adversary attempts to gather information to plan future operations, including active IP/port scanning and victim host queries.",
        keywords=["recon", "reconnaissance", "active scanning", "port scan", "nmap", "dns lookup", "gather host info", "network scan", "banner grab"],
        steps=[
            PlaybookStep(
                step_id="step_ta0043_win_dns_network",
                name="Windows DNS & Network Reconnaissance",
                tactic_id="TA0043",
                tactic_name="Reconnaissance",
                description="Parse Windows DNS Client operational logs and network discovery event logs.",
                target_os=TargetOS.WINDOWS,
                artifact_globs=["*DNS*.evtx", "*System.evtx", "*Security.evtx"],
                required_artifact_types=["evtx"],
                parser_plugin="ez_evtxecmd.yaml",
                default_event_ids=[3008, 3010, 4688],
            ),
            PlaybookStep(
                step_id="step_ta0043_linux_scan_logs",
                name="Linux Scanning & Auth Telemetry",
                tactic_id="TA0043",
                tactic_name="Reconnaissance",
                description="Parse Linux auth.log and syslog for rapid connection spikes, banner grabbing, and port scanning.",
                target_os=TargetOS.LINUX,
                artifact_globs=["*auth.log*", "*syslog*", "*secure*"],
                required_artifact_types=["collector_log", "log"],
                parser_plugin="dissect_adapter.py",
            ),
            PlaybookStep(
                step_id="step_ta0043_pcap_port_scan",
                name="Network PCAP Scan & SYN Sweep Hunter",
                tactic_id="TA0043",
                tactic_name="Reconnaissance",
                description="Deterministic parsing of PCAP traffic for SYN floods, sequential port touches, and ARP discovery sweeps.",
                target_os=TargetOS.NETWORK,
                artifact_globs=["*.pcap", "*.pcapng", "*zeek*", "*conn.log*"],
                required_artifact_types=["pcap", "network"],
                parser_plugin="dissect_adapter.py",
            ),
        ],
    )


def _build_playbook_ta0042_resource_dev() -> MitrePlaybook:
    return MitrePlaybook(
        tactic_id="TA0042",
        tactic_name="Resource Development",
        description="Identify adversary infrastructure establishment, staging payloads, certutil abuse, and staging tool downloads.",
        keywords=["resource development", "staging", "certutil", "tool download", "payload staging", "wget", "curl download", "acquire infrastructure"],
        steps=[
            PlaybookStep(
                step_id="step_ta0042_win_certutil_bits",
                name="Windows Certutil & BITS Transfer Staging",
                tactic_id="TA0042",
                tactic_name="Resource Development",
                description="Inspect Bits-Client, PowerShell, and CertUtil executions used to download external binaries.",
                target_os=TargetOS.WINDOWS,
                artifact_globs=["*Bits-Client*.evtx", "*PowerShell*.evtx", "*Security.evtx"],
                required_artifact_types=["evtx"],
                parser_plugin="chainsaw_sigma.yaml",
                default_event_ids=[4104, 4688, 59],
            ),
            PlaybookStep(
                step_id="step_ta0042_linux_staging",
                name="Linux Web & Shell Download Staging",
                tactic_id="TA0042",
                tactic_name="Resource Development",
                description="Inspect /tmp and /var/tmp directories, bash histories, and web server logs for downloaded tools.",
                target_os=TargetOS.LINUX,
                artifact_globs=["*.bash_history*", "*access.log*", "*audit.log*"],
                required_artifact_types=["collector_log", "log"],
                parser_plugin="dissect_adapter.py",
            ),
            PlaybookStep(
                step_id="step_ta0042_payload_yara",
                name="Staged Payload YARA Signature Match",
                tactic_id="TA0042",
                tactic_name="Resource Development",
                description="Scan staged payloads and dropped executables using deterministic compiled YARA rules.",
                target_os=TargetOS.CROSS_PLATFORM,
                artifact_globs=["*.bin", "*.exe", "*.sh", "*.dll", "*.blob"],
                required_artifact_types=["file", "raw_image"],
                parser_plugin="yara_scanner.yaml",
            ),
        ],
    )


def _build_playbook_ta0001_initial_access() -> MitrePlaybook:
    return MitrePlaybook(
        tactic_id="TA0001",
        tactic_name="Initial Access",
        description="Trace vectors adversaries use to gain initial entry, including brute-force logon, RDP, VPN, or public-facing service exploitation.",
        keywords=["initial access", "phishing", "logon anomaly", "interactive logon", "rdp access", "vpn", "ssh logon", "external remote", "brute force"],
        steps=[
            PlaybookStep(
                step_id="step_ta0001_win_logon",
                name="Windows Security Logons (Type 3 & Type 10)",
                tactic_id="TA0001",
                tactic_name="Initial Access",
                description="Parse Windows Security.evtx Event 4624 (Successful Logon) and 4625 (Failed Logon) for anomalies.",
                target_os=TargetOS.WINDOWS,
                artifact_globs=["*Security.evtx"],
                required_artifact_types=["evtx"],
                parser_plugin="ez_evtxecmd.yaml",
                default_event_ids=[4624, 4625, 4776],
            ),
            PlaybookStep(
                step_id="step_ta0001_linux_ssh",
                name="Linux SSH Auth Log & Key Injection",
                tactic_id="TA0001",
                tactic_name="Initial Access",
                description="Extract failed/accepted SSH authentication attempts, invalid user sweeps, and authorized_keys modifications.",
                target_os=TargetOS.LINUX,
                artifact_globs=["*auth.log*", "*secure*"],
                required_artifact_types=["collector_log", "log"],
                parser_plugin="dissect_adapter.py",
            ),
            PlaybookStep(
                step_id="step_ta0001_network_handshakes",
                name="Network Edge Ingress Session Analysis",
                tactic_id="TA0001",
                tactic_name="Initial Access",
                description="Evaluate external IP ingress sessions and port handshakes from network PCAP or firewall captures.",
                target_os=TargetOS.NETWORK,
                artifact_globs=["*.pcap", "*.pcapng"],
                required_artifact_types=["pcap", "network"],
                parser_plugin="dissect_adapter.py",
            ),
        ],
    )


def _build_playbook_ta0002_execution() -> MitrePlaybook:
    return MitrePlaybook(
        tactic_id="TA0002",
        tactic_name="Execution",
        description="Detect adversarial execution of malicious code, commands, scripts, PowerShell, or reverse shells.",
        keywords=["execution", "powershell", "command line", "process creation", "sysmon 1", "event 4688", "cmd.exe", "bash execution", "scripting", "wscript"],
        steps=[
            PlaybookStep(
                step_id="step_ta0002_win_process_creation",
                name="Windows Process Creation (Sysmon 1 & Security 4688)",
                tactic_id="TA0002",
                tactic_name="Execution",
                description="Inspect process spawn trees, command line arguments, parent-child relationships, and process hashes.",
                target_os=TargetOS.WINDOWS,
                artifact_globs=["*Sysmon*.evtx", "*Security.evtx"],
                required_artifact_types=["evtx"],
                parser_plugin="ez_evtxecmd.yaml",
                default_event_ids=[1, 4688],
            ),
            PlaybookStep(
                step_id="step_ta0002_win_powershell",
                name="PowerShell Script Block Logging (Event 4104)",
                tactic_id="TA0002",
                tactic_name="Execution",
                description="Extract deobfuscated PowerShell script block contents, base64 commands, and WebClient invocations.",
                target_os=TargetOS.WINDOWS,
                artifact_globs=["*PowerShell*Operational*.evtx", "*Security.evtx"],
                required_artifact_types=["evtx"],
                parser_plugin="chainsaw_sigma.yaml",
                default_event_ids=[4104, 4103],
            ),
            PlaybookStep(
                step_id="step_ta0002_linux_shell_execution",
                name="Linux Process Execution & Shell History",
                tactic_id="TA0002",
                tactic_name="Execution",
                description="Parse .bash_history, audit.log execve events, and running process trees.",
                target_os=TargetOS.LINUX,
                artifact_globs=["*.bash_history*", "*audit.log*", "*process*.json*"],
                required_artifact_types=["collector_log", "log", "process"],
                parser_plugin="dissect_adapter.py",
            ),
        ],
    )


def _build_playbook_ta0003_persistence() -> MitrePlaybook:
    return MitrePlaybook(
        tactic_id="TA0003",
        tactic_name="Persistence",
        description="Detect mechanisms adversaries use to maintain their foothold across restarts or credential changes.",
        keywords=["persistence", "persist", "run key", "runonce", "scheduled task", "cron", "cronjob", "systemd", "startup", "registry persist", "service install"],
        steps=[
            PlaybookStep(
                step_id="step_ta0003_win_registry_run",
                name="Windows Registry Autoruns & Run Keys",
                tactic_id="TA0003",
                tactic_name="Persistence",
                description="Parse Run, RunOnce, Winlogon, and Image File Execution Options (IFEO) registry keys using Eric Zimmerman RECmd.",
                target_os=TargetOS.WINDOWS,
                artifact_globs=["*NTUSER.DAT*", "*SOFTWARE*", "*SYSTEM*"],
                required_artifact_types=["registry"],
                parser_plugin="ez_recmd.yaml",
            ),
            PlaybookStep(
                step_id="step_ta0003_win_scheduled_tasks",
                name="Windows Scheduled Tasks & Services",
                tactic_id="TA0003",
                tactic_name="Persistence",
                description="Inspect TaskScheduler Operational logs (Event 106, 140) and System Service installation (Event 7045).",
                target_os=TargetOS.WINDOWS,
                artifact_globs=["*TaskScheduler*.evtx", "*System.evtx", "*Security.evtx"],
                required_artifact_types=["evtx"],
                parser_plugin="ez_evtxecmd.yaml",
                default_event_ids=[106, 140, 7045, 4698],
            ),
            PlaybookStep(
                step_id="step_ta0003_linux_cron_systemd",
                name="Linux Cron & Systemd Service Persistence",
                tactic_id="TA0003",
                tactic_name="Persistence",
                description="Parse /etc/cron*, /var/spool/cron, /etc/systemd/system, and /etc/rc.local configurations.",
                target_os=TargetOS.LINUX,
                artifact_globs=["*cron*", "*systemd*", "*rc.local*", "*persistence*.json*"],
                required_artifact_types=["collector_log", "file"],
                parser_plugin="dissect_adapter.py",
            ),
        ],
    )


def _build_playbook_ta0004_priv_esc() -> MitrePlaybook:
    return MitrePlaybook(
        tactic_id="TA0004",
        tactic_name="Privilege Escalation",
        description="Detect techniques used to gain higher-level permissions, including UAC bypass, Sudo abuse, or token manipulation.",
        keywords=["privilege escalation", "privesc", "uac bypass", "sudo", "su", "sedebugprivilege", "rootkit", "token impersonation", "elevate", "administrator"],
        steps=[
            PlaybookStep(
                step_id="step_ta0004_win_token_privileges",
                name="Windows Special Privileges Assigned & UAC Bypass",
                tactic_id="TA0004",
                tactic_name="Privilege Escalation",
                description="Inspect Security.evtx Event 4672 (Special privileges assigned) and 4673 (Privileged service called).",
                target_os=TargetOS.WINDOWS,
                artifact_globs=["*Security.evtx"],
                required_artifact_types=["evtx"],
                parser_plugin="ez_evtxecmd.yaml",
                default_event_ids=[4672, 4673, 4674],
            ),
            PlaybookStep(
                step_id="step_ta0004_linux_sudo_polkit",
                name="Linux Sudo, SUID & Polkit Escalation",
                tactic_id="TA0004",
                tactic_name="Privilege Escalation",
                description="Parse auth.log sudo commands, PAM authentication switches, and SUID/SGID binary enumerations.",
                target_os=TargetOS.LINUX,
                artifact_globs=["*auth.log*", "*secure*", "*sudoers*", "*audit.log*"],
                required_artifact_types=["collector_log", "log"],
                parser_plugin="dissect_adapter.py",
            ),
        ],
    )


def _build_playbook_ta0005_defense_evasion() -> MitrePlaybook:
    return MitrePlaybook(
        tactic_id="TA0005",
        tactic_name="Defense Evasion",
        description="Identify techniques adversaries use to avoid detection, including event log clearing, disabling AV, or timestomping.",
        keywords=["defense evasion", "log clear", "tamper", "disable defender", "event 1102", "masquerading", "timestomp", "obfuscation", "antivirus", "evasion"],
        steps=[
            PlaybookStep(
                step_id="step_ta0005_win_log_clearing",
                name="Windows Security & System Log Clearing",
                tactic_id="TA0005",
                tactic_name="Defense Evasion",
                description="Detect Security log clearing (Event 1102) and System log clearing (Event 104).",
                target_os=TargetOS.WINDOWS,
                artifact_globs=["*Security.evtx", "*System.evtx"],
                required_artifact_types=["evtx"],
                parser_plugin="ez_evtxecmd.yaml",
                default_event_ids=[1102, 104],
            ),
            PlaybookStep(
                step_id="step_ta0005_win_defender_tampering",
                name="Windows Defender Tampering & Exclusion Adds",
                tactic_id="TA0005",
                tactic_name="Defense Evasion",
                description="Inspect Windows Defender Operational logs (Event 5001, 5007) for disabled real-time protection.",
                target_os=TargetOS.WINDOWS,
                artifact_globs=["*Windows-Defender*Operational*.evtx"],
                required_artifact_types=["evtx"],
                parser_plugin="chainsaw_sigma.yaml",
                default_event_ids=[5001, 5007],
            ),
            PlaybookStep(
                step_id="step_ta0005_linux_log_tamper",
                name="Linux Log Deletion & Bash History Tampering",
                tactic_id="TA0005",
                tactic_name="Defense Evasion",
                description="Detect clearing of /var/log, zeroing of .bash_history, or HISTFILE environment overrides.",
                target_os=TargetOS.LINUX,
                artifact_globs=["*.bash_history*", "*audit.log*", "*syslog*"],
                required_artifact_types=["collector_log", "log"],
                parser_plugin="dissect_adapter.py",
            ),
        ],
    )


def _build_playbook_ta0006_credential_access() -> MitrePlaybook:
    return MitrePlaybook(
        tactic_id="TA0006",
        tactic_name="Credential Access",
        description="Detect techniques for stealing credentials such as account names and passwords (LSASS dumping, NTDS, Kerberoasting).",
        keywords=["credential access", "lsass", "mimikatz", "procdump", "credential dumping", "sam", "ntds", "shadow", "password", "hash dump", "pass-the-hash", "kerberoast"],
        steps=[
            PlaybookStep(
                step_id="step_ta0006_win_lsass_dumping",
                name="Windows LSASS Process Memory Access (Sysmon 10)",
                tactic_id="TA0006",
                tactic_name="Credential Access",
                description="Detect suspicious process access to lsass.exe requesting handle permissions (0x1010, 0x1FFFFF).",
                target_os=TargetOS.WINDOWS,
                artifact_globs=["*Sysmon*.evtx"],
                required_artifact_types=["evtx"],
                parser_plugin="ez_evtxecmd.yaml",
                default_event_ids=[10],
            ),
            PlaybookStep(
                step_id="step_ta0006_win_sam_system_hives",
                name="Windows SAM, SECURITY & SYSTEM Registry Hives",
                tactic_id="TA0006",
                tactic_name="Credential Access",
                description="Inspect SAM hive and Registry hive access used to extract cached credentials and LSA secrets.",
                target_os=TargetOS.WINDOWS,
                artifact_globs=["*SAM*", "*SYSTEM*", "*SECURITY*"],
                required_artifact_types=["registry"],
                parser_plugin="ez_recmd.yaml",
            ),
            PlaybookStep(
                step_id="step_ta0006_linux_shadow_pam",
                name="Linux Shadow File & PAM Credential Access",
                tactic_id="TA0006",
                tactic_name="Credential Access",
                description="Inspect access to /etc/shadow, unshadow execution, and memory credential dumpers.",
                target_os=TargetOS.LINUX,
                artifact_globs=["*shadow*", "*audit.log*", "*auth.log*"],
                required_artifact_types=["collector_log", "file"],
                parser_plugin="dissect_adapter.py",
            ),
        ],
    )


def _build_playbook_ta0007_discovery() -> MitrePlaybook:
    return MitrePlaybook(
        tactic_id="TA0007",
        tactic_name="Discovery",
        description="Detect adversary attempts to observe system configurations, domain trusts, network shares, and local accounts.",
        keywords=["discovery", "recon", "network discovery", "whoami", "net user", "nltest", "system discovery", "account discovery", "enumeration", "ipconfig"],
        steps=[
            PlaybookStep(
                step_id="step_ta0007_win_discovery_cmds",
                name="Windows System & Account Discovery Commands",
                tactic_id="TA0007",
                tactic_name="Discovery",
                description="Detect execution of discovery utilities: whoami.exe, net.exe, nltest.exe, adfind.exe, systeminfo.exe.",
                target_os=TargetOS.WINDOWS,
                artifact_globs=["*Security.evtx", "*Sysmon*.evtx"],
                required_artifact_types=["evtx"],
                parser_plugin="chainsaw_sigma.yaml",
                default_event_ids=[4688, 1],
            ),
            PlaybookStep(
                step_id="step_ta0007_linux_discovery",
                name="Linux Environment & Network Discovery",
                tactic_id="TA0007",
                tactic_name="Discovery",
                description="Identify execution of uname, id, ip a, route, netstat, lsof, and ps in Linux shell logs.",
                target_os=TargetOS.LINUX,
                artifact_globs=["*.bash_history*", "*audit.log*"],
                required_artifact_types=["collector_log", "log"],
                parser_plugin="dissect_adapter.py",
            ),
        ],
    )


def _build_playbook_ta0008_lateral_movement() -> MitrePlaybook:
    return MitrePlaybook(
        tactic_id="TA0008",
        tactic_name="Lateral Movement",
        description="Detect adversary techniques for extending access across systems on the network, including WMI, PsExec, and SMB.",
        keywords=["lateral movement", "psexec", "wmiexec", "wmi", "smb", "remote desktop", "ssh pivot", "pass the hash", "impacket", "winrm"],
        steps=[
            PlaybookStep(
                step_id="step_ta0008_win_wmi_psexec",
                name="Windows WMI & PsExec Remote Execution",
                tactic_id="TA0008",
                tactic_name="Lateral Movement",
                description="Inspect WMI-Activity operational logs, System Event 7045 (PsExec service creation), and Type 3 Network Logons.",
                target_os=TargetOS.WINDOWS,
                artifact_globs=["*WMI-Activity*Operational*.evtx", "*System.evtx", "*Security.evtx"],
                required_artifact_types=["evtx"],
                parser_plugin="ez_evtxecmd.yaml",
                default_event_ids=[5858, 5861, 7045, 4624],
            ),
            PlaybookStep(
                step_id="step_ta0008_win_rdp_remote",
                name="Windows TerminalServices RDP Lateral Connections",
                tactic_id="TA0008",
                tactic_name="Lateral Movement",
                description="Parse TerminalServices-LocalSessionManager and RemoteConnectionManager logs for incoming remote sessions.",
                target_os=TargetOS.WINDOWS,
                artifact_globs=["*TerminalServices*.evtx", "*Security.evtx"],
                required_artifact_types=["evtx"],
                parser_plugin="ez_evtxecmd.yaml",
                default_event_ids=[21, 24, 25, 1149],
            ),
            PlaybookStep(
                step_id="step_ta0008_linux_ssh_pivot",
                name="Linux Outbound SSH Pivoting & Known Hosts",
                tactic_id="TA0008",
                tactic_name="Lateral Movement",
                description="Extract outbound SSH sessions, SCP transfers, and known_hosts records from Linux endpoints.",
                target_os=TargetOS.LINUX,
                artifact_globs=["*.bash_history*", "*known_hosts*", "*auth.log*"],
                required_artifact_types=["collector_log", "file"],
                parser_plugin="dissect_adapter.py",
            ),
        ],
    )


def _build_playbook_ta0009_collection() -> MitrePlaybook:
    return MitrePlaybook(
        tactic_id="TA0009",
        tactic_name="Collection",
        description="Detect techniques adversaries use to gather information and sensitive sources prior to exfiltration.",
        keywords=["collection", "archive", "data staged", "zip", "tar", "screen capture", "keylogger", "clipboard", "sensitive data search", "7z"],
        steps=[
            PlaybookStep(
                step_id="step_ta0009_win_archive_staging",
                name="Windows Archive Utilities (7z / WinRAR / Compress)",
                tactic_id="TA0009",
                tactic_name="Collection",
                description="Detect process creation of archiving utilities (7z.exe, rar.exe, tar.exe) staging data.",
                target_os=TargetOS.WINDOWS,
                artifact_globs=["*Security.evtx", "*Sysmon*.evtx"],
                required_artifact_types=["evtx"],
                parser_plugin="chainsaw_sigma.yaml",
                default_event_ids=[4688, 1],
            ),
            PlaybookStep(
                step_id="step_ta0009_linux_archive",
                name="Linux Tar & Gzip Collection Staging",
                tactic_id="TA0009",
                tactic_name="Collection",
                description="Identify tar, gzip, zip invocations in Linux shell logs bundling sensitive files.",
                target_os=TargetOS.LINUX,
                artifact_globs=["*.bash_history*", "*audit.log*"],
                required_artifact_types=["collector_log", "log"],
                parser_plugin="dissect_adapter.py",
            ),
        ],
    )


def _build_playbook_ta0011_c2() -> MitrePlaybook:
    return MitrePlaybook(
        tactic_id="TA0011",
        tactic_name="Command and Control",
        description="Detect adversary communication with systems under their control, including reverse shells, TeamViewer, AnyDesk, and C2 beacons.",
        keywords=["command and control", "c2", "beaconing", "teamviewer", "anydesk", "tunneling", "dns tunnel", "reverse shell", "remote access tool", "rat", "c&c"],
        steps=[
            PlaybookStep(
                step_id="step_ta0011_win_remote_tools",
                name="Windows Remote Admin Software (TeamViewer, AnyDesk)",
                tactic_id="TA0011",
                tactic_name="Command and Control",
                description="Detect execution, service installation, and network connections made by remote administration software.",
                target_os=TargetOS.WINDOWS,
                artifact_globs=["*Security.evtx", "*Sysmon*.evtx", "*System.evtx"],
                required_artifact_types=["evtx"],
                parser_plugin="chainsaw_sigma.yaml",
                default_event_ids=[4688, 1, 3, 7045],
            ),
            PlaybookStep(
                step_id="step_ta0011_pcap_c2_beacon",
                name="Network PCAP C2 Beaconing & DNS Tunnels",
                tactic_id="TA0011",
                tactic_name="Command and Control",
                description="Inspect PCAP flow telemetry for periodic beacons, abnormal DNS request volumes, and non-standard egress ports.",
                target_os=TargetOS.NETWORK,
                artifact_globs=["*.pcap", "*.pcapng", "*zeek*"],
                required_artifact_types=["pcap", "network"],
                parser_plugin="dissect_adapter.py",
            ),
            PlaybookStep(
                step_id="step_ta0011_linux_reverse_shells",
                name="Linux Reverse Shell & Socket Connections",
                tactic_id="TA0011",
                tactic_name="Command and Control",
                description="Detect bash/python/perl reverse shell pipes and persistent netcat connections in Linux history and process snapshots.",
                target_os=TargetOS.LINUX,
                artifact_globs=["*.bash_history*", "*netstat*.json*", "*process*.json*"],
                required_artifact_types=["collector_log", "process"],
                parser_plugin="dissect_adapter.py",
            ),
        ],
    )


def _build_playbook_ta0010_exfiltration() -> MitrePlaybook:
    return MitrePlaybook(
        tactic_id="TA0010",
        tactic_name="Exfiltration",
        description="Detect adversary attempts to steal data, transfer archives to external IP addresses, cloud services, or webhooks.",
        keywords=["exfiltration", "data theft", "egress", "rclone", "dropbox upload", "mega", "outbound transfer", "exfil", "curl post"],
        steps=[
            PlaybookStep(
                step_id="step_ta0010_win_cloud_tools",
                name="Windows Cloud Storage & Exfiltration Tools",
                tactic_id="TA0010",
                tactic_name="Exfiltration",
                description="Detect process creation of rclone, mega, curl, or powershell WebClient POST requests.",
                target_os=TargetOS.WINDOWS,
                artifact_globs=["*Security.evtx", "*Sysmon*.evtx"],
                required_artifact_types=["evtx"],
                parser_plugin="chainsaw_sigma.yaml",
                default_event_ids=[4688, 1, 4104],
            ),
            PlaybookStep(
                step_id="step_ta0010_pcap_egress_volume",
                name="Network Large Outbound Flow Detection",
                tactic_id="TA0010",
                tactic_name="Exfiltration",
                description="Inspect PCAP packet sizes and flow session bytes for abnormal outbound data volume spikes.",
                target_os=TargetOS.NETWORK,
                artifact_globs=["*.pcap", "*.pcapng"],
                required_artifact_types=["pcap", "network"],
                parser_plugin="dissect_adapter.py",
            ),
        ],
    )


def _build_playbook_ta0040_impact() -> MitrePlaybook:
    return MitrePlaybook(
        tactic_id="TA0040",
        tactic_name="Impact",
        description="Detect adversary attempts to manipulate, interrupt, or destroy systems and data, including ransomware, shadow deletion, or disk wiping.",
        keywords=["impact", "ransomware", "encryptor", "vssadmin", "delete shadows", "wiper", "defacement", "denial of service", "shutdown"],
        steps=[
            PlaybookStep(
                step_id="step_ta0040_win_ransomware_vss",
                name="Windows Shadow Copy Deletion (vssadmin / wmic)",
                tactic_id="TA0040",
                tactic_name="Impact",
                description="Detect commands deleting Volume Shadow Copies (vssadmin delete shadows, wmic shadowcopy delete).",
                target_os=TargetOS.WINDOWS,
                artifact_globs=["*Security.evtx", "*Sysmon*.evtx"],
                required_artifact_types=["evtx"],
                parser_plugin="chainsaw_sigma.yaml",
                default_event_ids=[4688, 1],
            ),
            PlaybookStep(
                step_id="step_ta0040_linux_wiper",
                name="Linux Disk Wiper & Mass File Deletion",
                tactic_id="TA0040",
                tactic_name="Impact",
                description="Detect destructive commands (rm -rf /, dd if=/dev/zero, shred) in Linux shell and audit logs.",
                target_os=TargetOS.LINUX,
                artifact_globs=["*.bash_history*", "*audit.log*"],
                required_artifact_types=["collector_log", "log"],
                parser_plugin="dissect_adapter.py",
            ),
        ],
    )


# ==============================================================================
# Playbook Registry Class (Singleton / Factory)
# ==============================================================================

class PlaybookRegistry:
    """Registry maintaining the complete 14-tactic MITRE ATT&CK Playbooks and deterministic routers."""

    def __init__(self):
        self._playbooks: Dict[str, MitrePlaybook] = {
            "TA0043": _build_playbook_ta0043_recon(),
            "TA0042": _build_playbook_ta0042_resource_dev(),
            "TA0001": _build_playbook_ta0001_initial_access(),
            "TA0002": _build_playbook_ta0002_execution(),
            "TA0003": _build_playbook_ta0003_persistence(),
            "TA0004": _build_playbook_ta0004_priv_esc(),
            "TA0005": _build_playbook_ta0005_defense_evasion(),
            "TA0006": _build_playbook_ta0006_credential_access(),
            "TA0007": _build_playbook_ta0007_discovery(),
            "TA0008": _build_playbook_ta0008_lateral_movement(),
            "TA0009": _build_playbook_ta0009_collection(),
            "TA0011": _build_playbook_ta0011_c2(),
            "TA0010": _build_playbook_ta0010_exfiltration(),
            "TA0040": _build_playbook_ta0040_impact(),
        }

    def get_playbook(self, tactic_id: str) -> Optional[MitrePlaybook]:
        return self._playbooks.get(tactic_id.upper())

    def list_all_playbooks(self) -> List[MitrePlaybook]:
        return list(self._playbooks.values())

    def route_goal_to_playbooks(self, goal: str) -> List[MitrePlaybook]:
        """Deterministically match user investigation goal keywords against the 14 MITRE tactics."""
        g_lower = goal.lower().strip()
        matched: List[MitrePlaybook] = []

        # Check explicit tactic IDs in goal (e.g. TA0003)
        for tid, pb in self._playbooks.items():
            if tid.lower() in g_lower:
                if pb not in matched:
                    matched.append(pb)

        # Check playbook keywords
        for pb in self._playbooks.values():
            if pb in matched:
                continue
            for kw in pb.keywords:
                if kw in g_lower:
                    matched.append(pb)
                    break

        # Fallback default if no explicit keyword matched
        if not matched:
            if "linux" in g_lower or "ssh" in g_lower:
                matched.append(self._playbooks["TA0001"])  # Initial Access
                matched.append(self._playbooks["TA0002"])  # Execution
            elif "network" in g_lower or "pcap" in g_lower:
                matched.append(self._playbooks["TA0011"])  # Command and Control
            else:
                # Default baseline: Initial Access, Execution, Persistence
                matched.append(self._playbooks["TA0001"])
                matched.append(self._playbooks["TA0002"])
                matched.append(self._playbooks["TA0003"])

        return matched

    def extract_scoped_filter_params(self, goal: str) -> ScopedFilterParams:
        """Deterministically extract keywords, IOCs, timestamps, and event IDs from goal text."""
        keywords_or_iocs: List[str] = []
        event_ids: List[int] = []
        time_start: Optional[str] = None
        time_end: Optional[str] = None
        regex_pat: Optional[str] = None

        # 1. Extract Event IDs (e.g. "event 4624", "Event ID 7045", "ID: 1102")
        ev_matches = re.findall(r"(?:event\s*(?:id)?\s*[:#]?\s*|id\s*[:#]\s*)(\d{1,5})", goal, re.IGNORECASE)
        for m in ev_matches:
            try:
                event_ids.append(int(m))
            except ValueError:
                pass

        # 2. Extract Time Windows: "between HH:MM and HH:MM UTC" or "YYYY-MM-DDTHH:MM:SSZ to ..."
        time_between = re.search(
            r"between\s+([0-9:\-T Z]+?)\s+and\s+([0-9:\-T Z]+?)(?:\s+UTC)?(?:\s|\.|$)",
            goal,
            re.IGNORECASE,
        )
        if time_between:
            time_start = time_between.group(1).strip()
            time_end = time_between.group(2).strip()
        else:
            time_to = re.search(
                r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z?)\s*(?:to|-)\s*([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z?)",
                goal,
                re.IGNORECASE,
            )
            if time_to:
                time_start = time_to.group(1).strip()
                time_end = time_to.group(2).strip()

        # 3. Extract Named IOCs or software names (e.g. TeamViewer, Mimikatz, PsExec, AnyDesk, whoami)
        known_iocs = [
            "teamviewer", "anydesk", "mimikatz", "psexec", "wmiexec", "whoami",
            "certutil", "rclone", "procdump", "vssadmin", "powershell", "cmd.exe",
            "lsass", "cobalt strike", "metasploit", "impacket", "credential",
            "lateral", "persistence", "escalation", "evasion", "discovery",
        ]
        g_lower = goal.lower()
        for ioc in known_iocs:
            if ioc in g_lower:
                keywords_or_iocs.append(ioc)

        # Extract IPv4 IOCs
        ipv4_regex = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", goal)
        for ip in ipv4_regex:
            if not ip.startswith("0.") and not ip.startswith("255."):
                keywords_or_iocs.append(ip)

        # Extract explicitly quoted terms e.g. "something.exe"
        quoted = re.findall(r'["\']([^"\']{2,})["\']', goal)
        for q in quoted:
            if q.lower() not in [k.lower() for k in keywords_or_iocs]:
                keywords_or_iocs.append(q)

        # Extract explicit regex if prefixed with regex: or pattern:
        regex_match = re.search(r'(?:regex|pattern):\s*["\']?([^"\'\s]+)["\']?', goal, re.IGNORECASE)
        if regex_match:
            regex_pat = regex_match.group(1)

        # Safe instantiation of ScopedFilterParams (handles ISO conversion)
        params_dict: Dict[str, Any] = {
            "keywords_or_iocs": list(dict.fromkeys(keywords_or_iocs)),
            "event_ids": sorted(list(set(event_ids))),
        }
        if regex_pat:
            params_dict["regex_pattern"] = regex_pat
        if time_start:
            params_dict["time_start_utc"] = time_start
        if time_end:
            params_dict["time_end_utc"] = time_end

        return ScopedFilterParams(**params_dict)


# Singleton instance
_PLAYBOOK_REGISTRY_INSTANCE: Optional[PlaybookRegistry] = None


def get_playbook_registry() -> PlaybookRegistry:
    """Retrieve global singleton instance of PlaybookRegistry."""
    global _PLAYBOOK_REGISTRY_INSTANCE
    if _PLAYBOOK_REGISTRY_INSTANCE is None:
        _PLAYBOOK_REGISTRY_INSTANCE = PlaybookRegistry()
    return _PLAYBOOK_REGISTRY_INSTANCE
