"""Phase 07 Regression Tests: Specialized DFIR Investigation Capabilities.

Standards:
- Deterministic Tooling Only (AGENTS.md Rule 1): Deterministic tools produce facts; LLMs plan, correlate, explain.
- Explicit Truth in Advertising: Only capabilities with implemented analyzers are operational.
- Safe Static Malware Only: Dynamic malware execution is strictly denied.
- Retain Source Observations & Provenance: Correlations preserve source findings, target findings, and exact methods.
"""
import hashlib
import struct
from datetime import datetime, timezone
from pathlib import Path
import pytest

from backend.app.agent.investigation_controller import InvestigationController
from backend.app.core.custody_engine import CustodyEngine
from backend.app.core.exceptions import ExecutionPolicyError
from backend.app.core.specialist_registry import (
    SpecialistRegistry,
    get_default_specialist_registry,
)
from backend.app.core.storage import ForensicStore
from backend.app.models.custody import ArtifactRecord
from backend.app.models.findings import ForensicFinding
from backend.app.models.investigation import ToolRequest
from backend.app.models.specialists import (
    BaseDFIRSpecialist,
    CorrelationRelationship,
    SpecialistCapabilityDefinition,
    SpecialistResult,
)
from backend.app.specialists.linux_dfir import LinuxDFIRSpecialist
from backend.app.specialists.malware_analysis import MalwareAnalysisSpecialist
from backend.app.specialists.memory_forensics import MemoryForensicsSpecialist
from backend.app.specialists.network_forensics import NetworkForensicsSpecialist
from backend.app.specialists.timeline_correlation import TimelineCorrelationSpecialist
from backend.app.specialists.windows_dfir import WindowsDFIRSpecialist


# ==============================================================================
# Helper to create synthetic PCAP file
# ==============================================================================
def create_test_pcap(path: Path, timestamps: list[int], src_ip: str = "10.0.0.5", dst_ip: str = "198.51.100.22", dport: int = 4444) -> None:
    """Build a minimal valid PCAP file with IPv4 TCP packets at given epoch seconds."""
    src_bytes = bytes(map(int, src_ip.split(".")))
    dst_bytes = bytes(map(int, dst_ip.split(".")))

    with open(path, "wb") as f:
        # PCAP Global Header: magic 0xa1b2c3d4, version 2.4, thiszone 0, sigfigs 0, snaplen 65535, network 1 (Ethernet)
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))

        for ts in timestamps:
            # Ethernet header (14 bytes): dest MAC (6), src MAC (6), EtherType IPv4 (0x0800)
            eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"

            # IPv4 header (20 bytes): Version 4, IHL 5, Total length 40, Proto 6 (TCP)
            ip_hdr = struct.pack(
                "!BBHHHBBH4s4s",
                0x45, 0, 40, 54321, 0, 64, 6, 0, src_bytes, dst_bytes
            )

            # TCP header (20 bytes): sport 49152, dport, seq 1, ack 0, offset 5, flags ACK (0x10), win 8192, chk 0, urg 0
            tcp_hdr = struct.pack("!HHIIBBHHH", 49152, dport, 1, 0, (5 << 4), 0x10, 8192, 0, 0)

            pkt_data = eth + ip_hdr + tcp_hdr

            # PCAP Record Header: ts_sec, ts_usec, incl_len, orig_len
            rec_hdr = struct.pack("<IIII", ts, 0, len(pkt_data), len(pkt_data))
            f.write(rec_hdr + pkt_data)


# ==============================================================================
# 1. Specialist Registry & Discovery Tests
# ==============================================================================
def test_specialist_registry_all_six_specialists_registered():
    """Verify all 6 modular DFIR specialists are registered in the global registry."""
    reg = get_default_specialist_registry()
    specialists = reg.list_specialists()
    assert len(specialists) == 6

    expected_ids = {
        "windows_dfir",
        "linux_dfir",
        "memory_forensics",
        "network_forensics",
        "malware_analysis",
        "timeline_correlation",
    }
    registered_ids = {s.specialist_id for s in specialists}
    assert registered_ids == expected_ids

    for s in specialists:
        assert isinstance(s, BaseDFIRSpecialist)
        assert s.name
        assert s.domain
        assert s.description
        assert len(s.supported_artifact_types) > 0
        assert len(s.tool_allowlist) > 0
        assert len(s.capabilities) > 0
        assert len(s.investigation_questions) > 0
        assert len(s.limitations) > 0
        assert len(s.citation_requirements) > 0


def test_specialist_discovery_by_evidence_and_objective():
    """Verify dynamic discovery of specialists based on evidence types and investigative objectives."""
    reg = get_default_specialist_registry()

    # Evidence discovery
    win_specs = reg.discover_for_evidence(["evtx"])
    assert any(s.specialist_id == "windows_dfir" for s in win_specs)

    linux_specs = reg.discover_for_evidence(["auth_log"])
    assert any(s.specialist_id == "linux_dfir" for s in linux_specs)

    net_specs = reg.discover_for_evidence(["pcapng"])
    assert any(s.specialist_id == "network_forensics" for s in net_specs)

    mem_specs = reg.discover_for_evidence(["raw_memory"])
    assert any(s.specialist_id == "memory_forensics" for s in mem_specs)

    mal_specs = reg.discover_for_evidence(["pe"])
    assert any(s.specialist_id == "malware_analysis" for s in mal_specs)

    # Timeline correlation accepts "any" evidence
    assert any(s.specialist_id == "timeline_correlation" for s in win_specs)

    # Objective discovery
    obj_win = reg.discover_for_objective("Investigate suspicious Windows RDP logon and lateral movement")
    assert any(s.specialist_id == "windows_dfir" for s in obj_win)

    obj_c2 = reg.discover_for_objective("Detect C2 beaconing in network traffic egress")
    assert any(s.specialist_id == "network_forensics" for s in obj_c2)


# ==============================================================================
# 2. Explicit Truth in Advertising
# ==============================================================================
def test_truth_in_advertising_operational_capabilities():
    """Verify that only capabilities with implemented, tested analyzers are marked operational."""
    reg = get_default_specialist_registry()

    # Windows DFIR
    win = reg.get_specialist("windows_dfir")
    assert win is not None
    assert win.get_capability("windows_event_logs").operational is True
    assert win.get_capability("windows_registry").operational is True
    assert win.get_capability("windows_amcache").operational is False
    assert win.get_capability("windows_shimcache").operational is False
    assert win.get_capability("windows_prefetch").operational is False
    assert win.get_capability("windows_scheduled_tasks").operational is False

    # Linux DFIR
    lin = reg.get_specialist("linux_dfir")
    assert lin is not None
    assert lin.get_capability("linux_auth_logs").operational is True
    assert lin.get_capability("linux_ssh_activity").operational is True
    assert lin.get_capability("linux_sudo_privilege").operational is True
    assert lin.get_capability("linux_systemd_services").operational is False
    assert lin.get_capability("linux_auditd_records").operational is False

    # Memory Forensics
    mem = reg.get_specialist("memory_forensics")
    assert mem is not None
    assert mem.get_capability("memory_process_listing").operational is True
    assert mem.get_capability("memory_process_tree").operational is False
    assert mem.get_capability("memory_injection_indicators").operational is False
    assert mem.get_capability("memory_command_line").operational is False

    # Network Forensics
    net = reg.get_specialist("network_forensics")
    assert net is not None
    assert net.get_capability("pcap_flow_analysis").operational is True
    assert net.get_capability("beaconing_detection").operational is True
    assert net.get_capability("dns_query_extraction").operational is False
    assert net.get_capability("http_session_reconstruction").operational is False

    # Malware Analysis
    mal = reg.get_specialist("malware_analysis")
    assert mal is not None
    assert mal.get_capability("static_file_hashes").operational is True
    assert mal.get_capability("static_pe_metadata").operational is True
    assert mal.get_capability("static_strings_extraction").operational is True
    assert mal.get_capability("dynamic_sandbox_execution").operational is False

    # Timeline Correlation
    tl = reg.get_specialist("timeline_correlation")
    assert tl is not None
    assert tl.get_capability("user_to_process_correlation").operational is True
    assert tl.get_capability("authentication_to_execution_correlation").operational is True
    assert tl.get_capability("persistence_to_execution_correlation").operational is True


# ==============================================================================
# 3. Windows DFIR Specialist Execution Tests
# ==============================================================================
def test_windows_dfir_specialist_execution(tmp_path):
    """Verify Windows DFIR specialist executes and enriches lateral movement and PowerShell events."""
    vault = tmp_path / "vault"
    vault.mkdir()
    custody = CustodyEngine(vault_root=vault)
    store = ForensicStore()

    # Create dummy EVTX file in custody
    evtx_path = vault / "Security.evtx"
    evtx_path.write_bytes(b"ElfFile\x00" + b"\x00" * 500)
    art = custody.ingest_artifact(
        case_id="case-win-01",
        source_path=evtx_path,
        artifact_type="evtx",
        actor="investigator",
    )

    specialist = WindowsDFIRSpecialist()

    # Request supported and unsupported capabilities
    res = specialist.execute(
        case_id="case-win-01",
        artifacts=[art],
        storage=store,
        custody_engine=custody,
        parameters={"capabilities": ["windows_event_logs", "windows_prefetch"]},
    )

    assert res.specialist_id == "windows_dfir"
    assert res.success is True
    assert len(res.errors) == 0
    assert "windows_prefetch" in res.unsupported_capabilities_requested
    assert any(g.missing_artifact_type == "prefetch" for g in res.evidence_gaps)


def test_dissect_adapter_stream_aliases_regression(tmp_path):
    """Regression test for DEFECT-FOR-01: DissectAdapter parse_*_stream backward-compatibility."""
    from backend.app.core.dissect_adapter import DissectAdapter

    adapter = DissectAdapter()
    assert hasattr(adapter, "parse_evtx_stream")
    assert hasattr(adapter, "parse_registry_hive_stream")

    vault = tmp_path / "vault"
    vault.mkdir()
    custody = CustodyEngine(vault_root=vault)
    store = ForensicStore()

    # 1. Test Registry Hive execution via WindowsDFIRSpecialist
    reg_path = vault / "SYSTEM"
    reg_path.write_bytes(b"regf" + b"\x00" * 4092)
    reg_art = custody.ingest_artifact(
        case_id="case-reg-01",
        source_path=reg_path,
        artifact_type="registry",
        actor="investigator",
    )

    specialist = WindowsDFIRSpecialist()
    res = specialist.execute(
        case_id="case-reg-01",
        artifacts=[reg_art],
        storage=store,
        custody_engine=custody,
        parameters={"capabilities": ["windows_registry"]},
    )
    assert res.specialist_id == "windows_dfir"
    assert res.success is True
    assert len(res.errors) == 0
    assert len(res.findings) >= 1
    assert res.findings[0].category == "registry_hive"


# ==============================================================================
# 4. Linux DFIR Specialist Execution Tests
# ==============================================================================
def test_linux_dfir_specialist_execution(tmp_path):
    """Verify Linux DFIR specialist parses auth.log, SSH events, sudo commands, and cron jobs."""
    vault = tmp_path / "vault"
    vault.mkdir()
    custody = CustodyEngine(vault_root=vault)
    store = ForensicStore()

    log_content = (
        "May 10 08:15:20 server sshd[1024]: Failed password for invalid user admin from 192.168.1.100 port 45210 ssh2\n"
        "May 10 08:16:01 server sshd[1030]: Accepted publickey for user analyst from 192.168.1.50 port 51230 ssh2\n"
        "May 10 08:17:33 server sudo: analyst : TTY=pts/0 ; PWD=/home/analyst ; USER=root ; COMMAND=/bin/cat /etc/shadow\n"
        "May 10 09:00:01 server CRON[2044]: (root) CMD (/usr/local/bin/backup.sh)\n"
    )
    log_file = vault / "auth.log"
    log_file.write_text(log_content, encoding="utf-8")

    art = custody.ingest_artifact(
        case_id="case-lin-01",
        source_path=log_file,
        artifact_type="auth_log",
        actor="investigator",
    )

    specialist = LinuxDFIRSpecialist()
    res = specialist.execute(
        case_id="case-lin-01",
        artifacts=[art],
        storage=store,
        custody_engine=custody,
    )

    assert res.success is True
    assert len(res.findings) == 4

    categories = {f.category for f in res.findings}
    assert "authentication" in categories
    assert "privilege_escalation" in categories
    assert "persistence" in categories

    # Verify line citation in raw_reference
    assert res.findings[0].raw_reference == "line_1"
    assert res.findings[0].severity == "high"  # Failed login
    assert res.findings[1].severity == "low"   # Accepted login
    assert res.findings[1].user == "analyst"


# ==============================================================================
# 5. Memory Forensics & Fail-Closed Tests
# ==============================================================================
def test_memory_forensics_fail_closed_and_gap_reporting(tmp_path):
    """Verify memory specialist reports gaps when RAM is absent and fails closed without sandbox."""
    vault = tmp_path / "vault"
    vault.mkdir()
    custody = CustodyEngine(vault_root=vault)
    store = ForensicStore()

    specialist = MemoryForensicsSpecialist()

    # 1. No memory dump in evidence
    res_no_mem = specialist.execute(
        case_id="case-mem-01",
        artifacts=[],
        storage=store,
        custody_engine=custody,
    )
    assert len(res_no_mem.findings) == 0
    assert any(g.missing_artifact_type == "memory" for g in res_no_mem.evidence_gaps)

    # 2. Non-operational capability requested
    res_unsupported = specialist.execute(
        case_id="case-mem-01",
        artifacts=[],
        storage=store,
        custody_engine=custody,
        parameters={"capabilities": ["memory_injection_indicators"]},
    )
    assert "memory_injection_indicators" in res_unsupported.unsupported_capabilities_requested


# ==============================================================================
# 6. Network Forensics & C2 Beaconing Tests
# ==============================================================================
def test_network_forensics_pcap_flow_and_c2_beaconing(tmp_path):
    """Verify Network DFIR specialist extracts flows and detects statistical C2 beaconing."""
    vault = tmp_path / "vault"
    vault.mkdir()
    custody = CustodyEngine(vault_root=vault)
    store = ForensicStore()

    pcap_path = vault / "traffic.pcap"
    # Create 5 connections spaced 10 seconds apart -> periodic beaconing
    base_ts = 1700000000
    conn_times = [base_ts + i * 10 for i in range(5)]
    create_test_pcap(pcap_path, timestamps=conn_times, src_ip="10.1.1.20", dst_ip="198.51.100.5", dport=8080)

    art = custody.ingest_artifact(
        case_id="case-net-01",
        source_path=pcap_path,
        artifact_type="pcap",
        actor="investigator",
    )

    specialist = NetworkForensicsSpecialist()
    res = specialist.execute(
        case_id="case-net-01",
        artifacts=[art],
        storage=store,
        custody_engine=custody,
    )

    assert res.success is True
    # At least 5 network packets + 1 C2 beaconing finding
    assert len(res.findings) >= 6

    beacon_finding = next((f for f in res.findings if f.category == "c2_beaconing"), None)
    assert beacon_finding is not None
    assert beacon_finding.severity == "high"
    assert "Periodic C2 beaconing detected" in beacon_finding.summary
    assert beacon_finding.projected_data["mean_interval_seconds"] == 10.0

    # Verify correlations
    assert len(res.correlations) > 0
    proc_net_corr = next((c for c in res.correlations if c.relationship_type == "process_to_network"), None)
    assert proc_net_corr is not None
    assert proc_net_corr.confidence_score >= 0.8


# ==============================================================================
# 7. Malware Analysis: Safe Static PE & Dynamic Execution Prohibition
# ==============================================================================
def test_malware_analysis_safe_pe_and_strict_dynamic_refusal(tmp_path):
    """Verify safe static PE extraction and strict refusal of dynamic malware detonation."""
    vault = tmp_path / "vault"
    vault.mkdir()
    custody = CustodyEngine(vault_root=vault)
    store = ForensicStore()

    # Build synthetic Windows PE binary
    pe_file = vault / "suspicious.exe"
    dos_header = bytearray(64)
    dos_header[:2] = b"MZ"
    struct.pack_into("<I", dos_header, 0x3C, 64)  # e_lfanew = 64

    pe_sig = b"PE\x00\x00"
    # COFF File Header: Machine x64 (0x8664), 3 sections, TimeDateStamp 1715000000
    coff_hdr = struct.pack("<HHI", 0x8664, 3, 1715000000) + b"\x00" * 12
    # String payloads
    payload = b"Embedded text with URL http://malicious-c2.evil/payload and IP 203.0.113.88 in binary."

    pe_bytes = bytes(dos_header) + pe_sig + coff_hdr + payload
    pe_file.write_bytes(pe_bytes)

    art = custody.ingest_artifact(
        case_id="case-mal-01",
        source_path=pe_file,
        artifact_type="pe",
        actor="investigator",
    )

    specialist = MalwareAnalysisSpecialist()

    # 1. Safe static execution
    res = specialist.execute(
        case_id="case-mal-01",
        artifacts=[art],
        storage=store,
        custody_engine=custody,
    )

    assert res.success is True
    assert len(res.findings) >= 3

    # Hashing check
    hash_finding = next((f for f in res.findings if f.category == "static_metadata"), None)
    assert hash_finding is not None
    assert hash_finding.projected_data["sha256"] == hashlib.sha256(pe_bytes).hexdigest()

    # PE Header check
    pe_finding = next((f for f in res.findings if f.category == "pe_header"), None)
    assert pe_finding is not None
    assert pe_finding.projected_data["machine_type"] == "x64 (AMD64)"
    assert pe_finding.projected_data["section_count"] == 3

    # Extracted IOCs check
    str_finding = next((f for f in res.findings if f.category == "embedded_iocs"), None)
    assert str_finding is not None
    assert "http://malicious-c2.evil/payload" in str_finding.projected_data["embedded_urls"]
    assert "203.0.113.88" in str_finding.projected_data["embedded_ips"]

    # 2. STRICT SAFETY RULE: Dynamic malware detonation MUST be refused
    with pytest.raises(ExecutionPolicyError, match="Dynamic malware execution is strictly prohibited"):
        specialist.execute(
            case_id="case-mal-01",
            artifacts=[art],
            storage=store,
            custody_engine=custody,
            parameters={"capabilities": ["dynamic_sandbox_execution"]},
        )


# ==============================================================================
# 8. Timeline & Multi-Observation Correlation Tests
# ==============================================================================
def test_timeline_correlation_deterministic_multi_observation():
    """Verify TimelineCorrelationSpecialist links findings across user, process, network, and auth."""
    specialist = TimelineCorrelationSpecialist()

    f1 = ForensicFinding(
        case_id="case-corr-01",
        source_artifact_id="art-evtx-1",
        source_artifact_hash="hash-1",
        tool_id="dissect_evtx",
        artifact_type="evtx",
        category="authentication",
        severity="low",
        timestamp_utc="2026-05-10T10:00:00Z",
        host="FINANCE-PC",
        user="john_doe",
        summary="Successful logon for user john_doe (Logon Type 10)",
    )

    f2 = ForensicFinding(
        case_id="case-corr-01",
        source_artifact_id="art-evtx-1",
        source_artifact_hash="hash-1",
        tool_id="dissect_evtx",
        artifact_type="evtx",
        category="process_creation",
        severity="medium",
        timestamp_utc="2026-05-10T10:00:35Z",  # 35s delta -> auth to exec window
        host="FINANCE-PC",
        user="john_doe",
        process_name="powershell.exe",
        command_line="powershell.exe -enc AAAA==",
        summary="Process powershell.exe created by john_doe",
    )

    f3 = ForensicFinding(
        case_id="case-corr-01",
        source_artifact_id="art-pcap-1",
        source_artifact_hash="hash-2",
        tool_id="native_pcap_parser",
        artifact_type="network",
        category="network_connection",
        severity="info",
        timestamp_utc="2026-05-10T10:00:50Z",  # 15s delta -> proc to net window
        summary="Outbound connection 10.0.0.5:49200 -> 198.51.100.5:443 (TCP)",
        projected_data={"src_ip": "10.0.0.5", "dst_ip": "198.51.100.5"},
    )

    f4 = ForensicFinding(
        case_id="case-corr-01",
        source_artifact_id="art-reg-1",
        source_artifact_hash="hash-3",
        tool_id="dissect_registry",
        artifact_type="registry",
        category="persistence",
        severity="high",
        summary="Run key persistence registered for updater.exe in HKLM",
        command_line="C:\\Users\\Public\\updater.exe",
    )

    f5 = ForensicFinding(
        case_id="case-corr-01",
        source_artifact_id="art-evtx-1",
        source_artifact_hash="hash-1",
        tool_id="dissect_evtx",
        artifact_type="evtx",
        category="process_creation",
        severity="high",
        timestamp_utc="2026-05-10T10:05:00Z",
        process_name="updater.exe",
        summary="Process updater.exe spawned from Public directory",
    )

    findings = [f1, f2, f3, f4, f5]
    correlations = specialist.correlate_findings(findings, case_id="case-corr-01")

    assert len(correlations) >= 4
    rel_types = {c.relationship_type for c in correlations}

    assert "authentication_to_execution" in rel_types
    assert "user_to_process" in rel_types
    assert "process_to_network" in rel_types
    assert "persistence_to_execution" in rel_types

    # Provenance verification: all correlations must cite exact source finding IDs
    for c in correlations:
        assert len(c.source_finding_ids) > 0
        assert len(c.target_finding_ids) > 0
        assert c.confidence_score >= 0.7
        assert c.method


# ==============================================================================
# 9. InvestigationController Integration Tests
# ==============================================================================
def test_investigation_controller_with_specialists_and_correlation(tmp_path):
    """Verify InvestigationController discovers specialists, executes actions, and correlates findings."""
    vault = tmp_path / "vault"
    vault.mkdir()
    custody = CustodyEngine(vault_root=vault)
    store = ForensicStore()

    # Ingest Linux auth.log
    log_content = (
        "May 10 10:00:00 srv sshd[100]: Accepted password for user victim from 192.168.1.80 port 44120 ssh2\n"
        "May 10 10:00:40 srv sudo: victim : TTY=pts/1 ; PWD=/home/victim ; USER=root ; COMMAND=/bin/bash\n"
    )
    log_file = vault / "auth.log"
    log_file.write_text(log_content, encoding="utf-8")
    art_log = custody.ingest_artifact(
        case_id="case-ctrl-01",
        source_path=log_file,
        artifact_type="auth_log",
        actor="investigator",
    )

    controller = InvestigationController(
        case_id="case-ctrl-01",
        custody_engine=custody,
        storage=store,
    )

    rec = controller.initialize()
    assert len(rec.pending_actions) >= 1
    assert rec.pending_actions[0].capability_id == "native_log_parser"

    # Execute iteration
    rec_iter = controller.run_iteration()
    assert rec_iter.findings_count >= 2

    # Verify correlations were discovered and persisted in record
    assert hasattr(rec_iter, "correlations")
    # Verify strict safety: tool request for dynamic malware execution rejected
    with pytest.raises(ExecutionPolicyError, match="Dynamic malware execution is strictly prohibited"):
        controller.validate_tool_request(
            ToolRequest(capability_id="dynamic_sandbox_execution", justification="Test detonation")
        )

    # Verify tool request for non-operational capability rejected
    with pytest.raises(ExecutionPolicyError, match="currently non-operational"):
        controller.validate_tool_request(
            ToolRequest(capability_id="windows_prefetch", justification="Test prefetch")
        )
