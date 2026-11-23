"""Phase 15-A Verification Suite: Forensic Engine & Dissect Integration.

Tests:
1. Read-only evidence integrity: Evidence hashes (SHA-256, SHA-512) immutable before and after parsing.
2. Flat RAW/DD disk stream parsing (MBR/GPT userspace inspection, zero kernel mounting).
3. Windows EVTX parsing and stream aliases.
4. Windows Registry hive parsing via WindowsRegistryHiveParser.
5. Triage directory recursive parsing.
6. Clean rejection of unsupported E01/VMDK container formats.
7. PluginRunner.execute_analyzer dispatch for Tier A and Tier B.
8. Provenance preservation across all findings (case_id, artifact_id, artifact_hash, tool_id, tool_version).
9. Fail-closed handling for missing container runtime or tools.
"""
from __future__ import annotations

import hashlib
import json
import os
import struct
from pathlib import Path
from typing import Dict
from uuid import uuid4

import pytest

from backend.app.core.analyzer_registry import get_analyzer_registry
from backend.app.core.custody_engine import CustodyEngine
from backend.app.core.dissect_adapter import DissectAdapter
from backend.app.core.exceptions import ForensicOpsError, SandboxUnavailableError
from backend.app.core.plugin_runner import AirGappedSubprocessRunner, PluginRunner
from backend.app.models.custody import ArtifactRecord
from backend.app.models.findings import ForensicFinding


@pytest.fixture
def temp_vault(tmp_path: Path):
    vault = tmp_path / "vault"
    vault.mkdir(parents=True, exist_ok=True)
    return vault


@pytest.fixture
def custody(temp_vault: Path):
    return CustodyEngine(vault_root=temp_vault)


def _compute_hashes(path: Path) -> Dict[str, str]:
    data = path.read_bytes()
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha512": hashlib.sha512(data).hexdigest(),
    }


# ==============================================================================
# 1. Read-Only Evidence Immutability Tests
# ==============================================================================
def test_evidence_immutability_guaranteed(tmp_path: Path, custody: CustodyEngine):
    """Verify that original evidence files are never modified during analysis."""
    adapter = DissectAdapter()
    test_file = tmp_path / "test_immutability.evtx"
    test_file.write_bytes(b"ElfFile\x00" + b"\x00" * 1024)

    hashes_before = _compute_hashes(test_file)

    # Ingest and parse
    art = custody.ingest_artifact(
        case_id="case-imm-01",
        source_path=test_file,
        artifact_type="evtx",
        actor="lead_investigator",
    )

    findings = adapter.parse_evtx(
        file_path=test_file,
        case_id="case-imm-01",
        artifact_id=art.artifact_id,
        artifact_hash=art.sha256,
    )

    hashes_after = _compute_hashes(test_file)
    assert hashes_before["sha256"] == hashes_after["sha256"]
    assert hashes_before["sha512"] == hashes_after["sha512"]


# ==============================================================================
# 2. Flat RAW/DD Disk Stream Parsing (Userspace MBR/GPT)
# ==============================================================================
def test_raw_disk_stream_mbr_and_gpt_parsing(tmp_path: Path):
    """Verify flat RAW/DD disk stream parsing inspects MBR and GPT partition tables in userspace."""
    adapter = DissectAdapter()
    raw_img = tmp_path / "disk.raw"

    # Construct synthetic 1MB disk with MBR boot signature and 1 partition entry
    data = bytearray(1024 * 1024)
    # Boot signature 0x55AA at offset 510-512
    data[510:512] = b"\x55\xaa"
    # Partition 1 at offset 446: Bootable=0x80, Type=0x07 (NTFS), Start LBA=2048, Sectors=1000
    part_entry = struct.pack("<B3sB3sII", 0x80, b"\x00\x00\x00", 0x07, b"\x00\x00\x00", 2048, 1000)
    data[446 : 446 + 16] = part_entry

    # GPT Header at LBA 1 (offset 512)
    gpt_sig = b"EFI PART"
    gpt_header = gpt_sig + b"\x00\x00\x01\x00" + struct.pack("<I", 92) + b"\x00" * 8 + struct.pack("<Q", 1) + b"\x00" * 400
    data[512 : 512 + len(gpt_header)] = gpt_header

    raw_img.write_bytes(bytes(data))

    findings = adapter.parse_disk_image_stream(
        image_path=raw_img,
        case_id="case-disk-01",
        artifact_id="art-disk-01",
        artifact_hash="hash-disk-01",
    )

    assert len(findings) >= 2
    mbr_f = [f for f in findings if f.raw_reference == "MBR_Partition_1"][0]
    assert mbr_f.category == "disk_partition"
    assert mbr_f.projected_data["type_hex"] == "0x07"
    assert mbr_f.projected_data["bootable"] is True
    assert mbr_f.projected_data["start_lba"] == 2048

    gpt_f = [f for f in findings if f.raw_reference == "GPT_Header_LBA1"][0]
    assert gpt_f.projected_data["partition_table"] == "GPT"


# ==============================================================================
# 3. Clean Rejection of Unsupported E01 / VMDK Formats
# ==============================================================================
def test_unsupported_e01_and_vmdk_rejection(tmp_path: Path):
    """Verify proprietary E01 and VMDK container formats are explicitly rejected fail-closed."""
    adapter = DissectAdapter()

    # E01 signature
    e01_img = tmp_path / "image.E01"
    e01_img.write_bytes(b"EVF01\r\n\x00\x00" + b"\x00" * 1024)

    with pytest.raises(ForensicOpsError, match="Unsupported container format.*E01/VMDK"):
        adapter.parse_disk_image_stream(
            image_path=e01_img,
            case_id="case-e01-01",
            artifact_id="art-01",
            artifact_hash="hash-01",
        )

    # VMDK signature
    vmdk_img = tmp_path / "disk.vmdk"
    vmdk_img.write_bytes(b"KDMV" + b"\x00" * 1024)

    with pytest.raises(ForensicOpsError, match="Unsupported container format.*E01/VMDK"):
        adapter.parse_disk_image_stream(
            image_path=vmdk_img,
            case_id="case-vmdk-01",
            artifact_id="art-02",
            artifact_hash="hash-02",
        )


# ==============================================================================
# 4. Windows Registry Hive Parsing Integration
# ==============================================================================
def test_registry_hive_parsing_integration(tmp_path: Path):
    """Verify registry hive parser extracts forensic findings with valid provenance."""
    adapter = DissectAdapter()
    reg_file = tmp_path / "SYSTEM"
    # 4096-byte header with regf magic
    reg_file.write_bytes(b"regf" + b"\x00" * 4092)

    findings = adapter.parse_registry_hive(
        hive_path=reg_file,
        case_id="case-reg-01",
        artifact_id="art-reg-01",
        artifact_hash="hash-reg-01",
    )

    assert len(findings) >= 1
    f = findings[0]
    assert f.case_id == "case-reg-01"
    assert f.source_artifact_id == "art-reg-01"
    assert f.source_artifact_hash == "hash-reg-01"
    assert f.tool_id == "dissect_registry"
    assert f.category == "registry_hive"


# ==============================================================================
# 5. Triage Directory Recursive Extraction
# ==============================================================================
def test_triage_directory_extraction(tmp_path: Path):
    """Verify parse_triage_directory recursively walks and extracts EVTX, Registry, and JSON logs."""
    adapter = DissectAdapter()
    triage_dir = tmp_path / "triage_dump"
    triage_dir.mkdir()

    logs_subdir = triage_dir / "logs"
    logs_subdir.mkdir()

    # 1. EVTX log
    evtx_path = logs_subdir / "Application.evtx"
    evtx_path.write_bytes(b"ElfFile\x00" + b"\x00" * 500)

    # 2. Registry hive
    reg_path = triage_dir / "SOFTWARE"
    reg_path.write_bytes(b"regf" + b"\x00" * 4092)

    # 3. Collector JSON
    json_path = triage_dir / "processes.json"
    json_path.write_text(
        json.dumps([{"process_name": "cmd.exe", "command_line": "cmd.exe /c whoami", "user": "SYSTEM"}]),
        encoding="utf-8",
    )

    findings = adapter.parse_triage_directory(
        directory_path=triage_dir,
        case_id="case-triage-01",
        artifact_id="art-triage-01",
        artifact_hash="hash-triage-01",
    )

    assert len(findings) >= 2  # At least registry header and collector process
    categories = {f.category for f in findings}
    assert "registry_hive" in categories
    assert "process_list" in categories


# ==============================================================================
# 6. PluginRunner.execute_analyzer Provenance & Execution Dispatch
# ==============================================================================
def test_plugin_runner_execute_analyzer_tier_a(tmp_path: Path, custody: CustodyEngine):
    """Verify PluginRunner.execute_analyzer correctly dispatches Tier A built-in analyzers with provenance."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    evtx_path = tmp_path / "Security.evtx"
    evtx_path.write_bytes(b"ElfFile\x00" + b"\x00" * 500)

    art = custody.ingest_artifact(
        case_id="case-exec-01",
        source_path=evtx_path,
        artifact_type="evtx",
        actor="investigator",
    )

    runner = PluginRunner(custody_engine=custody)
    result = runner.execute_analyzer(
        tool_id="dissect_evtx",
        artifact=art,
        output_workspace=workspace,
    )

    assert result.tool_id == "dissect_evtx"
    assert result.success is True
    assert result.exit_code == 0
    assert result.source_artifact_hash == art.sha256


def test_plugin_runner_execute_analyzer_unsupported_e01(tmp_path: Path, custody: CustodyEngine):
    """Verify execute_analyzer cleanly reports unsupported E01 format with warning instead of crashing."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    e01_path = tmp_path / "disk.E01"
    e01_path.write_bytes(b"EVF01\r\n\x00\x00" + b"\x00" * 500)

    art = custody.ingest_artifact(
        case_id="case-e01-test",
        source_path=e01_path,
        artifact_type="e01",
        actor="investigator",
    )

    runner = PluginRunner(custody_engine=custody)
    result = runner.execute_analyzer(
        tool_id="dissect_disk_stream",
        artifact=art,
        output_workspace=workspace,
        raise_on_error=False,
    )

    assert result.success is False
    assert any("E01 or VMDK" in w for w in result.warnings)
    assert any("E01 or VMDK" in e for e in result.errors)


def test_plugin_runner_execute_analyzer_tier_b_mock(tmp_path: Path, custody: CustodyEngine):
    """Verify execute_analyzer executes Tier B tools under mock handler and preserves provenance."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    evtx_path = tmp_path / "Security.evtx"
    evtx_path.write_bytes(b"ElfFile\x00" + b"\x00" * 500)

    art = custody.ingest_artifact(
        case_id="case-mock-01",
        source_path=evtx_path,
        artifact_type="evtx",
        actor="investigator",
    )

    sub_runner = AirGappedSubprocessRunner(allow_test_mock=True)

    def mock_chainsaw(argv, in_dir, out_dir):
        # Write valid mock JSON output
        out = [{"timestamp": "2026-11-20T10:00:00Z", "id": "1", "name": "Suspicious Process", "level": "high"}]
        return 0, json.dumps(out), ""

    sub_runner.register_mock_tool("chainsaw", mock_chainsaw)

    runner = PluginRunner(subprocess_runner=sub_runner, custody_engine=custody)
    result = runner.execute_analyzer(
        tool_id="chainsaw_sigma",
        artifact=art,
        output_workspace=workspace,
    )

    assert result.success is True
    assert result.tool_id == "chainsaw_sigma"
    assert len(result.findings) >= 1
    finding = result.findings[0]
    assert finding.case_id == "case-mock-01"
    assert finding.source_artifact_id == art.artifact_id
    assert finding.source_artifact_hash == art.sha256
    assert finding.tool_id == "chainsaw_sigma"


def test_plugin_runner_execute_analyzer_missing_container_runtime(tmp_path: Path, custody: CustodyEngine, monkeypatch: pytest.MonkeyPatch):
    """Verify execute_analyzer returns clean fail-closed warning when container runtime is missing."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    evtx_path = tmp_path / "Security.evtx"
    evtx_path.write_bytes(b"ElfFile\x00" + b"\x00" * 500)

    art = custody.ingest_artifact(
        case_id="case-fail-01",
        source_path=evtx_path,
        artifact_type="evtx",
        actor="investigator",
    )

    sub_runner = AirGappedSubprocessRunner(allow_test_mock=False)
    monkeypatch.setattr("backend.app.core.plugin_runner.is_container_runtime_available", lambda rt: False)

    runner = PluginRunner(subprocess_runner=sub_runner, custody_engine=custody)
    result = runner.execute_analyzer(
        tool_id="chainsaw_sigma",
        artifact=art,
        output_workspace=workspace,
        raise_on_error=False,
    )

    assert result.success is False
    assert any("Sandbox execution failed" in e or "unavailable" in e.lower() for e in result.errors)
