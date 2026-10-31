"""Phase 1 Custody and Evidence Sandbox Test Suite.

Tests RFC 3227 custody chain integrity, 4-layer sandbox defenses,
Streaming Zip Guard, defanged .blob vault, and capsule unpacker.
"""
import hashlib
import io
import json
import os
import stat
import sqlite3
import zipfile
import pytest
from pathlib import Path

from backend.app.core.custody_engine import CustodyEngine, GENESIS_HASH, safe_make_writable
from backend.app.core.exceptions import (
    CustodyTamperError,
    DecompressionBombError,
    ForensicOpsError,
    HashMismatchError,
    SuspiciousArchiveError,
    ZipSlipError,
)
from backend.app.models.custody import ArtifactRecord, CustodyChainEntry


@pytest.fixture
def temp_vault(tmp_path):
    """Provide a fresh temporary vault root directory."""
    vault_dir = tmp_path / "vault"
    vault_dir.mkdir(parents=True, exist_ok=True)
    yield vault_dir
    # Cleanup permissions to ensure Windows tear-down succeeds
    for root, dirs, files in os.walk(vault_dir):
        for f in files:
            safe_make_writable(Path(root) / f)


@pytest.fixture
def engine(temp_vault):
    """Provide a CustodyEngine instance attached to the temporary vault."""
    return CustodyEngine(vault_root=temp_vault)


# ------------------------------------------------------------------------------
# Test 1: Streaming Zip Guard - Zip Slip Directory Traversal
# ------------------------------------------------------------------------------
def test_streaming_zip_guard_zip_slip_relative(engine, tmp_path):
    """Verify that archives with relative traversal components ('..') are blocked."""
    zip_path = tmp_path / "malicious_slip.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("../../evil.bat", b"@echo off\r\ncalc.exe")

    extract_dest = tmp_path / "extract_dest"
    with pytest.raises(ZipSlipError):
        engine.safe_extract_archive(zip_path, extract_dest)


def test_streaming_zip_guard_zip_slip_absolute(engine, tmp_path):
    """Verify that archives with absolute paths are blocked."""
    zip_path = tmp_path / "malicious_abs.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("/etc/cron.d/malicious", b"* * * * * root /tmp/evil.sh")

    extract_dest = tmp_path / "extract_dest"
    with pytest.raises(ZipSlipError):
        engine.safe_extract_archive(zip_path, extract_dest)


# ------------------------------------------------------------------------------
# Test 2: Streaming Zip Guard - Symlink Prevention
# ------------------------------------------------------------------------------
def test_streaming_zip_guard_symlink_blocking(engine, tmp_path):
    """Verify that archives containing symlinks are blocked."""
    zip_path = tmp_path / "malicious_symlink.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        info = zipfile.ZipInfo("symlink_pointer")
        # 0o120000 = S_IFLNK (symlink)
        info.external_attr = 0o120777 << 16
        zf.writestr(info, "/etc/shadow")

    extract_dest = tmp_path / "extract_dest"
    with pytest.raises(SuspiciousArchiveError):
        engine.safe_extract_archive(zip_path, extract_dest)


# ------------------------------------------------------------------------------
# Test 3: Streaming Zip Guard - Decompression Bomb Defense
# ------------------------------------------------------------------------------
def test_streaming_zip_guard_ratio_bomb(engine, tmp_path):
    """Verify that archives exceeding safe compression ratios are blocked."""
    zip_path = tmp_path / "decompression_bomb.zip"
    payload = b"0" * (5 * 1024 * 1024)  # 5 MB of zeroes compresses to very few bytes
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("huge_zeroes.dat", payload)

    extract_dest = tmp_path / "extract_dest"
    # Setting max_ratio=5.0 should catch the ~1000x ratio
    with pytest.raises(DecompressionBombError):
        engine.safe_extract_archive(zip_path, extract_dest, max_ratio=5.0)


def test_streaming_zip_guard_size_quota_exceeded(engine, tmp_path):
    """Verify that archives exceeding maximum file size quota are blocked."""
    zip_path = tmp_path / "quota_exceeded.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("file.txt", b"A" * 2000)

    extract_dest = tmp_path / "extract_dest"
    with pytest.raises(DecompressionBombError):
        engine.safe_extract_archive(zip_path, extract_dest, max_single_size_bytes=1000)


# ------------------------------------------------------------------------------
# Test 4: Defanged .blob Vault Storage & Read-Only Permissions
# ------------------------------------------------------------------------------
def test_defanged_blob_vault_permissions_and_naming(engine, tmp_path):
    """Verify executable files are defanged to .blob and made read-only."""
    malware_src = tmp_path / "mimikatz.exe"
    malware_bytes = b"MZ\x90\x00\x03\x00\x00\x00mimikatz_test_binary"
    malware_src.write_bytes(malware_bytes)

    expected_sha256 = hashlib.sha256(malware_bytes).hexdigest()
    expected_sha512 = hashlib.sha512(malware_bytes).hexdigest()

    record = engine.ingest_artifact(
        case_id="CASE-2026-001",
        source_path=malware_src,
        artifact_type="pe_executable",
        actor="lead_analyst",
    )

    assert record.sha256 == expected_sha256
    assert record.sha512 == expected_sha512
    assert record.blob_path == f"blobs/{expected_sha256[:2]}/{expected_sha256}.blob"

    blob_file = engine.vault_root / record.blob_path
    assert blob_file.exists()
    assert blob_file.name.endswith(".blob")
    assert not blob_file.name.endswith(".exe")

    # Verify read-only permission (stat.S_IWRITE is not set, or writing fails)
    file_mode = os.stat(blob_file).st_mode
    if os.name == "nt":
        assert not (file_mode & stat.S_IWRITE)
    else:
        assert (file_mode & 0o777) == 0o400


# ------------------------------------------------------------------------------
# Test 5: Zero-Copy Read-Only Reference (:ro)
# ------------------------------------------------------------------------------
def test_zero_copy_read_only_reference(engine, tmp_path):
    """Verify large disk images can be referenced in place without data duplication."""
    image_path = tmp_path / "server_image.E01"
    image_data = b"EVF\x09\x0d\x0a\xff\x00simulated_raw_image_data" * 100
    image_path.write_bytes(image_data)

    expected_sha256 = hashlib.sha256(image_data).hexdigest()
    expected_sha512 = hashlib.sha512(image_data).hexdigest()

    record = engine.register_zero_copy_reference(
        case_id="CASE-2026-002",
        file_path=image_path,
        artifact_type="disk_image",
        actor="triage_officer",
    )

    assert record.blob_path == f":ro:{image_path.resolve()}"
    assert record.acquisition_method == "zero_copy_reference"
    assert record.sha256 == expected_sha256
    assert record.sha512 == expected_sha512
    assert record.size_bytes == len(image_data)

    # Check that image was NOT duplicated into the blobs folder
    shard_blob = engine.blobs_dir / expected_sha256[:2] / f"{expected_sha256}.blob"
    assert not shard_blob.exists()


# ------------------------------------------------------------------------------
# Test 6: Collector Capsule Unpacker & Dual-Hash Validation
# ------------------------------------------------------------------------------
def test_collector_capsule_unpacker_valid(engine, tmp_path):
    """Verify unpacking of a valid endpoint capsule with manifest.json."""
    capsule_zip = tmp_path / "valid_capsule.zip"

    # Create dummy artifact files
    log_content = b"2026-10-31 06:00:00 [EVENT 4624] Successful Logon"
    mft_content = b"FILE0\x00\x00simulated_mft_header"

    log_sha256 = hashlib.sha256(log_content).hexdigest()
    log_sha512 = hashlib.sha512(log_content).hexdigest()

    mft_sha256 = hashlib.sha256(mft_content).hexdigest()
    mft_sha512 = hashlib.sha512(mft_content).hexdigest()

    manifest_dict = {
        "case_id": "CASE-TRIAGE-8891",
        "collector_version": "4.0",
        "artifacts": [
            {
                "artifact_id": "art-001",
                "type": "evtx",
                "original_path": "C:\\Windows\\System32\\Winevt\\Logs\\Security.evtx",
                "bundle_path": "artifacts/Security.evtx",
                "size_bytes": len(log_content),
                "sha256": log_sha256,
                "sha512": log_sha512,
                "acquired_utc": "2026-10-31T06:00:00Z",
                "acquisition_method": "collector",
            },
            {
                "artifact_id": "art-002",
                "type": "mft",
                "original_path": "C:\\$MFT",
                "bundle_path": "artifacts/$MFT",
                "size_bytes": len(mft_content),
                "sha256": mft_sha256,
                "sha512": mft_sha512,
                "acquired_utc": "2026-10-31T06:00:05Z",
                "acquisition_method": "collector",
            },
        ],
    }

    with zipfile.ZipFile(capsule_zip, "w") as zf:
        zf.writestr("manifest.json", json.dumps(manifest_dict))
        zf.writestr("collector_execution.log", b"Execution log completed normally.")
        zf.writestr("artifacts/Security.evtx", log_content)
        zf.writestr("artifacts/$MFT", mft_content)

    records = engine.unpack_collector_capsule(capsule_zip, actor="forensic_daemon")
    assert len(records) == 2

    # Check both records are in SQLite artifacts table
    all_artifacts = engine.get_artifacts(case_id="CASE-TRIAGE-8891")
    assert len(all_artifacts) == 2

    hashes = {a.sha256 for a in all_artifacts}
    assert log_sha256 in hashes
    assert mft_sha256 in hashes

    # Verify chain integrity
    is_valid, errors = engine.verify_chain_integrity()
    assert is_valid is True
    assert errors == []


def test_collector_capsule_unpacker_hash_mismatch_rejection(engine, tmp_path):
    """Verify that tampered artifacts inside a capsule trigger HashMismatchError."""
    capsule_zip = tmp_path / "tampered_capsule.zip"

    original_content = b"Original Authentic Content"
    tampered_content = b"Tampered Injected Content by Adversary"

    orig_sha256 = hashlib.sha256(original_content).hexdigest()
    orig_sha512 = hashlib.sha512(original_content).hexdigest()

    manifest_dict = {
        "case_id": "CASE-TAMPERED-001",
        "artifacts": [
            {
                "artifact_id": "art-tampered",
                "type": "log",
                "original_path": "/var/log/auth.log",
                "bundle_path": "artifacts/auth.log",
                "size_bytes": len(original_content),
                "sha256": orig_sha256,
                "sha512": orig_sha512,
                "acquired_utc": "2026-10-31T06:10:00Z",
                "acquisition_method": "collector",
            }
        ],
    }

    with zipfile.ZipFile(capsule_zip, "w") as zf:
        zf.writestr("manifest.json", json.dumps(manifest_dict))
        zf.writestr("artifacts/auth.log", tampered_content)  # Injected payload!

    with pytest.raises(HashMismatchError) as exc_info:
        engine.unpack_collector_capsule(capsule_zip, actor="analyst")

    assert "SHA-256 mismatch" in str(exc_info.value)


# ------------------------------------------------------------------------------
# Test 7: Hash-Chained Custody Ledger & Tamper Detection
# ------------------------------------------------------------------------------
def test_custody_chain_tamper_detection(engine):
    """Verify append-only ledger cryptographic chaining and detection of altered entries."""
    case_id = "CASE-INTEGRITY-900"

    # 1. Append legitimate operations
    entry1 = engine.append_custody_entry(
        case_id=case_id,
        actor="agent_1",
        action="INTAKE_ARTIFACT",
        artifact_sha256="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        tool_id="intake_tool",
    )
    assert entry1.seq_id == 1
    assert entry1.prev_hash == GENESIS_HASH

    entry2 = engine.append_custody_entry(
        case_id=case_id,
        actor="agent_2",
        action="RUN_YARA",
        artifact_sha256="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        tool_id="yara_v4",
    )
    assert entry2.seq_id == 2
    assert entry2.prev_hash == entry1.entry_hash

    entry3 = engine.append_custody_entry(
        case_id=case_id,
        actor="agent_3",
        action="EXPORT_REPORT",
        artifact_sha256=None,
        tool_id="report_generator",
    )
    assert entry3.seq_id == 3
    assert entry3.prev_hash == entry2.entry_hash

    # Validate pristine chain
    is_valid, errors = engine.verify_chain_integrity()
    assert is_valid is True
    assert errors == []

    # 2. Simulate adversary directly modifying SQL record at seq_id 2
    with sqlite3.connect(engine.db_path) as conn:
        conn.execute("UPDATE custody_chain SET action = 'ALTERED_ACTION' WHERE seq_id = 2;")
        conn.commit()

    # 3. Verify that verify_chain_integrity detects the tampering
    is_valid, errors = engine.verify_chain_integrity()
    assert is_valid is False
    assert len(errors) >= 1
    assert any("Tamper detected at seq_id 2" in err for err in errors)


def test_custody_chain_link_break_detection(engine):
    """Verify detection when an entry's prev_hash is forged or broken."""
    case_id = "CASE-CHAIN-BREAK"

    engine.append_custody_entry(case_id=case_id, actor="act1", action="A1")
    engine.append_custody_entry(case_id=case_id, actor="act2", action="A2")

    # Manually corrupt prev_hash of entry 2 in DB
    with sqlite3.connect(engine.db_path) as conn:
        conn.execute(
            "UPDATE custody_chain SET prev_hash = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' WHERE seq_id = 2;"
        )
        conn.commit()

    is_valid, errors = engine.verify_chain_integrity()
    assert is_valid is False
    assert any("Chain break at seq_id 2" in err for err in errors)


# ------------------------------------------------------------------------------
# Test 8: Audit Transparency Log (audit.jsonl)
# ------------------------------------------------------------------------------
def test_audit_transparency_log(engine, tmp_path):
    """Verify that every intake and reference writes to audit.jsonl."""
    sample_file = tmp_path / "sample.log"
    sample_file.write_text("Audit test event log content")

    engine.ingest_artifact(
        case_id="CASE-AUDIT-101",
        source_path=sample_file,
        artifact_type="log",
        actor="auditor_test",
    )

    assert engine.audit_log_path.exists()
    lines = engine.audit_log_path.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) >= 1

    last_record = json.loads(lines[-1])
    assert last_record["case_id"] == "CASE-AUDIT-101"
    assert last_record["actor"] == "auditor_test"
    assert last_record["action"] == "INGEST_ARTIFACT"
    assert "sha256" in last_record["details"]
