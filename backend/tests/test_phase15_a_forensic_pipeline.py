"""Deterministic Real-Fixture Integration Test Suite for Phase 15-A Forensic Engine.

Standards & Acceptance Criteria:
1. Deterministic Fixture Execution (Zero Mocks):
   - Real execution of RAW disk stream (.raw) and Windows Registry hive (.hiv)
     through DissectAdapter, WindowsRegistryHiveParser, and PluginRunner.
   - Non-destructive read-only verification: original evidence SHA-256 hashes must
     match identically before and after analysis.
2. DuckDB / SQLite ForensicStore Persistence:
   - Extracted findings correctly persist into structured columnar storage with
     provenance (artifact_id, artifact_hash, tool_id, tool_version, case_id).
3. CitationGuard Anti-Hallucination Gate:
   - Valid claims referencing real findings and artifact hashes succeed.
   - Ungrounded claims referencing non-existent finding IDs or modified hashes fail.
4. Cross-Case Contamination Shield:
   - Case A findings cannot be queried, retrieved, or cited inside Case B.
   - Cross-case citation attempts are strictly rejected.
5. Explicit Rejection of Unsupported Containers:
   - Proprietary E01 and VMDK files fail cleanly with explicit capability warnings
     without crashing or fabricating findings.
"""
from __future__ import annotations

import hashlib
import os
import shutil
from pathlib import Path
from typing import Any, Dict, List
import pytest

from backend.app.core.analyzer_registry import BUILTIN_TIER_A_ANALYZERS, AnalyzerRegistry
from backend.app.core.citation_guard import CitationGuard
from backend.app.core.dissect_adapter import DissectAdapter
from backend.app.core.exceptions import ForensicOpsError
from backend.app.core.plugin_runner import PluginRunner
from backend.app.core.registry_parser import WindowsRegistryHiveParser
from backend.app.core.storage import ForensicStore
from backend.app.models.custody import ArtifactRecord
from backend.app.models.findings import CitedClaim, ForensicFinding
from backend.app.models.plugins import ToolPluginCard
from backend.tests.fixtures.generate_fixtures import ensure_all_fixtures, FIXTURES_DIR


def sha256_file(path: Path) -> str:
    """Calculate SHA-256 digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


@pytest.fixture(scope="module")
def real_fixtures():
    """Ensure all deterministic binary test fixtures exist."""
    return ensure_all_fixtures()


@pytest.fixture
def real_pipeline_env(tmp_path: Path):
    """Hermetic isolated environment for real forensic pipeline testing."""
    vault_dir = tmp_path / "vault"
    vault_dir.mkdir(parents=True, exist_ok=True)
    db_path = vault_dir / "forensic_store.duckdb"

    storage = ForensicStore(db_path=db_path)
    adapter = DissectAdapter()
    runner = PluginRunner(dissect_adapter=adapter)
    guard = CitationGuard(storage=storage)

    yield {
        "tmp_path": tmp_path,
        "vault_dir": vault_dir,
        "storage": storage,
        "adapter": adapter,
        "runner": runner,
        "guard": guard,
    }


# ==============================================================================
# 1. Real Deterministic Execution: Flat Raw MBR Disk Stream
# ==============================================================================

def test_real_raw_mbr_disk_parsing_and_persistence(real_pipeline_env: Dict[str, Any], real_fixtures: Dict[str, Path]):
    """Verify real Dissect userspace parsing of flat raw MBR disk image without host kernel mounting."""
    storage: ForensicStore = real_pipeline_env["storage"]
    adapter: DissectAdapter = real_pipeline_env["adapter"]
    mbr_path = real_fixtures["mbr"]
    case_id = "CASE-REAL-MBR-01"
    artifact_id = "art-mbr-raw-01"

    # 1. Non-destructive read-only verification: check SHA-256 before and after
    hash_before = sha256_file(mbr_path)

    # 2. Execute userspace stream parser
    findings = adapter.parse_disk_image_stream(
        image_path=mbr_path,
        case_id=case_id,
        artifact_id=artifact_id,
        artifact_hash=hash_before,
    )

    hash_after = sha256_file(mbr_path)
    assert hash_before == hash_after, "RFC 3227 violation: Original evidence file was modified by analysis!"

    # 3. Verify extracted findings
    assert len(findings) == 2, f"Expected 2 partitions from MBR fixture, got {len(findings)}"

    part1 = findings[0]
    assert part1.case_id == case_id
    assert part1.source_artifact_id == artifact_id
    assert part1.source_artifact_hash == hash_before
    assert part1.artifact_type in ("raw_image", "disk_image")
    assert part1.category == "disk_partition"
    assert part1.projected_data["type_hex"] == "0x07"
    assert part1.projected_data["bootable"] is True
    assert part1.projected_data["start_lba"] == 2048

    part2 = findings[1]
    assert part2.projected_data["type_hex"] == "0x83"
    assert part2.projected_data["bootable"] is False
    assert part2.projected_data["start_lba"] == 22528

    # 4. Insert into ForensicStore and verify persistence
    inserted = storage.insert_findings(findings)
    assert inserted == 2

    persisted1 = storage.get_finding(part1.finding_id)
    assert persisted1 is not None
    assert persisted1.case_id == case_id
    assert persisted1.source_artifact_hash == hash_before
    assert persisted1.projected_data["start_lba"] == 2048


# ==============================================================================
# 2. Real Deterministic Execution: Windows Registry Hive Binary
# ==============================================================================

def test_real_registry_hive_parsing_and_persistence(real_pipeline_env: Dict[str, Any], real_fixtures: Dict[str, Path]):
    """Verify real WindowsRegistryHiveParser checksum validation and DissectAdapter extraction."""
    storage: ForensicStore = real_pipeline_env["storage"]
    adapter: DissectAdapter = real_pipeline_env["adapter"]
    hive_path = real_fixtures["registry"]
    case_id = "CASE-REAL-REG-01"
    artifact_id = "art-reg-system-01"

    # 1. Non-destructive read-only verification
    hash_before = sha256_file(hive_path)

    # 2. Low-level checksum verification via WindowsRegistryHiveParser
    reg_parser = WindowsRegistryHiveParser()
    root_key = reg_parser.parse_file(hive_path, validate_checksum=True)
    assert reg_parser.header is not None
    assert reg_parser.header.hive_name == "SYSTEM"
    assert reg_parser.header.magic == b"regf"
    assert reg_parser.header.is_corrupted is False
    assert reg_parser.header.checksum == reg_parser.header.calculated_checksum

    # 3. Parse through DissectAdapter
    findings = adapter.parse_registry_hive(
        hive_path=hive_path,
        case_id=case_id,
        artifact_id=artifact_id,
        artifact_hash=hash_before,
    )

    hash_after = sha256_file(hive_path)
    assert hash_before == hash_after, "RFC 3227 violation: Original registry hive was modified!"

    assert len(findings) >= 1
    f = findings[0]
    assert f.case_id == case_id
    assert f.source_artifact_id == artifact_id
    assert f.source_artifact_hash == hash_before
    assert f.artifact_type == "registry"
    assert f.category == "registry_hive"
    assert f.projected_data["hive_name"] == "SYSTEM.hiv" or f.projected_data["hive_name"] == "SYSTEM"

    # 4. Insert and verify storage
    storage.insert_findings(findings)
    stored = storage.get_finding(f.finding_id)
    assert stored is not None
    assert stored.projected_data["hive_name"] in ("SYSTEM.hiv", "SYSTEM")


# ==============================================================================
# 3. Real Deterministic Execution: Synthetic Triage Archive
# ==============================================================================

def test_real_triage_archive_parsing(real_pipeline_env: Dict[str, Any], real_fixtures: Dict[str, Path]):
    """Verify real userspace parsing of collector archive JSONL artifacts."""
    storage: ForensicStore = real_pipeline_env["storage"]
    adapter: DissectAdapter = real_pipeline_env["adapter"]
    triage_dir = real_fixtures["triage"]
    case_id = "CASE-REAL-TRIAGE-01"

    proc_file = triage_dir / "processes.jsonl"
    net_file = triage_dir / "network_connections.jsonl"

    proc_hash = sha256_file(proc_file)
    net_hash = sha256_file(net_file)

    # 1. Parse processes
    proc_findings = adapter.parse_collector_artifact(
        file_path=proc_file,
        case_id=case_id,
        artifact_id="art-triage-proc",
        artifact_hash=proc_hash,
    )
    assert len(proc_findings) == 2
    procs = {p.process_name: p for p in proc_findings}
    assert "powershell.exe" in procs
    assert "rundll32.exe" in procs
    assert procs["powershell.exe"].category == "process_list"

    # 2. Parse network connections
    net_findings = adapter.parse_collector_artifact(
        file_path=net_file,
        case_id=case_id,
        artifact_id="art-triage-net",
        artifact_hash=net_hash,
    )
    assert len(net_findings) == 1
    assert net_findings[0].category == "network_connection"

    # 3. Batch insert
    all_findings = proc_findings + net_findings
    storage.insert_findings(all_findings)

    # Query structured findings
    queried_procs = storage.query_structured_findings(case_id=case_id, filters={"category": "process_list"})
    assert len(queried_procs) == 2


# ==============================================================================
# 4. Explicit Rejection of Unsupported Container Formats (E01 & VMDK)
# ==============================================================================

def test_unsupported_e01_vmdk_explicit_rejection(real_pipeline_env: Dict[str, Any], tmp_path: Path):
    """Verify that unsupported proprietary container formats fail cleanly with explicit capability warnings."""
    adapter: DissectAdapter = real_pipeline_env["adapter"]

    # 1. Synthetic E01 (EnCase) file header
    e01_path = tmp_path / "evidence.E01"
    e01_path.write_bytes(b"EVF01\r\n\x00\x01\x00\x00\x00sample_encase_header_data_block")

    with pytest.raises(ForensicOpsError, match="Unsupported container format: E01/VMDK"):
        adapter.parse_disk_image_stream(
            image_path=e01_path,
            case_id="case_unsupported",
            artifact_id="art_e01",
            artifact_hash="dummy_hash",
        )

    # 2. Synthetic VMDK file header
    vmdk_path = tmp_path / "disk.vmdk"
    vmdk_path.write_bytes(b"KDMV\x01\x00\x00\x00sample_vmdk_sparse_descriptor_block")

    with pytest.raises(ForensicOpsError, match="Unsupported container format: E01/VMDK"):
        adapter.parse_disk_image_stream(
            image_path=vmdk_path,
            case_id="case_unsupported",
            artifact_id="art_vmdk",
            artifact_hash="dummy_hash",
        )


# ==============================================================================
# 5. CitationGuard Validation on Real Persisted Findings
# ==============================================================================

def test_citation_guard_real_evidence_validation(real_pipeline_env: Dict[str, Any], real_fixtures: Dict[str, Path]):
    """Verify CitationGuard strictly accepts grounded claims and rejects ungrounded/hallucinated claims."""
    storage: ForensicStore = real_pipeline_env["storage"]
    adapter: DissectAdapter = real_pipeline_env["adapter"]
    guard: CitationGuard = real_pipeline_env["guard"]

    mbr_path = real_fixtures["mbr"]
    case_id = "CASE-CITATION-GUARD"
    art_id = "art-mbr-01"
    art_hash = sha256_file(mbr_path)

    findings = adapter.parse_disk_image_stream(mbr_path, case_id, art_id, art_hash)
    storage.insert_findings(findings)

    valid_fid = findings[0].finding_id

    # 1. Grounded Factual Claim: cites real finding and real artifact hash -> Succeeds
    grounded_claim = CitedClaim(
        claim_id="claim-001",
        claim_type="observed_fact",
        statement="The raw disk image contains an NTFS bootable partition at LBA 2048.",
        citing_finding_ids=[valid_fid],
        source_artifact_hashes=[art_hash],
    )
    is_valid, reasons = guard.validate_claim(grounded_claim, case_id=case_id)
    assert is_valid is True
    assert len(reasons) == 0

    # 2. Ungrounded Claim: cites non-existent/fabricated finding_id -> Fails
    hallucinated_claim = CitedClaim(
        claim_id="claim-002",
        claim_type="observed_fact",
        statement="Adversary created persistent backdoor in Volume Shadow Copy.",
        citing_finding_ids=["find-non-existent-hallucination-uuid"],
        source_artifact_hashes=[art_hash],
    )
    is_valid_fake, reasons_fake = guard.validate_claim(hallucinated_claim, case_id=case_id)
    assert is_valid_fake is False
    assert any("cites non-existent finding_id" in r for r in reasons_fake)

    # 3. Missing/Tampered Source Artifact Hash -> Fails
    tampered_hash_claim = CitedClaim(
        claim_id="claim-003",
        claim_type="observed_fact",
        statement="Partition table detected.",
        citing_finding_ids=[valid_fid],
        source_artifact_hashes=["wrong_tampered_hash_64_characters_long_00000000000000000000000000000"],
    )
    is_valid_hash, reasons_hash = guard.validate_claim(tampered_hash_claim, case_id=case_id)
    assert is_valid_hash is False
    assert any("requires source artifact hash" in r for r in reasons_hash)


# ==============================================================================
# 6. Cross-Case Contamination Shield
# ==============================================================================

def test_cross_case_contamination_shield(real_pipeline_env: Dict[str, Any], real_fixtures: Dict[str, Path]):
    """Verify complete isolation between Case A and Case B across storage, queries, and citations."""
    storage: ForensicStore = real_pipeline_env["storage"]
    adapter: DissectAdapter = real_pipeline_env["adapter"]
    guard: CitationGuard = real_pipeline_env["guard"]

    mbr_path = real_fixtures["mbr"]
    hive_path = real_fixtures["registry"]

    case_a = "CASE-ALPHA-ISOLATED"
    case_b = "CASE-BETA-ISOLATED"

    # Ingest MBR findings into Case A
    hash_a = sha256_file(mbr_path)
    findings_a = adapter.parse_disk_image_stream(mbr_path, case_a, "art-a", hash_a)
    storage.insert_findings(findings_a)

    # Ingest Registry findings into Case B
    hash_b = sha256_file(hive_path)
    findings_b = adapter.parse_registry_hive(hive_path, case_b, "art-b", hash_b)
    storage.insert_findings(findings_b)

    fid_a = findings_a[0].finding_id
    fid_b = findings_b[0].finding_id

    # 1. Query Isolation: Case A queries return ONLY Case A findings
    res_a = storage.query_structured_findings(case_id=case_a)
    assert all(f.case_id == case_a for f in res_a)
    assert not any(f.finding_id == fid_b for f in res_a)

    # Query Isolation: Case B queries return ONLY Case B findings
    res_b = storage.query_structured_findings(case_id=case_b)
    assert all(f.case_id == case_b for f in res_b)
    assert not any(f.finding_id == fid_a for f in res_b)

    # 2. Citation Verification Isolation
    verified_fids_a, _ = storage.check_citations_exist(finding_ids=[fid_a, fid_b], artifact_hashes=[hash_a, hash_b], case_id=case_a)
    assert fid_a in verified_fids_a
    assert fid_b not in verified_fids_a, "Case B finding leaked into Case A citation verification!"

    # 3. CitationGuard Cross-Case Rejection
    # Claim inside Case B citing Case A finding MUST fail with foreign case violation
    cross_claim = CitedClaim(
        claim_id="claim-cross-01",
        claim_type="observed_fact",
        statement="Citing finding from another case.",
        citing_finding_ids=[fid_a],
        source_artifact_hashes=[hash_a],
    )
    is_valid, reasons = guard.validate_claim(cross_claim, case_id=case_b)
    assert is_valid is False
    assert any("from foreign case" in r for r in reasons)


# ==============================================================================
# 7. Real PluginRunner Tier A Execution Pipeline
# ==============================================================================

def test_real_plugin_runner_tier_a_pipeline(real_pipeline_env: Dict[str, Any], real_fixtures: Dict[str, Path], tmp_path: Path):
    """Verify PluginRunner runs Tier A Dissect analyzer on real artifact producing typed ToolExecutionResult."""
    runner: PluginRunner = real_pipeline_env["runner"]
    storage: ForensicStore = real_pipeline_env["storage"]
    mbr_path = real_fixtures["mbr"]
    case_id = "CASE-RUNNER-TIER-A"
    art_hash = sha256_file(mbr_path)

    art_sha512 = hashlib.sha512(mbr_path.read_bytes()).hexdigest()

    # Create real ArtifactRecord
    artifact = ArtifactRecord(
        artifact_id="art-runner-mbr",
        case_id=case_id,
        type="raw_image",
        original_name="minimal_mbr.raw",
        original_path=str(mbr_path),
        blob_path=str(mbr_path),
        size_bytes=mbr_path.stat().st_size,
        sha256=art_hash,
        sha512=art_sha512,
        acquisition_method="offline_disk_stream",
    )

    # Real ToolPluginCard for dissect_disk_stream
    plugin = ToolPluginCard(
        tool_id="dissect_disk_stream",
        name="Dissect Userspace Raw Disk Partition Inspector",
        version="1.0.0",
        description="Inspects flat MBR and GPT partition tables in raw uncompressed disk streams.",
        category="disk_partition",
        execution_tier="tier_a_builtin",
        supported_artifact_types=["raw_image", "disk_image", "raw"],
        command_template=["dissect_disk_stream", "{input_path}"],
    )

    scratch_dir = tmp_path / "scratch"
    scratch_dir.mkdir(parents=True, exist_ok=True)

    result = runner.run_plugin(
        plugin=plugin,
        artifact=artifact,
        output_workspace=scratch_dir,
    )

    assert result.success is True
    assert result.tool_id == "dissect_disk_stream"
    assert result.findings_count == 2
    assert len(result.findings) == 2
    assert result.input_artifact_hash == art_hash

    # Persist and query
    storage.insert_findings(result.findings)
    stored_findings = storage.query_structured_findings(case_id=case_id)
    assert len(stored_findings) == 2


# ==============================================================================
# 8. Strict Zero-Mock Verification
# ==============================================================================

def test_strict_zero_mocks_enforcement(real_pipeline_env: Dict[str, Any]):
    """Ensure no unittest.mock or monkeypatch objects are active on core forensic components."""
    adapter = real_pipeline_env["adapter"]
    runner = real_pipeline_env["runner"]

    assert type(adapter) is DissectAdapter
    assert type(runner) is PluginRunner
    assert "Mock" not in type(adapter).__name__
    assert "Mock" not in type(runner).__name__
    assert not hasattr(adapter.parse_disk_image_stream, "assert_called")
    assert not hasattr(adapter.parse_registry_hive, "assert_called")
