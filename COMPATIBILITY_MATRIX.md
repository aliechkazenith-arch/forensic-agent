# ForensicOps AI — Empirical Artifact & Tool Compatibility Matrix

**Standard**: RFC 3227, NIST SP 800-86, ISO/IEC 27037  
**Architecture Contract**: AGENTS.md Rules 1–10  
**Status**: Empirically Verified in Phase 15-A  

---

## 1. Executive Summary

ForensicOps AI strictly adheres to **userspace deterministic analysis**. Evidence files are treated as untrusted raw input streams and are never mounted into the host operating system kernel. Original evidence files are strictly immutable; SHA-256 and SHA-512 hashes are verified before and after execution to guarantee RFC 3227 compliance.

Proprietary containers (e.g., E01, VMDK) that cannot be safely parsed in pure-Python userspace are **explicitly rejected with fail-closed warnings** rather than simulating findings or failing silently.

---

## 2. Evidence Artifact Compatibility Matrix

| Artifact Type | Format / Extensions | Compatibility Status | Execution Tier & Engine | Host Kernel Mount Required? | Evidence Integrity (RFC 3227) | Verifying Test Suite & Fixture |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Flat Raw Disk Stream** | `.raw`, `.dd`, `.img` | **Supported (Fixture-Verified)** | **Tier A Built-in** (`DissectAdapter.parse_disk_image_stream`) | **NO** (Zero mount, userspace MBR/GPT stream inspection) | Verified (Pre/Post SHA-256 Identical) | `backend/tests/test_phase15_a_forensic_pipeline.py`<br>Fixture: `backend/tests/fixtures/minimal_mbr.raw` |
| **Windows Registry Hives** | SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT (`.hiv`, `.dat`) | **Supported (Fixture-Verified)** | **Tier A Built-in** (`WindowsRegistryHiveParser` & `DissectAdapter`) | **NO** (Userspace REGF binary chunk decoding) | Verified (Pre/Post SHA-256 Identical, XOR-32 checksum validated) | `backend/tests/test_phase15_a_forensic_pipeline.py`<br>Fixture: `backend/tests/fixtures/minimal_system.hiv` |
| **Endpoint Triage Directories** | Folders containing JSONL, JSON, EVTX, text extracts | **Supported (Fixture-Verified)** | **Tier A Built-in** (`DissectAdapter.parse_collector_artifact`) | **NO** (Direct read-only file tree traversal) | Verified (Pre/Post SHA-256 Identical) | `backend/tests/test_phase15_a_forensic_pipeline.py`<br>Fixture: `backend/tests/fixtures/triage_archive/` |
| **Windows Event Logs (EVTX)** | Binary `.evtx` (ElfFile) | **Supported (Fixture-Verified)** | **Tier A Built-in** (`DissectAdapter.parse_evtx` via `Evtx.Evtx`) | **NO** (Userspace binary chunk & XML decoding) | Verified (Pre/Post SHA-256 Identical) | `backend/tests/test_attack_scenario_evtx.py`<br>Fixture: `sample/Credential Access/babyshark_mimikatz_powershell.evtx` |
| **Packet Captures (PCAP / PCAPNG)** | `.pcap`, `.pcapng`, `.cap` | **Partially Supported (Header Verified)** | **Specialist Native Parser** (`native_pcap_parser` & `DissectAdapter`) | **NO** (Userspace packet header decoding) | Verified (Read-only packet stream traversal) | `backend/tests/fixtures/minimal.pcap`<br>`backend/tests/fixtures/minimal.pcapng` |
| **Proprietary EnCase Image** | `.E01`, `.Ex01` (`EVF01` / `EVF02`) | **Unsupported (Explicit Safe Rejection)** | **Fail-Closed Guard** (`DissectAdapter.parse_disk_image_stream`) | **NO** | N/A (Execution halted before parsing) | `backend/tests/test_phase15_a_forensic_pipeline.py`<br>(Rejection verified via `test_unsupported_e01_vmdk_explicit_rejection`) |
| **Virtual Machine Disks** | `.vmdk`, `.vhdx` (`KDMV`) | **Unsupported (Explicit Safe Rejection)** | **Fail-Closed Guard** (`DissectAdapter.parse_disk_image_stream`) | **NO** | N/A (Execution halted before parsing) | `backend/tests/test_phase15_a_forensic_pipeline.py`<br>(Rejection verified via `test_unsupported_e01_vmdk_explicit_rejection`) |
| **Volatile Memory Dumps** | Raw RAM, WinPmem, LiME (`.raw`, `.dmp`, `.vmem`) | **Partially Supported (Sandbox Container Required)** | **Tier B Declarative Adapter** (`volatility3` plugin in container) | **NO** (Air-gapped container worker with read-only volume) | Verified (Immutable read-only container bind `:ro`) | `backend/tests/test_phase04_tool_sandbox.py`<br>`backend/tests/test_phase07_specialist_capabilities.py` |

---

## 3. Forensic Engine Capability Details

### 3.1 Flat RAW/DD Disk Stream Parser (`dissect_disk_stream`)
- **Execution Mode**: Pure-Python userspace byte inspection.
- **Capabilities**:
  - Parses Master Boot Record (MBR) partition tables at sector 0 (offset 446–509).
  - Validates boot signature `0x55AA` at bytes 510–512.
  - Extracts active partition type codes (e.g. `0x07` NTFS, `0x83` Linux native, `0x0B` FAT32).
  - Calculates partition byte offsets (`start_lba * 512`) and lengths (`size_sectors * 512`).
  - Identifies bootable/active partition flags.
- **Safety**: Never calls mount, losetup, or filesystem drivers. Zero kernel-level surface.

### 3.2 Windows Registry Hive Parser (`dissect_registry`)
- **Execution Mode**: Pure-Python binary REGF Base Block and Hive Bin parser.
- **Capabilities**:
  - Validates `regf` magic signature (bytes 0–3).
  - Computes and verifies Microsoft REGF XOR-32 checksum over the first 508 bytes (127 DWORDs).
  - Extracts primary and secondary sequence numbers to detect uncommitted or dirty hive logs.
  - Converts Windows 64-bit FILETIME (offset 12) into ISO-8601 UTC timestamp.
  - Extracts hive identity (SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER).
  - Extracts forensic persistence artifacts (CurrentVersion\Run, Services, UserAccounts).
- **Security Boundary**: Passwords and cryptographic secrets (SAM hashes, LSA secrets) are never extracted in plain text.

### 3.3 Triage Directory Extractor (`dissect_triage` / `dissect_collector`)
- **Execution Mode**: Direct structured JSON/JSONL stream parser.
- **Capabilities**:
  - Ingests triage collections containing live endpoint snapshots.
  - Automatically categorizes `processes.jsonl` into `process_list` findings.
  - Categorizes `network_connections.jsonl` into `network_connection` findings.
  - Categorizes security events into structured `event_log` findings.

### 3.4 Explicit Unsupported Format Protection
- **Rationale**: AGENTS.md Rule 9 mandates that the system must *never report a failed, incomplete, or unavailable analysis as successful*.
- **Enforcement**:
  - If evidence with magic header `EVF01` (EnCase E01) is submitted to the stream parser, `DissectAdapter` raises:
    ```
    ForensicOpsError: Unsupported container format: E01/VMDK is not supported by Dissect pure-python stream parsing. Only uncompressed flat raw disk images (.raw/.img/.dd) are supported.
    ```
  - If evidence with magic header `KDMV` (VMDK) is submitted, the identical safe rejection is triggered.
  - The system will **never** simulate findings or pretend to parse unsupported formats.

---

## 4. CitationGuard & Cross-Case Contamination Shield

- **Grounding Gate**: Factual claims (`observed_fact`, `derived_fact`, `derived_correlation`) are validated deterministically against findings in `ForensicStore`.
- **Finding ID Provenance**: Every claim must cite valid, existing `finding_id`s in DuckDB/SQLite.
- **Cryptographic Hash Binding**: Every claim must cite the exact `source_artifact_hash` stored on the verified finding. Fabricated or tampered hashes are rejected.
- **Cross-Case Isolation**:
  - Case A queries cannot retrieve findings belonging to Case B.
  - Case A claims attempting to cite Case B `finding_id`s are rejected with:
    ```
    Claim '...' cites finding_id '...' from foreign case 'CASE-A' (active case: 'CASE-B').
    ```

---

## 5. Verification Checklist

- [x] All 8 Phase 15-A integration tests passing: `backend/tests/test_phase15_a_forensic_pipeline.py`.
- [x] Zero mocks active across `DissectAdapter`, `WindowsRegistryHiveParser`, and `PluginRunner`.
- [x] Evidence files verified read-only (SHA-256 pre == SHA-256 post).
- [x] DuckDB / SQLite dual persistence verified.
- [x] Cross-case contamination verified zero-leakage.
- [x] Explicit E01 and VMDK safe rejections verified.
