# ForensicOps AI — Security Audit, 4-Layer Sandbox & Threat Model

## 1. The 4-Layer Evidence Sandbox (Protecting the Analyst's Machine)
1. **Zero Host-OS Mounting:** Disk and VM images (`.E01`, `.vmdk`, `.vhdx`, `.raw`) are never mounted on the host kernel; they are read in userspace as flat byte streams via `Dissect`.
2. **Streaming Zip Guard & Defanged `.blob` Vault:** Archive headers are inspected in memory to block Zip Slip (`..`), symlinks, and decompression bombs. Extracted files are stripped of executable extensions (`.exe`, `.ps1`, `.bat`), assigned `0400` read-only permissions, and stored as `vault/blobs/<sha256[:2]>/<sha256>.blob` so malware cannot execute or be deleted by host antivirus.
3. **Air-Gapped Tool Worker Sandbox:** External binaries run with `shell=False` inside isolated containers/workers enforced with `--network=none`, `--read-only` evidence mounts, `--cap-drop=ALL`, and CPU/RAM quotas.
4. **Zero-Copy Read-Only Path Reference:** Supports reading large external images (`:ro`) in place without duplicating hundreds of gigabytes onto the system drive.

## 2. Forensic Integrity & Anti-Tampering (RFC 3227)
- **Order of Volatility:** In `Invoke-ForensicCollector.ps1` and `collect_linux_triage.sh`, physical RAM acquisition (`WinPmem`/`DumpIt`/`AVML`) and live network/process tables execute before disk-heavy Event Log or Registry exports.
- **Hash-Chained Custody Ledger:** Every intake, filter, and tool execution appends a record to `custody_chain` where `entry_hash = sha256(prev_hash + canonical_json(entry))`.
- **Zero Silent Sampling (`audit.jsonl`):** Every date filter, deduplication, or column projection logs exact before/after row and column counts.

## 3. AI Security & Anti-Hallucination
- **Indirect Prompt Injection (IPI) Shield:** All strings extracted from evidence are wrapped in `<untrusted_evidence_data nonce="...">` tags with system-prompt isolation so malicious log strings (`"Ignore previous instructions..."`) are treated strictly as passive adversary data.
- **`CitationGuard` Post-LLM Validator:** Deterministically verifies every `finding_id` and `source_artifact_hash` cited by the local LLM against DuckDB/SQLite before accepting a node's output. Automatically rejects fabricated IDs or uncited factual claims.
