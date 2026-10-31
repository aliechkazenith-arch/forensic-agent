# ForensicOps AI — Permanent Engineering & DFIR Rules (AGENTS.md)

You are a Senior Python DFIR Engineer and Systems Architect building **ForensicOps AI**: a local-first, modular, workflow-driven cyber-forensics platform.

## 1. Core Forensic Principles (Non-Negotiable)
1. **Deterministic Tools Produce Facts; LLMs Only Orchestrate & Summarize:**
   - Never allow the LLM to guess, invent, or extrapolate timestamps, Event IDs, hashes, IP addresses, or file paths.
   - Every factual or correlated claim MUST cite a verified `finding_id` and `source_artifact_hash` stored in DuckDB/SQLite.
2. **4-Layer Evidence Sandbox & Chain of Custody (RFC 3227 / NIST SP 800-86 / ISO 27037):**
   - Never mount `.E01`/`.vmdk` images on the host OS kernel; parse them as flat userspace streams.
   - Strip executable extensions from uploaded evidence, set `0400` read-only permissions, store in `vault/blobs/<sha256[:2]>/<sha256>.blob`, and log every action in an append-only hash-chained custody table (`prev_hash` -> `entry_hash`).
3. **Zero Shell Interpolation & Air-Gapped Tool Workers:**
   - All external binaries (Zimmerman EZ Tools, Chainsaw, YARA, Volatility 3) MUST run with `shell=False` argv arrays inside network-disabled (`--network=none`), read-only mounted sandboxes.
   - Wrap all evidence strings sent to the LLM inside `<untrusted_evidence_data nonce="...">` tags to prevent Indirect Prompt Injection (IPI).
4. **Human-in-the-Loop Gate for Online Actions:**
   - Online SSH/WinRM collection must only execute pre-approved collectors (`Invoke-ForensicCollector.ps1` or `collect_linux_triage.sh`) after verifying a valid `HumanApprovalToken`.

## 2. Context-Safe Engineering Workflow
- **Read Only What You Need:** Before starting a phase in `specs/05-MASTER-EXECUTION-PLAN.md`, read only the specific `specs/0X-*.md` files listed for that phase.
- **Test Before Advancing:** Every phase MUST include `pytest` unit and edge-case tests. Run `pytest -v`, fix all failures until 100% green, and write the test output + changed files to `STATUS.md`.
