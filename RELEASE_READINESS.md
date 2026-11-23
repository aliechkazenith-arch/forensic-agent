# ForensicOps AI — Production Release Readiness & Air-Gapped Deployment Guide

**Version:** 1.0.0-GA  
**Target Autonomy:** Controlled Autonomy (Human-in-the-Loop)  
**Security Baseline:** Phase 14–16 Hardened  
**Standards Compliance:** RFC 3227, RFC 8785, NIST SP 800-86, ISO/IEC 27037  

---

## 1. Executive Summary & Architectural Principles

ForensicOps AI is an autonomous, air-gapped digital forensics and incident response (DFIR) investigation platform. It performs deterministic forensic parsing, automated hypothesis evaluation, multi-source entity correlation, and court-admissible cited report generation without compromising evidence integrity or system boundaries.

### Non-Negotiable Core Principles (AGENTS.md Rules 1–10)
1. **Deterministic Tools Produce Facts:** LLMs plan, correlate, explain, and draft hypotheses. An LLM is never the source of a forensic fact.
2. **Cryptographic Citation Grounding:** Every factual claim must cite verified finding IDs, source artifact cryptographic hashes, and exact artifact offsets.
3. **Evidence Immutability:** Original evidence is strictly read-only and never modified by analysis (RFC 3227). Pre- and post-execution SHA-256 hashes are verified on every analyzer run.
4. **Untrusted Evidence Isolation:** Evidence files, strings, and extracted registry keys are untrusted data, never prompt instructions to the model.
5. **Air-Gapped Local Operation by Default:** Evidence and findings are never transmitted to external services without explicit, signed human authorization.
6. **Userspace Kernel Isolation:** Disk images and partition tables are inspected in userspace byte streams; host kernel mounting (`mount`, `losetup`, `kpartx`) is strictly forbidden.
7. **Strict Operation-Specific Human Approval:** High-risk actions (containment, remediation, external sharing) require cryptographically signed one-time approval tokens.

---

## 2. Air-Gapped Deployment & Installation Guide

ForensicOps AI requires no active internet access during operational deployment.

### 2.1 System Prerequisites
- **Operating System:** Linux (Ubuntu 22.04+ / RHEL 9+) or Windows 10/11 / Windows Server 2022.
- **Python Runtime:** Python 3.11, 3.12, 3.13, or 3.14 (64-bit).
- **Node.js Runtime (Build-time only):** Node.js 20+ with npm (for compiling the frontend React bundle).
- **Storage Subsystems:** Embedded SQLite 3 and DuckDB (no external database server required).

### 2.2 Offline Python Environment Installation
In an air-gapped enclave, install Python packages from a pre-mirrored directory of wheels:
```bash
# In air-gapped staging directory containing cached wheels:
python -m venv venv
# Linux / macOS
source venv/bin/activate
# Windows PowerShell
.\venv\Scripts\Activate.ps1

# Install wheels without internet connection
pip install --no-index --find-links=./offline_wheels -r requirements.txt
```

### 2.3 Frontend Production Build
Compile the React/TypeScript frontend into static distribution assets:
```bash
cd frontend
npm ci --prefer-offline
npm run build
```
The compiled single-page application is written to `frontend/dist/`.

---

## 3. Cryptographic Key Management & Initialization

Before starting ForensicOps AI in a production environment, generate cryptographically secure keys:

### 3.1 Configure Cryptographic Secrets
Create a `.env` file from `.env.example`:
```bash
cp .env.example .env
```

Generate the mandatory production keys:
```bash
# 1. Generate HUMAN_APPROVAL_HMAC_SECRET (64 hex characters)
python -c "import secrets; print('HUMAN_APPROVAL_HMAC_SECRET=' + secrets.token_hex(32))"

# 2. Generate JWT_SECRET_KEY (at least 32 characters)
python -c "import secrets; print('JWT_SECRET_KEY=' + secrets.token_urlsafe(32))"

# 3. Generate FORENSICOPS_CREDENTIAL_KEY (32-byte AES-256-GCM master key)
python -c "import secrets; print('FORENSICOPS_CREDENTIAL_KEY=' + secrets.token_hex(32))"
```
Place these values in `.env` and restrict file permissions (`chmod 600 .env`).

### 3.2 Key Derivation & Vault Encryption
The encrypted SQLite vault supports offline export and import protected by PBKDF2 (HMAC-SHA256, 600,000 iterations) or Argon2id key derivation combined with AES-256-GCM authenticated envelope encryption.

---

## 4. Operational Startup Commands

### 4.1 Starting the Backend API Daemon
Bind exclusively to loopback (`127.0.0.1`):
```bash
# From workspace root:
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --workers 1
```

### 4.2 Serving the Production Frontend
Option A: Using the built-in Vite preview server on loopback:
```bash
cd frontend
npm run preview -- --host 127.0.0.1 --port 5173
```
Option B: Serve `frontend/dist/` via Nginx, Caddy, or your organization's air-gapped reverse proxy.

### 4.3 Configuring Local LLM Providers
For 100% offline air-gapped intelligence:

- **Ollama**: Run `ollama serve` locally on `http://127.0.0.1:11434`.
  In `.env`:
  ```ini
  OPENAI_API_BASE_URL=http://127.0.0.1:11434/v1
  OPENAI_MODEL=llama3:8b-instruct-q8_0
  OPENAI_API_KEY=ollama-local
  ```

- **LM Studio**: Start the local server on `http://127.0.0.1:1234`.
  In `.env`:
  ```ini
  OPENAI_API_BASE_URL=http://127.0.0.1:1234/v1
  OPENAI_MODEL=local-model
  OPENAI_API_KEY=lm-studio-local
  ```

---

## 5. Artifact Compatibility & Forensic Capabilities

| Artifact Category | Supported Formats | Engine & Execution Tier | Host Kernel Mount? | Immutability Verification |
|---|---|---|---|---|
| **Raw Disk Streams** | `.raw`, `.dd`, `.img` | **Tier A Built-in** (`DissectAdapter.parse_disk_image_stream`) | **NO** (Stream inspection) | SHA-256 Pre == Post |
| **Windows Registry Hives** | SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT (`.hiv`, `.dat`) | **Tier A Built-in** (`WindowsRegistryHiveParser`) | **NO** (Binary REGF parser) | SHA-256 Pre == Post (XOR-32 checksum validated) |
| **Triage Directories** | Folders with JSONL / JSON / EVTX extracts | **Tier A Built-in** (`DissectAdapter.parse_collector_artifact`) | **NO** (Directory traversal) | SHA-256 Pre == Post |
| **Windows Event Logs** | `.evtx` (ElfFile) | **Tier A Built-in** (`DissectAdapter.parse_evtx`) | **NO** (Binary chunk decode) | SHA-256 Pre == Post |
| **Packet Captures** | `.pcap`, `.pcapng` | **Specialist Native Parser** | **NO** (Stream packet decode) | SHA-256 Pre == Post |
| **EnCase / VMDK** | `.E01`, `.Ex01`, `.vmdk` | **Unsupported (Explicit Safe Rejection)** | **N/A** (Fail-closed guard) | Execution halted before parsing |

*For complete details, see [COMPATIBILITY_MATRIX.md](COMPATIBILITY_MATRIX.md).*

---

## 6. Security Boundaries & Permanent Enforcements

1. **Permanent Exclusion of Remote Collection:** SSH endpoint collector code and credentials have been permanently removed. Forensic intake accepts only offline disk images, registry hives, triage directories, and event logs.
2. **Browser Storage Hardening (SEC-UI-001):** Sensitive credentials (SIEM API keys, tokens, passwords) are never stored in browser `sessionStorage` or `localStorage`. Credentials exist in browser memory only long enough to be transmitted via POST over loopback to the backend encrypted vault.
3. **SSRF & DNS Pinning:** Backend outbound connections enforce strict loopback DNS resolution, private subnet blocking, and DNS rebinding protections.
4. **Append-Only HMAC Audit Chains:** All human approval transitions and token consumptions are chained with `HMAC-SHA256(secret, prev_hash || canonical_json)`. Any alteration to SQLite records invalidates the chain.
5. **Strict Citation Quarantine:** With `strict_citations=True`, claims lacking verified finding IDs or exact source artifact hashes are quarantined to `unverified_hypotheses` and never promoted to `observed_facts` or `derived_correlations`.

---

## 7. Performance & Resource Bounds

Empirical benchmarks run via `scripts/benchmark_large_fixtures.py` demonstrate:
- **Streaming SHA-256 Throughput:** > 2,100 MB/s utilizing OS-level `hashlib.file_digest` streaming.
- **Peak RAM Consumption:** 0.38 MB RAM during hashing of 1 GB disk image (Limit: < 50.0 MB RAM).
- **Userspace Partition Parsing:** < 0.001 seconds for standard MBR partition discovery.
- **Anti-DoS Protection:** Configurable ceilings on archive entries (10,000), total uncompressed bytes (20 GB), decompression ratio (100:1), registry hive bytes (256 MB), and registry recursion depth (60).

---

## 8. Verification & Release Acceptance Status

- **Backend Pytest Suite:** 489 / 489 passed (100% green, 0 failures, 0 regressions).
- **Frontend TypeScript & Vite Build:** 0 errors, 0 warnings (clean build in 411ms).
- **Reproducibility Test:** Verified dual-execution parity across independent runs with identical hashes, findings, and HMAC audit chains.
- **Air-Gapped Status:** Fully self-contained; zero external network dependencies.
