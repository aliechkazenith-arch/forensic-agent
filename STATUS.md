# ForensicOps AI — Implementation Status & Architecture Baseline (`STATUS.md`)

**Current Phase:** **5-Lens Read-Only Adversarial Audit (COMPLETED) | Hardened Alpha Baseline**  
**Date:** 2026-11-22  
**Auditor / Principal DFIR Architect:** ForensicOps AI Lead Engineering Swarm (@coordinator, Synthesis Auditor 5, @docs, @security, @forensics, @architect, @qa)  
**Maturity Level:** **Hardened Alpha** ([FINAL_GAP_AND_FIX_PLAN.md](file:///c:/forensicops-ai/.audit/FINAL_GAP_AND_FIX_PLAN.md))  
**Audit Artifacts:** [REPORT_01_SECURITY.md](file:///c:/forensicops-ai/.audit/REPORT_01_SECURITY.md) | [REPORT_02_FORENSICS.md](file:///c:/forensicops-ai/.audit/REPORT_02_FORENSICS.md) | [REPORT_03_AGENT.md](file:///c:/forensicops-ai/.audit/REPORT_03_AGENT.md) | [REPORT_04_UI_TESTS.md](file:///c:/forensicops-ai/.audit/REPORT_04_UI_TESTS.md) | [FINAL_GAP_AND_FIX_PLAN.md](file:///c:/forensicops-ai/.audit/FINAL_GAP_AND_FIX_PLAN.md)  
**Live Smoke Test Status:** **17 PASS / 2 FAIL / 0 BLOCKED (89.5% Pass Rate)** ([SMOKE_TEST_REPORT.md](file:///c:/forensicops-ai/SMOKE_TEST_REPORT.md))  
**Test Suite Status:** **489 / 489 PASSED (100% Green, 489 tests collected across 38 test modules in 138.54s)**  
**Frontend Production Build:** **0 Errors, 0 Warnings** (built in 413ms)  
**Knowledge Graph (Graphify):** **Updated** (`graphify-out/graph.json`)

---

## 0.00 5-Lens Read-Only Adversarial Audit & Distance-to-Goal Synthesis (2026-11-22)

On 2026-11-22, an exhaustive 5-lens read-only adversarial audit was completed across the entire repository without modifying tracked files. Five specialized reports were synthesized into a comprehensive distance-to-goal scorecard and 3-phase finish-line roadmap:

### 1. Distance-to-Goal Scorecard (Maturity: Hardened Alpha)
- **Security & Execution Foundation: 75%** (Strong cryptography, AES-256-GCM vault, air-gapped `PluginRunner`, SSRF-pinned transports; blocked by prompt injection omission in node goals `SEC-01` and approval gate bypass `SEC-08`).
- **Real Forensic Analysis Depth: 40%** (1,575-line pure-Python Windows Registry parser and EVTX parsing verified; raw disk parsing is MBR/GPT header-only with zero filesystem drivers, E01 check fails open, and PCAPNG drops packets).
- **Autonomous Investigation Intelligence: 45%** (FSM with iteration budgets and fail-safe LLM degradation verified; follow-up planning is static file-extension lookup, correlation has 5 hardcoded heuristic rules, and hypotheses are hardcoded binary pairs).
- **Investigator UI & Operational Readiness: 35%** (React/Tailwind frontend with wizard, case manager, and report viewer; approval resume crashes on `gate-` prefix, 20 API methods unwired, and frontend tests at 0.0%).

### 2. 5-Lens Audit Deliverables ([.audit/](file:///c:/forensicops-ai/.audit/)):
1. **[REPORT_01_SECURITY.md](file:///c:/forensicops-ai/.audit/REPORT_01_SECURITY.md)** (43.9 kB): Threat model, trust boundaries, indirect prompt injection analysis, and authentication lifecycle.
2. **[REPORT_02_FORENSICS.md](file:///c:/forensicops-ai/.audit/REPORT_02_FORENSICS.md)** (41.1 kB): RFC 3227 custody, parser depth, real disk stream parsing limitations, and evidence immutability.
3. **[REPORT_03_AGENT.md](file:///c:/forensicops-ai/.audit/REPORT_03_AGENT.md)** (41.8 kB): LangGraph loop, CitationGuard grounding, competing hypothesis evaluation, and local LLM failure modes.
4. **[REPORT_04_UI_TESTS.md](file:///c:/forensicops-ai/.audit/REPORT_04_UI_TESTS.md)** (39.1 kB): Frontend wiring, unwired API methods, React component contracts, and test suite honesty.
5. **[FINAL_GAP_AND_FIX_PLAN.md](file:///c:/forensicops-ai/.audit/FINAL_GAP_AND_FIX_PLAN.md)** (54.5 kB): Master gap analysis, 8-layer + 5-intelligence scorecard, consolidated defect register, and 3-phase finish-line roadmap.

---

## 0.0 Live Smoke Test & Diagnostic Audit Summary (Strict Read-Only Mode)

On 2026-11-21, a full-stack live smoke test and diagnostic audit was executed across 19 end-to-end verification stages (`s0_1` to `s7_2`) in strict read-only diagnostic mode (zero mocking, zero application code modifications, ephemeral data isolation, and live LM Studio integration with active `gemma-4-e4b-it` model).

### Summary Results:
- **Total Checks:** 19
- **Passing Checks:** **17 (89.5%)**
- **Failing Checks:** **2 (10.5%)** (`s0_1` and `s3_2` — genuine defects documented for remediation)
- **Blocked Checks:** **0 (0.0%)**
- **Canary Secret Audit (`SUPER_SECRET_SMOKE_TOKEN_999`):** 0 leaks across all 4 surfaces (API JSON responses, browser storage, backend logs, and raw SQLite database bytes).
- **Audit Artifact:** Complete evidence, logs, and remediation plans published in [SMOKE_TEST_REPORT.md](file:///c:/forensicops-ai/SMOKE_TEST_REPORT.md).

### Findings & Identified Defects:
1. **Defect `s0_1` (Unwired Frontend Methods):** `getInvestigationHypotheses` and `getInvestigationTimeline` defined in `frontend/src/services/api.ts` (lines 674, 677) are not yet called by React UI components (`InvestigationView.tsx`).
2. **Defect `s3_2` (Fail-Closed E01 Magic Header Mismatch):** In `backend/app/core/dissect_adapter.py:65`, `mbr_header.startswith(b"EVF01")` failed to match genuine EnCase EVF bytes (`45 56 46 09` / `EVF\t\r\n\xff\x00`), resulting in empty findings `[]` rather than raising `ForensicOpsError`.

---

## 0. Executive Implementation Summary — Phase 16 (Final Hardening, Frontend Alignment, Reproducibility & Release Sign-Off)

Phase 16 successfully completed all remaining production hardening, frontend API and UI contract synchronization, constant-space RFC 3227 streaming evidence integrity, dual-execution deterministic reproducibility, large-fixture performance benchmarking, and air-gapped operational packaging.

### Key Accomplishments & Technical Deliverables in Phase 16:

1. **Sub-Phase 16-A — Backend Defense-in-Depth & Streaming RFC 3227 Evidence Integrity:**
   - **Zero-Copy Streaming Hashing:** Implemented memory-bounded `compute_streaming_sha256()` with `hashlib.file_digest` (Python 3.11+ OS-level zero-copy streaming) and an 8 MiB chunk fallback in `backend/app/core/plugin_runner.py`. Replaced all `read_bytes()` hashing in `plugin_runner.py` and `backend/app/agent/graph.py` to eliminate heap memory spikes when hashing multi-gigabyte forensic disk images.
   - **Fail-Closed Citation Enforcement:** Enforced `strict_citations=True` across all report compilation routes in `backend/app/api/reports.py` and defaulted `strict_citations=True` in `backend/app/agent/graph.py` and `InvestigationController`.
   - **Content-Disposition Regex Sanitization:** Applied strict regex character allowlisting (`re.sub(r"[^a-zA-Z0-9_-]", "_", case_id)`) to `Content-Disposition` headers in `backend/app/api/reports.py` and `backend/app/api/intake.py` to prevent header injection or path traversal on client file downloads.
   - **Regression Suite:** Authored `backend/tests/test_phase16_a_hardening.py` (9/9 passed) covering tamper detection fail-closed in Tier A & B, streaming hash on 64 MB sparse files, HTTP 422 on ungrounded claims, and filename header sanitization.

2. **Sub-Phase 16-B — Frontend API Client & UI Contract Alignment:**
   - **TypeScript Contract Alignment (`frontend/src/types/index.ts`):** Added complete TypeScript interfaces matching backend models (`InvestigationRecord`, `InvestigationPlan`, `InvestigationBudget`, `CompetingHypothesis`, `EvidenceGap`, `InvestigationAction`, `InvestigationStepTrace`, `InvestigationTimelineEntry`, and `review_notes` on `CitedClaim`).
   - **API Client Extensions (`frontend/src/services/api.ts`):** Configured dynamic `API_BASE` (`VITE_API_BASE_URL` with `/api` fallback), `requestBlob()`, `triggerBrowserDownload()`, `getInvestigationFindings()`, `getInvestigationHypotheses()`, `getInvestigationTimeline()`, `exportReport()`, and `exportCustodyLedger()`.
   - **Cited Report Viewer (`frontend/src/components/CitedReportViewer.tsx`):** Added Export .MD and Export .JSON buttons; added Section 4B for `unverified_hypotheses` with explicit warning callout boxes separating hypotheses from verified facts.
   - **Custody Ledger Modal (`frontend/src/components/CustodyLedgerModal.tsx`):** Added Export .JSONL and Export .JSON buttons.
   - **Investigation View (`frontend/src/components/InvestigationView.tsx`):** Typed `investigationData` as `InvestigationRecord`, wired to `getInvestigationFindings()`, and added honest degraded banners for `partially_completed` and `failed`.
   - **Environment Wizard (`frontend/src/components/EnvironmentWizard.tsx`):** Wrapped default token generation in `useMemo` to eliminate impure render warnings (`DEF-QA-003`).
   - **Production Build:** `tsc -b && vite build` built cleanly in 413ms with 0 errors and 0 warnings.

3. **Sub-Phase 16-C — Reproducibility, Large-Fixture Benchmarks & Air-Gapped Packaging:**
   - **Deterministic Dual-Execution Reproducibility (`backend/tests/test_phase16_c_reproducibility.py`, 3/3 passed):** Ran two independent end-to-end multi-step investigations from scratch in isolated directories (`run_a` and `run_b`), proving 100% deterministic parity across pre/post evidence hashes (RFC 3227), finding counts, categories, artifact types, correlation types (`persistence_to_execution`, `process_to_network`), and CitedReport claim partitions.
   - **Tamper Detection & Fail-Closed Vault:** Verified that direct database row modification breaks HMAC-SHA256 audit chains immediately, and importing an encrypted SQLite vault with the wrong passphrase fails closed with `CryptographicTamperError`.
   - **Large-Fixture Performance Benchmark (`scripts/benchmark_large_fixtures.py`, `docs/BENCHMARK_RESULTS.md`):** Benchmarked 512 MB and 1024 MB (1 GB) sparse disk images:
     - Streaming SHA-256 Throughput: > 2,100 MB/s.
     - Peak Hashing RAM: 0.38 MB (Bound: < 50.0 MB RAM).
     - Userspace Partition Stream Parsing: < 0.001s, 0.13 MB RAM.
   - **Production Environment Template (`.env.example`):** Created a comprehensive configuration template with zero hardcoded secrets and documented configurations for air-gapped local LLMs (Ollama / LM Studio).
   - **Release Documentation (`RELEASE_READINESS.md`):** Documented air-gapped installation, key generation, startup commands, supported formats from `COMPATIBILITY_MATRIX.md`, and operational limitations.

4. **Sub-Phase 16-D — Final Full-System Adversarial Audit & Controlled Release Sign-Off:**
   - Full test suite regression: **489 / 489 passed (100% green across all 38 test modules in 138.54s)**.
   - Full frontend production build: **0 errors, 0 warnings (built in 413ms)**.
   - Independent read-only security boundary audit across all Phase 14–16 controls: Verified 100% pass rate.
   - All acceptance criteria satisfied.

---

## 0.1 Executive Implementation Summary — Phase 15-B (Autonomous Loop, API Alignment & E2E Known-Answer Audit)

Phase 15-B achieved full autonomous investigation loop completion, frontend-backend API alignment, live vault WAL checkpointing, deterministic known-answer attack scenario validation, and comprehensive negative resilience verification.

### Key Accomplishments & Technical Deliverables in Phase 15-B:

1. **Multi-Step Investigation Loop & Follow-Up Routing (`backend/app/agent/investigation_controller.py`, @architect):**
   - **Continuous Follow-Up Generation:** Implemented `_plan_follow_up_actions()` to detect unanalyzed artifacts in custody matching empirical pivots (processes, user accounts, network connections) and queue targeted follow-up parser actions instead of prematurely terminating after a single pass.
   - **Finite Bounded Execution:** Strictly enforced `budget.max_iterations` and `budget.max_tool_executions`, transitioning the lifecycle state cleanly to `PARTIALLY_COMPLETED` upon budget exhaustion.
   - **Fail-Closed Degraded Transitions:** Guaranteed that if all actions fail or unhandled errors occur, the investigation transitions to `FAILED` or `PARTIALLY_COMPLETED` rather than falsely claiming `COMPLETED`.

2. **Strict Report Separation & Fail-Closed Citations (`backend/app/agent/report_builder.py`, @architect):**
   - **Confirmed Findings vs Unverified Hypotheses:** Added `unverified_hypotheses: List[CitedClaim]` to `CitedReport` and updated `ReportBuilder.build_report()` to partition claims into two disjoint categories:
     - **Confirmed Findings (`observed_facts`, `derived_correlations`):** 100% backed by verified DuckDB finding IDs and hashes, confidence > 0.40, `verification_status="VERIFIED"`, and not requiring review. Confirmed findings NEVER contain ungrounded or downgraded assertions.
     - **Unverified Hypotheses (`unverified_hypotheses`):** Hypotheses, ungrounded leads, and downgraded assertions (confidence <= 0.40 or requiring review) explicitly separated from verified forensic facts.
   - **Markdown Rendering:** Rendered a dedicated subsection `### Unverified Hypotheses & Evaluated Leads` in `CitedReport.to_markdown()` with explicit forensic disclaimers.
   - **Strict Citations Default:** Flipped `InvestigationController.compile_report(self, strict_citations: bool = True)` to default to `True`.

3. **Investigation API Alignment & Safe WAL Vault Checkpoint (@security):**
   - **Investigation Endpoints (`backend/app/api/investigations.py`):**
     - `GET /api/investigations/{case_id}/findings`: Case-scoped structured findings from DuckDB with pagination.
     - `GET /api/investigations/{case_id}/hypotheses`: Active competing hypotheses with status and confidence.
     - `GET /api/investigations/{case_id}/timeline`: Chronologically unified timeline combining empirical findings and action execution traces.
   - **Report & Custody Download Endpoints (`backend/app/api/reports.py`, `backend/app/api/intake.py`):**
     - `GET /api/reports/{case_id}/export`: Exports cited report in Markdown (`.md`) or JSON (`.json`) with attachment headers.
     - `GET /api/intake/custody/{case_id}/export`: Exports custody ledger in JSONL (`application/x-ndjson`) or JSON (`application/json`).
   - **Safe Live Vault WAL Checkpoint (`backend/app/core/crypto.py`):**
     - Executed `PRAGMA wal_checkpoint(TRUNCATE)` prior to generating SQLite SQL dump/iterdump during `export_encrypted_vault()`, guaranteeing zero lost rows under active concurrent write workloads.

4. **Deterministic Known-Answer Scenario & Resilience Test Suite (`backend/tests/fixtures/known_answer_case/`, `backend/tests/test_phase15_b_e2e_investigation.py`, @qa):**
   - **Known-Answer Attack Fixtures:**
     - `software.hiv`: Binary REGF hive with Run key persistence (`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SystemUpdater = "C:\Users\Public\updater.exe"`).
     - `software_run.jsonl`: JSONL export format for fallback and direct ingestion.
     - `triage/`: Directory with `processes.jsonl` (updater.exe PID 4120, parent 1024), `network_connections.jsonl` (outbound C2 socket to `198.51.100.45:4444`), and `security_events.jsonl` (Logon 4624, Service 7045).
   - **Multi-Step E2E Investigation Test:** Verified autonomous ingestion, pivot extraction, correlation (`persistence_to_execution`, `process_to_network`), and formal report compilation with `strict_citations=True`.
   - **Ungrounded Claim Quarantine Resilience:** Verified that hallucinated finding IDs, unverified hashes, and text without entity overlap are quarantined into hypotheses/rejected claims, never polluting Confirmed Findings.
   - **Honest LLM Failure Degradation:** Verified that analyzer timeout and malformed JSON errors degrade to `partial` or `failed` without claiming false success.
   - **Concurrent WAL Vault Export:** Verified that active background SQLite writers lose zero committed rows across export and import.
   - **Evidence Immutability:** Verified pre- and post-analysis fixture hashes remain identical (RFC 3227).

5. **Test Suite & Build Verification:**
   - Full repository regression: **477 / 477 passed (100% green, 0 failures across all 36 test modules in 154.57s)**.
   - Frontend production build: **0 errors, clean build in 409ms**.
   - Knowledge graph updated: **4802 nodes, 12845 edges** (`graphify update .`).

---

## 0.1 Executive Implementation Summary — Phase 15-A (LangGraph Loop, Case Isolation, CitationGuard & Real Forensics Pipeline)

Phase 15-A replaced mock pipelines with genuine deterministic forensics analyzers, enforced strict cross-case tenant isolation in the storage and citation layers, connected the complete LangGraph state machine lifecycle, and enabled ungrounded claim downgrading to calibrated hypotheses.

### Key Accomplishments & Technical Deliverables in Phase 15-A (Agent 2):

1. **LangGraph State Machine & Lifecycle Loop (`backend/app/agent/graph.py`, `backend/app/agent/investigation_controller.py`):**
   - **Triage Directory & Flat Stream Parsing:** Enhanced `_make_dissect_parser_node` in `graph.py` to identify directory-based triage capsules (`triage`, `triage_directory`, `directory`, `dir`), replacing rigid `is_file()` checks with `exists()`, guarding file-only hashing, and routing directly to `DissectAdapter.parse_triage_directory()`.
   - **Provenance Preservation Across Nodes:** Standardized extraction and edge data passing between analyzer execution, DuckDB/SQLite ingestion, hypothesis planning, and reporting nodes.
   - **Controller Integration:** Added Tier A execution dispatch for `dissect_triage` and implemented `compile_report(self, strict_citations: bool = False)` on `InvestigationController` bridging the controller directly to `CitationGuard` and `ReportBuilder`.

2. **Strict Multi-Case Data Isolation (`backend/app/core/storage.py`, `backend/app/agent/report_builder.py`):**
   - **Storage Layer Scoping:** Added explicit `case_id: Optional[str] = None` filtering across `ForensicStore.get_finding()`, `ForensicStore.get_findings_by_ids()`, and `ForensicStore.check_citations_exist()`.
   - **Report Scoping:** Scoped `ReportBuilder` finding lookups strictly to the active `case_id`, preventing finding leakage across investigation boundaries.
   - Verified that findings, timelines, artifacts, and citations from Case A cannot be retrieved or cited in Case B.

3. **CitationGuard Grounding & Hypothesis Downgrading (`backend/app/core/citation_guard.py`):**
   - **Cross-Case Citation Shielding:** Enforced in `validate_claim` that any finding citing a `finding.case_id != case_id` immediately fails validation with `foreign case` error and is rejected.
   - **Hypothesis Downgrade Engine:** Implemented `downgrade_claim_to_hypothesis(claim, reasons)` and wired `downgrade_ungrounded=True` in `validate_node_result()`. Ungrounded factual claims are converted to hypotheses (`claim_type="hypothesis"`, `verification_status="UNVERIFIED"`, `confidence <= 0.40`, `requires_analyst_review=True`, with detailed review notes) instead of silently vanishing or poisoning factual findings.

4. **Testing, Verification & Full Regression:**
   - Dedicated regression test suite `backend/tests/test_phase15_a_architect_isolation.py` (4/4 passed in 0.62s).
   - Phase 15-A verification suites: `test_phase15_a_architect_isolation.py`, `test_phase15_a_dissect_plugin_runner.py`, and `test_phase15_a_forensic_pipeline.py` (21/21 passed in 1.08s).
   - Full repository regression: **459 / 459 passed (100% green, 0 failures across all 34 test modules in 133.19s)**.
   - Frontend production build: **0 errors, clean build in 408ms**.

---

## 0.1 Executive Implementation Summary — Phase 14.3 (Cryptography, Key Derivation, Vault Packaging & Hash-Chained Audit Logging)

Phase 14.3 implemented production-grade enterprise cryptographic controls across key derivation, authenticated vault export/import, and tamper-evident sequential hash chaining for both human approval audit records and consumed authorization tokens.

### Key Accomplishments & Technical Deliverables in Phase 14.3:

1. **Robust Key Derivation & Cryptographic Module (`backend/app/core/crypto.py`):**
   - **PBKDF2HMAC Derivation:** `derive_key_pbkdf2()` with SHA-256 and OWASP-recommended work factors (>= 100,000 iterations enforced; 600,000 iterations default).
   - **Argon2id Memory-Hard Derivation:** `derive_key_argon2id()` with memory cost 64MB (65536KB), 2 iterations, 4 lanes, with graceful fallback to PBKDF2HMAC via `derive_key()` dispatcher.
   - **Entropy & Randomness:** Zero hardcoded salts or nonces; strictly enforced random CSPRNG byte generation via `generate_salt(16)` and `generate_nonce(12)` using `os.urandom()`.
   - **AES-256-GCM Envelope Encryption (`AESGCMVaultCipher`):**
     - Authenticated encryption (AEAD) with structured JSON payload containing version, algorithm (`AES-256-GCM`), KDF metadata, base64-encoded salt, nonce, and ciphertext (with 16-byte authentication tag).
     - Fail-closed tamper detection raising `CryptographicTamperError(CredentialEncryptionError)` upon key error, tag mismatch, truncated tag, or corrupted ciphertext.

2. **Authenticated SQLite Vault Export & Import (`backend/app/core/crypto.py`, `backend/app/db/sqlite_store.py`):**
   - **Export (`export_encrypted_vault`):** Atomically extracts SQLite schema and records via `iterdump()`, encodes structured payload, and encrypts into an authenticated AES-256-GCM envelope file.
   - **Import (`import_encrypted_vault`):** Decrypts and authenticates package, wipes existing database state cleanly, and restores full schema and rows into target store.
   - Integrated as methods on `LLMStateStore` and module-level helpers.

3. **Tamper-Evident Sequential Hash Chains (`backend/app/core/approval_engine.py`, `backend/app/db/sqlite_store.py`):**
   - **Schema Migrations:**
     - Safe `ALTER TABLE` migration for `consumed_approval_tokens` adding `previous_hash TEXT NOT NULL DEFAULT ''` and `current_hash TEXT NOT NULL DEFAULT ''`.
     - Created `approval_audit_log` table: `id INTEGER PRIMARY KEY AUTOINCREMENT`, `event_id TEXT UNIQUE NOT NULL`, `case_id TEXT NOT NULL`, `actor TEXT NOT NULL`, `action TEXT NOT NULL`, `target TEXT NOT NULL`, `requesting_principal_id TEXT`, `approving_principal_id TEXT`, `details_json TEXT NOT NULL`, `timestamp_utc TEXT NOT NULL`, `previous_hash TEXT NOT NULL`, `current_hash TEXT NOT NULL`.
     - Indexes created on `case_id`, `timestamp_utc`, and `action`.
   - **RFC 8785 Canonical JSON Serialization:**
     - `canonicalize_consumed_token_data()` and `canonicalize_approval_audit_data()` serialize all immutable record attributes with sorted keys and compact separators.
   - **Sequential HMAC-SHA256 Hash Chain Computation:**
     - Anchored with `GENESIS_HASH = "0" * 64`.
     - Within transaction and reentrant lock (`threading.RLock()`), sequentially fetches preceding `current_hash` and calculates `HMAC-SHA256(secret_key, previous_hash || canonical_data)`.
     - Fail-closed execution: any hash calculation or database insertion failure raises `ForensicOpsError` immediately.
     - Covers all approval lifecycle transitions (`create_request`, `approve_request`, `reject_request`, `revoke_request`, `verify_and_consume_token`, `consume_token`).
   - **Verification & Tamper Detection:**
     - `verify_consumed_tokens_chain(case_id=None, secret_key=None) -> Tuple[bool, Optional[str]]`
     - `verify_approval_audit_chain(case_id=None, secret_key=None) -> Tuple[bool, Optional[str]]`
     - Chronologically walks table rows, recalculating HMAC-SHA256 and validating previous hash links.
     - Returns `(False, f"Tamper detected at row {row_id}...")` immediately on any data modification, deleted row, or broken link.
     - Methods available on `ApprovalEngine` and exported as module-level functions.
     - Added `get_approval_audit_logs()` to `ApprovalEngine` and `LLMStateStore`.

4. **Testing, Verification & Full Repository Regression:**
   - Dedicated adversarial test suite `backend/tests/test_phase14_3_crypto_audit.py` (11/11 passed in 1.62s).
   - Dedicated key derivation test suite `backend/tests/test_crypto_key_derivation_vault.py` (8/8 passed in 0.50s).
   - Approval engine test suites: `test_phase08_human_approval_engine.py`, `test_phase14_1_approval_security.py`, `test_phase14_1_r1_approval_security.py` (51/51 passed).
   - Full repository regression: **438 / 438 passed (100% green, 0 failures across all 33 test modules in 131.27s)**.
   - Frontend production build: **0 errors, clean build in 475ms**.

---

## 0.1 Executive Implementation Summary — Phase 14.2-C (Complete Windows Registry Hive Parser)

Phase 14.2-C completely resolved defect **DEFECT-FOR-02** by implementing a production-grade, zero-dependency, pure-Python binary Windows Registry Hive parser (`WindowsRegistryHiveParser`) capable of ingesting, validating, parsing, and normalizing offline Windows Registry hives as forensic evidence in air-gapped environments.

### Key Accomplishments & Defect Remediations in Phase 14.2-C:

1. **Resolution of DEFECT-FOR-02 (Offline Binary Hive Parsing & Forensic Extraction):**
   - **Binary REGF Format Engine (`registry_parser.py`):**
     - REGF Base Block (4096 bytes) parser with strict XOR-32 running checksum verification over offset 0..508 (127 DWORDs), handling Microsoft edge cases (0 -> 1, 0xFFFFFFFF -> 0xFFFFFFFE).
     - Hive bins (`hbin`) parsing with cell allocation sign decoding (negative size = allocated cell, positive size = unallocated cell).
     - Named Key (`nk`) record traversal supporting UTF-16LE and ASCII/Latin-1 (bit 5) encodings.
     - Subkey indexing supporting all standard leaf structures: fast leaf (`lf`), hash leaf (`lh`), index leaf (`li`), and root index (`ri`).
     - Value Key (`vk`) parsing supporting both inline data (bit 31 of data size set) and cell-referenced data, big data (`db`) chains, and default `(Default)` unnamed values.
     - Full data type decoders: `REG_SZ`, `REG_EXPAND_SZ`, `REG_BINARY`, `REG_DWORD` (little-endian & big-endian), `REG_LINK`, `REG_MULTI_SZ`, `REG_QWORD`.
     - Timestamp conversion: Windows 64-bit `FILETIME` (100-nanosecond intervals since Jan 1, 1601 UTC) converted accurately to ISO-8601 UTC.
   - **Verification:** Verified by `backend/tests/test_phase14_2_c_registry_parser.py` (Tests 1 through 10, 28).

2. **Supported Hive Families & Artifact Extraction:**
   - **SYSTEM:** Active ControlSet detection via `Select\Current`, `ComputerName`, `TimeZoneInformation`, `Services` & `Drivers` (automatically flagging suspicious ImagePath keywords such as `\Temp\`, `\AppData\`, `powershell`, `cmd.exe`, `rundll32`, etc. as severity `high`), `USBSTOR` device enumeration, and Network Interfaces.
   - **SOFTWARE:** OS build/version metadata (`Microsoft\Windows NT\CurrentVersion`), Installed Applications (`Microsoft\Windows\CurrentVersion\Uninstall\*`), and Run/RunOnce persistence keys.
   - **NTUSER.DAT:** `RunMRU` dialog history, `RecentDocs` MRU, `UserAssist` execution history with ROT13 path decoding and run count / last execution timestamps, `TypedPaths`, and user-level Run persistence.
   - **SAM & SECURITY:** User account metadata, RIDs, and last logon timestamps. **Strict Forensic Security Rule:** Password hashes (LM/NT hashes) and LSA secrets are NEVER exposed, parsed, or exported; marked as `REDACTED_BY_FORENSIC_SECURITY_POLICY`.
   - **Amcache.hve:** `Root\InventoryApplication` and `Root\InventoryApplicationFile` program execution metadata.
   - **UsrClass.dat:** Shellbags folder interaction artifacts (`Local Settings\Software\Microsoft\Windows\Shell\Bags`).
   - **BCD:** Boot Configuration Data boot objects.
   - **Verification:** Verified by `backend/tests/test_phase14_2_c_registry_parser.py` (Tests 11 through 18).

3. **Forensic Integrity & Provenance Tracking:**
   - Non-destructive read-only access: verified bit-identical before and after parsing.
   - Cryptographic SHA-256 hash calculated and embedded in every generated `ForensicFinding`.
   - Exact source registry key path tracked in `raw_reference` (e.g. `HKLM\SYSTEM\ControlSet001\Services\MalService`).
   - All findings seamlessly ingested and queryable via DuckDB `ForensicStore`.
   - **Verification:** Verified by `backend/tests/test_phase14_2_c_registry_parser.py` (Tests 19, 20, 29, 30, 31).

4. **Security Hardening & Resource Limits:**
   - **Bounds Checking:** Out-of-bounds cell offsets handled safely without crashing.
   - **Cycle Detection:** Visited cell tracking (`_visited_cells: Set[int]`) terminates cyclic branch references without infinite loops.
   - **Resource Limits:** Configurable limits for max hive size (256MB), max keys (50,000), max recursion depth (60), and execution timeout (60.0s) fail closed with `RegistryResourceLimitError`.
   - **Air-Gapped Zero-Dependency:** Implemented purely in Python standard library (`struct`, `codecs`, `datetime`, `pathlib`, `hashlib`), with zero external dependencies, zero subprocess execution, and zero network calls.
   - **Verification:** Verified by `backend/tests/test_phase14_2_c_registry_parser.py` (Tests 21 through 27).

5. **DissectAdapter & Intake API Integration:**
   - `DissectAdapter.parse_registry_hive()` delegates to `WindowsRegistryHiveParser` and `extract_forensic_artifacts()`.
   - `parse_artifact_auto()` checks magic bytes `magic[:4] == b"regf"` to route any binary hive to the registry parser regardless of filename or extension.
   - `intake.py` classification updated to recognize `.hve`, `.hiv`, `SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY`, `NTUSER.DAT`, `UsrClass.dat`, `Amcache.hve`, and `BCD`.
   - **Verification:** Verified by `backend/tests/test_phase14_2_c_registry_parser.py` (Tests 29, 32) and `backend/tests/test_phase2_plugins.py`.

---

## 0.1 Executive Implementation Summary — Phase 14.2-B (SIEM Credential Storage Security)

Phase 14.2-B completely resolved vulnerability **SEC-UI-001** by eliminating insecure storage of SIEM credentials in browser `sessionStorage` and `localStorage`, and implementing a secure, server-side encrypted credential store with fail-closed key management and zero secret leakage.

### Key Accomplishments & Defect Remediations in Phase 14.2-B:

1. **Resolution of SEC-UI-001 (Zero Secret Leakage in Browser Storage & API Responses):**
   - **Frontend Elimination:**
     - Removed hardcoded default `siemApiKey: "es-sec-token-1234"` from `DEFAULT_WIZARD_STATE` in `frontend/src/context/InvestigationContext.tsx`.
     - In `updateWizardState`: Added sanitization filter ensuring `siemApiKey`, `password`, `apiKey`, `token`, and `credentials` are stripped prior to `sessionStorage.setItem()`.
     - In `saveSessionNow`: Stripped credentials before calling `api.saveSession()` or `api.createOrUpdateCase()`.
     - In `EnvironmentWizard.tsx`: Replaced plaintext API key input with a managed connection selector and write-only credential fields. Credentials are held only in transient React memory for write operations, never stored in `sessionStorage`.
   - **API Zero-Leakage Guarantee:**
     - `GET /api/siem/connections` and `GET /api/siem/connections/{connection_id}` strictly return `SIEMConnectionResponse` exposing only boolean presence flags (`has_password`, `has_api_key`, `has_token`).
     - Plaintext passwords, API keys, tokens, and raw ciphertexts are NEVER included in response payloads.
   - **Verification:** Verified by `backend/tests/test_phase14_2_b_siem_credential_security.py` (`test_create_and_get_siem_connection_zero_secret_leakage`, `test_session_state_sanitizes_wizard_credentials`).

2. **Server-Side Authenticated Symmetric Credential Store (`credential_store.py`):**
   - **Engine:** Built `backend/app/core/credential_store.py` utilizing `cryptography.fernet.Fernet` (AES-128-CBC with HMAC-SHA256 authenticated encryption at rest).
   - **Fail-Closed Key Loading:**
     - Master key loaded from `FORENSICOPS_CREDENTIAL_KEY` or file path `FORENSICOPS_CREDENTIAL_KEY_FILE`.
     - Validates key format (32 url-safe base64-encoded bytes).
     - If key is missing or invalid, immediately fails closed by raising `CredentialEncryptionError(ForensicOpsError)`. Plaintext fallback is strictly prohibited.
     - Never stores encryption keys alongside ciphertext in the database.
   - **Tamper Evidence:** Tampered or corrupted ciphertext fails closed via Fernet `InvalidToken` caught and translated into `CredentialEncryptionError`.
   - **Verification:** Verified by `backend/tests/test_phase14_2_b_siem_credential_security.py` (`test_missing_encryption_key_fails_closed`, `test_invalid_key_format_fails_closed`, `test_tampered_ciphertext_fails_closed`, `test_api_create_connection_fails_closed_when_key_missing`).

3. **At-Rest Encrypted Persistence & SQLite Schema (`sqlite_store.py`):**
   - Added table `siem_connections` to SQLite database (`sqlite_store.py`):
     - Stores `connection_id`, `case_id`, `siem_type`, `endpoint_url`, `index_pattern`, `allowed_hosts_json`, `headers_json`, `verify_ssl`, `timeout_seconds`, `encrypted_credentials`, `has_password`, `has_api_key`, `has_token`, `username`, `created_by`, `created_at_utc`, `updated_at_utc`.
     - Implemented `create_siem_connection_record`, `get_siem_connection_record`, `list_siem_connection_records`, `update_siem_connection_record`, `delete_siem_connection_record`.
   - Verified that inspecting raw SQLite database files confirms plaintext secrets are absent on disk.
   - Implemented `sanitize_session_data()` in `sqlite_store.py` to recursively strip credentials from `investigation_sessions` and `cases.serialized_state`.
   - **Verification:** Verified by `backend/tests/test_phase14_2_b_siem_credential_security.py` (`test_sqlite_database_stores_only_ciphertext`, `test_credentials_persist_across_restarts`).

4. **Preservation of Existing SIEM Connectors & Safe Updates:**
   - Supported Elasticsearch, Wazuh, and Splunk connectors.
   - **Blank Update Safety:** When updating connection metadata, blank/None credential fields preserve existing encrypted credentials.
   - **Explicit Removal:** Deletion of stored credentials requires explicit flags (`remove_password`, `remove_api_key`, `remove_token`, `clear_credentials`) or `DELETE /api/siem/connections/{connection_id}`.
   - **In-Memory Decryption for Queries:** `POST /api/intake/siem` accepts `connection_id`. Decryption occurs in backend memory only to initialize the pinned connector, returning findings without exposing secrets.
   - **Scrubbed Exceptions & Logging:** Exceptions occurring in connectors or test endpoints are scrubbed with `sanitize_credentials()`, preventing secret leakage in HTTP 400/500 error bodies.
   - **Verification:** Verified by `backend/tests/test_phase14_2_b_siem_credential_security.py` (`test_blank_update_preserves_existing_credentials`, `test_explicit_credential_removal_and_deletion`, `test_siem_intake_query_with_connection_id`, `test_exception_handling_scrubs_credentials`, `test_siem_connection_test_endpoint_sanitizes_errors`).

---

Phase 14.2-A completely resolved vulnerability **SEC-NET-002** by eliminating DNS rebinding and time-of-check / time-of-use (TOCTOU) attack surfaces across all SIEM HTTP connectors (Elasticsearch, Wazuh, Splunk).

A socket-level IP-pinning transport was engineered that guarantees the exact IP address validated against network boundary and SSRF security policies is the exact IP address contacted by the operating system socket layer. This is achieved while 100% preserving original hostnames for HTTP `Host` headers, TLS Server Name Indication (SNI), and TLS certificate hostname verification without disabling or weakening TLS certificate validation (`verify_ssl=True`).

### Key Accomplishments & Defect Remediations in Phase 14.2-A:

1. **Resolution of SEC-NET-002 (Elimination of DNS Rebinding & TOCTOU in SIEM Connectors):**
   - **Files:** `backend/app/core/network_validator.py`, `backend/app/connectors/siem_connectors.py`
   - **Root Cause Eliminated:** Connectors previously validated the endpoint URL once during initialization via `socket.getaddrinfo()`, but subsequently instantiated an unpinned `httpx.Client`. At request time, standard HTTP connection establishment executed a secondary, uncontrolled DNS resolution. Domains with short or zero TTL could pass pre-flight checks and then rebind to `127.0.0.1` or `169.254.169.254`.
   - **Fix Applied:**
     - Implemented `PinnedNetworkBackend(httpcore.SyncBackend)`: Overrides `connect_tcp()` to resolve and validate destination IP addresses against strict SSRF and network allowlists at socket creation time, and binds `socket.create_connection((pinned_ip, port))` directly to the validated raw IP literal. This eliminates secondary DNS queries by the OS or HTTP transport.
     - Implemented `PinnedSIEMTransport(httpx.HTTPTransport)`: Injects `PinnedNetworkBackend` into the connection pool and performs pre-flight URL validation via `validate_url_ssrf()` on every dispatched request, including redirect hops.
     - Implemented `create_pinned_siem_client()` factory providing secure `httpx.Client` instances.
     - Updated `BaseSIEMConnector.__init__()` to use `create_pinned_siem_client()` by default whenever `http_client` is not injected.
     - Added `except SSRFSecurityError: raise` in `ElasticsearchConnector`, `WazuhConnector`, and `SplunkConnector` (`test_connection` and `search`), ensuring security policy violations fail closed and are never disguised as generic `SIEMQueryError`.
   - **Verification:** Verified by `backend/tests/test_phase14_2_a_siem_ssrf.py` (`test_dns_rebinding_between_validation_and_connection_blocked`, `test_dns_rebinding_blocked_in_siem_connector`).

2. **Preservation of TLS SNI, Certificate Verification & HTTP Host Headers:**
   - **Files:** `backend/app/core/network_validator.py` (`PinnedNetworkBackend`)
   - **Mechanism:** In `httpcore`, `HTTPConnection._connect` separates TCP connection from TLS upgrading. `PinnedNetworkBackend.connect_tcp` connects the socket to the validated IP, and then `stream.start_tls(server_hostname=...)` is invoked with the original hostname.
   - **Security Guarantee:**
     - HTTP `Host` header sent to server contains the original hostname and port (`Host: siem.corp:9200`).
     - TLS SNI extension in ClientHello contains the original hostname.
     - Native Python `ssl.SSLContext` validates the server certificate against the original hostname (`check_hostname=True`, `CERT_REQUIRED`). Mismatched certificates immediately raise `ConnectError`/`SSLCertVerificationError`.
     - Zero relaxation or disabling of TLS certificate verification.
   - **Verification:** Verified by `backend/tests/test_phase14_2_a_siem_ssrf.py` (`test_tls_verification_preserves_hostname_and_sni`, `test_http_host_header_preserved`).

3. **Strict IPv4-Mapped IPv6 Bypass Rejection (Requirement 7):**
   - **File:** `backend/app/core/network_validator.py` (`is_ip_prohibited`, `resolve_and_validate_destination`, `STRICTLY_PROHIBITED_HOSTNAMES`)
   - **Root Cause Eliminated:** `ipaddress.IPv6Address.is_loopback` and `IPv4Network` containment checks previously failed on IPv4-mapped IPv6 representations (e.g. `::ffff:127.0.0.1`, `::ffff:7f00:1`, `::ffff:169.254.169.254`).
   - **Fix Applied:**
     - Added unmapping logic at the entrance of `is_ip_prohibited()`: `if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped: ip = ip.ipv4_mapped`.
     - Underlying IPv4 addresses are evaluated strictly against loopback, metadata, link-local, multicast, and private CIDR boundaries.
     - Added `::ffff:127.0.0.1` and `::ffff:169.254.169.254` to `STRICTLY_PROHIBITED_HOSTNAMES`.
     - Bracketed IPv6 notation (`[::ffff:...]`) is safely normalized.
   - **Verification:** Verified by `backend/tests/test_phase14_2_a_siem_ssrf.py` (`test_ipv4_mapped_ipv6_loopback_rejected`, `test_ipv4_mapped_ipv6_metadata_rejected`, `test_is_ip_prohibited_unmaps_ipv6`).

4. **Safe Redirect Handling (Requirement 9):**
   - **Files:** `backend/app/connectors/siem_connectors.py`, `backend/app/core/network_validator.py`
   - **Behavior:**
     - Default policy in `BaseSIEMConnector`: `follow_redirects=False` prevents unexpected external hops.
     - If redirects are followed (e.g. via `PinnedSIEMTransport`), `handle_request()` evaluates `validate_url_ssrf()` on every redirect destination URL before the hop occurs.
     - Redirects to cloud metadata (`169.254.169.254`), loopback (`127.0.0.1`), or unauthorized private networks raise `SSRFSecurityError` and terminate the request immediately.
     - Redirects to authorized endpoints are validated and pinned.
   - **Verification:** Verified by `backend/tests/test_phase14_2_a_siem_ssrf.py` (`test_redirect_to_forbidden_destination_blocked`, `test_redirect_to_allowed_destination_validated`).

5. **Dedicated Private Subnet SIEM Support & Universal Loopback Prohibition:**
   - **Files:** `backend/app/models/connectors.py` (`SIEMConnectionConfig`), `backend/app/core/network_validator.py`
   - **Enhancement:** Replaced `@field_validator("endpoint_url")` with `@model_validator(mode="after")` so `allowed_hosts` (e.g., `["10.200.0.0/16"]`) is passed into `validate_url_ssrf()`. Authorized enterprise SIEM servers in private RFC 1918 / RFC 4193 subnets are permitted when explicitly configured.
   - **Loopback Invariant:** Fixed `network_validator.py` dev-mode logic to ensure loopback addresses (`127.0.0.1`, `::1`) are strictly prohibited under all circumstances, even when `FORENSICOPS_ALLOW_PRIVATE_SIEM` is enabled.
   - **Verification:** Verified by `backend/tests/test_phase14_2_a_siem_ssrf.py` (`test_private_siem_allowed_when_configured_in_allowed_hosts`, `test_private_siem_rejected_when_not_in_allowed_hosts`).

6. **Full Test Suite & Verification:**
   - **New Verification Suite:** `backend/tests/test_phase14_2_a_siem_ssrf.py` (17 tests covering all requirements, 100% passing).
   - **Complete Repository Suite:** **365 / 365 tests PASSED (100% Green)** across 35 test files.
   - **Frontend Production Build:** Clean build (0 errors, 0 warnings).
   - **Graphify AST Update:** 4171 nodes, 11823 edges synchronized.

---

## 1. Executive Implementation Summary — Phase 14.1-R1 (Critical Approval Security Remediation)

Phase 14.1-R1 resolved the three critical security vulnerabilities identified during the independent Phase 14.1 security audit:
- **AUDIT-P14-01**: Two-Person Rule identity representation bypass.
- **AUDIT-P14-02**: Approval token issuance from incomplete or invalid approved database records.
- **AUDIT-P14-03**: LangGraph workflow execution and resume paths bypassing persistent token consumption.

A unified, fail-closed approval authorization path was established across the API (`POST /api/approvals`, `POST /api/workflows`), `ApprovalEngine`, `InvestigationController`, and `ForensicOpsWorkflowEngine` (LangGraph).

### Key Accomplishments & Defect Remediations in Phase 14.1-R1:

1. **Remediation of AUDIT-P14-01 (Canonical Identity & Universal Two-Person Rule Enforcement):**
   - **Files:** `backend/app/auth/models.py`, `backend/app/auth/store.py`, `backend/app/models/approval.py`, `backend/app/core/approval_engine.py`, `backend/app/api/investigations.py`, `backend/app/agent/investigation_controller.py`, `backend/app/api/approvals.py`, `backend/app/api/workflows.py`
   - **Root Cause Eliminated:** `InvestigationController` previously formatted investigator strings as `f"{username} ({badge_id})"`, stored in `requesting_investigator`, whereas approver verification used `current_user.username`. String inequality (`"alice" != "alice (BADGE-001)"`) allowed self-approval.
   - **Fix Applied:**
     - Added `account_type: Literal["human", "service_account", "agent"]` to user auth models and user database store with safe automatic schema migration.
     - Added `requesting_principal_id`, `approving_principal_id`, `requesting_badge_id`, and `approving_badge_id` to `ApprovalRequest` and SQLite table `approval_requests`.
     - In `ApprovalEngine.approve_request()`, `api/workflows.py::issue_approval_token`, and `api/investigations.py`, self-approval comparison now evaluates:
       1. Canonical principal UUIDs (`req.requesting_principal_id == approver.id`).
       2. Normalized base usernames (`req.requesting_investigator.split('(')[0] == approver.username.split('(')[0]`).
       3. Badge IDs (`req.requesting_badge_id == approver.badge_id`).
       4. Rejection of non-human accounts (`account_type != "human"`, or usernames matching `copilot_daemon`, `system`, `bot_lead`, `forensicops_runner`, `ai_planner`).
     - `InvestigationController` now stores clean `current_user.username` while explicitly forwarding `current_user.id` and `current_user.badge_id`.
   - **Verification:** Verified by `backend/tests/test_phase14_1_r1_approval_security.py` (`test_p14_01_badge_in_username_self_approval_rejected`, `test_p14_01_principal_id_self_approval_rejected`, `test_p14_01_service_account_and_daemon_approval_rejected`, `test_p14_01_investigation_controller_two_person_enforcement`).

2. **Remediation of AUDIT-P14-02 (Strict 12-Point Integrity Validation in `get_approved_token()`):**
   - **File:** `backend/app/core/approval_engine.py` (`get_approved_token`)
   - **Root Cause Eliminated:** `get_approved_token()` previously fell back to `issued_by = req.approving_investigator or "lead_investigator"`, allowing corrupt or tampered database records with `NULL` approver to mint cryptographically valid tokens without Two-Person verification.
   - **Fix Applied:**
     - Completely removed default fallback to `"lead_investigator"`. `req.approving_investigator` must be explicitly non-empty.
     - Verified Two-Person Rule directly on the stored database record (requester != approver by canonical ID, base username, and badge ID).
     - Verified non-empty `parameter_digest`.
     - Verified timestamp consistency (`created_at_utc <= resolved_at_utc < expires_at_utc` and not expired).
     - Verified that the approver exists in `user_store`, is active (`is_active=True`), and is a human account (`account_type="human"`).
     - Verified token has not been recorded in `consumed_approval_tokens`.
     - Fails closed and returns `None` on any anomaly or failure.
   - **Verification:** Verified by `backend/tests/test_phase14_1_r1_approval_security.py` (`test_p14_02_null_approver_db_record_returns_none`, `test_p14_02_self_approved_db_record_returns_none`, `test_p14_02_inactive_or_service_approver_returns_none`).

3. **Remediation of AUDIT-P14-03 (LangGraph Persistent One-Time Token Consumption & Cross-Subsystem Replay Prevention):**
   - **Files:** `backend/app/agent/graph.py` (`resume_workflow`, `_make_human_approval_gate_node`, `ForensicOpsWorkflowEngine`), `backend/app/api/deps.py` (`get_workflow_engine`), `backend/app/api/workflows.py` (`resume_workflow`)
   - **Root Cause Eliminated:** LangGraph `resume_workflow` and gate nodes only verified HMAC signatures in memory without writing to SQLite `consumed_approval_tokens`. Tokens could be replayed across workflows and after restarts.
   - **Fix Applied:**
     - Connected `ForensicOpsWorkflowEngine` to `ApprovalEngine`.
     - In `resume_workflow()`, `ApprovalEngine.verify_and_consume_token()` is invoked prior to re-executing the DAG. This validates bindings, marks `consumed_approval_tokens` in SQLite, updates the request to `status='consumed'`, and sets `token.consumed = True`.
     - Duplicate resume attempts immediately raise `UnauthorizedCollectorExecutionError: Replay detected: Approval token has already been consumed.`, mapped to HTTP 400 Bad Request in the API.
     - In `_make_human_approval_gate_node()`, unconsumed tokens provided at execution start are persistently consumed in SQLite.
     - Replay prevention works symmetrically across subsystems: a token consumed by `InvestigationController` cannot resume a LangGraph workflow, and a token consumed by LangGraph cannot be reused by `InvestigationController`.
   - **Verification:** Verified by `backend/tests/test_phase14_1_r1_approval_security.py` (`test_p14_03_langgraph_resume_persistently_consumes_token`, `test_p14_03_langgraph_replay_rejected_same_workflow`, `test_p14_03_cross_workflow_token_replay_rejected`, `test_p14_03_cross_subsystem_replay_controller_to_langgraph`, `test_p14_03_api_resume_workflow_replay_returns_400`).

4. **Preserved Capabilities & Architectural Integrity:**
   - **Strict Air-Gap & Local-First:** All analysis remains strictly local/offline. SSH remote collection remains completely removed.
   - **Full Test Suite Verification:** **348 / 348 PASSED** across 34 test modules.
   - **Frontend Production Build:** Clean build (0 errors, 0 warnings).

---

## 1. Executive Implementation Summary — Phase 14.1-R0 (Removal of SSH Remote Collection)

Phase 14.1-R0 completely eliminated SSH-based remote evidence collection from ForensicOps AI, strictly focusing the platform on local-first, air-gapped, and offline digital forensics investigations for the current development roadmap. All attack surfaces associated with remote SSH transport, endpoint credentials, remote shell acquisition, and online intake routes have been dismantled while preserving all offline forensic analysis capabilities.

### Key Accomplishments in Phase 14.1-R0:

1. **Complete Deletion of Remote SSH Collector Infrastructure:**
   - **Deleted File:** `backend/app/connectors/ssh_collector.py`
   - **Removed Components:** `EndpointTransport`, `SSHSubprocessTransport`, `WinRMTransport`, `MockEndpointTransport`, `OnlineCollectorOrchestrator`, `CollectorProtocol`, `CollectorExecutionResult`, `EndpointTarget`, and `TargetOSType`.
   - **Cleaned Modules:** `backend/app/connectors/__init__.py`, `backend/app/models/connectors.py`, `backend/app/models/__init__.py`, `backend/app/api/deps.py`.

2. **Removal of Remote Collection API Endpoints & Schemas:**
   - **Removed Endpoint:** `POST /api/intake/online` and `OnlineCollectorIntakeRequest` schema removed from `backend/app/api/intake.py`.
   - **Fail-Closed Gate:** Requests to `/api/intake/online` return HTTP 404 Not Found.
   - **Workflow Rejection:** Requests to `POST /api/workflows/approval-token` for `action_type in ("remote_collection", "remote_endpoint_collection", "remote_access")` or nodes referencing `ssh_collector`, `winrm_collector`, `online_collector`, or `remote_collector` are rejected with HTTP 400 Bad Request ("Remote collection has been removed. ForensicOps AI operates strictly in local/offline mode.").

3. **Autonomous Controller & Capability Registry Alignment:**
   - **Files:** `backend/app/agent/investigation_controller.py`, `backend/app/models/investigation.py`
   - **Alignment:** Removed `"ssh_collector"` and `"winrm_collector"` from active capabilities. Added `"system_containment"` and refined action types to `Literal["tier_a_parser", "tier_b_tool", "store_query", "pivot_search", "containment"]`.
   - **Deterministic Target Resolution:** Added `_resolve_action_target` to `InvestigationController` ensuring consistent host/artifact target binding across request creation, verification, and execution.

4. **Frontend Remote Intake Elimination & Clean Build:**
   - **Files:** `frontend/src/types/index.ts`, `frontend/src/context/InvestigationContext.tsx`, `frontend/src/services/api.ts`, `frontend/src/components/EnvironmentWizard.tsx`
   - **Removal:** Removed online host, port, protocol, OS, and credential fields from the frontend state. Removed the "Online Remote Triage" option from `EnvironmentWizard.tsx`.
   - **Build Verification:** `npm --prefix frontend run build` built with 0 errors and 0 warnings.

5. **Preserved Capabilities (Offline & Local Integrity):**
   - **Local Evidence Ingestion:** Full disk images (raw, dd, VMDK, E01), memory dumps, PCAP network captures, Windows EVTX logs, Registry hives.
   - **Offline Capsule Ingestion:** `CustodyEngine.unpack_collector_capsule` for analyst-uploaded triage capsules (`.zip`).
   - **Offline Log Analysis:** `LinuxDFIRSpecialist.linux_ssh_activity` for local `/var/log/auth.log` parsing.
   - **Local Approvals:** Human approval tokens for sensitive local operations (containment, report signing, evidence deletion).
   - **SIEM Connectors:** Read-only query connectors (Elasticsearch, Wazuh, Splunk) with SSRF loopback protections.

6. **Full Test Suite Verification:**
   - **Test Suite Status:** **336 / 336 PASSED** across 33 test modules in 113.75s.
   - **Frontend Production Build:** Clean build (0 errors, 0 warnings).

---

## 1. Executive Implementation Summary — Phase 14.1

Phase 14.1 resolved all residual security vulnerabilities and architectural defects identified during the independent Phase 13 security audit (`AUDIT-P13-01`, `AUDIT-P13-02`, and `AUDIT-P13-03`). The platform's approval architecture was fundamentally reformed: direct workflow token manufacturing was eliminated, enforcing a strict lifecycle where approval tokens can only be issued following an independent, pre-existing, and cryptographically verified approval request under an uncompromised Two-Person Rule.

The test suite expanded from **328 to 353 tests (+25 tests across a dedicated Phase 14.1 security suite)** with zero regressions, zero skipped tests, and full backward compatibility across all existing APIs, workflows, and frontend components.

### Key Accomplishments & Defect Remediations in Phase 14.1:

1. **Remediation of AUDIT-P13-01 (Unconditional Target Enforcement in Remote Collection):**
   - **File:** `backend/app/connectors/ssh_collector.py` (`verify_approval_gate`)
   - **Security Hardening:** Eliminated conditional checks that permitted tokens with `target=None` to pass. `verify_approval_gate()` now unconditionally requires `token.target` to be non-empty and strictly equal to `target.host`. Furthermore, `token.verify(..., expected_target=target.host)` is executed unconditionally, guaranteeing that tokens issued for Host A cannot execute against Host B, and tokens without explicit targets are rejected prior to any transport initiation.
   - **Verification:** Verified by `backend/tests/test_phase14_1_approval_security.py` (`test_remote_collection_null_target_rejected`, `test_remote_collection_empty_target_rejected`, `test_remote_collection_target_mismatch_rejected`, `test_remote_collection_valid_target_succeeds`).

2. **Remediation of AUDIT-P13-02 (Two-Person Rule Hardening & Elimination of Identity Spoofing):**
   - **Files:** `backend/app/api/workflows.py` (`issue_approval_token`), `backend/app/core/approval_engine.py` (`approve_request`)
   - **Security Hardening:** Eradicated the client-supplied `requesting_investigator` parameter from the workflow token request body. Requester identity is now derived exclusively and immutably from the authenticated session of Investigator A when the request is created. Approver identity is derived strictly from the authenticated JWT session of Investigator B at approval time. The Two-Person Rule is enforced unconditionally (`found_req.requesting_investigator != current_user.username`), rejecting self-approval and autonomous controller self-authorization.
   - **Verification:** Verified by `backend/tests/test_phase14_1_approval_security.py` (`test_two_person_rule_self_approval_rejected`, `test_two_person_rule_client_spoofed_requester_ignored`, `test_two_person_rule_independent_approver_succeeds`, `test_agent_cannot_self_approve`).

3. **Remediation of AUDIT-P13-03 (Fail-Closed Token Persistence & Database Error Handling):**
   - **File:** `backend/app/api/workflows.py` (`issue_approval_token`)
   - **Security Hardening:** Removed `try ... except Exception: pass` blocks that silently swallowed database registration failures. If SQLite database persistence or transaction commit fails during approval or token registration, the endpoint fails closed immediately (HTTP 500) and no token is ever minted or returned to the client.
   - **Verification:** Verified by `backend/tests/test_phase14_1_approval_security.py` (`test_db_persistence_failure_fails_closed_no_token_issued`).

4. **Architectural Reform: Decoupled Approval Lifecycle (Elimination of Direct Token Manufacturing):**
   - **Files:** `backend/app/api/workflows.py`, `backend/app/core/approval_engine.py` (`approve_request`, `get_approved_token`)
   - **Architectural Reform:** Completely deleted direct token manufacturing (`INSERT OR REPLACE ... status='approved'`). The workflow router now requires a pre-existing `ApprovalRequest` record in the database. If no matching request exists, the route fails closed with HTTP 400 Bad Request. If a request is in `pending` status, it is transactionally transitioned to `approved` via `ApprovalEngine.approve_request()`. If already approved, the signed token is retrieved via `ApprovalEngine.get_approved_token()`.
   - **Verification:** Verified by `backend/tests/test_phase14_1_approval_security.py` (`test_workflow_endpoint_rejects_nonexistent_request`, `test_workflow_endpoint_approves_pending_request`, `test_workflow_endpoint_retrieves_existing_approved_token`).

5. **Concurrency & Replay Defense Hardening:**
   - **File:** `backend/app/core/approval_engine.py` (`consume_token`, `approve_request`)
   - **Security Hardening:** Added threading mutex synchronization (`self._lock`) to protect SQLite connection concurrency. State transitions use atomic conditional updates (`UPDATE approval_requests SET status = 'approved' ... WHERE approval_id = ? AND status = 'pending'`). Token consumption catches `sqlite3.IntegrityError` on the `consumed_approval_tokens` primary key and raises `UnauthorizedCollectorExecutionError` on duplicate or concurrent replay attempts.
   - **Verification:** Verified by `backend/tests/test_phase14_1_approval_security.py` (`test_concurrent_consumption_replay_prevention`, `test_token_replay_rejected_after_consumption`, `test_expired_token_rejected`).

### Test Verification & Quality Metrics:
- **Dedicated Phase 14.1 Security Suite:** `backend/tests/test_phase14_1_approval_security.py` (25/25 passed in 15.96s).
- **Comprehensive Security & Collector Suites:** `test_phase14_1_approval_security.py`, `test_phase13_security_hardening.py`, `test_phase12_security_fixes.py`, `test_phase5_connectors.py`, `test_phase10_siem_and_live_endpoints.py` (72/72 passed in 234.77s).
- **Full Backend Test Suite:** **353 / 353 PASSED** (100% green across 33 test modules).
- **Frontend Production Build:** **0 errors, 0 warnings** (built in 406ms).

---

## 1. Executive Implementation Summary — Phase 13

Phase 13 remediated the high-priority security defects identified during the independent Phase 12 audit and Phase 0 roadmap. The platform's evidence container isolation, human approval lifecycle, two-person authorization enforcement, zero-copy at-rest protection, SSRF loopback defense, and command argument validation were systematically hardened and verified with 100% automated regression coverage.

The test suite expanded from **318 to 328 tests (+10 tests across a dedicated security hardening suite)** with zero regressions, zero skipped tests, and complete backward compatibility across all existing APIs, workflows, and frontend components.

### Key Accomplishments & High-Priority Defect Remediations:

1. **Remediation of SEC-EXEC-002 (Single-File Container Evidence Isolation):**
   - **File:** `backend/app/core/plugin_runner.py` (`PluginRunner.run_plugin`, `build_container_argv`, `AirGappedSubprocessRunner.execute`)
   - **Security Hardening:** Replaced overly broad parent directory bind mounts (`-v {input_path.parent}:/evidence:ro`) with precise single-file bind mounts (`-v {input_path.resolve()}:/evidence/{input_path.name}:ro`). Untrusted tool containers are strictly isolated from sibling evidence artifacts residing within the same storage shard in `vault/blobs/<case_id>/`.
   - **Verification:** Verified by `backend/tests/test_phase13_security_hardening.py::test_sec_exec_002_container_evidence_isolation_single_file_mount`.

2. **Remediation of Missing `/rules` Container Mount:**
   - **File:** `backend/app/core/plugin_runner.py` (`build_container_argv`, `AirGappedSubprocessRunner.execute`, `PluginRunner.run_plugin`)
   - **Security Hardening:** Added container volume mounting for YARA/Sigma rules directories (`-v {rules_path}:/rules/{rules_path.name}:ro`), ensuring rule-based forensic scanners execute within containerized isolation without path-resolution failures.
   - **Verification:** Verified by `backend/tests/test_phase13_security_hardening.py::test_container_rules_volume_mount`.

3. **Remediation of SEC-APPR-003 (Target Host Binding in Approval Gate):**
   - **File:** `backend/app/connectors/ssh_collector.py` (`verify_approval_gate`)
   - **Security Hardening:** Corrected approval gate verification from self-comparison (`token.verify(expected_target=token.target)`) to actual host assertion (`token.verify(expected_target=target.host)`). Parameter digests are rigorously validated against target-specific or model-bound digests.
   - **Verification:** Verified by `backend/tests/test_phase13_security_hardening.py::test_sec_appr_003_ssh_collector_rejects_host_mismatch`.

4. **Approval Lifecycle & Two-Person Authorization Rule Enforcement:**
   - **Files:** `backend/app/api/workflows.py`, `backend/app/core/approval_engine.py`, `backend/app/core/action_risk_policy.py`
   - **Security Hardening:** 
     - Enforced mandatory non-empty target hosts for remote collection approval tokens (HTTP 422 Unprocessable Content if missing).
     - Enforced deterministic parameter digest computation across all issued workflow tokens.
     - Implemented the Two-Person Rule: tokens specify `requesting_investigator`, and self-approval by the requesting investigator is rejected (HTTP 400 Bad Request).
     - Workflow tokens issued through `/api/workflows/approval-token` are now directly registered into `ApprovalEngine` (`approval_requests` SQLite table) with status `approved`.
     - Hardened `ApprovalEngine.consume_token()` to query `consumed_approval_tokens` before recording, raising `UnauthorizedCollectorExecutionError` on duplicate/replay attempts.
   - **Verification:** Verified by `backend/tests/test_phase13_security_hardening.py` (`test_approval_token_remote_collection_requires_target`, `test_approval_token_enforces_non_empty_parameter_digest`, `test_two_person_rule_rejects_self_approval`, `test_workflow_approval_registered_and_consumed_in_approval_engine`).

5. **Remediation of SEC-CUST-001 (Zero-Copy Evidence Write-Protection at Rest):**
   - **File:** `backend/app/core/custody_engine.py` (`register_zero_copy_reference`)
   - **Security Hardening:** Invoked `safe_make_readonly(resolved_path)` upon zero-copy disk/VM image registration, stripping write permissions and marking evidence read-only at rest on both POSIX and Windows.
   - **Verification:** Verified by `backend/tests/test_phase13_security_hardening.py::test_sec_cust_001_zero_copy_sets_readonly`.

6. **Remediation of SEC-NET-001 (SSRF Loopback Defense in Dev Override Mode):**
   - **File:** `backend/app/core/network_validator.py` (`resolve_and_validate_destination`)
   - **Security Hardening:** Retained strict blocking of loopback addresses (`127.0.0.1`, `localhost`, `ip.is_loopback`) even when `FORENSICOPS_ALLOW_PRIVATE_TARGETS=true` is enabled. Differentiated private target collection from local mock SIEM test harness isolation.
   - **Verification:** Verified by `backend/tests/test_phase13_security_hardening.py::test_sec_net_001_dev_mode_still_blocks_loopback`.

7. **Remediation of SEC-EXEC-003 (Disallowed & Allowed Argument Enforcement):**
   - **File:** `backend/app/core/execution_policy.py` (`validate_tool_execution`)
   - **Security Hardening:** Validated tool invocation arguments against `policy.disallowed_arguments` and `policy.allowed_arguments`. Disallowed flags immediately raise `ExecutionPolicyError` prior to process spawning.
   - **Verification:** Verified by `backend/tests/test_phase13_security_hardening.py::test_sec_exec_003_execution_policy_disallowed_arguments`.

### Test Verification & Quality Metrics:
- **Dedicated Phase 13 Hardening Suite:** `backend/tests/test_phase13_security_hardening.py` (10/10 passed in 3.02s).
- **Targeted Security & Collector Suite:** `backend/tests/test_phase13_security_hardening.py`, `backend/tests/test_phase12_security_fixes.py`, `backend/tests/test_attack_scenario_evtx.py`, `backend/tests/test_phase5_connectors.py` (30/30 passed in 84.79s).
- **Full Backend Test Suite:** **328 / 328 PASSED** (100% green in 320.26s across 32 test modules).
- **Frontend Production Build:** **0 errors, 0 warnings** (built in 483ms).

---

## 1. Executive Implementation Summary — Phase 12

Phase 12 remediated all five Critical architectural, security, and execution defects identified during the Phase 0 Comprehensive Audit. The platform's human authorization enforcement, containerized tool pathing, built-in userspace parser interfaces, and autonomous investigation REST APIs were hardened and verified with 100% automated regression coverage.

The test suite expanded from **305 to 318 tests (+13 tests across 2 new test modules)** with zero regressions, zero skipped tests, and full backward compatibility across the React 19 frontend and legacy workflow execution paths.

### Key Accomplishments & Critical Defect Remediations:

1. **Remediation of SEC-APPR-001 (Fail-Closed Approval Token Verification):**
   - **File:** `backend/app/models/workflow.py` (`HumanApprovalToken.verify`)
   - **Security Hardening:** Enforced strict fail-closed validation on cryptographic token verification. If an operational gate asserts `expected_case_id`, `expected_action_type`, `expected_target`, or `expected_parameter_digest`, the token **must** contain non-empty values for those fields and match them exactly.
   - **Defect Closed:** Eradicated the unconstrained wildcard master token bypass where `self.action_type = None` previously skipped constraint checks.

2. **Remediation of SEC-APPR-002 (Scoped Token Issuance on `/api/workflows/approval-token`):**
   - **File:** `backend/app/api/workflows.py` (`issue_approval_token`)
   - **Security Hardening:** Scoped all approval tokens issued through the workflow router. Binds `action_type` to `ActionType.REMOTE_COLLECTION` for collector nodes and `ActionType.WORKFLOW_EXECUTION` for workflow nodes, binds `effective_target`, computes a deterministic parameter digest, and enforces an explicit 15-minute expiration timestamp (`expires_at_utc`).
   - **Compatibility:** Full backward compatibility preserved for `EnvironmentWizard`, `WorkflowCanvas`, and `test_attack_scenario_evtx.py`.

3. **Remediation of SEC-EXEC-001 (In-Container Path Translation):**
   - **File:** `backend/app/core/plugin_runner.py` (`run_plugin`, `build_container_argv`)
   - **Execution Fix:** Implemented deterministic in-container path mapping (`/evidence/<basename>`, `/scratch`, `/rules/<basename>`) for all containerized plugin executions while preserving host filesystem paths for mock and local subprocess execution. Added defense-in-depth template resolution in `build_container_argv`.
   - **Defect Closed:** Containerized forensic tools running in Linux environments no longer fail with "file not found" errors when executed on Windows or external hosts.

4. **Remediation of DEFECT-FOR-01 (Dissect Adapter Stream Method Aliases):**
   - **File:** `backend/app/core/dissect_adapter.py`
   - **Forensic Fix:** Added backward-compatible method aliases `parse_evtx_stream = parse_evtx` and `parse_registry_hive_stream = parse_registry_hive` on `DissectAdapter`.
   - **Defect Closed:** Resolved silent `AttributeError` exceptions in `WindowsDFIRSpecialist` (lines 217, 276) and `InvestigationController` (lines 806, 808), restoring full parsing of Windows EVTX logs and Registry hives.

5. **Remediation of DEF-QA-001 (Autonomous Investigation REST API Test Suite):**
   - **Files:** `backend/tests/test_api_investigations.py`, `backend/app/api/investigations.py`
   - **QA Assurance:** Authoring of a comprehensive 7-test integration suite covering all 7 endpoints of `/api/investigations/*` (`/start`, `/{case_id}`, `/{case_id}/iterate`, `/{case_id}/resume`, `/{case_id}/cancel`, `/{case_id}/specialists`, `/{case_id}/tool-history`).
   - **Controls Verified:** Anonymous 401 rejection, auditor 403 mutation block / 200 audit read, foreign lead 403 case isolation, HMAC approval token pause and resumption lifecycle, and bounded autorun. Fixed specialist attribute mapping in the router.

### Test Verification & Quality Metrics:
- **Dedicated Security Regression Suite:** `backend/tests/test_phase12_security_fixes.py` (5 passed in 0.52s).
- **Dedicated Investigation REST API Suite:** `backend/tests/test_api_investigations.py` (7 passed in 6.61s).
- **Specialist Capabilities Suite:** `backend/tests/test_phase07_specialist_capabilities.py` (11 passed, including new stream alias regression assertions).
- **Full Backend Test Suite:** **318 / 318 PASSED** (100% green in 310.15s across 31 test modules).
- **Frontend Production Build:** **0 errors, 0 warnings** (built in 468ms).

---

## 2. Executive Implementation Summary — Phase 11

Phase 11 completed the operational user experience, deployment hardening, and full system integration acceptance across all forensic tiers. The platform now operates as a single, coherent, production-ready controlled-autonomy digital forensics investigation system.

The frontend experience was hardened and unified through the `InvestigationView` dashboard and dedicated backend REST APIs (`/api/investigations/*`), exposing real-time state machine progression (`created` -> `evidence_validation` -> `planning` -> `executing` -> `evaluating` -> `awaiting_approval` -> `completed`), step-by-step specialist activity, tool execution history, evidence gaps, competing hypotheses, verified findings previews, and integrated human approval gates.

Browser-side security was hardened to eliminate forensic data leakage: persistent `localStorage` token storage was completely eliminated in favor of ephemeral `sessionStorage` and in-memory React state, with active `localStorage` purging upon authentication lifecycle transitions and zero browser disk caching of raw evidence or finding payloads.

Production deployment controls were established and verified: server bindings strictly default to loopback (`127.0.0.1`), requiring explicit affirmative operator opt-in (`FORENSICOPS_ALLOW_EXTERNAL=true`) before binding to external interfaces. Production environments fail closed if default HMAC or JWT secrets are detected. Logging pipelines enforce `SecretRedactingFilter` to scrub credentials, passwords, Bearer tokens, and SIEM API keys. Maintenance primitives (`backup_database`, `verify_and_restore_backup`, `cleanup_temporary_staging`) provide crash-consistent SQLite backup/restore and automated extraction staging retention. Liveness (`/health/live`), readiness (`/health/ready`), and diagnostic (`/health`, `/api/health`) endpoints provide continuous health monitoring.

A full 15-step end-to-end integration acceptance test suite was implemented and verified, validating the entire investigation lifecycle from authentication through dual-hash verification, autonomous controller planning, approval pauses, cryptographically signed human authorization, cited report generation via `CitationGuard`, report finalization and signing, and append-only hash-chained custody ledger integrity.

### Key Accomplishments in Phase 11:
1. **Autonomous Investigation Interface (`frontend/src/components/InvestigationView.tsx`):**
   - Implemented interactive investigation interface: case selection, investigation objective input, execution budget progress meters, active lifecycle state badges (`created`, `evidence_validation`, `planning`, `executing`, `evaluating`, `awaiting_approval`, `needs_more_data`, `completed`, `partially_completed`, `failed`, `cancelled`).
   - Integrated live views for:
     - 6 Modular DFIR Specialists with operational status, limitations, and tool requirements.
     - Competing Hypotheses with support/refute confidence metrics and cited finding references.
     - Evidence Gaps with collection recommendations and non-invention distinction (missing data vs evidence of absence).
     - Tool Execution History table detailing tool IDs, execution IDs, finding counts, raw output references, and execution errors.
     - Verified Findings preview table with category, event ID, host, user, and artifact hash badges.
     - Human Approval Gate prompt allowing direct review of sensitive tool requests (target host, operation, justification, parameter digest) and one-click cryptographic authorization.
2. **Investigation Controller REST API (`backend/app/api/investigations.py`):**
   - Implemented authenticated endpoints:
     - `POST /api/investigations/start`: Initializes autonomous investigation controller with typed objective, evidence scope, and execution budgets.
     - `GET /api/investigations/{case_id}`: Retrieves current `InvestigationRecord` state.
     - `POST /api/investigations/{case_id}/iterate`: Executes a single bounded loop iteration.
     - `POST /api/investigations/{case_id}/resume`: Resumes paused investigation with signed `HumanApprovalToken`.
     - `POST /api/investigations/{case_id}/cancel`: Safely cancels active investigation with audit logging.
     - `GET /api/investigations/{case_id}/specialists`: Discovers operational and non-operational specialist capabilities.
     - `GET /api/investigations/{case_id}/tool-history`: Returns complete deterministic execution history.
3. **Frontend Security Hardening & Zero-LocalStorage Leakage:**
   - Modified `frontend/src/services/api.ts` to strictly read authentication tokens from `sessionStorage.getItem("forensicops_token")`, removing fallback to `localStorage`.
   - Updated `frontend/src/context/AuthContext.tsx` to explicitly execute `localStorage.removeItem("forensicops_token")` on login, logout, and token refresh.
   - Enforced that sensitive case findings, evidence blobs, and investigation notes are stored solely in ephemeral component memory.
4. **Structured Logging & Secret Redaction (`backend/app/core/logging_config.py`):**
   - Implemented `SecretRedactingFilter` and `setup_structured_logging()`.
   - Formats log entries as JSON in production with automatic scrubbing of passwords, tokens, API keys, Bearer headers, and Authorization headers.
5. **Deployment Hardening & Configuration Validation (`backend/app/core/config.py`):**
   - Implemented `validate_production_configuration()`:
     - Enforces loopback binding (`127.0.0.1` / `localhost` / `::1`) by default; non-loopback addresses fail startup unless `FORENSICOPS_ALLOW_EXTERNAL=true` is set.
     - Validates production secrets: rejects default or weak values for `HUMAN_APPROVAL_HMAC_SECRET` and requires `JWT_SECRET_KEY` length >= 32 characters in production.
6. **Database Maintenance, Backup & Retention (`backend/app/core/maintenance.py`):**
   - Implemented `backup_database()`: performs crash-consistent online SQLite backup via `conn.backup()` and computes SHA-256 backup digest.
   - Implemented `verify_and_restore_backup()`: cryptographically verifies backup digest, performs atomic staging restoration, and checks SQLite `PRAGMA integrity_check`.
   - Implemented `cleanup_temporary_staging()`: safely identifies and purges expired extraction staging directories older than configurable threshold (default 24 hours).
   - Implemented `get_health_metrics()`: verifies vault directory existence, read/write permissions, database connectivity, and table status.
7. **Production Health & Probe Endpoints (`backend/app/main.py`):**
   - Added `/health` and `/api/health`: service identification and status.
   - Added `/health/live`: lightweight liveness probe for container orchestrators.
   - Added `/health/ready`: comprehensive readiness probe reporting vault writability, database accessibility, and degraded service HTTP 503 response.
8. **End-to-End Acceptance Test Suite (`backend/tests/test_phase11_full_system_acceptance.py`):**
   - 6 comprehensive tests validating:
     - Liveness, readiness, and system health checks (`test_health_checks_and_probes`).
     - Crash-consistent SQLite online backup, hash verification, and atomic restoration (`test_sqlite_online_backup_and_recovery`).
     - Temporary extraction staging retention and cleanup (`test_staging_cleanup_retention`).
     - Loopback binding enforcement and weak secret rejection (`test_secure_configuration_validation`).
     - Structured logging secret sanitization (`test_secret_redacting_logging_filter`).
     - Full 15-step operational investigation path (`test_full_system_acceptance_lifecycle`): Authenticate -> Open Case -> Upload Evidence -> Dual-Hash Verification -> Deterministic Analyzer -> Finding Persistence -> Autonomous Controller -> Safe Iterations -> Hypotheses/Correlations/Gaps -> Approval Pause -> Cryptographic Human Authorization -> Resume -> Cited Report via CitationGuard -> Report Finalization & Signing -> Hash-Chained Custody Ledger & Execution History Integrity.
   - Test results: **6 / 6 PASSED**.
   - Entire test suite: **305 / 305 PASSED (100% green)**.
   - Frontend build: **0 errors, 0 warnings (built in 398ms)**.

---

## 2. Executive Implementation Summary — Phase 10

Phase 10 integrated approved remote acquisition (Windows `Invoke-ForensicCollector.ps1` and Linux `collect_linux_triage.sh`) and read-only SIEM query connectors (Elasticsearch, Wazuh, and Splunk) into the unified forensic evidence and custody lifecycle without creating a separate evidence store or bypassing central security policies. Strict SSRF defense blocks loopback addresses, cloud metadata endpoints (`169.254.169.254`), and unapproved RFC 1918 private networks unless explicitly authorized in the target allowlist. Pre-flight DNS resolution prevents DNS rebinding attacks, and HTTP clients disable automatic redirects (`follow_redirects=False`) to prevent open-redirect pivoting. Online endpoint collection requires an authenticated investigator, authorized target scope, and a cryptographically signed, operation-specific Phase 08 `HumanApprovalToken` bound to case ID, target host, and parameter digest. Retrieved capsules are unpacked, verified against manifest dual-hashes (SHA-256 and SHA-512), vaulted defanged, and recorded in the append-only hash-chained custody ledger. Read-only SIEM connectors reject all mutating operations, compute canonical SHA-256 query snapshot hashes, and normalize telemetry hits into `ForensicFinding` records verifiable by `CitationGuard`. Zero credentials, tokens, or private keys are leaked in logs, stdout/stderr, or exception traces.

### Key Accomplishments in Phase 10:
1. **SSRF and Destination Defense Engine (`backend/app/core/network_validator.py`):**
   - Implemented `resolve_and_validate_destination()`, `is_ip_prohibited()`, and `validate_url_ssrf()`.
   - Strictly blocks loopback (`127.0.0.0/8`, `localhost`, `::1`), link-local/cloud metadata (`169.254.169.254`, `169.254.0.0/16`, `fe80::/10`, `metadata.google.internal`), and unapproved RFC 1918 private address ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`).
   - Resolves all destination IP addresses via DNS pre-flight to prevent DNS rebinding.
   - Enforces target allowlists (exact host, IP, or CIDR).
   - Rejects URLs with embedded user credentials (`user:pass@host`) and non-HTTP/HTTPS schemes.

2. **Credential Redaction & Zero Secret Leakage:**
   - Implemented `sanitize_credentials()` to scrub passwords, tokens, API keys, Bearer headers, and custom secret keys from logs, execution results, error strings, and exception tracebacks.
   - Verified that sensitive passwords on target endpoints or SIEM connectors never appear in stdout, stderr, exception messages, or custody entries.

3. **Operation-Specific Human Approval Gate for Online Actions:**
   - Hardened `OnlineCollectorOrchestrator.verify_approval_gate()`:
     - Enforces non-negotiable Rule 4: requires a cryptographically valid `HumanApprovalToken`.
     - Rejects expired tokens and prevents replay attacks via one-time token consumption (`consumed = True` and persistent recording in `ApprovalEngine`).
     - Verifies operation-specific binding: `action_type in ("remote_collection", "remote_endpoint_collection", "remote_access")`; tokens for other actions (e.g. `report_signing`, `deletion`) are rejected.
     - Enforces target host binding: `token.target == target.host`.
     - Enforces parameter digest binding: compares `token.parameter_digest` against deterministic target parameter digest (`compute_target_parameter_digest(target)`).

4. **Pre-Approved Collector Scripts & Zero Shell Interpolation:**
   - `resolve_collector_script()` strictly locates and verifies SHA-256 hashes of pre-approved scripts (`collectors/linux/collect_linux_triage.sh` and `collectors/windows/Invoke-ForensicCollector.ps1`). Unapproved or custom scripts are strictly rejected.
   - `build_collector_command()` constructs structured argv arrays with zero shell interpolation or command concatenation.

5. **Direct Custody Pipeline Ingestion (No Parallel Evidence Store):**
   - Streamlined remote capsule retrieval: downloaded capsule archives are fed directly to `CustodyEngine.unpack_collector_capsule()`.
   - Validates internal `manifest.json`, validates dual SHA-256 and SHA-512 hashes for all artifacts, vaults files defanged (0400 permissions, stripped executable extensions), and records `DISPATCH_ONLINE_COLLECTOR`, `INTAKE_CAPSULE`, `INTAKE_CAPSULE_ARTIFACT`, and `ONLINE_CAPSULE_INGESTED` in the immutable hash-chained custody ledger.
   - Safely removes temporary download staging files.

6. **Read-Only SIEM Query Adapters with Canonical Snapshot Hashing (`backend/app/connectors/siem_connectors.py`):**
   - **Elasticsearch Adapter:** Validates read-only queries against `MUTATING_ES_TERMS`, sends queries to `/_search`, normalizes hits into `ForensicFinding` (ECS timestamp, winlog event ID, severity, host, user, process), and computes canonical SHA-256 snapshot hashes.
   - **Wazuh Adapter:** Validates read-only queries against `MUTATING_WAZUH_TERMS`, queries `/alerts`, normalizes alert items into `ForensicFinding` with MITRE ATT&CK mapping, and computes canonical SHA-256 snapshot hashes.
   - **Splunk Adapter:** Validates read-only SPL against `MUTATING_SPLUNK_COMMANDS`, queries streaming JSON export endpoint, normalizes into `ForensicFinding`, and computes canonical SHA-256 snapshot hashes.
   - All SIEM HTTP clients configure `follow_redirects = False` to prevent redirect-based SSRF.
   - Recorded `INGEST_SIEM_QUERY_SNAPSHOT` in the custody chain and indexed into DuckDB `ForensicStore`.

7. **End-to-End Citation Verification:**
   - Verified that claims citing SIEM-ingested findings pass `CitationGuard` verification using the query snapshot hash.

8. **Comprehensive Regression Test Suite (`backend/tests/test_phase10_siem_and_live_endpoints.py`):**
   - 20 dedicated tests covering SSRF loopback/metadata/private network blocking, allowlist matching, credential scrubbing in logs/errors, approval token gate checks (expiration, replay, action type mismatch, target mismatch, parameter tampering), collector script integrity, capsule ingestion into custody ledger, read-only SIEM queries, snapshot hashing, mutation query rejection, and open redirect defense.
   - Test results: **20 / 20 PASSED**.
   - Entire repository test suite: **299 / 299 PASSED (100% green in 309.29s)**.
   - Frontend production build: **0 errors, 0 warnings (built in 396ms)**.

---

## 2. Executive Implementation Summary — Phase 09

Phase 09 established a defensible forensic timeline, deterministic correlation records, evidence conflict handling, and an authorization-gated reporting engine. The system constructs chronological forensic timelines from verified findings without inventing timestamps or silently assuming UTC for naive timestamps. Correlations are captured in structured relationship records with explicit entity bindings, temporal windows, supporting/conflicting observations, and limitations. Naive Patient Zero inference was eliminated in favor of bounded evidential requirements. Contradictory evidence (causality inversions, conflicting usernames, missing artifacts) is preserved and exposed without suppression. Independent citation validation is enforced prior to report assembly, custody verification fails closed when corrupted or absent, and final report signing is strictly gated by Phase 08 cryptographic human approval tokens.

### Key Accomplishments in Phase 09:
1. **Evidence-Backed Timeline with Provenance & Precision (`backend/app/agent/report_builder.py`):**
   - Implemented `parse_forensic_timestamp()` and enhanced `TimelineEntry`: preserves `original_timestamp`, `original_timezone`, `timezone_status` (`EXPLICIT_UTC`, `EXPLICIT_OFFSET`, `UNKNOWN_AMBIGUOUS`, `NO_TIMESTAMP`), `normalized_timestamp_utc`, `timestamp_source` (`evtx_TimeCreated`, `packet_capture_header`, `registry_key_lastwritten`, `volatility_pslist_createtime`, `file_mtime_or_mft`), `timestamp_precision` (`100ns`, `microseconds`, `milliseconds`, `seconds`), and `clock_uncertainty`.
   - Strictly enforced non-invention of timestamps and no silent assumption of UTC for naive/unverified timestamps.

2. **Deterministic Correlation Engine (`DeterministicCorrelationRecord`):**
   - Implemented structured correlation records binding `correlation_id`, `case_id`, `relationship_type`, `source_finding_ids`, `source_artifact_hashes`, `entity_identifiers`, `correlation_method`, `supporting_observations`, `conflicting_observations`, `time_window` (with start, end, duration), and `limitations`.
   - Rendered in Section 4 of master reports with full entity and telemetry details.

3. **Bounded Patient Zero Assessment:**
   - Prohibited naive Patient Zero inference based solely on earliest available event.
   - Evaluates explicit initial compromise indicators (phishing, macro execution, web shell, external ingress, exploit).
   - If earliest event is an internal process without initial access telemetry, explicitly marks `patient_zero_status = "UNDETERMINED_INSUFFICIENT_EVIDENCE"`, sets `patient_zero_host = None`, and logs explicit data gaps.

4. **Evidence Conflict Detection Without Suppression (`EvidenceConflict`):**
   - Implemented `ReportBuilder.detect_evidence_conflicts()`: detects causality inversions (future timestamps, process execution preceding logon), conflicting usernames on identical processes/timestamps, conflicting host/IP mappings, duplicate observations, missing artifacts, and telemetry gaps > 24 hours.
   - Contradictory evidence is preserved and rendered in the master report and visual UI.

5. **Independent Citation Enforcement:**
   - Independent verification via `CitationGuard` prior to report assembly.
   - In non-strict mode, unverified or fabricated claims are suppressed from verified facts/correlations, quarantined in `rejected_claims`, and recorded as conflict records; in strict mode, raises `CitationValidationError`.

6. **Custody Verification Fail-Closed Integrity:**
   - Chain of custody verification never defaults to True (`tamper_check_passed` defaults to False).
   - If `custody_engine` is absent: report marked `status = "incomplete"`.
   - If custody ledger is corrupted: report marked `status = "blocked"` and exact discrepancies exposed.

7. **Report Finalization & Phase 08 Human Approval Gate:**
   - Autonomous generation produces `draft` versions with incrementing version numbers.
   - Final approval or signing requires a valid Phase 08 `HumanApprovalToken` (`action_type = "report_finalization_or_signing"`) signed by `lead_investigator` or `soc_analyst`.
   - Computes deterministic canonical report digest (`sha256:...`), consumes the approval token (replay protection), and appends `REPORT_FINALIZED_AND_SIGNED` to the hash-chained custody ledger.

8. **Thread-Safe SQLite Report Store & REST API (`backend/app/api/reports.py`):**
   - Implemented `ReportStore` managing draft history, provenance, versions, and digests in SQLite table `forensic_reports`.
   - Endpoints: `GET /api/reports/{case_id}`, `POST /api/reports/compile`, `POST /api/reports/{report_id}/finalize`, and `GET /api/reports/{case_id}/history`.

9. **Frontend Visual Report Enhancements (`frontend/src/`):**
   - Updated TypeScript interfaces (`frontend/src/types/index.ts`) and API client (`frontend/src/services/api.ts`).
   - `CitedReportViewer.tsx`: Displays report status badge (`DRAFT`, `SIGNED`, `BLOCKED`, `INCOMPLETE`), preserved evidence conflicts warning block, custody discrepancies, and bounded Patient Zero evidentiary basis.

10. **Comprehensive Regression Test Suite (`backend/tests/test_phase09_reporting_engine.py`):**
    - 11 dedicated regression tests covering timeline provenance, unknown timezones, deterministic correlations, bounded Patient Zero, conflict detection, missing artifacts, citation enforcement, custody fail-closed, Phase 08 human approval finalization, report reproducibility, and full REST API lifecycle.
    - Test results: **11 / 11 PASSED**.
    - Entire repository test suite: **279 / 279 PASSED (100% green in 36.37s)**.
    - Frontend production build: **0 errors, 0 warnings (built in 396ms)**.

---

## 2. Executive Implementation Summary — Phase 08

Phase 08 established deterministic human control over sensitive and destructive forensic operations (remote collection, remote access, network access, containment, deletion, external sharing, and report finalization) in accordance with AGENTS.md Rules 6 & 7, RFC 3227, and ISO/IEC 27037. The central action risk policy deterministically classifies all capabilities into explicit risk levels, preventing execution of sensitive actions without a cryptographically bound, one-time HMAC-SHA256 human approval token. Agent self-approval is strictly prohibited, dual-control validation is enforced, and all approval lifecycle events are immutably recorded in the forensic custody chain.

### Key Accomplishments in Phase 08:
1. **Central Deterministic Action Risk Policy (`backend/app/core/action_risk_policy.py`):**
   - Implemented `ActionRiskPolicy` and `ActionRiskLevel` (`AUTOMATIC_OFFLINE_ALLOWED`, `EXPLICITLY_DENIED`, `REQUIRES_HUMAN_APPROVAL`, `UNKNOWN_BLOCKED`).
   - Classifies capabilities into typed `ActionType` (`read_only_offline_analysis`, `local_evidence_modification`, `remote_endpoint_collection`, `remote_endpoint_access`, `external_network_access`, `host_containment_or_remediation`, `evidence_deletion`, `external_evidence_sharing`, `report_finalization_or_signing`, `unknown`).
   - Allowlist: pure-Python analyzers and sandboxed offline tools (`dissect_*`, `chainsaw_sigma`, `yara_scanner`, etc.) execute automatically.
   - Denylist: local evidence modification and dynamic malware detonation are blocked unconditionally (`denied_by_default`).
   - Sensitive operations (remote collection, SSH, containment, deletion, report finalization) require explicit human approval. Unknown actions are blocked by default.

2. **Operation-Specific Approval Requests & Canonical Digest (`backend/app/models/approval.py`):**
   - Implemented `ApprovalRequest` model binding: `approval_id`, `case_id`, `requesting_investigator`, `action_type`, `target`, `capability_id`, `parameter_digest`, `policy_version`, `status`, `created_utc`, `expires_utc`, and reason.
   - Deterministic parameter hashing: `compute_parameter_digest()` canonicalizes parameters (`json.dumps(params, sort_keys=True)`) and outputs `sha256:<64-char-hex>`. Any change to parameters or targets invalidates the approval request.

3. **Tamper-Evident HMAC-SHA256 Approval Tokens & Replay Protection (`backend/app/models/workflow.py`):**
   - Hardened `HumanApprovalToken` to bind `token_id`, `approval_id`, `case_id`, `approved_by`, `role`, `action_type`, `target`, `capability_id`, `parameter_digest`, `issued_utc`, `expires_utc`, `signature`, and `consumed`.
   - Cryptographic signing: `calculate_signature(secret_key)` computes `HMAC-SHA256(secret_key, canonical_payload)`. Strict secret validation: empty, default, or weak fallback secrets raise `ValueError`.
   - Standalone `is_expired()` check and atomic replay protection: token verification rejects consumed, expired, or tampered tokens with `ForensicOpsError`.

4. **Approval Lifecycle & Dual-Control Engine (`backend/app/core/approval_engine.py`):**
   - Full lifecycle state machine: `pending` -> `approved` / `rejected` / `expired` / `revoked` / `consumed`.
   - Prevent Agent Self-Approval & Dual Control: Requests where `requesting_investigator == approver.username` or where `approver.username` begins with `agent` / `ai_planner` are rejected with `HTTP 403 Forbidden`. Only authorized roles (`lead_investigator`, `soc_analyst`) may approve requests.
   - Persistent storage: SQLite-backed storage in `LLMStateStore` for requests and persistent `consumed_approval_tokens` table for bulletproof replay prevention across process restarts.
   - Audit logging: Every approval lifecycle event (created, approved, rejected, revoked, consumed) is immutably recorded in the case's hash-chained custody ledger via `CustodyEngine`.

5. **Autonomous Controller & Tool Execution Integration (`backend/app/agent/investigation_controller.py`):**
   - Integrated `ApprovalEngine` into `InvestigationController`.
   - Pre-execution validation in `validate_tool_request` checks action risk policy. When a requested action requires human approval, the controller automatically creates an `ApprovalRequest` and pauses execution in `awaiting_approval`.
   - Resumption gate: Calling `controller.resume(case_id, approval_token=token)` strictly validates token integrity, verifies exact parameter digest and target matching, marks the token consumed in the engine, transitions action status to `approved`, and continues autonomous execution.

6. **Target-Bound Remote SSH Collector Gate (`backend/app/connectors/ssh_collector.py`):**
   - Enhanced `verify_approval_gate` to verify that `token.target` explicitly matches `target_host` alongside case ID, action type (`remote_endpoint_collection`), and cryptographic signature.

7. **REST API Endpoints with Case-Level RBAC (`backend/app/api/approvals.py`):**
   - Implemented dependency-injected FastAPI routes: `POST /api/approvals/requests`, `GET /api/approvals`, `GET /api/approvals/{id}`, `POST /api/approvals/{id}/approve`, `POST /api/approvals/{id}/reject`, and `POST /api/approvals/{id}/revoke`.
   - Enforces case membership via `CaseAuthorizationService` and role validation via `require_roles`.

8. **Frontend Review Modal & Visual Controls (`frontend/src/`):**
   - `ApprovalReviewModal.tsx`: Displays risk level badge, target host/endpoint, capability ID, canonical parameter digest, expiration countdown, dual-control warning, and structured JSON parameters with explicit Approve and Reject buttons.
   - Integrated into `WorkflowCanvas.tsx` replacing legacy approval dialogs.
   - Updated TypeScript interfaces (`frontend/src/types/index.ts`) and API client (`frontend/src/services/api.ts`).

9. **Comprehensive Regression Test Suite (`backend/tests/test_phase08_human_approval_engine.py`):**
   - 14 tests verifying action risk classification, canonical parameter digest stability, HMAC signing, tamper detection, expiration, replay protection, self-approval prevention, auditor approval rejection, atomic token consumption, controller pause/resume gate, SSH collector target matching, REST API lifecycle, and custody audit ledger recording.
   - Test results: **14 / 14 PASSED**.
   - Entire test suite: **268 / 268 PASSED (100% green in 39.04s)**.
   - Frontend production build: **0 errors, 0 warnings (built in 429ms)**.

---

## 2. Executive Implementation Summary — Phase 07

Phase 07 introduced Level 3 modular DFIR specialization without creating an uncontrolled collection of autonomous agents. The six specialist modules are typed, bounded capability units governed by the central `InvestigationController`. Each specialist defines its domain objective, evidence requirements, tool allowlists, typed inputs/outputs, investigation questions, domain limitations, and citation requirements. In accordance with strict DFIR architectural principles, truth in advertising is enforced: only capabilities with genuinely implemented, tested analyzers are advertised as operational; unimplemented capabilities (e.g. Amcache, Shimcache, Prefetch, Zeek HTTP reassembly, dynamic execution) are flagged non-operational and generate evidence gaps. Furthermore, dynamic malware detonation is strictly prohibited in normal forensic workers.

### Key Accomplishments in Phase 07:
1. **Base Specialist Contract & Domain Models (`backend/app/models/specialists.py`):**
   - Implemented `BaseDFIRSpecialist` abstract base class with common interface: `specialist_id`, `name`, `domain`, `description`, `supported_artifact_types`, `tool_allowlist`, `capabilities`, `investigation_questions`, `limitations`, `citation_requirements`, and `execute()`.
   - Defined `SpecialistCapabilityDefinition` tracking `operational: bool`, `required_artifact_types`, `required_tools`, and `limitations`.
   - Defined `CorrelationRelationship` recording `relationship_type` (`user_to_process`, `process_to_network`, `host_to_host`, `authentication_to_execution`, `persistence_to_execution`, `cross_source_event`), source observation IDs, target observation IDs, bounded confidence scores, deterministic method, and timestamps.
   - Defined `SpecialistResult` capturing findings, correlations, evidence gaps, pivots, raw outputs, errors, and unsupported requested capabilities.

2. **Specialist 1: Windows DFIR (`backend/app/specialists/windows_dfir.py`):**
   - Operational capabilities: `windows_event_logs` (Dissect EVTX / EvtxECmd), `windows_sysmon` (Chainsaw Sigma), `windows_registry` (Dissect Registry / RECmd), `windows_powershell` (EVTX Event ID 4104), `windows_lateral_movement` (EVTX Logon Types 3 and 10).
   - Non-operational capabilities: `windows_amcache`, `windows_shimcache`, `windows_prefetch`, `windows_scheduled_tasks` (flagged non-operational with explicit tool deployment requirements).
   - Enriches findings with lateral movement and PowerShell categories; records missing EVTX or hives as evidence gaps.

3. **Specialist 2: Linux DFIR (`backend/app/specialists/linux_dfir.py`):**
   - Operational capabilities: `linux_auth_logs` (/var/log/auth.log, /var/log/secure), `linux_ssh_activity` (accepted/failed SSH logins with user extraction), `linux_sudo_privilege` (sudo commands), `linux_cron_persistence` (cron jobs), `linux_shell_history` (.bash_history/.zsh_history).
   - Non-operational capabilities: `linux_systemd_services`, `linux_auditd_records` (flagged pending future parser integration).
   - Citations: Enforces exact line number citations in `raw_reference` (`line_1`, `line_2`, etc.) and SHA-256 source hash recording.

4. **Specialist 3: Memory Forensics (`backend/app/specialists/memory_forensics.py`):**
   - Operational capability: `memory_process_listing` (sandboxed Volatility 3 `volatility3_pslist`).
   - Non-operational capabilities: `memory_process_tree`, `memory_network_connections`, `memory_loaded_modules`, `memory_injection_indicators`, `memory_command_line` (flagged non-operational until respective Volatility 3 plugins are integrated).
   - Fail-closed guarantee: Never assumes success merely because a YAML card exists; honestly reports container sandbox unavailability or missing symbol tables without inventing facts.

5. **Specialist 4: Network Forensics (`backend/app/specialists/network_forensics.py`):**
   - Operational capabilities: `pcap_flow_analysis` (pure-Python deterministic PCAP stream parser), `beaconing_detection` (statistical inter-arrival interval analysis detecting C2 beacon periodicity with std-dev variance thresholds), `suspicious_destination_detection` (identifying RAT ports e.g. TeamViewer 5938/5939, RDP 3389), `host_communication_relationships` (source-destination endpoint graphs).
   - Non-operational capabilities: `dns_query_extraction`, `http_session_reconstruction`, `tls_metadata_extraction` (Zeek / Tshark deep inspection pending container deployment).
   - Generates typed `CorrelationRelationship` records of types `process_to_network` and `host_to_host`.

6. **Specialist 5: Malware Analysis (`backend/app/specialists/malware_analysis.py`):**
   - Operational capabilities: `static_file_hashes` (MD5, SHA-1, SHA-256), `static_file_metadata` (size, magic bytes, timestamps), `static_pe_metadata` (MZ/PE headers, machine type x86/x64, section count, compile timestamp), `static_strings_extraction` (embedded URLs and IPv4 addresses), `yara_signature_scan` (YARA scanner plugin).
   - STRICT SAFETY RESTRICTION: `dynamic_sandbox_execution` is strictly non-operational and prohibited. Any attempt to dynamically detonate unknown malware in normal forensic workers raises `ExecutionPolicyError`.

7. **Specialist 6: Timeline & Multi-Observation Correlation (`backend/app/specialists/timeline_correlation.py`):**
   - Operational capabilities: `user_to_process_correlation`, `process_to_network_correlation`, `host_to_host_correlation`, `authentication_to_execution_correlation`, `persistence_to_execution_correlation`, `cross_source_event_correlation`.
   - Deterministic temporal windowing: correlates logons followed by process executions within 120s, process creation followed by outbound network traffic within 60s, persistence artifacts matching executing process names, and cross-source telemetry matching shared users or IPs.
   - Every correlation records source finding IDs, target finding IDs, calculated confidence score (0.70 - 0.95), and deterministic matching method.

8. **Central Specialist Registry (`backend/app/core/specialist_registry.py`):**
   - Implemented `SpecialistRegistry` singleton managing all 6 specialists.
   - Dynamic discovery methods: `discover_for_evidence(artifact_types)` and `discover_for_objective(objective)`.
   - Filter methods: `list_all_capabilities()` and `list_operational_capabilities()` enforcing truth in advertising.

9. **InvestigationController Integration (`backend/app/agent/investigation_controller.py`):**
   - Integrated `SpecialistRegistry` into `InvestigationController`.
   - Initial planning maps Linux logs, PCAPs, malware samples, and memory dumps to operational capabilities.
   - Tool-request validation rejects dynamic malware detonation and non-operational capabilities with explanatory policy errors.
   - The autonomous evaluation loop automatically invokes `TimelineCorrelationSpecialist` over all empirical findings and persists discovered `CorrelationRelationship` records in `InvestigationRecord.correlations`.

10. **Regression Test Suite (`backend/tests/test_phase07_specialist_capabilities.py`):**
    - 10 comprehensive regression tests verifying registration of all 6 specialists, dynamic discovery, truth-in-advertising capability filtering, Windows EVTX/Registry execution, Linux auth.log line citations, Memory fail-closed safety, Network C2 beaconing interval analysis, safe static PE extraction, strict dynamic malware detonation refusal, deterministic multi-observation correlation, and end-to-end controller execution.
    - Test results: **10 / 10 PASSED**.
    - Entire test suite: **254 / 254 PASSED (100% green in 26.27s)**.
    - Frontend production build: **0 errors, 0 warnings (built in 389ms)**.

---

## 2. Executive Implementation Summary — Phase 06

Phase 06 evolved the ForensicOps AI workflow engine into a persistent, bounded, and iterative `InvestigationController`. The controller implements an explicit 11-state lifecycle state machine, formulates competing forensic hypotheses, tracks evidence gaps (distinguishing missing data from evidence of absence), executes safe deterministic tools under strict resource budgets, pauses for human authorization when sensitive operations arise, persists full state and execution telemetry into SQLite, and supports seamless recovery after system restarts.

### Key Accomplishments in Phase 06:
1. **Explicit Investigation Lifecycle State Machine (`backend/app/models/investigation.py`):**
   - Implemented `InvestigationLifecycleState`: `created`, `evidence_validation`, `planning`, `executing`, `evaluating`, `awaiting_approval`, `needs_more_data`, `completed`, `partially_completed`, `failed`, `cancelled`.
   - Formalized `VALID_TRANSITIONS` and `validate_lifecycle_transition`; all illegal state transitions are strictly blocked with `InvalidStateTransitionError`.
2. **Autonomous Investigation Controller (`backend/app/agent/investigation_controller.py`):**
   - Implemented `InvestigationController` receiving case ID, investigator identity, objective, authorized evidence scope, available capabilities, and finite budgets.
   - Orchestrates the iterative cycle: Goal Comprehension -> Evidence Inspection -> Evidence Gap Tracking -> Competing Hypotheses -> Capability Selection -> Policy Validation -> Safe Execution -> Finding Evaluation -> Pivot Updates -> Hypothesis Testing -> Continuation/Conclusion.
3. **Competing Hypotheses & Evidence Gap Tracking:**
   - Automatically generates competing hypotheses: Malicious Intrusion hypothesis vs. Benign Administrative Null hypothesis.
   - Evaluates supporting vs. contradicting findings, recalculates confidence scores, and increments hypothesis versioning.
   - Tracks `EvidenceGap` objects, explicitly distinguishing missing uncollected artifacts from evidence of absence in examined evidence.
4. **Typed LLM Tool-Request Contract:**
   - Implemented `ToolRequest` contract; validates capability ID against `AnalyzerRegistry` and `ExecutionPolicyRegistry`.
   - Strictly verifies that requested artifacts exist within the case vault and fall inside `authorized_evidence_scope`.
   - Prohibits arbitrary shell commands, enforcing typed parameters and allowlisted forensic containers.
5. **Configurable Execution Budgets:**
   - Implemented `InvestigationBudget`: `max_iterations`, `max_tool_executions`, `per_tool_timeout_seconds`, `max_total_execution_seconds`, `max_findings_per_step`, `max_context_tokens`, `max_retries_per_step`.
   - Budget exhaustion cleanly halts execution and transitions the investigation to `partially_completed`.
6. **Persistence & Restart Recovery (`backend/app/db/sqlite_store.py`):**
   - Added tables `investigation_states` and `investigation_traces` to SQLite `LLMStateStore`.
   - Serializes complete investigation records including objectives, plans, pivots, hypotheses, evidence gaps, completed actions, pending actions, and execution IDs.
   - `resume()` reloads the persisted state from SQLite and continues execution from the exact paused or interrupted point without duplicating completed actions.
7. **Human Approval Gate Integration:**
   - High-risk, containment, or external operations automatically pause the controller in `awaiting_approval`.
   - Verified resumption requires a cryptographically signed HMAC-SHA256 `HumanApprovalToken`. Forged or missing tokens are rejected with `ForensicOpsError`.
8. **Human Feedback Integration & Benign Suppression:**
   - Injected `KnowledgeAndMemoryProvider` into the controller.
   - Suppresses organizational false-positive baselines (e.g. backup accounts, monitoring agents) from pivot escalation without mutating or deleting raw forensic facts in DuckDB or the custody ledger.
9. **Full Step Traceability:**
   - Every iteration logs an `InvestigationStepTrace` into SQLite containing inputs, outputs, executed queries, cited finding IDs, tool telemetry, duration, and status.
10. **Regression Test Suite (`backend/tests/test_phase06_autonomous_controller.py`):**
    - 15 comprehensive tests covering state machine transitions, end-to-end autonomous loops, evidence gap tracking, competing hypotheses versioning, tool-request validation, budget exhaustion, approval gates, restart recovery, benign baseline suppression, and execution trace persistence.
    - Test results: **15 / 15 PASSED**.
    - Entire test suite: **244 / 244 PASSED (100% green in 27.37s)**.
    - Frontend production build: **0 errors, 0 warnings (built in 435ms)**.

---

## 2. Executive Implementation Summary — Phase 05

Phase 05 connected actual forensic analyzers to the ForensicOps AI investigative workflow, permanently retiring the passive mock behavior where parser and tool runner nodes only retrieved pre-existing findings from DuckDB. The workflow now resolves authorized case vault artifacts, validates their cryptographic hashes against the custody ledger, executes deterministic analyzers (pure-Python Dissect in Tier A, container-sandboxed external tools in Tier B), normalizes outputs into provenance-backed `ForensicFinding` records with `tool_version`, persists them into DuckDB, and records immutable execution provenance with deterministic idempotency keys.

### Key Accomplishments in Phase 05:
1. **Typed Analyzer Registry (`backend/app/core/analyzer_registry.py`):**
   - Implemented `AnalyzerDefinition` and `AnalyzerRegistry` with strict validation of tool ID, version, supported artifact types, execution tier, input requirements, output schema, resource limits, and capability permissions.
   - Built-in Tier A analyzers (`dissect_evtx`, `dissect_registry`, `dissect_disk_stream`, `dissect_collector`) declared with precise userspace stream parsing capabilities.
   - Tier B declarative tools (`ez_evtxecmd`, `chainsaw_sigma`, `ez_recmd`, `volatility3_pslist`, `yara_scanner`) auto-loaded and validated from `plugins/*.yaml`.
2. **Dissect Adapter Hardening & Scope Honesty (`backend/app/core/dissect_adapter.py`):**
   - Strictly enforced unsupported container format rejection: any disk image artifact with `EVF01`/`EVF02` (E01) or `KDMV` (VMDK) magic bytes is rejected with `ForensicOpsError`.
   - Removed unverified capability advertisements for compressed/sparse disk containers, advertising only genuine flat raw disk streams (`.raw`, `.img`, `.dd`), EVTX, Registry, and collector archives.
   - Populated `tool_version="1.0.0"` across all generated `ForensicFinding` instances.
3. **Active Dissect Parser Workflow Node (`backend/app/agent/graph.py`):**
   - Updated `_make_dissect_parser_node` to actively inspect the case vault for matching artifacts via `CustodyEngine`.
   - Verifies SHA-256 integrity on disk before executing userspace stream parsing.
   - Evaluates deterministic execution keys in `CustodyEngine` to avoid redundant parsing while supporting `force_rerun`.
   - Populates DuckDB storage with newly parsed findings and distinguishes `completed` (new findings) from `retrieved_existing` or `cached`.
4. **Active Tool Runner Workflow Node (`backend/app/agent/graph.py`):**
   - Updated `_make_tool_runner_node` to resolve requested tools against `AnalyzerRegistry` and `ExecutionPolicyRegistry`.
   - Rejects unapproved or unclassified tools with `failed` status and explicit error logs.
   - Resolves case artifacts via `CustodyEngine.resolve_artifact_file(artifact)` and verifies physical disk SHA-256 against the immutable custody record; halts immediately on hash mismatch.
   - Invokes `PluginRunner.run_plugin` within the Phase 04 container sandbox (`AirGappedSubprocessRunner`).
   - Normalizes raw tool outputs, updates DuckDB findings, and returns structured node execution results.
5. **Deterministic Execution Idempotency (`backend/app/core/custody_engine.py`):**
   - Added SQLite table `tool_executions` with unique index on `execution_key` and index on `case_id`.
   - Implemented `compute_execution_key(case_id, artifact_hash, tool_id, tool_version, parameters)`.
   - Implemented `get_tool_execution` and `record_tool_execution` to store immutable provenance of every analyzer run.
   - Enabled replay of existing cached execution results on subsequent workflow invocations unless `force_rerun=True`.
6. **Findings Model & Storage Compatibility (`backend/app/models/findings.py`, `backend/app/core/storage.py`):**
   - Added `tool_version: Optional[str] = None` to `ForensicFinding`.
   - Updated DuckDB `findings` schema with `tool_version VARCHAR` and automated backwards-compatible schema migration (`ALTER TABLE findings ADD COLUMN IF NOT EXISTS tool_version VARCHAR`).
   - Defined `FINDINGS_SELECT_COLS` ensuring order-independent tuple unpacking in `ForensicStore._row_to_finding`, preventing column mismatch errors between newly created and migrated tables.
7. **Structured Workflow Node Outputs:**
   - Standardized node execution outputs returning: `execution_id`, `status` (`completed`, `cached`, `retrieved_existing`, `failed`, `SKIPPED_NO_ARTIFACT`), `findings_count`, `raw_output_reference`, `input_artifact_ids`, `tool_metadata`, `warnings`, `errors`, `dataset_pointer`, `pivots`.
8. **End-to-End Vertical Slice Verified:**
   - Authorized EVTX artifact ingested into vault -> SHA-256 verified -> sandboxed EZ Tools execution -> raw JSONL output saved -> smart column projection -> normalized `ForensicFinding` persisted into DuckDB -> `CitationGuard` successfully validates and grounds claim citations with `VERIFIED` status.
9. **Regression Test Suite (`backend/tests/test_phase05_workflow_analyzers.py`):**
   - 10 comprehensive tests covering vertical slice, Dissect node execution, E01/VMDK format rejection, direct magic bytes rejection, unapproved tool blocking, idempotency caching and force rerun, on-disk tampering detection, malformed parser output safety, process timeout handling, and honest non-success reporting.
   - Test results: **10 / 10 PASSED**.
   - Entire test suite: **229 / 229 PASSED (100% green in 23.41s)**.
   - Frontend production build: **0 errors, 0 warnings (built in 388ms)**.

---

## 2. Executive Implementation Summary — Phase 04

Phase 04 transformed the existing `PluginRunner` and subprocess execution infrastructure into a reliable, fail-closed forensic execution sandbox. External forensic binaries that parse untrusted evidence are strictly isolated within hardened containers with offline network denial, read-only root filesystems, read-only evidence mounts, non-root user execution, dropped Linux capabilities, and strict CPU/memory/process-count limits. Silent fallback to host execution has been permanently eliminated. All execution requests are validated against a deterministic, centralized execution policy, and full cryptographic provenance is recorded for every tool execution.

### Key Accomplishments in Phase 04:
1. **Centralized Execution Policy (`backend/app/core/execution_policy.py`):**
   - Implemented `ToolExecutionPolicy`, `ResourceLimits`, and `ExecutionPolicyRegistry`.
   - Defined canonical approved execution policies for forensic tools: `chainsaw_sigma`, `ez_evtxecmd`, `ez_recmd`, `volatility3_pslist`, `yara_scanner`, and `safe_bin`.
   - Classifies tools by approved tool ID, binary name, binary digest, version, container image prefix/digest, supported artifact types, allowed arguments, resource requirements, read/write mounts, network requirements, and risk classification.
   - Rejects unapproved tool IDs and unapproved executable binaries with `ExecutionPolicyError`.
2. **Mandatory Container Sandbox (`AirGappedSubprocessRunner`):**
   - Created `build_container_argv` constructing hardened container arguments:
     - Network disabled: `--network none`
     - Read-only root filesystem: `--read-only`
     - Dropped capabilities: `--cap-drop ALL`
     - Privilege escalation blocked: `--security-opt no-new-privileges:true`
     - Non-root user: `--user 1000:1000`
     - Resource limits: `--cpus <limit>`, `--memory <limit>`, `--pids-limit <limit>`
     - Temporary storage: `--tmpfs /tmp:rw,noexec,nosuid,size=<limit>`
     - Read-only evidence mount: `-v <evidence_dir>:/evidence:ro` (evidence never mounted read-write)
     - Controlled output mount: `-v <scratch_dir>:/scratch:rw`
   - Added container runtime availability verification (`is_container_runtime_available`).
3. **Fail-Closed Guarantee (No Silent Host Fallback):**
   - If a container runtime is unavailable or fails, `AirGappedSubprocessRunner` raises `SandboxUnavailableError` immediately.
   - Silent host fallback has been completely removed.
   - Direct host execution of forensic binaries processing evidence is prohibited (`SandboxUnavailableError`).
   - Test mock handlers are permitted only under explicit test environments (`FORENSICOPS_TEST_MODE=true` or pytest runtime).
4. **Process Safety & Resource Protection:**
   - Enforced `shell=False` unconditionally across all subprocess execution paths.
   - Implemented argument defense against shell metacharacters (`;`, `&`, `|`, `` ` ``, `$`, `>`, `<`, `\n`, `\r`).
   - Implemented cross-platform process-tree termination on timeout (`terminate_process_tree`) using `taskkill /F /T /PID` on Windows and `os.killpg` on POSIX, preventing lingering orphan child processes.
   - Enforced bounded stdout and stderr capture (capped at 10 MB per stream) with explicit truncation warnings to protect against memory exhaustion.
   - Enforced workspace confinement preventing path traversal or mounting arbitrary host directories.
5. **Declarative Plugin Card Validation (`ExecutionPolicyRegistry.validate_plugin_card`):**
   - Enforced strict validation before YAML plugin card registration or execution:
     - Container image required for Tier B plugins, restricted to approved registry prefixes (`ghcr.io/forensicops/`, `docker.io/forensicops/`, `forensicops/`).
     - Command template placeholders strictly restricted to `{input_path}`, `{output_dir}`, and `{rules_path}`.
     - Shell metacharacters in templates prohibited.
     - Timeout bounded strictly between 1 and 3600 seconds.
     - Input types restricted to `file` or `directory`; output formats restricted to `json`, `jsonl`, `csv`.
   - Connected validation to `/api/plugins/register`, returning HTTP 400 on policy violation.
6. **Complete Cryptographic Execution Provenance:**
   - Expanded `ToolExecutionResult` with 11 provenance fields: `tool_version`, `binary_digest`, `container_image`, `container_image_digest`, `parameters`, `started_at_utc`, `finished_at_utc`, `input_artifact_hash`, `output_hashes`, `warnings`, and `errors`.
   - `PluginRunner.run_plugin` hashes all generated output files and records tool execution events in the append-only `CustodyEngine` ledger.
7. **Active LangGraph Tool Runner Execution (`backend/app/agent/graph.py`):**
   - Updated `_make_tool_runner_node` to actively trigger `PluginRunner.run_plugin` against unindexed artifacts in the case vault when structured findings are not already present, resolving the passive tool runner concern from Phase 00.
8. **Regression Test Suite:**
   - Authored `backend/tests/test_phase04_tool_sandbox.py` with 10 comprehensive tests covering container hardening flags, unapproved tool blocking, fail-closed sandbox behavior, direct host execution denial, process-tree termination on timeout, bounded output capture, workspace traversal prevention, invalid YAML rejection, provenance recording, and API registration policy enforcement.
   - Full test suite: **219 / 219 PASSED (100% green in 22.90s)**.
   - Frontend production build: **0 errors, 0 warnings (built in 388ms)**.

---

## 2. Actual Repository Inventory

```
c:\forensicops-ai\
├── AGENTS.md                          # Permanent engineering contract & DFIR rules
├── CODEBASE.md                        # High-level architecture map
├── STATUS.md                          # Current implementation status & baseline
├── audit.md                           # Audit overview
├── pyproject.toml                     # Python packaging and dependency declarations
├── .env                               # Local environment variables
├── .gitignore                         # Git exclusion rules
├── audits/                            # Security audit reports & proof-of-concept scripts
│   ├── SECURITY_AUDIT_REPORT.md       # Audit report (SA-001 through SA-013)
│   ├── findings.json                  # Machine-readable audit findings database
│   └── poc/                           # Reproducible vulnerability PoC scripts
├── backend/
│   ├── app/
│   │   ├── main.py                    # FastAPI entrypoint, CORS & error handlers
│   │   ├── agent/                     # LangGraph DAG orchestration & LLM planning
│   │   │   ├── graph.py               # LangGraph DAG workflow execution engine
│   │   │   ├── hypothesis_planner.py  # Playbook-constrained goal & hypothesis planner
│   │   │   ├── lmstudio_client.py     # LM Studio OpenAI-compatible thin proxy client
│   │   │   ├── ollama_client.py       # Backward-compatibility alias to LMStudioClient
│   │   │   ├── memory_protocol.py     # SQLite episodic feedback & knowledge provider
│   │   │   ├── prompts.py             # System prompts & anti-IPI XML boundaries
│   │   │   ├── provider_registry.py   # Multi-provider LLM registry (local/cloud)
│   │   │   ├── report_builder.py      # 6-section RFC 3227 forensic report compiler
│   │   │   └── tools.py               # In-memory analytical tools (PCAP, Linux log, DuckDB)
│   │   ├── api/                       # REST & SSE API endpoints
│   │   │   ├── __init__.py            # Central api_router definition
│   │   │   ├── agent.py               # Hypothesis planning & plan execution endpoints
│   │   │   ├── auth.py                # Login, registration & user profile endpoints
│   │   │   ├── cases.py               # Case management & peer review vault endpoints
│   │   │   ├── copilot.py             # DFIR Lead interactive conversational co-pilot
│   │   │   ├── deps.py                # Dependency injection providers & vault roots
│   │   │   ├── feedback.py            # Micro-feedback (TP/benign baseline) endpoints
│   │   │   ├── findings.py            # Normalized findings query & lookup
│   │   │   ├── intake.py              # Offline/online intake, upload & custody query
│   │   │   ├── llm.py                 # LLM provider selection & smoke-test endpoints
│   │   │   ├── plugins.py             # Plugin discovery, dry-run & registration
│   │   │   ├── reports.py             # Forensic report compilation & retrieval
│   │   │   ├── session.py             # Investigation session state persistence
│   │   │   └── workflows.py           # DAG execution, SSE streaming & approval tokens
│   │   ├── auth/                      # Authentication & Multi-User RBAC
│   │   │   ├── case_authorization.py  # Centralized case authorization service
│   │   │   ├── dependencies.py        # JWT validation & role enforcement (require_roles)
│   │   │   ├── models.py              # User models & role types
│   │   │   ├── security.py            # Bcrypt password hashing & JWT token encoding
│   │   │   └── store.py               # SQLite user credentials database (users.db)
│   │   ├── connectors/                # Remote triage & SIEM integration
│   │   │   ├── siem_connectors.py     # Read-only Elasticsearch, Splunk & Wazuh connectors
│   │   │   └── ssh_collector.py       # SSH / WinRM remote triage collector
│   │   ├── core/                      # Forensic core engines & parsers
│   │   │   ├── artifact_indexer.py    # Target OS & vault artifact indexer
│   │   │   ├── auto_mapper.py         # Heuristic tool output normalization
│   │   │   ├── citation_guard.py      # Post-LLM cryptographic citation validator
│   │   │   ├── config.py              # Pydantic v2 application configuration settings
│   │   │   ├── custody_engine.py      # Defanged blob vault, path confinement & custody ledger
│   │   │   ├── dissect_adapter.py     # Dissect target loader & parser adapter
│   │   │   ├── exceptions.py          # Custom domain exceptions
│   │   │   ├── playbook_registry.py   # MITRE ATT&CK goal router & investigation blueprints
│   │   │   ├── plugin_runner.py       # Air-gapped subprocess runner
│   │   │   └── storage.py             # DuckDB forensic store & SQL dataset views
│   │   ├── db/
│   │   │   └── sqlite_store.py        # SQLite persistent state store
│   │   └── models/                    # Pydantic v2 data models
│   │       ├── cases.py               # ForensicCase and CaseManifest models
│   │       ├── connectors.py          # SIEM & EndpointTarget connection schemas
│   │       ├── custody.py             # ArtifactRecord, CustodyChainEntry & CapsuleManifest
│   │       ├── feedback.py            # MicroFeedback and AnalystRule models
│   │       ├── findings.py            # ForensicFinding, CitedClaim & HypothesisDraft
│   │       └── workflow.py            # WorkflowDefinition, NodeGoalResult & HumanApprovalToken
│   └── tests/                         # Comprehensive automated test suite (199 tests)
│       ├── conftest.py                # Test configuration & shared fixtures
│       ├── test_agent_hypothesis_planner.py
│       ├── test_attack_scenario_evtx.py
│       ├── test_case_manager_and_vault.py
│       ├── test_copilot_chat.py
│       ├── test_goal_playbook_engine.py
│       ├── test_phase01_auth_isolation.py
│       ├── test_phase02_evidence_integrity.py  # Phase 02 regression tests
│       ├── test_phase1_5_auth_rbac.py
│       ├── test_phase1_custody.py
│       ├── test_phase2_plugins.py
│       ├── test_phase3_storage_and_llm.py
│       ├── test_phase4_workflow_agent.py
│       ├── test_phase5_connectors.py
│       ├── test_phase6_api.py
│       ├── test_phase7_llm_persistence.py
│       ├── test_phase7_llm_registry.py
│       ├── test_phase8_intake_upload.py
│       ├── test_security_audit_fixes.py
│       ├── test_security_hardening.py
│       └── test_stabilization_plan.py
├── frontend/                          # React 19 + TypeScript + Vite frontend
└── sample/                            # Forensic sample datasets & EVTX captures
```
│   │   │   ├── column_projector.py    # Smart column projection with audit.jsonl logging
│   │   │   ├── config.py              # Pydantic Settings application configuration
│   │   │   ├── custody_engine.py      # RFC 3227 hash-chained custody engine & vault
│   │   │   ├── dissect_adapter.py     # Flat userspace EVTX & Registry parser (python-evtx)
│   │   │   ├── exceptions.py          # Platform-wide custom exceptions
│   │   │   ├── playbook_registry.py   # 14-tactic MITRE ATT&CK Enterprise playbook registry
│   │   │   ├── plugin_runner.py       # Air-gapped tool execution runner
│   │   │   └── storage.py             # ForensicStore DuckDB analytical engine
│   │   ├── db/
│   │   │   └── sqlite_store.py        # SQLite LLMStateStore, cases, uploads & sessions
│   │   └── models/                    # Pydantic data schemas & contracts
│   │       ├── cases.py               # Case metadata & CRUD DTOs
│   │       ├── connectors.py          # SIEM & collector schemas
│   │       ├── custody.py             # ArtifactRecord, CustodyChainEntry & CapsuleManifest
│   │       ├── feedback.py            # HumanFeedbackRecord & NodeExecutionTrace
│   │       ├── findings.py            # ForensicFinding, CitedClaim & HypothesisDraft
│   │       ├── plugins.py             # ToolPluginCard & execution results
│   │       └── workflow.py            # WorkflowDefinition, Node, Edge & ApprovalToken
│   ├── data/
│   │   └── evidence_intake/           # Staging directory for streamed uploads
│   └── tests/                         # Automated test suite (18 test files)
├── collectors/                        # Endpoint collection scripts
│   ├── linux/collect_linux_triage.sh  # Bash volatile triage collection script
│   └── windows/Invoke-ForensicCollector.ps1 # PowerShell triage collection script
├── frontend/                          # React 19 + TypeScript + Vite SPA
│   ├── src/
│   │   ├── App.tsx                    # Root application component
│   │   ├── components/                # 14 React UI components & modal views
│   │   ├── context/                   # AuthContext & InvestigationContext
│   │   ├── services/api.ts            # HTTP client & SSE streaming reader
│   │   ├── store/useForensicStore.ts  # Zustand global state store
│   │   └── types/                     # TypeScript data contracts & models
│   └── package.json                   # Frontend dependencies & build scripts
├── plugins/                           # Pre-built YAML forensic tool cards
│   ├── chainsaw_sigma.yaml            # Chainsaw Sigma EVTX rule scanner
│   ├── ez_evtxecmd.yaml               # Eric Zimmerman EvtxECmd event log parser
│   ├── ez_recmd.yaml                  # Eric Zimmerman RECmd registry parser
│   ├── volatility3_pslist.yaml        # Volatility 3 memory process list
│   └── yara_scanner.yaml              # YARA filesystem scanner
├── sample/                            # Real-world EVTX test evidence files
│   ├── Credential Access/             # babyshark_mimikatz_powershell.evtx
│   ├── Lateral Movement/              # LM_wmiexec_impacket_sysmon_whoami.evtx
│   └── Privilege Escalation/          # 32 Sysmon & Security EVTX samples
└── specs/                             # Architecture specifications (01 through 05)
```

### Ad-hoc Root Scripts Identified (Unused in Package):
- `create_clean_zip.ps1` / `codebase_clean.zip`: Archive packaging script.
- `dump_benchmark_report.py`, `evaluate_models.py`, `inspect_answers.py`, `run_dfir_benchmark.py`, `run_gemma_qwen_benchmark.py`: Local LLM evaluation scripts not integrated into package testing.

---

## 3. Implemented vs. Incomplete Architecture Matrix

| Component | Status | Verified Behavior in Current Source | Gap / Incomplete Functionality |
| :--- | :--- | :--- | :--- |
| **Evidence Intake (Upload & Defanging)** | **Implemented** | Streams 1MB chunks to `backend/data/evidence_intake`, computes SHA-256/512, enforces `safe_make_readonly` (`0400`), defangs into `.blob` vault, writes to `custody_chain`. | Max size limit enforced in memory but no volume quota management. |
| **Zero-Copy Intake (`:ro`)** | **Implemented** | Computes stream hashes in place, verifies path confinement against `evidence_allowlist_dirs`. | None. Confined and operational. |
| **Custody Ledger (`custody.db`)** | **Implemented** | Sequential RFC 3227 SHA-256 hash chaining (`entry_hash = sha256(prev_hash + canonical_json)`). | `verify_chain(case_id)` ignores `case_id`. |
| **Userspace Evidence Parsing (Dissect)** | **Implemented** | Flat userspace parsing using `python-evtx` for EVTX and `dissect.target` for Registry hives. Avoids kernel mounting. | Dissect registry parser depends on dissect libraries installed; fallback handles basic keys. |
| **Native In-Memory Parsers** | **Implemented** | `parse_pcap_file` (PCAP) and `parse_linux_text_log` (Linux auth/syslog) in `backend/app/agent/tools.py`. | Limited to common protocols and syslog formats. |
| **Analytical Store (`ForensicStore`)** | **Implemented** | Per-case DuckDB instance (`forensic_store.duckdb`), structured column filters, keyword search, dataset views. | `get_finding(finding_id)` does not filter by `case_id`. |
| **Plugin Runner (`PluginRunner`)** | **Partially Implemented** | Shell=False, argv array validation, allowlist check (`ALLOWED_FORENSIC_BINARIES`), YAML manifest loading. | **Graph workflow `tool_runner` nodes do NOT call `run_plugin()`**; Docker execution disabled by default. |
| **Workflow Engine (LangGraph)** | **Partially Implemented** | DAG compilation, state transitions, SSE streaming, starter blueprints, human approval gates. | **LLM exceptions masked as fake success**; `tool_runner` nodes passive; evidence input node passive. |
| **Hypothesis & Playbook Planner** | **Partially Implemented** | 14-tactic MITRE ATT&CK registry, `ScopedFilterParams`, blueprint inference, artifact cross-referencing. | **Claim types assigned via modulo 2** (`idx % 2 == 0`); **arbitrary confidence values**; unvalidated caller findings. |
| **CitationGuard** | **Implemented** | Cryptographic existence of `finding_id` and artifact hashes in DuckDB, case matching, 3-char substring match. | Substring match is rudimentary; does not verify semantic truth or disk blob integrity. `strict=False` strips silently. |
| **Report Builder (`ReportBuilder`)** | **Partially Implemented** | 6-section RFC 3227 report generation, Patient Zero correlation, markdown export. | If `custody_engine is None`, defaults to `tamper_ok = True`; custody failure outputs warning but does not halt. |
| **Authentication & RBAC** | **Implemented** | Bcrypt hashing, JWT HS256, SQLite `users.db`, `require_roles` dependencies on cases, reports, copilot. | `agent.py` endpoints use `get_current_user_optional`. Test header bypass active in test mode. |
| **SIEM & SSH Remote Connectors** | **Implemented** | Read-only AST validation on queries, SSRF IP filtering, HMAC token gate enforcement for SSH/WinRM. | Real SSH/WinRM tested via hermetic mocks in CI. |
| **Frontend UI (React 19)** | **Implemented** | Canvas, Vault, Case Manager, Report Viewer, Co-pilot Drawer, Plugins, AuthGate, EnvironmentWizard. | Production build succeeds in 385ms with 0 errors. |

---

## 4. Test Baseline & Environment

### Test Execution Results
- **Command:** `python -m pytest -v`
- **Python Version:** `Python 3.14.7`
- **Pytest Version:** `pytest-9.2.0` (pluggy-1.7.0)
- **Active Plugins:** `anyio-4.15.1`, `langsmith-0.14.16`, `platformdirs-4.14.5`, `asyncio-1.4.1`
- **Result:** **175 passed in 12.56s (100% green)**

### Breakdown by Test Module:
1. `backend/tests/test_agent_hypothesis_planner.py`: **5 passed**
2. `backend/tests/test_attack_scenario_evtx.py`: **3 passed**
3. `backend/tests/test_case_manager_and_vault.py`: **2 passed**
4. `backend/tests/test_copilot_chat.py`: **4 passed**
5. `backend/tests/test_goal_playbook_engine.py`: **22 passed**
6. `backend/tests/test_phase1_5_auth_rbac.py`: **13 passed**
7. `backend/tests/test_phase1_custody.py`: **12 passed**
8. `backend/tests/test_phase2_plugins.py`: **13 passed**
9. `backend/tests/test_phase3_storage_and_llm.py`: **16 passed**
10. `backend/tests/test_phase4_workflow_agent.py`: **10 passed**
11. `backend/tests/test_phase5_connectors.py`: **12 passed**
12. `backend/tests/test_phase6_api.py`: **12 passed**
13. `backend/tests/test_phase7_llm_persistence.py`: **5 passed**
14. `backend/tests/test_phase7_llm_registry.py`: **9 passed**
15. `backend/tests/test_phase8_intake_upload.py`: **6 passed**
16. `backend/tests/test_security_audit_fixes.py`: **12 passed**
17. `backend/tests/test_security_hardening.py`: **13 passed**
18. `backend/tests/test_stabilization_plan.py`: **5 passed**

### Frontend Production Build:
- **Command:** `npm run build` (`tsc -b && vite build`)
- **Vite Version:** `vite v8.3.5`
- **Transformed:** `2221 modules`
- **Duration:** `385ms`
- **Errors / Warnings:** `0 errors, 0 build warnings` (1 bundle chunk size notice for index bundle > 500 kB)

---

## 5. Verification of the 10 Critical Architectural Targets

### Target 1: Tool-runner and parser nodes in `backend/app/agent/graph.py`
- **Claim:** Parser and tool-runner nodes currently retrieve existing findings rather than executing their corresponding analyzers.
- **Verification Status:** **CONFIRMED.**
- **Evidence:**
  - In `_make_tool_runner_node` (lines 478-517): Node handler simply executes `self.storage.query_structured_findings(case_id=state.case_id, filters={"tool_id": tool_id}, limit=100)`. `self.plugin_runner.run_plugin(...)` is **never** invoked.
  - In `_make_dissect_parser_node` (lines 396-453): Checks if findings already exist in `self.storage.query_structured_findings(...)`. Only if `not findings` does it perform fallback parsing of vault artifacts. If findings are present, it performs no parsing and simply returns the query result.

### Target 2: Sandbox execution in `backend/app/core/plugin_runner.py`
- **Claim:** Docker execution is conditional and host execution remains possible.
- **Verification Status:** **CONFIRMED.**
- **Evidence:**
  - `AirGappedSubprocessRunner.__init__(self, use_docker_if_available: bool = False)` defaults to `False`.
  - In `deps.py:133`, `PluginRunner` is instantiated without a custom subprocess runner, inheriting `use_docker=False`.
  - In `execute()` (lines 111-135): Host execution is explicitly allowed for binaries matching `ALLOWED_FORENSIC_BINARIES` (`chainsaw`, `evtxecmd`, `recmd`, `vol`, `yara`, `python`, etc.) via `subprocess.Popen(shell=False)`.

### Target 3: Single-finding retrieval in `backend/app/api/findings.py`
- **Claim:** Single-finding retrieval does not explicitly verify the returned finding's case ID.
- **Verification Status:** **CONFIRMED.**
- **Evidence:**
  - In `get_finding` (lines 21-35): Handler calls `storage = get_storage(case_id)` and `finding = storage.get_finding(finding_id)`.
  - In `storage.get_finding(finding_id)` (`backend/app/core/storage.py:221-225`): SQL query is `SELECT * FROM findings WHERE finding_id = ? LIMIT 1;`, with no `AND case_id = ?` clause.
  - In `findings.py:35`, the returned `finding` is never validated with `if finding.case_id != case_id: raise HTTPException(404)`.

### Target 4: Custody verification in `backend/app/core/custody_engine.py`
- **Claim:** `verify_chain(case_id)` does not use the supplied case ID. Determine whether per-case engine/database boundary makes this safe and add an explicit consistency guarantee.
- **Verification Status:** **CONFIRMED.**
- **Evidence:**
  - Lines 952-955:
    ```python
    def verify_chain(self, case_id: Optional[str] = None) -> bool:
        passed, _ = self.verify_chain_integrity()
        return passed
    ```
  - `case_id` is a dead parameter. In standard API routing, `get_custody_engine(case_id)` provisions `vault/<case_id>/custody.db`, meaning the DB typically contains records for one case. However, if multiple cases share an engine or an in-memory test database, or if an engine for `case_A` is mistakenly invoked with `verify_chain("case_B")`, it verifies all records without verifying `case_id` consistency. An explicit assertion `entry.case_id == case_id` must be guaranteed.

### Target 5: LLM exception handling in `backend/app/agent/graph.py`
- **Claim:** LLM exception handling must be checked for false-success results.
- **Verification Status:** **CONFIRMED — CRITICAL DEFECT.**
- **Evidence:**
  - In `_make_ai_goal_step_node` (lines 597-633):
    ```python
    except Exception as e:
        # Fallback mock result with verified citation
        ...
        raw_result = NodeGoalResult(
            node_id=node.id,
            status="success",  # <-- FALSE SUCCESS!
            summary=f"Forensic analysis completed for goal: {user_goal}...",
            claims=claims,
            ...
            confidence_score=0.95 if evidence else 0.70,
        )
    ```
  - When the LLM provider fails, crashes, or times out, the node catches the exception and returns `status="success"` with synthesized mock claims and `confidence_score=0.95`. This directly violates AGENTS.md Principle 9: *"Never report a failed, incomplete, or unavailable analysis as successful."*

### Target 6: Authentication & finding ingestion in `backend/app/api/agent.py`
- **Claim:** Inspect optional authentication and caller-supplied findings.
- **Verification Status:** **CONFIRMED.**
- **Evidence:**
  - In `plan_hypothesis_endpoint`, `compile_goal_plan_endpoint`, and `execute_goal_plan_endpoint`:
    `current_user: Optional[UserRead] = Depends(get_current_user_optional)`.
  - All three endpoints accept `findings: Optional[List[ForensicFinding]] = None` directly from the request JSON payload.
  - The endpoints allow anonymous callers to submit arbitrary forensic finding dictionaries, which are processed into claims without verifying their cryptographic presence in the vault or DuckDB store.

### Target 7: Finding trust, claim classification & confidence in `backend/app/agent/hypothesis_planner.py`
- **Claim:** Inspect finding trust, claim classification and confidence generation.
- **Verification Status:** **CONFIRMED.**
- **Evidence:**
  - **Claim classification by modulo:** Lines 524 and 450:
    `claim_type = "observed_fact" if idx % 2 == 0 else "derived_correlation"`
    Classification of claims as observed facts vs. derived correlations is literally determined by whether the finding loop index is even or odd.
  - **Arbitrary confidence values:** Hardcoded constants `confidence=0.98` (line 454), `confidence=0.95` (line 531), `confidence_score = 0.95 if resolved_findings else 0.75` (line 612). Violates AGENTS.md Forensic Data Rule: *"Never assign arbitrary confidence values."*

### Target 8: Validation guarantees of `backend/app/core/citation_guard.py`
- **Claim:** Determine exactly what its validation guarantees.
- **Verification Status:** **CONFIRMED.**
- **Evidence:**
  - **What it guarantees:**
    1. Rejects claims marked as `"observed_fact"` or `"derived_correlation"` if `citing_finding_ids` or `source_artifact_hashes` are empty.
    2. Rejects claims citing finding IDs not present in DuckDB.
    3. Rejects claims citing finding IDs belonging to a different `case_id`.
    4. Rejects claims where the finding's registered `source_artifact_hash` is not cited.
    5. Rejects claims with unverified source artifact hashes.
    6. Basic semantic overlap: requires at least one 3-character keyword from the finding's entities (host, user, process, event_id, command_line) to appear anywhere in `claim.statement.lower()`.
  - **What it does NOT guarantee:**
    1. Does not evaluate semantic truth or deductive validity of the statement beyond substring presence.
    2. Does not verify that source files exist on disk or match their expected SHA-256 hashes at citation time.
    3. In `strict=False` mode (used in `graph.py` and `hypothesis_planner.py`), it quietly drops rejected claims without failing the execution or marking node status as failed.

### Target 9: Anonymous access in `backend/app/api/cases.py` and `backend/app/api/copilot.py`
- **Claim:** Inspect anonymous access.
- **Verification Status:** **VERIFIED REMEDIATED (WITH KNOWN EXCEPTION).**
- **Evidence:**
  - `backend/app/api/cases.py`: All routes (`list_cases`, `get_case`, `create_or_update_case`, `update_case`, `delete_case`, `toggle_share`) strictly enforce `current_user: UserRead = Depends(require_roles(...))`.
  - `backend/app/api/copilot.py`: `POST /api/copilot/chat` enforces `require_roles("lead_investigator", "soc_analyst", "external_auditor")`.
  - **Known Exception:** In test mode (`PYTEST_CURRENT_TEST` or `FORENSICOPS_ENVIRONMENT=test`), header bypass via `X-ForensicOps-Test-Role` is permitted when `FORENSICOPS_AUTH_DISABLED=true`. In production, this bypass is strictly blocked.

### Target 10: Custody verification and failure in `backend/app/agent/report_builder.py`
- **Claim:** Inspect custody verification and failure behavior.
- **Verification Status:** **CONFIRMED.**
- **Evidence:**
  - In `ReportBuilder.build_report` (lines 423-441):
    `tamper_ok = True` is initialized as `True`. If `custody_engine is None`, `tamper_ok` remains `True` and the report certifies `VERIFIED (100% Chain Integrity)`.
  - If custody check fails (`tamper_ok = False`), the report does NOT abort or raise an exception; it proceeds to compile the entire report, merely setting `sec2.tamper_check_passed = False` and rendering `WARNING: Custody Discrepancy Detected` in Markdown.

---

## 6. Confirmed Functional & Codebase Gaps

1. **Passive Tool Runner Nodes in Graph DAG:**
   `_make_tool_runner_node` in `graph.py` queries pre-existing DuckDB findings rather than executing analyzers through `PluginRunner`. Forensic DAG workflows cannot run unindexed tool plugins dynamically.
2. **Duplicated Workflow Routers:**
   `backend/app/api/workflows.py` defines both `router` (`/api/workflows`) and `workflow_single_router` (`/api/workflow`) to patch singular/plural URL inconsistencies.
3. **Empty Compatibility Shims:**
   `backend/app/agent/ollama_client.py` is an alias for `LMStudioClient`.
4. **Architectural Naming Mismatch in SQLite Store:**
   `LLMStateStore` in `backend/app/db/sqlite_store.py` stores not only LLM settings, but case management records (`cases`), session states (`investigation_sessions`), and evidence uploads (`evidence_intake_uploads`).
5. **Ad-Hoc Benchmark Scripts in Root:**
   Root scripts (`dump_benchmark_report.py`, `evaluate_models.py`, `inspect_answers.py`, `run_dfir_benchmark.py`, `run_gemma_qwen_benchmark.py`) should be grouped under a `benchmarks/` directory or archived.

---

## 7. Technical Dependencies & Environment Blockers

- **Python Runtime:** Python 3.14.7.
- **Deprecation Warnings Observed (Non-Fatal):**
  - `langsmith/_internal/_beta_decorator.py:92`: Deprecation warning for `asyncio.iscoroutinefunction` (scheduled for removal in Python 3.16).
  - `fastapi/routing.py:372`: Starlette deprecation warning for `HTTP_413_REQUEST_ENTITY_TOO_LARGE` (prefer `HTTP_413_CONTENT_TOO_LARGE`).
- **Dependencies:** All dependencies in `pyproject.toml` and `package.json` are installed and operational without requiring external services (PostgreSQL, Qdrant, Redis are not required).

---

## 8. Recommended Implementation Sequence

Following the AGENTS.md contract and master plan, the recommended sequence is:

- **Phase 01: Core Architecture, Custody & Finding Isolation Integrity**
  - Fix `CustodyEngine.verify_chain(case_id)` to enforce explicit `case_id` matching.
  - Enforce `case_id` verification on single-finding retrieval in `findings.py` and `storage.py`.
  - Eliminate unauthenticated access on `backend/app/api/agent.py` endpoints (`require_roles`).
  - Validate caller-supplied findings against vault/storage before processing in `hypothesis_planner.py`.
  - Eliminate false-success LLM exception masking in `graph.py`; propagate actual failure states.
  - Eliminate modulo-2 claim classification and arbitrary confidence numbers; ground classification in empirical finding attributes.
  - Ensure `ReportBuilder` does not default to `tamper_ok = True` when `custody_engine is None`.
  - Add regression tests for all fixes.

- **Phase 02: Active Tool Runner & Air-Gapped Sandbox Execution**
  - Connect `PluginRunner.run_plugin()` into LangGraph `tool_runner` nodes.
  - Define containerized vs. host execution policies with deterministic error handling when binaries are absent.
  - Add regression tests verifying tool execution within DAG.

- **Phase 03: Hypothesis Engine & Playbook Hardening**
  - Connect playbook steps directly to executable analyzers.
  - Implement empirical correlation tracing between parent-child processes, network connections, and user accounts.
  - Replace static recommendations with evidence-gap driven recommendations.

- **Phase 04: Report Builder Defensibility & Integrity Hardening**
  - Implement physical disk hash verification at report compile time.
  - Implement strict custody tamper policies (abort or fail report generation on tamper).

- **Phase 05: Interface Consolidation, Codebase Hygiene & Documentation**
  - Consolidate `/api/workflow` and `/api/workflows` routes.
  - Move ad-hoc root benchmark scripts to `benchmarks/`.
  - Clean up dead shims and refine store naming.

---

## 9. Phase 04 Completion Verification & Next Phase Prerequisites

### Phase 04 Acceptance Verification:
- **Centralized Execution Policy:** `ExecutionPolicyRegistry` classifies tools by approved ID, binary, container image, supported artifact types, allowed arguments, resource requirements, read/write mounts, network requirements, and risk level. Unknown tools strictly rejected.
- **Mandatory Container Sandbox:** `AirGappedSubprocessRunner` builds hardened container command line with `--network none`, `--read-only`, `--cap-drop ALL`, `--security-opt no-new-privileges:true`, `--user 1000:1000`, `--cpus`, `--memory`, `--pids-limit`, `--tmpfs /tmp:rw,noexec,nosuid`, read-only evidence mount (`:ro`), and isolated output mount (`:rw`).
- **Fail-Closed Guarantee:** Host fallback is strictly prohibited when container runtime is missing or fails (`SandboxUnavailableError`). Direct host execution of forensic binaries on untrusted evidence is blocked.
- **Process Safety:** `shell=False` unconditionally; shell metacharacter defense in arguments and templates; cross-platform process-tree termination on timeout (`taskkill /F /T /PID` on Windows, `os.killpg` on POSIX); bounded 10MB stdout/stderr capture; workspace path traversal blocked.
- **Plugin Validation:** Declarative YAML plugin cards validated before registration and execution against approved image prefixes, command template placeholders (`{input_path}`, `{output_dir}`, `{rules_path}`), bounded timeouts (1-3600s), and supported formats.
- **Cryptographic Provenance:** `ToolExecutionResult` populates all 11 provenance fields (`tool_version`, `binary_digest`, `container_image`, `container_image_digest`, `parameters`, `started_at_utc`, `finished_at_utc`, `input_artifact_hash`, `output_hashes`, `warnings`, `errors`) and records execution events into the append-only `CustodyEngine` ledger.
- **LangGraph Integration:** `_make_tool_runner_node` invokes `PluginRunner.run_plugin` when unindexed artifacts exist in the vault, inserting results into DuckDB.
- **Regression Test Suite:** 10 dedicated regression tests in `backend/tests/test_phase04_tool_sandbox.py`.
- **Full Test Suite:** 219 / 219 tests passed (100% green in 22.90s).
- **Frontend Build:** Built cleanly with 0 type errors in 388ms.

### Outstanding Risks & Known Limitations (Tracked for Future Phases):
1. **Host-Side Container Image Management:** Container images for Tier B external tools (`ghcr.io/forensicops/*`) must be pulled or imported prior to air-gapped deployment; runtime fail-closes cleanly when images are unavailable.
2. **Dissect Adapter Format Boundaries:** Dissect adapter intentionally supports only flat raw disk streams (`.raw`, `.img`, `.dd`), EVTX, Registry, and collector archives; compressed forensic containers (`.E01`, `.VMDK`) require external tool plugins or dedicated converters.

---

## 10. Phase 07 Completion Verification & Next Phase Prerequisites

### Phase 07 Acceptance Verification:
- **All 6 Specialist Interfaces Exist:** Implemented `WindowsDFIRSpecialist`, `LinuxDFIRSpecialist`, `MemoryForensicsSpecialist`, `NetworkForensicsSpecialist`, `MalwareAnalysisSpecialist`, and `TimelineCorrelationSpecialist` inheriting from `BaseDFIRSpecialist`.
- **Truth in Advertising:** Non-operational capabilities (e.g. Amcache, Shimcache, Prefetch, Systemd units, Auditd records, deep Zeek stream carving, dynamic malware detonation) are explicitly flagged `operational=False`. Tool requests for non-operational capabilities fail closed with `ExecutionPolicyError`.
- **Strict Safe Static Malware Only:** Dynamic detonation is strictly prohibited; requesting `dynamic_sandbox_execution` raises `ExecutionPolicyError`. Static PE header parsing, hashing, and string extraction are fully operational.
- **Deterministic Multi-Observation Correlation:** `TimelineCorrelationSpecialist` correlates verified findings across `user_to_process`, `process_to_network`, `host_to_host`, `authentication_to_execution`, `persistence_to_execution`, and `cross_source_event`. Every correlation records source/target finding IDs, calculated confidence (0.70-0.95), and deterministic method.
- **End-to-End InvestigationController Integration:** Discovers operational specialists for case evidence; runs actions across Windows, Linux, and Network domains; automatically executes timeline correlation during evaluation; populates `record.correlations`.
- **Regression Test Suite:** 10 dedicated regression tests in `backend/tests/test_phase07_specialist_capabilities.py`.
- **Full Test Suite:** 254 / 254 tests passed (100% green in 26.27s).
- **Frontend Build:** Built cleanly with 0 type errors in 389ms.

### Outstanding Risks & Known Limitations (Tracked for Future Phases):
1. **Container Image Availability for Advanced Parsers:** Non-operational capabilities (Amcache, Shimcache, Zeek, Volatility sub-plugins) require dedicated container images before they can be marked operational.
2. **Clock Drift Across Heterogeneous Sources:** Temporal correlation windows assume UTC synchronization across evidence sources; clock skew compensation should be considered if evidence sources lack NTP synchronization.

---

## 11. Phase 08 Completion Verification & Next Phase Prerequisites

### Phase 08 Acceptance Verification:
- **Central Action Risk Policy:** Evaluates all capabilities into 4 deterministic risk levels; allows read-only offline tools, strictly denies local evidence modification and dynamic malware detonation by default, and gates sensitive operations behind explicit human approval.
- **Operation-Specific Approval Binding & Canonical Digest:** Request binds `approval_id`, `case_id`, `requesting_investigator`, `action_type`, `target`, `capability_id`, `parameter_digest` (`sha256:...`), `policy_version`, and timestamps. Any change to arguments invalidates the approval request.
- **HMAC-SHA256 Approval Tokens & Replay Protection:** Cryptographic tokens bind all execution parameters; tokens are single-use, verified against an atomic SQLite ledger (`consumed_approval_tokens`), and reject expired, consumed, or tampered signatures.
- **Dual Control & Agent Self-Approval Prevention:** Automated agents (`agent`, `ai_planner`) and requesting investigators are strictly prohibited from approving their own requests; approvals require authorized human roles (`lead_investigator`, `soc_analyst`).
- **Autonomous Controller Integration:** `InvestigationController` checks action risk policy during pre-execution validation; pauses into `awaiting_approval` when sensitive actions are encountered; resumes safely upon receipt of a valid, unconsumed token.
- **Remote SSH Collector Target Gate:** `SSHCollectorConnector.verify_approval_gate` verifies token target host matches the remote target endpoint.
- **Immutable Custody Chain Audit Trail:** All creation, approval, rejection, revocation, and consumption events are appended to the case's hash-chained custody ledger.
- **Frontend Approval Modal:** Interactive review modal displays risk badges, canonical digest, parameters, and dual-control warnings with explicit Approve and Reject buttons.
- **Regression Test Suite:** 14 dedicated regression tests in `backend/tests/test_phase08_human_approval_engine.py`.
- **Full Test Suite:** 268 / 268 tests passed (100% green in 39.04s).
- **Frontend Build:** Built cleanly with 0 type errors in 429ms.

### Outstanding Risks & Known Limitations (Tracked for Future Phases):
1. **Approval Secret Key Distribution:** Production multi-node deployments must configure a secure `APPROVAL_SECRET_KEY` via KMS or environment secrets rather than local runtime configuration.
2. **Revocation Propagation During Active Subprocess Execution:** Revoking an approval after an external process has spawned will not preemptively kill the process unless coordinated with `PluginRunner.cancel()`.

---

## 12. Phase 09 Completion Verification & Next Phase Prerequisites

### Phase 09 Acceptance Verification:
- **Evidence-Backed Timeline with Provenance:** Chronological events preserve original timestamp, original timezone, timezone status (`EXPLICIT_UTC`, `EXPLICIT_OFFSET`, `UNKNOWN_AMBIGUOUS`, `NO_TIMESTAMP`), normalized UTC timestamp, timestamp source, precision (`100ns`, `microseconds`, `milliseconds`, `seconds`), and clock uncertainty.
- **Non-Invention & No Silent Assumptions:** Findings lacking timestamps do not fabricate timestamps; naive timestamps without timezone offsets are explicitly marked `UNKNOWN_AMBIGUOUS` with clock uncertainty rather than assumed UTC.
- **Deterministic Correlation Records:** Formulates structured correlation records (`DeterministicCorrelationRecord`) binding correlation ID, case ID, relationship type, source finding IDs, source hashes, entity identifiers, method, supporting/conflicting observations, temporal window, and limitations.
- **Bounded Patient Zero Assessment:** Prohibits naive patient zero attribution solely from earliest timestamp. Requires explicit initial access telemetry (phishing lure, macro, web shell, external ingress, exploit). Honestly reports `patient_zero_status = "UNDETERMINED_INSUFFICIENT_EVIDENCE"` and logs data gaps when telemetry begins post-compromise.
- **Evidence Conflict Handling Without Suppression:** Detects causality inversions, conflicting usernames on identical processes/timestamps, conflicting host/IP mappings, duplicate observations, missing artifacts, and telemetry gaps > 24 hours. Contradictory observations are preserved in `evidence_conflicts` and rendered in reports and UI.
- **Independent Citation Enforcement:** `CitationGuard` validates all claims prior to report creation; ungrounded or invalid claims are quarantined in `rejected_claims` and recorded as conflicts; strict mode raises `CitationValidationError`.
- **Custody Verification Fail-Closed:** Chain of custody verification never defaults to True (`tamper_check_passed` defaults to False). Corrupted or missing custody chains flag the report as `blocked` or `incomplete` and expose discrepancies.
- **Report Finalization Gated by Phase 08 Human Approval:** Autonomous generation produces versioned drafts; final release or signing requires a cryptographically verified `HumanApprovalToken` (`action_type = "report_finalization_or_signing"`) signed by `lead_investigator` or `soc_analyst`. Computes canonical report digest (`sha256:...`), consumes the approval token (replay protection), and records `REPORT_FINALIZED_AND_SIGNED` in the custody ledger.
- **Thread-Safe SQLite Report Store & REST API:** Manages version history and drafts in `forensic_reports` SQLite table with endpoints `GET /api/reports/{case_id}`, `POST /api/reports/compile`, `POST /api/reports/{report_id}/finalize`, and `GET /api/reports/{case_id}/history`.
- **Full Test Suite:** 279 / 279 tests passed (100% green in 36.37s).
- **Frontend Build:** Built cleanly with 0 type errors in 396ms.

### Outstanding Risks & Known Limitations (Tracked for Future Phases):
1. **Clock Skew Cross-Host Calibration:** Timeline windowing relies on endpoint time reporting; if evidence sources lack NTP synchronization, manual or automated clock-skew compensation offsets may be required during intake.
2. **Key Management in Distributed Deployments:** For multi-node or cloud-connected deployments, the `APPROVAL_SECRET_KEY` and JWT secrets must be managed via centralized KMS or Vault secrets rather than local environment variables.

---

## 13. Phase 14.1 Completion Verification & Next Phase Prerequisites

### Phase 14.1 Acceptance Verification:
- **AUDIT-P13-01 Remediated:** Remote collection tokens strictly require a non-empty target host matching `target.host`. `ssh_collector.py` unconditionally calls `token.verify(..., expected_target=target.host)`. Wildcard or unbound tokens are rejected prior to network transport.
- **AUDIT-P13-02 Remediated:** Two-Person authorization decoupling enforced. Client request body cannot provide or spoof `requesting_investigator`. Requester identity is bound immutably from Investigator A's authenticated session, and approver identity is bound strictly from Investigator B's authenticated JWT session. Self-approval and AI controller self-approval are rejected.
- **AUDIT-P13-03 Remediated:** Fail-closed token persistence. Exceptions during approval registration in SQLite are no longer swallowed; failures return HTTP 500 and prevent token issuance.
- **Decoupled Workflow Approval Architecture:** Direct token manufacturing (`INSERT OR REPLACE ... status='approved'`) deleted from `POST /api/workflows/approval-token`. The endpoint requires a pre-existing pending or approved request in `ApprovalEngine`.
- **Concurrency & Replay Defense:** Mutex synchronization (`self._lock`) and transactional primary key checks protect `ApprovalEngine` against concurrent token consumption and replay attacks.
- **Regression Test Coverage:** 25 dedicated security tests in `backend/tests/test_phase14_1_approval_security.py` covering all required test suites (100% green).
- **Security & Collector Suite:** 72 / 72 passed across all security modules (`test_phase14_1`, `test_phase13`, `test_phase12`, `test_phase5`, `test_phase10`).
- **Total Test Suite:** 353 / 353 passed (100% green).
- **Frontend Build:** Built cleanly with 0 type errors and 0 warnings in 406ms.

### Outstanding Risks & Known Limitations (Tracked for Future Phases):
1. **SEC-NET-002 (DNS Rebinding TOCTOU):** Pre-flight URL validation resolves DNS, but HTTP clients re-resolve hostnames upon connection. IP-pinned custom transport scheduled for Phase 14.2.
2. **SEC-UI-001 (Plaintext Credentials in Frontend):** `sessionStorage` credential persistence in wizard components scheduled for remediation in Phase 14.2 / Phase 15.
3. **DEFECT-FOR-02 (Registry Hive Parsing):** Pure-Python registry parser is header-only; full cell tree and subkey extraction scheduled for Phase 14.2.
4. **DEFECT-ARC-01 (TypeScript Interface Alignment):** Investigation and finding TypeScript interfaces need synchronization with Pydantic schemas in Phase 14.2 / Phase 15.

---

## 14. Exact Next Phase: Phase 14.2

### Phase 14.2 — Network Rebinding, Frontend Credential Sanitization & Deep Parser Integration
**Objective:** Remediate remaining High-priority findings from the roadmap (`SEC-NET-002`, `SEC-UI-001`, `DEFECT-FOR-02`, `DEFECT-ARC-01`).
**Prerequisites:** Phase 14.1 approval security and token architecture fully verified with 100% green tests (all satisfied).
**Scope:**
1. Pin resolved IP addresses in outbound transport (`SEC-NET-002`) to prevent DNS rebinding TOCTOU attacks.
2. Scrub sensitive credentials from frontend `sessionStorage` wizard state (`SEC-UI-001`).
3. Expand registry parser beyond header-only stub to extract cell trees, keys, and values (`DEFECT-FOR-02`).
4. Synchronize TypeScript data contracts with Pydantic backend models (`DEFECT-ARC-01`).

*Per AGENTS.md permanent engineering contract, Phase 14.2 will NOT start automatically and requires explicit user authorization.*
