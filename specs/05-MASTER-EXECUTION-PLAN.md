# ForensicOps AI — Master Execution Plan for Antigravity IDE (`05-MASTER-EXECUTION-PLAN.md`)

## Instructions for Antigravity IDE / CLI (`agy`)
We are building **ForensicOps AI**. Before writing code for any phase, read ONLY `AGENTS.md` and the specific `specs/0X-*.md` files referenced for that phase so your context window stays clean and focused.

Execute this build in **6 sequential, self-tested phases**. After completing each phase:
1. Run `pytest -v`.
2. Fix any failures autonomously until 100% of tests pass.
3. Update `STATUS.md` with the exact test results, files created/modified, and next phase readiness.
4. Commit the working slice before starting the next phase.

---

### Phase 1: 4-Layer Evidence Sandbox, Capsule Unpacker & Hash-Chained Custody Engine
- **Read First:** `AGENTS.md`, `specs/01-PROJECT-OVERVIEW.md`, `specs/03-SECURITY-AUDIT-AND-THREAT-MODEL.md`
- **Deliverables:**
  1. `pyproject.toml` configured for Python 3.12+, `fastapi`, `uvicorn`, `pydantic>=2.0`, `duckdb`, `httpx`, `pyyaml`, `langgraph`, `pytest`, `pytest-asyncio`.
  2. `backend/app/models/custody.py` & `backend/app/core/custody_engine.py`:
     - Streaming Zip Guard blocking Zip Slip (`..`), symlinks, and decompression bombs.
     - Defanged `.blob` Vault (`vault/blobs/<sha256[:2]>/<sha256>.blob`) with `0400` read-only permissions and zero executable extensions.
     - Zero-copy Read-Only path reference support (`:ro`) for large `.E01`/`.vmdk` images.
     - Collector Capsule unpacker validating every file in `manifest.json` against its SHA-256 and SHA-512 hash.
     - Append-only SQLite/DuckDB `custody_chain` ledger (`entry_hash = sha256(prev_hash + canonical_payload)`) + `audit.jsonl` transparency log.
- **Verification:** Run `pytest backend/tests/test_phase1_custody.py -v` (test valid intake, hash mismatch rejection, Zip Slip blocking, and custody chain tamper detection).

---
### Phase 1.5: JWT Authentication & Multi-User Role-Based Access Control (RBAC)
- **Read First:** `AGENTS.md`, `specs/02-UI-SPECIFICATION.md`, `specs/03-SECURITY-AUDIT-AND-THREAT-MODEL.md`
- **Deliverables:**
  1. `backend/app/auth/models.py`, `backend/app/auth/security.py`, `backend/app/auth/store.py`, `backend/app/auth/dependencies.py`:
     - Three non-overlapping DFIR roles: `lead_investigator`, `soc_analyst`, and `auditor`.
     - Direct `bcrypt` password hashing (with safe 72-byte truncation) + `python-jose` HS256 JWT access token generation and validation.
     - SQLite `users` table (`vault/users.db`) storing `id`, `username`, `badge_id`, `password_hash`, `role`, `full_name`, `is_active`, `created_at`.
     - Fast, dependency-injected `get_current_user` and `require_roles(*allowed_roles)` security guards.
  2. `backend/app/api/auth.py` Router:
     - `GET /api/auth/status`: Returns system setup status (`initialized: bool`, active accounts count).
     - `POST /api/auth/setup`: First-boot Lead Investigator creation (permitted ONLY when `users` table is empty; rejected with HTTP 403 thereafter).
     - `POST /api/auth/login`: Authenticates username or badge_id + password, returns JWT bearer token + investigator metadata.
     - `GET /api/auth/me`: Verifies active JWT session and returns current investigator profile.
     - `GET /api/auth/users`: Lists all investigator accounts (`lead_investigator` only).
     - `POST /api/auth/users`: Creates new `soc_analyst` or `auditor` accounts (`lead_investigator` only).
     - `PATCH /api/auth/users/{user_id}/status`: Activates or suspends an investigator account (`lead_investigator` only).
  3. **Forensic Identity Ledger & Feedback Binding:**
     - In `backend/app/api/intake.py` and workflow executions, inject authenticated user identity into every `CustodyChainEntry` so `actor` is permanently recorded as:
       `f"{user.username} ({user.badge_id}) [{user.role}]"`
     - Update `backend/app/models/feedback.py` & `backend/app/agent/memory_protocol.py` (`human_feedback` SQLite table) to store `badge_id`, `analyst_role`, and `analyst_username`.
     - In `POST /api/feedback`, auto-populate `badge_id`, `analyst_role`, and `analyst_username` from `current_user`.
  4. **Frontend AuthGate & RBAC UI (`frontend/src/`):**
     - `frontend/src/types/auth.ts`: Data types for user profiles, roles, and auth tokens.
     - `frontend/src/context/AuthContext.tsx`: React Context provider managing JWT storage, active investigator session, case assignment, and sign-out.
     - `frontend/src/components/AuthGate.tsx`: First-Boot Lead Account creation form OR Investigator Login Card with Badge ID/Username + Password, followed by Case Selection.
     - `frontend/src/components/UserManagementModal.tsx`: Account creation and suspension modal for Lead Investigators.
     - `frontend/src/components/Navbar.tsx`: Top Navigation Identity Bar showing Badge ID, Role chip (`LEAD`, `SOC ANALYST`, `AUDITOR`), Manage Users button, and Sign Out.
     - Role-Aware UI Guards across `WorkflowCanvas.tsx` (disable node editing & hide "Run Workflow" for `auditor`; gate online collection for `soc_analyst`) and `CitedReportViewer.tsx`.
- **Verification:** Run `pytest backend/tests/test_phase1_5_auth_rbac.py -v` (testing first-boot setup, login, JWT validation, role-based 403 blocks, custody actor chaining, and feedback identity tracking).

### Phase 2: Two-Tier Parsing (`Dissect` + YAML Tool Adapters), Dry-Run Auto-Mapper & Column Projection
- **Read First:** `AGENTS.md`, `specs/03-SECURITY-AUDIT-AND-THREAT-MODEL.md`, `specs/04-TOOL-ADAPTERS-AND-WORKFLOW.md`
- **Deliverables:**
  1. `backend/app/models/plugins.py`, `backend/app/models/findings.py`, `backend/app/core/plugin_runner.py`.
  2. Pre-built YAML Tool Cards in `plugins/` for `ez_evtxecmd.yaml`, `ez_recmd.yaml`, `chainsaw_sigma.yaml`, `volatility3_pslist.yaml`, and `yara_scanner.yaml`.
  3. Built-in pure-Python `Dissect` / fallback adapter for offline disk images, `.evtx`, Registry, and collector JSONL/JSON artifacts.
  4. Air-gapped subprocess/container execution wrapper (`shell=False`, `--network=none`, `--read-only` input mount).
  5. Smart Column Projection (`ai_keep_fields`) stripping noisy metadata while logging exact before/after column and row counts in `audit.jsonl`.
  6. Visual Tool Dry-Run Auto-Mapper service that inspects 5 sample rows from a new tool and suggests `field_map` + `ai_keep_fields` automatically.
- **Verification:** Run `pytest backend/tests/test_phase2_plugins.py -v`.

---

### Phase 3: Dual Forensic Store, Local Ollama Client, `CitationGuard` & v2.0 RAG/Learning Hooks
- **Read First:** `AGENTS.md`, `specs/03-SECURITY-AUDIT-AND-THREAT-MODEL.md`, `specs/04-TOOL-ADAPTERS-AND-WORKFLOW.md`
- **Deliverables:**
  1. `backend/app/core/storage.py`: DuckDB/SQLite indexed `ForensicFinding` store + hybrid keyword/semantic search.
  2. `backend/app/models/feedback.py` & `backend/app/agent/memory_protocol.py`:
     - Define `NodeExecutionTrace`, `HumanFeedbackRecord`, and the pluggable `KnowledgeAndMemoryProvider` Protocol (`get_benign_baselines`, `get_similar_successful_traces`, `retrieve_dfir_domain_knowledge`, `record_human_feedback`).
     - Implement `SQLiteFeedbackMemoryProvider` as the default MVP provider so v2.0 Qdrant RAG swaps in with zero refactoring.
  3. `backend/app/agent/ollama_client.py` & `backend/app/core/citation_guard.py`:
     - Local Ollama structured output client enforcing `NodeGoalResult` JSON schema.
     - `<untrusted_evidence_data nonce="...">` Indirect Prompt Injection (IPI) wrapper.
     - `CitationGuard` deterministic post-validator rejecting any claim whose `citing_finding_ids` or `source_artifact_hashes` do not exist in `storage`.
- **Verification:** Run `pytest backend/tests/test_phase3_storage_and_llm.py -v`.

---

### Phase 4: Context-Passing LangGraph Workflow Engine & Cited Report Builder (with AIFT Rubric)
- **Read First:** `AGENTS.md`, `specs/04-TOOL-ADAPTERS-AND-WORKFLOW.md`
- **Deliverables:**
  1. `backend/app/models/workflow.py`, `backend/app/agent/tools.py`, `backend/app/agent/graph.py`:
     - LangGraph engine executing DAG workflows where edges pass lightweight `WorkflowEdgePayload` objects (`dataset_pointer` + extracted `pivots` like `compromised_users`, `source_ips`, `pivot_timestamps_utc`, `file_paths`).
     - Built-in Starter Workflow Blueprints (Windows Intrusion, Full Windows Triage, Linux SSH Compromise, Memory+PCAP Hunt).
     - Human Approval Gate node support (`interrupt_before` / token verification).
  2. `backend/app/agent/report_builder.py`:
     - Compiles verified node outputs into the 6-section Cited Report featuring AIFT's 4-Part Rubric (`why_it_matters`, `benign_alternative`, `verification_steps`, `data_gaps`) and Multi-Host "Patient Zero" correlation.
- **Verification:** Run `pytest backend/tests/test_phase4_workflow_agent.py -v`.

---

### Phase 5: Online SSH/WinRM Collector Orchestrator & Hybrid SIEM Connectors
- **Read First:** `AGENTS.md`, `specs/01-PROJECT-OVERVIEW.md`, `specs/03-SECURITY-AUDIT-AND-THREAT-MODEL.md`
- **Deliverables:**
  1. `backend/app/connectors/ssh_collector.py`: Deploys `collectors/windows/Invoke-ForensicCollector.ps1` or `collectors/linux/collect_linux_triage.sh` only after verifying a valid `HumanApprovalToken`, retrieves the capsule, and feeds it into Phase 1 Custody Intake.
  2. `backend/app/connectors/siem_connectors.py`: Read-only query adapters for **Elasticsearch**, **Wazuh**, and **Splunk** normalizing hits into `ForensicFinding` records with SHA-256 query-snapshot hashes.
- **Verification:** Run `pytest backend/tests/test_phase5_connectors.py -v`.

---

### Phase 6: FastAPI REST/SSE API & React Flow n8n-Style Web Application
- **Read First:** `AGENTS.md`, `specs/02-UI-SPECIFICATION.md`
- **Deliverables:**
  1. `backend/app/api/` & `backend/app/main.py`: Endpoints for Wizard Intake, Plugin Dry-Run & Registration, Workflow Execution (with SSE node state streaming), Report Retrieval, and Human Feedback submission (`POST /api/feedback`).
  2. `frontend/`: React + TypeScript + Tailwind + React Flow UI implementing `EnvironmentWizard.tsx`, `WorkflowCanvas.tsx`, `PluginManagerModal.tsx`, and `CitedReportViewer.tsx` (complete with clickable SHA-256 citation drawers and v2.0 `[👍 Confirm TP]` / `[🛡️ Mark Benign Baseline]` / `[✏️ Correct Query]` feedback buttons).
- **Verification:** Run full backend test suite (`pytest -v`) and frontend build verification (`npm run build`).
