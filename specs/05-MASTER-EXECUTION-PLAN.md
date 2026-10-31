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
