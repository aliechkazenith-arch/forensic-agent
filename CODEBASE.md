# ForensicOps AI — Codebase Map & Directory Guide

This document provides a concise, structured breakdown of every file in the **ForensicOps AI** codebase and its specific role.

---

## 1. Project Root & Configuration

| File | Purpose |
| :--- | :--- |
| [`AGENTS.md`](file:///c:/forensicops-ai/AGENTS.md) | Permanent engineering instructions, forensic principles (RFC 3227, non-mounting sandbox, zero shell interpolation), and workflow rules. |
| [`STATUS.md`](file:///c:/forensicops-ai/STATUS.md) | Living status tracker recording completed phases, test suite results (100% green), and security fixes. |
| [`audit.md`](file:///c:/forensicops-ai/audit.md) | High-level summary of security audit findings and verification status. |
| [`pyproject.toml`](file:///c:/forensicops-ai/pyproject.toml) | Python project packaging, dependencies, tool configurations (`pytest`, `ruff`), and build metadata. |
| [`.env`](file:///c:/forensicops-ai/.env) | Environment variable definitions (JWT secrets, LLM API keys, server ports). |
| [`.gitignore`](file:///c:/forensicops-ai/.gitignore) | Git ignore rules excluding virtual environments, vault caches, temporary blobs, and logs. |

---

## 2. Backend Application (`backend/app/`)

### Core Entry & Settings
- [`backend/app/main.py`](file:///c:/forensicops-ai/backend/app/main.py) — FastAPI application entrypoint; registers CORS, exception handlers, and mounts all API routers.
- [`backend/app/core/config.py`](file:///c:/forensicops-ai/backend/app/core/config.py) — Centralized configuration using Pydantic Settings (`AppConfig`), managing paths, secrets, and environment defaults.
- [`backend/app/core/exceptions.py`](file:///c:/forensicops-ai/backend/app/core/exceptions.py) — Custom platform exceptions (e.g., `CustodyTamperError`, `SecurityBoundaryError`).

### Chain of Custody, Storage & Parsers (`backend/app/core/`)
- [`backend/app/core/custody_engine.py`](file:///c:/forensicops-ai/backend/app/core/custody_engine.py) — RFC 3227 append-only hash-chained ledger engine (`custody.db`) computing SHA-256 links (`prev_hash` $\to$ `entry_hash`).
- [`backend/app/core/storage.py`](file:///c:/forensicops-ai/backend/app/core/storage.py) — Forensic storage layer (`ForensicStore`) managing isolated DuckDB instances and defanged `.blob` storage (`0400` read-only).
- [`backend/app/core/dissect_adapter.py`](file:///c:/forensicops-ai/backend/app/core/dissect_adapter.py) — Flat userspace evidence parser utilizing `dissect` and `python-evtx` to extract forensic events without mounting disk images on host kernel.
- [`backend/app/core/playbook_registry.py`](file:///c:/forensicops-ai/backend/app/core/playbook_registry.py) — Complete 14-tactic MITRE ATT&CK Enterprise playbook registry (`TA0001` - `TA0043`), mapping tactics to exact artifact globs, deterministic parsers, and `ScopedFilterParams`.
- [`backend/app/core/artifact_indexer.py`](file:///c:/forensicops-ai/backend/app/core/artifact_indexer.py) — Target OS & artifact indexer for Windows, Linux, and PCAP artifacts; cross-references playbook steps to mark missing artifacts as `SKIPPED_NO_ARTIFACT`.
- [`backend/app/core/auto_mapper.py`](file:///c:/forensicops-ai/backend/app/core/auto_mapper.py) — Normalization engine mapping heterogeneous tool outputs to standard forensic finding records.
- [`backend/app/core/citation_guard.py`](file:///c:/forensicops-ai/backend/app/core/citation_guard.py) — Verification guard ensuring every LLM-generated claim strictly cites a verified `finding_id` and artifact hash.
- [`backend/app/core/column_projector.py`](file:///c:/forensicops-ai/backend/app/core/column_projector.py) — Dynamic query projector and schema filter for DuckDB analytical queries.
- [`backend/app/core/plugin_runner.py`](file:///c:/forensicops-ai/backend/app/core/plugin_runner.py) — Sandboxed external tool runner enforcing `shell=False`, read-only mounts, and air-gapped process execution.

### Authentication & RBAC (`backend/app/auth/`)
- [`backend/app/auth/dependencies.py`](file:///c:/forensicops-ai/backend/app/auth/dependencies.py) — FastAPI route dependencies verifying JWT bearer tokens and enforcing role permissions (`lead_investigator`, `analyst`, `observer`).
- [`backend/app/auth/models.py`](file:///c:/forensicops-ai/backend/app/auth/models.py) — Pydantic schemas for authentication requests, tokens, and user credentials.
- [`backend/app/auth/security.py`](file:///c:/forensicops-ai/backend/app/auth/security.py) — Cryptographic utilities: password hashing (bcrypt), JWT creation/validation, and HMAC signature verification.
- [`backend/app/auth/store.py`](file:///c:/forensicops-ai/backend/app/auth/store.py) — SQLite user store persisting user accounts, hashed credentials, and role assignments.

### Agent, Planning & LLM Orchestration (`backend/app/agent/`)
- [`backend/app/agent/graph.py`](file:///c:/forensicops-ai/backend/app/agent/graph.py) — LangGraph state machine compiling and executing investigative DAG workflows; supports converting `DeterministicGoalPlan` to workflows and handling `SKIPPED_NO_ARTIFACT` nodes.
- [`backend/app/agent/hypothesis_planner.py`](file:///c:/forensicops-ai/backend/app/agent/hypothesis_planner.py) — Deterministic, Playbook-Constrained Goal Engine executing standard MITRE playbooks with `auto_approve` toggle and `ScopedFilterParams`.
- [`backend/app/agent/provider_registry.py`](file:///c:/forensicops-ai/backend/app/agent/provider_registry.py) — Unified registry managing local and cloud LLM providers (Ollama, LM Studio, NVIDIA NIM, OpenRouter, Gemini).
- [`backend/app/agent/lmstudio_client.py`](file:///c:/forensicops-ai/backend/app/agent/lmstudio_client.py) — Connector for local LM Studio instances.
- [`backend/app/agent/ollama_client.py`](file:///c:/forensicops-ai/backend/app/agent/ollama_client.py) — Connector for local Ollama instances.
- [`backend/app/agent/prompts.py`](file:///c:/forensicops-ai/backend/app/agent/prompts.py) — System prompts and indirect prompt injection defense boundaries (`<untrusted_evidence_data nonce="...">`).
- [`backend/app/agent/report_builder.py`](file:///c:/forensicops-ai/backend/app/agent/report_builder.py) — RFC 3227 forensic report generator producing 6-section cited investigative reports.
- [`backend/app/agent/tools.py`](file:///c:/forensicops-ai/backend/app/agent/tools.py) — Agent tool functions for DuckDB analytical queries, Scope 4B `apply_scoped_filters`, native PCAP stream parsing, and Linux log parsing.
- [`backend/app/agent/memory_protocol.py`](file:///c:/forensicops-ai/backend/app/agent/memory_protocol.py) — Conversation history and working memory protocol for agent sessions.

### Connectors (`backend/app/connectors/`)
- [`backend/app/connectors/siem_connectors.py`](file:///c:/forensicops-ai/backend/app/connectors/siem_connectors.py) — Read-only connectors for external SIEM / data stores (Elasticsearch, Splunk).
- [`backend/app/connectors/ssh_collector.py`](file:///c:/forensicops-ai/backend/app/connectors/ssh_collector.py) — Remote live-triage collector (SSH/WinRM) guarded by human approval token verification.

### API Endpoints (`backend/app/api/`)
- [`backend/app/api/auth.py`](file:///c:/forensicops-ai/backend/app/api/auth.py) — Login, token renewal, user registration, and profile endpoints.
- [`backend/app/api/cases.py`](file:///c:/forensicops-ai/backend/app/api/cases.py) — Forensic case CRUD, status management, and active case selection.
- [`backend/app/api/intake.py`](file:///c:/forensicops-ai/backend/app/api/intake.py) — Evidence ingestion API: upload validation, hashing, defanging into `.blob`, and zero-copy intake.
- [`backend/app/api/findings.py`](file:///c:/forensicops-ai/backend/app/api/findings.py) — Query and filter normalized forensic findings stored in DuckDB.
- [`backend/app/api/plugins.py`](file:///c:/forensicops-ai/backend/app/api/plugins.py) — List, test, and invoke external forensic tool plugins.
- [`backend/app/api/workflows.py`](file:///c:/forensicops-ai/backend/app/api/workflows.py) — Manage DAG workflows, stream real-time execution via SSE, and issue HMAC approval tokens.
- [`backend/app/api/agent.py`](file:///c:/forensicops-ai/backend/app/api/agent.py) — Trigger automated hypothesis planning and agent reasoning runs.
- [`backend/app/api/copilot.py`](file:///c:/forensicops-ai/backend/app/api/copilot.py) — Technical DFIR Co-pilot interactive Q&A endpoint with evidence citation enforcement.
- [`backend/app/api/llm.py`](file:///c:/forensicops-ai/backend/app/api/llm.py) — Configure LLM providers, test connections, and select active models.
- [`backend/app/api/reports.py`](file:///c:/forensicops-ai/backend/app/api/reports.py) — Generate, download, and verify integrity of RFC 3227 forensic reports.
- [`backend/app/api/session.py`](file:///c:/forensicops-ai/backend/app/api/session.py) — Active investigation session management and state persistence.
- [`backend/app/api/feedback.py`](file:///c:/forensicops-ai/backend/app/api/feedback.py) — Collect investigator ratings and feedback on LLM outputs.
- [`backend/app/api/deps.py`](file:///c:/forensicops-ai/backend/app/api/deps.py) — Common FastAPI dependency providers (case scope, database sessions).

### Data Models & Schemas (`backend/app/models/` & `backend/app/db/`)
- [`backend/app/models/cases.py`](file:///c:/forensicops-ai/backend/app/models/cases.py) — Case schemas and metadata models.
- [`backend/app/models/custody.py`](file:///c:/forensicops-ai/backend/app/models/custody.py) — Chain of custody entry, hash verification, and log models.
- [`backend/app/models/findings.py`](file:///c:/forensicops-ai/backend/app/models/findings.py) — Standardized finding record model (host, timestamps, MITRE ATT&CK mapping).
- [`backend/app/models/plugins.py`](file:///c:/forensicops-ai/backend/app/models/plugins.py) — Declarative YAML plugin manifest definitions.
- [`backend/app/models/workflow.py`](file:///c:/forensicops-ai/backend/app/models/workflow.py) — Workflow graph nodes, edges, states, and execution step schemas.
- [`backend/app/models/connectors.py`](file:///c:/forensicops-ai/backend/app/models/connectors.py) — SIEM and remote collection configuration schemas.
- [`backend/app/models/feedback.py`](file:///c:/forensicops-ai/backend/app/models/feedback.py) — Feedback and rating data models.
- [`backend/app/db/sqlite_store.py`](file:///c:/forensicops-ai/backend/app/db/sqlite_store.py) — SQLite interface for platform metadata and application records.

---

## 3. Backend Test Suite (`backend/tests/`)

- [`backend/tests/conftest.py`](file:///c:/forensicops-ai/backend/tests/conftest.py) — Shared pytest fixtures (temporary isolated vaults, mock cases, authenticated clients).
- [`backend/tests/test_attack_scenario_evtx.py`](file:///c:/forensicops-ai/backend/tests/test_attack_scenario_evtx.py) — End-to-end integration test running real EVTX samples (credential dumping & lateral movement) through ingestion, hypothesis generation, and report building.
- [`backend/tests/test_agent_hypothesis_planner.py`](file:///c:/forensicops-ai/backend/tests/test_agent_hypothesis_planner.py) — Validates dual-hypothesis formulation and blueprint inference.
- [`backend/tests/test_case_manager_and_vault.py`](file:///c:/forensicops-ai/backend/tests/test_case_manager_and_vault.py) — Tests case creation, data isolation, and `.blob` evidence defanging.
- [`backend/tests/test_copilot_chat.py`](file:///c:/forensicops-ai/backend/tests/test_copilot_chat.py) — Tests DFIR Co-pilot interactive chat and prompt injection protections.
- [`backend/tests/test_phase1_custody.py`](file:///c:/forensicops-ai/backend/tests/test_phase1_custody.py) — Tests RFC 3227 hash chaining and tamper detection.
- [`backend/tests/test_phase1_5_auth_rbac.py`](file:///c:/forensicops-ai/backend/tests/test_phase1_5_auth_rbac.py) — Tests user authentication, password hashing, and RBAC enforcement.
- [`backend/tests/test_phase2_plugins.py`](file:///c:/forensicops-ai/backend/tests/test_phase2_plugins.py) — Tests plugin manifest parsing and sandbox runner isolation.
- [`backend/tests/test_phase3_storage_and_llm.py`](file:///c:/forensicops-ai/backend/tests/test_phase3_storage_and_llm.py) — Tests DuckDB analytical storage and LLM provider interfaces.
- [`backend/tests/test_phase4_workflow_agent.py`](file:///c:/forensicops-ai/backend/tests/test_phase4_workflow_agent.py) — Tests LangGraph DAG execution and state transitions.
- [`backend/tests/test_phase5_connectors.py`](file:///c:/forensicops-ai/backend/tests/test_phase5_connectors.py) — Tests SIEM queries and SSH remote collection with HMAC approval tokens.
- [`backend/tests/test_phase6_api.py`](file:///c:/forensicops-ai/backend/tests/test_phase6_api.py) — Tests REST endpoints and HTTP status codes.
- [`backend/tests/test_phase7_llm_registry.py`](file:///c:/forensicops-ai/backend/tests/test_phase7_llm_registry.py) — Tests multi-provider connectivity tests and model listings.
- [`backend/tests/test_phase7_llm_persistence.py`](file:///c:/forensicops-ai/backend/tests/test_phase7_llm_persistence.py) — Tests persistence and reloading of user LLM configurations.
- [`backend/tests/test_phase8_intake_upload.py`](file:///c:/forensicops-ai/backend/tests/test_phase8_intake_upload.py) — Tests evidence file upload, defanging, and duplicate detection.
- [`backend/tests/test_security_audit_fixes.py`](file:///c:/forensicops-ai/backend/tests/test_security_audit_fixes.py) — Regression tests for previously identified security findings.
- [`backend/tests/test_security_hardening.py`](file:///c:/forensicops-ai/backend/tests/test_security_hardening.py) — Verifies input validation, path traversal defense, and header hardening.
- [`backend/tests/test_stabilization_plan.py`](file:///c:/forensicops-ai/backend/tests/test_stabilization_plan.py) — Comprehensive regression suite ensuring cross-component stability.

---

## 4. Frontend Application (`frontend/src/`)

### Core Application & State
- [`frontend/src/App.tsx`](file:///c:/forensicops-ai/frontend/src/App.tsx) — Main React container with view navigation (Canvas, Vault, Reports, Copilot, Settings).
- [`frontend/src/main.tsx`](file:///c:/forensicops-ai/frontend/src/main.tsx) — React DOM mounting root with context providers.
- [`frontend/src/store/useForensicStore.ts`](file:///c:/forensicops-ai/frontend/src/store/useForensicStore.ts) — Zustand global store managing active case, workflow graph state, findings, and drawer visibility.
- [`frontend/src/services/api.ts`](file:///c:/forensicops-ai/frontend/src/services/api.ts) — HTTP client and SSE streaming helper for interacting with backend API routes.
- [`frontend/src/context/AuthContext.tsx`](file:///c:/forensicops-ai/frontend/src/context/AuthContext.tsx) — React context providing authenticated user info, login/logout, and role checks.
- [`frontend/src/context/InvestigationContext.tsx`](file:///c:/forensicops-ai/frontend/src/context/InvestigationContext.tsx) — Context coordinating active case findings and live analysis state.

### React Components (`frontend/src/components/`)
- [`frontend/src/components/Navbar.tsx`](file:///c:/forensicops-ai/frontend/src/components/Navbar.tsx) — Header bar with case switcher, system health badge, user profile, and view tabs.
- [`frontend/src/components/WorkflowCanvas.tsx`](file:///c:/forensicops-ai/frontend/src/components/WorkflowCanvas.tsx) — ReactFlow-based interactive canvas for orchestrating and executing forensic DAGs.
- [`frontend/src/components/ForensicNode.tsx`](file:///c:/forensicops-ai/frontend/src/components/ForensicNode.tsx) — Custom canvas node showing tool name, execution status, and finding counts.
- [`frontend/src/components/PivotEdge.tsx`](file:///c:/forensicops-ai/frontend/src/components/PivotEdge.tsx) — Custom graph edge displaying pivot relationships and data flow between nodes.
- [`frontend/src/components/CaseVaultView.tsx`](file:///c:/forensicops-ai/frontend/src/components/CaseVaultView.tsx) — Evidence intake and management view: upload zone, hash list, and defanged `.blob` explorer.
- [`frontend/src/components/CaseManagerView.tsx`](file:///c:/forensicops-ai/frontend/src/components/CaseManagerView.tsx) — Case management dashboard to create, switch, and archive forensic cases.
- [`frontend/src/components/CitedReportViewer.tsx`](file:///c:/forensicops-ai/frontend/src/components/CitedReportViewer.tsx) — Report viewer with clickable evidence citations linked to source facts.
- [`frontend/src/components/CitationDrawer.tsx`](file:///c:/forensicops-ai/frontend/src/components/CitationDrawer.tsx) — Slide-out drawer displaying verified raw finding details when a report citation is clicked.
- [`frontend/src/components/ForensicCopilotDrawer.tsx`](file:///c:/forensicops-ai/frontend/src/components/ForensicCopilotDrawer.tsx) — Interactive DFIR Co-pilot chat assistant with citation enforcement.
- [`frontend/src/components/CustodyLedgerModal.tsx`](file:///c:/forensicops-ai/frontend/src/components/CustodyLedgerModal.tsx) — Modal rendering the tamper-evident RFC 3227 hash-chained custody log.
- [`frontend/src/components/EnvironmentWizard.tsx`](file:///c:/forensicops-ai/frontend/src/components/EnvironmentWizard.tsx) — Configuration wizard for selecting local/cloud LLMs and verifying tool binaries.
- [`frontend/src/components/PluginsView.tsx`](file:///c:/forensicops-ai/frontend/src/components/PluginsView.tsx) — Management screen showing installed tool plugins and adapter definitions.
- [`frontend/src/components/PluginManagerModal.tsx`](file:///c:/forensicops-ai/frontend/src/components/PluginManagerModal.tsx) — Dialog to inspect plugin manifests and test execution sandboxes.
- [`frontend/src/components/UserManagementModal.tsx`](file:///c:/forensicops-ai/frontend/src/components/UserManagementModal.tsx) — Admin modal for creating user accounts and managing RBAC privileges.
- [`frontend/src/components/AuthGate.tsx`](file:///c:/forensicops-ai/frontend/src/components/AuthGate.tsx) — Modal barrier requesting login/registration when an unauthenticated session is detected.

### Types & Frontend Config
- [`frontend/src/types/index.ts`](file:///c:/forensicops-ai/frontend/src/types/index.ts) — TypeScript definitions for cases, nodes, edges, findings, and plugins.
- [`frontend/src/types/auth.ts`](file:///c:/forensicops-ai/frontend/src/types/auth.ts) — TypeScript definitions for authentication tokens and user roles.
- [`frontend/package.json`](file:///c:/forensicops-ai/frontend/package.json) — Frontend dependencies, scripts (`dev`, `build`, `lint`), and dev dependencies.
- [`frontend/vite.config.ts`](file:///c:/forensicops-ai/frontend/vite.config.ts) — Vite bundler setup and `/api` proxy configuration.

---

## 5. Tool Adapters & Plugins (`plugins/`)

- [`plugins/chainsaw_sigma.yaml`](file:///c:/forensicops-ai/plugins/chainsaw_sigma.yaml) — Adapter for Chainsaw, running Sigma rules against Windows EVTX logs.
- [`plugins/ez_evtxecmd.yaml`](file:///c:/forensicops-ai/plugins/ez_evtxecmd.yaml) — Adapter for Eric Zimmerman's EvtxECmd event log parser.
- [`plugins/ez_recmd.yaml`](file:///c:/forensicops-ai/plugins/ez_recmd.yaml) — Adapter for Eric Zimmerman's RECmd Windows Registry parser.
- [`plugins/volatility3_pslist.yaml`](file:///c:/forensicops-ai/plugins/volatility3_pslist.yaml) — Adapter for Volatility 3 memory analysis (`windows.pslist.PsList`).
- [`plugins/yara_scanner.yaml`](file:///c:/forensicops-ai/plugins/yara_scanner.yaml) — Adapter for YARA scanning across filesystem targets and memory dumps.

---

## 6. Remote Triage Collectors (`collectors/`)

- [`collectors/windows/Invoke-ForensicCollector.ps1`](file:///c:/forensicops-ai/collectors/windows/Invoke-ForensicCollector.ps1) — PowerShell script for collecting volatile triage data (processes, network connections, autoruns, security logs).
- [`collectors/linux/collect_linux_triage.sh`](file:///c:/forensicops-ai/collectors/linux/collect_linux_triage.sh) — Bash script for capturing Linux live triage data (process list, open sockets, system logs, memory info).

---

## 7. Specifications & Security Audits (`specs/` & `audits/`)

### Technical Specifications (`specs/`)
- [`specs/01-PROJECT-OVERVIEW.md`](file:///c:/forensicops-ai/specs/01-PROJECT-OVERVIEW.md) — Platform vision, local-first architecture, and forensic principles.
- [`specs/02-UI-SPECIFICATION.md`](file:///c:/forensicops-ai/specs/02-UI-SPECIFICATION.md) — Design system specifications, React component layout, and canvas interaction patterns.
- [`specs/03-SECURITY-AUDIT-AND-THREAT-MODEL.md`](file:///c:/forensicops-ai/specs/03-SECURITY-AUDIT-AND-THREAT-MODEL.md) — Threat model, IPI defense, sandboxing constraints, and forensic boundary rules.
- [`specs/04-TOOL-ADAPTERS-AND-WORKFLOW.md`](file:///c:/forensicops-ai/specs/04-TOOL-ADAPTERS-AND-WORKFLOW.md) — Tool plugin specification, DAG execution model, and data mapping definitions.
- [`specs/05-MASTER-EXECUTION-PLAN.md`](file:///c:/forensicops-ai/specs/05-MASTER-EXECUTION-PLAN.md) — Step-by-step master plan with milestones across all phases.

### Security Audits & PoCs (`audits/`)
- [`audits/SECURITY_AUDIT_REPORT.md`](file:///c:/forensicops-ai/audits/SECURITY_AUDIT_REPORT.md) — Detailed security vulnerability audit report.
- [`audits/findings.json`](file:///c:/forensicops-ai/audits/findings.json) — Structured vulnerability findings registry.
- [`audits/poc/`](file:///c:/forensicops-ai/audits/poc) — Reproducible vulnerability test scripts validating security hardening (token forgery, custody bypass, arbitrary file read prevention).

---

## 8. Test Suite (`backend/tests/`)

- [`backend/tests/test_goal_playbook_engine.py`](file:///c:/forensicops-ai/backend/tests/test_goal_playbook_engine.py) — Verification suite for Scopes 1C, 2C (14 MITRE tactics), 3B (Auto-Execution & HITL pause), and 4B (ScopedFilterParams & Scoped Sweep).
- [`backend/tests/test_agent_hypothesis_planner.py`](file:///c:/forensicops-ai/backend/tests/test_agent_hypothesis_planner.py) — Tests for hypothesis planning, blueprint inference, HITL pause, and scoped filter routing.
- [`backend/tests/test_phase4_workflow_agent.py`](file:///c:/forensicops-ai/backend/tests/test_phase4_workflow_agent.py) — Tests for LangGraph workflow execution, blueprint DAGs, CitationGuard, AIFT rubric, and `SKIPPED_NO_ARTIFACT` handling.
- [`backend/tests/test_attack_scenario_evtx.py`](file:///c:/forensicops-ai/backend/tests/test_attack_scenario_evtx.py) — Full end-to-end scenario lifecycle with real Sysmon EVTX evidence files and fuzzing.
- [`backend/tests/test_phase6_api.py`](file:///c:/forensicops-ai/backend/tests/test_phase6_api.py) — REST and SSE streaming API integration tests.
- [`backend/tests/test_security_audit_fixes.py`](file:///c:/forensicops-ai/backend/tests/test_security_audit_fixes.py) — Security vulnerability regression test suite.

