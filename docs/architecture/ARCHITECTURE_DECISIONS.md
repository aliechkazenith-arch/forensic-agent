# ForensicOps AI — Architecture Decision Records (`ARCHITECTURE_DECISIONS.md`)

**Document Reference:** `docs/architecture/ARCHITECTURE_DECISIONS.md`  
**Current Status:** Phase 0 Architecture Decision Records  
**Date:** 2026-11-16  
**Auditor / Engineering Swarm:** ForensicOps AI Core Engineering Swarm (@analyst, @architect, @forensics, @security, @qa, @docs)  
**Governing Standard:** RFC 3227, ISO/IEC 27037, NIST SP 800-86, AGENTS.md Permanent Engineering Contract  

---

## Table of Contents

- [ADR-001: SQLite + DuckDB Dual Storage Engine (over PostgreSQL / Qdrant)](#adr-001-sqlite--duckdb-dual-storage-engine-over-postgresql--qdrant)
- [ADR-002: Non-Mounting Flat Userspace Evidence Parsing (over Kernel Mounting)](#adr-002-non-mounting-flat-userspace-evidence-parsing-over-kernel-mounting)
- [ADR-003: Subprocess & OCI Container Tool Sandbox (over Direct Host Shell Execution)](#adr-003-subprocess--oci-container-tool-sandbox-over-direct-host-shell-execution)
- [ADR-004: Lightweight Context-Passing Orchestration (`WorkflowEdgePayload`)](#adr-004-lightweight-context-passing-orchestration-workflowedgepayload)
- [ADR-005: Dual Orchestration Strategy (LangGraph DAGs + Autonomous Investigation Controller)](#adr-005-dual-orchestration-strategy-langgraph-dags--autonomous-investigation-controller)
- [ADR-006: Deterministic Citation Enforcement (`CitationGuard`) & Anti-IPI Nonce Delimiters](#adr-006-deterministic-citation-enforcement-citationguard--anti-ipi-nonce-delimiters)
- [ADR-007: Cryptographic Hash-Chained Chain of Custody (RFC 3227 & RFC 8785)](#adr-007-cryptographic-hash-chained-chain-of-custody-rfc-3227--rfc-8785)
- [ADR-008: Operation-Specific Human Approval Gate (HMAC-SHA256 Token Binding)](#adr-008-operation-specific-human-approval-gate-hmac-sha256-token-binding)
- [ADR-009: Smart Column Projection (`ai_keep_fields`) with Full Raw Output Retention](#adr-009-smart-column-projection-ai_keep_fields-with-full-raw-output-retention)
- [ADR-010: Ephemeral Browser Storage & Zero LocalStorage Forensic Artifact Caching](#adr-010-ephemeral-browser-storage--zero-localstorage-forensic-artifact-caching)

---

### ADR-001: SQLite + DuckDB Dual Storage Engine (over PostgreSQL / Qdrant)

#### Status
**ACCEPTED**

#### Context
A digital forensics investigation generates two distinct classes of data:
1. **Transactional Platform Metadata:** User authentication credentials, case records, active investigator sessions, human approval requests, and audit logs.
2. **High-Volume Analytical Findings:** Heterogeneous security events extracted from event logs, memory captures, network traces, and file systems, often numbering in the hundreds of thousands of rows per investigation.

Traditional enterprise architectures often introduce external client-server databases such as PostgreSQL for relational data, Redis for caching, and Qdrant or Milvus for vector embeddings. However, ForensicOps AI is designed as a local-first, air-gapped forensic platform capable of running on portable investigator laptops, ruggedized field tablets, or isolated triage workstations without external service dependencies.

#### Decision
We adopt an embedded dual-store architecture utilizing:
- **DuckDB** as the isolated analytical finding database per case (`vault/<case_id>/findings.duckdb`).
- **SQLite3** as the local transactional metadata and custody store (`vault/users.db`, `vault/custody.db`, `vault/reports.db`, `vault/feedback_memory.db`).

We explicitly prohibit introducing PostgreSQL, Redis, Qdrant, or external containerized database servers.

#### Consequences
- **Positive:**
  - Zero external deployment dependencies; runs out-of-the-box on standard Python runtimes.
  - Complete case isolation: each case has its own DuckDB file that can be archived, backed up, or transferred independently.
  - Exceptional analytical query performance: DuckDB's vectorized columnar execution executes aggregations and timeline queries across 1,000,000+ findings in milliseconds.
  - Built-in crash consistency via SQLite `conn.backup()` and SQLite/DuckDB ACID transactions.
- **Negative:**
  - SQLite requires careful connection lifecycle handling in multi-threaded environments (using short-lived connections and WAL mode).
  - Vector similarity search is implemented via exact mathematical cosine distance or lightweight SQLite extensions rather than a dedicated vector index.

---

### ADR-002: Non-Mounting Flat Userspace Evidence Parsing (over Kernel Mounting)

#### Status
**ACCEPTED**

#### Context
Traditional forensics workflows often mount raw disk images (`.raw`, `.dd`) or forensic containers (`.E01`, `.VMDK`, `.VHD`) onto the host operating system kernel (e.g. using `losetup`, `mount`, or virtual disk services). Mounting evidence to the host kernel introduces substantial risks:
- Malicious or corrupted filesystems can exploit host kernel filesystem driver vulnerabilities.
- The host operating system may inadvertently write metadata (such as `Volume Information`, trash folders, or access times) to the image.
- Mounting requires elevated administrative/root privileges on the host system.

#### Decision
We enforce a strict non-kernel-mounting architecture:
- All baseline disk evidence is parsed strictly in userspace via pure-Python streaming readers (`DissectAdapter`).
- MBR partition tables, GPT headers, EVTX event log chunks, and registry blocks are read directly from flat byte streams.
- Compressed proprietary forensic containers (`.E01`, `.VMDK`) are rejected at the boundary with clear instructions requiring conversion to raw flat streams before intake.

#### Consequences
- **Positive:**
  - Preserves absolute evidence integrity: impossible for the host operating system to alter evidence bytes.
  - Operates completely in non-elevated user space without root/administrator privileges.
  - Immune to host kernel filesystem driver exploits.
- **Negative:**
  - Full NTFS file extraction and MFT traversal are limited in pure-Python Tier A; complex filesystem extraction requires containerized Tier B tools.

---

### ADR-003: Subprocess & OCI Container Tool Sandbox (over Direct Host Shell Execution)

#### Status
**ACCEPTED**

#### Context
Forensic analysis requires executing specialized third-party forensic tools (such as Eric Zimmerman's EZ-Tools, Chainsaw, Volatility 3, and YARA). Running third-party tools directly on the host with shell execution (`shell=True`) exposes the investigator machine to arbitrary command execution, argument injection, and unauthorized network egress.

#### Decision
We enforce a strict two-tier sandboxed execution architecture via `PluginRunner` and `ExecutionPolicyRegistry`:
- Subprocesses strictly use `shell=False` with argv argument lists; shell metacharacters (`&`, `;`, `|`, `` ` ``, `$`) are rejected during argument validation.
- Tool containers run with `--network=none` to enforce total network denial.
- Evidence files are mounted read-only (`:ro`).
- Subprocess execution enforces explicit timeouts (default 120s–300s) with recursive process-tree termination.

#### Consequences
- **Positive:**
  - Absolute defense against command injection and network data exfiltration by third-party tools.
  - Guaranteed process isolation and bounded resource consumption.
- **Negative:**
  - Requires container runtimes (Docker/Podman) for Tier B plugins when running outside Linux environments.
  - Requires explicit in-container path translation (`/evidence:ro`, `/scratch:rw`).

---

### ADR-004: Lightweight Context-Passing Orchestration (`WorkflowEdgePayload`)

#### Status
**ACCEPTED**

#### Context
In complex multi-stage forensic workflows, nodes frequently process tens of thousands of findings. Passing full dataframes or lists of raw finding records across workflow edges causes excessive memory overhead, slow serialization, and potential message broker bottlenecks.

#### Decision
We implement a lightweight context-passing model using `WorkflowEdgePayload`:
- Workflow edges carry only a lightweight pointer to the DuckDB view or table (`dataset_pointer`) and a compact list of discovered entity pivots (`compromised_users`, `source_ips`, `pivot_timestamps_utc`, `file_paths`).
- Downstream nodes execute targeted DuckDB SQL queries against the dataset pointer filtered by the extracted pivots.

#### Consequences
- **Positive:**
  - Workflow edge payloads remain minuscule (< 5 KB) regardless of the number of findings.
  - Eliminates redundant inter-process data copying and serialization overhead.
  - Downstream specialist nodes query only relevant findings deterministically.
- **Negative:**
  - Nodes must share access to the same underlying per-case DuckDB instance.

---

### ADR-005: Dual Orchestration Strategy (LangGraph DAGs + Autonomous Investigation Controller)

#### Status
**ACCEPTED**

#### Context
Investigators encounter two distinct operational scenarios:
1. **Analyst-Directed Playbook Execution:** A known incident type (e.g. ransomware, phishing triage) where the investigator wants a structured, predictable DAG workflow visualized on an interactive canvas.
2. **Autonomous Goal-Seeking Investigation:** An open-ended investigation where an autonomous agent must inspect initial artifacts, formulate hypotheses, identify evidence gaps, and iteratively request specialist analysis within finite execution budgets.

#### Decision
We implement and maintain two complementary orchestration engines:
- **LangGraph Directed Acyclic Graph (DAG) Engine (`backend/app/agent/graph.py`):** Compiles visual node-and-edge workflows for interactive execution, SSE node streaming, and manual approval pauses.
- **Autonomous Investigation Controller (`backend/app/agent/investigation_controller.py`):** An iterative Finite State Machine (`created` $\to$ `evidence_validation` $\to$ `planning` $\to$ `executing` $\to$ `evaluating` $\to$ `awaiting_approval` $\to$ `completed`) that explores evidence autonomously, maintains competing hypotheses, tracks evidence gaps, and pauses for human authorization.

#### Consequences
- **Positive:**
  - Accommodates both structured SOC analyst workflows and autonomous deep-dive investigations.
  - Both engines share the same underlying Pydantic findings models, custody ledger, and specialist registries.
- **Negative:**
  - Requires ongoing maintenance of two orchestration surfaces; method signatures and tool calls must remain strictly synchronized.

---

### ADR-006: Deterministic Citation Enforcement (`CitationGuard`) & Anti-IPI Nonce Delimiters

#### Status
**ACCEPTED**

#### Context
Large Language Models exhibit hallucinations (fabricating log lines, events, or timestamps) and are vulnerable to Indirect Prompt Injection (IPI) embedded in attacker-controlled log files or malicious binary strings. In a forensic investigation, an unverified LLM claim destroys legal defensibility.

#### Decision
We establish a two-layer defense architecture:
1. **Anti-IPI Nonce Boundaries:** All evidence text supplied to LLM prompts is wrapped in cryptographic nonce envelopes (`<untrusted_evidence_data nonce="...">`). The model instructions forbid treating content inside this tag as instructions.
2. **Deterministic Citation Enforcement (`CitationGuard`):** Every claim emitted by the LLM must be categorized as `observed_fact`, `derived_fact`, or `derived_correlation` and cite valid `finding_id` values and source artifact hashes. `CitationGuard` verifies these citations directly against DuckDB, discarding or flagging any unverified assertions.

#### Consequences
- **Positive:**
  - Eliminates fabricated or hallucinated facts from final reports.
  - Guarantees forensic defensibility: every sentence in a report traces directly to verified tool findings on disk.
- **Negative:**
  - Requires LLMs capable of following strict JSON Schema structured output.
  - Claims that fail validation are stripped, potentially requiring retry iterations.

---

### ADR-007: Cryptographic Hash-Chained Chain of Custody (RFC 3227 & RFC 8785)

#### Status
**ACCEPTED**

#### Context
Digital forensics standards (RFC 3227, ISO/IEC 27037) require an unbroken, tamper-evident record of all evidence handling, tool executions, and analytical steps. A standard relational database table allows undetectable modifications or deletions if the database file is compromised.

#### Decision
We implement a cryptographically hash-chained custody ledger in SQLite (`custody_chain` table):
- Every entry computes:
  $$\text{entry\_hash} = \text{SHA-256}(\text{prev\_hash} + \text{canonical\_json}(\text{entry\_payload}))$$
- Payloads are serialized using RFC 8785 canonical JSON sorting to eliminate whitespace or key ordering discrepancies.
- Genesis entries link to a fixed 64-zero initial hash.
- The report builder and verification APIs verify the complete chain before generating or signing reports.

#### Consequences
- **Positive:**
  - Any unauthorized modification, insertion, or deletion of a custody record invalidates all subsequent hashes, immediately exposing tampering.
  - Fully compliant with RFC 3227 legal chain of custody requirements.
- **Negative:**
  - Ledger cannot be modified retrospectively; corrections must be recorded as append-only superseding events.

---

### ADR-008: Operation-Specific Human Approval Gate (HMAC-SHA256 Token Binding)

#### Status
**ACCEPTED**

#### Context
An autonomous AI agent must never perform sensitive, destructive, or external operations without human authorization. Simple boolean approval flags (e.g. `approved: true`) are vulnerable to parameter tampering, replay attacks, or model self-authorization.

#### Decision
We implement an operation-specific cryptographic approval gate:
- Operations classified as `HIGH_RISK_SENSITIVE` or `CRITICAL_MUTATION` (such as live remote endpoint collection, external network calls, remediation commands, or final report signing) halt execution and generate an `ApprovalRequest`.
- A human investigator authorizes the action via the UI, generating a `HumanApprovalToken`.
- The token is signed using `HMAC-SHA256` with `HUMAN_APPROVAL_HMAC_SECRET` and cryptographically binds:
  - `case_id`
  - `action_type`
  - `target`
  - `parameter_digest` (SHA-256 of canonical action parameters)
- Tokens have strict expiration times and are consumed atomically in SQLite to prevent replay.

#### Consequences
- **Positive:**
  - Prevents agent self-authorization and parameter tampering.
  - Eliminates replay attacks: a token issued for one host or parameter set cannot be re-used for another.
- **Negative:**
  - Introduces latency: autonomous investigations must pause until an authorized human signs the token.

---

### ADR-009: Smart Column Projection (`ai_keep_fields`) with Full Raw Output Retention

#### Status
**ACCEPTED**

#### Context
Forensic tools output dozens of system metadata columns (e.g. EvtxECmd outputs 30+ columns per event). Sending raw tables to an LLM quickly exhausts context windows and degrades model attention. However, stripping raw data from the disk destroys forensic defensibility.

#### Decision
We implement smart column projection via `ColumnProjector`:
- 100% of raw forensic outputs are retained on disk in their original format.
- High-signal columns designated by `ai_keep_fields` are projected into `ForensicFinding.projected_data` for model consumption.
- Exact before-and-after column and row counts are recorded in `audit.jsonl`.

#### Consequences
- **Positive:**
  - Reduces LLM token consumption by approximately 70% while improving reasoning focus.
  - Retains complete forensic defensibility: original raw outputs remain available on disk for manual inspection.
- **Negative:**
  - Requires maintaining curated `ai_keep_fields` definitions across all tool cards.

---

### ADR-010: Ephemeral Browser Storage & Zero LocalStorage Forensic Artifact Caching

#### Status
**ACCEPTED**

#### Context
Browser `localStorage` persists indefinitely across browser sessions and is accessible to any script executing in the same origin. Storing sensitive authentication tokens or forensic evidence metadata in `localStorage` leaves sensitive investigative artifacts exposed on shared workstations.

#### Decision
We enforce an ephemeral browser storage policy:
- Authentication tokens are stored exclusively in `sessionStorage` or in-memory React state.
- `localStorage.removeItem("forensicops_token")` is executed on login, logout, and token refresh.
- Finding details, evidence payloads, and investigation notes are stored solely in React component memory and cleared upon tab closure.

#### Consequences
- **Positive:**
  - Eliminates cross-session data leakage and forensic residue on client workstations.
  - Meets strict healthcare, enterprise, and law enforcement privacy standards.
- **Negative:**
  - Closing a browser tab clears the active session, requiring investigators to re-authenticate.
