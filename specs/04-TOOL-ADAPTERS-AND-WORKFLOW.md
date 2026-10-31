# ForensicOps AI — Tool Adapters, Workflow Engine & v2.0 RAG/Learning Hooks

## 1. Two-Tier Parsing & Smart Column Projection
- **Tier A (Built-In Pure Python `Dissect`):** Extracts 60 Windows and 44 Linux baseline artifacts directly from `.E01`, `.vmdk`, or triage capsules with zero external binary dependencies.
- **Tier B (Declarative YAML Tool Adapters):** Runs Chainsaw (Sigma), Eric Zimmerman EZ Tools (`EvtxECmd`, `RECmd`, `PECmd`, `AmcacheParser`), Volatility 3 (`-r json`), YARA, and Tshark/Zeek.
- **Smart Column Projection (`ai_keep_fields`):** Saves 100% of raw output to disk while projecting only high-signal columns into `ForensicFinding.projected_data`, cutting LLM token usage by ~70%.

## 2. Context-Passing LangGraph Workflow Engine
- Workflow edges never carry multi-megabyte raw row arrays. Instead, edges pass a `WorkflowEdgePayload`:
  - `dataset_pointer`: Queryable DuckDB/SQLite view ID.
  - `pivots`: Extracted forensic entities (`compromised_users`, `source_ips`, `pivot_timestamps_utc`, `file_paths`, `process_names`, `verified_finding_ids`).
- Downstream `ai_goal_step` nodes automatically use incoming `pivots` to scope their deterministic SQL (`query_structured_findings`), timeline (`get_timeline_window`), and hybrid search calls.

## 3. Built-In Scalability Hooks for v2.0 (RAG, Episodic Learning & Human Feedback)
To ensure upgrading from MVP (v1.0) to the Self-Learning RAG Agent (v2.0) requires **zero refactoring** of LangGraph nodes, FastAPI routes, or UI components, implement these three contracts in the MVP:

### A. Feedback & Trace Persistence (`backend/app/models/feedback.py`)
- `NodeExecutionTrace`: Automatically logs `trace_id`, `case_id`, `node_id`, `user_goal`, `incoming_pivots`, `executed_queries`, `cited_finding_ids`, and `human_rating`.
- `HumanFeedbackRecord`: Captures analyst feedback from the UI (`true_positive`, `false_positive_benign_baseline`, `query_correction`), `analyst_note`, `entity_pattern`, and `scope` (`this_case_only`, `organization_baseline`, `global_playbook`).

### B. Pluggable `KnowledgeAndMemoryProvider` Protocol (`backend/app/agent/memory_protocol.py`)
Every LangGraph Goal Node receives an injected `KnowledgeAndMemoryProvider` interface with four async methods:
1. `get_benign_baselines(org_id, artifact_type, entities) -> list[dict]` *(Suppresses known org false positives learned from human feedback — never cross-contaminates attacker facts across cases).*
2. `get_similar_successful_traces(user_goal, artifact_types, top_k=3) -> list[dict]` *(Episodic Few-Shot Learning: injects past human-approved Goal -> Query strategies).*
3. `retrieve_dfir_domain_knowledge(query, artifact_type, top_k=5) -> list[str]` *(Offline DFIR RAG over MITRE ATT&CK, LOLBAS, GTFOBins, and Event ID cheat sheets).*
4. `record_human_feedback(feedback: HumanFeedbackRecord) -> None`
- **MVP Default:** `SQLiteFeedbackMemoryProvider` (stores all traces/feedback in SQLite and performs fast keyword matching).
- **v2.0 Drop-In Upgrade:** Swap `QdrantHybridRAGMemoryProvider` in `config.py` with zero changes to the rest of the codebase.
