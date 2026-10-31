# ForensicOps AI — Project Overview & Data Contracts

## 1. System Vision
ForensicOps AI combines deterministic forensic parsers (`Dissect`, Chainsaw, Eric Zimmerman Tools, Volatility 3, YARA) with an n8n-style goal-driven workflow engine (LangGraph + React Flow) and a citation-verified Local LLM (Ollama).

## 2. Three-Mode Intake Architecture
1. **Offline Mode:** Accepts individual artifacts (`.pcap`, `.evtx`, Registry `.hiv`, RAM `.raw`/`.lime`), Collector `.zip`/`.tar.gz` capsules containing `manifest.json`, or zero-copy read-only local path references (`:ro`) to large `.E01`/`.vmdk` disk images.
2. **Online Endpoint Mode:** Connects via SSH or WinRM (after a Human Approval Gate) to run headless RFC 3227 collectors (`Invoke-ForensicCollector.ps1` for Windows, `collect_linux_triage.sh` for Linux) and retrieves the hashed `manifest.json` capsule.
3. **Hybrid SIEM Mode:** Read-only query connectors for **Elasticsearch**, **Wazuh**, and **Splunk** that normalize SIEM search hits directly into `ForensicFinding` records with SHA-256 query-snapshot hashes.

## 3. Core Pydantic v2 Data Models (`backend/app/models/`)
- `ArtifactRecord` (`custody.py`): `artifact_id`, `case_id`, `type`, `original_path`, `blob_path`, `size_bytes`, `sha256`, `sha512`, `acquired_utc`, `acquisition_method`.
- `CustodyChainEntry` (`custody.py`): `seq_id`, `case_id`, `timestamp_utc`, `actor`, `action`, `artifact_sha256`, `tool_id`, `prev_hash`, `entry_hash`.
- `ForensicFinding` (`findings.py`): `finding_id`, `case_id`, `source_artifact_id`, `source_artifact_hash`, `tool_id`, `timestamp_utc`, `artifact_type`, `category`, `event_id`, `severity`, `host`, `user`, `process_name`, `command_line`, `raw_reference`, `summary`, `projected_data` (high-signal columns for AI), `raw_data_path`.
- `CitedClaim` (`findings.py`): `claim_id`, `claim_type` (`observed_fact`, `derived_correlation`, `hypothesis`, `recommendation`), `statement`, `citing_finding_ids` (non-empty for facts/correlations), `source_artifact_hashes`, `confidence`, `why_it_matters`, `benign_alternative`, `verification_steps`, `data_gaps`.
