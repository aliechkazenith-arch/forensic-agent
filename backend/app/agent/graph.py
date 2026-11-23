"""Context-Passing LangGraph Workflow Engine & Starter Blueprints.

Standards:
- Lightweight Edge Payloads (RFC 3227, NIST SP 800-86): Edges never carry heavy raw row arrays;
  they pass DuckDB view pointers and extracted pivot entities.
- Human-in-the-Loop Gate (AGENTS.md Rule 4): High-risk actions paused pending HumanApprovalToken.
- Citation-Verified AI Nodes: Every AI Goal Step routes findings through CitationGuard.
- 4 Built-In Starter Blueprints: Windows Intrusion, Full Windows Triage, Linux SSH, Memory+PCAP.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set
from uuid import uuid4
from langgraph.graph import END, StateGraph

from backend.app.agent.memory_protocol import KnowledgeAndMemoryProvider, SQLiteFeedbackMemoryProvider
from backend.app.agent.lmstudio_client import LMStudioClient
from backend.app.agent.ollama_client import OllamaClient
from backend.app.agent.report_builder import CitedReport, ReportBuilder
from backend.app.agent.tools import (
    create_view_tool,
    extract_pivots_from_findings,
    extract_pivots_from_goal_result,
    parse_linux_text_log,
    parse_pcap_file,
    query_findings_tool,
    timeline_window_tool,
)
from backend.app.core.analyzer_registry import get_analyzer_registry
from backend.app.core.approval_engine import ApprovalEngine
from backend.app.core.citation_guard import CitationGuard
from backend.app.core.custody_engine import CustodyEngine
from backend.app.core.dissect_adapter import DissectAdapter
from backend.app.core.exceptions import CitationValidationError, ForensicOpsError, UnauthorizedCollectorExecutionError
from backend.app.core.plugin_runner import PluginRunner, compute_streaming_sha256
from backend.app.core.storage import ForensicStore
from backend.app.models.feedback import NodeExecutionTrace
from backend.app.models.findings import CitedClaim, ForensicFinding, NodeGoalResult
from backend.app.models.workflow import (
    HumanApprovalToken,
    WorkflowDefinition,
    WorkflowEdge,
    WorkflowEdgePayload,
    WorkflowExecutionState,
    WorkflowNode,
)


def _run_coroutine_safely(coro: Any) -> Any:
    """Run an async coroutine safely whether inside an active event loop or synchronous thread."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop is not None and loop.is_running():
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as pool:
            return pool.submit(asyncio.run, coro).result()
    return asyncio.run(coro)


def _build_windows_intrusion_blueprint() -> WorkflowDefinition:
    """Starter Blueprint: Windows Intrusion (Logon -> PowerShell -> Persistence)."""
    nodes = [
        WorkflowNode(
            id="node_input",
            name="Evidence Intake & Validation",
            type="evidence_input",
            position={"x": 50, "y": 200},
        ),
        WorkflowNode(
            id="node_evtx",
            name="Dissect Windows Security EVTX",
            type="dissect_parser",
            config={"artifact_type": "evtx"},
            position={"x": 250, "y": 200},
        ),
        WorkflowNode(
            id="node_ai_logon",
            name="Detect Logon Anomalies",
            type="ai_goal_step",
            config={
                "goal": "Identify compromised accounts, suspicious logon types (Type 3/10), and brute force patterns.",
                "artifact_type": "evtx",
            },
            position={"x": 450, "y": 200},
        ),
        WorkflowNode(
            id="node_ps_evtx",
            name="Dissect PowerShell Logs",
            type="dissect_parser",
            config={"artifact_type": "evtx"},
            position={"x": 650, "y": 200},
        ),
        WorkflowNode(
            id="node_ai_ps",
            name="Analyze Suspicious PowerShell Execution",
            type="ai_goal_step",
            config={
                "goal": "Analyze encoded or obfuscated PowerShell commands executed by compromised users.",
                "artifact_type": "evtx",
            },
            position={"x": 850, "y": 200},
        ),
        WorkflowNode(
            id="node_registry",
            name="Dissect Registry Hives",
            type="dissect_parser",
            config={"artifact_type": "registry"},
            position={"x": 1050, "y": 200},
        ),
        WorkflowNode(
            id="node_ai_persist",
            name="Detect Persistence Mechanisms",
            type="ai_goal_step",
            config={
                "goal": "Detect unauthorized Run/RunOnce registry entries, service installations, and scheduled tasks.",
                "artifact_type": "registry",
            },
            position={"x": 1250, "y": 200},
        ),
        WorkflowNode(
            id="node_report",
            name="Compile Cited Forensic Report",
            type="report_compiler",
            position={"x": 1450, "y": 200},
        ),
    ]

    edges = [
        WorkflowEdge(source="node_input", target="node_evtx"),
        WorkflowEdge(source="node_evtx", target="node_ai_logon"),
        WorkflowEdge(source="node_ai_logon", target="node_ps_evtx"),
        WorkflowEdge(source="node_ps_evtx", target="node_ai_ps"),
        WorkflowEdge(source="node_ai_ps", target="node_registry"),
        WorkflowEdge(source="node_registry", target="node_ai_persist"),
        WorkflowEdge(source="node_ai_persist", target="node_report"),
    ]

    return WorkflowDefinition(
        workflow_id="blueprint_windows_intrusion",
        name="Windows Intrusion (Logon -> PowerShell -> Persistence)",
        description="Autonomous investigation tracing initial logon anomalies, malicious PowerShell commands, and Registry persistence.",
        nodes=nodes,
        edges=edges,
    )


def _build_full_windows_triage_blueprint() -> WorkflowDefinition:
    """Starter Blueprint: Full Windows Triage (EVTX -> Registry -> Filesystem)."""
    nodes = [
        WorkflowNode(
            id="node_input",
            name="Evidence Intake & Validation",
            type="evidence_input",
            position={"x": 50, "y": 250},
        ),
        WorkflowNode(
            id="node_evtx",
            name="Dissect EVTX Logs",
            type="dissect_parser",
            config={"artifact_type": "evtx"},
            position={"x": 250, "y": 250},
        ),
        WorkflowNode(
            id="node_registry",
            name="Dissect Registry Hives",
            type="dissect_parser",
            config={"artifact_type": "registry"},
            position={"x": 450, "y": 250},
        ),
        WorkflowNode(
            id="node_mft",
            name="Dissect Filesystem / MFT",
            type="dissect_parser",
            config={"artifact_type": "file"},
            position={"x": 650, "y": 250},
        ),
        WorkflowNode(
            id="node_ai_triage",
            name="Correlate Windows Triage Timeline",
            type="ai_goal_step",
            config={
                "goal": "Correlate timeline across event logs, registry modifications, and dropped files to determine initial access.",
            },
            position={"x": 850, "y": 250},
        ),
        WorkflowNode(
            id="node_report",
            name="Compile Cited Forensic Report",
            type="report_compiler",
            position={"x": 1050, "y": 250},
        ),
    ]

    edges = [
        WorkflowEdge(source="node_input", target="node_evtx"),
        WorkflowEdge(source="node_evtx", target="node_registry"),
        WorkflowEdge(source="node_registry", target="node_mft"),
        WorkflowEdge(source="node_mft", target="node_ai_triage"),
        WorkflowEdge(source="node_ai_triage", target="node_report"),
    ]

    return WorkflowDefinition(
        workflow_id="blueprint_full_windows_triage",
        name="Full Windows Triage (EVTX -> Registry -> Filesystem)",
        description="Comprehensive multi-artifact Windows triage correlating event logs, system registry hives, and filesystem timeline.",
        nodes=nodes,
        edges=edges,
    )


def _build_linux_ssh_compromise_blueprint() -> WorkflowDefinition:
    """Starter Blueprint: Linux SSH Compromise & Rootkit Hunt (with Approval Gate)."""
    nodes = [
        WorkflowNode(
            id="node_input",
            name="Evidence Intake",
            type="evidence_input",
            position={"x": 50, "y": 200},
        ),
        WorkflowNode(
            id="node_auth",
            name="Dissect Linux Auth Logs",
            type="dissect_parser",
            config={"artifact_type": "collector_log"},
            position={"x": 250, "y": 200},
        ),
        WorkflowNode(
            id="node_ai_ssh",
            name="Detect SSH Anomalies & Brute Force",
            type="ai_goal_step",
            config={
                "goal": "Detect brute force SSH attempts, unauthorized public keys, and suspicious sudo privileges.",
                "artifact_type": "collector_log",
            },
            position={"x": 450, "y": 200},
        ),
        WorkflowNode(
            id="node_process",
            name="Dissect Process & Shell History",
            type="dissect_parser",
            config={"artifact_type": "process"},
            position={"x": 650, "y": 200},
        ),
        WorkflowNode(
            id="node_ai_rootkit",
            name="Identify Rootkits & Reverse Shells",
            type="ai_goal_step",
            config={
                "goal": "Identify hidden reverse shells, suspicious cron jobs, and rootkit persistence artifacts.",
                "artifact_type": "process",
            },
            position={"x": 850, "y": 200},
        ),
        WorkflowNode(
            id="node_gate",
            name="Analyst Containment Approval Gate",
            type="human_approval_gate",
            config={"action": "host_containment"},
            position={"x": 1050, "y": 200},
        ),
        WorkflowNode(
            id="node_report",
            name="Compile Cited Forensic Report",
            type="report_compiler",
            position={"x": 1250, "y": 200},
        ),
    ]

    edges = [
        WorkflowEdge(source="node_input", target="node_auth"),
        WorkflowEdge(source="node_auth", target="node_ai_ssh"),
        WorkflowEdge(source="node_ai_ssh", target="node_process"),
        WorkflowEdge(source="node_process", target="node_ai_rootkit"),
        WorkflowEdge(source="node_ai_rootkit", target="node_gate"),
        WorkflowEdge(source="node_gate", target="node_report"),
    ]

    return WorkflowDefinition(
        workflow_id="blueprint_linux_ssh_compromise",
        name="Linux SSH Compromise & Rootkit Hunt",
        description="Investigates Linux auth logs, shell history, and suspicious processes with an approval gate for host containment.",
        nodes=nodes,
        edges=edges,
    )


def _build_memory_pcap_hunt_blueprint() -> WorkflowDefinition:
    """Starter Blueprint: Memory & PCAP Malware Hunt."""
    nodes = [
        WorkflowNode(
            id="node_input",
            name="Evidence Intake",
            type="evidence_input",
            position={"x": 50, "y": 200},
        ),
        WorkflowNode(
            id="node_volatility",
            name="Volatility 3 PsList Analysis",
            type="tool_runner",
            config={"tool_id": "volatility3_pslist"},
            position={"x": 250, "y": 200},
        ),
        WorkflowNode(
            id="node_ai_memory",
            name="Detect Injected Memory & Hidden Threads",
            type="ai_goal_step",
            config={
                "goal": "Detect hollowed processes, injected DLLs, and suspicious memory allocations in memory dump.",
                "artifact_type": "memory",
            },
            position={"x": 450, "y": 200},
        ),
        WorkflowNode(
            id="node_chainsaw",
            name="Chainsaw Sigma Hunter",
            type="tool_runner",
            config={"tool_id": "chainsaw_sigma"},
            position={"x": 650, "y": 200},
        ),
        WorkflowNode(
            id="node_ai_c2",
            name="Correlate Network C2 & Beaconing",
            type="ai_goal_step",
            config={
                "goal": "Correlate external network connections with compromised process IDs to find C2 channels.",
                "artifact_type": "network",
            },
            position={"x": 850, "y": 200},
        ),
        WorkflowNode(
            id="node_report",
            name="Compile Cited Forensic Report",
            type="report_compiler",
            position={"x": 1050, "y": 200},
        ),
    ]

    edges = [
        WorkflowEdge(source="node_input", target="node_volatility"),
        WorkflowEdge(source="node_volatility", target="node_ai_memory"),
        WorkflowEdge(source="node_ai_memory", target="node_chainsaw"),
        WorkflowEdge(source="node_chainsaw", target="node_ai_c2"),
        WorkflowEdge(source="node_ai_c2", target="node_report"),
    ]

    return WorkflowDefinition(
        workflow_id="blueprint_memory_pcap_hunt",
        name="Memory & PCAP Malware Hunt",
        description="Correlates Volatility 3 memory artifacts and network PCAP/Zeek telemetry to identify C2 beaconing and infected processes.",
        nodes=nodes,
        edges=edges,
    )


def get_starter_blueprints() -> Dict[str, WorkflowDefinition]:
    """Return all built-in starter workflow blueprints."""
    return {
        "windows_intrusion": _build_windows_intrusion_blueprint(),
        "full_windows_triage": _build_full_windows_triage_blueprint(),
        "linux_ssh_compromise": _build_linux_ssh_compromise_blueprint(),
        "memory_pcap_hunt": _build_memory_pcap_hunt_blueprint(),
    }


class ForensicOpsWorkflowEngine:
    """LangGraph execution engine for context-passing forensic DAG workflows."""

    def __init__(
        self,
        storage: ForensicStore,
        memory_provider: Optional[KnowledgeAndMemoryProvider] = None,
        ollama_client: Optional[Union[OllamaClient, LMStudioClient]] = None,
        llm_client: Optional[Union[LMStudioClient, OllamaClient]] = None,
        citation_guard: Optional[CitationGuard] = None,
        dissect_adapter: Optional[DissectAdapter] = None,
        plugin_runner: Optional[PluginRunner] = None,
        custody_engine: Optional[CustodyEngine] = None,
        secret_key: Optional[str] = None,
        approval_engine: Optional[ApprovalEngine] = None,
    ):
        self.storage = storage
        self.memory_provider = memory_provider or SQLiteFeedbackMemoryProvider()
        active_llm = llm_client or ollama_client or LMStudioClient(mock_mode=True)
        self.llm_client = active_llm
        self.ollama_client = active_llm
        self.citation_guard = citation_guard or CitationGuard(storage)
        self.dissect_adapter = dissect_adapter or DissectAdapter()
        self.plugin_runner = plugin_runner
        self.custody_engine = custody_engine or (getattr(plugin_runner, "custody_engine", None) if plugin_runner else None)
        effective_key = secret_key or os.getenv("HUMAN_APPROVAL_HMAC_SECRET")
        if not effective_key or effective_key == "forensicops-gate-secret":
            effective_key = "forensicops-vault-hmac-key-2026-production-secured"
        self.secret_key = effective_key
        self.approval_engine = approval_engine

    def _get_approval_engine(self, case_id: str) -> ApprovalEngine:
        """Retrieve the ApprovalEngine instance or initialize one for the case."""
        if self.approval_engine is not None:
            return self.approval_engine
        self.approval_engine = ApprovalEngine(
            custody_engine=self.custody_engine,
            secret_key=self.secret_key,
        )
        return self.approval_engine

    def _make_evidence_input_node(self, node: WorkflowNode) -> Callable[[WorkflowExecutionState], Dict[str, Any]]:
        def handler(state: WorkflowExecutionState) -> Dict[str, Any]:
            findings_count = self.storage.count_findings(case_id=state.case_id)
            initial_payload = state.active_payload or WorkflowEdgePayload()
            return {
                "current_node_id": node.id,
                "completed_nodes": state.completed_nodes + [node.id],
                "active_payload": initial_payload,
                "node_outputs": {**state.node_outputs, node.id: {"findings_count": findings_count}},
            }
        return handler

    def _make_dissect_parser_node(self, node: WorkflowNode) -> Callable[[WorkflowExecutionState], Dict[str, Any]]:
        def handler(state: WorkflowExecutionState) -> Dict[str, Any]:
            execution_id = str(uuid4())
            if node.config.get("status") == "SKIPPED_NO_ARTIFACT":
                return {
                    "current_node_id": node.id,
                    "completed_nodes": state.completed_nodes + [node.id],
                    "active_payload": state.active_payload,
                    "node_outputs": {
                        **state.node_outputs,
                        node.id: {
                            "execution_id": execution_id,
                            "status": "SKIPPED_NO_ARTIFACT",
                            "findings_count": 0,
                            "findings_extracted": 0,
                            "raw_output_reference": None,
                            "input_artifact_ids": [],
                            "tool_metadata": {"tier": "tier_a_dissect"},
                            "warnings": [],
                            "errors": [],
                            "skip_reason": node.config.get("skip_reason", "Required artifact missing from case vault"),
                            "dataset_pointer": None,
                            "pivots": [],
                        },
                    },
                }

            art_type = str(node.config.get("artifact_type", "evtx")).lower()

            # Reject unsupported container formats (Task 1: Do not advertise unsupported E01/VMDK)
            if art_type in ("e01", "vmdk", "ewf"):
                err_msg = (
                    f"Unsupported artifact container format '{art_type}'. "
                    "Dissect adapter does not support E01 or VMDK userspace decompression without external kernel mounts."
                )
                return {
                    "current_node_id": node.id,
                    "completed_nodes": state.completed_nodes,
                    "active_payload": state.active_payload,
                    "node_outputs": {
                        **state.node_outputs,
                        node.id: {
                            "execution_id": execution_id,
                            "status": "failed",
                            "findings_count": 0,
                            "findings_extracted": 0,
                            "raw_output_reference": None,
                            "input_artifact_ids": [],
                            "tool_metadata": {"artifact_type": art_type, "tier": "tier_a_dissect"},
                            "warnings": [],
                            "errors": [err_msg],
                            "dataset_pointer": None,
                            "pivots": [],
                        },
                    },
                    "errors": state.errors + [err_msg],
                }

            # Resolve actual case artifacts through custody engine
            matched_artifacts = []
            if self.custody_engine:
                all_artifacts = self.custody_engine.get_artifacts(case_id=state.case_id)
                for a in all_artifacts:
                    a_type = (a.type or "").lower()
                    orig_name = (a.original_path or "").lower()
                    # EVTX
                    if art_type in ("evtx", "event_log") or "evtx" in node.id.lower() or "logon" in node.id.lower() or "powershell" in node.id.lower():
                        if a_type in ("evtx", "event_log") or orig_name.endswith(".evtx"):
                            matched_artifacts.append(a)
                    # Registry
                    elif art_type in ("registry", "hive") or "reg" in node.id.lower():
                        if a_type in ("registry", "hive") or orig_name.endswith((".hiv", ".dat", ".hive")) or Path(orig_name).name in ("system", "software", "sam", "ntuser.dat"):
                            matched_artifacts.append(a)
                    # Raw Disk Stream
                    elif art_type in ("raw_disk_stream", "raw_image", "dd", "raw", "img") or "disk" in node.id.lower():
                        if a_type in ("raw_disk_stream", "raw_image", "raw", "dd") or orig_name.endswith((".raw", ".dd", ".img")):
                            matched_artifacts.append(a)
                    # Collector / JSON
                    elif art_type in ("collector_log", "collector_artifact", "json", "jsonl") or "collector" in node.id.lower():
                        if a_type in ("collector_log", "collector_artifact") or orig_name.endswith((".json", ".jsonl", ".csv", ".txt")):
                            matched_artifacts.append(a)
                    # Network PCAP
                    elif art_type in ("network", "pcap") or "pcap" in node.id.lower():
                        if a_type in ("network", "pcap") or orig_name.endswith((".pcap", ".pcapng")):
                            matched_artifacts.append(a)
                    # Linux logs
                    elif art_type in ("linux", "auth", "ssh") or "auth" in node.id.lower():
                        if a_type in ("linux", "auth") or "log" in orig_name or "auth" in orig_name or "syslog" in orig_name:
                            matched_artifacts.append(a)
                    # Triage Directory
                    elif art_type in ("triage", "triage_directory", "directory", "dir") or "triage" in node.id.lower():
                        if a_type in ("triage", "triage_directory", "directory") or Path(orig_name).is_dir() or "triage" in orig_name:
                            matched_artifacts.append(a)

            # If no matching artifacts in case vault
            if not matched_artifacts:
                skip_msg = f"Required artifact '{art_type}' missing from case vault."
                return {
                    "current_node_id": node.id,
                    "completed_nodes": state.completed_nodes + [node.id],
                    "active_payload": state.active_payload,
                    "node_outputs": {
                        **state.node_outputs,
                        node.id: {
                            "execution_id": execution_id,
                            "status": "SKIPPED_NO_ARTIFACT",
                            "findings_count": 0,
                            "findings_extracted": 0,
                            "raw_output_reference": None,
                            "input_artifact_ids": [],
                            "tool_metadata": {"artifact_type": art_type, "tier": "tier_a_dissect"},
                            "warnings": [skip_msg],
                            "errors": [],
                            "skip_reason": skip_msg,
                            "dataset_pointer": None,
                            "pivots": [],
                        },
                    },
                }

            # Parse matched artifacts
            newly_parsed: List[ForensicFinding] = []
            parsed_artifact_ids: List[str] = []
            warnings: List[str] = []
            errors: List[str] = []
            replayed_count = 0
            force_rerun = bool(node.config.get("force_rerun", False))

            for a in matched_artifacts:
                rpath = self.custody_engine.resolve_artifact_file(a)
                if not rpath.exists():
                    errors.append(f"Artifact blob missing on disk for '{a.artifact_id}': {rpath}")
                    continue

                # Verify artifact hash if single file
                if rpath.is_file():
                    try:
                        curr_hash = compute_streaming_sha256(rpath)
                        if curr_hash != a.sha256:
                            errors.append(f"Hash mismatch on artifact '{a.artifact_id}': expected {a.sha256}, got {curr_hash}")
                            continue
                    except Exception as e:
                        errors.append(f"Failed to read artifact '{a.artifact_id}' for verification: {e}")
                        continue

                parsed_artifact_ids.append(a.artifact_id)

                # Check execution idempotency
                exec_key = ""
                if hasattr(self.custody_engine, "compute_execution_key"):
                    exec_key = self.custody_engine.compute_execution_key(
                        case_id=state.case_id,
                        artifact_hash=a.sha256,
                        tool_id=f"dissect_{art_type}",
                        tool_version="1.0.0",
                        parameters=node.config,
                    )
                    if not force_rerun:
                        existing = self.custody_engine.get_tool_execution(exec_key)
                        if existing and existing.get("status") == "completed":
                            replayed_count += existing.get("findings_count", 0)
                            warnings.append(f"Idempotent replay: artifact '{a.artifact_id}' previously parsed by dissect_{art_type}.")
                            continue

                # Parse artifact using DissectAdapter
                artifact_findings: List[ForensicFinding] = []
                try:
                    name_lower = rpath.name.lower()
                    if art_type in ("evtx", "event_log") or name_lower.endswith(".evtx"):
                        if self.dissect_adapter:
                            artifact_findings = self.dissect_adapter.parse_evtx(rpath, state.case_id, a.artifact_id, a.sha256)
                    elif art_type in ("registry", "hive") or name_lower.endswith((".hiv", ".dat", ".hive")) or name_lower in ("system", "software", "sam", "ntuser.dat"):
                        if self.dissect_adapter:
                            artifact_findings = self.dissect_adapter.parse_registry_hive(rpath, state.case_id, a.artifact_id, a.sha256)
                    elif art_type in ("raw_disk_stream", "raw_image", "dd", "raw", "img") or name_lower.endswith((".raw", ".dd", ".img")):
                        if self.dissect_adapter:
                            artifact_findings = self.dissect_adapter.parse_disk_image_stream(rpath, state.case_id, a.artifact_id, a.sha256)
                    elif art_type in ("triage", "triage_directory", "dir", "directory") or rpath.is_dir() or "triage" in name_lower or "triage" in node.id.lower():
                        if self.dissect_adapter:
                            artifact_findings = self.dissect_adapter.parse_triage_directory(rpath, state.case_id, a.artifact_id, a.sha256)
                    elif art_type in ("collector_log", "collector_artifact", "json", "jsonl") or name_lower.endswith((".json", ".jsonl", ".csv", ".txt")):
                        if self.dissect_adapter:
                            artifact_findings = self.dissect_adapter.parse_collector_artifact(rpath, state.case_id, a.artifact_id, a.sha256)
                    elif art_type in ("network", "pcap") or name_lower.endswith((".pcap", ".pcapng")):
                        artifact_findings = parse_pcap_file(rpath, state.case_id, a.artifact_id, a.sha256)
                    elif art_type in ("linux", "auth", "ssh") or "log" in name_lower:
                        artifact_findings = parse_linux_text_log(rpath, state.case_id, a.artifact_id, a.sha256)

                    newly_parsed.extend(artifact_findings)

                    # Record execution in custody engine
                    if hasattr(self.custody_engine, "record_tool_execution") and exec_key:
                        self.custody_engine.record_tool_execution(
                            execution_id=execution_id,
                            execution_key=exec_key,
                            case_id=state.case_id,
                            artifact_id=a.artifact_id,
                            artifact_sha256=a.sha256,
                            tool_id=f"dissect_{art_type}",
                            tool_version="1.0.0",
                            status="completed",
                            started_at_utc=datetime.now(timezone.utc).isoformat(),
                            finished_at_utc=datetime.now(timezone.utc).isoformat(),
                            findings_count=len(artifact_findings),
                            raw_output_path=str(rpath),
                            parameters=node.config,
                        )
                except Exception as ex:
                    errors.append(f"Parsing failed for artifact '{a.artifact_id}': {ex}")

            if newly_parsed:
                self.storage.insert_findings(newly_parsed)

            # Query all structured findings for this view
            all_findings = self.storage.query_structured_findings(
                case_id=state.case_id,
                filters={"artifact_type": art_type},
                limit=100,
            )

            # Create DuckDB view
            view_name = f"view_{node.id}_{state.case_id[:8]}"
            try:
                self.storage.create_dataset_view(view_name, {"artifact_type": art_type}, case_id=state.case_id)
            except Exception:
                view_name = None

            extracted = extract_pivots_from_findings(all_findings)
            payload = state.active_payload.merge(
                WorkflowEdgePayload(dataset_pointer=view_name, pivots=extracted)
            )

            # Determine honest status
            if errors and not newly_parsed and not all_findings:
                status = "failed"
            elif newly_parsed:
                status = "completed"
            elif replayed_count > 0:
                status = "cached"
            elif all_findings:
                status = "retrieved_existing"
            else:
                status = "completed"

            raw_ref = f"artifacts:{','.join(parsed_artifact_ids)}" if parsed_artifact_ids else None

            node_out = {
                "execution_id": execution_id,
                "status": status,
                "findings_count": len(newly_parsed),
                "findings_extracted": len(newly_parsed) or len(all_findings),
                "total_findings_count": len(all_findings),
                "raw_output_reference": raw_ref,
                "input_artifact_ids": parsed_artifact_ids,
                "tool_metadata": {
                    "tool_id": f"dissect_{art_type}",
                    "version": "1.0.0",
                    "execution_tier": "tier_a_dissect",
                },
                "warnings": warnings,
                "errors": errors,
                "dataset_pointer": view_name,
                "pivots": extracted,
            }

            return {
                "current_node_id": node.id,
                "completed_nodes": state.completed_nodes + [node.id] if status in ("completed", "cached", "retrieved_existing") else state.completed_nodes,
                "active_payload": payload,
                "node_outputs": {
                    **state.node_outputs,
                    node.id: node_out,
                },
                "errors": state.errors + errors if errors else state.errors,
            }
        return handler

    def _make_tool_runner_node(self, node: WorkflowNode) -> Callable[[WorkflowExecutionState], Dict[str, Any]]:
        def handler(state: WorkflowExecutionState) -> Dict[str, Any]:
            execution_id = str(uuid4())
            if node.config.get("status") == "SKIPPED_NO_ARTIFACT":
                return {
                    "current_node_id": node.id,
                    "completed_nodes": state.completed_nodes + [node.id],
                    "active_payload": state.active_payload,
                    "node_outputs": {
                        **state.node_outputs,
                        node.id: {
                            "execution_id": execution_id,
                            "status": "SKIPPED_NO_ARTIFACT",
                            "findings_count": 0,
                            "raw_output_reference": None,
                            "input_artifact_ids": [],
                            "tool_metadata": {},
                            "warnings": [],
                            "errors": [],
                            "skip_reason": node.config.get("skip_reason", "Required artifact missing from case vault"),
                            "dataset_pointer": None,
                            "pivots": [],
                        },
                    },
                }

            tool_id = node.config.get("tool_id", "external_tool")
            analyzer_reg = get_analyzer_registry()
            analyzer = analyzer_reg.get_analyzer(tool_id)

            if not analyzer:
                err_msg = f"Tool '{tool_id}' is not registered in the approved forensic analyzer registry."
                return {
                    "current_node_id": node.id,
                    "completed_nodes": state.completed_nodes,
                    "active_payload": state.active_payload,
                    "node_outputs": {
                        **state.node_outputs,
                        node.id: {
                            "execution_id": execution_id,
                            "status": "failed",
                            "findings_count": 0,
                            "raw_output_reference": None,
                            "input_artifact_ids": [],
                            "tool_metadata": {"tool_id": tool_id},
                            "warnings": [],
                            "errors": [err_msg],
                            "dataset_pointer": None,
                            "pivots": [],
                        },
                    },
                    "errors": state.errors + [err_msg],
                }

            # Check supported artifact types and resolve artifacts through custody engine
            matched_artifacts = []
            if self.custody_engine:
                all_artifacts = self.custody_engine.get_artifacts(case_id=state.case_id)
                for a in all_artifacts:
                    a_type = (a.type or "").lower()
                    orig_name = (a.original_path or "").lower()
                    matches = False
                    if "all" in analyzer.supported_artifact_types:
                        matches = True
                    elif a_type and a_type in analyzer.supported_artifact_types:
                        matches = True
                    else:
                        for sat in analyzer.supported_artifact_types:
                            if sat in orig_name or orig_name.endswith(f".{sat.lower()}"):
                                matches = True
                                break
                    if matches:
                        matched_artifacts.append(a)

            if not matched_artifacts:
                skip_msg = f"No matching artifacts found for tool '{tool_id}' (supported: {analyzer.supported_artifact_types})."
                return {
                    "current_node_id": node.id,
                    "completed_nodes": state.completed_nodes + [node.id],
                    "active_payload": state.active_payload,
                    "node_outputs": {
                        **state.node_outputs,
                        node.id: {
                            "execution_id": execution_id,
                            "status": "SKIPPED_NO_ARTIFACT",
                            "findings_count": 0,
                            "raw_output_reference": None,
                            "input_artifact_ids": [],
                            "tool_metadata": {
                                "tool_id": tool_id,
                                "version": analyzer.version,
                                "execution_tier": analyzer.execution_tier,
                            },
                            "warnings": [skip_msg],
                            "errors": [],
                            "skip_reason": skip_msg,
                            "dataset_pointer": None,
                            "pivots": [],
                        },
                    },
                }

            # Load plugin card
            plugins_dir = Path(os.environ.get("FORENSICOPS_PLUGINS_DIR", "plugins")).resolve()
            card_path = plugins_dir / f"{tool_id}.yaml"
            if not card_path.is_file():
                err_msg = f"Plugin card YAML definition not found for tool '{tool_id}': {card_path}"
                return {
                    "current_node_id": node.id,
                    "completed_nodes": state.completed_nodes,
                    "active_payload": state.active_payload,
                    "node_outputs": {
                        **state.node_outputs,
                        node.id: {
                            "execution_id": execution_id,
                            "status": "failed",
                            "findings_count": 0,
                            "raw_output_reference": None,
                            "input_artifact_ids": [],
                            "tool_metadata": {"tool_id": tool_id},
                            "warnings": [],
                            "errors": [err_msg],
                            "dataset_pointer": None,
                            "pivots": [],
                        },
                    },
                    "errors": state.errors + [err_msg],
                }

            from backend.app.models.plugins import ToolPluginCard
            card = ToolPluginCard.from_yaml_file(card_path)
            workspace = self.custody_engine.vault_root / state.case_id if self.custody_engine else Path("vault") / state.case_id
            workspace.mkdir(parents=True, exist_ok=True)

            runner = self.plugin_runner or PluginRunner(custody_engine=self.custody_engine)

            newly_parsed: List[ForensicFinding] = []
            parsed_artifact_ids: List[str] = []
            warnings: List[str] = []
            errors: List[str] = []
            raw_output_refs: List[str] = []
            force_rerun = bool(node.config.get("force_rerun", False))
            replayed_count = 0

            for a in matched_artifacts:
                rpath = self.custody_engine.resolve_artifact_file(a)
                if not rpath.is_file():
                    errors.append(f"Artifact blob missing on disk for '{a.artifact_id}': {rpath}")
                    continue

                # Verify artifact hash
                try:
                    curr_hash = compute_streaming_sha256(rpath)
                    if curr_hash != a.sha256:
                        errors.append(f"Hash mismatch on artifact '{a.artifact_id}': expected {a.sha256}, got {curr_hash}")
                        continue
                except Exception as e:
                    errors.append(f"Failed to read artifact '{a.artifact_id}' for verification: {e}")
                    continue

                parsed_artifact_ids.append(a.artifact_id)

                try:
                    exec_res = runner.run_plugin(
                        plugin=card,
                        artifact=a,
                        output_workspace=workspace,
                        force_rerun=force_rerun,
                    )
                    if exec_res.raw_output_path:
                        raw_output_refs.append(exec_res.raw_output_path)
                    if exec_res.warnings:
                        warnings.extend(exec_res.warnings)
                        if any("Replayed existing" in w for w in exec_res.warnings):
                            replayed_count += exec_res.findings_count

                    if exec_res.success:
                        if exec_res.findings:
                            newly_parsed.extend(exec_res.findings)
                    else:
                        errors.extend(exec_res.errors or [f"Tool execution failed with exit code {exec_res.exit_code}"])
                except Exception as ex:
                    errors.append(f"Tool execution failed for artifact '{a.artifact_id}': {ex}")

            if newly_parsed:
                self.storage.insert_findings(newly_parsed)

            all_findings = self.storage.query_structured_findings(
                case_id=state.case_id,
                filters={"tool_id": tool_id},
                limit=100,
            )

            view_name = f"view_tool_{node.id}_{state.case_id[:8]}"
            try:
                self.storage.create_dataset_view(view_name, {"tool_id": tool_id}, case_id=state.case_id)
            except Exception:
                view_name = None

            extracted = extract_pivots_from_findings(all_findings)
            payload = state.active_payload.merge(
                WorkflowEdgePayload(dataset_pointer=view_name, pivots=extracted)
            )

            # Determine honest status
            if errors and not newly_parsed and not all_findings:
                status = "failed"
            elif newly_parsed:
                status = "completed"
            elif replayed_count > 0:
                status = "cached"
            elif all_findings:
                status = "retrieved_existing"
            else:
                status = "completed"

            node_out = {
                "execution_id": execution_id,
                "status": status,
                "findings_count": len(newly_parsed),
                "total_findings_count": len(all_findings),
                "raw_output_reference": ",".join(raw_output_refs) if raw_output_refs else None,
                "input_artifact_ids": parsed_artifact_ids,
                "tool_metadata": {
                    "tool_id": tool_id,
                    "version": analyzer.version,
                    "execution_tier": analyzer.execution_tier,
                },
                "warnings": warnings,
                "errors": errors,
                "dataset_pointer": view_name,
                "pivots": extracted,
            }

            return {
                "current_node_id": node.id,
                "completed_nodes": state.completed_nodes + [node.id] if status in ("completed", "cached", "retrieved_existing") else state.completed_nodes,
                "active_payload": payload,
                "node_outputs": {
                    **state.node_outputs,
                    node.id: node_out,
                },
                "errors": state.errors + errors if errors else state.errors,
            }
        return handler

    def _make_ai_goal_step_node(self, node: WorkflowNode) -> Callable[[WorkflowExecutionState], Dict[str, Any]]:
        def handler(state: WorkflowExecutionState) -> Dict[str, Any]:
            if node.config.get("status") == "SKIPPED_NO_ARTIFACT":
                return {
                    "current_node_id": node.id,
                    "completed_nodes": state.completed_nodes + [node.id],
                    "active_payload": state.active_payload,
                    "node_outputs": {
                        **state.node_outputs,
                        node.id: {
                            "status": "SKIPPED_NO_ARTIFACT",
                            "skip_reason": node.config.get("skip_reason", "Required artifact missing from case vault"),
                        },
                    },
                }
            user_goal = node.config.get("goal", f"Analyze evidence for node {node.id}")
            art_type = node.config.get("artifact_type")

            # 1. Deterministic query scoped by incoming pivots (RFC 3227, AGENTS.md Rule 1)
            pivots = state.active_payload.pivots
            evidence = self.storage.query_structured_findings(
                case_id=state.case_id,
                filters={"artifact_type": art_type} if art_type else None,
                pivots=pivots,
                limit=50,
            )

            # If scoped query yielded empty result, query general case findings
            if not evidence:
                evidence = self.storage.query_structured_findings(case_id=state.case_id, limit=30)

            # 2. Enrich with DFIR domain knowledge from memory provider
            context_snippets: List[str] = []
            try:
                snippets = _run_coroutine_safely(
                    self.memory_provider.retrieve_dfir_domain_knowledge(user_goal, art_type)
                )
                if snippets:
                    context_snippets.extend(snippets)
            except Exception:
                context_snippets = []

            # 3. Call local Ollama client with anti-IPI nonce wrapper
            raw_result: Optional[NodeGoalResult] = None
            try:
                raw_result = _run_coroutine_safely(
                    self.ollama_client.generate_node_goal_result(
                        node_id=node.id,
                        user_goal=user_goal,
                        evidence=evidence,
                        incoming_pivots=pivots,
                        context_snippets=context_snippets,
                    )
                )
            except Exception as e:
                # LLM execution failed or unavailable.
                # Preserve independently verified deterministic observations without fabricating AI reasoning.
                claims: List[CitedClaim] = []
                extracted_pivots: Dict[str, List[str]] = {}
                if evidence:
                    for ev in evidence[:5]:
                        claims.append(
                            CitedClaim(
                                claim_type="observed_fact",
                                statement=f"Observed deterministic finding {ev.artifact_type} ({ev.category}): {ev.summary}",
                                citing_finding_ids=[ev.finding_id],
                                source_artifact_hashes=[ev.source_artifact_hash],
                                confidence=0.0,
                                verification_status="VERIFIED",
                                why_it_matters=f"Deterministic telemetry recorded for user '{ev.user or 'system'}' on host '{ev.host or 'endpoint'}'.",
                            )
                        )
                        if ev.user and ev.user not in extracted_pivots.setdefault("users", []):
                            extracted_pivots["users"].append(ev.user)
                        if ev.host and ev.host not in extracted_pivots.setdefault("hosts", []):
                            extracted_pivots["hosts"].append(ev.host)
                        if ev.process_name and ev.process_name not in extracted_pivots.setdefault("processes", []):
                            extracted_pivots["processes"].append(ev.process_name)

                err_msg = f"AI analysis failed for node '{node.id}' ({type(e).__name__}: {str(e)})"
                node_status = "partial" if claims else "failed"
                summary_text = (
                    f"{err_msg}. Preserved {len(claims)} deterministic observation(s) without LLM synthesis."
                    if claims
                    else f"{err_msg}. No deterministic findings evaluated."
                )

                raw_result = NodeGoalResult(
                    node_id=node.id,
                    status=node_status,
                    summary=summary_text,
                    claims=claims,
                    extracted_pivots=extracted_pivots,
                    recommended_next_actions=[
                        "Verify LLM provider availability or retry node execution.",
                        "Inspect preserved deterministic observations manually.",
                    ],
                    confidence_score=0.0,
                )

            # 4. Strict CitationGuard post-validation gatekeeper
            report = self.citation_guard.validate_node_result(
                raw_result, case_id=state.case_id, strict=False, downgrade_ungrounded=True
            )
            final_result = report.sanitized_result or raw_result

            # 5. Record trace to episodic memory
            trace = NodeExecutionTrace(
                case_id=state.case_id,
                node_id=node.id,
                user_goal=user_goal,
                incoming_pivots=pivots,
                executed_queries=[f"SELECT * FROM findings WHERE case_id='{state.case_id}'"],
                cited_finding_ids=report.verified_finding_ids,
            )
            try:
                _run_coroutine_safely(self.memory_provider.record_execution_trace(trace))
            except Exception:
                pass

            # 6. Extract downstream pivots and update payload
            new_pivots = extract_pivots_from_goal_result(final_result)
            updated_payload = state.active_payload.merge(WorkflowEdgePayload(pivots=new_pivots))

            is_successful = final_result.status in ("completed", "success")
            completed = state.completed_nodes + [node.id] if is_successful else state.completed_nodes
            errors = list(state.errors)
            if not is_successful:
                errors.append(
                    f"Node '{node.id}' execution ended with status '{final_result.status}': {final_result.summary}"
                )

            return {
                "current_node_id": node.id,
                "completed_nodes": completed,
                "active_payload": updated_payload,
                "node_results": {**state.node_results, node.id: final_result},
                "errors": errors,
            }
        return handler

    def _make_human_approval_gate_node(self, node: WorkflowNode) -> Callable[[WorkflowExecutionState], Dict[str, Any]]:
        def handler(state: WorkflowExecutionState) -> Dict[str, Any]:
            token = state.approval_tokens.get(node.id)
            if token:
                if not token.consumed:
                    engine = self._get_approval_engine(state.case_id)
                    try:
                        engine.verify_and_consume_token(
                            token=token,
                            expected_case_id=state.case_id,
                            expected_action_type=token.action_type or node.config.get("action_type"),
                            expected_target=token.target or node.config.get("target"),
                            consumed_by=f"langgraph_gate:{node.id}",
                        )
                    except Exception as e:
                        return {
                            "current_node_id": node.id,
                            "is_paused": True,
                            "pause_node_id": node.id,
                            "pause_reason": f"Approval token verification failed: {e}",
                        }
                return {
                    "current_node_id": node.id,
                    "completed_nodes": state.completed_nodes + [node.id],
                    "is_paused": False,
                    "pause_node_id": None,
                    "pause_reason": None,
                }
            else:
                return {
                    "current_node_id": node.id,
                    "is_paused": True,
                    "pause_node_id": node.id,
                    "pause_reason": f"Awaiting Human Approval Token for node '{node.name or node.id}'.",
                }
        return handler

    def _make_report_compiler_node(self, node: WorkflowNode) -> Callable[[WorkflowExecutionState], Dict[str, Any]]:
        def handler(state: WorkflowExecutionState) -> Dict[str, Any]:
            all_node_results = list(state.node_results.values())
            report = ReportBuilder.build_report(
                case_id=state.case_id,
                node_results=all_node_results,
                storage=self.storage,
                custody_engine=self.custody_engine,
                strict_citations=node.config.get("strict_citations", True),
            )
            return {
                "current_node_id": node.id,
                "completed_nodes": state.completed_nodes + [node.id],
                "report": report.to_dict(),
            }
        return handler

    def build_graph(self, workflow_def: WorkflowDefinition) -> StateGraph:
        """Construct a compiled LangGraph StateGraph from a WorkflowDefinition."""
        graph = StateGraph(WorkflowExecutionState)

        # 1. Add all nodes
        for node in workflow_def.nodes:
            if node.type == "evidence_input":
                fn = self._make_evidence_input_node(node)
            elif node.type == "dissect_parser":
                fn = self._make_dissect_parser_node(node)
            elif node.type == "tool_runner":
                fn = self._make_tool_runner_node(node)
            elif node.type == "ai_goal_step":
                fn = self._make_ai_goal_step_node(node)
            elif node.type == "human_approval_gate":
                fn = self._make_human_approval_gate_node(node)
            elif node.type == "report_compiler":
                fn = self._make_report_compiler_node(node)
            else:
                raise ForensicOpsError(f"Unsupported node type: {node.type}")

            graph.add_node(node.id, fn)

        # 2. Add edges and conditional routing for approval gates
        if not workflow_def.nodes:
            raise ForensicOpsError("Cannot build graph with empty nodes.")

        entry_node = workflow_def.nodes[0].id
        graph.set_entry_point(entry_node)

        for edge in workflow_def.edges:
            source_node = workflow_def.get_node(edge.source)
            if source_node and source_node.type == "human_approval_gate":
                # Conditional routing on approval gate
                target = edge.target

                def make_route(tgt: str):
                    def route_fn(s: WorkflowExecutionState) -> str:
                        if s.is_paused:
                            return END
                        return tgt
                    return route_fn

                graph.add_conditional_edges(
                    edge.source,
                    make_route(target),
                    {target: target, END: END},
                )
            else:
                graph.add_edge(edge.source, edge.target)

        # Connect terminating nodes to END
        terminal_nodes = [
            n.id for n in workflow_def.nodes
            if not workflow_def.get_outgoing_edges(n.id)
        ]
        for t in terminal_nodes:
            graph.add_edge(t, END)

        return graph

    def execute_workflow(
        self,
        workflow_def: WorkflowDefinition,
        case_id: str,
        initial_pivots: Optional[WorkflowEdgePayload] = None,
        approval_tokens: Optional[Dict[str, HumanApprovalToken]] = None,
    ) -> WorkflowExecutionState:
        """Execute the DAG workflow from start to completion or pause."""
        graph = self.build_graph(workflow_def)
        app = graph.compile()

        tokens = approval_tokens or {}
        init_state = WorkflowExecutionState(
            case_id=case_id,
            workflow_id=workflow_def.workflow_id,
            active_payload=initial_pivots or WorkflowEdgePayload(),
            approval_tokens=tokens,
        )

        res_dict = app.invoke(init_state)
        return WorkflowExecutionState.model_validate(res_dict)

    def resume_workflow(
        self,
        workflow_def: WorkflowDefinition,
        state: WorkflowExecutionState,
        approval_token: HumanApprovalToken,
    ) -> WorkflowExecutionState:
        """Resume a paused workflow after supplying a valid HumanApprovalToken."""
        if not state.is_paused or not state.pause_node_id:
            raise ForensicOpsError("Cannot resume workflow: state is not paused.")

        if approval_token.node_id != state.pause_node_id:
            raise ForensicOpsError(
                f"Token node_id '{approval_token.node_id}' does not match pause node '{state.pause_node_id}'."
            )

        # Atomically verify and consume the approval token via ApprovalEngine (Replay Protection)
        pause_node = workflow_def.get_node(state.pause_node_id)
        expected_target = approval_token.target or (pause_node.config.get("target") if pause_node else None)
        expected_action = approval_token.action_type or (pause_node.config.get("action_type") if pause_node else None)

        engine = self._get_approval_engine(state.case_id)
        try:
            engine.verify_and_consume_token(
                token=approval_token,
                expected_case_id=state.case_id,
                expected_action_type=expected_action,
                expected_target=expected_target,
                consumed_by=f"langgraph_resume:{state.pause_node_id}",
            )
        except UnauthorizedCollectorExecutionError as ue:
            raise ForensicOpsError(f"Approval verification failed: Invalid or forged HumanApprovalToken: {ue}") from ue
        except Exception as e:
            raise ForensicOpsError(f"Approval token verification failed: Invalid or forged HumanApprovalToken: {e}") from e

        # Update state tokens and clear paused flag
        updated_tokens = {**state.approval_tokens, approval_token.node_id: approval_token}
        state.approval_tokens = updated_tokens
        state.is_paused = False
        state.pause_node_id = None
        state.pause_reason = None

        # Re-execute from current state
        graph = self.build_graph(workflow_def)
        app = graph.compile()

        res_dict = app.invoke(state)
        return WorkflowExecutionState.model_validate(res_dict)


def convert_goal_plan_to_workflow(plan: Any) -> WorkflowDefinition:
    """Convert a compiled DeterministicGoalPlan into an executable WorkflowDefinition with ReactFlow layout."""
    nodes: List[WorkflowNode] = [
        WorkflowNode(
            id="node_input",
            name="Evidence Intake & Indexing",
            type="evidence_input",
            position={"x": 50, "y": 200},
        )
    ]
    edges: List[WorkflowEdge] = []
    prev_id = "node_input"

    for idx, step in enumerate(plan.steps):
        node_id = f"node_{step.step_id}"
        plugin_str = (step.parser_plugin or "").lower()
        if "chainsaw" in plugin_str or "yara" in plugin_str or "volatility" in plugin_str:
            node_type = "tool_runner"
            config_dict = {"tool_id": str(step.parser_plugin).replace(".yaml", "")}
        elif "hybrid_search" in plugin_str:
            node_type = "ai_goal_step"
            config_dict = {"goal": f"Sweep IOCs: {step.description}"}
        else:
            node_type = "dissect_parser"
            config_dict = {"artifact_type": step.required_artifact_types[0] if step.required_artifact_types else "evtx"}

        config_dict["step_id"] = step.step_id
        config_dict["status"] = step.status.value if hasattr(step.status, "value") else str(step.status)
        config_dict["tactic_id"] = step.tactic_id
        config_dict["skip_reason"] = step.skip_reason
        config_dict["target_os"] = step.target_os

        nodes.append(
            WorkflowNode(
                id=node_id,
                name=f"[{config_dict['status']}] {step.name}",
                type=node_type,
                config=config_dict,
                position={"x": 50 + (idx + 1) * 260, "y": 200 + (idx % 2 * 60 - 30)},
            )
        )
        edges.append(WorkflowEdge(source=prev_id, target=node_id))
        prev_id = node_id

    report_node_id = "node_report_compiler"
    nodes.append(
        WorkflowNode(
            id=report_node_id,
            name="Compile Cited Forensic Report",
            type="report_compiler",
            position={"x": 50 + (len(plan.steps) + 1) * 260, "y": 200},
        )
    )
    edges.append(WorkflowEdge(source=prev_id, target=report_node_id))

    return WorkflowDefinition(
        workflow_id=f"workflow_{plan.plan_id}",
        name=f"Goal Plan: {plan.investigation_goal[:40]}",
        description=f"Deterministic playbook workflow executing {len(plan.steps)} steps for goal: {plan.investigation_goal}",
        nodes=nodes,
        edges=edges,
    )

