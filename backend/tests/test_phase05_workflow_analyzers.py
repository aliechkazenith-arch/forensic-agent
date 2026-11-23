"""Phase 05 Regression Test Suite: Connect Real Forensic Analyzers to Workflow.

Tests:
1. End-to-end vertical slice: Authorized EVTX -> hash verification -> sandboxed EZ Tools ->
   normalized findings -> DuckDB persistence -> verified citation.
2. Dissect parser node real execution on case vault artifacts.
3. Dissect rejection of unsupported E01 and VMDK container formats.
4. Direct rejection of E01/VMDK container magic bytes in DissectAdapter.
5. Tool runner blocks unapproved tools not in AnalyzerRegistry.
6. Execution idempotency: deterministic execution key prevents accidental duplicates while
   force_rerun permits intentional re-analysis.
7. Corrupted artifact hash mismatch halts analysis and marks node failed.
8. Malformed parser output handled safely without fabricating findings.
9. Process timeout terminates and marks execution failed.
10. Honest reporting: workflow does not report parser execution success if only retrieving existing records.
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from unittest.mock import MagicMock, patch
from uuid import uuid4
import pytest

from backend.app.agent.graph import ForensicOpsWorkflowEngine
from backend.app.core.analyzer_registry import AnalyzerRegistry, get_analyzer_registry
from backend.app.core.citation_guard import CitationGuard
from backend.app.core.custody_engine import CustodyEngine
from backend.app.core.dissect_adapter import DissectAdapter
from backend.app.core.exceptions import ExecutionPolicyError, ForensicOpsError, ProcessTimeoutError
from backend.app.core.plugin_runner import AirGappedSubprocessRunner, PluginRunner
from backend.app.core.storage import ForensicStore
from backend.app.models.custody import ArtifactRecord
from backend.app.models.findings import CitedClaim, ForensicFinding
from backend.app.models.plugins import ToolPluginCard
from backend.app.models.workflow import (
    WorkflowDefinition,
    WorkflowEdge,
    WorkflowNode,
)


@pytest.fixture
def temp_workspace(tmp_path: Path):
    vault_dir = tmp_path / "vault"
    vault_dir.mkdir(parents=True, exist_ok=True)
    custody_db = tmp_path / "custody.db"
    duckdb_file = tmp_path / "test_store.duckdb"

    custody = CustodyEngine(vault_root=vault_dir, db_path=custody_db, case_id="case-ph05-test")
    store = ForensicStore(duckdb_file)

    def _ingest_raw(raw_bytes: bytes, case_id: str, original_filename: str, artifact_type: str, actor: str = "analyst"):
        src = tmp_path / f"src_{uuid4().hex}_{original_filename}"
        src.write_bytes(raw_bytes)
        return custody.ingest_artifact(
            case_id=case_id,
            source_path=src,
            artifact_type=artifact_type,
            actor=actor,
            original_name=original_filename,
        )

    setattr(custody, "ingest_raw_artifact", _ingest_raw)

    yield {
        "root": tmp_path,
        "vault_dir": vault_dir,
        "custody": custody,
        "store": store,
    }

    store.close()


@pytest.fixture
def real_evtx_bytes() -> bytes:
    """Minimal valid binary EVTX file header structure ('ElfFile\\x00')."""
    header = bytearray(4096)
    header[0:8] = b"ElfFile\x00"
    header[8:16] = (0).to_bytes(8, "little")  # first chunk number
    header[16:24] = (0).to_bytes(8, "little")  # last chunk number
    header[24:32] = (1).to_bytes(8, "little")  # next record number
    header[32:36] = (4096).to_bytes(4, "little")  # header size
    header[36:38] = (1).to_bytes(2, "little")  # minor version
    header[38:40] = (3).to_bytes(2, "little")  # major version
    header[40:42] = (4096).to_bytes(2, "little")  # header chunk size
    header[42:44] = (1).to_bytes(2, "little")  # chunk count

    # Add a mock 64KB chunk
    chunk = bytearray(65536)
    chunk[0:8] = b"ElfChnk\x00"
    chunk[8:16] = (1).to_bytes(8, "little")  # first event record number
    chunk[16:24] = (5).to_bytes(8, "little")  # last event record number
    return bytes(header + chunk)


# ------------------------------------------------------------------------------
# 1. Initial Real Vertical Slice: Authorized EVTX -> Sandboxed EZ Tools -> DuckDB -> Citation
# ------------------------------------------------------------------------------
def test_vertical_slice_real_evtx_to_verified_citation(temp_workspace, real_evtx_bytes):
    """End-to-end vertical slice: EVTX artifact -> EZ Tools -> normalized findings -> DuckDB -> citation."""
    custody: CustodyEngine = temp_workspace["custody"]
    store: ForensicStore = temp_workspace["store"]

    # 1. Ingest authorized EVTX artifact into custody
    artifact = custody.ingest_raw_artifact(
        raw_bytes=real_evtx_bytes,
        case_id="case-ph05-test",
        original_filename="Security.evtx",
        artifact_type="evtx",
        actor="lead_investigator",
    )
    assert artifact.sha256 is not None

    # 2. Configure AirGappedSubprocessRunner with mock EZ Tools EvtxECmd output
    sub_runner = AirGappedSubprocessRunner(allow_test_mock=True)

    def mock_evtxecmd_handler(argv, in_dir, out_dir):
        out_f = out_dir / "EvtxECmd_Output.jsonl"
        records = [
            {
                "TimeCreated": "2026-11-15T02:00:00Z",
                "EventId": 4624,
                "Computer": "DC-PRIMARY",
                "UserName": "Administrator",
                "ExecutableInfo": "winlogon.exe",
                "CommandLine": "winlogon.exe",
                "RecordNumber": 1001,
                "Payload": "Successful RDP logon of Administrator",
            },
            {
                "TimeCreated": "2026-11-15T02:05:00Z",
                "EventId": 4688,
                "Computer": "DC-PRIMARY",
                "UserName": "Administrator",
                "ExecutableInfo": "cmd.exe",
                "CommandLine": "cmd.exe /c whoami",
                "RecordNumber": 1002,
                "Payload": "Process created whoami",
            },
        ]
        out_f.write_text("\n".join(json.dumps(r) for r in records) + "\n")
        return 0, "EvtxECmd parsed 2 events", ""

    sub_runner.register_mock_tool("evtxecmd", mock_evtxecmd_handler)
    plugin_runner = PluginRunner(subprocess_runner=sub_runner, custody_engine=custody)

    # 3. Build DAG Workflow with tool_runner node
    wf = WorkflowDefinition(
        workflow_id="wf_vertical_slice",
        name="Vertical Slice EZ Tools EVTX",
        description="Verify end-to-end execution of EZ Tools on EVTX",
        nodes=[
            WorkflowNode(
                id="node_ez_tools",
                name="EZ EvtxECmd Parser",
                type="tool_runner",
                config={"tool_id": "ez_evtxecmd"},
            )
        ],
        edges=[],
    )

    engine = ForensicOpsWorkflowEngine(
        storage=store,
        custody_engine=custody,
        plugin_runner=plugin_runner,
    )

    # 4. Execute workflow
    state = engine.execute_workflow(workflow_def=wf, case_id="case-ph05-test")
    assert state.is_paused is False
    assert "node_ez_tools" in state.completed_nodes

    # 5. Verify structured node output
    node_out = state.node_outputs["node_ez_tools"]
    assert node_out["status"] == "completed"
    assert node_out["findings_count"] == 2
    assert node_out["tool_metadata"]["tool_id"] == "ez_evtxecmd"
    assert node_out["tool_metadata"]["version"] == "1.5.0"
    assert node_out["dataset_pointer"] is not None

    # 6. Verify DuckDB persistence and tool_version population
    duckdb_findings = store.query_structured_findings(
        case_id="case-ph05-test",
        filters={"tool_id": "ez_evtxecmd"},
    )
    assert len(duckdb_findings) == 2
    f1 = duckdb_findings[0]
    assert f1.tool_id == "ez_evtxecmd"
    assert f1.tool_version == "1.5.0"
    assert f1.source_artifact_id == artifact.artifact_id
    assert f1.source_artifact_hash == artifact.sha256
    assert f1.case_id == "case-ph05-test"

    # 7. Verify CitationGuard citation of newly produced finding
    guard = CitationGuard(storage=store, custody_engine=custody)
    claim = CitedClaim(
        claim_id="claim-001",
        claim_type="observed_fact",
        statement="Administrator logged on via RDP to DC-PRIMARY",
        citing_finding_ids=[f1.finding_id],
        source_artifact_hashes=[artifact.sha256],
        confidence=1.0,
    )
    is_valid, reasons = guard.validate_claim(
        claim=claim,
        case_id="case-ph05-test",
    )
    assert is_valid is True
    assert reasons == []
    assert claim.verification_status == "VERIFIED"
    assert claim.requires_analyst_review is False


# ------------------------------------------------------------------------------
# 2. Dissect Parser Node: Real Execution on Ingested Vault Artifact
# ------------------------------------------------------------------------------
def test_dissect_parser_node_real_execution(temp_workspace, real_evtx_bytes):
    """Verify dissect_parser resolves case artifacts, executes userspace parsing, and persists findings."""
    custody: CustodyEngine = temp_workspace["custody"]
    store: ForensicStore = temp_workspace["store"]

    artifact = custody.ingest_raw_artifact(
        raw_bytes=real_evtx_bytes,
        case_id="case-ph05-test",
        original_filename="System.evtx",
        artifact_type="evtx",
        actor="lead_investigator",
    )

    wf = WorkflowDefinition(
        workflow_id="wf_dissect_test",
        name="Dissect EVTX Parser Workflow",
        nodes=[
            WorkflowNode(
                id="node_dissect_evtx",
                name="Dissect EVTX",
                type="dissect_parser",
                config={"artifact_type": "evtx"},
            )
        ],
        edges=[],
    )

    engine = ForensicOpsWorkflowEngine(
        storage=store,
        custody_engine=custody,
        dissect_adapter=DissectAdapter(),
    )

    state = engine.execute_workflow(workflow_def=wf, case_id="case-ph05-test")
    assert "node_dissect_evtx" in state.completed_nodes

    node_out = state.node_outputs["node_dissect_evtx"]
    assert node_out["status"] == "completed"
    assert node_out["findings_count"] > 0
    assert node_out["input_artifact_ids"] == [artifact.artifact_id]
    assert node_out["tool_metadata"]["execution_tier"] == "tier_a_dissect"

    # Verify DuckDB has dissect findings
    findings = store.query_structured_findings(
        case_id="case-ph05-test",
        filters={"artifact_type": "evtx"},
    )
    assert len(findings) > 0
    assert any(f.tool_id == "dissect_evtx" for f in findings)


# ------------------------------------------------------------------------------
# 3. Dissect Rejection of Unsupported E01 & VMDK Container Formats
# ------------------------------------------------------------------------------
def test_dissect_unsupported_e01_vmdk_rejection(temp_workspace):
    """Verify dissect_parser rejects unsupported E01/VMDK requests with explicit failure."""
    custody: CustodyEngine = temp_workspace["custody"]
    store: ForensicStore = temp_workspace["store"]

    wf = WorkflowDefinition(
        workflow_id="wf_unsupported_e01",
        name="Unsupported E01 Node",
        nodes=[
            WorkflowNode(
                id="node_e01",
                name="Attempt E01",
                type="dissect_parser",
                config={"artifact_type": "e01"},
            )
        ],
        edges=[],
    )

    engine = ForensicOpsWorkflowEngine(
        storage=store,
        custody_engine=custody,
    )

    state = engine.execute_workflow(workflow_def=wf, case_id="case-ph05-test")
    node_out = state.node_outputs["node_e01"]

    assert node_out["status"] == "failed"
    assert "Unsupported artifact container format 'e01'" in node_out["errors"][0]
    assert len(state.errors) > 0


# ------------------------------------------------------------------------------
# 4. Direct Rejection of E01/VMDK Magic Bytes in DissectAdapter
# ------------------------------------------------------------------------------
def test_dissect_direct_magic_bytes_rejection(tmp_path: Path):
    """Verify DissectAdapter rejects files with E01 or VMDK magic signatures."""
    adapter = DissectAdapter()

    # Fake E01 file
    fake_e01 = tmp_path / "evidence.E01"
    fake_e01.write_bytes(b"EVF01\r\n\x00\x00\x00")

    with pytest.raises(ForensicOpsError, match="Unsupported container format: E01/VMDK"):
        adapter.parse_disk_image_stream(
            image_path=fake_e01,
            case_id="case1",
            artifact_id="art1",
            artifact_hash="hash1",
        )

    # Fake VMDK file
    fake_vmdk = tmp_path / "disk.vmdk"
    fake_vmdk.write_bytes(b"KDMV\x01\x00\x00\x00")

    with pytest.raises(ForensicOpsError, match="Unsupported container format: E01/VMDK"):
        adapter.parse_disk_image_stream(
            image_path=fake_vmdk,
            case_id="case1",
            artifact_id="art1",
            artifact_hash="hash1",
        )


# ------------------------------------------------------------------------------
# 5. Tool Runner Blocks Unapproved Tools
# ------------------------------------------------------------------------------
def test_tool_runner_blocks_unapproved_tool(temp_workspace):
    """Verify tool_runner fails closed when an unapproved tool ID is requested."""
    custody: CustodyEngine = temp_workspace["custody"]
    store: ForensicStore = temp_workspace["store"]

    wf = WorkflowDefinition(
        workflow_id="wf_unapproved_tool",
        name="Unapproved Tool",
        nodes=[
            WorkflowNode(
                id="node_evil",
                name="Evil Tool",
                type="tool_runner",
                config={"tool_id": "malicious_unapproved_binary"},
            )
        ],
        edges=[],
    )

    engine = ForensicOpsWorkflowEngine(
        storage=store,
        custody_engine=custody,
    )

    state = engine.execute_workflow(workflow_def=wf, case_id="case-ph05-test")
    node_out = state.node_outputs["node_evil"]

    assert node_out["status"] == "failed"
    assert "not registered in the approved forensic analyzer registry" in node_out["errors"][0]


# ------------------------------------------------------------------------------
# 6. Execution Idempotency: Deterministic Execution Key & Force Rerun
# ------------------------------------------------------------------------------
def test_execution_idempotency_and_force_rerun(temp_workspace, real_evtx_bytes):
    """Verify deterministic execution key avoids accidental duplicate execution while force_rerun permits re-run."""
    custody: CustodyEngine = temp_workspace["custody"]
    store: ForensicStore = temp_workspace["store"]

    artifact = custody.ingest_raw_artifact(
        raw_bytes=real_evtx_bytes,
        case_id="case-ph05-test",
        original_filename="Security.evtx",
        artifact_type="evtx",
    )

    sub_runner = AirGappedSubprocessRunner(allow_test_mock=True)
    call_count = 0

    def counting_mock_evtxecmd(argv, in_dir, out_dir):
        nonlocal call_count
        call_count += 1
        out_f = out_dir / "EvtxECmd_Output.jsonl"
        out_f.write_text(json.dumps({"TimeCreated": "2026-11-15T00:00:00Z", "EventId": 1102, "Payload": "Log cleared"}) + "\n")
        return 0, "Parsed 1 event", ""

    sub_runner.register_mock_tool("evtxecmd", counting_mock_evtxecmd)
    plugin_runner = PluginRunner(subprocess_runner=sub_runner, custody_engine=custody)

    card = ToolPluginCard.from_yaml_file(Path("plugins/ez_evtxecmd.yaml"))
    workspace = temp_workspace["vault_dir"] / "case-ph05-test"

    # 1. First execution: runs analyzer
    res1 = plugin_runner.run_plugin(plugin=card, artifact=artifact, output_workspace=workspace)
    assert res1.success is True
    assert call_count == 1
    assert res1.findings_count == 1

    # 2. Second execution (without force_rerun): idempotent cache replay
    res2 = plugin_runner.run_plugin(plugin=card, artifact=artifact, output_workspace=workspace, force_rerun=False)
    assert res2.success is True
    assert call_count == 1  # Subprocess was NOT called again
    assert any("Replayed existing" in w for w in res2.warnings)

    # 3. Third execution (with force_rerun=True): intentionally re-runs
    res3 = plugin_runner.run_plugin(plugin=card, artifact=artifact, output_workspace=workspace, force_rerun=True)
    assert res3.success is True
    assert call_count == 2  # Subprocess was re-invoked


# ------------------------------------------------------------------------------
# 7. Corrupted Artifact Hash Mismatch Halts Analysis
# ------------------------------------------------------------------------------
def test_corrupted_artifact_hash_mismatch_blocks_execution(temp_workspace, real_evtx_bytes):
    """Verify tool_runner detects on-disk artifact tampering and aborts analysis."""
    custody: CustodyEngine = temp_workspace["custody"]
    store: ForensicStore = temp_workspace["store"]

    artifact = custody.ingest_raw_artifact(
        raw_bytes=real_evtx_bytes,
        case_id="case-ph05-test",
        original_filename="Security.evtx",
        artifact_type="evtx",
    )

    # Tamper with the artifact file on disk
    artifact_path = custody.resolve_artifact_file(artifact)
    from backend.app.core.custody_engine import safe_make_writable
    safe_make_writable(artifact_path)
    artifact_path.write_bytes(real_evtx_bytes + b"_TAMPERED_BYTES_DETECTED_")

    wf = WorkflowDefinition(
        workflow_id="wf_tamper_test",
        name="Tamper Test",
        nodes=[
            WorkflowNode(
                id="node_tamper_test",
                name="EZ EvtxECmd",
                type="tool_runner",
                config={"tool_id": "ez_evtxecmd"},
            )
        ],
        edges=[],
    )

    engine = ForensicOpsWorkflowEngine(
        storage=store,
        custody_engine=custody,
    )

    state = engine.execute_workflow(workflow_def=wf, case_id="case-ph05-test")
    node_out = state.node_outputs["node_tamper_test"]

    assert node_out["status"] == "failed"
    assert any("Hash mismatch on artifact" in err for err in node_out["errors"])


# ------------------------------------------------------------------------------
# 8. Malformed Parser Output Handled Safely
# ------------------------------------------------------------------------------
def test_malformed_parser_output_handled_safely(temp_workspace, real_evtx_bytes):
    """Verify that corrupted or malformed tool outputs do not crash the engine or fabricate findings."""
    custody: CustodyEngine = temp_workspace["custody"]
    store: ForensicStore = temp_workspace["store"]

    artifact = custody.ingest_raw_artifact(
        raw_bytes=real_evtx_bytes,
        case_id="case-ph05-test",
        original_filename="Security.evtx",
        artifact_type="evtx",
    )

    sub_runner = AirGappedSubprocessRunner(allow_test_mock=True)

    def mock_broken_tool(argv, in_dir, out_dir):
        out_f = out_dir / "broken.jsonl"
        # Write corrupted garbage instead of valid JSON
        out_f.write_text("INVALID_JSON_CORRUPTED_LINE_1\n{broken:\n")
        return 0, "", ""

    sub_runner.register_mock_tool("evtxecmd", mock_broken_tool)
    plugin_runner = PluginRunner(subprocess_runner=sub_runner, custody_engine=custody)

    card = ToolPluginCard.from_yaml_file(Path("plugins/ez_evtxecmd.yaml"))
    workspace = temp_workspace["vault_dir"] / "case-ph05-test"

    result = plugin_runner.run_plugin(plugin=card, artifact=artifact, output_workspace=workspace)
    assert result.success is True
    assert result.findings_count == 0
    assert len(result.findings) == 0


# ------------------------------------------------------------------------------
# 9. Tool Runner Timeout Marks Node Failed
# ------------------------------------------------------------------------------
def test_tool_runner_timeout_marks_failed(temp_workspace, real_evtx_bytes):
    """Verify that process timeout fails the node execution honestly."""
    custody: CustodyEngine = temp_workspace["custody"]
    store: ForensicStore = temp_workspace["store"]

    artifact = custody.ingest_raw_artifact(
        raw_bytes=real_evtx_bytes,
        case_id="case-ph05-test",
        original_filename="Security.evtx",
        artifact_type="evtx",
    )

    sub_runner = AirGappedSubprocessRunner(allow_test_mock=True)

    def mock_hanging_tool(argv, in_dir, out_dir):
        raise ProcessTimeoutError("EvtxECmd process timed out after 300 seconds.")

    sub_runner.register_mock_tool("evtxecmd", mock_hanging_tool)
    plugin_runner = PluginRunner(subprocess_runner=sub_runner, custody_engine=custody)

    wf = WorkflowDefinition(
        workflow_id="wf_timeout_test",
        name="Timeout Test",
        nodes=[
            WorkflowNode(
                id="node_timeout",
                name="EZ EvtxECmd Timeout",
                type="tool_runner",
                config={"tool_id": "ez_evtxecmd"},
            )
        ],
        edges=[],
    )

    engine = ForensicOpsWorkflowEngine(
        storage=store,
        custody_engine=custody,
        plugin_runner=plugin_runner,
    )

    state = engine.execute_workflow(workflow_def=wf, case_id="case-ph05-test")
    node_out = state.node_outputs["node_timeout"]

    assert node_out["status"] == "failed"
    assert any("timed out" in err for err in node_out["errors"])


# ------------------------------------------------------------------------------
# 10. Honest Reporting: Does Not Report Success If Only Retrieving Existing Records
# ------------------------------------------------------------------------------
def test_honest_reporting_when_only_retrieving_existing_records(temp_workspace):
    """Verify workflow reports 'retrieved_existing' or 'cached' instead of fabricated analysis success."""
    custody: CustodyEngine = temp_workspace["custody"]
    store: ForensicStore = temp_workspace["store"]

    # Pre-populate DuckDB with an existing finding without ingesting vault artifacts
    existing_finding = ForensicFinding(
        case_id="case-ph05-test",
        source_artifact_id="art-pre-existing",
        source_artifact_hash="hash-pre-existing",
        tool_id="ez_evtxecmd",
        artifact_type="evtx",
        category="event_log",
        summary="Pre-existing finding from previous run",
    )
    store.insert_findings([existing_finding])

    # No artifacts in custody vault!
    wf = WorkflowDefinition(
        workflow_id="wf_existing_only",
        name="Existing Records Only",
        nodes=[
            WorkflowNode(
                id="node_query_only",
                name="EZ EvtxECmd",
                type="tool_runner",
                config={"tool_id": "ez_evtxecmd"},
            )
        ],
        edges=[],
    )

    engine = ForensicOpsWorkflowEngine(
        storage=store,
        custody_engine=custody,
    )

    state = engine.execute_workflow(workflow_def=wf, case_id="case-ph05-test")
    node_out = state.node_outputs["node_query_only"]

    # Since no vault artifacts matched, it skipped analyzer execution honestly
    assert node_out["status"] == "SKIPPED_NO_ARTIFACT"
    assert node_out["findings_count"] == 0
