"""Phase 04 Regression Test Suite: Isolated Forensic Tool Execution Sandbox.

Tests:
1. Container hardening flags: network none, read-only, cap-drop, no-new-privileges, user, limits, tmpfs, read-only evidence, isolated output.
2. Unapproved tools blocked: execution policy blocks unlisted tool IDs and unknown executables.
3. Fail-closed behavior: missing or failing container runtime strictly halts execution without host fallback.
4. Direct host execution blocked: external forensic parsers cannot run bare on the host.
5. Process-tree termination on timeout: timeout triggers clean termination of process tree.
6. Bounded stdout/stderr capture: outputs exceeding limit are truncated with explicit warning.
7. Workspace confinement: path traversal and arbitrary host mounts are rejected.
8. Plugin validation: invalid YAML cards (dangerous images, unapproved tools, shell meta, bad placeholders) rejected.
9. Provenance completeness: all provenance fields and custody records are generated upon execution.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from backend.app.core.exceptions import (
    ExecutionPolicyError,
    ForensicOpsError,
    ProcessTimeoutError,
    SandboxUnavailableError,
    UnsafePluginCardError,
)
from backend.app.core.execution_policy import (
    ExecutionPolicyRegistry,
    ResourceLimits,
    ToolExecutionPolicy,
    get_execution_policy_registry,
)
from backend.app.core.plugin_runner import (
    AirGappedSubprocessRunner,
    PluginRunner,
    is_container_runtime_available,
    terminate_process_tree,
)
from backend.app.models.custody import ArtifactRecord
from backend.app.models.plugins import ToolPluginCard


@pytest.fixture
def policy_registry() -> ExecutionPolicyRegistry:
    return get_execution_policy_registry()


@pytest.fixture
def sample_artifact(tmp_path: Path) -> ArtifactRecord:
    ev_file = tmp_path / "Security.evtx"
    ev_file.write_bytes(b"ELF_MOCK_EVTX_DATA_FOR_SANDBOX_TEST")
    return ArtifactRecord(
        artifact_id="art-sbx-001",
        case_id="case-sbx-001",
        type="evtx",
        original_path=str(ev_file),
        blob_path=str(ev_file),
        size_bytes=ev_file.stat().st_size,
        sha256="abcd1234ef567890abcd1234ef567890abcd1234ef567890abcd1234ef567890",
        sha512="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        acquired_utc="2026-11-15T00:00:00Z",
        actor="lead_investigator",
        acquisition_method="offline_upload",
        custody_seq_id=1,
    )


# -----------------------------------------------------------------------------
# 1. Container Hardening Flags Verification
# -----------------------------------------------------------------------------
def test_container_command_line_hardening_flags():
    """Verify that build_container_argv enforces all mandatory container security flags."""
    runner = AirGappedSubprocessRunner(container_runtime="docker")
    policy = ToolExecutionPolicy(
        tool_id="test_tool",
        name="Test Tool",
        version="1.0.0",
        approved_binary="test_bin",
        container_image="ghcr.io/forensicops/test:latest",
        resource_limits=ResourceLimits(cpu_limit=1.5, memory_limit="1g", pids_limit=50, tmpfs_size="64m"),
    )

    argv = ["test_bin", "--input", "/evidence/sample.evtx", "--output", "/scratch"]
    cmd = runner.build_container_argv(
        argv=argv,
        container_image=policy.container_image,
        readonly_input_dir=Path("/vault/case1/evidence"),
        scratch_output_dir=Path("/vault/case1/scratch"),
        tool_policy=policy,
    )

    # Core isolation flags
    assert "--network" in cmd and cmd[cmd.index("--network") + 1] == "none"
    assert "--read-only" in cmd
    assert "--cap-drop" in cmd and cmd[cmd.index("--cap-drop") + 1] == "ALL"
    assert "--security-opt" in cmd and cmd[cmd.index("--security-opt") + 1] == "no-new-privileges:true"
    assert "--user" in cmd and cmd[cmd.index("--user") + 1] == "1000:1000"

    # Resource constraints
    assert "--cpus" in cmd and cmd[cmd.index("--cpus") + 1] == "1.5"
    assert "--memory" in cmd and cmd[cmd.index("--memory") + 1] == "1g"
    assert "--pids-limit" in cmd and cmd[cmd.index("--pids-limit") + 1] == "50"
    assert "--tmpfs" in cmd and "/tmp:rw,noexec,nosuid,size=64m" in cmd[cmd.index("--tmpfs") + 1]

    # Mount restrictions: read-only evidence, isolated scratch output
    assert any(":/evidence:ro" in arg for arg in cmd)
    assert any(":/scratch:rw" in arg for arg in cmd)
    # Never mount evidence as read-write
    assert not any(":/evidence:rw" in arg for arg in cmd)


# -----------------------------------------------------------------------------
# 2. Execution Policy: Unapproved Tools Blocked
# -----------------------------------------------------------------------------
def test_unapproved_tool_id_and_binary_blocked(policy_registry: ExecutionPolicyRegistry):
    """Verify execution policy rejects unapproved tool IDs and unapproved binaries."""
    # Unknown tool ID
    with pytest.raises(ExecutionPolicyError, match="Unknown tool 'unapproved_malicious_tool'"):
        policy_registry.validate_tool_execution(
            tool_id="unapproved_malicious_tool",
            argv=["evil_bin", "--dump"],
        )

    # Approved tool ID but mismatched executable binary
    with pytest.raises(ExecutionPolicyError, match="does not match approved binary 'chainsaw'"):
        policy_registry.validate_tool_execution(
            tool_id="chainsaw_sigma",
            argv=["powershell.exe", "-Command", "whoami"],
        )


# -----------------------------------------------------------------------------
# 3. Fail-Closed: Missing Container Runtime Prohibits Host Fallback
# -----------------------------------------------------------------------------
def test_sandbox_failure_fails_closed_without_host_fallback():
    """Verify that if Docker/container runtime is unavailable, execution fails closed."""
    runner = AirGappedSubprocessRunner(container_runtime="docker")

    # Force is_container_runtime_available to return False
    with patch("backend.app.core.plugin_runner.is_container_runtime_available", return_value=False):
        with pytest.raises(SandboxUnavailableError, match="Host execution fallback is strictly prohibited"):
            runner.execute(
                argv=["chainsaw", "hunt"],
                cwd=Path("."),
                container_image="ghcr.io/forensicops/chainsaw:latest",
            )


# -----------------------------------------------------------------------------
# 4. Direct Host Execution of Forensic Binary Blocked
# -----------------------------------------------------------------------------
def test_direct_host_execution_of_forensic_binary_blocked():
    """Verify that attempting to execute external forensic tools on host without container is blocked."""
    runner = AirGappedSubprocessRunner()
    # Attempting to run chainsaw directly on the host (container_image=None)
    with pytest.raises(SandboxUnavailableError, match="Direct host execution of forensic binary.*is prohibited"):
        runner.execute(
            argv=["chainsaw", "hunt", "--input", "test.evtx"],
            cwd=Path("."),
            container_image=None,
            allow_host_process=False,
        )


# -----------------------------------------------------------------------------
# 5. Process-Tree Termination on Timeout
# -----------------------------------------------------------------------------
def test_process_tree_termination_on_timeout(tmp_path: Path):
    """Verify that timed-out processes are killed and raise ProcessTimeoutError."""
    runner = AirGappedSubprocessRunner()
    # Write python script to avoid inline semicolons or quoting issues
    py_file = tmp_path / "hang.py"
    py_file.write_text("import time\ntime.sleep(10)\n")
    argv = [sys.executable, str(py_file)]

    t_start = time.perf_counter()
    with pytest.raises((ProcessTimeoutError, ForensicOpsError), match="timed out"):
        runner.execute(
            argv=argv,
            cwd=tmp_path,
            timeout_seconds=0.3,
            allow_host_process=True,
        )
    t_elapsed = time.perf_counter() - t_start
    assert t_elapsed < 4.0, f"Process timeout took too long to terminate: {t_elapsed}s"


# -----------------------------------------------------------------------------
# 6. Bounded Output Capture
# -----------------------------------------------------------------------------
def test_bounded_output_capture(tmp_path: Path):
    """Verify that standard output exceeding limit is safely capped to prevent OOM."""
    runner = AirGappedSubprocessRunner()
    py_file = tmp_path / "large_output.py"
    py_file.write_text("import sys\nsys.stdout.write('A' * 11000000)\n")
    argv = [sys.executable, str(py_file)]

    ret, stdout, stderr, dur = runner.execute(
        argv=argv,
        cwd=tmp_path,
        allow_host_process=True,
    )
    assert ret == 0
    assert "[OUTPUT TRUNCATED: Exceeded 10MB limit]" in stdout
    # Ensure stdout does not consume unbounded memory
    assert len(stdout) <= 10 * 1024 * 1024 + 200


# -----------------------------------------------------------------------------
# 7. Workspace Confinement & Traversal Prevention
# -----------------------------------------------------------------------------
def test_workspace_confinement_prevents_arbitrary_mounts(tmp_path: Path, sample_artifact: ArtifactRecord):
    """Verify PluginRunner prevents path traversal outside the designated case workspace."""
    workspace = tmp_path / "case_workspace"
    workspace.mkdir()

    card = ToolPluginCard(
        tool_id="../traversal_tool",
        name="Traversal Hunter",
        version="1.0.0",
        description="Path traversal attempt",
        category="triage",
        artifact_type="evtx",
        container_image="ghcr.io/forensicops/chainsaw:latest",
        command_template=["chainsaw", "hunt", "{input_path}"],
    )
    runner = PluginRunner()

    with pytest.raises(ForensicOpsError, match="Invalid 'tool_id' format|Path traversal detected"):
        runner.run_plugin(
            plugin=card,
            artifact=sample_artifact,
            output_workspace=workspace,
        )


# -----------------------------------------------------------------------------
# 8. Plugin Validation: Invalid YAML Cards Rejected
# -----------------------------------------------------------------------------
def test_invalid_yaml_plugin_cards_rejected(policy_registry: ExecutionPolicyRegistry):
    """Verify ExecutionPolicyRegistry rejects invalid or unsafe plugin cards."""
    # 1. Unapproved tool ID
    bad_id_card = ToolPluginCard(
        tool_id="unregistered_tool",
        name="Unregistered",
        version="1.0.0",
        description="Test tool",
        category="triage",
        artifact_type="file",
        container_image="ghcr.io/forensicops/unregistered:latest",
        command_template=["unregistered", "{input_path}"],
    )
    with pytest.raises(UnsafePluginCardError, match="is not in the approved forensic tool execution policy"):
        policy_registry.validate_plugin_card(bad_id_card)

    # 2. Missing container image (bare host execution attempt)
    missing_container_card = ToolPluginCard(
        tool_id="chainsaw_sigma",
        name="Chainsaw",
        version="2.9.0",
        description="Chainsaw test",
        category="triage",
        artifact_type="evtx",
        container_image=None,
        command_template=["chainsaw", "hunt", "{input_path}"],
    )
    with pytest.raises(UnsafePluginCardError, match="requires a valid 'container_image'"):
        policy_registry.validate_plugin_card(missing_container_card)

    # 3. Unapproved container image prefix (e.g. untrusted public registry)
    bad_img_card = ToolPluginCard(
        tool_id="chainsaw_sigma",
        name="Chainsaw",
        version="2.9.0",
        description="Chainsaw test",
        category="triage",
        artifact_type="evtx",
        container_image="attacker.io/evil/chainsaw:latest",
        command_template=["chainsaw", "hunt", "{input_path}"],
    )
    with pytest.raises(UnsafePluginCardError, match="Must originate from approved registry"):
        policy_registry.validate_plugin_card(bad_img_card)

    # 4. Dangerous shell metacharacters in command template
    shell_inject_card = ToolPluginCard(
        tool_id="chainsaw_sigma",
        name="Chainsaw",
        version="2.9.0",
        description="Chainsaw test",
        category="triage",
        artifact_type="evtx",
        container_image="ghcr.io/forensicops/chainsaw:latest",
        command_template=["chainsaw", "hunt", "; rm -rf / ;", "{input_path}"],
    )
    with pytest.raises(UnsafePluginCardError, match="Unsafe shell metacharacter"):
        policy_registry.validate_plugin_card(shell_inject_card)

    # 5. Unknown placeholder in command template
    bad_placeholder_card = ToolPluginCard(
        tool_id="chainsaw_sigma",
        name="Chainsaw",
        version="2.9.0",
        description="Chainsaw test",
        category="triage",
        artifact_type="evtx",
        container_image="ghcr.io/forensicops/chainsaw:latest",
        command_template=["chainsaw", "hunt", "{malicious_variable}"],
    )
    with pytest.raises(UnsafePluginCardError, match="Unsafe or unknown path substitution"):
        policy_registry.validate_plugin_card(bad_placeholder_card)

    # 6. Unbounded timeout (> 3600s)
    huge_timeout_card = ToolPluginCard(
        tool_id="chainsaw_sigma",
        name="Chainsaw",
        version="2.9.0",
        description="Chainsaw test",
        category="triage",
        artifact_type="evtx",
        container_image="ghcr.io/forensicops/chainsaw:latest",
        command_template=["chainsaw", "hunt", "{input_path}"],
        timeout_seconds=7200,
    )
    with pytest.raises(UnsafePluginCardError, match="is outside allowable bounds"):
        policy_registry.validate_plugin_card(huge_timeout_card)


# -----------------------------------------------------------------------------
# 9. Execution Provenance Completeness
# -----------------------------------------------------------------------------
def test_execution_provenance_recording(tmp_path: Path, sample_artifact: ArtifactRecord):
    """Verify ToolExecutionResult records complete execution provenance and hashes."""
    from backend.app.core.custody_engine import CustodyEngine

    workspace = tmp_path / "case_workspace"
    workspace.mkdir()
    custody_db = tmp_path / "custody.db"
    vault_root = tmp_path / "vault"
    vault_root.mkdir()

    custody = CustodyEngine(vault_root=vault_root, db_path=custody_db, case_id="case-sbx-001")
    sub_runner = AirGappedSubprocessRunner()

    # Mock chainsaw execution handler inside the test runner
    def mock_chainsaw(argv, in_dir, out_dir):
        out_f = out_dir / "chainsaw_results.jsonl"
        out_f.write_text('{"Timestamp": "2026-11-15T01:00:00Z", "RuleTitle": "Mimikatz Memory Dump", "EventId": 10}\n')
        return 0, "Executed mock chainsaw successfully", ""

    sub_runner.register_mock_tool("chainsaw", mock_chainsaw)
    plugin_runner = PluginRunner(subprocess_runner=sub_runner, custody_engine=custody)

    card = ToolPluginCard(
        tool_id="chainsaw_sigma",
        name="Chainsaw Sigma Hunter",
        version="2.9.0",
        description="Chainsaw test",
        category="triage",
        artifact_type="evtx",
        container_image="ghcr.io/forensicops/chainsaw:latest",
        command_template=["chainsaw", "hunt", "--json", "{input_path}"],
    )

    result = plugin_runner.run_plugin(
        plugin=card,
        artifact=sample_artifact,
        output_workspace=workspace,
    )

    # Provenance fields verification
    assert result.success is True
    assert result.tool_id == "chainsaw_sigma"
    assert result.tool_version == "2.9.0"
    assert result.container_image == "ghcr.io/forensicops/chainsaw:latest"
    assert result.input_artifact_hash == sample_artifact.sha256
    assert result.started_at_utc is not None
    assert result.finished_at_utc is not None
    assert result.parameters is not None
    assert isinstance(result.output_hashes, dict)
    assert len(result.output_hashes) > 0

    # Verify custody ledger entry was recorded
    passed, issues = custody.verify_chain_integrity(case_id="case-sbx-001")
    assert passed is True, f"Custody chain integrity failed: {issues}"
    history = custody.get_custody_chain(case_id="case-sbx-001")
    tool_entries = [e for e in history if e.action == "executed_tool_chainsaw_sigma"]
    assert len(tool_entries) == 1
    assert tool_entries[0].tool_id == "chainsaw_sigma"


# -----------------------------------------------------------------------------
# 10. API Route: Plugin Registration Enforces Execution Policy
# -----------------------------------------------------------------------------
def test_api_register_plugin_enforces_execution_policy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Verify POST /api/plugins/register rejects cards violating execution policy with HTTP 400."""
    from fastapi.testclient import TestClient
    from backend.app.main import app
    from backend.app.auth.dependencies import get_current_user
    from backend.app.auth.models import UserRead

    monkeypatch.setenv("FORENSICOPS_PLUGINS_DIR", str(tmp_path))

    # Mock lead investigator user
    mock_user = UserRead(
        id="usr-lead-01",
        username="lead_analyst",
        role="lead_investigator",
        badge_id="BADGE-001",
        created_at="2026-11-15T00:00:00Z",
        is_active=True,
    )
    app.dependency_overrides[get_current_user] = lambda: mock_user

    client = TestClient(app)
    try:
        # Submit card with dangerous container image
        payload = {
            "tool_id": "chainsaw_sigma",
            "name": "Chainsaw Sigma Hunter",
            "version": "2.9.0",
            "description": "Chainsaw test",
            "category": "triage",
            "artifact_type": "evtx",
            "container_image": "malicious.registry.org/evil/chainsaw:latest",
            "command_template": ["chainsaw", "hunt", "{input_path}"],
        }
        res = client.post("/api/plugins/register", json=payload)
        assert res.status_code == 400
        assert "Plugin card failed policy validation" in res.json()["detail"]
    finally:
        app.dependency_overrides.clear()
