"""Phase 12 Regression Tests: Critical Security & Execution Defect Remediation.

Covers:
- SEC-APPR-001: Fail-closed HumanApprovalToken.verify() prevents wildcard token reuse.
- SEC-APPR-002: Workflow approval-token endpoint issues strictly scoped and time-bounded tokens.
- SEC-EXEC-001: Container command line path translation for /evidence and /scratch.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict
from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient

from backend.app.auth.security import hash_password
from backend.app.auth.models import UserCreate
from backend.app.auth.dependencies import get_user_store
from backend.app.core.config import get_settings
from backend.app.core.execution_policy import ResourceLimits, ToolExecutionPolicy
from backend.app.core.plugin_runner import AirGappedSubprocessRunner, PluginRunner
from backend.app.main import app
from backend.app.models.custody import ArtifactRecord
from backend.app.models.plugins import ToolPluginCard
from backend.app.models.workflow import HumanApprovalToken


@pytest.fixture
def secret_key() -> str:
    return "test-strong-secret-key-32-characters-minimum!!"


@pytest.fixture(scope="module")
def setup_admin_user():
    """Ensure admin/123456 user exists in user DB."""
    store = get_user_store()
    existing = store.get_by_username("admin")
    if not existing:
        store.create_user(
            UserCreate(
                username="admin",
                password="123456",
                role="lead_investigator",
                badge_id="BADGE-001",
            ),
            password_hash=hash_password("123456"),
        )
    return "admin"


@pytest.fixture(scope="module")
def client(setup_admin_user):
    """Test client with application lifecycle."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(scope="module")
def auth_headers(client: TestClient) -> Dict[str, str]:
    """Obtain real JWT token by logging in as admin / 123456."""
    resp = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "123456"},
    )
    assert resp.status_code == 200, f"Login failed: {resp.text}"
    token_data = resp.json()
    assert "access_token" in token_data
    return {
        "Authorization": f"Bearer {token_data['access_token']}",
        "Content-Type": "application/json",
    }


# ==============================================================================
# SEC-APPR-001: Fail-Closed HumanApprovalToken Verification
# ==============================================================================

def test_sec_appr_001_wildcard_token_rejected_on_expected_constraints(secret_key: str):
    """Verify that an unconstrained token (None fields) cannot authorize actions with expected bindings."""
    token = HumanApprovalToken(
        token_id="gate-test-wildcard",
        node_id="test_node",
        case_id="case-100",
        action_type=None,
        target=None,
        parameter_digest=None,
        issued_by="lead_investigator",
        timestamp_utc=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        is_valid=True,
    )
    token.sign(secret_key)
    assert token.signature is not None

    # 1. Generic verification without operation constraints passes (backward compatibility)
    assert token.verify(secret_key, expected_case_id="case-100") is True

    # 2. Case mismatch fails
    assert token.verify(secret_key, expected_case_id="case-wrong") is False

    # 3. Expected action_type fails if token.action_type is None
    assert token.verify(secret_key, expected_case_id="case-100", expected_action_type="containment") is False
    assert token.verify(secret_key, expected_case_id="case-100", expected_action_type="remote_collection") is False

    # 4. Expected target fails if token.target is None
    assert token.verify(secret_key, expected_case_id="case-100", expected_target="10.0.0.5") is False

    # 5. Expected parameter_digest fails if token.parameter_digest is None
    assert token.verify(secret_key, expected_case_id="case-100", expected_parameter_digest="sha256:abc123") is False


def test_sec_appr_001_properly_bound_token_succeeds(secret_key: str):
    """Verify that a properly bound token passes verification when all constraints match."""
    token = HumanApprovalToken(
        token_id="gate-test-bound",
        node_id="online_gate",
        case_id="case-100",
        action_type="remote_collection",
        target="192.168.1.50",
        parameter_digest="sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        issued_by="lead_investigator",
        timestamp_utc=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        is_valid=True,
    )
    token.sign(secret_key)

    # All matching constraints pass
    assert token.verify(
        secret_key=secret_key,
        expected_case_id="case-100",
        expected_action_type="remote_collection",
        expected_target="192.168.1.50",
        expected_parameter_digest="sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ) is True

    # Any mismatch fails
    assert token.verify(secret_key, expected_action_type="containment") is False
    assert token.verify(secret_key, expected_target="192.168.1.99") is False
    assert token.verify(secret_key, expected_parameter_digest="sha256:wrong") is False


# ==============================================================================
# SEC-APPR-002: Workflow Approval-Token Endpoint Scoping
# ==============================================================================

def test_sec_appr_002_workflow_token_scoped_and_bounded(client: TestClient, auth_headers: Dict[str, str]):
    """Verify that POST /api/workflows/approval-token issues scoped tokens with expiration and action_type."""
    # Ensure case exists
    c_res = client.post(
        "/api/cases",
        json={"case_id": "case-test-scoped", "case_name": "Scoped Token Case", "lead_analyst": "admin"},
        headers=auth_headers,
    )
    assert c_res.status_code == 201

    # 1. Issue token for a generic workflow node
    from backend.app.api.deps import get_approval_engine
    engine = get_approval_engine("case-test-scoped")
    engine.create_request(
        case_id="case-test-scoped",
        requesting_investigator="ai_planner",
        action_type="workflow_node_execution",
        target="node:node_analysis_step",
        capability_id="node_analysis_step",
        reason="Workflow step execution",
    )

    res = client.post(
        "/api/workflows/approval-token",
        json={"case_id": "case-test-scoped", "node_id": "node_analysis_step"},
        headers=auth_headers,
    )
    assert res.status_code == 200
    data = res.json()
    assert data["action_type"] == "workflow_node_execution"
    assert data["target"] == "node:node_analysis_step"
    assert data["approval_id"] is not None
    assert data["expires_at_utc"] is not None

    # Verify expiration is in the future
    exp_dt = datetime.fromisoformat(data["expires_at_utc"].replace("Z", "+00:00"))
    assert exp_dt > datetime.now(timezone.utc)

    # 2. Issue token for a sensitive containment node with mandatory target
    engine.create_request(
        case_id="case-test-scoped",
        requesting_investigator="ai_planner",
        action_type="containment",
        target="10.0.1.25",
        capability_id="system_containment",
        reason="Isolate compromised endpoint",
    )

    res2 = client.post(
        "/api/workflows/approval-token",
        json={"case_id": "case-test-scoped", "node_id": "system_containment", "action_type": "containment", "target": "10.0.1.25"},
        headers=auth_headers,
    )
    assert res2.status_code == 200
    data2 = res2.json()
    assert data2["action_type"] == "containment"
    assert data2["target"] == "10.0.1.25"
    assert data2["parameter_digest"] is not None

    # Verify rejection of containment token without target host
    res_no_tgt = client.post(
        "/api/workflows/approval-token",
        json={"case_id": "case-test-scoped", "node_id": "system_containment", "action_type": "containment"},
        headers=auth_headers,
    )
    assert res_no_tgt.status_code == 422

    # Verify remote collection requests are permanently rejected with 400
    res_remote = client.post(
        "/api/workflows/approval-token",
        json={"case_id": "case-test-scoped", "node_id": "node_online_collector", "target": "10.0.1.25"},
        headers=auth_headers,
    )
    assert res_remote.status_code == 400

    # 3. Token cannot be verified as containment or arbitrary sensitive action
    settings = get_settings()
    tok_obj = HumanApprovalToken.model_validate(data)
    assert tok_obj.verify(settings.human_approval_hmac_secret, expected_action_type="containment") is False


# ==============================================================================
# SEC-EXEC-001: Container Path Translation
# ==============================================================================

def test_sec_exec_001_build_container_argv_translates_host_paths():
    """Verify that build_container_argv replaces host paths with /evidence and /scratch."""
    runner = AirGappedSubprocessRunner(container_runtime="docker")
    policy = ToolExecutionPolicy(
        tool_id="test_tool",
        name="Test Tool",
        version="1.0.0",
        approved_binary="test_bin",
        container_image="ghcr.io/forensicops/test:latest",
        resource_limits=ResourceLimits(cpu_limit=2.0, memory_limit="2g", pids_limit=100),
    )

    host_input = Path("/vault/case123/blobs/ab/ab5678.blob")
    host_scratch = Path("/vault/case123/scratch/tool1")

    # Command array with host paths
    argv = ["test_bin", "-f", str(host_input), "--out", str(host_scratch)]

    cmd = runner.build_container_argv(
        argv=argv,
        container_image=policy.container_image,
        readonly_input_dir=host_input.parent,
        scratch_output_dir=host_scratch,
        tool_policy=policy,
    )

    # Ensure container run arguments have translated in-container paths
    assert "-f" in cmd
    input_idx = cmd.index("-f") + 1
    assert cmd[input_idx] == "/evidence/ab5678.blob" or cmd[input_idx].startswith("/evidence")
    assert "--out" in cmd
    out_idx = cmd.index("--out") + 1
    assert cmd[out_idx] == "/scratch"


def test_sec_exec_001_plugin_runner_container_path_translation(tmp_path: Path):
    """Verify that PluginRunner translates paths when container execution applies."""
    sub_runner = AirGappedSubprocessRunner(allow_test_mock=False)
    runner = PluginRunner(subprocess_runner=sub_runner)

    workspace = tmp_path / "workspace"
    evidence_file = tmp_path / "evidence" / "test.evtx"
    evidence_file.parent.mkdir(parents=True)
    evidence_file.write_bytes(b"dummy evtx data")

    artifact = ArtifactRecord(
        artifact_id="art-test-01",
        case_id="case-container-test",
        type="evtx",
        original_path=str(evidence_file),
        blob_path=str(evidence_file),
        size_bytes=evidence_file.stat().st_size,
        sha256="abc123456",
        sha512="def567890",
        acquired_utc=datetime.now(timezone.utc).isoformat(),
        acquisition_method="test",
    )

    card = ToolPluginCard(
        tool_id="ez_evtxecmd",
        name="Eric Zimmerman EvtxECmd",
        version="1.5.0",
        description="Eric Zimmerman EvtxECmd parser",
        category="triage",
        artifact_type="evtx",
        container_image="ghcr.io/forensicops/ez-tools:latest",
        command_template=["evtxecmd", "-f", "{input_path}", "--json", "{output_dir}"],
    )

    # Intercept execute call to inspect the constructed argv
    captured_argv = []
    def fake_execute(argv, cwd, **kwargs):
        captured_argv.extend(argv)
        return 0, "[]", "", 0.1

    sub_runner.execute = fake_execute

    with patch.object(sub_runner, "allow_test_mock", False):
        runner.run_plugin(
            plugin=card,
            artifact=artifact,
            output_workspace=workspace,
        )

    # Assert that argv received by execute contains translated in-container paths
    assert captured_argv[0] == "evtxecmd"
    assert captured_argv[1] == "-f"
    assert captured_argv[2] == f"/evidence/{evidence_file.name}"
    assert captured_argv[3] == "--json"
    assert captured_argv[4] == "/scratch"
