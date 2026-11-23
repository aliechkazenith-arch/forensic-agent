"""Test Suite for Phase 13: High Priority Security Defect Remediation.

Covers:
1. Approval Token Strict Validation (Mandatory Target & Non-Empty Parameter Digest).
2. Two-Person Rule & Self-Approval Prevention in Workflow Approval Tokens.
3. Unified Token Registration & Consumption in ApprovalEngine.
4. SEC-APPR-003: Target Mismatch Rejection in SSH Collector Gate.
5. SEC-EXEC-002: Container Evidence Single-File Isolation (No Sibling Exposure).
6. Missing /rules Volume Mount in Container Runtimes.
7. SEC-CUST-001: Zero-Copy Evidence Read-Only Attribute Enforcement.
8. SEC-NET-001: SSRF Loopback Defense Active Even Under Dev/Private Overrides.
9. SEC-EXEC-003: Disallowed and Allowed Argument Validation in Execution Policy.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any, Dict
from uuid import uuid4
import pytest
from fastapi.testclient import TestClient

from backend.app.api.deps import (
    get_approval_engine,
    get_custody_engine,
    reset_dependencies,
    set_base_vault_dir,
)
from backend.app.auth.dependencies import set_user_store
from backend.app.auth.models import UserCreate
from backend.app.auth.security import create_access_token, hash_password
from backend.app.auth.store import UserStore
from backend.app.core.approval_engine import compute_parameter_digest
from backend.app.core.config import get_settings
from backend.app.core.custody_engine import CustodyEngine, safe_make_writable
from backend.app.core.exceptions import (
    ExecutionPolicyError,
    SSRFSecurityError,
    UnauthorizedCollectorExecutionError,
)
from backend.app.core.execution_policy import (
    ExecutionPolicyRegistry,
    ToolExecutionPolicy,
    get_execution_policy_registry,
)
from backend.app.core.network_validator import resolve_and_validate_destination
from backend.app.core.plugin_runner import (
    AirGappedSubprocessRunner,
    PluginRunner,
)
from backend.app.db.sqlite_store import get_llm_state_store, reset_llm_state_store
from backend.app.main import create_app
from backend.app.models.plugins import ToolPluginCard
from backend.app.models.workflow import HumanApprovalToken


@pytest.fixture
def phase13_env(tmp_path: Path):
    """Hermetic isolated environment for Phase 13 security hardening tests."""
    vault_dir = tmp_path / "vault"
    vault_dir.mkdir(parents=True, exist_ok=True)
    secret_key = "test-phase13-security-hmac-secret-32b!!"
    jwt_secret = "test-phase13-security-jwt-secret-32b!!"

    old_env = {
        "FORENSICOPS_VAULT_DIR": os.environ.get("FORENSICOPS_VAULT_DIR"),
        "FORENSICOPS_JWT_SECRET": os.environ.get("FORENSICOPS_JWT_SECRET"),
        "HUMAN_APPROVAL_HMAC_SECRET": os.environ.get("HUMAN_APPROVAL_HMAC_SECRET"),
        "FORENSICOPS_AUTH_DISABLED": os.environ.get("FORENSICOPS_AUTH_DISABLED"),
        "FORENSICOPS_ALLOW_PRIVATE_TARGETS": os.environ.get("FORENSICOPS_ALLOW_PRIVATE_TARGETS"),
    }

    os.environ["FORENSICOPS_VAULT_DIR"] = str(vault_dir)
    os.environ["FORENSICOPS_JWT_SECRET"] = jwt_secret
    os.environ["HUMAN_APPROVAL_HMAC_SECRET"] = secret_key
    os.environ["FORENSICOPS_AUTH_DISABLED"] = "false"

    set_base_vault_dir(vault_dir)
    reset_dependencies()
    reset_llm_state_store()

    # User Store setup
    users_db = vault_dir / "users.db"
    user_store = UserStore(db_path=users_db)
    set_user_store(user_store)

    lead_user = user_store.create_user(
        UserCreate(
            username="sec_lead",
            password="password123",
            role="lead_investigator",
            badge_id="BADGE-SEC-01",
            full_name="Lead Security Architect",
        ),
        password_hash=hash_password("password123"),
    )

    analyst_user = user_store.create_user(
        UserCreate(
            username="sec_analyst",
            password="password123",
            role="soc_analyst",
            badge_id="BADGE-SEC-02",
            full_name="SOC Triage Analyst",
        ),
        password_hash=hash_password("password123"),
    )

    tokens = {
        "lead": create_access_token({"sub": lead_user.username, "user_id": lead_user.id, "role": lead_user.role, "badge_id": lead_user.badge_id}),
        "analyst": create_access_token({"sub": analyst_user.username, "user_id": analyst_user.id, "role": analyst_user.role, "badge_id": analyst_user.badge_id}),
    }

    app = create_app()
    client = TestClient(app)

    case_id = "case-phase13-sec"
    state_store = get_llm_state_store()
    state_store.create_or_update_case({
        "case_id": case_id,
        "case_name": "Phase 13 Security Hardening Case",
        "lead_analyst": lead_user.username,
        "organization_name": "ForensicOps AI Labs",
        "status": "OPEN",
    })

    yield {
        "client": client,
        "tokens": tokens,
        "case_id": case_id,
        "vault_dir": vault_dir,
        "secret_key": secret_key,
        "lead_user": lead_user,
        "analyst_user": analyst_user,
    }

    reset_dependencies()
    reset_llm_state_store()
    for k, v in old_env.items():
        if v is not None:
            os.environ[k] = v
        else:
            os.environ.pop(k, None)

    for root, _, files in os.walk(vault_dir):
        for f in files:
            safe_make_writable(Path(root) / f)


# ==============================================================================
# PACKAGE 1: Approval Token Strict Validation
# ==============================================================================

def test_approval_token_remote_collection_rejected_and_containment_requires_target(phase13_env: Dict[str, Any]):
    """Verify that remote collection is rejected (400) and containment tokens require target hosts."""
    client: TestClient = phase13_env["client"]
    token = phase13_env["tokens"]["lead"]
    case_id = phase13_env["case_id"]
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    # 1. Action type remote_collection is permanently rejected -> 400 Bad Request
    resp1 = client.post(
        "/api/workflows/approval-token",
        json={"case_id": case_id, "node_id": "collector_gate", "action_type": "remote_collection"},
        headers=headers,
    )
    assert resp1.status_code == 400
    assert "Remote collection has been removed" in resp1.json()["detail"]

    # 2. Containment action without target host -> 422 or 400
    resp2 = client.post(
        "/api/workflows/approval-token",
        json={"case_id": case_id, "node_id": "isolate_host", "action_type": "containment"},
        headers=headers,
    )
    assert resp2.status_code in (400, 422)

    # 3. Supplying target host for containment -> 200 OK with strictly bound target
    engine = get_approval_engine(case_id)
    engine.create_request(
        case_id=case_id,
        requesting_investigator="ai_planner",
        action_type="containment",
        target="192.168.10.15",
        capability_id="isolate_host",
        reason="Host containment request",
    )
    resp3 = client.post(
        "/api/workflows/approval-token",
        json={"case_id": case_id, "node_id": "isolate_host", "action_type": "containment", "target": "192.168.10.15"},
        headers=headers,
    )
    assert resp3.status_code == 200
    data = resp3.json()
    assert data["target"] == "192.168.10.15"
    assert data["action_type"] == "containment"


def test_approval_token_enforces_non_empty_parameter_digest(phase13_env: Dict[str, Any]):
    """Verify that every token receives a non-empty, deterministic parameter digest."""
    client: TestClient = phase13_env["client"]
    token = phase13_env["tokens"]["lead"]
    case_id = phase13_env["case_id"]
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    engine = get_approval_engine(case_id)
    engine.create_request(
        case_id=case_id,
        requesting_investigator="ai_planner",
        action_type="workflow_node_execution",
        target="node:generic_analysis_node",
        capability_id="generic_analysis_node",
        reason="Analysis node",
    )

    # Token requested without explicit parameters
    resp = client.post(
        "/api/workflows/approval-token",
        json={"case_id": case_id, "node_id": "generic_analysis_node"},
        headers=headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["parameter_digest"] is not None
    assert data["parameter_digest"].startswith("sha256:")
    assert len(data["parameter_digest"]) == 71  # sha256: + 64 hex chars


# ==============================================================================
# PACKAGE 4: Two-Person Authorization & Approval Lifecycle
# ==============================================================================

def test_two_person_rule_rejects_self_approval(phase13_env: Dict[str, Any]):
    """Verify that an investigator cannot approve an action they requested themselves."""
    client: TestClient = phase13_env["client"]
    lead_token = phase13_env["tokens"]["lead"]
    case_id = phase13_env["case_id"]
    headers = {"Authorization": f"Bearer {lead_token}", "Content-Type": "application/json"}

    engine = get_approval_engine(case_id)
    # 1. Requester sec_lead creates request
    req1 = engine.create_request(
        case_id=case_id,
        requesting_investigator="sec_lead",
        action_type="containment",
        target="10.0.1.50",
        capability_id="system_containment",
        reason="Host containment",
    )

    # Requester sec_lead tries to issue an approval token as sec_lead -> 400 Bad Request
    resp = client.post(
        "/api/workflows/approval-token",
        json={
            "case_id": case_id,
            "node_id": "system_containment",
            "action_type": "containment",
            "target": "10.0.1.50",
            "approval_id": req1.approval_id,
        },
        headers=headers,
    )
    assert resp.status_code == 400
    assert "Self-approval rejected" in resp.json()["detail"]

    # 2. Different requester (sec_analyst) creates request, approved by sec_lead -> 200 OK
    req2 = engine.create_request(
        case_id=case_id,
        requesting_investigator="sec_analyst",
        action_type="containment",
        target="10.0.1.50",
        capability_id="system_containment",
        reason="Host containment by analyst",
    )
    resp_ok = client.post(
        "/api/workflows/approval-token",
        json={
            "case_id": case_id,
            "node_id": "system_containment",
            "action_type": "containment",
            "target": "10.0.1.50",
            "approval_id": req2.approval_id,
        },
        headers=headers,
    )
    assert resp_ok.status_code == 200
    assert resp_ok.json()["is_valid"] is True


def test_workflow_approval_registered_and_consumed_in_approval_engine(phase13_env: Dict[str, Any]):
    """Verify that workflow approval tokens are recorded in ApprovalEngine and consumable."""
    client: TestClient = phase13_env["client"]
    lead_token = phase13_env["tokens"]["lead"]
    case_id = phase13_env["case_id"]
    headers = {"Authorization": f"Bearer {lead_token}", "Content-Type": "application/json"}

    engine = get_approval_engine(case_id)
    req = engine.create_request(
        case_id=case_id,
        requesting_investigator="sec_analyst",
        action_type="workflow_node_execution",
        target="node:node_analysis",
        capability_id="node_analysis",
        reason="Analysis execution",
    )

    resp = client.post(
        "/api/workflows/approval-token",
        json={"case_id": case_id, "node_id": "node_analysis", "target": "node:node_analysis", "approval_id": req.approval_id},
        headers=headers,
    )
    assert resp.status_code == 200
    token_data = resp.json()

    # Check that approval request was updated into status approved
    appr_req = engine.get_request(token_data["approval_id"])
    assert appr_req is not None
    assert appr_req.case_id == case_id
    assert appr_req.target == "node:node_analysis"
    assert appr_req.status.value == "approved"

    # Verify that the token can be consumed
    tok = HumanApprovalToken.model_validate(token_data)
    engine.consume_token(tok.token_id)

    # Replay attempt must raise error
    with pytest.raises(UnauthorizedCollectorExecutionError, match="already been consumed"):
        engine.consume_token(tok.token_id)


def test_sec_appr_003_approval_engine_rejects_target_mismatch(phase13_env: Dict[str, Any]):
    """Verify that a token bound to Target A is strictly rejected when verified against Target B."""
    case_id = phase13_env["case_id"]
    engine = get_approval_engine(case_id)
    secret_key = phase13_env["secret_key"]

    # Pre-create and approve request bound to 192.168.1.10
    param_dig = compute_parameter_digest({"host": "192.168.1.10"})
    appr_req = engine.create_request(
        case_id=case_id,
        requesting_investigator="planner_agent",
        action_type="containment",
        target="192.168.1.10",
        capability_id="isolate_host",
        parameters={"host": "192.168.1.10"},
        reason="Isolate compromised host 192.168.1.10",
    )
    from backend.app.auth.models import UserRead
    from datetime import datetime, timezone
    approver = UserRead(
        id=str(uuid4()),
        username="sec_lead_approver",
        badge_id="BADGE-SEC-01",
        created_at=datetime.now(timezone.utc).isoformat(),
        role="lead_investigator",
        is_active=True,
    )
    result = engine.approve_request(
        approval_id=appr_req.approval_id,
        approver=approver,
        reason="Authorized containment",
    )
    token = result.token

    # Verification against mismatched target 192.168.1.20 must fail closed
    with pytest.raises(UnauthorizedCollectorExecutionError, match="Target mismatch"):
        engine.verify_and_consume_token(
            token=token,
            expected_case_id=case_id,
            expected_action_type="containment",
            expected_target="192.168.1.20",
            expected_parameters={"host": "192.168.1.10"},
            consumed_by="containment_daemon",
        )


# ==============================================================================
# PACKAGE 2: Container Evidence Isolation (SEC-EXEC-002)
# ==============================================================================

def test_sec_exec_002_container_evidence_isolation_single_file_mount(tmp_path: Path):
    """Verify build_container_argv mounts only the single target evidence file, not the parent directory."""
    runner = AirGappedSubprocessRunner(container_runtime="docker")
    policy = ToolExecutionPolicy(
        tool_id="evtx_dump",
        name="EVTX Dump",
        version="1.0.0",
        approved_binary="evtx_dump",
        container_image="registry.local/dfir/evtx_dump:1.0",
    )

    # Create evidence directory with target and sensitive sibling
    evidence_dir = tmp_path / "evidence_shard"
    evidence_dir.mkdir()
    target_file = evidence_dir / "Security.evtx"
    target_file.write_bytes(b"target_evtx_blob")
    sibling_secret = evidence_dir / "unauthorized_memory.dmp"
    sibling_secret.write_bytes(b"sensitive_case_data")

    scratch_dir = tmp_path / "scratch"
    scratch_dir.mkdir()

    cmd = runner.build_container_argv(
        argv=["evtx_dump", "/evidence/Security.evtx"],
        container_image="registry.local/dfir/evtx_dump:1.0",
        readonly_input_file=target_file,
        scratch_output_dir=scratch_dir,
        tool_policy=policy,
    )

    cmd_str = " ".join(cmd)
    # Target file must be mounted directly as single file
    expected_mount = f"{target_file.resolve()}:/evidence/Security.evtx:ro"
    assert expected_mount in cmd_str

    # Parent directory must NOT be mounted
    unwanted_mount = f"{evidence_dir.resolve()}:/evidence:ro"
    assert unwanted_mount not in cmd_str


# ==============================================================================
# PACKAGE 3: Missing /rules Volume Mount
# ==============================================================================

def test_container_rules_volume_mount(tmp_path: Path):
    """Verify build_container_argv mounts rules file/dir into /rules:ro."""
    runner = AirGappedSubprocessRunner(container_runtime="podman")
    policy = ToolExecutionPolicy(
        tool_id="yara_scanner",
        name="YARA Scanner",
        version="4.2.0",
        approved_binary="yara",
        container_image="registry.local/dfir/yara:4.2.0",
    )

    rules_file = tmp_path / "malware_rules.yar"
    rules_file.write_text("rule Mal { condition: true }", encoding="utf-8")
    scratch_dir = tmp_path / "scratch"
    scratch_dir.mkdir()

    cmd = runner.build_container_argv(
        argv=["yara", "/rules/malware_rules.yar", "/evidence/sample.bin"],
        container_image="registry.local/dfir/yara:4.2.0",
        scratch_output_dir=scratch_dir,
        rules_path=rules_file,
        tool_policy=policy,
    )

    cmd_str = " ".join(cmd)
    expected_rules_mount = f"{rules_file.resolve()}:/rules/malware_rules.yar:ro"
    assert expected_rules_mount in cmd_str


# ==============================================================================
# ADDITIONAL SECURITY HARDENING
# ==============================================================================

def test_sec_cust_001_zero_copy_sets_readonly(tmp_path: Path):
    """Verify that register_zero_copy_reference sets read-only attributes on source image."""
    vault = tmp_path / "vault"
    vault.mkdir()
    custody = CustodyEngine(vault_root=vault)

    img_file = tmp_path / "disk.raw"
    img_file.write_bytes(b"\x00" * 4096)
    # Ensure initially writable
    os.chmod(img_file, stat.S_IREAD | stat.S_IWRITE)
    assert os.access(img_file, os.W_OK)

    custody.register_zero_copy_reference(
        case_id="case-zc",
        file_path=img_file,
        artifact_type="disk_image",
        actor="lead_analyst",
    )

    # After registration, write permissions must be removed
    mode = os.stat(img_file).st_mode
    is_write_restricted = (mode & stat.S_IWRITE == 0) or not os.access(img_file, os.W_OK)
    assert is_write_restricted is True

    # Cleanup permission for teardown
    safe_make_writable(img_file)


def test_sec_net_001_dev_mode_still_blocks_loopback(monkeypatch):
    """Verify that SSRF loopback defense blocks 127.0.0.1 and localhost even with dev overrides."""
    monkeypatch.setenv("FORENSICOPS_ALLOW_PRIVATE_TARGETS", "true")
    monkeypatch.setenv("FORENSICOPS_ALLOW_PRIVATE_SIEM", "false")

    # 127.0.0.1 must be rejected
    with pytest.raises(SSRFSecurityError, match="restricted host|loopback"):
        resolve_and_validate_destination("127.0.0.1", enforce_strict=False)

    # localhost must be rejected
    with pytest.raises(SSRFSecurityError, match="restricted host|loopback"):
        resolve_and_validate_destination("localhost", enforce_strict=False)


def test_sec_exec_003_execution_policy_disallowed_arguments():
    """Verify that disallowed arguments raise ExecutionPolicyError."""
    registry = ExecutionPolicyRegistry()
    policy = ToolExecutionPolicy(
        tool_id="yara_custom",
        name="Custom YARA",
        version="1.0.0",
        approved_binary="yara",
        container_image="registry.local/yara:1.0",
        disallowed_arguments=["--output-format=exe", "--danger"],
        allowed_arguments=["-s", "-m", "-r"],
    )
    registry.register_policy(policy)

    # Disallowed argument -> ExecutionPolicyError
    with pytest.raises(ExecutionPolicyError, match="prohibited by execution policy"):
        registry.validate_tool_execution(
            tool_id="yara_custom",
            argv=["yara", "--output-format=exe", "/evidence/sample.bin"],
            container_image="registry.local/yara:1.0",
        )

    # Unlisted flag when allowed_arguments specified -> ExecutionPolicyError
    with pytest.raises(ExecutionPolicyError, match="not in allowed arguments"):
        registry.validate_tool_execution(
            tool_id="yara_custom",
            argv=["yara", "--unauthorized-flag", "/evidence/sample.bin"],
            container_image="registry.local/yara:1.0",
        )

    # Allowed argument -> passes
    validated = registry.validate_tool_execution(
        tool_id="yara_custom",
        argv=["yara", "-s", "/evidence/sample.bin"],
        container_image="registry.local/yara:1.0",
    )
    assert validated.tool_id == "yara_custom"
