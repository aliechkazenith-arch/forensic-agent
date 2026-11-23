"""Phase 08 Comprehensive Regression Tests: Human Approval and Action Authorization Engine.

Validates:
1. Central deterministic action risk policy (allow, require approval, deny, block unknown).
2. Operation-specific approval requests bound to canonical parameter digest.
3. Cryptographic HMAC-SHA256 signatures with no fallback secret.
4. Token replay protection (one-time consumption).
5. Expired token and request rejection.
6. Changed parameter and changed target rejection.
7. Case ID mismatch rejection.
8. Agent self-approval prevention.
9. Approver RBAC enforcement (auditor blocked, lead/analyst allowed).
10. Approval lifecycle transitions and revocation.
11. Custody audit logging for all approval transitions.
12. API endpoints for approval creation, listing, approval, rejection, and revocation.
13. Autonomous InvestigationController approval gate integration.
"""
import os
import json
import pytest
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import MagicMock

from backend.app.core.action_risk_policy import (
    ActionRiskPolicy,
    ActionRiskLevel,
    ActionType,
    APPROVED_OFFLINE_CAPABILITIES,
)
from backend.app.models.approval import (
    ApprovalRequest,
    ApprovalStatus,
    compute_parameter_digest,
)
from backend.app.models.workflow import HumanApprovalToken
from backend.app.core.approval_engine import (
    ApprovalEngine,
    generate_secure_approval_token,
    verify_approval_token,
)
from backend.app.core.custody_engine import CustodyEngine
from backend.app.core.exceptions import (
    ForensicOpsError,
    ExecutionPolicyError,
    UnauthorizedCollectorExecutionError,
)
from backend.app.auth.models import UserRead
from backend.app.models.investigation import (
    InvestigationAction,
    InvestigationLifecycleState,
    ToolRequest,
)
from backend.app.agent.investigation_controller import InvestigationController
from backend.app.core.storage import ForensicStore
from backend.app.db.sqlite_store import LLMStateStore
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.auth.dependencies import get_current_user
from backend.app.api.deps import get_approval_engine, get_case_authorization_service


def make_user(username: str, role: str = "lead_investigator") -> UserRead:
    """Helper to create a typed UserRead object for testing."""
    return UserRead(
        id=f"usr-{username}",
        username=username,
        badge_id=f"B-{username}",
        role=role,
        full_name=username.replace("_", " ").title(),
        created_at=datetime.now(timezone.utc).isoformat(),
        is_active=True,
    )


# ------------------------------------------------------------------------------
# Test 1: Action Risk Policy Classifications
# ------------------------------------------------------------------------------
def test_action_risk_policy_classifications():
    """Verify deterministic policy evaluates actions according to AGENTS.md rules."""
    # 1. Read-only offline analysis: auto-allowed without approval
    eval_dissect = ActionRiskPolicy.evaluate("read_only_offline_analysis", "dissect_evtx")
    assert eval_dissect.is_allowed is True
    assert eval_dissect.requires_approval is False
    assert eval_dissect.risk_level == ActionRiskLevel.LOW
    assert eval_dissect.action_type == ActionType.READ_ONLY_OFFLINE_ANALYSIS

    # 2. Local evidence modification: denied by default (RFC 3227 / AGENTS.md Principle 3)
    eval_mod = ActionRiskPolicy.evaluate("local_evidence_modification", "modify_evidence")
    assert eval_mod.is_allowed is False
    assert eval_mod.requires_approval is False
    assert eval_mod.risk_level == ActionRiskLevel.CRITICAL
    assert "Evidence modification" in eval_mod.policy_reason

    # 3. Remote collection: approval required
    eval_coll = ActionRiskPolicy.evaluate("remote_collection", "ssh_collector")
    assert eval_coll.is_allowed is True
    assert eval_coll.requires_approval is True
    assert eval_coll.risk_level in (ActionRiskLevel.HIGH, ActionRiskLevel.CRITICAL)

    # 4. Remote access: approval required
    eval_rem = ActionRiskPolicy.evaluate("remote_access", "ssh_exec")
    assert eval_rem.is_allowed is True
    assert eval_rem.requires_approval is True

    # 5. Network access: approval required
    eval_net = ActionRiskPolicy.evaluate("network_access", "external_dns")
    assert eval_net.is_allowed is True
    assert eval_net.requires_approval is True

    # 6. Containment: approval required
    eval_cont = ActionRiskPolicy.evaluate("containment", "isolate_host")
    assert eval_cont.is_allowed is True
    assert eval_cont.requires_approval is True
    assert eval_cont.risk_level == ActionRiskLevel.CRITICAL

    # 7. Deletion: approval required
    eval_del = ActionRiskPolicy.evaluate("deletion", "delete_artifact")
    assert eval_del.is_allowed is True
    assert eval_del.requires_approval is True
    assert eval_del.risk_level == ActionRiskLevel.CRITICAL

    # 8. External sharing: approval required
    eval_share = ActionRiskPolicy.evaluate("external_sharing", "export_external")
    assert eval_share.is_allowed is True
    assert eval_share.requires_approval is True

    # 9. Report signing: approval required
    eval_sign = ActionRiskPolicy.evaluate("report_signing", "finalize_report")
    assert eval_sign.is_allowed is True
    assert eval_sign.requires_approval is True

    # 10. Unknown actions: blocked by default
    eval_unknown = ActionRiskPolicy.evaluate("unknown_action", "unregistered_custom_script")
    assert eval_unknown.is_allowed is False
    assert eval_unknown.requires_approval is False
    assert eval_unknown.risk_level == ActionRiskLevel.CRITICAL
    assert "Unknown or unclassified" in eval_unknown.policy_reason


# ------------------------------------------------------------------------------
# Test 2: Operation-Specific Approval Request Binding & Parameter Digest
# ------------------------------------------------------------------------------
def test_approval_request_binding_and_parameter_digest():
    """Verify approval request binds operation fields and canonicalizes parameter digest."""
    params = {"timeout": 30, "target_ip": "10.0.0.5", "commands": ["whoami", "uname -a"]}
    # Permute dictionary key order
    params_reordered = {"commands": ["whoami", "uname -a"], "timeout": 30, "target_ip": "10.0.0.5"}

    digest1 = compute_parameter_digest(params)
    digest2 = compute_parameter_digest(params_reordered)
    assert digest1 == digest2
    assert digest1.startswith("sha256:")

    req = ApprovalRequest(
        approval_id="appr-test-001",
        case_id="case-binding-01",
        requesting_investigator="analyst_alice",
        action_type="remote_collection",
        target="10.0.0.5",
        capability_id="ssh_collector",
        parameters=params,
        risk_level=ActionRiskLevel.HIGH,
        justification="Collect triage archive from compromised bastion",
    )

    assert req.parameter_digest == digest1
    assert req.verify_parameters(params) is True
    assert req.verify_parameters(params_reordered) is True
    # Changing any parameter must fail verification
    assert req.verify_parameters({"timeout": 60, "target_ip": "10.0.0.5"}) is False


# ------------------------------------------------------------------------------
# Test 3: Cryptographic HMAC Signature & No Fallback Secret
# ------------------------------------------------------------------------------
def test_hmac_signature_calculation_and_no_fallback_secret():
    """Verify HMAC token calculation fails without explicit secret and verifies accurately."""
    secret = "production-grade-hmac-secret-string-2026"
    now_utc = datetime.now(timezone.utc).isoformat()
    exp_utc = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()

    token = HumanApprovalToken(
        token_id="tok-001",
        node_id="act-remote-triage",
        case_id="case-hmac-01",
        issued_by="lead_investigator",
        timestamp_utc=now_utc,
        approval_id="appr-001",
        action_type="remote_collection",
        target="srv-bastion.internal",
        parameter_digest="sha256:abc123canonicaldigest",
        expires_at_utc=exp_utc,
    )

    # Must fail if secret is empty or missing
    with pytest.raises(ValueError, match="HMAC secret must not be empty or default"):
        token.calculate_signature("")

    with pytest.raises(ValueError, match="HMAC secret must not be empty or default"):
        token.calculate_signature("dev_approval_secret_replace_in_production")

    sig = token.calculate_signature(secret)
    token.signature = sig
    assert token.is_valid is True

    # Valid verification
    assert (
        token.verify(
            secret_key=secret,
            expected_case_id="case-hmac-01",
            expected_action_type="remote_collection",
            expected_target="srv-bastion.internal",
            expected_parameter_digest="sha256:abc123canonicaldigest",
        )
        is True
    )

    # Forged signature fails
    token.signature = "bad_signature_deadbeef"
    assert (
        token.verify(
            secret_key=secret,
            expected_case_id="case-hmac-01",
            expected_action_type="remote_collection",
            expected_target="srv-bastion.internal",
            expected_parameter_digest="sha256:abc123canonicaldigest",
        )
        is False
    )


# ------------------------------------------------------------------------------
# Test 4: Replay Protection (One-Time Token Consumption)
# ------------------------------------------------------------------------------
def test_token_replay_protection(tmp_path):
    """Verify approval token can only be consumed once and cannot be replayed."""
    db_file = tmp_path / "approvals.db"
    custody = CustodyEngine(vault_root=tmp_path / "vault")
    secret = "super-secret-hmac-key-test-replay-2026"
    engine = ApprovalEngine(db_path=db_file, custody_engine=custody, secret_key=secret)

    lead = make_user("lead_bob", "lead_investigator")
    params = {"host": "192.168.1.100", "port": 22}

    req = engine.create_request(
        case_id="case-replay-01",
        action_type="remote_collection",
        target="192.168.1.100",
        capability_id="ssh_collector",
        parameters=params,
        requesting_investigator="analyst_carol",
        justification="Forensic triage of victim host",
    )

    # Lead approves and gets signed token
    approved_req = engine.approve_request(req.approval_id, approver=lead, reason="Authorized")
    assert approved_req.token is not None
    token = approved_req.token

    # 1st consumption: succeeds
    verified_req = engine.verify_and_consume_token(
        token=token,
        expected_case_id="case-replay-01",
        expected_action_type="remote_collection",
        expected_target="192.168.1.100",
        expected_parameters=params,
        consumed_by="ssh_collector_daemon",
    )
    assert verified_req.status == ApprovalStatus.CONSUMED

    # 2nd consumption attempt (replay attack): must raise UnauthorizedCollectorExecutionError
    with pytest.raises(UnauthorizedCollectorExecutionError, match="Replay detected: Approval token.*has already been consumed"):
        engine.verify_and_consume_token(
            token=token,
            expected_case_id="case-replay-01",
            expected_action_type="remote_collection",
            expected_target="192.168.1.100",
            expected_parameters=params,
            consumed_by="attacker_daemon",
        )


# ------------------------------------------------------------------------------
# Test 5: Expired Token and Expired Approval Request Rejection
# ------------------------------------------------------------------------------
def test_expired_token_and_request_rejection(tmp_path):
    """Verify expired approval request cannot be approved or consumed."""
    db_file = tmp_path / "approvals.db"
    custody = CustodyEngine(vault_root=tmp_path / "vault")
    secret = "super-secret-hmac-key-test-expiry-2026"
    engine = ApprovalEngine(db_path=db_file, custody_engine=custody, secret_key=secret)

    lead = make_user("lead_bob", "lead_investigator")

    # Create request with validity of -1 minutes (already expired)
    req = engine.create_request(
        case_id="case-exp-01",
        action_type="remote_access",
        target="srv-db.corp",
        capability_id="remote_shell",
        parameters={"session": "db_query"},
        requesting_investigator="analyst_dan",
        validity_minutes=-1,
    )

    # Attempt to approve expired request: fails
    with pytest.raises(ForensicOpsError, match="expired and cannot be approved"):
        engine.approve_request(req.approval_id, approver=lead)

    # Test expired token directly
    exp_token = HumanApprovalToken(
        token_id="tok-exp-001",
        node_id="act-exp",
        case_id="case-exp-01",
        issued_by="lead_bob",
        timestamp_utc=(datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(),
        approval_id="appr-exp-001",
        action_type="remote_access",
        target="srv-db.corp",
        parameter_digest="sha256:digest",
        expires_at_utc=(datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat(),
    )
    exp_token.signature = exp_token.calculate_signature(secret)

    # verify() must return False for expired token
    assert exp_token.verify(secret_key=secret, expected_case_id="case-exp-01") is False


# ------------------------------------------------------------------------------
# Test 6: Parameter Mutation Rejection
# ------------------------------------------------------------------------------
def test_parameter_mutation_rejection(tmp_path):
    """Verify altering parameters between approval and execution fails."""
    db_file = tmp_path / "approvals.db"
    custody = CustodyEngine(vault_root=tmp_path / "vault")
    secret = "super-secret-hmac-key-test-mutation-2026"
    engine = ApprovalEngine(db_path=db_file, custody_engine=custody, secret_key=secret)

    lead = make_user("lead_bob", "lead_investigator")
    orig_params = {"command": "ss -tulpn", "scope": "listening_ports"}

    req = engine.create_request(
        case_id="case-param-01",
        action_type="remote_collection",
        target="10.0.0.1",
        capability_id="ssh_collector",
        parameters=orig_params,
        requesting_investigator="analyst_alice",
    )
    approved = engine.approve_request(req.approval_id, approver=lead)
    token = approved.token

    # Malicious actor changes parameters to destructive command
    mutated_params = {"command": "rm -rf /", "scope": "listening_ports"}

    with pytest.raises(UnauthorizedCollectorExecutionError, match="Parameter digest mismatch"):
        engine.verify_and_consume_token(
            token=token,
            expected_case_id="case-param-01",
            expected_action_type="remote_collection",
            expected_target="10.0.0.1",
            expected_parameters=mutated_params,
        )


# ------------------------------------------------------------------------------
# Test 7: Target Mutation Rejection
# ------------------------------------------------------------------------------
def test_target_mutation_rejection(tmp_path):
    """Verify changing target IP/host fails token verification."""
    db_file = tmp_path / "approvals.db"
    custody = CustodyEngine(vault_root=tmp_path / "vault")
    secret = "super-secret-hmac-key-test-target-2026"
    engine = ApprovalEngine(db_path=db_file, custody_engine=custody, secret_key=secret)

    lead = make_user("lead_bob", "lead_investigator")
    params = {"scan": "quick"}

    req = engine.create_request(
        case_id="case-target-01",
        action_type="remote_collection",
        target="192.168.1.10",
        capability_id="ssh_collector",
        parameters=params,
        requesting_investigator="analyst_alice",
    )
    approved = engine.approve_request(req.approval_id, approver=lead)
    token = approved.token

    # Attempt to consume against different target
    with pytest.raises(UnauthorizedCollectorExecutionError, match="Target mismatch"):
        engine.verify_and_consume_token(
            token=token,
            expected_case_id="case-target-01",
            expected_action_type="remote_collection",
            expected_target="192.168.1.99",
            expected_parameters=params,
        )


# ------------------------------------------------------------------------------
# Test 8: Case ID Mismatch Rejection
# ------------------------------------------------------------------------------
def test_case_id_mismatch_rejection(tmp_path):
    """Verify token from Case A cannot be replayed in Case B."""
    db_file = tmp_path / "approvals.db"
    custody = CustodyEngine(vault_root=tmp_path / "vault")
    secret = "super-secret-hmac-key-test-case-2026"
    engine = ApprovalEngine(db_path=db_file, custody_engine=custody, secret_key=secret)

    lead = make_user("lead_bob", "lead_investigator")
    params = {"tool": "yara"}

    req = engine.create_request(
        case_id="case-alpha",
        action_type="remote_collection",
        target="192.168.1.5",
        capability_id="ssh_collector",
        parameters=params,
        requesting_investigator="analyst_alice",
    )
    approved = engine.approve_request(req.approval_id, approver=lead)
    token = approved.token

    with pytest.raises(UnauthorizedCollectorExecutionError, match="Case ID mismatch"):
        engine.verify_and_consume_token(
            token=token,
            expected_case_id="case-beta",
            expected_action_type="remote_collection",
            expected_target="192.168.1.5",
            expected_parameters=params,
        )


# ------------------------------------------------------------------------------
# Test 9: Agent Self-Approval Prevention
# ------------------------------------------------------------------------------
def test_agent_self_approval_prevention(tmp_path):
    """Verify neither the requesting human nor an agent can self-approve operations."""
    db_file = tmp_path / "approvals.db"
    custody = CustodyEngine(vault_root=tmp_path / "vault")
    secret = "super-secret-hmac-key-test-self-2026"
    engine = ApprovalEngine(db_path=db_file, custody_engine=custody, secret_key=secret)

    # 1. Human self-approval
    alice = make_user("analyst_alice", "lead_investigator")
    req1 = engine.create_request(
        case_id="case-self-01",
        action_type="containment",
        target="10.0.0.2",
        capability_id="isolate_host",
        requesting_investigator="analyst_alice",
    )
    with pytest.raises(ForensicOpsError, match="Self-approval rejected: The requesting investigator or autonomous agent cannot approve"):
        engine.approve_request(req1.approval_id, approver=alice)

    # 2. Agent / AI self-approval
    agent_user = make_user("agent_autonomous_planner", "lead_investigator")
    req2 = engine.create_request(
        case_id="case-self-01",
        action_type="remote_collection",
        target="10.0.0.3",
        capability_id="ssh_collector",
        requesting_investigator="ai_planner",
    )
    with pytest.raises(ForensicOpsError, match="Self-approval rejected: The requesting investigator or autonomous agent cannot approve"):
        engine.approve_request(req2.approval_id, approver=agent_user)


# ------------------------------------------------------------------------------
# Test 10: Approver RBAC Role Enforcement
# ------------------------------------------------------------------------------
def test_approver_rbac_role_enforcement(tmp_path):
    """Verify only lead_investigator or soc_analyst can approve; auditor is rejected."""
    db_file = tmp_path / "approvals.db"
    custody = CustodyEngine(vault_root=tmp_path / "vault")
    secret = "super-secret-hmac-key-test-rbac-2026"
    engine = ApprovalEngine(db_path=db_file, custody_engine=custody, secret_key=secret)

    req = engine.create_request(
        case_id="case-rbac-01",
        action_type="remote_collection",
        target="10.0.0.10",
        capability_id="ssh_collector",
        requesting_investigator="analyst_alice",
    )

    # Auditor cannot approve
    auditor = make_user("auditor_dave", "auditor")
    with pytest.raises(ForensicOpsError, match="Unauthorized approver: Role 'auditor' is not authorized"):
        engine.approve_request(req.approval_id, approver=auditor)

    # SOC Analyst CAN approve
    analyst = make_user("analyst_eve", "soc_analyst")
    approved = engine.approve_request(req.approval_id, approver=analyst, reason="Approved by SOC")
    assert approved.status == ApprovalStatus.APPROVED
    assert approved.approving_investigator == "analyst_eve"


# ------------------------------------------------------------------------------
# Test 11: Approval Lifecycle & Revocation
# ------------------------------------------------------------------------------
def test_approval_lifecycle_rejection_and_revocation(tmp_path):
    """Verify rejecting or revoking an approval permanently prevents execution."""
    db_file = tmp_path / "approvals.db"
    custody = CustodyEngine(vault_root=tmp_path / "vault")
    secret = "super-secret-hmac-key-test-lifecycle-2026"
    engine = ApprovalEngine(db_path=db_file, custody_engine=custody, secret_key=secret)

    lead = make_user("lead_bob", "lead_investigator")

    # 1. Rejection
    req_rej = engine.create_request(
        case_id="case-life-01",
        action_type="containment",
        target="critical-db.prod",
        capability_id="isolate_host",
        requesting_investigator="analyst_alice",
    )
    rejected = engine.reject_request(req_rej.approval_id, rejector=lead, reason="Out of maintenance window")
    assert rejected.status == ApprovalStatus.REJECTED
    assert rejected.decision_reason == "Out of maintenance window"

    # Attempting to approve rejected request fails
    with pytest.raises(ForensicOpsError, match="status 'rejected'"):
        engine.approve_request(req_rej.approval_id, approver=lead)

    # 2. Revocation after approval
    req_rev = engine.create_request(
        case_id="case-life-01",
        action_type="remote_collection",
        target="10.0.0.8",
        capability_id="ssh_collector",
        requesting_investigator="analyst_alice",
    )
    approved = engine.approve_request(req_rev.approval_id, approver=lead)
    token = approved.token

    # Revoke before token consumption
    revoked = engine.revoke_request(req_rev.approval_id, revoker=lead, reason="Incident scope de-escalated")
    assert revoked.status == ApprovalStatus.REVOKED

    # Attempting to consume revoked token fails
    with pytest.raises(UnauthorizedCollectorExecutionError, match="Approval request.*has status 'revoked'"):
        engine.verify_and_consume_token(
            token=token,
            expected_case_id="case-life-01",
            expected_action_type="remote_collection",
            expected_target="10.0.0.8",
        )


# ------------------------------------------------------------------------------
# Test 12: Custody Audit Trail Verification
# ------------------------------------------------------------------------------
def test_custody_audit_trail_recorded(tmp_path):
    """Verify every approval transition produces a verified custody ledger entry."""
    vault = tmp_path / "vault"
    vault.mkdir()
    custody = CustodyEngine(vault_root=vault)
    db_file = tmp_path / "approvals.db"
    secret = "super-secret-hmac-key-test-custody-2026"
    engine = ApprovalEngine(db_path=db_file, custody_engine=custody, secret_key=secret)

    lead = make_user("lead_bob", "lead_investigator")
    case_id = "case-audit-trail-01"

    req = engine.create_request(
        case_id=case_id,
        action_type="remote_collection",
        target="10.0.0.50",
        capability_id="ssh_collector",
        parameters={"port": 22},
        requesting_investigator="analyst_alice",
    )
    approved = engine.approve_request(req.approval_id, approver=lead)
    engine.verify_and_consume_token(
        token=approved.token,
        expected_case_id=case_id,
        expected_action_type="remote_collection",
        expected_target="10.0.0.50",
        expected_parameters={"port": 22},
    )

    ledger = custody.get_custody_chain(case_id=case_id)
    actions = [e.action for e in ledger]
    assert any("approval_requested" in a for a in actions)
    assert any("approval_granted" in a for a in actions)
    assert any("approval_token_consumed" in a for a in actions)


# ------------------------------------------------------------------------------
# Test 13: Approval REST API Endpoints
# ------------------------------------------------------------------------------
def test_approval_rest_api_endpoints(tmp_path):
    """Verify REST API routes for creating, listing, approving, and rejecting requests."""
    vault = tmp_path / "vault"
    vault.mkdir()
    custody = CustodyEngine(vault_root=vault)
    db_file = tmp_path / "approvals.db"
    secret = "api-test-secret-key-2026-production"
    engine = ApprovalEngine(db_path=db_file, custody_engine=custody, secret_key=secret)

    lead_user = make_user("lead_frank", "lead_investigator")
    mock_case_auth = MagicMock()
    mock_case_auth.verify_case_access.return_value = True

    app.dependency_overrides[get_current_user] = lambda: lead_user
    app.dependency_overrides[get_approval_engine] = lambda: engine
    app.dependency_overrides[get_case_authorization_service] = lambda: mock_case_auth

    try:
        client = TestClient(app)

        # 1. Create request
        resp = client.post(
            "/api/approvals/requests",
            json={
                "case_id": "case-api-01",
                "action_type": "remote_collection",
                "target": "10.0.0.12",
                "capability_id": "ssh_collector",
                "parameters": {"depth": 2},
                "justification": "API triage test",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        appr_id = data["approval_id"]
        assert data["status"] == "pending"

        # 2. List requests
        resp_list = client.get("/api/approvals?case_id=case-api-01")
        assert resp_list.status_code == 200
        items = resp_list.json()
        assert len(items) == 1
        assert items[0]["approval_id"] == appr_id

        # 3. Approve request as different user (lead_grace)
        grace_user = make_user("lead_grace", "lead_investigator")
        app.dependency_overrides[get_current_user] = lambda: grace_user

        resp_appr = client.post(
            f"/api/approvals/{appr_id}/approve",
            json={"reason": "Approved by Grace via API"},
        )
        assert resp_appr.status_code == 200, resp_appr.json()
        appr_data = resp_appr.json()
        assert appr_data["request"]["status"] == "approved"
        assert appr_data["token"] is not None
        assert appr_data["token"]["signature"] is not None

        # 4. Auditor cannot approve
        auditor_user = make_user("auditor_sam", "auditor")
        app.dependency_overrides[get_current_user] = lambda: auditor_user

        resp_aud = client.post(
            f"/api/approvals/{appr_id}/approve",
            json={"reason": "Auditor attempt"},
        )
        assert resp_aud.status_code == 403

    finally:
        app.dependency_overrides.clear()


# ------------------------------------------------------------------------------
# Test 14: Autonomous InvestigationController Approval Gate Integration
# ------------------------------------------------------------------------------
def test_investigation_controller_approval_gate_integration(tmp_path):
    """Verify InvestigationController pauses on sensitive action, binds approval, and resumes with valid token."""
    vault = tmp_path / "vault"
    vault.mkdir()
    custody = CustodyEngine(vault_root=vault)
    store = ForensicStore()
    state_store = LLMStateStore(db_path=tmp_path / "state.db")
    secret = "controller-integration-secret-2026"
    engine = ApprovalEngine(db_path=tmp_path / "approvals.db", custody_engine=custody, secret_key=secret)

    case_id = "case-ctrl-gate-01"

    controller = InvestigationController(
        case_id=case_id,
        investigator="analyst_alice",
        custody_engine=custody,
        storage=store,
        state_store=state_store,
        approval_engine=engine,
        secret_key=secret,
    )

    controller.transition_to(InvestigationLifecycleState.EVIDENCE_VALIDATION)
    controller.transition_to(InvestigationLifecycleState.PLANNING)

    # Queue an action that requires approval
    sensitive_act = InvestigationAction(
        action_id="act-gate-001",
        step_index=1,
        action_type="tier_b_tool",
        capability_id="remote_collection",
        artifact_id=case_id,
        arguments={"host": "10.0.0.99"},
        requires_approval=True,
        status="pending",
    )
    controller.record.pending_actions.append(sensitive_act)

    # Run iteration: controller must pause in AWAITING_APPROVAL
    rec = controller.run_iteration()
    assert rec.lifecycle_state == InvestigationLifecycleState.AWAITING_APPROVAL
    assert "requires explicit human approval" in rec.pause_reason
    assert sensitive_act.approval_id is not None

    # Retrieve the automatically created approval request
    appr_req = engine.get_request(sensitive_act.approval_id)
    assert appr_req is not None
    assert appr_req.status == ApprovalStatus.PENDING

    # Attempt resume without token: fails
    with pytest.raises(ForensicOpsError, match="Cannot resume investigation awaiting approval without a valid HumanApprovalToken"):
        controller.resume()

    # Lead investigator approves request
    lead = make_user("lead_commander", "lead_investigator")
    approved_req = engine.approve_request(sensitive_act.approval_id, approver=lead, reason="Mission approved")
    assert approved_req.token is not None

    # Resume with valid token: must transition from AWAITING_APPROVAL to EXECUTING
    rec_resumed = controller.approve_action(sensitive_act.action_id, approved_req.token)
    assert rec_resumed.lifecycle_state == InvestigationLifecycleState.EXECUTING
    resumed_act = [a for a in rec_resumed.pending_actions if a.action_id == sensitive_act.action_id][0]
    assert resumed_act.status == "approved"
    assert resumed_act.approval_token is not None
