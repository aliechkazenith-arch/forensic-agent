"""Workflow Execution & SSE Streaming API Endpoints.

Standards:
- Context-Passing LangGraph DAG Engine (specs/04-TOOL-ADAPTERS-AND-WORKFLOW.md)
- Real-time Server-Sent Events (SSE) Streaming
- Human-in-the-Loop Gate Pause & Resume (AGENTS.md Rule 4)
- 4 Built-In Starter Blueprints
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, AsyncGenerator, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from backend.app.agent.graph import get_starter_blueprints
from backend.app.api.deps import (
    get_approval_engine,
    get_case_authorization_service,
    get_workflow_engine,
)
from backend.app.auth.dependencies import get_current_user, require_roles
from backend.app.auth.models import UserRead
from backend.app.core.exceptions import ForensicOpsError, UnauthorizedCollectorExecutionError
from backend.app.db.sqlite_store import get_llm_state_store
from backend.app.models.approval import compute_parameter_digest
from backend.app.models.workflow import (
    HumanApprovalToken,
    WorkflowDefinition,
    WorkflowEdgePayload,
    WorkflowExecutionState,
)

router = APIRouter(prefix="/api/workflows", tags=["Workflows"])
workflow_single_router = APIRouter(prefix="/api/workflow", tags=["Workflows"])


class ExecuteWorkflowRequest(BaseModel):
    case_id: str = "default_case"
    workflow: WorkflowDefinition
    initial_pivots: Optional[WorkflowEdgePayload] = None
    approval_tokens: Dict[str, HumanApprovalToken] = Field(default_factory=dict)


class ResumeWorkflowRequest(BaseModel):
    case_id: str = "default_case"
    workflow: WorkflowDefinition
    state: WorkflowExecutionState
    approval_token: HumanApprovalToken


class ApprovalTokenRequest(BaseModel):
    case_id: str = "default_case"
    node_id: str = "workflow_gate"
    reason: Optional[str] = "Manual analyst authorization"
    action_type: Optional[str] = None
    target: Optional[str] = None
    parameters: Optional[Dict[str, Any]] = None
    parameter_digest: Optional[str] = None
    validity_minutes: Optional[int] = 15
    requesting_investigator: Optional[str] = None
    approval_id: Optional[str] = None


@router.post("/approval-token", response_model=HumanApprovalToken)
@workflow_single_router.post("/approval-token", response_model=HumanApprovalToken)
def issue_approval_token(
    req: ApprovalTokenRequest,
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst")),
) -> HumanApprovalToken:
    """Issue a cryptographically signed HumanApprovalToken for a sensitive workflow gate."""
    # Reject remote collection actions (removed in Phase 14.1-R0)
    if req.action_type in ("remote_collection", "remote_endpoint_collection", "remote_access") or any(
        k in (req.node_id or "").lower() for k in ("ssh_collector", "winrm_collector", "online_collector", "remote_collector")
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Remote collection has been removed. ForensicOps AI operates strictly in local/offline mode.",
        )

    case_auth = get_case_authorization_service()
    case_auth.verify_case_access(current_user, req.case_id, action="write")

    validity = req.validity_minutes if req.validity_minutes is not None else 15

    effective_action = req.action_type or "workflow_node_execution"
    effective_target = str(req.target).strip() if req.target else f"node:{req.node_id}"

    # Containment actions require an explicit target host
    if effective_action in ("containment", "system_containment") or (req.node_id and "containment" in req.node_id.lower()):
        if not req.target or not str(req.target).strip() or str(req.target).strip().startswith("node:"):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Containment action requires a non-empty target host.",
            )

    # Non-empty deterministic parameter digest
    if req.parameter_digest:
        param_digest = str(req.parameter_digest).strip()
    elif req.parameters is not None:
        param_digest = compute_parameter_digest(req.parameters)
    else:
        param_digest = compute_parameter_digest({"node_id": req.node_id, "case_id": req.case_id, "target": effective_target})

    # Retrieve pre-existing approval request: Token issuance strictly requires prior independent approval
    engine = get_approval_engine(req.case_id)
    from backend.app.models.approval import ApprovalStatus

    found_req: Optional[Any] = None
    if req.approval_id:
        found_req = engine.get_request(req.approval_id)
        if not found_req:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Approval request '{req.approval_id}' not found.",
            )
    else:
        # Search for an existing request matching case, capability, target
        requests = engine.list_requests(case_id=req.case_id)
        for r in requests:
            if (
                (r.capability_id == req.node_id or r.action_type.value == effective_action)
                and (r.target == effective_target or (not req.target and r.target == f"node:{req.node_id}"))
            ):
                if r.status == ApprovalStatus.PENDING and not r.is_expired():
                    found_req = r
                    break
        if not found_req:
            for r in requests:
                if (
                    (r.capability_id == req.node_id or r.action_type.value == effective_action)
                    and (r.target == effective_target or (not req.target and r.target == f"node:{req.node_id}"))
                ):
                    if r.status == ApprovalStatus.APPROVED and not r.is_expired():
                        found_req = r
                        break

    if not found_req:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Approval token cannot be issued without prior approval. A pending approval request must first be created via POST /api/approvals/requests and approved by an independent investigator.",
        )

    # If the request is already approved, retrieve and return the signed token
    if found_req.status == ApprovalStatus.APPROVED:
        if found_req.is_expired():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Approval request '{found_req.approval_id}' has expired and cannot produce an active token.",
            )
        token = engine.get_approved_token(found_req.approval_id)
        if not token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Approval token for request '{found_req.approval_id}' cannot be issued: it has already been consumed, revoked, or failed security integrity validation.",
            )
        return token

    # If the request is pending, perform genuine independent approval
    if found_req.status == ApprovalStatus.PENDING:
        if found_req.is_expired():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Approval request '{found_req.approval_id}' has expired and cannot be approved.",
            )

        # Validate approver is a human account
        if getattr(current_user, "account_type", "human") != "human" or current_user.username.lower() in {
            "copilot_daemon", "system", "bot_lead", "forensicops_runner", "ai_planner"
        }:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unauthorized approver: Service accounts, autonomous agents, and non-human principals ({current_user.username}) cannot approve actions.",
            )

        # Two-Person Rule: Server-authenticated approver cannot be the requesting investigator or agent
        def _normalize_name(name: Optional[str]) -> str:
            if not name:
                return ""
            return name.split("(")[0].strip().lower()

        base_req = _normalize_name(found_req.requesting_investigator)
        base_appr = _normalize_name(current_user.username)
        req_pid = (found_req.requesting_principal_id or "").strip().lower()
        appr_pid = str(current_user.id or "").strip().lower()

        is_self_approval = False
        if req_pid and appr_pid and req_pid == appr_pid:
            is_self_approval = True
        elif base_req and base_appr and base_req == base_appr:
            is_self_approval = True
        elif found_req.requesting_badge_id and current_user.badge_id and found_req.requesting_badge_id.strip().lower() == str(current_user.badge_id).strip().lower():
            is_self_approval = True
        elif base_appr.startswith("agent") or base_appr.startswith("ai_planner"):
            is_self_approval = True

        if is_self_approval:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Self-approval rejected: The requesting investigator or autonomous agent cannot approve its own operation.",
            )

        try:
            result = engine.approve_request(
                approval_id=found_req.approval_id,
                approver=current_user,
                expiration_seconds=validity * 60,
                reason=req.reason,
            )
            return result.token
        except ForensicOpsError as fe:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(fe))
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to record approval: {e}",
            )

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=f"Approval request '{found_req.approval_id}' is in status '{found_req.status.value}' and cannot be approved.",
    )


@router.get("/blueprints", response_model=Dict[str, WorkflowDefinition])
def get_blueprints(
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst", "auditor")),
) -> Dict[str, WorkflowDefinition]:
    """Return all built-in starter workflow blueprints (Windows Intrusion, Triage, Linux, Memory+PCAP)."""
    return get_starter_blueprints()


def _run_workflow_impl(
    req: ExecuteWorkflowRequest,
    current_user: UserRead,
) -> WorkflowExecutionState:
    """Execute a complete DAG workflow synchronously via POST /api/workflow/run and persist execution state in SQLite session store."""
    case_auth = get_case_authorization_service()
    store = get_llm_state_store()
    if store.get_case(req.case_id):
        case_auth.verify_case_access(current_user, req.case_id, action="execute")
    else:
        case_auth.ensure_case_registered(req.case_id, current_user.username)

    engine = get_workflow_engine(req.case_id)
    try:
        final_state = engine.execute_workflow(
            workflow_def=req.workflow,
            case_id=req.case_id,
            initial_pivots=req.initial_pivots,
            approval_tokens=req.approval_tokens,
        )
        # Automatically update SQLite session store with latest execution state and workflow
        store = get_llm_state_store()
        existing = store.get_investigation_session(req.case_id)
        existing_wizard = existing.get("wizard_state", {}) if existing else {}
        workflow_state_dict = {
            "selected_blueprint_key": getattr(req.workflow, "workflow_id", "custom"),
            "workflow": req.workflow.model_dump(),
            "execution_state": final_state.model_dump(),
            "completed_nodes": final_state.completed_nodes,
            "is_paused": final_state.is_paused,
            "pause_node_id": final_state.pause_node_id,
            "last_run_utc": datetime.now(timezone.utc).isoformat(),
        }
        store.save_investigation_session(
            case_id=req.case_id,
            wizard_state=existing_wizard,
            workflow_state=workflow_state_dict,
            active_tab="canvas",
        )
        return final_state
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Workflow execution failed via /api/workflow/run: {e}",
        )


@router.post("/run", response_model=WorkflowExecutionState)
def run_workflows_plural(
    req: ExecuteWorkflowRequest,
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst")),
) -> WorkflowExecutionState:
    """Execute workflow and persist state via POST /api/workflows/run."""
    return _run_workflow_impl(req, current_user)


@router.post("/execute", response_model=WorkflowExecutionState)
def execute_workflow(
    req: ExecuteWorkflowRequest,
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst")),
) -> WorkflowExecutionState:
    """Execute a complete DAG workflow synchronously to completion or pause (backward compatible)."""
    return _run_workflow_impl(req, current_user)


@workflow_single_router.post("/run", response_model=WorkflowExecutionState)
def run_workflow_singular(
    req: ExecuteWorkflowRequest,
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst")),
) -> WorkflowExecutionState:
    """Execute workflow and persist state via POST /api/workflow/run."""
    return _run_workflow_impl(req, current_user)


@router.post("/resume", response_model=WorkflowExecutionState)
@workflow_single_router.post("/resume", response_model=WorkflowExecutionState)
def resume_workflow(
    req: ResumeWorkflowRequest,
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst")),
) -> WorkflowExecutionState:
    """Resume a paused workflow after analyst presents a valid signed HumanApprovalToken."""
    case_auth = get_case_authorization_service()
    store = get_llm_state_store()
    if store.get_case(req.case_id):
        case_auth.verify_case_access(current_user, req.case_id, action="execute")
    else:
        case_auth.ensure_case_registered(req.case_id, current_user.username)

    engine = get_workflow_engine(req.case_id)
    try:
        resumed_state = engine.resume_workflow(
            workflow_def=req.workflow,
            state=req.state,
            approval_token=req.approval_token,
        )
        return resumed_state
    except (ForensicOpsError, UnauthorizedCollectorExecutionError) as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to resume workflow: {e}",
        )


def _format_sse_event(event_type: str, data: Dict[str, Any]) -> str:
    """Format SSE payload adhering to the standard text/event-stream specification."""
    payload = json.dumps(data, ensure_ascii=True, default=str)
    return f"event: {event_type}\ndata: {payload}\n\n"


@router.post("/stream")
def stream_workflow_execution(
    req: ExecuteWorkflowRequest,
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst")),
) -> StreamingResponse:
    """Stream DAG workflow node state transitions and edge pivot transfers via Server-Sent Events (SSE)."""
    case_auth = get_case_authorization_service()
    store = get_llm_state_store()
    if store.get_case(req.case_id):
        case_auth.verify_case_access(current_user, req.case_id, action="execute")
    else:
        case_auth.ensure_case_registered(req.case_id, current_user.username)

    engine = get_workflow_engine(req.case_id)

    def sse_event_generator():
        # Emit initial start event
        yield _format_sse_event(
            "workflow_started",
            {
                "case_id": req.case_id,
                "workflow_id": req.workflow.workflow_id,
                "workflow_name": req.workflow.name,
                "total_nodes": len(req.workflow.nodes),
            },
        )

        try:
            graph = engine.build_graph(req.workflow)
            app = graph.compile()

            init_state = WorkflowExecutionState(
                case_id=req.case_id,
                workflow_id=req.workflow.workflow_id,
                active_payload=req.initial_pivots or WorkflowEdgePayload(),
                approval_tokens=req.approval_tokens or {},
            )

            current_state = init_state
            # Stream execution chunk by chunk from LangGraph
            for chunk in app.stream(init_state):
                for node_id, node_update in chunk.items():
                    node_obj = req.workflow.get_node(node_id)
                    node_name = node_obj.name if node_obj else node_id

                    # 1. Emit node completed
                    yield _format_sse_event(
                        "node_completed",
                        {
                            "node_id": node_id,
                            "node_name": node_name,
                            "completed_nodes": node_update.get("completed_nodes", []),
                            "has_goal_result": bool(node_update.get("node_results", {}).get(node_id)),
                        },
                    )

                    # 2. Check for edge pivot transfer
                    if "active_payload" in node_update and node_update["active_payload"]:
                        p = node_update["active_payload"]
                        pivots = p.pivots if hasattr(p, "pivots") else p.get("pivots", {})
                        dataset_ptr = p.dataset_pointer if hasattr(p, "dataset_pointer") else p.get("dataset_pointer")
                        yield _format_sse_event(
                            "edge_payload_transferred",
                            {
                                "from_node": node_id,
                                "pivots": pivots,
                                "dataset_pointer": dataset_ptr,
                            },
                        )

                    # 3. Check for pause gate
                    if node_update.get("is_paused"):
                        pause_node = node_update.get("pause_node_id") or node_id
                        yield _format_sse_event(
                            "paused_for_approval",
                            {
                                "node_id": pause_node,
                                "pause_reason": node_update.get("pause_reason", "Awaiting Human Approval Token"),
                            },
                        )
                        yield _format_sse_event(
                            "workflow_paused",
                            {
                                "pause_node_id": pause_node,
                                "state": node_update,
                            },
                        )
                        return

                    # 4. Check for final report
                    if "report" in node_update and node_update["report"]:
                        yield _format_sse_event(
                            "report_compiled",
                            {
                                "case_id": req.case_id,
                                "report": node_update["report"],
                            },
                        )

            # Workflow completed successfully
            yield _format_sse_event(
                "workflow_finished",
                {
                    "status": "completed",
                    "case_id": req.case_id,
                    "workflow_id": req.workflow.workflow_id,
                },
            )

        except Exception as e:
            yield _format_sse_event(
                "workflow_error",
                {
                    "error": str(e),
                    "case_id": req.case_id,
                    "workflow_id": req.workflow.workflow_id,
                },
            )

    return StreamingResponse(
        sse_event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
