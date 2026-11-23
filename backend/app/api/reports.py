"""Cited Report API Endpoints.

Standards:
- 6-Section Forensic Report Structure
- AIFT 4-Part Evaluative Rubric (Why It Matters, Benign Alternative, How to Verify, Data Gaps)
- Multi-Host Patient Zero Correlation & Attack Path Tracing
- Strict Anti-Hallucination Citation Binding
- Phase 08 Human Approval Gate for Report Finalization and Signing
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, Field

from backend.app.agent.report_builder import CitedReport, ReportBuilder, get_report_store
from backend.app.api.deps import (
    get_approval_engine,
    get_case_authorization_service,
    get_custody_engine,
    get_storage,
)
from backend.app.auth.dependencies import require_roles
from backend.app.auth.models import UserRead
from backend.app.core.exceptions import ForensicOpsError
from backend.app.models.findings import NodeGoalResult
from backend.app.models.workflow import HumanApprovalToken

router = APIRouter(prefix="/api/reports", tags=["Cited Reports"])


class ReportResponse(BaseModel):
    case_id: str
    report: Dict[str, Any]
    markdown: str


class BuildReportRequest(BaseModel):
    case_id: str = "default_case"
    node_results: List[NodeGoalResult] = Field(default_factory=list)


class FinalizeReportRequest(BaseModel):
    approval_token: HumanApprovalToken


@router.get("/{case_id}/export")
def export_cited_report(
    case_id: str,
    format: str = Query(default="markdown", pattern="^(markdown|json|md)$", description="Export format: markdown or json"),
    refresh: bool = Query(default=False, description="Force re-generation of draft report before export"),
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst", "auditor")),
    case_auth: Any = Depends(get_case_authorization_service),
) -> Response:
    """Export cited forensic report in markdown or JSON format as a downloadable attachment."""
    case_auth.verify_case_access(current_user, case_id, action="read")

    store = get_report_store()
    latest_report = store.get_latest_report(case_id) if not refresh else None

    if latest_report is None:
        storage = get_storage(case_id)
        custody = get_custody_engine(case_id)
        latest_report = ReportBuilder.build_report(
            case_id=case_id,
            node_results=[],
            storage=storage,
            custody_engine=custody,
            strict_citations=True,
            creator=f"{current_user.username} ({current_user.badge_id})",
        )

    clean_case_id = re.sub(r"[^a-zA-Z0-9_-]", "_", case_id)
    fmt = format.lower().strip()
    if fmt in ("markdown", "md"):
        content = latest_report.to_markdown()
        media_type = "text/markdown; charset=utf-8"
        filename = f"report_{clean_case_id}.md"
    elif fmt == "json":
        content = json.dumps(latest_report.to_dict(), indent=2, ensure_ascii=False)
        media_type = "application/json; charset=utf-8"
        filename = f"report_{clean_case_id}.json"
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Unsupported export format '{format}'.")

    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{case_id}", response_model=ReportResponse)
def get_cited_report(
    case_id: str,
    refresh: bool = Query(default=False, description="Force re-generation of draft report"),
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst", "auditor")),
    case_auth: Any = Depends(get_case_authorization_service),
) -> ReportResponse:
    """Retrieve the latest report or assemble a new draft report for a specific case."""
    case_auth.verify_case_access(current_user, case_id, action="read")

    store = get_report_store()
    latest_report = store.get_latest_report(case_id) if not refresh else None

    if latest_report is None:
        storage = get_storage(case_id)
        custody = get_custody_engine(case_id)
        latest_report = ReportBuilder.build_report(
            case_id=case_id,
            node_results=[],
            storage=storage,
            custody_engine=custody,
            strict_citations=True,
            creator=f"{current_user.username} ({current_user.badge_id})",
        )

    return ReportResponse(
        case_id=case_id,
        report=latest_report.to_dict(),
        markdown=latest_report.to_markdown(),
    )


@router.post("/compile", response_model=ReportResponse)
def compile_report_from_nodes(
    req: BuildReportRequest,
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst")),
    case_auth: Any = Depends(get_case_authorization_service),
) -> ReportResponse:
    """Compile a new draft report combining AI node results and storage telemetry."""
    case_auth.verify_case_access(current_user, req.case_id, action="write")

    storage = get_storage(req.case_id)
    custody = get_custody_engine(req.case_id)

    report = ReportBuilder.build_report(
        case_id=req.case_id,
        node_results=req.node_results,
        storage=storage,
        custody_engine=custody,
        strict_citations=True,
        creator=f"{current_user.username} ({current_user.badge_id})",
    )

    return ReportResponse(
        case_id=req.case_id,
        report=report.to_dict(),
        markdown=report.to_markdown(),
    )


@router.post("/{report_id}/finalize", response_model=ReportResponse)
def finalize_and_sign_report(
    report_id: str,
    req: FinalizeReportRequest,
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst")),
    case_auth: Any = Depends(get_case_authorization_service),
) -> ReportResponse:
    """Finalize and cryptographically sign a forensic report using a Phase 08 Human Approval Token."""
    store = get_report_store()
    report = store.get_report(report_id)
    if report is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Report '{report_id}' not found.")

    case_auth.verify_case_access(current_user, report.case_id, action="write")

    custody = get_custody_engine(report.case_id)
    approval_engine = get_approval_engine(report.case_id)

    try:
        finalized = ReportBuilder.finalize_report(
            report=report,
            approval_token=req.approval_token,
            approver_username=current_user.username,
            approver_role=current_user.role,
            approver_badge=current_user.badge_id,
            approval_engine=approval_engine,
            custody_engine=custody,
            store=store,
        )
    except ForensicOpsError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Report finalization failed: {e}")

    return ReportResponse(
        case_id=finalized.case_id,
        report=finalized.to_dict(),
        markdown=finalized.to_markdown(),
    )


@router.get("/{case_id}/history")
def get_report_history(
    case_id: str,
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst", "auditor")),
    case_auth: Any = Depends(get_case_authorization_service),
) -> List[Dict[str, Any]]:
    """Retrieve version history and cryptographic signing provenance for all reports in a case."""
    case_auth.verify_case_access(current_user, case_id, action="read")
    store = get_report_store()
    return store.list_history(case_id)
