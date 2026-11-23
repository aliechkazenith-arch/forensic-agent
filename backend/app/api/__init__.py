"""ForensicOps AI API Package Router Initialization."""
from __future__ import annotations

from fastapi import APIRouter

from backend.app.api.agent import router as agent_router
from backend.app.api.approvals import router as approvals_router
from backend.app.api.auth import router as auth_router
from backend.app.api.cases import router as cases_router
from backend.app.api.copilot import router as copilot_router
from backend.app.api.feedback import router as feedback_router
from backend.app.api.findings import router as findings_router
from backend.app.api.intake import router as intake_router
from backend.app.api.investigations import router as investigations_router
from backend.app.api.llm import router as llm_router
from backend.app.api.plugins import router as plugins_router
from backend.app.api.reports import router as reports_router
from backend.app.api.session import router as session_router
from backend.app.api.siem import router as siem_router
from backend.app.api.workflows import router as workflows_router, workflow_single_router

api_router = APIRouter()
api_router.include_router(cases_router)
api_router.include_router(approvals_router)
api_router.include_router(copilot_router)
api_router.include_router(agent_router)
api_router.include_router(auth_router)
api_router.include_router(intake_router)
api_router.include_router(investigations_router)
api_router.include_router(plugins_router)
api_router.include_router(workflows_router)
api_router.include_router(workflow_single_router)
api_router.include_router(session_router)
api_router.include_router(siem_router)
api_router.include_router(reports_router)
api_router.include_router(findings_router)
api_router.include_router(feedback_router)
api_router.include_router(llm_router)

__all__ = [
    "api_router",
    "cases_router",
    "copilot_router",
    "agent_router",
    "auth_router",
    "intake_router",
    "investigations_router",
    "plugins_router",
    "workflows_router",
    "workflow_single_router",
    "session_router",
    "siem_router",
    "reports_router",
    "findings_router",
    "feedback_router",
    "llm_router",
]

