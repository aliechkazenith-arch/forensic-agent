"""Forensic Findings API Endpoints.

Standards:
- Deterministic Facts & Verification (RFC 3227, NIST SP 800-86)
- Cryptographic SHA-256 Provenance Inspection
- High-Performance Structured Pivoting & Filtering
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status

from backend.app.api.deps import get_case_authorization_service, get_storage
from backend.app.auth.dependencies import require_roles
from backend.app.auth.models import UserRead
from backend.app.models.findings import ForensicFinding

router = APIRouter(prefix="/api/findings", tags=["Forensic Findings"])


@router.get("/{finding_id}", response_model=ForensicFinding)
def get_finding(
    finding_id: str,
    case_id: str = "default_case",
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst", "auditor")),
) -> ForensicFinding:
    """Retrieve raw forensic finding record and cryptographic provenance by finding_id."""
    case_auth = get_case_authorization_service()
    case_auth.verify_case_access(current_user, case_id, action="read")

    storage = get_storage(case_id)
    finding = storage.get_finding(finding_id, case_id=case_id)
    if not finding or finding.case_id != case_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Forensic finding '{finding_id}' not found in case '{case_id}'.",
        )
    return finding


@router.get("", response_model=List[ForensicFinding])
def query_findings(
    case_id: str = "default_case",
    category: Optional[str] = None,
    artifact_type: Optional[str] = None,
    severity: Optional[str] = None,
    user: Optional[str] = None,
    host: Optional[str] = None,
    limit: int = Query(default=100, ge=1, le=1000),
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst", "auditor")),
) -> List[ForensicFinding]:
    """Query and filter structured findings for a case."""
    case_auth = get_case_authorization_service()
    case_auth.verify_case_access(current_user, case_id, action="read")

    storage = get_storage(case_id)
    filters: Dict[str, Any] = {}
    if category:
        filters["category"] = category
    if artifact_type:
        filters["artifact_type"] = artifact_type
    if severity:
        filters["severity"] = severity
    if user:
        filters["user"] = user
    if host:
        filters["host"] = host

    findings = storage.query_structured_findings(
        case_id=case_id,
        filters=filters,
        limit=limit,
    )
    return findings
