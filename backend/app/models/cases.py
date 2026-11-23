"""Pydantic models for Forensic Case Registry and Vault Sharing.

Standards:
- Local-first case lifecycle management: OPEN -> IN_REVIEW -> COMPLETED
- Optional Peer Review & Forensic Case Vault sharing flag (is_shared_to_vault)
- Serialized state persistence for wizard, workflow, and hypothesis drafts
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field

CaseStatus = Literal["OPEN", "IN_REVIEW", "COMPLETED"]


class CaseCreatePayload(BaseModel):
    """Payload to create or initialize a forensic investigation case."""
    case_id: str = Field(..., min_length=2, max_length=64, description="Unique case identifier")
    case_name: str = Field(..., min_length=2, max_length=256, description="Human-readable case name")
    organization_name: str = Field(default="Default Organization", min_length=2, max_length=256)
    investigation_goal: Optional[str] = Field(default=None, description="Primary investigation objective")
    lead_analyst: Optional[str] = Field(default=None, description="Lead investigator username or badge")
    active_provider_id: Optional[str] = Field(default="lm_studio_local", description="Initial active LLM provider")
    status: CaseStatus = "OPEN"
    is_shared_to_vault: bool = False
    serialized_state: Optional[Dict[str, Any]] = None


class CaseUpdatePayload(BaseModel):
    """Payload to update an existing case's metadata, status, or serialized state."""
    case_name: Optional[str] = None
    organization_name: Optional[str] = None
    investigation_goal: Optional[str] = None
    lead_analyst: Optional[str] = None
    active_provider_id: Optional[str] = None
    status: Optional[CaseStatus] = None
    is_shared_to_vault: Optional[bool] = None
    serialized_state: Optional[Dict[str, Any]] = None


class CaseReadDTO(BaseModel):
    """Public data transfer object for a forensic case."""
    case_id: str
    case_name: str
    organization_name: str
    investigation_goal: Optional[str] = None
    lead_analyst: str
    active_provider_id: str
    status: CaseStatus
    is_shared_to_vault: bool
    created_at_utc: str
    updated_at_utc: str
    serialized_state: Optional[Dict[str, Any]] = None


class CaseShareResponse(BaseModel):
    """Response returned when toggling vault sharing for peer review."""
    status: str
    case_id: str
    is_shared_to_vault: bool
    updated_at_utc: str
