"""Pydantic v2 data models for Node Execution Traces and Human Feedback.

Standards: v2.0 RAG & Episodic Learning Contracts, Zero-Refactor Upgrades.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional
from uuid import uuid4
from pydantic import BaseModel, Field


FeedbackType = Literal[
    "true_positive",
    "false_positive_benign_baseline",
    "query_correction",
]

FeedbackScope = Literal[
    "this_case_only",
    "organization_baseline",
    "global_playbook",
]


class NodeExecutionTrace(BaseModel):
    """Execution trace of an AI Goal node for episodic few-shot learning."""
    trace_id: str = Field(default_factory=lambda: str(uuid4()))
    case_id: str
    node_id: str
    user_goal: str
    incoming_pivots: Dict[str, Any] = Field(default_factory=dict)
    executed_queries: List[str] = Field(default_factory=list)
    cited_finding_ids: List[str] = Field(default_factory=list)
    human_rating: Optional[float] = Field(default=None, ge=-1.0, le=5.0)
    created_utc: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    execution_metadata: Dict[str, Any] = Field(default_factory=dict)


class HumanFeedbackRecord(BaseModel):
    """Analyst feedback captured from UI micro-controls for organizational learning."""
    feedback_id: str = Field(default_factory=lambda: str(uuid4()))
    case_id: Optional[str] = None
    finding_id: Optional[str] = None
    feedback_type: FeedbackType
    analyst_note: Optional[str] = None
    entity_pattern: Optional[str] = None  # e.g. "user:svc_backup", "process:svchost.exe", "ip:10.0.0.5"
    scope: FeedbackScope = "organization_baseline"
    org_id: Optional[str] = None
    artifact_type: Optional[str] = None
    created_utc: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    corrected_query: Optional[str] = None
