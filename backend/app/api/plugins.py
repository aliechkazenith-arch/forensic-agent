"""Plugin Dry-Run & Registration Endpoints.

Standards:
- Zero-YAML 4-Step Onboarding Wizard
- Visual Tool Dry-Run Auto-Mapper (Heuristics & Confidence Scoring)
- Smart Column Projection & Pre-Built Tool Card Discovery
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from backend.app.api.deps import get_auto_mapper
from backend.app.auth.dependencies import require_roles
from backend.app.auth.models import UserRead
from backend.app.core.execution_policy import get_execution_policy_registry
from backend.app.core.exceptions import ExecutionPolicyError, UnsafePluginCardError
from backend.app.models.plugins import DryRunAutoMapperResult, ToolPluginCard

router = APIRouter(prefix="/api/plugins", tags=["Tool Plugins"])

TOOL_ID_REGEX = re.compile(r"^[a-zA-Z0-9_-]+$")


class DryRunRequest(BaseModel):
    sample_rows: List[Dict[str, Any]] = Field(default_factory=list)
    command_template: Optional[List[str]] = None
    tool_id: Optional[str] = None


class RegisterPluginResponse(BaseModel):
    status: str = "success"
    tool_id: str
    message: str
    yaml_path: str
    card: ToolPluginCard


def get_plugins_directory() -> Path:
    plugins_env = os.environ.get("FORENSICOPS_PLUGINS_DIR")
    if plugins_env:
        return Path(plugins_env).resolve()
    return Path("plugins").resolve()


@router.get("", response_model=List[ToolPluginCard])
def list_plugins(
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst", "auditor")),
) -> List[ToolPluginCard]:
    """List all registered forensic tool cards from the plugins directory."""
    plugins_dir = get_plugins_directory()
    cards: List[ToolPluginCard] = []

    if not plugins_dir.is_dir():
        return cards

    for yaml_file in sorted(plugins_dir.glob("*.yaml")):
        try:
            card = ToolPluginCard.from_yaml_file(yaml_file)
            cards.append(card)
        except Exception:
            # Skip invalid cards gracefully
            continue

    return cards


@router.post("/dry-run", response_model=DryRunAutoMapperResult)
def dry_run_auto_mapper(
    req: DryRunRequest,
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst")),
) -> DryRunAutoMapperResult:
    """Analyze sample rows from a tool execution and auto-suggest field mappings & column projections."""
    if not req.sample_rows:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one sample row must be provided in 'sample_rows' for auto-mapping.",
        )

    auto_mapper = get_auto_mapper()
    result = auto_mapper.analyze_sample_rows(req.sample_rows, max_rows_to_inspect=5)
    return result


@router.post("/register", response_model=RegisterPluginResponse)
def register_plugin(
    card: ToolPluginCard,
    current_user: UserRead = Depends(require_roles("lead_investigator")),
) -> RegisterPluginResponse:
    """Validate and register a new tool plugin card into the plugins directory."""
    if not card.tool_id or not card.name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Tool 'tool_id' and 'name' are required.",
        )

    if not TOOL_ID_REGEX.match(card.tool_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid 'tool_id' format '{card.tool_id}'. Must strictly match ^[a-zA-Z0-9_-]+$",
        )

    # Validate card against Execution Policy Registry (fail-closed)
    policy_registry = get_execution_policy_registry()
    try:
        policy_registry.validate_plugin_card(card, allow_new=True)
    except (UnsafePluginCardError, ExecutionPolicyError, ValueError) as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Plugin card failed policy validation: {err}",
        )

    # Dynamically register into execution policy registry
    if not policy_registry.get_policy(card.tool_id):
        from backend.app.core.execution_policy import ToolExecutionPolicy
        first_bin = Path(card.command_template[0]).name if card.command_template else card.tool_id
        sat = getattr(card, "supported_artifact_types", None) or ["file"]
        policy_registry.register_policy(
            ToolExecutionPolicy(
                tool_id=card.tool_id,
                name=card.name,
                version=card.version or "1.0.0",
                approved_binary=first_bin,
                container_image=card.container_image,
                supported_artifact_types=list(sat),
                max_timeout_seconds=card.timeout_seconds,
            )
        )

    plugins_dir = get_plugins_directory()
    plugins_dir.mkdir(parents=True, exist_ok=True)

    dest_path = (plugins_dir / f"{card.tool_id}.yaml").resolve()
    if not dest_path.is_relative_to(plugins_dir.resolve()):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Path traversal detected in tool_id",
        )

    card.to_yaml_file(dest_path)

    return RegisterPluginResponse(
        status="success",
        tool_id=card.tool_id,
        message=f"Plugin '{card.name}' ({card.tool_id}) successfully registered.",
        yaml_path=str(dest_path),
        card=card,
    )
