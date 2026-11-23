"""ForensicOps AI - LLM Provider Management & Smoke-Testing Endpoints.

Standards:
- Zero Secret Leakage: API keys are strictly kept server-side and are NEVER returned in GET /providers responses.
- Proxy Isolation: All network requests strictly enforce trust_env=False via httpx.
- Deterministic Tooling & Air-Gapped Safety: Nonce-enforced IPI defense and isolated smoke testing.
"""
from __future__ import annotations

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from backend.app.agent.lmstudio_client import run_provider_smoke_test
from backend.app.agent.provider_registry import (
    LLMProviderPublicDTO,
    get_provider_registry,
)
from backend.app.auth.dependencies import require_roles
from backend.app.auth.models import UserRead

router = APIRouter(prefix="/api/llm", tags=["LLM Provider Registry"])


class SelectProviderPayload(BaseModel):
    """Payload to select the active LLM provider."""

    provider_id: str


class SelectProviderResponse(BaseModel):
    """Response returned when an LLM provider is successfully set active."""

    status: str
    active_provider_id: str
    message: str


class SmokeTestResponse(BaseModel):
    """Response payload for provider connection smoke test."""

    provider_id: str
    success: bool
    latency_ms: int
    response_preview: Optional[str] = None
    error_detail: Optional[str] = None


@router.get(
    "/providers",
    response_model=List[LLMProviderPublicDTO],
    summary="List all available LLM providers",
    description="Returns metadata and configuration status for all supported model engines without leaking API keys.",
)
async def list_providers(
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst", "auditor")),
) -> List[LLMProviderPublicDTO]:
    """Retrieve list of registered LLM providers with safe public DTOs."""
    registry = get_provider_registry()
    return registry.get_public_providers()


@router.post(
    "/select",
    response_model=SelectProviderResponse,
    summary="Set the active LLM provider",
    description="Updates the active provider engine used for downstream forensic agent workflow steps.",
)
async def select_provider(
    payload: SelectProviderPayload,
    current_user: UserRead = Depends(require_roles("lead_investigator")),
) -> SelectProviderResponse:
    """Set the active LLM provider by provider_id."""
    registry = get_provider_registry()
    try:
        registry.set_active_provider_id(payload.provider_id)
        return SelectProviderResponse(
            status="success",
            active_provider_id=payload.provider_id,
            message=f"Active LLM provider successfully updated to '{payload.provider_id}'",
        )
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc


@router.post(
    "/smoke-test/{provider_id}",
    response_model=SmokeTestResponse,
    summary="Smoke test a specific LLM provider connection",
    description="Executes an isolated 1-sentence DFIR test query against the target provider without changing active selection.",
)
async def smoke_test_provider(
    provider_id: str,
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst")),
) -> SmokeTestResponse:
    """Run an isolated connection test against a specific model provider."""
    registry = get_provider_registry()
    provider = registry.get_provider(provider_id)
    if not provider:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Provider '{provider_id}' not found in registry",
        )

    result = await run_provider_smoke_test(provider_id=provider_id, timeout=15.0)
    return SmokeTestResponse(
        provider_id=result["provider_id"],
        success=result["success"],
        latency_ms=result["latency_ms"],
        response_preview=result["response_preview"],
        error_detail=result["error_detail"],
    )


@router.get(
    "/audit-logs",
    summary="List recent LLM provider audit logs",
    description="Retrieve append-only audit log records of provider switching and smoke testing.",
)
async def list_audit_logs(
    limit: int = 50,
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst", "external_auditor", "auditor")),
):
    """Retrieve audit log records for provider switches and smoke tests."""
    from backend.app.db.sqlite_store import get_llm_state_store
    store = get_llm_state_store()
    return store.get_audit_logs(limit=limit)
