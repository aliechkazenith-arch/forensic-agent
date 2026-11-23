"""Phase 7 Tests - Multi-Provider LLM Registry & Smoke-Test Endpoints.

Standards:
- Verifies registration of all 6 providers: lm_studio_local, openrouter_gemma, deepseek, nemotron, glm_5_3, gemini.
- Zero Secret Leakage: API keys must never appear in public DTOs or GET /providers responses.
- Dynamic Client Routing: LMStudioClient routes requests dynamically based on provider_id.
- Isolated Smoke Testing: Smoke tests do NOT change active provider state.
"""
from __future__ import annotations

import unittest.mock as mock
import pytest
from fastapi.testclient import TestClient

from backend.app.agent.lmstudio_client import LMStudioClient, run_provider_smoke_test
from backend.app.agent.provider_registry import (
    LLMProviderRegistry,
    get_provider_registry,
    reset_provider_registry,
)
from backend.app.main import app


@pytest.fixture(autouse=True)
def clean_registry():
    """Ensure registry state is clean before and after each test."""
    reset_provider_registry()
    yield
    reset_provider_registry()


@pytest.fixture
def client() -> TestClient:
    """Create FastAPI test client."""
    return TestClient(app)


def test_provider_registry_initialization_all_six():
    """Verify all 6 required forensic LLM providers are registered with proper metadata."""
    registry = get_provider_registry()
    providers = {p.provider_id: p for p in registry.get_providers()}

    expected_ids = [
        "lm_studio_local",
        "openrouter_gemma",
        "deepseek",
        "nemotron",
        "glm_5_3",
        "gemini",
    ]
    for pid in expected_ids:
        assert pid in providers, f"Missing provider: '{pid}'"

    # LM Studio must be local
    assert providers["lm_studio_local"].is_local is True
    # Cloud providers must not be local
    for cloud_id in ["openrouter_gemma", "deepseek", "nemotron", "glm_5_3", "gemini"]:
        assert providers[cloud_id].is_local is False, f"Provider '{cloud_id}' should not be marked local"

    # Default active provider
    assert registry.get_active_provider_id() in expected_ids


def test_provider_registry_zero_secret_leakage():
    """Verify public DTOs strictly omit API keys to prevent accidental UI leakage."""
    registry = get_provider_registry()
    public_dtos = registry.get_public_providers()

    assert len(public_dtos) >= 6
    for dto in public_dtos:
        # Pydantic model dump should never contain api_key
        dumped = dto.model_dump()
        assert "api_key" not in dumped, f"api_key leaked in public DTO for {dto.provider_id}"
        assert not hasattr(dto, "api_key")
        assert isinstance(dto.is_active, bool)
        assert isinstance(dto.is_local, bool)
        assert isinstance(dto.is_configured, bool)


def test_provider_registry_selection_and_validation():
    """Verify selecting active provider works and rejects unregistered keys."""
    registry = get_provider_registry()

    # Valid selection
    registry.set_active_provider_id("deepseek")
    assert registry.get_active_provider_id() == "deepseek"
    assert registry.get_active_provider().provider_id == "deepseek"

    # Public DTO reflects active selection
    dtos = {d.provider_id: d for d in registry.get_public_providers()}
    assert dtos["deepseek"].is_active is True
    assert dtos["lm_studio_local"].is_active is False

    # Invalid selection raises KeyError
    with pytest.raises(KeyError):
        registry.set_active_provider_id("unknown_quantum_llm")


def test_lmstudio_client_dynamic_provider_routing():
    """Verify LMStudioClient dynamically resolves endpoints and models by provider_id."""
    registry = get_provider_registry()

    # Route through Gemini
    gemini_client = LMStudioClient(provider_id="gemini")
    gemini_cfg = registry.get_provider("gemini")
    assert gemini_client.provider_id == "gemini"
    assert gemini_client.model == gemini_cfg.model_name
    assert gemini_client.base_url == gemini_cfg.base_url
    assert "gemini-3.5-flash-lite" in gemini_client.fallback_models

    # Route through DeepSeek
    deepseek_client = LMStudioClient(provider_id="deepseek")
    deepseek_cfg = registry.get_provider("deepseek")
    assert deepseek_client.provider_id == "deepseek"
    assert deepseek_client.model == deepseek_cfg.model_name


def test_fastapi_get_llm_providers(client: TestClient):
    """Test GET /api/llm/providers endpoint returns safe provider metadata."""
    resp = client.get("/api/llm/providers")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) >= 6

    provider_ids = [item["provider_id"] for item in data]
    assert "lm_studio_local" in provider_ids
    assert "gemini" in provider_ids
    assert "deepseek" in provider_ids
    assert "openrouter_gemma" in provider_ids
    assert "nemotron" in provider_ids
    assert "glm_5_3" in provider_ids

    for item in data:
        assert "api_key" not in item
        assert "provider_id" in item
        assert "label" in item
        assert "model_name" in item
        assert "base_url" in item
        assert "is_local" in item
        assert "is_configured" in item
        assert "is_active" in item


def test_fastapi_select_llm_provider(client: TestClient):
    """Test POST /api/llm/select endpoint updates active provider."""
    # 1. Select DeepSeek
    resp = client.post("/api/llm/select", json={"provider_id": "deepseek"})
    assert resp.status_code == 200
    res_data = resp.json()
    assert res_data["status"] == "success"
    assert res_data["active_provider_id"] == "deepseek"

    # Verify via GET that deepseek is active
    get_resp = client.get("/api/llm/providers")
    active_item = next(p for p in get_resp.json() if p["is_active"])
    assert active_item["provider_id"] == "deepseek"

    # 2. Select Invalid Provider returns 400
    bad_resp = client.post("/api/llm/select", json={"provider_id": "non_existent_provider"})
    assert bad_resp.status_code == 400


@pytest.mark.asyncio
async def test_fastapi_smoke_test_success_and_isolation(client: TestClient):
    """Test POST /api/llm/smoke-test/{provider_id} returns latency & preview without changing active provider."""
    registry = get_provider_registry()
    registry.set_active_provider_id("lm_studio_local")

    mock_resp = mock.MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "Event ID 4624 Logon Type 3 indicates network logon authentication.",
                },
            }
        ]
    }
    mock_resp.raise_for_status = mock.MagicMock()

    with mock.patch("httpx.AsyncClient.post", return_value=mock_resp):
        resp = client.post("/api/llm/smoke-test/nemotron")
        assert resp.status_code == 200
        data = resp.json()
        assert data["provider_id"] == "nemotron"
        assert data["success"] is True
        assert data["latency_ms"] >= 1
        assert "Event ID 4624" in data["response_preview"]
        assert data["error_detail"] is None

        # Verify active provider was NOT mutated by the smoke test
        assert registry.get_active_provider_id() == "lm_studio_local"


@pytest.mark.asyncio
async def test_fastapi_smoke_test_failure_handling(client: TestClient):
    """Test POST /api/llm/smoke-test/{provider_id} handles errors gracefully without crashing."""
    registry = get_provider_registry()
    registry.set_active_provider_id("lm_studio_local")

    with mock.patch("httpx.AsyncClient.post", side_effect=Exception("Connection refused to mock host")):
        resp = client.post("/api/llm/smoke-test/glm_5_3")
        assert resp.status_code == 200
        data = resp.json()
        assert data["provider_id"] == "glm_5_3"
        assert data["success"] is False
        assert "Connection refused" in data["error_detail"]
        assert data["response_preview"] is None

        # Active provider still unchanged
        assert registry.get_active_provider_id() == "lm_studio_local"


def test_fastapi_smoke_test_unknown_provider(client: TestClient):
    """Test POST /api/llm/smoke-test/{provider_id} returns 404 for unknown provider."""
    resp = client.post("/api/llm/smoke-test/unknown_ghost_model")
    assert resp.status_code == 404
