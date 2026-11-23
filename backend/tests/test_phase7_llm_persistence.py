"""Phase 7 Tests - SQLite Persistence, Runtime Settings, Audit Logging, and Zero Secret Leakage.

Standards:
- Verifies SQLite persistence of active_provider_id across manager and server restarts.
- Verifies per-provider smoke test status persistence (last_success, last_latency_ms, response_preview, error_detail).
- Verifies append-only audit logging recording provider switches and smoke tests with is_cloud_transmission.
- Verifies Zero Secret Leakage: API keys are NEVER written to SQLite tables or exposed in public DTOs.
"""
from __future__ import annotations

import sqlite3
import unittest.mock as mock
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.app.agent.lmstudio_client import run_provider_smoke_test
from backend.app.agent.provider_registry import (
    LLMProviderRegistry,
    get_provider_registry,
    reset_provider_registry,
)
from backend.app.db.sqlite_store import (
    LLMStateStore,
    get_llm_state_store,
    reset_llm_state_store,
)
from backend.app.main import app


@pytest.fixture(autouse=True)
def clean_state(tmp_path: Path):
    """Ensure clean registry and SQLite state store before and after each test."""
    db_file = tmp_path / "test_llm_state.db"
    store = LLMStateStore(db_path=db_file)
    reset_llm_state_store(store)
    reset_provider_registry()
    yield store
    reset_llm_state_store()
    reset_provider_registry()


@pytest.fixture
def client() -> TestClient:
    """Create FastAPI test client."""
    return TestClient(app)


def test_sqlite_runtime_settings_survives_restart(tmp_path: Path):
    """Verify provider selection persists across store and registry restarts using the same SQLite DB."""
    db_file = tmp_path / "persist_test.db"

    # Step 1: Initial store instance sets active provider to gemini
    store1 = LLMStateStore(db_path=db_file)
    registry1 = LLMProviderRegistry(state_store=store1)
    registry1.set_active_provider_id("gemini")
    assert registry1.get_active_provider_id() == "gemini"

    # Step 2: Simulate restart by destroying store1 and creating store2 on the same DB file
    del registry1
    del store1

    store2 = LLMStateStore(db_path=db_file)
    assert store2.get_active_provider_id() == "gemini"

    # Step 3: Registry initialized with restarted store reflects gemini immediately
    registry2 = LLMProviderRegistry(state_store=store2)
    assert registry2.get_active_provider_id() == "gemini"
    assert registry2.get_active_provider().provider_id == "gemini"

    public_dtos = {p.provider_id: p for p in registry2.get_public_providers()}
    assert public_dtos["gemini"].is_active is True
    assert public_dtos["lm_studio_local"].is_active is False


def test_sqlite_smoke_test_status_persistence(tmp_path: Path):
    """Verify per-provider smoke test latency, status, and preview persist across store reloads."""
    db_file = tmp_path / "smoke_persist_test.db"
    store1 = LLMStateStore(db_path=db_file)

    # Record smoke test results for two providers
    store1.record_smoke_test(
        provider_id="openrouter_gemma",
        success=True,
        latency_ms=342,
        response_preview="Event 4624 Type 3 logon denotes SMB/RPC network logon.",
        error_detail=None,
    )
    store1.record_smoke_test(
        provider_id="deepseek",
        success=False,
        latency_ms=1205,
        response_preview=None,
        error_detail="HTTP 401 Unauthorized: Invalid API key",
    )

    # Destroy store1 and reload store2 from disk
    del store1
    store2 = LLMStateStore(db_path=db_file)
    all_statuses = store2.get_all_smoke_test_statuses()

    assert "openrouter_gemma" in all_statuses
    assert all_statuses["openrouter_gemma"]["last_success"] is True
    assert all_statuses["openrouter_gemma"]["last_latency_ms"] == 342
    assert "Event 4624" in all_statuses["openrouter_gemma"]["response_preview"]
    assert all_statuses["openrouter_gemma"]["error_detail"] is None
    assert all_statuses["openrouter_gemma"]["tested_at_utc"] is not None

    assert "deepseek" in all_statuses
    assert all_statuses["deepseek"]["last_success"] is False
    assert all_statuses["deepseek"]["last_latency_ms"] == 1205
    assert "Invalid API key" in all_statuses["deepseek"]["error_detail"]

    # Verify public DTO merges these SQLite statuses
    registry = LLMProviderRegistry(state_store=store2)
    dtos = {p.provider_id: p for p in registry.get_public_providers()}
    assert dtos["openrouter_gemma"].last_test_success is True
    assert dtos["openrouter_gemma"].last_latency_ms == 342
    assert dtos["deepseek"].last_test_success is False
    assert dtos["deepseek"].last_latency_ms == 1205


def test_sqlite_audit_log_append_only(tmp_path: Path):
    """Verify append-only audit log records provider switches and tests with cloud flags."""
    db_file = tmp_path / "audit_test.db"
    store = LLMStateStore(db_path=db_file)
    registry = LLMProviderRegistry(state_store=store)

    # 1. Switch to local provider (is_cloud_transmission=False)
    registry.set_active_provider_id("lm_studio_local")

    # 2. Switch to external cloud provider (is_cloud_transmission=True)
    registry.set_active_provider_id("nemotron")

    # 3. Record test
    store.record_audit_log(
        event_type="smoke_test",
        provider_id="nemotron",
        is_cloud_transmission=True,
        details="Smoke test completed in 410ms",
    )

    logs = store.get_audit_logs(limit=10)
    assert len(logs) >= 3

    # Most recent log is the smoke test
    assert logs[0]["event_type"] == "smoke_test"
    assert logs[0]["provider_id"] == "nemotron"
    assert logs[0]["is_cloud_transmission"] is True

    # Previous was nemotron switch
    assert logs[1]["event_type"] == "provider_switch"
    assert logs[1]["provider_id"] == "nemotron"
    assert logs[1]["is_cloud_transmission"] is True

    # Earlier was lm_studio_local switch
    assert logs[2]["event_type"] == "provider_switch"
    assert logs[2]["provider_id"] == "lm_studio_local"
    assert logs[2]["is_cloud_transmission"] is False


def test_zero_secret_leakage_in_sqlite(tmp_path: Path):
    """Verify API keys are NEVER written to any table or log in the SQLite database."""
    db_file = tmp_path / "leakage_test.db"
    store = LLMStateStore(db_path=db_file)
    registry = LLMProviderRegistry(state_store=store)

    # Collect known test keys or patterns
    known_keys = [
        "sk-or-v1-secret-key-123",
        "nvapi-ultra-secret-test-key",
        "thk_live_super_secret_deepseek",
        "sk-apxe-secret-glm-key",
        "AQ.Ab8-secret-gemini-key",
    ]

    # Inject mock providers with secret keys
    for key, pid in zip(known_keys, ["openrouter_gemma", "nemotron", "deepseek", "glm_5_3", "gemini"]):
        cfg = registry.get_provider(pid)
        if cfg:
            cfg.api_key = key

    # Perform switches and record statuses
    for pid in ["lm_studio_local", "openrouter_gemma", "gemini"]:
        registry.set_active_provider_id(pid)
        store.record_smoke_test(
            provider_id=pid,
            success=True,
            latency_ms=100,
            response_preview=f"Response from {pid}",
            error_detail=None,
        )

    # Close store and open raw sqlite database file directly
    store.close()
    conn = sqlite3.connect(str(db_file))
    cursor = conn.cursor()

    # Read all text from all tables
    all_stored_text = []
    for table in ["llm_runtime_settings", "llm_smoke_test_status", "llm_provider_audit_log"]:
        cursor.execute(f"SELECT * FROM {table};")
        for row in cursor.fetchall():
            all_stored_text.append(str(row))
    conn.close()

    combined_db_dump = " ".join(all_stored_text)

    # Strict assertion: None of the secret keys exist anywhere in SQLite
    for key in known_keys:
        assert key not in combined_db_dump, f"FATAL: Secret API key '{key}' leaked into SQLite table!"


def test_api_endpoints_merge_sqlite_state(client: TestClient, tmp_path: Path):
    """Verify FastAPI GET /api/llm/providers, POST /api/llm/select, and GET /api/llm/audit-logs."""
    # 1. Select provider
    select_resp = client.post("/api/llm/select", json={"provider_id": "gemini"})
    assert select_resp.status_code == 200
    assert select_resp.json()["active_provider_id"] == "gemini"

    # 2. Verify via GET /api/llm/providers that gemini is active
    get_resp = client.get("/api/llm/providers")
    assert get_resp.status_code == 200
    providers = get_resp.json()
    gemini_item = next(p for p in providers if p["provider_id"] == "gemini")
    assert gemini_item["is_active"] is True
    assert "api_key" not in gemini_item

    # 3. Check audit logs via GET /api/llm/audit-logs
    audit_resp = client.get("/api/llm/audit-logs")
    assert audit_resp.status_code == 200
    logs = audit_resp.json()
    assert isinstance(logs, list)
    assert len(logs) >= 1
    assert logs[0]["event_type"] == "provider_switch"
    assert logs[0]["provider_id"] == "gemini"
    assert logs[0]["is_cloud_transmission"] is True


@pytest.mark.asyncio
async def test_smoke_test_endpoint_updates_sqlite_and_audit_log(client: TestClient):
    """Verify POST /api/llm/smoke-test/{provider_id} persists results and writes to audit log in SQLite."""
    store = get_llm_state_store()

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
        resp = client.post("/api/llm/smoke-test/openrouter_gemma")
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["provider_id"] == "openrouter_gemma"

    # Verify SQLite status table updated
    status = store.get_smoke_test_status("openrouter_gemma")
    assert status is not None
    assert status["last_success"] is True
    assert status["last_latency_ms"] >= 1
    assert "Event ID 4624" in status["response_preview"]

    # Verify audit log recorded
    logs = store.get_audit_logs(limit=5)
    smoke_logs = [l for l in logs if l["event_type"] == "smoke_test" and l["provider_id"] == "openrouter_gemma"]
    assert len(smoke_logs) >= 1
    assert smoke_logs[0]["is_cloud_transmission"] is True

