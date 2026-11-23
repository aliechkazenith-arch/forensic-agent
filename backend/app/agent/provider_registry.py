"""ForensicOps AI - Multi-Provider LLM Registry.

Standards:
- Local-first & Air-Gapped: Defaults to local LM Studio (http://localhost:1234/v1).
- Zero Secret Leakage: API keys remain strictly server-side in internal configs and are
  never exposed in public DTOs or sent over frontend APIs.
- Proxy Isolation: Coordinates with httpx.Client(trust_env=False) to prevent local proxy pollution.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


from backend.app.db.sqlite_store import LLMStateStore, get_llm_state_store


def _load_env_files() -> None:
    """Manually parse .env files if present to populate os.environ without requiring external dependencies."""
    candidates = [
        Path(".env"),
        Path("backend/.env"),
        Path(__file__).resolve().parent.parent.parent.parent / ".env",
        Path(__file__).resolve().parent.parent.parent / ".env",
    ]
    for env_path in candidates:
        if env_path.exists():
            try:
                with open(env_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            key, val = line.split("=", 1)
                            key = key.strip()
                            val = val.strip().strip("\"'")
                            os.environ[key] = val
            except Exception:
                pass


_load_env_files()


class LLMProviderConfig(BaseModel):
    """Internal provider configuration containing server-side credentials and endpoints."""

    provider_id: str
    label: str
    model_name: str
    base_url: str
    api_key: str = ""
    is_local: bool = False
    is_configured: bool = True
    extra_headers: Dict[str, str] = Field(default_factory=dict)
    fallback_models: List[str] = Field(default_factory=list)

    def to_public_dto(self, is_active: bool = False) -> LLMProviderPublicDTO:
        """Convert internal configuration to safe public DTO, stripping API keys."""
        return LLMProviderPublicDTO(
            provider_id=self.provider_id,
            label=self.label,
            model_name=self.model_name,
            base_url=self.base_url,
            is_local=self.is_local,
            is_configured=self.is_configured,
            is_active=is_active,
        )


class LLMProviderPublicDTO(BaseModel):
    """Public model representation exposed safely to the frontend UI without credentials."""

    provider_id: str
    label: str
    model_name: str
    base_url: str
    is_local: bool
    is_configured: bool
    is_active: bool = False
    last_test_success: Optional[bool] = None
    last_latency_ms: Optional[int] = None
    last_tested_at_utc: Optional[str] = None
    response_preview: Optional[str] = None
    error_detail: Optional[str] = None


class LLMProviderRegistry:
    """Central registry managing supported forensic LLM providers and persistent SQLite active selection."""

    def __init__(self, state_store: Optional[LLMStateStore] = None) -> None:
        _load_env_files()
        self._state_store = state_store or get_llm_state_store()
        self._providers: Dict[str, LLMProviderConfig] = {}
        self._active_provider_id = "lm_studio_local"
        self._initialize_providers()
        default_pid = os.getenv("DEFAULT_LLM_PROVIDER", "lm_studio_local")
        self._active_provider_id = self._state_store.get_active_provider_id(default=default_pid)
        if self._active_provider_id not in self._providers:
            self._active_provider_id = "lm_studio_local"

    def _initialize_providers(self) -> None:
        """Populate the 6 core supported providers from environment variables."""
        # 1. Local On-Premise LM Studio (Default / 100% Offline Safe)
        lm_key = os.getenv("LM_STUDIO_API_KEY", "not-needed").strip()
        self._providers["lm_studio_local"] = LLMProviderConfig(
            provider_id="lm_studio_local",
            label="LM Studio Local (Air-Gapped)",
            model_name=os.getenv("LM_STUDIO_MODEL", "local-model").strip(),
            base_url=os.getenv("LM_STUDIO_BASE_URL", "http://localhost:1234/v1").rstrip("/"),
            api_key=lm_key,
            is_local=True,
            is_configured=True,
            extra_headers={},
            fallback_models=[],
        )

        # 2. OpenRouter (Gemma 4 31B Free / Nemotron Free Fallback)
        openrouter_key = os.getenv("OPENROUTER_API_KEY", "").strip()
        self._providers["openrouter_gemma"] = LLMProviderConfig(
            provider_id="openrouter_gemma",
            label="OpenRouter (Gemma 4 31B Free)",
            model_name=os.getenv("OPENROUTER_MODEL", "google/gemma-4-31b-it:free").strip(),
            base_url=os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1").rstrip("/"),
            api_key=openrouter_key,
            is_local=False,
            is_configured=bool(openrouter_key and openrouter_key not in ("not-needed", "none")),
            extra_headers={
                "HTTP-Referer": "http://localhost:5173",
                "X-Title": "ForensicOps AI",
            },
            fallback_models=["nvidia/nemotron-3.5-lightning:free"],
        )

        # 3. DeepSeek (via TokenHarbor or Direct Endpoint)
        deepseek_key = os.getenv("DEEPSEEK_API_KEY", "").strip()
        deepseek_base = os.getenv("DEEPSEEK_BASE_URL", "https://tokenharbor.ai/v1").rstrip("/")
        self._providers["deepseek"] = LLMProviderConfig(
            provider_id="deepseek",
            label="DeepSeek V4.1 Flash (TokenHarbor)",
            model_name=os.getenv("DEEPSEEK_MODEL", "deepseek-v4.1-flash:free").strip(),
            base_url=deepseek_base,
            api_key=deepseek_key,
            is_local=False,
            is_configured=bool(deepseek_key and deepseek_key not in ("not-needed", "none")),
            extra_headers={},
            fallback_models=[],
        )

        # 4. NVIDIA NIM (Nemotron 3 Ultra)
        nemotron_key = os.getenv("NEMOTRON_API_KEY", "").strip()
        self._providers["nemotron"] = LLMProviderConfig(
            provider_id="nemotron",
            label="NVIDIA Nemotron 3 Ultra (NIM)",
            model_name=os.getenv("NEMOTRON_MODEL", "nvidia/nemotron-3-ultra-550b-a55b").strip(),
            base_url=os.getenv("NEMOTRON_BASE_URL", "https://integrate.api.nvidia.com/v1").rstrip("/"),
            api_key=nemotron_key,
            is_local=False,
            is_configured=bool(nemotron_key and nemotron_key not in ("not-needed", "none")),
            extra_headers={},
            fallback_models=[],
        )

        # 5. Zhipu GLM-5.3 (Apinex OpenAI-Compatible)
        glm_key = os.getenv("GLM_API_KEY", "").strip()
        self._providers["glm_5_3"] = LLMProviderConfig(
            provider_id="glm_5_3",
            label="GLM 5.3 Flash (Apinex)",
            model_name=os.getenv("GLM_MODEL", "free/glm-5.3-flash").strip(),
            base_url=os.getenv("GLM_BASE_URL", "https://api.apinex.bond/v1").rstrip("/"),
            api_key=glm_key,
            is_local=False,
            is_configured=bool(glm_key and glm_key not in ("not-needed", "none")),
            extra_headers={},
            fallback_models=[],
        )

        # 6. Google Gemini 3.8 Flash (OpenAI-Compatible endpoint)
        gemini_key = os.getenv("GEMINI_API_KEY", "").strip()
        gemini_base = os.getenv(
            "GEMINI_BASE_URL",
            "https://generativelanguage.googleapis.com/v1beta/openai",
        ).rstrip("/")
        self._providers["gemini"] = LLMProviderConfig(
            provider_id="gemini",
            label="Google Gemini 3.8 Flash",
            model_name=os.getenv("GEMINI_MODEL", "gemini-3.8-flash").strip(),
            base_url=gemini_base,
            api_key=gemini_key,
            is_local=False,
            is_configured=bool(gemini_key and gemini_key not in ("not-needed", "none")),
            extra_headers={},
            fallback_models=["gemini-3.5-flash-lite"],
        )

    def get_providers(self) -> List[LLMProviderConfig]:
        """Return list of all internal provider configurations."""
        return list(self._providers.values())

    def get_public_providers(self) -> List[LLMProviderPublicDTO]:
        """Return safe public DTO list with active provider flag and SQLite smoke-test history merged."""
        active_id = self.get_active_provider_id()
        smoke_statuses = self._state_store.get_all_smoke_test_statuses()
        results: List[LLMProviderPublicDTO] = []
        for cfg in self._providers.values():
            dto = cfg.to_public_dto(is_active=(cfg.provider_id == active_id))
            status_entry = smoke_statuses.get(cfg.provider_id)
            if status_entry:
                dto.last_test_success = status_entry.get("last_success")
                dto.last_latency_ms = status_entry.get("last_latency_ms")
                dto.last_tested_at_utc = status_entry.get("tested_at_utc")
                dto.response_preview = status_entry.get("response_preview")
                dto.error_detail = status_entry.get("error_detail")
            results.append(dto)
        return results

    def get_provider(self, provider_id: str) -> Optional[LLMProviderConfig]:
        """Retrieve internal provider configuration by id."""
        return self._providers.get(provider_id)

    @property
    def state_store(self) -> LLMStateStore:
        if self._state_store is not None:
            try:
                self._state_store._conn.execute("SELECT 1;")
                return self._state_store
            except Exception:
                pass
        self._state_store = get_llm_state_store()
        return self._state_store

    def get_active_provider_id(self) -> str:
        """Get the currently active provider id from SQLite store."""
        try:
            stored_id = self.state_store.get_active_provider_id(default=self._active_provider_id)
            if stored_id in self._providers:
                self._active_provider_id = stored_id
        except Exception:
            pass
        return self._active_provider_id

    def set_active_provider_id(self, provider_id: str) -> None:
        """Set the active provider id in memory and persist in SQLite with an audit log entry."""
        if provider_id not in self._providers:
            raise KeyError(f"Unknown LLM provider_id: '{provider_id}'")
        self._active_provider_id = provider_id
        try:
            self.state_store.set_active_provider_id(provider_id)
        except Exception:
            pass
        cfg = self._providers[provider_id]
        self._state_store.record_audit_log(
            event_type="provider_switch",
            provider_id=provider_id,
            is_cloud_transmission=not cfg.is_local,
            details=f"Active provider switched to '{provider_id}' ({cfg.model_name})",
        )

    def get_active_provider(self) -> LLMProviderConfig:
        """Retrieve configuration for currently selected active provider."""
        active_id = self.get_active_provider_id()
        return self._providers[active_id]


_provider_registry_instance: Optional[LLMProviderRegistry] = None


def get_provider_registry() -> LLMProviderRegistry:
    """Retrieve singleton LLMProviderRegistry instance."""
    global _provider_registry_instance
    if _provider_registry_instance is None:
        _provider_registry_instance = LLMProviderRegistry()
    return _provider_registry_instance


def reset_provider_registry() -> None:
    """Reset singleton registry for test isolation."""
    global _provider_registry_instance
    _provider_registry_instance = None
