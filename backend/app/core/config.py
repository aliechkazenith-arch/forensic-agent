"""Centralized Configuration & Environment Settings for ForensicOps AI.

Standards:
- Configurable LLM Providers: Supports OpenRouter, local LM Studio, or OpenAI-compatible endpoints.
- Air-gapped & proxy isolation: trust_env=False enforced on HTTP transport clients.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional
from pydantic import BaseModel, Field


def _load_env_files() -> None:
    """Manually parse .env files if present to populate os.environ without requiring external dependencies."""
    candidates = [
        Path(".env"),
        Path("backend/.env"),
        Path(__file__).resolve().parent.parent.parent.parent / ".env",
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


class Settings(BaseModel):
    """ForensicOps AI configuration settings."""

    # OpenRouter / OpenAI-Compatible LLM Settings
    openai_api_base_url: str = Field(
        default_factory=lambda: os.getenv("OPENAI_API_BASE_URL", "https://openrouter.ai/api/v1")
    )
    openai_api_key: str = Field(
        default_factory=lambda: os.getenv("OPENROUTER_API_KEY") or os.getenv("OPENAI_API_KEY", "not-needed")
    )
    openai_model: str = Field(
        default_factory=lambda: os.getenv("MODEL_NAME") or os.getenv("OPENAI_MODEL", "google/gemma-4-31b-it:free")
    )
    openrouter_api_key: Optional[str] = Field(
        default_factory=lambda: os.getenv("OPENROUTER_API_KEY")
    )
    model_name: str = Field(
        default_factory=lambda: os.getenv("MODEL_NAME") or os.getenv("OPENAI_MODEL", "google/gemma-4-31b-it:free")
    )
    llm_timeout: float = Field(
        default_factory=lambda: float(os.getenv("LLM_TIMEOUT", "60.0"))
    )
    llm_mock_mode: bool = Field(
        default_factory=lambda: os.getenv("LLM_MOCK_MODE", "false").lower() in ("true", "1", "yes")
    )

    # Custody & Storage Settings
    vault_dir: str = Field(
        default_factory=lambda: os.getenv("FORENSICOPS_VAULT_DIR", "vault")
    )
    plugins_dir: str = Field(
        default_factory=lambda: os.getenv("FORENSICOPS_PLUGINS_DIR", "plugins")
    )
    human_approval_hmac_secret: str = Field(
        default_factory=lambda: os.getenv("HUMAN_APPROVAL_HMAC_SECRET", "")
    )
    credential_key: Optional[str] = Field(
        default_factory=lambda: os.getenv("FORENSICOPS_CREDENTIAL_KEY")
    )
    credential_key_file: Optional[str] = Field(
        default_factory=lambda: os.getenv("FORENSICOPS_CREDENTIAL_KEY_FILE")
    )
    evidence_allowlist_dirs: str = Field(
        default_factory=lambda: os.getenv(
            "FORENSICOPS_EVIDENCE_ALLOWLIST",
            "vault,sample,evidence,data/evidence,backend/data,backend/data/evidence_intake",
        )
    )
    max_upload_size_bytes: int = Field(
        default_factory=lambda: int(os.getenv("FORENSICOPS_MAX_UPLOAD_BYTES", str(10 * 1024 * 1024 * 1024)))
    )

    # Archive Intake & Decompression Limits
    max_archive_entries: int = Field(
        default_factory=lambda: int(os.getenv("FORENSICOPS_MAX_ARCHIVE_ENTRIES", "10000"))
    )
    max_archive_single_size_bytes: int = Field(
        default_factory=lambda: int(os.getenv("FORENSICOPS_MAX_ARCHIVE_SINGLE_BYTES", str(5 * 1024 * 1024 * 1024)))
    )
    max_archive_total_size_bytes: int = Field(
        default_factory=lambda: int(os.getenv("FORENSICOPS_MAX_ARCHIVE_TOTAL_BYTES", str(20 * 1024 * 1024 * 1024)))
    )
    max_archive_compression_ratio: float = Field(
        default_factory=lambda: float(os.getenv("FORENSICOPS_MAX_ARCHIVE_RATIO", "100.0"))
    )
    max_b64_inline_bytes: int = Field(
        default_factory=lambda: int(os.getenv("FORENSICOPS_MAX_B64_INLINE_BYTES", str(50 * 1024 * 1024)))
    )

    # Windows Registry Hive Limits (Phase 14.2-C / DEFECT-FOR-02)
    max_registry_hive_size_bytes: int = Field(
        default_factory=lambda: int(os.getenv("FORENSICOPS_MAX_REGISTRY_HIVE_BYTES", str(256 * 1024 * 1024)))
    )
    max_registry_parse_seconds: float = Field(
        default_factory=lambda: float(os.getenv("FORENSICOPS_MAX_REGISTRY_PARSE_SECONDS", "60.0"))
    )
    max_registry_keys: int = Field(
        default_factory=lambda: int(os.getenv("FORENSICOPS_MAX_REGISTRY_KEYS", "50000"))
    )
    max_registry_depth: int = Field(
        default_factory=lambda: int(os.getenv("FORENSICOPS_MAX_REGISTRY_DEPTH", "60"))
    )


_settings_instance: Optional[Settings] = None


def get_settings() -> Settings:
    """Retrieve the cached singleton Settings instance."""
    global _settings_instance
    if _settings_instance is None:
        _load_env_files()
        _settings_instance = Settings()
    return _settings_instance


def reset_settings() -> None:
    """Reset settings singleton (used for testing environment changes)."""
    global _settings_instance
    _settings_instance = None


def validate_production_configuration(settings: Optional[Settings] = None) -> List[str]:
    """Validate deployment security controls and fail-closed configurations."""
    cfg = settings or get_settings()
    errors: List[str] = []

    # 1. Loopback binding check: non-loopback requires explicit opt-in
    host = os.getenv("FORENSICOPS_HOST", "127.0.0.1").strip().lower()
    allow_external = os.getenv("FORENSICOPS_ALLOW_EXTERNAL", "false").lower() in ("true", "1", "yes")
    if host not in ("127.0.0.1", "localhost", "::1") and not allow_external:
        errors.append(
            f"Deployment Security: Non-loopback host '{host}' configured without explicit "
            "opt-in (FORENSICOPS_ALLOW_EXTERNAL=true). Local deployments must bind to loopback (127.0.0.1)."
        )

    # 2. Production secret validation
    is_prod = os.getenv("ENVIRONMENT", "").lower() == "production" or os.getenv("FORENSICOPS_ENV", "").lower() == "production"
    hmac_sec = os.getenv("HUMAN_APPROVAL_HMAC_SECRET") or (cfg.human_approval_hmac_secret if cfg else "")
    if is_prod:
        if not hmac_sec or hmac_sec in ("forensicops-gate-secret", "default", "dev_approval_secret_replace_in_production"):
            errors.append(
                "Production Security: HUMAN_APPROVAL_HMAC_SECRET must be configured with a secure non-default secret."
            )
        jwt_sec = os.getenv("JWT_SECRET_KEY") or (cfg.jwt_secret_key if hasattr(cfg, "jwt_secret_key") else "")
        if not jwt_sec or len(jwt_sec) < 32:
            errors.append(
                "Production Security: JWT_SECRET_KEY must be configured with at least 32 characters in production."
            )

    return errors
