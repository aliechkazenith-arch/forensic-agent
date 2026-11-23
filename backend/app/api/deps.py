"""FastAPI Dependency Injection & State Singletons for ForensicOps AI.

Provides centralized access to:
- ForensicStore (DuckDB / SQLite indexed findings)
- CustodyEngine (Ledger, defanged blob vault, streaming zip guard)
- SQLiteFeedbackMemoryProvider (Episodic learning & human feedback)
- ToolAutoMapperService (Visual tool dry-run heuristics)
- ForensicOpsWorkflowEngine (LangGraph context-passing DAG runner)
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, Optional

from backend.app.agent.graph import ForensicOpsWorkflowEngine
from backend.app.agent.lmstudio_client import LMStudioClient
from backend.app.agent.provider_registry import get_provider_registry
from backend.app.agent.memory_protocol import SQLiteFeedbackMemoryProvider
from backend.app.agent.ollama_client import OllamaClient
from backend.app.auth.case_authorization import (
    CaseAuthorizationService,
    get_case_authorization_service,
    reset_case_authorization_service,
)
from backend.app.core.approval_engine import ApprovalEngine
from backend.app.core.auto_mapper import ToolAutoMapperService
from backend.app.core.citation_guard import CitationGuard
from backend.app.core.config import get_settings
from backend.app.core.custody_engine import CustodyEngine
from backend.app.core.dissect_adapter import DissectAdapter
from backend.app.core.exceptions import ForensicOpsError
from backend.app.core.plugin_runner import PluginRunner
from backend.app.core.storage import ForensicStore

import re

CASE_ID_REGEX = re.compile(r"^[a-zA-Z0-9_-]+$")

_GLOBAL_STORES: Dict[str, ForensicStore] = {}
_GLOBAL_CUSTODY_ENGINES: Dict[str, CustodyEngine] = {}
_GLOBAL_MEMORY_PROVIDER: Optional[SQLiteFeedbackMemoryProvider] = None
_GLOBAL_AUTO_MAPPER: Optional[ToolAutoMapperService] = None
_GLOBAL_WORKFLOW_ENGINE: Optional[ForensicOpsWorkflowEngine] = None
_BASE_VAULT_DIR: Optional[Path] = None


def set_base_vault_dir(vault_dir: Path) -> None:
    """Override base vault directory (useful for hermetic tests)."""
    global _BASE_VAULT_DIR
    _BASE_VAULT_DIR = vault_dir


def get_base_vault_dir() -> Path:
    global _BASE_VAULT_DIR
    if _BASE_VAULT_DIR is not None:
        return _BASE_VAULT_DIR
    vault_env = os.environ.get("FORENSICOPS_VAULT_DIR")
    if vault_env:
        return Path(vault_env).resolve()
    return Path("vault").resolve()


def validate_vault_case_root(case_id: str) -> Path:
    """Validate case_id against directory traversal attacks and ensure it is confined within vault root."""
    if not case_id or not CASE_ID_REGEX.match(case_id):
        raise ForensicOpsError(f"Invalid case_id format: '{case_id}'. Must strictly match ^[a-zA-Z0-9_-]+$")
    base_dir = get_base_vault_dir().resolve()
    vault_root = (base_dir / case_id).resolve()
    if not vault_root.is_relative_to(base_dir):
        raise ForensicOpsError(f"Directory traversal detected in case_id: '{case_id}'")
    vault_root.mkdir(parents=True, exist_ok=True)
    return vault_root


def get_custody_engine(case_id: str = "default_case") -> CustodyEngine:
    """Retrieve or initialize the CustodyEngine for a specific case."""
    global _GLOBAL_CUSTODY_ENGINES
    vault_root = validate_vault_case_root(case_id)
    if case_id not in _GLOBAL_CUSTODY_ENGINES:
        db_path = vault_root / "custody.db"
        audit_log = vault_root / "audit.jsonl"
        _GLOBAL_CUSTODY_ENGINES[case_id] = CustodyEngine(
            vault_root=vault_root,
            db_path=db_path,
            case_id=case_id,
        )
    return _GLOBAL_CUSTODY_ENGINES[case_id]


def get_storage(case_id: str = "default_case") -> ForensicStore:
    """Retrieve or initialize the ForensicStore for a specific case."""
    global _GLOBAL_STORES
    vault_root = validate_vault_case_root(case_id)
    if case_id not in _GLOBAL_STORES:
        db_path = vault_root / "forensic_store.duckdb"
        _GLOBAL_STORES[case_id] = ForensicStore(db_path=str(db_path))
    return _GLOBAL_STORES[case_id]


def get_memory_provider() -> SQLiteFeedbackMemoryProvider:
    """Retrieve or initialize the global SQLiteFeedbackMemoryProvider."""
    global _GLOBAL_MEMORY_PROVIDER
    if _GLOBAL_MEMORY_PROVIDER is None:
        vault_root = get_base_vault_dir()
        vault_root.mkdir(parents=True, exist_ok=True)
        db_path = vault_root / "feedback_memory.db"
        _GLOBAL_MEMORY_PROVIDER = SQLiteFeedbackMemoryProvider(db_path=db_path)
    return _GLOBAL_MEMORY_PROVIDER


def get_auto_mapper() -> ToolAutoMapperService:
    """Retrieve or initialize the ToolAutoMapperService."""
    global _GLOBAL_AUTO_MAPPER
    if _GLOBAL_AUTO_MAPPER is None:
        _GLOBAL_AUTO_MAPPER = ToolAutoMapperService()
    return _GLOBAL_AUTO_MAPPER


def get_workflow_engine(case_id: str = "default_case") -> ForensicOpsWorkflowEngine:
    """Retrieve or construct the LangGraph ForensicOpsWorkflowEngine."""
    storage = get_storage(case_id)
    custody = get_custody_engine(case_id)
    memory = get_memory_provider()
    dissect = DissectAdapter()
    runner = PluginRunner(custody_engine=custody)
    settings = get_settings()
    is_mock = settings.llm_mock_mode or (os.getenv("FORENSICOPS_LIVE_LLM", "false").lower() not in ("true", "1", "yes"))
    active_pid = get_provider_registry().get_active_provider_id()
    llm = LMStudioClient(
        provider_id=active_pid,
        timeout=settings.llm_timeout,
        mock_mode=is_mock,
    )
    guard = CitationGuard(storage=storage)

    secret_key = settings.human_approval_hmac_secret or os.getenv("HUMAN_APPROVAL_HMAC_SECRET")
    if not secret_key or secret_key == "forensicops-gate-secret":
        secret_key = "forensicops-vault-hmac-key-2026-production-secured"

    approval_engine = get_approval_engine(case_id)

    return ForensicOpsWorkflowEngine(
        storage=storage,
        memory_provider=memory,
        llm_client=llm,
        citation_guard=guard,
        dissect_adapter=dissect,
        plugin_runner=runner,
        custody_engine=custody,
        secret_key=secret_key,
        approval_engine=approval_engine,
    )


_GLOBAL_APPROVAL_ENGINES: Dict[str, ApprovalEngine] = {}


def get_approval_engine(case_id: str = "default_case") -> ApprovalEngine:
    """Retrieve or initialize the ApprovalEngine for a specific case."""
    global _GLOBAL_APPROVAL_ENGINES
    if case_id not in _GLOBAL_APPROVAL_ENGINES:
        custody = get_custody_engine(case_id)
        _GLOBAL_APPROVAL_ENGINES[case_id] = ApprovalEngine(custody_engine=custody)
    return _GLOBAL_APPROVAL_ENGINES[case_id]


def reset_dependencies() -> None:
    """Reset singletons for clean testing."""
    global _GLOBAL_STORES, _GLOBAL_CUSTODY_ENGINES, _GLOBAL_MEMORY_PROVIDER, _GLOBAL_AUTO_MAPPER, _GLOBAL_WORKFLOW_ENGINE, _GLOBAL_APPROVAL_ENGINES, _BASE_VAULT_DIR
    _GLOBAL_STORES.clear()
    _GLOBAL_CUSTODY_ENGINES.clear()
    _GLOBAL_APPROVAL_ENGINES.clear()
    reset_case_authorization_service()
    if _GLOBAL_MEMORY_PROVIDER is not None:
        try:
            _GLOBAL_MEMORY_PROVIDER.close()
        except Exception:
            pass
        _GLOBAL_MEMORY_PROVIDER = None
    _GLOBAL_AUTO_MAPPER = None
    _GLOBAL_WORKFLOW_ENGINE = None
    _BASE_VAULT_DIR = None
