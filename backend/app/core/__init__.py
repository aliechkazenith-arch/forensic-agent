"""Core engines and utilities for ForensicOps AI."""
from backend.app.core.auto_mapper import DryRunAutoMapper
from backend.app.core.column_projector import SmartColumnProjector
from backend.app.core.custody_engine import CustodyEngine, GENESIS_HASH, safe_make_readonly, safe_make_writable
from backend.app.core.dissect_adapter import DissectAdapter
from backend.app.core.citation_guard import CitationGuard, CitationValidationReport
from backend.app.core.exceptions import (
    CitationValidationError,
    CustodyTamperError,
    DecompressionBombError,
    ForensicOpsError,
    HashMismatchError,
    StorageError,
    SuspiciousArchiveError,
    VaultIntegrityError,
    ZipSlipError,
)
from backend.app.core.plugin_runner import AirGappedSubprocessRunner, PluginRunner
from backend.app.core.storage import ForensicStore

__all__ = [
    "ForensicOpsError",
    "ZipSlipError",
    "SuspiciousArchiveError",
    "DecompressionBombError",
    "HashMismatchError",
    "CustodyTamperError",
    "VaultIntegrityError",
    "StorageError",
    "CitationValidationError",
    "CustodyEngine",
    "GENESIS_HASH",
    "safe_make_readonly",
    "safe_make_writable",
    "SmartColumnProjector",
    "DryRunAutoMapper",
    "DissectAdapter",
    "AirGappedSubprocessRunner",
    "PluginRunner",
    "ForensicStore",
    "CitationGuard",
    "CitationValidationReport",
]
