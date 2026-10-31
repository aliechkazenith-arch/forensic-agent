"""Core engines and utilities for ForensicOps AI."""
from backend.app.core.auto_mapper import DryRunAutoMapper
from backend.app.core.column_projector import SmartColumnProjector
from backend.app.core.custody_engine import CustodyEngine, GENESIS_HASH, safe_make_readonly, safe_make_writable
from backend.app.core.dissect_adapter import DissectAdapter
from backend.app.core.exceptions import (
    CustodyTamperError,
    DecompressionBombError,
    ForensicOpsError,
    HashMismatchError,
    SuspiciousArchiveError,
    VaultIntegrityError,
    ZipSlipError,
)
from backend.app.core.plugin_runner import AirGappedSubprocessRunner, PluginRunner

__all__ = [
    "ForensicOpsError",
    "ZipSlipError",
    "SuspiciousArchiveError",
    "DecompressionBombError",
    "HashMismatchError",
    "CustodyTamperError",
    "VaultIntegrityError",
    "CustodyEngine",
    "GENESIS_HASH",
    "safe_make_readonly",
    "safe_make_writable",
    "SmartColumnProjector",
    "DryRunAutoMapper",
    "DissectAdapter",
    "AirGappedSubprocessRunner",
    "PluginRunner",
]
