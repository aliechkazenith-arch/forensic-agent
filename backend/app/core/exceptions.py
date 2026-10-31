"""Core exception classes for ForensicOps AI."""


class ForensicOpsError(Exception):
    """Base exception for all ForensicOps AI errors."""
    pass


class ZipSlipError(ForensicOpsError):
    """Raised when an archive member attempts directory traversal (Zip Slip)."""
    pass


class SuspiciousArchiveError(ForensicOpsError):
    """Raised when an archive contains suspicious elements like symlinks or device files."""
    pass


class DecompressionBombError(ForensicOpsError):
    """Raised when decompression exceeds compression ratio or absolute size quotas."""
    pass


class HashMismatchError(ForensicOpsError):
    """Raised when an artifact hash does not match the manifest or declared hash."""
    pass


class CustodyTamperError(ForensicOpsError):
    """Raised when hash-chain ledger inconsistency or tampering is detected."""
    pass


class VaultIntegrityError(ForensicOpsError):
    """Raised on storage or read-only permission failures inside the evidence vault."""
    pass
