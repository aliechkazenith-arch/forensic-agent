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


class StorageError(ForensicOpsError):
    """Raised on storage or database query/insertion errors."""
    pass


class CitationValidationError(ForensicOpsError):
    """Raised when an AI-generated claim fails citation verification."""
    pass


class ConnectorError(ForensicOpsError):
    """Base exception for online collector and SIEM connector errors."""
    pass


class UnauthorizedCollectorExecutionError(ConnectorError, PermissionError):
    """Raised when an online collector action is attempted without a valid HumanApprovalToken."""
    pass


class ReadOnlyViolationError(ConnectorError):
    """Raised when a query or connector action attempts a mutating operation."""
    pass


class SSRFSecurityError(ConnectorError, ValueError):
    """Raised when a remote collector target or SIEM endpoint violates SSRF boundaries."""
    pass


class SIEMQueryError(ConnectorError):
    """Raised when a SIEM query execution fails or returns an error."""
    pass


class ExecutionPolicyError(ForensicOpsError):
    """Raised when a tool, binary, image, argument, or resource request violates the execution policy."""
    pass


class SandboxUnavailableError(ForensicOpsError):
    """Raised when the required container sandbox is unavailable and host fallback is rejected (fail-closed)."""
    pass


class ProcessTimeoutError(ForensicOpsError):
    """Raised when process execution times out and process trees are terminated."""
    pass


class UnsafePluginCardError(ForensicOpsError):
    """Raised when a plugin card fails validation against safety invariants."""
    pass


class CredentialEncryptionError(ForensicOpsError):
    """Raised on credential encryption, decryption, key configuration, or integrity failures."""
    pass


class CryptographicTamperError(CredentialEncryptionError):
    """Raised when cryptographic authentication fails (e.g., AEAD tag mismatch, HMAC chain break, or tampered ciphertext)."""
    pass


class RegistryParserError(ForensicOpsError):
    """Base exception for Windows Registry hive parsing errors."""
    pass


class RegistryInvalidSignatureError(RegistryParserError):
    """Raised when file signature is not 'regf'."""
    pass


class RegistryCorruptedError(RegistryParserError):
    """Raised when a Registry hive base block, hive bin, cell, or offset is corrupted or malformed."""
    pass


class RegistryTruncatedError(RegistryParserError):
    """Raised when a Registry hive file is truncated before expected blocks or cells."""
    pass


class RegistryResourceLimitError(RegistryParserError):
    """Raised when Registry hive parsing exceeds configured resource limits (size, keys, depth, timeout)."""
    pass

