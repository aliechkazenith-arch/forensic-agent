"""Evidence Sandbox, Defanged Blob Vault, Capsule Unpacker, and Hash-Chained Custody Engine.

Standards: RFC 3227, NIST SP 800-86, ISO/IEC 27037
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import stat
import tarfile
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from uuid import uuid4

from backend.app.core.config import get_settings
from backend.app.core.exceptions import (
    CustodyTamperError,
    DecompressionBombError,
    ForensicOpsError,
    HashMismatchError,
    SuspiciousArchiveError,
    VaultIntegrityError,
    ZipSlipError,
)
from backend.app.models.custody import (
    ArtifactRecord,
    CapsuleManifest,
    CustodyChainEntry,
    canonical_json_dump,
)

GENESIS_HASH = "0" * 64
DEFAULT_CHUNK_SIZE = 64 * 1024  # 64 KB
EXECUTABLE_EXTENSIONS = {
    ".exe", ".ps1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".msc", ".cpl", ".scr", ".pif", ".hta", ".dll",
    ".sys", ".com", ".msi", ".msp", ".mst", ".bin", ".elf", ".so",
    ".dylib", ".sh", ".bash", ".zsh", ".py", ".pyc", ".pyo"
}


def is_prohibited_system_directory(p: Union[str, Path]) -> bool:
    """Check if target path is within sensitive OS system directories."""
    resolved = Path(p).resolve()
    # Windows system directories
    sys_root = os.environ.get("SystemRoot")
    if sys_root:
        try:
            sr_path = Path(sys_root).resolve()
            if resolved == sr_path or resolved.is_relative_to(sr_path):
                return True
        except (ValueError, RuntimeError):
            pass
    prog_files = os.environ.get("ProgramFiles")
    if prog_files:
        try:
            pf_path = Path(prog_files).resolve()
            if resolved == pf_path or resolved.is_relative_to(pf_path):
                return True
        except (ValueError, RuntimeError):
            pass
    prog_files_x86 = os.environ.get("ProgramFiles(x86)")
    if prog_files_x86:
        try:
            pfx_path = Path(prog_files_x86).resolve()
            if resolved == pfx_path or resolved.is_relative_to(pfx_path):
                return True
        except (ValueError, RuntimeError):
            pass
    # POSIX system directories
    posix_str = str(resolved).replace("\\", "/")
    for prohibited in ["/etc", "/root", "/proc", "/sys", "/dev", "/boot"]:
        if posix_str == prohibited or posix_str.startswith(prohibited + "/"):
            return True
    return False


def validate_evidence_path(
    path_str: Union[str, Path],
    allowed_roots: Optional[List[Path]] = None,
) -> Path:
    """Validate that local evidence path is strictly confined to approved evidence roots.

    Prevents directory traversal, symlink escapes, arbitrary filesystem reads,
    path normalization bypasses, Windows UNC paths, and sensitive system files.
    """
    raw_str = str(path_str).strip()
    if "\x00" in raw_str:
        raise ForensicOpsError("Access denied: Invalid path with null byte sequence.")

    # Reject Windows UNC paths and device paths
    if raw_str.startswith(("\\\\", "//", "\\\\?\\", "\\\\.\\")):
        raise ForensicOpsError(f"Access denied: UNC and device paths are prohibited: '{raw_str}'")

    target_path = Path(raw_str)
    try:
        resolved = target_path.resolve(strict=True)
    except FileNotFoundError:
        raise ForensicOpsError(f"Evidence path not found: {path_str}")
    except (OSError, RuntimeError) as e:
        raise ForensicOpsError(f"Failed to resolve evidence path '{path_str}': {e}")

    if not resolved.is_file():
        raise ForensicOpsError(f"Evidence path must point to a file, not a directory: {path_str}")

    # Disallow sensitive config/secrets/source files and private keys
    sensitive_names = {
        ".env", "users.db", "pyproject.toml", "poetry.lock",
        "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
        "sam", "system", "security", "software", "ntuser.dat",
    }
    name_lower = resolved.name.lower()
    if name_lower in sensitive_names or any(part.startswith(".git") for part in resolved.parts):
        raise ForensicOpsError(f"Access denied: Prohibited sensitive system file '{resolved.name}'.")

    # Reject OS system directories
    if is_prohibited_system_directory(resolved):
        raise ForensicOpsError(f"Access denied: Path '{path_str}' is inside a protected OS system directory.")

    # Confinement to allowed roots
    if allowed_roots is None:
        settings = get_settings()
        raw_allowlist = settings.evidence_allowlist_dirs
        roots = [Path(p.strip()).resolve() for p in raw_allowlist.split(",") if p.strip()]
        vault_root = Path(settings.vault_dir).resolve()
        if vault_root not in roots:
            roots.append(vault_root)

        is_test = bool(os.getenv("PYTEST_CURRENT_TEST")) or os.getenv("FORENSICOPS_ENVIRONMENT") == "test"
        # In test mode, only include tempdir if no explicit evidence allowlist was configured in the environment
        if is_test and "FORENSICOPS_EVIDENCE_ALLOWLIST" not in os.environ:
            roots.append(Path(tempfile.gettempdir()).resolve())
        allowed_roots = roots

    is_allowed = any(
        resolved == root or root in resolved.parents
        for root in allowed_roots
    )
    if not is_allowed:
        raise ForensicOpsError(f"Access denied: Path '{path_str}' is outside approved evidence roots.")

    return resolved


def compute_stream_hashes(file_path: Union[str, Path], chunk_size: int = DEFAULT_CHUNK_SIZE) -> Tuple[str, str, int]:
    """Compute SHA-256 and SHA-512 hashes and total byte size for a file in userspace."""
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()
    total_bytes = 0

    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            sha256.update(chunk)
            sha512.update(chunk)
            total_bytes += len(chunk)

    return sha256.hexdigest(), sha512.hexdigest(), total_bytes


def compute_bytes_hashes(data: bytes) -> Tuple[str, str, int]:
    """Compute SHA-256 and SHA-512 hashes and byte length for bytes in memory."""
    sha256 = hashlib.sha256(data).hexdigest()
    sha512 = hashlib.sha512(data).hexdigest()
    return sha256, sha512, len(data)


def safe_make_readonly(target_path: Path) -> None:
    """Apply read-only permissions across Windows and Unix platforms."""
    try:
        # On Windows, stat.S_IREAD removes write permissions.
        # On Unix, 0o400 (stat.S_IRUSR) sets owner read-only.
        if os.name == "nt":
            os.chmod(target_path, stat.S_IREAD)
        else:
            os.chmod(target_path, stat.S_IRUSR)
    except Exception as e:
        raise VaultIntegrityError(f"Failed to set read-only permissions on {target_path}: {e}") from e


def safe_make_writable(target_path: Path) -> None:
    """Temporarily restore write permissions for cleanup/teardown."""
    try:
        if os.name == "nt":
            os.chmod(target_path, stat.S_IWRITE | stat.S_IREAD)
        else:
            os.chmod(target_path, 0o600)
    except Exception:
        pass


class CustodyEngine:
    """Manages the 4-layer evidence sandbox, defanged blob vault, and append-only custody ledger."""

    def __init__(
        self,
        vault_root: Union[str, Path],
        db_path: Optional[Union[str, Path]] = None,
        case_id: Optional[str] = None,
    ):
        self.vault_root = Path(vault_root).resolve()
        self.blobs_dir = self.vault_root / "blobs"
        self.blobs_dir.mkdir(parents=True, exist_ok=True)

        self.db_path = Path(db_path).resolve() if db_path else self.vault_root / "custody.db"
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self.audit_log_path = self.vault_root / "audit.jsonl"
        self.case_id = case_id
        self._init_database()

    def _verify_case_match(self, case_id: str) -> None:
        """Enforce strict case boundary if CustodyEngine is bound to a specific case."""
        if self.case_id is not None and case_id != self.case_id:
            raise ForensicOpsError(
                f"CustodyEngine bound to case '{self.case_id}' cannot operate on mismatched case '{case_id}'"
            )

    def _get_connection(self) -> sqlite3.Connection:
        """Create a database connection with WAL mode and row factory."""
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_database(self) -> None:
        """Initialize append-only SQLite custody ledger schema with migrations."""
        with self._get_connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS custody_chain (
                    seq_id INTEGER PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    timestamp_utc TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    artifact_sha256 TEXT,
                    tool_id TEXT,
                    prev_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS artifacts (
                    artifact_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    type TEXT NOT NULL,
                    original_path TEXT NOT NULL,
                    blob_path TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    sha256 TEXT NOT NULL,
                    sha512 TEXT NOT NULL,
                    acquired_utc TEXT NOT NULL,
                    acquisition_method TEXT NOT NULL,
                    original_name TEXT,
                    actor TEXT,
                    custody_seq_id INTEGER,
                    verification_status TEXT DEFAULT 'VERIFIED'
                );

                CREATE INDEX IF NOT EXISTS idx_custody_case ON custody_chain(case_id);
                CREATE INDEX IF NOT EXISTS idx_custody_seq ON custody_chain(seq_id);
                CREATE INDEX IF NOT EXISTS idx_artifacts_case ON artifacts(case_id);
                CREATE INDEX IF NOT EXISTS idx_artifacts_sha256 ON artifacts(sha256);

                CREATE TABLE IF NOT EXISTS tool_executions (
                    execution_id TEXT PRIMARY KEY,
                    execution_key TEXT UNIQUE NOT NULL,
                    case_id TEXT NOT NULL,
                    artifact_id TEXT NOT NULL,
                    artifact_sha256 TEXT NOT NULL,
                    tool_id TEXT NOT NULL,
                    tool_version TEXT NOT NULL,
                    status TEXT NOT NULL,
                    started_at_utc TEXT NOT NULL,
                    finished_at_utc TEXT,
                    findings_count INTEGER DEFAULT 0,
                    raw_output_path TEXT,
                    parameters TEXT,
                    warnings TEXT,
                    errors TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_tool_exec_key ON tool_executions(execution_key);
                CREATE INDEX IF NOT EXISTS idx_tool_exec_case ON tool_executions(case_id);
            """)

            # Dynamic column migration for backward compatibility
            cols = {row[1] for row in conn.execute("PRAGMA table_info(artifacts);").fetchall()}
            if "original_name" not in cols:
                conn.execute("ALTER TABLE artifacts ADD COLUMN original_name TEXT;")
            if "actor" not in cols:
                conn.execute("ALTER TABLE artifacts ADD COLUMN actor TEXT;")
            if "custody_seq_id" not in cols:
                conn.execute("ALTER TABLE artifacts ADD COLUMN custody_seq_id INTEGER;")
            if "verification_status" not in cols:
                conn.execute("ALTER TABLE artifacts ADD COLUMN verification_status TEXT DEFAULT 'VERIFIED';")

    def _write_audit_log(self, case_id: str, actor: str, action: str, details: Dict[str, Any]) -> None:
        """Append a tamper-evident audit record to audit.jsonl with sync to disk."""
        audit_entry = {
            "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "case_id": case_id,
            "actor": actor,
            "action": action,
            "details": details,
        }
        with open(self.audit_log_path, "a", encoding="utf-8") as f:
            f.write(canonical_json_dump(audit_entry) + "\n")
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass

    # --------------------------------------------------------------------------
    # Layer 1 & 2: Streaming Zip Guard
    # --------------------------------------------------------------------------
    def safe_extract_archive(
        self,
        archive_path: Union[str, Path],
        extract_to: Union[str, Path],
        max_ratio: Optional[float] = None,
        max_single_size_bytes: Optional[int] = None,
        max_total_size_bytes: Optional[int] = None,
        max_entries: Optional[int] = None,
    ) -> List[Path]:
        """Safely extract zip/tar archives with strict Zip Slip, symlink, disk space, and zip bomb guards."""
        archive_path = Path(archive_path).resolve()
        extract_to = Path(extract_to).resolve()
        extract_to.mkdir(parents=True, exist_ok=True)

        settings = get_settings()
        effective_max_ratio = max_ratio if max_ratio is not None else settings.max_archive_compression_ratio
        effective_single_max = max_single_size_bytes if max_single_size_bytes is not None else settings.max_archive_single_size_bytes
        effective_total_max = max_total_size_bytes if max_total_size_bytes is not None else settings.max_archive_total_size_bytes
        effective_max_entries = max_entries if max_entries is not None else settings.max_archive_entries

        if zipfile.is_zipfile(archive_path):
            return self._safe_extract_zip(
                archive_path,
                extract_to,
                effective_max_ratio,
                effective_single_max,
                effective_total_max,
                effective_max_entries,
            )
        elif tarfile.is_tarfile(archive_path):
            return self._safe_extract_tar(
                archive_path,
                extract_to,
                effective_max_ratio,
                effective_single_max,
                effective_total_max,
                effective_max_entries,
            )
        else:
            raise ForensicOpsError(f"Unsupported archive format: {archive_path.name}")

    def _safe_extract_zip(
        self,
        archive_path: Path,
        extract_to: Path,
        max_ratio: float,
        max_single_size_bytes: int,
        max_total_size_bytes: int,
        max_entries: int = 10000,
    ) -> List[Path]:
        extracted_paths: List[Path] = []
        total_extracted_bytes = 0

        with zipfile.ZipFile(archive_path, "r") as zf:
            members = zf.infolist()
            # 1. Total entry count check
            if len(members) > max_entries:
                raise DecompressionBombError(
                    f"Archive entry count {len(members)} exceeds maximum limit {max_entries}"
                )

            # 2. Total declared size check
            declared_total = sum(m.file_size for m in members)
            if declared_total > max_total_size_bytes:
                raise DecompressionBombError(
                    f"Declared uncompressed size {declared_total} exceeds maximum limit {max_total_size_bytes}"
                )

            # 3. Available disk space pre-check
            try:
                free_disk = shutil.disk_usage(str(extract_to)).free
                # Reserve declared size + 500 MB safety buffer
                if free_disk < declared_total + (500 * 1024 * 1024):
                    raise ForensicOpsError(
                        f"Insufficient disk space for archive extraction: available {free_disk} bytes, required {declared_total + 500*1024*1024} bytes"
                    )
            except (OSError, ValueError):
                pass

            for member in members:
                raw_filename = member.filename
                if "\x00" in raw_filename:
                    raise ZipSlipError(f"Zip Slip null byte in filename blocked: {repr(raw_filename)}")

                # Check Zip Slip path traversal
                normalized_name = os.path.normpath(raw_filename)
                if (
                    normalized_name.startswith("..")
                    or os.path.isabs(normalized_name)
                    or normalized_name.startswith("/")
                    or normalized_name.startswith("\\")
                    or (len(normalized_name) >= 2 and normalized_name[1] == ":")
                ):
                    raise ZipSlipError(f"Zip Slip path traversal blocked: {raw_filename}")

                target_dest = (extract_to / normalized_name).resolve()
                try:
                    target_dest.relative_to(extract_to)
                except ValueError as e:
                    raise ZipSlipError(f"Zip Slip escape outside root: {raw_filename}") from e

                # Check for symlinks in zip external attributes
                # High 16 bits contain Unix file mode bits. S_IFLNK is 0o120000.
                unix_mode = member.external_attr >> 16
                if unix_mode and stat.S_ISLNK(unix_mode):
                    raise SuspiciousArchiveError(f"Archive symlink prohibited: {raw_filename}")

                # Check single file ratio / bomb
                if member.compress_size > 0:
                    ratio = member.file_size / member.compress_size
                    if ratio > max_ratio and member.file_size > 1024 * 1024:
                        raise DecompressionBombError(
                            f"Compression ratio {ratio:.1f} for {raw_filename} exceeds threshold {max_ratio}"
                        )
                if member.file_size > max_single_size_bytes:
                    raise DecompressionBombError(
                        f"File {raw_filename} declared size {member.file_size} exceeds max single file limit {max_single_size_bytes}"
                    )

                if member.is_dir():
                    target_dest.mkdir(parents=True, exist_ok=True)
                    continue

                # Streaming extraction with byte tracking
                target_dest.parent.mkdir(parents=True, exist_ok=True)
                member_bytes = 0
                with zf.open(member, "r") as src, open(target_dest, "wb") as dst:
                    while True:
                        chunk = src.read(DEFAULT_CHUNK_SIZE)
                        if not chunk:
                            break
                        member_bytes += len(chunk)
                        total_extracted_bytes += len(chunk)
                        if member_bytes > max_single_size_bytes:
                            raise DecompressionBombError(
                                f"Extracted bytes for {raw_filename} exceeded {max_single_size_bytes}"
                            )
                        if total_extracted_bytes > max_total_size_bytes:
                            raise DecompressionBombError(
                                f"Total extracted bytes exceeded {max_total_size_bytes}"
                            )
                        dst.write(chunk)

                # Post-extraction symlink verification
                if os.path.islink(target_dest) or target_dest.is_symlink():
                    target_dest.unlink(missing_ok=True)
                    raise SuspiciousArchiveError(f"Extracted member is a symlink: {raw_filename}")

                extracted_paths.append(target_dest)

        return extracted_paths

    def _safe_extract_tar(
        self,
        archive_path: Path,
        extract_to: Path,
        max_ratio: float,
        max_single_size_bytes: int,
        max_total_size_bytes: int,
        max_entries: int = 10000,
    ) -> List[Path]:
        extracted_paths: List[Path] = []
        total_extracted_bytes = 0

        with tarfile.open(archive_path, "r:*") as tf:
            members = tf.getmembers()
            if len(members) > max_entries:
                raise DecompressionBombError(
                    f"Tar archive entry count {len(members)} exceeds maximum limit {max_entries}"
                )

            declared_total = sum(m.size for m in members)
            if declared_total > max_total_size_bytes:
                raise DecompressionBombError(
                    f"Declared uncompressed size {declared_total} exceeds maximum limit {max_total_size_bytes}"
                )

            try:
                free_disk = shutil.disk_usage(str(extract_to)).free
                if free_disk < declared_total + (500 * 1024 * 1024):
                    raise ForensicOpsError(
                        f"Insufficient disk space for archive extraction: available {free_disk} bytes, required {declared_total + 500*1024*1024} bytes"
                    )
            except (OSError, ValueError):
                pass

            for member in members:
                if "\x00" in member.name:
                    raise ZipSlipError(f"Tar null byte in member name blocked: {repr(member.name)}")

                if member.issym() or member.islnk():
                    raise SuspiciousArchiveError(f"Tar symlink/hardlink prohibited: {member.name}")
                if member.isdev() or member.ischr() or member.isblk() or member.isfifo():
                    raise SuspiciousArchiveError(f"Special device member prohibited: {member.name}")

                normalized_name = os.path.normpath(member.name)
                if (
                    normalized_name.startswith("..")
                    or os.path.isabs(normalized_name)
                    or normalized_name.startswith("/")
                    or normalized_name.startswith("\\")
                    or (len(normalized_name) >= 2 and normalized_name[1] == ":")
                ):
                    raise ZipSlipError(f"Tar Slip path traversal blocked: {member.name}")

                target_dest = (extract_to / normalized_name).resolve()
                try:
                    target_dest.relative_to(extract_to)
                except ValueError as e:
                    raise ZipSlipError(f"Tar Slip escape outside root: {member.name}") from e

                if member.size > max_single_size_bytes:
                    raise DecompressionBombError(
                        f"Tar member {member.name} size {member.size} exceeds single limit {max_single_size_bytes}"
                    )

                if member.isdir():
                    target_dest.mkdir(parents=True, exist_ok=True)
                    continue

                target_dest.parent.mkdir(parents=True, exist_ok=True)
                fobj = tf.extractfile(member)
                if fobj is None:
                    continue

                member_bytes = 0
                with open(target_dest, "wb") as dst:
                    while True:
                        chunk = fobj.read(DEFAULT_CHUNK_SIZE)
                        if not chunk:
                            break
                        member_bytes += len(chunk)
                        total_extracted_bytes += len(chunk)
                        if member_bytes > max_single_size_bytes:
                            raise DecompressionBombError(f"Extracted bytes exceeded limit on {member.name}")
                        if total_extracted_bytes > max_total_size_bytes:
                            raise DecompressionBombError("Total extracted bytes exceeded limit")
                        dst.write(chunk)

                if os.path.islink(target_dest) or target_dest.is_symlink():
                    target_dest.unlink(missing_ok=True)
                    raise SuspiciousArchiveError(f"Extracted member is a symlink: {member.name}")

                extracted_paths.append(target_dest)

        return extracted_paths

    # --------------------------------------------------------------------------
    # Layer 2: Defanged .blob Vault Storage
    # --------------------------------------------------------------------------
    def store_in_blob_vault(self, source_path: Union[str, Path]) -> Tuple[Path, str, str, int]:
        """Store an evidence file into the defanged .blob vault with read-only permissions and integrity checks."""
        source_path = Path(source_path).resolve()
        if not source_path.is_file():
            raise ForensicOpsError(f"Source file does not exist: {source_path}")

        sha256, sha512, size_bytes = compute_stream_hashes(source_path)
        shard_dir = self.blobs_dir / sha256[:2]
        shard_dir.mkdir(parents=True, exist_ok=True)
        blob_path = shard_dir / f"{sha256}.blob"

        if blob_path.exists():
            # Verify existing blob integrity
            try:
                ex_sha256, ex_sha512, ex_size = compute_stream_hashes(blob_path)
                if ex_sha256.lower() != sha256.lower() or ex_size != size_bytes:
                    # Existing blob is corrupted/tampered; replace from verified source
                    safe_make_writable(blob_path)
                    blob_path.unlink(missing_ok=True)
                else:
                    safe_make_readonly(blob_path)
                    return blob_path, sha256, sha512, size_bytes
            except Exception:
                safe_make_writable(blob_path)
                blob_path.unlink(missing_ok=True)

        # Atomic copy to a temp file in shard, verify post-write hashes, and rename
        temp_dest = shard_dir / f"{sha256}.tmp_{uuid4().hex}"
        try:
            shutil.copyfile(source_path, temp_dest)
            v_sha256, v_sha512, v_size = compute_stream_hashes(temp_dest)
            if v_sha256.lower() != sha256.lower() or v_sha512.lower() != sha512.lower() or v_size != size_bytes:
                raise VaultIntegrityError(f"Post-write integrity check failed for blob {sha256}")
            safe_make_readonly(temp_dest)
            os.replace(temp_dest, blob_path)
        except Exception as e:
            if temp_dest.exists():
                safe_make_writable(temp_dest)
                temp_dest.unlink(missing_ok=True)
            raise VaultIntegrityError(f"Failed to store blob {sha256}: {e}") from e

        return blob_path, sha256, sha512, size_bytes

    def store_bytes_in_blob_vault(self, data: bytes) -> Tuple[Path, str, str, int]:
        """Store raw bytes directly into the defanged .blob vault with integrity verification."""
        sha256, sha512, size_bytes = compute_bytes_hashes(data)
        shard_dir = self.blobs_dir / sha256[:2]
        shard_dir.mkdir(parents=True, exist_ok=True)
        blob_path = shard_dir / f"{sha256}.blob"

        if blob_path.exists():
            try:
                ex_sha256, _, ex_size = compute_stream_hashes(blob_path)
                if ex_sha256.lower() != sha256.lower() or ex_size != size_bytes:
                    safe_make_writable(blob_path)
                    blob_path.unlink(missing_ok=True)
                else:
                    safe_make_readonly(blob_path)
                    return blob_path, sha256, sha512, size_bytes
            except Exception:
                safe_make_writable(blob_path)
                blob_path.unlink(missing_ok=True)

        temp_dest = shard_dir / f"{sha256}.tmp_{uuid4().hex}"
        try:
            with open(temp_dest, "wb") as f:
                f.write(data)
            v_sha256, v_sha512, v_size = compute_stream_hashes(temp_dest)
            if v_sha256.lower() != sha256.lower() or v_sha512.lower() != sha512.lower() or v_size != size_bytes:
                raise VaultIntegrityError(f"Post-write integrity check failed for byte blob {sha256}")
            safe_make_readonly(temp_dest)
            os.replace(temp_dest, blob_path)
        except Exception as e:
            if temp_dest.exists():
                safe_make_writable(temp_dest)
                temp_dest.unlink(missing_ok=True)
            raise VaultIntegrityError(f"Failed to store blob bytes: {e}") from e

        return blob_path, sha256, sha512, size_bytes

    # --------------------------------------------------------------------------
    # Layer 4: Zero-Copy Read-Only Reference (:ro)
    # --------------------------------------------------------------------------
    def register_zero_copy_reference(
        self,
        case_id: str,
        file_path: Union[str, Path],
        artifact_type: str = "disk_image",
        actor: str = "analyst",
        original_name: Optional[str] = None,
    ) -> ArtifactRecord:
        """Register large external disk/VM images in place without copying to system drive."""
        self._verify_case_match(case_id)
        resolved_path = validate_evidence_path(file_path)

        # Stream hashes in userspace without OS kernel mounting
        sha256, sha512, size_bytes = compute_stream_hashes(resolved_path)
        # SEC-CUST-001: Write-protect source evidence at rest on filesystem
        safe_make_readonly(resolved_path)
        blob_path = f":ro:{resolved_path}"
        effective_name = original_name or resolved_path.name

        custody_entry = self.append_custody_entry(
            case_id=case_id,
            actor=actor,
            action="ZERO_COPY_REFERENCE",
            artifact_sha256=sha256,
            tool_id="dissect_userspace_stream",
        )

        record = ArtifactRecord(
            artifact_id=str(uuid4()),
            case_id=case_id,
            type=artifact_type,
            original_path=str(resolved_path),
            blob_path=blob_path,
            size_bytes=size_bytes,
            sha256=sha256,
            sha512=sha512,
            acquired_utc=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            acquisition_method="zero_copy_reference",
            original_name=effective_name,
            actor=actor,
            custody_seq_id=custody_entry.seq_id,
            verification_status="VERIFIED",
        )

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO artifacts (
                    artifact_id, case_id, type, original_path, blob_path,
                    size_bytes, sha256, sha512, acquired_utc, acquisition_method,
                    original_name, actor, custody_seq_id, verification_status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.artifact_id,
                    record.case_id,
                    record.type,
                    record.original_path,
                    record.blob_path,
                    record.size_bytes,
                    record.sha256,
                    record.sha512,
                    record.acquired_utc,
                    record.acquisition_method,
                    record.original_name,
                    record.actor,
                    record.custody_seq_id,
                    record.verification_status,
                ),
            )

        self._write_audit_log(
            case_id=case_id,
            actor=actor,
            action="ZERO_COPY_REFERENCE",
            details={
                "artifact_id": record.artifact_id,
                "original_path": str(resolved_path),
                "sha256": sha256,
                "size_bytes": size_bytes,
                "custody_seq_id": custody_entry.seq_id,
            },
        )

        return record

    # --------------------------------------------------------------------------
    # Direct Ingestion & Defanging
    # --------------------------------------------------------------------------
    def ingest_artifact(
        self,
        case_id: str,
        source_path: Union[str, Path],
        artifact_type: str,
        actor: str = "analyst",
        original_source: Optional[str] = None,
        original_name: Optional[str] = None,
    ) -> ArtifactRecord:
        """Ingest a standalone forensic file, defang it into the blob vault, and log custody."""
        self._verify_case_match(case_id)
        source_path = Path(source_path).resolve()
        blob_path, sha256, sha512, size_bytes = self.store_in_blob_vault(source_path)

        rel_blob_path = str(blob_path.relative_to(self.vault_root)).replace("\\", "/")
        effective_name = original_name or source_path.name

        custody_entry = self.append_custody_entry(
            case_id=case_id,
            actor=actor,
            action="INGEST_ARTIFACT",
            artifact_sha256=sha256,
            tool_id="vault_defanger",
        )

        record = ArtifactRecord(
            artifact_id=str(uuid4()),
            case_id=case_id,
            type=artifact_type,
            original_path=original_source or str(source_path),
            blob_path=rel_blob_path,
            size_bytes=size_bytes,
            sha256=sha256,
            sha512=sha512,
            acquired_utc=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            acquisition_method="offline_upload",
            original_name=effective_name,
            actor=actor,
            custody_seq_id=custody_entry.seq_id,
            verification_status="VERIFIED",
        )

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO artifacts (
                    artifact_id, case_id, type, original_path, blob_path,
                    size_bytes, sha256, sha512, acquired_utc, acquisition_method,
                    original_name, actor, custody_seq_id, verification_status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.artifact_id,
                    record.case_id,
                    record.type,
                    record.original_path,
                    record.blob_path,
                    record.size_bytes,
                    record.sha256,
                    record.sha512,
                    record.acquired_utc,
                    record.acquisition_method,
                    record.original_name,
                    record.actor,
                    record.custody_seq_id,
                    record.verification_status,
                ),
            )

        self._write_audit_log(
            case_id=case_id,
            actor=actor,
            action="INGEST_ARTIFACT",
            details={
                "artifact_id": record.artifact_id,
                "original_path": record.original_path,
                "blob_path": record.blob_path,
                "sha256": sha256,
                "size_bytes": size_bytes,
                "custody_seq_id": custody_entry.seq_id,
            },
        )

        return record

    # --------------------------------------------------------------------------
    # Collector Capsule Unpacker & Dual-Hash Validator
    # --------------------------------------------------------------------------
    def unpack_collector_capsule(
        self,
        capsule_path: Optional[Union[str, Path]] = None,
        case_id: Optional[str] = None,
        actor: str = "analyst",
        *,
        capsule_zip_path: Optional[Union[str, Path]] = None,
    ) -> List[ArtifactRecord]:
        """Safely unpack an endpoint collector capsule, validating dual hashes against manifest.json."""
        target_path = capsule_path if capsule_path is not None else capsule_zip_path
        if target_path is None:
            raise ForensicOpsError("capsule_path must be provided to unpack_collector_capsule")
        capsule_path = Path(target_path).resolve()
        if not capsule_path.is_file():
            raise ForensicOpsError(f"Capsule file not found: {capsule_path}")

        if self.case_id and case_id and case_id != self.case_id:
            raise ForensicOpsError(
                f"CustodyEngine bound to case '{self.case_id}' cannot unpack capsule for mismatched case '{case_id}'"
            )

        temp_extract_dir = Path(tempfile.mkdtemp(prefix="forensicops_capsule_"))
        try:
            # 1. Extract safely via Streaming Zip Guard
            self.safe_extract_archive(capsule_path, temp_extract_dir)

            # 2. Locate manifest.json
            manifest_candidates = list(temp_extract_dir.glob("**/manifest.json"))
            if not manifest_candidates:
                raise ForensicOpsError("Collector capsule does not contain manifest.json")

            manifest_file = manifest_candidates[0]
            capsule_base_dir = manifest_file.parent

            with open(manifest_file, "r", encoding="utf-8") as f:
                manifest_data = json.load(f)

            manifest = CapsuleManifest.model_validate(manifest_data)
            effective_case_id = case_id or self.case_id or manifest.case_id
            if not effective_case_id:
                raise ForensicOpsError("No case_id could be determined for collector capsule")

            # Manifest declared case_id must match effective_case_id if manifest specifies it
            if self.case_id and manifest.case_id and manifest.case_id != self.case_id:
                raise ForensicOpsError(
                    f"Capsule manifest declared case '{manifest.case_id}' does not match CustodyEngine case '{self.case_id}'"
                )
            if case_id and manifest.case_id and manifest.case_id != case_id:
                raise ForensicOpsError(
                    f"Capsule manifest declared case '{manifest.case_id}' does not match destination case '{case_id}'"
                )

            # Log intake of capsule container itself
            capsule_sha256, capsule_sha512, _ = compute_stream_hashes(capsule_path)
            self.append_custody_entry(
                case_id=effective_case_id,
                actor=actor,
                action="INTAKE_CAPSULE",
                artifact_sha256=capsule_sha256,
                tool_id="collector_unpacker",
            )

            results: List[ArtifactRecord] = []

            # 3. Validate every declared artifact against SHA-256 and SHA-512
            for item in manifest.artifacts:
                rel_path = item.bundle_path.replace("\\", "/").lstrip("/")
                item_file = (capsule_base_dir / rel_path).resolve()

                if not item_file.is_relative_to(capsule_base_dir.resolve()):
                    raise SuspiciousArchiveError(
                        f"Path traversal detected in capsule manifest bundle_path: '{item.bundle_path}' attempts to escape archive root"
                    )

                if not item_file.is_file():
                    raise ForensicOpsError(
                        f"Capsule manifest declared artifact not found in archive: {item.bundle_path}"
                    )

                computed_sha256, computed_sha512, computed_size = compute_stream_hashes(item_file)

                # Strict cryptographic match
                if computed_sha256.lower() != item.sha256.lower():
                    raise HashMismatchError(
                        f"SHA-256 mismatch for {item.bundle_path}: manifest={item.sha256}, computed={computed_sha256}"
                    )
                if computed_sha512.lower() != item.sha512.lower():
                    raise HashMismatchError(
                        f"SHA-512 mismatch for {item.bundle_path}: manifest={item.sha512}, computed={computed_sha512}"
                    )

                # 4. Defang and store in vault
                blob_path, _, _, _ = self.store_in_blob_vault(item_file)
                rel_blob_path = str(blob_path.relative_to(self.vault_root)).replace("\\", "/")

                custody_entry = self.append_custody_entry(
                    case_id=effective_case_id,
                    actor=actor,
                    action="INTAKE_CAPSULE_ARTIFACT",
                    artifact_sha256=computed_sha256,
                    tool_id="collector_unpacker",
                )

                record = ArtifactRecord(
                    artifact_id=item.artifact_id,
                    case_id=effective_case_id,
                    type=item.type,
                    original_path=item.original_path,
                    blob_path=rel_blob_path,
                    size_bytes=computed_size,
                    sha256=computed_sha256,
                    sha512=computed_sha512,
                    acquired_utc=item.acquired_utc,
                    acquisition_method=item.acquisition_method or "collector_capsule",
                    original_name=Path(item.bundle_path).name,
                    actor=actor,
                    custody_seq_id=custody_entry.seq_id,
                    verification_status="VERIFIED",
                )

                with self._get_connection() as conn:
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO artifacts (
                            artifact_id, case_id, type, original_path, blob_path,
                            size_bytes, sha256, sha512, acquired_utc, acquisition_method,
                            original_name, actor, custody_seq_id, verification_status
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            record.artifact_id,
                            record.case_id,
                            record.type,
                            record.original_path,
                            record.blob_path,
                            record.size_bytes,
                            record.sha256,
                            record.sha512,
                            record.acquired_utc,
                            record.acquisition_method,
                            record.original_name,
                            record.actor,
                            record.custody_seq_id,
                            record.verification_status,
                        ),
                    )

                self._write_audit_log(
                    case_id=effective_case_id,
                    actor=actor,
                    action="INTAKE_CAPSULE_ARTIFACT",
                    details={
                        "artifact_id": record.artifact_id,
                        "bundle_path": item.bundle_path,
                        "sha256": computed_sha256,
                        "size_bytes": computed_size,
                        "custody_seq_id": custody_entry.seq_id,
                    },
                )

                results.append(record)

            return results

        finally:
            # Clean up temporary uncompressed files
            try:
                for root, dirs, files in os.walk(temp_extract_dir):
                    for f in files:
                        safe_make_writable(Path(root) / f)
                shutil.rmtree(temp_extract_dir, ignore_errors=True)
            except Exception:
                pass

    # --------------------------------------------------------------------------
    # Layer 5: Append-Only Hash-Chained Custody Ledger & Tamper Detection
    # --------------------------------------------------------------------------
    def append_custody_entry(
        self,
        case_id: str,
        actor: str,
        action: str,
        artifact_sha256: Optional[str] = None,
        tool_id: Optional[str] = None,
    ) -> CustodyChainEntry:
        """Atomically append a cryptographically linked custody record to the ledger."""
        self._verify_case_match(case_id)
        timestamp_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        with self._get_connection() as conn:
            # Lock table with immediate transaction for consistency
            conn.execute("BEGIN IMMEDIATE;")

            cur = conn.execute("SELECT seq_id, entry_hash FROM custody_chain ORDER BY seq_id DESC LIMIT 1;")
            last_row = cur.fetchone()

            if last_row is None:
                next_seq = 1
                prev_hash = GENESIS_HASH
            else:
                next_seq = last_row["seq_id"] + 1
                prev_hash = last_row["entry_hash"]

            payload = {
                "seq_id": next_seq,
                "case_id": case_id,
                "timestamp_utc": timestamp_utc,
                "actor": actor,
                "action": action,
                "artifact_sha256": artifact_sha256,
                "tool_id": tool_id,
            }
            entry_hash = CustodyChainEntry.calculate_entry_hash(prev_hash, payload)

            entry = CustodyChainEntry(
                seq_id=next_seq,
                case_id=case_id,
                timestamp_utc=timestamp_utc,
                actor=actor,
                action=action,
                artifact_sha256=artifact_sha256,
                tool_id=tool_id,
                prev_hash=prev_hash,
                entry_hash=entry_hash,
            )

            conn.execute(
                """
                INSERT INTO custody_chain (
                    seq_id, case_id, timestamp_utc, actor, action,
                    artifact_sha256, tool_id, prev_hash, entry_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry.seq_id,
                    entry.case_id,
                    entry.timestamp_utc,
                    entry.actor,
                    entry.action,
                    entry.artifact_sha256,
                    entry.tool_id,
                    entry.prev_hash,
                    entry.entry_hash,
                ),
            )
            conn.commit()

        return entry

    def get_custody_chain(self, case_id: Optional[str] = None) -> List[CustodyChainEntry]:
        """Retrieve all custody chain entries in sequential order."""
        with self._get_connection() as conn:
            if case_id:
                cur = conn.execute(
                    "SELECT * FROM custody_chain WHERE case_id = ? ORDER BY seq_id ASC;", (case_id,)
                )
            else:
                cur = conn.execute("SELECT * FROM custody_chain ORDER BY seq_id ASC;")
            rows = cur.fetchall()

        return [
            CustodyChainEntry(
                seq_id=row["seq_id"],
                case_id=row["case_id"],
                timestamp_utc=row["timestamp_utc"],
                actor=row["actor"],
                action=row["action"],
                artifact_sha256=row["artifact_sha256"],
                tool_id=row["tool_id"],
                prev_hash=row["prev_hash"],
                entry_hash=row["entry_hash"],
            )
            for row in rows
        ]

    def verify_chain_integrity(self, case_id: Optional[str] = None) -> Tuple[bool, List[str]]:
        """Verify complete cryptographic integrity of the entire chain from genesis to head."""
        effective_case_id = case_id or self.case_id
        if self.case_id and case_id and case_id != self.case_id:
            raise ForensicOpsError(
                f"CustodyEngine bound to case '{self.case_id}' cannot verify mismatched case '{case_id}'"
            )

        entries = self.get_custody_chain(case_id=None)
        if not entries:
            return True, []

        errors: List[str] = []
        expected_prev = GENESIS_HASH

        for idx, entry in enumerate(entries):
            # Check cross-case consistency when effective_case_id is supplied
            if effective_case_id and entry.case_id != effective_case_id:
                errors.append(
                    f"Cross-case contamination at seq_id {entry.seq_id}: entry.case_id='{entry.case_id}' != expected='{effective_case_id}'"
                )

            # Check seq_id sequence
            expected_seq = idx + 1
            if entry.seq_id != expected_seq:
                errors.append(f"Sequence break: entry {entry.seq_id} found at index {expected_seq}")

            # Check previous hash link
            if entry.prev_hash.lower() != expected_prev.lower():
                errors.append(
                    f"Chain break at seq_id {entry.seq_id}: prev_hash={entry.prev_hash} != expected={expected_prev}"
                )

            # Check self-hash calculation
            if not entry.verify_hash():
                computed = CustodyChainEntry.calculate_entry_hash(entry.prev_hash, entry.payload_dict())
                errors.append(
                    f"Tamper detected at seq_id {entry.seq_id}: entry_hash={entry.entry_hash} != computed={computed}"
                )

            expected_prev = entry.entry_hash

        return len(errors) == 0, errors

    def get_artifacts(self, case_id: Optional[str] = None) -> List[ArtifactRecord]:
        """Retrieve registered artifacts."""
        effective_case_id = case_id or self.case_id
        with self._get_connection() as conn:
            if effective_case_id:
                cur = conn.execute("SELECT * FROM artifacts WHERE case_id = ?;", (effective_case_id,))
            else:
                cur = conn.execute("SELECT * FROM artifacts;")
            rows = cur.fetchall()

        return [
            ArtifactRecord(
                artifact_id=row["artifact_id"],
                case_id=row["case_id"],
                type=row["type"],
                original_path=row["original_path"],
                blob_path=row["blob_path"],
                size_bytes=row["size_bytes"],
                sha256=row["sha256"],
                sha512=row["sha512"],
                acquired_utc=row["acquired_utc"],
                acquisition_method=row["acquisition_method"],
                original_name=row["original_name"] if "original_name" in row.keys() else None,
                actor=row["actor"] if "actor" in row.keys() else None,
                custody_seq_id=row["custody_seq_id"] if "custody_seq_id" in row.keys() else None,
                verification_status=row["verification_status"] if ("verification_status" in row.keys() and row["verification_status"]) else "VERIFIED",
            )
            for row in rows
        ]

    def get_artifact(self, artifact_id: str, case_id: Optional[str] = None) -> Optional[ArtifactRecord]:
        """Retrieve an individual ArtifactRecord by artifact_id, optionally filtered by case_id."""
        artifacts = self.get_artifacts(case_id=case_id)
        for a in artifacts:
            if a.artifact_id == artifact_id:
                return a
        return None

    def resolve_artifact_file(self, artifact: ArtifactRecord) -> Path:
        """Resolve absolute filesystem path for an ArtifactRecord (blob or :ro reference)."""
        if artifact.blob_path.startswith(":ro:"):
            return Path(artifact.blob_path[4:]).resolve()
        p = self.vault_root / artifact.blob_path
        if p.exists():
            return p.resolve()
        p2 = self.blobs_dir / artifact.blob_path
        if p2.exists():
            return p2.resolve()
        return p.resolve()

    def verify_artifact_integrity(self, artifact: ArtifactRecord) -> bool:
        """Verify that stored blob or zero-copy file matches artifact record SHA-256, SHA-512, and size."""
        target_file = self.resolve_artifact_file(artifact)
        if not target_file.exists() or not target_file.is_file():
            return False
        c_sha256, c_sha512, c_size = compute_stream_hashes(target_file)
        return (
            c_sha256.lower() == artifact.sha256.lower()
            and c_sha512.lower() == artifact.sha512.lower()
            and c_size == artifact.size_bytes
        )

    def defang_and_store_blob(
        self,
        source_file_path: Union[str, Path],
        case_id: str,
        artifact_type: str = "file",
        actor: str = "analyst",
        acquisition_method: str = "offline_upload",
    ) -> ArtifactRecord:
        """Alias for ingest_artifact for backward compatibility."""
        return self.ingest_artifact(
            case_id=case_id,
            source_path=source_file_path,
            artifact_type=artifact_type,
            actor=actor,
        )

    def store_raw_bytes(
        self,
        raw_bytes: bytes,
        case_id: str,
        original_filename: str = "uploaded.bin",
        artifact_type: str = "file",
        acquisition_method: str = "offline_upload",
        actor: str = "analyst",
    ) -> ArtifactRecord:
        """Store raw bytes into the defanged .blob vault and log custody."""
        self._verify_case_match(case_id)
        blob_path, sha256, sha512, size_bytes = self.store_bytes_in_blob_vault(raw_bytes)
        rel_blob_path = str(blob_path.relative_to(self.vault_root)).replace("\\", "/")

        custody_entry = self.append_custody_entry(
            case_id=case_id,
            actor=actor,
            action="INGEST_RAW_BYTES",
            artifact_sha256=sha256,
            tool_id="vault_defanger",
        )

        record = ArtifactRecord(
            artifact_id=str(uuid4()),
            case_id=case_id,
            type=artifact_type,
            original_path=original_filename,
            blob_path=rel_blob_path,
            size_bytes=size_bytes,
            sha256=sha256,
            sha512=sha512,
            acquired_utc=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            acquisition_method=acquisition_method,
            original_name=original_filename,
            actor=actor,
            custody_seq_id=custody_entry.seq_id,
            verification_status="VERIFIED",
        )

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO artifacts (
                    artifact_id, case_id, type, original_path, blob_path,
                    size_bytes, sha256, sha512, acquired_utc, acquisition_method,
                    original_name, actor, custody_seq_id, verification_status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.artifact_id,
                    record.case_id,
                    record.type,
                    record.original_path,
                    record.blob_path,
                    record.size_bytes,
                    record.sha256,
                    record.sha512,
                    record.acquired_utc,
                    record.acquisition_method,
                    record.original_name,
                    record.actor,
                    record.custody_seq_id,
                    record.verification_status,
                ),
            )

        return record

    def verify_chain(self, case_id: Optional[str] = None) -> bool:
        """Verify chain integrity returning boolean."""
        passed, _ = self.verify_chain_integrity(case_id=case_id)
        return passed

    @staticmethod
    def compute_execution_key(
        case_id: str,
        artifact_hash: str,
        tool_id: str,
        tool_version: str,
        parameters: Optional[Union[Dict[str, Any], List[str], str]] = None,
    ) -> str:
        """Compute deterministic execution key for idempotency."""
        params_str = ""
        if isinstance(parameters, dict):
            params_str = json.dumps(parameters, sort_keys=True)
        elif isinstance(parameters, (list, tuple)):
            params_str = json.dumps(list(parameters))
        elif parameters:
            params_str = str(parameters)
        raw = f"{case_id}:{artifact_hash}:{tool_id}:{tool_version}:{params_str}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def get_tool_execution(self, execution_key: str) -> Optional[Dict[str, Any]]:
        """Retrieve existing tool execution record by deterministic execution key."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM tool_executions WHERE execution_key = ? LIMIT 1;",
                (execution_key,),
            ).fetchone()
            if not row:
                return None
            return dict(row)

    def record_tool_execution(
        self,
        execution_id: str,
        execution_key: str,
        case_id: str,
        artifact_id: str,
        artifact_sha256: str,
        tool_id: str,
        tool_version: str,
        status: str,
        started_at_utc: str,
        finished_at_utc: Optional[str] = None,
        findings_count: int = 0,
        raw_output_path: Optional[str] = None,
        parameters: Optional[Union[Dict[str, Any], List[str], str]] = None,
        warnings: Optional[List[str]] = None,
        errors: Optional[List[str]] = None,
    ) -> None:
        """Record or update a deterministic tool execution result in SQLite custody database."""
        self._verify_case_match(case_id)
        params_str = json.dumps(parameters) if isinstance(parameters, (dict, list)) else (str(parameters) if parameters else "")
        warn_str = json.dumps(warnings) if warnings else ""
        err_str = json.dumps(errors) if errors else ""

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO tool_executions (
                    execution_id, execution_key, case_id, artifact_id, artifact_sha256,
                    tool_id, tool_version, status, started_at_utc, finished_at_utc,
                    findings_count, raw_output_path, parameters, warnings, errors
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    execution_id, execution_key, case_id, artifact_id, artifact_sha256,
                    tool_id, tool_version, status, started_at_utc, finished_at_utc,
                    findings_count, raw_output_path, params_str, warn_str, err_str
                ),
            )
            conn.commit()
