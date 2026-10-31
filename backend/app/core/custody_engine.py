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

    def __init__(self, vault_root: Union[str, Path], db_path: Optional[Union[str, Path]] = None):
        self.vault_root = Path(vault_root).resolve()
        self.blobs_dir = self.vault_root / "blobs"
        self.blobs_dir.mkdir(parents=True, exist_ok=True)

        self.db_path = Path(db_path).resolve() if db_path else self.vault_root / "custody.db"
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self.audit_log_path = self.vault_root / "audit.jsonl"
        self._init_database()

    def _get_connection(self) -> sqlite3.Connection:
        """Create a database connection with WAL mode and row factory."""
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_database(self) -> None:
        """Initialize append-only SQLite custody ledger schema."""
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
                    acquisition_method TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_custody_case ON custody_chain(case_id);
                CREATE INDEX IF NOT EXISTS idx_custody_seq ON custody_chain(seq_id);
                CREATE INDEX IF NOT EXISTS idx_artifacts_case ON artifacts(case_id);
                CREATE INDEX IF NOT EXISTS idx_artifacts_sha256 ON artifacts(sha256);
            """)

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
        max_ratio: float = 100.0,
        max_single_size_bytes: int = 5 * 1024 * 1024 * 1024,  # 5 GB
        max_total_size_bytes: int = 20 * 1024 * 1024 * 1024,  # 20 GB
    ) -> List[Path]:
        """Safely extract zip/tar archives with strict Zip Slip, symlink, and zip bomb guards."""
        archive_path = Path(archive_path).resolve()
        extract_to = Path(extract_to).resolve()
        extract_to.mkdir(parents=True, exist_ok=True)

        if zipfile.is_zipfile(archive_path):
            return self._safe_extract_zip(
                archive_path, extract_to, max_ratio, max_single_size_bytes, max_total_size_bytes
            )
        elif tarfile.is_tarfile(archive_path):
            return self._safe_extract_tar(
                archive_path, extract_to, max_ratio, max_single_size_bytes, max_total_size_bytes
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
    ) -> List[Path]:
        extracted_paths: List[Path] = []
        total_extracted_bytes = 0

        with zipfile.ZipFile(archive_path, "r") as zf:
            members = zf.infolist()
            # 1. Total pre-check
            declared_total = sum(m.file_size for m in members)
            if declared_total > max_total_size_bytes:
                raise DecompressionBombError(
                    f"Declared uncompressed size {declared_total} exceeds maximum limit {max_total_size_bytes}"
                )

            for member in members:
                # 2. Check Zip Slip path traversal
                raw_filename = member.filename
                # Strip leading slashes and drive letters
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
                    # Target destination must strictly be inside extract_to
                    target_dest.relative_to(extract_to)
                except ValueError as e:
                    raise ZipSlipError(f"Zip Slip escape outside root: {raw_filename}") from e

                # 3. Check for symlinks in zip external attributes
                # High 16 bits contain Unix file mode bits. S_IFLNK is 0o120000.
                unix_mode = member.external_attr >> 16
                if unix_mode and stat.S_ISLNK(unix_mode):
                    raise SuspiciousArchiveError(f"Archive symlink prohibited: {raw_filename}")

                # 4. Check single file ratio / bomb
                if member.compress_size > 0:
                    ratio = member.file_size / member.compress_size
                    # Only enforce ratio if uncompressed size is non-trivial (> 1 MB)
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

                # 5. Streaming extraction with byte tracking
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

                extracted_paths.append(target_dest)

        return extracted_paths

    def _safe_extract_tar(
        self,
        archive_path: Path,
        extract_to: Path,
        max_ratio: float,
        max_single_size_bytes: int,
        max_total_size_bytes: int,
    ) -> List[Path]:
        extracted_paths: List[Path] = []
        total_extracted_bytes = 0

        with tarfile.open(archive_path, "r:*") as tf:
            for member in tf.getmembers():
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
                        f"Tar member {member.name} size {member.size} exceeds single limit"
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

                extracted_paths.append(target_dest)

        return extracted_paths

    # --------------------------------------------------------------------------
    # Layer 2: Defanged .blob Vault Storage
    # --------------------------------------------------------------------------
    def store_in_blob_vault(self, source_path: Union[str, Path]) -> Tuple[Path, str, str, int]:
        """Store an evidence file into the defanged .blob vault with read-only permissions."""
        source_path = Path(source_path).resolve()
        if not source_path.is_file():
            raise ForensicOpsError(f"Source file does not exist: {source_path}")

        sha256, sha512, size_bytes = compute_stream_hashes(source_path)
        shard_dir = self.blobs_dir / sha256[:2]
        shard_dir.mkdir(parents=True, exist_ok=True)
        blob_path = shard_dir / f"{sha256}.blob"

        if blob_path.exists():
            # Already exists in vault, ensure it is read-only
            safe_make_readonly(blob_path)
            return blob_path, sha256, sha512, size_bytes

        # If not present, copy to a temp file in the shard and atomically rename
        temp_dest = shard_dir / f"{sha256}.tmp_{uuid4().hex}"
        try:
            shutil.copyfile(source_path, temp_dest)
            safe_make_readonly(temp_dest)
            os.replace(temp_dest, blob_path)
        except Exception as e:
            if temp_dest.exists():
                safe_make_writable(temp_dest)
                temp_dest.unlink(missing_ok=True)
            raise VaultIntegrityError(f"Failed to store blob {sha256}: {e}") from e

        return blob_path, sha256, sha512, size_bytes

    def store_bytes_in_blob_vault(self, data: bytes) -> Tuple[Path, str, str, int]:
        """Store raw bytes directly into the defanged .blob vault."""
        sha256, sha512, size_bytes = compute_bytes_hashes(data)
        shard_dir = self.blobs_dir / sha256[:2]
        shard_dir.mkdir(parents=True, exist_ok=True)
        blob_path = shard_dir / f"{sha256}.blob"

        if blob_path.exists():
            safe_make_readonly(blob_path)
            return blob_path, sha256, sha512, size_bytes

        temp_dest = shard_dir / f"{sha256}.tmp_{uuid4().hex}"
        try:
            with open(temp_dest, "wb") as f:
                f.write(data)
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
    ) -> ArtifactRecord:
        """Register large external disk/VM images in place without copying to system drive."""
        resolved_path = Path(file_path).resolve()
        if not resolved_path.exists():
            raise ForensicOpsError(f"Target file for zero-copy reference not found: {file_path}")

        # Stream hashes in userspace without OS kernel mounting
        sha256, sha512, size_bytes = compute_stream_hashes(resolved_path)
        blob_path = f":ro:{resolved_path}"

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
        )

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO artifacts (
                    artifact_id, case_id, type, original_path, blob_path,
                    size_bytes, sha256, sha512, acquired_utc, acquisition_method
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                ),
            )

        self.append_custody_entry(
            case_id=case_id,
            actor=actor,
            action="ZERO_COPY_REFERENCE",
            artifact_sha256=sha256,
            tool_id="dissect_userspace_stream",
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
    ) -> ArtifactRecord:
        """Ingest a standalone forensic file, defang it into the blob vault, and log custody."""
        source_path = Path(source_path).resolve()
        blob_path, sha256, sha512, size_bytes = self.store_in_blob_vault(source_path)

        rel_blob_path = str(blob_path.relative_to(self.vault_root)).replace("\\", "/")

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
        )

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO artifacts (
                    artifact_id, case_id, type, original_path, blob_path,
                    size_bytes, sha256, sha512, acquired_utc, acquisition_method
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                ),
            )

        self.append_custody_entry(
            case_id=case_id,
            actor=actor,
            action="INGEST_ARTIFACT",
            artifact_sha256=sha256,
            tool_id="vault_defanger",
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
            },
        )

        return record

    # --------------------------------------------------------------------------
    # Collector Capsule Unpacker & Dual-Hash Validator
    # --------------------------------------------------------------------------
    def unpack_collector_capsule(
        self,
        capsule_path: Union[str, Path],
        case_id: Optional[str] = None,
        actor: str = "analyst",
    ) -> List[ArtifactRecord]:
        """Safely unpack an endpoint collector capsule, validating dual hashes against manifest.json."""
        capsule_path = Path(capsule_path).resolve()
        if not capsule_path.is_file():
            raise ForensicOpsError(f"Capsule file not found: {capsule_path}")

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
            effective_case_id = case_id or manifest.case_id

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
                item_file = capsule_base_dir / rel_path

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
                )

                with self._get_connection() as conn:
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO artifacts (
                            artifact_id, case_id, type, original_path, blob_path,
                            size_bytes, sha256, sha512, acquired_utc, acquisition_method
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                        ),
                    )

                self.append_custody_entry(
                    case_id=effective_case_id,
                    actor=actor,
                    action="INTAKE_CAPSULE_ARTIFACT",
                    artifact_sha256=computed_sha256,
                    tool_id="collector_unpacker",
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

    def verify_chain_integrity(self) -> Tuple[bool, List[str]]:
        """Verify complete cryptographic integrity of the entire chain from genesis to head."""
        entries = self.get_custody_chain()
        if not entries:
            return True, []

        errors: List[str] = []
        expected_prev = GENESIS_HASH

        for idx, entry in enumerate(entries):
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
        with self._get_connection() as conn:
            if case_id:
                cur = conn.execute("SELECT * FROM artifacts WHERE case_id = ?;", (case_id,))
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
            )
            for row in rows
        ]
