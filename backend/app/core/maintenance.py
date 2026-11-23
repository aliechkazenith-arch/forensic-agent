"""Database Backup, Recovery, and Retention Maintenance Procedures.

Standards:
- Crash-Consistent SQLite Online Backup API (zero locking of concurrent readers).
- SHA-256 Digest Verification of Backup Artifacts.
- Retention & Cleanup Policies for Expired Sessions & Temporary Staging Archives.
- Storage Health & Resource Metrics.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
from typing import Any, Dict, List, Optional, Tuple

from backend.app.core.config import get_settings
from backend.app.core.custody_engine import compute_stream_hashes
from backend.app.db.sqlite_store import get_llm_state_store


def backup_database(
    source_db_path: Optional[Path] = None,
    backup_dest_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """Perform online crash-consistent backup of a SQLite database using the SQLite Backup API.
    
    Guarantees consistent, non-corrupt snapshot without stopping active readers or writers.
    Computes cryptographic SHA-256 digest of the backup file.
    """
    settings = get_settings()
    store = get_llm_state_store()

    source_path = source_db_path or store.db_path
    if not source_path.is_file():
        raise FileNotFoundError(f"Source database file not found: {source_path}")

    target_dir = backup_dest_dir or Path(settings.vault_dir) / "backups"
    target_dir.mkdir(parents=True, exist_ok=True)

    timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    backup_filename = f"{source_path.stem}_backup_{timestamp_str}.db"
    backup_path = target_dir / backup_filename

    # Perform online backup
    src_conn = sqlite3.connect(str(source_path))
    dst_conn = sqlite3.connect(str(backup_path))
    try:
        with dst_conn:
            src_conn.backup(dst_conn, pages=100)
    finally:
        dst_conn.close()
        src_conn.close()

    # Verify integrity of backup copy
    verify_conn = sqlite3.connect(str(backup_path))
    try:
        cursor = verify_conn.execute("PRAGMA integrity_check;")
        res = cursor.fetchone()
        integrity_ok = res and res[0] == "ok"
    finally:
        verify_conn.close()

    if not integrity_ok:
        if backup_path.exists():
            backup_path.unlink()
        raise ValueError(f"SQLite integrity check failed on generated backup '{backup_path}'.")

    sha256, sha512, size_bytes = compute_stream_hashes(backup_path)

    return {
        "status": "success",
        "source_db": str(source_path),
        "backup_path": str(backup_path),
        "backup_sha256": sha256,
        "backup_sha512": sha512,
        "size_bytes": size_bytes,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "integrity_verified": integrity_ok,
    }


def verify_and_restore_backup(
    backup_path: Path,
    target_db_path: Path,
    expected_sha256: Optional[str] = None,
) -> bool:
    """Verify cryptographic hash and SQLite integrity before restoring a database."""
    if not backup_path.is_file():
        raise FileNotFoundError(f"Backup file not found: {backup_path}")

    # Hash check
    if expected_sha256:
        sha256, _, _ = compute_stream_hashes(backup_path)
        if sha256.lower() != expected_sha256.strip().lower():
            raise ValueError(f"Backup hash mismatch: expected {expected_sha256}, got {sha256}")

    # Integrity check
    conn = sqlite3.connect(str(backup_path))
    try:
        res = conn.execute("PRAGMA integrity_check;").fetchone()
        if not res or res[0] != "ok":
            raise ValueError(f"Backup integrity verification failed: {res}")
    finally:
        conn.close()

    # Atomic restore via SQLite backup
    target_db_path.parent.mkdir(parents=True, exist_ok=True)
    src_conn = sqlite3.connect(str(backup_path))
    dst_conn = sqlite3.connect(str(target_db_path))
    try:
        with dst_conn:
            src_conn.backup(dst_conn, pages=100)
    finally:
        dst_conn.close()
        src_conn.close()

    return True


def cleanup_temporary_staging(
    staging_root: Optional[Path] = None,
    max_age_hours: int = 24,
) -> int:
    """Clean up orphaned temporary intake extraction folders and staging directories."""
    cleaned_count = 0
    cutoff = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)
    cutoff_timestamp = cutoff.timestamp()

    temp_dir = staging_root or Path(tempfile.gettempdir())
    for item in temp_dir.glob("forensicops_*"):
        try:
            mtime = item.stat().st_mtime
            if mtime < cutoff_timestamp:
                if item.is_dir():
                    shutil.rmtree(item, ignore_errors=True)
                elif item.is_file():
                    item.unlink()
                cleaned_count += 1
        except Exception:
            pass

    return cleaned_count


def get_health_metrics() -> Dict[str, Any]:
    """Collect runtime health, storage metrics, and resource availability."""
    settings = get_settings()
    vault_path = Path(settings.vault_dir)

    vault_exists = vault_path.exists()
    vault_writable = False
    blob_count = 0
    total_vault_bytes = 0

    if vault_exists:
        try:
            test_file = vault_path / f".write_test_{os.getpid()}"
            test_file.write_text("ok")
            test_file.unlink()
            vault_writable = True
        except Exception:
            vault_writable = False

        blobs_dir = vault_path / "blobs"
        if blobs_dir.exists():
            for p in blobs_dir.glob("*.blob"):
                blob_count += 1
                try:
                    total_vault_bytes += p.stat().st_size
                except Exception:
                    pass

    # SQLite store check
    store = get_llm_state_store()
    db_ok = False
    try:
        res = store._conn.execute("SELECT 1;").fetchone()
        db_ok = res is not None and res[0] == 1
    except Exception:
        db_ok = False

    return {
        "status": "healthy" if (vault_writable and db_ok) else "degraded",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "database_accessible": db_ok,
        "vault_accessible": vault_exists,
        "vault_writable": vault_writable,
        "vault_blob_count": blob_count,
        "vault_total_bytes": total_vault_bytes,
        "evidence_roots": settings.evidence_allowlist_dirs.split(","),
    }
