"""Intake API Endpoints (Offline, Online Collector, Hybrid SIEM, Custody Ledger).

Standards:
- RFC 3227 & NIST SP 800-86
- 4-Layer Evidence Sandbox (Defanged .blob vault, 0400 permissions, zero kernel mounting)
- Human-in-the-Loop Gate (AGENTS.md Rule 4)
- Read-Only SIEM Query Ingestion with Canonical SHA-256 Hashing
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4
from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Response, UploadFile, status
from pydantic import BaseModel, Field

from backend.app.api.deps import (
    get_custody_engine,
    get_storage,
)
from backend.app.core.config import get_settings
from backend.app.core.custody_engine import (
    CustodyEngine,
    is_prohibited_system_directory,
    safe_make_readonly,
    safe_make_writable,
    validate_evidence_path,
)
from backend.app.connectors.siem_connectors import (
    ElasticsearchConnector,
    SplunkConnector,
    WazuhConnector,
    ingest_siem_query_findings,
)
from backend.app.core.dissect_adapter import DissectAdapter
from backend.app.core.exceptions import (
    DecompressionBombError,
    ForensicOpsError,
    HashMismatchError,
    ReadOnlyViolationError,
    SSRFSecurityError,
    SuspiciousArchiveError,
    UnauthorizedCollectorExecutionError,
    VaultIntegrityError,
    ZipSlipError,
)
from backend.app.core.storage import ForensicStore
from backend.app.auth.dependencies import get_current_user, require_roles
from backend.app.auth.case_authorization import get_case_authorization_service
from backend.app.auth.models import UserRead
from backend.app.models.connectors import (
    SIEMConnectionConfig,
    SIEMQuerySnapshot,
)
from backend.app.models.custody import ArtifactRecord, CustodyChainEntry
from backend.app.models.findings import ForensicFinding
from backend.app.models.workflow import HumanApprovalToken

router = APIRouter(prefix="/api/intake", tags=["Intake & Custody"])


def validate_evidence_path_confinement(path_str: str) -> Path:
    """Validate that local evidence path is strictly confined to approved evidence roots."""
    try:
        return validate_evidence_path(path_str)
    except ForensicOpsError as e:
        msg = str(e)
        if "not found" in msg.lower():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=msg)
        if "directory" in msg.lower() and "file" in msg.lower():
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=msg)


class OfflineIntakeRequest(BaseModel):
    case_id: str = "default_case"
    evidence_path: Optional[str] = None  # File path or path with ':ro' for zero-copy
    artifact_type: str = "auto"
    raw_content_b64: Optional[str] = None
    filename: Optional[str] = "uploaded_evidence.bin"
    acquisition_method: str = "offline_intake"
    actor: str = "analyst"
    auto_index: bool = True


class OfflineIntakeResponse(BaseModel):
    status: str = "success"
    case_id: str
    artifacts: List[ArtifactRecord] = Field(default_factory=list)
    findings_indexed_count: int = 0
    custody_entries: List[CustodyChainEntry] = Field(default_factory=list)


class SIEMIntakeRequest(BaseModel):
    case_id: str = "default_case"
    config: Optional[SIEMConnectionConfig] = None
    connection_id: Optional[str] = None
    query: str
    limit: int = 100
    actor: str = "analyst"


class SIEMIntakeResponse(BaseModel):
    status: str = "success"
    case_id: str
    query_snapshot: SIEMQuerySnapshot
    findings_count: int
    findings: List[ForensicFinding] = Field(default_factory=list)


class CustodyLedgerResponse(BaseModel):
    case_id: str
    is_tamper_free: bool
    entry_count: int
    entries: List[CustodyChainEntry] = Field(default_factory=list)


class EvidenceUploadResponse(BaseModel):
    status: str = "success"
    upload_id: str
    filename: str
    file_path: str
    size_bytes: int
    sha256: str
    sha512: str
    detected_artifact_type: str
    uploaded_at_utc: str


class BrowseLocalItem(BaseModel):
    name: str
    path: str
    is_dir: bool
    size_bytes: int
    extension: str


class BrowseLocalRequest(BaseModel):
    current_path: Optional[str] = None
    open_dialog: bool = False
    filter_extensions: Optional[List[str]] = None


class BrowseLocalResponse(BaseModel):
    status: str = "success"
    current_path: str
    parent_path: Optional[str] = None
    selected_file: Optional[str] = None
    drives: List[str] = Field(default_factory=list)
    items: List[BrowseLocalItem] = Field(default_factory=list)


SAFE_EVIDENCE_EXTENSIONS = {
    ".evtx", ".pcap", ".pcapng", ".dmp", ".raw", ".lime", ".vmem",
    ".e01", ".vmdk", ".dd", ".img", ".zip", ".tar", ".gz", ".json", ".log", ".txt"
}


def sanitize_evidence_filename(raw_filename: str) -> str:
    """Sanitize uploaded evidence filename against directory traversal and illegal characters."""
    base = Path(raw_filename).name
    # Strip path separators, null bytes, control characters
    clean = re.sub(r'[\\/:\x00-\x1f*?"<>|]', "_", base).strip(" .")
    if not clean:
        clean = f"evidence_{uuid4().hex[:8]}.bin"
    if len(clean) > 120:
        ext = Path(clean).suffix
        clean = clean[: 120 - len(ext)] + ext
    return clean


def detect_artifact_type_from_name(filename: str) -> str:
    """Infer forensic artifact type from filename and extension."""
    ext = Path(filename).suffix.lower()
    name_lower = Path(filename).name.lower()
    if ext == ".evtx":
        return "evtx"
    if ext in (".pcap", ".pcapng"):
        return "pcap"
    if ext in (".dmp", ".raw", ".lime", ".vmem"):
        return "memory"
    if ext in (".e01", ".vmdk", ".dd", ".img"):
        return "disk_image"
    if ext in (".zip", ".tar", ".gz"):
        return "capsule"
    if ext == ".json":
        return "json_log"
    if ext in (".log", ".txt"):
        return "text_log"
    if ext in (".hiv", ".hve") or any(h in name_lower for h in ["system", "software", "sam", "security", "ntuser", "usrclass", "amcache", "bcd"]):
        return "registry"
    if ext == ".dat" and any(h in name_lower for h in ["ntuser", "usrclass"]):
        return "registry"
    return "file"


def _get_available_drives() -> List[str]:
    """Return available root drives on Windows or root on Unix."""
    if os.name == "nt":
        import string
        drives = []
        for letter in string.ascii_uppercase:
            drive = f"{letter}:\\"
            if Path(drive).exists():
                drives.append(drive)
        return drives
    return ["/"]


@router.post("/upload", response_model=EvidenceUploadResponse)
async def upload_evidence_artifact(
    file: UploadFile = File(...),
    case_id: str = Form("default_case"),
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst")),
) -> EvidenceUploadResponse:
    """Stream uploaded evidence in 1 MB chunks to backend/data/evidence_intake, compute hashes, and set read-only."""
    case_auth = get_case_authorization_service()
    from backend.app.db.sqlite_store import get_llm_state_store
    sqlite_store = get_llm_state_store()
    if sqlite_store.get_case(case_id):
        case_auth.verify_case_access(current_user, case_id, "write")
    else:
        case_auth.ensure_case_registered(case_id, current_user.username)

    intake_dir = Path("backend/data/evidence_intake").resolve()
    intake_dir.mkdir(parents=True, exist_ok=True)

    raw_filename = file.filename or "uploaded_artifact.bin"
    safe_name = sanitize_evidence_filename(raw_filename)
    timestamp_prefix = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    dest_file = intake_dir / f"{timestamp_prefix}_{safe_name}"

    # Path traversal protection
    try:
        resolved_dest = dest_file.resolve()
        if not resolved_dest.is_relative_to(intake_dir):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid filename: path traversal sequence detected",
            )
    except (ValueError, RuntimeError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid filename: path traversal sequence detected",
        )

    sha256_hasher = hashlib.sha256()
    sha512_hasher = hashlib.sha512()
    total_bytes = 0

    CHUNK_SIZE = 1024 * 1024  # 1 MB chunks
    settings = get_settings()
    max_bytes = settings.max_upload_size_bytes

    try:
        with open(dest_file, "wb") as f_out:
            while True:
                chunk = await file.read(CHUNK_SIZE)
                if not chunk:
                    break
                total_bytes += len(chunk)
                if total_bytes > max_bytes:
                    f_out.close()
                    safe_make_writable(dest_file)
                    dest_file.unlink(missing_ok=True)
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=f"Upload exceeded maximum allowed size of {max_bytes} bytes.",
                    )
                f_out.write(chunk)
                sha256_hasher.update(chunk)
                sha512_hasher.update(chunk)
    except HTTPException:
        raise
    except Exception as e:
        safe_make_writable(dest_file)
        dest_file.unlink(missing_ok=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to process upload stream: {e}",
        )

    safe_make_readonly(dest_file)

    sha256_hex = sha256_hasher.hexdigest()
    sha512_hex = sha512_hasher.hexdigest()
    artifact_type = detect_artifact_type_from_name(safe_name)
    upload_id = f"upl-{uuid4().hex[:12]}"
    now_utc = datetime.now(timezone.utc).isoformat()

    # Record in SQLite store
    from backend.app.db.sqlite_store import get_llm_state_store
    store = get_llm_state_store()
    store.record_evidence_upload(
        upload_id=upload_id,
        filename=safe_name,
        stored_path=str(dest_file.resolve()),
        size_bytes=total_bytes,
        sha256=sha256_hex,
        sha512=sha512_hex,
        artifact_type=artifact_type,
    )

    return EvidenceUploadResponse(
        status="success",
        upload_id=upload_id,
        filename=safe_name,
        file_path=str(dest_file.resolve()),
        size_bytes=total_bytes,
        sha256=sha256_hex,
        sha512=sha512_hex,
        detected_artifact_type=artifact_type,
        uploaded_at_utc=now_utc,
    )


def is_prohibited_system_directory(p: Path) -> bool:
    """Check if target path is within sensitive OS system directories."""
    resolved = p.resolve()
    # Windows system directories
    sys_root = os.environ.get("SystemRoot")
    if sys_root:
        sr_path = Path(sys_root).resolve()
        if resolved == sr_path or resolved.is_relative_to(sr_path):
            return True
    prog_files = os.environ.get("ProgramFiles")
    if prog_files:
        pf_path = Path(prog_files).resolve()
        if resolved == pf_path or resolved.is_relative_to(pf_path):
            return True
    prog_files_x86 = os.environ.get("ProgramFiles(x86)")
    if prog_files_x86:
        pfx_path = Path(prog_files_x86).resolve()
        if resolved == pfx_path or resolved.is_relative_to(pfx_path):
            return True
    # POSIX system directories
    posix_str = str(resolved).replace("\\", "/")
    for prohibited in ["/etc", "/root", "/proc", "/sys", "/dev", "/boot"]:
        if posix_str == prohibited or posix_str.startswith(prohibited + "/"):
            return True
    return False


@router.post("/browse-local", response_model=BrowseLocalResponse)
async def browse_local_host(
    req: BrowseLocalRequest,
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst")),
) -> BrowseLocalResponse:
    """Browse server host filesystem directory tree for Zero-Copy evidence references without OS GUI dialogs."""
    target_p = Path(req.current_path).resolve() if req.current_path else Path(".").resolve()
    if not target_p.exists():
        target_p = Path(".").resolve()

    if is_prohibited_system_directory(target_p):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied: Browsing sensitive operating system directory '{target_p}' is strictly prohibited.",
        )

    evidence_root_env = os.environ.get("FORENSICOPS_EVIDENCE_ROOT")
    if evidence_root_env:
        ev_root = Path(evidence_root_env).resolve()
        if not (target_p == ev_root or target_p.is_relative_to(ev_root)):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: Path '{target_p}' is outside configured evidence root '{ev_root}'.",
            )

    if target_p.is_file():
        p = target_p
        return BrowseLocalResponse(
            status="success",
            current_path=str(p.parent),
            parent_path=str(p.parent.parent) if p.parent.parent != p.parent else None,
            selected_file=str(p),
            drives=_get_available_drives(),
            items=[],
        )

    allowed_exts = set(req.filter_extensions) if req.filter_extensions else SAFE_EVIDENCE_EXTENSIONS

    items: List[BrowseLocalItem] = []
    try:
        for entry in sorted(target_p.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower())):
            try:
                is_dir = entry.is_dir()
                ext = entry.suffix.lower()
                if is_dir or not allowed_exts or ext in allowed_exts:
                    size = entry.stat().st_size if not is_dir else 0
                    items.append(
                        BrowseLocalItem(
                            name=entry.name,
                            path=str(entry.resolve()),
                            is_dir=is_dir,
                            size_bytes=size,
                            extension=ext,
                        )
                    )
            except (PermissionError, OSError):
                continue
    except (PermissionError, OSError) as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission denied accessing directory '{target_p}': {exc}",
        )

    parent_path = str(target_p.parent) if target_p.parent != target_p else None
    return BrowseLocalResponse(
        status="success",
        current_path=str(target_p),
        parent_path=parent_path,
        selected_file=None,
        drives=_get_available_drives(),
        items=items,
    )


@router.post("/offline", response_model=OfflineIntakeResponse)
def intake_offline_evidence(
    req: OfflineIntakeRequest,
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst")),
) -> OfflineIntakeResponse:
    """Intake offline evidence artifacts, capsule archives, or zero-copy read-only references."""
    case_auth = get_case_authorization_service()
    from backend.app.db.sqlite_store import get_llm_state_store
    sqlite_store = get_llm_state_store()
    if sqlite_store.get_case(req.case_id):
        case_auth.verify_case_access(current_user, req.case_id, "write")
    else:
        case_auth.ensure_case_registered(req.case_id, current_user.username)

    custody = get_custody_engine(req.case_id)
    store = get_storage(req.case_id)
    dissect = DissectAdapter()

    artifacts: List[ArtifactRecord] = []
    findings_indexed = 0

    effective_actor = (
        f"{current_user.username} ({current_user.badge_id}) [{current_user.role}]"
        if current_user
        else req.actor
    )

    # Case 1: Raw base64 upload payload
    if req.raw_content_b64:
        settings = get_settings()
        max_b64_len = settings.max_b64_inline_bytes * 4 // 3 + 4
        if len(req.raw_content_b64) > max_b64_len:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Inline base64 payload length ({len(req.raw_content_b64)} chars) exceeds maximum allowed inline size ({settings.max_b64_inline_bytes} bytes). Use /api/intake/upload instead.",
            )
        try:
            content_bytes = base64.b64decode(req.raw_content_b64)
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid base64 payload: {exc}",
            )
        if len(content_bytes) > settings.max_b64_inline_bytes:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Decoded inline payload exceeds maximum allowed size of {settings.max_b64_inline_bytes} bytes.",
            )

        art_record = custody.store_raw_bytes(
            raw_bytes=content_bytes,
            case_id=req.case_id,
            original_filename=req.filename or "uploaded.bin",
            artifact_type=req.artifact_type,
            acquisition_method=req.acquisition_method,
            actor=effective_actor,
        )
        artifacts.append(art_record)

    # Case 2: File path provided
    elif req.evidence_path:
        ev_path = req.evidence_path.strip()

        # Zero-copy Read-Only path reference (:ro)
        if ev_path.endswith(":ro"):
            clean_path = ev_path[:-3]
            validated_path = validate_evidence_path_confinement(clean_path)
            art_record = custody.register_zero_copy_reference(
                case_id=req.case_id,
                file_path=str(validated_path),
                artifact_type=req.artifact_type,
                actor=effective_actor,
            )
            artifacts.append(art_record)
        else:
            p = validate_evidence_path_confinement(ev_path)

            # Check if capsule archive (.zip)
            if p.suffix.lower() == ".zip":
                try:
                    capsule_artifacts = custody.unpack_collector_capsule(
                        capsule_path=p,
                        case_id=req.case_id,
                        actor=effective_actor,
                    )
                    artifacts.extend(capsule_artifacts)
                except (ZipSlipError, SuspiciousArchiveError, DecompressionBombError, HashMismatchError, VaultIntegrityError) as sec_err:
                    # Never swallow security errors from malicious archives
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Security violation during archive processing: {sec_err}",
                    )
                except Exception as e:
                    # If not a structured capsule with manifest, defang and store as regular archive blob
                    art_record = custody.defang_and_store_blob(
                        source_file_path=p,
                        case_id=req.case_id,
                        artifact_type=req.artifact_type or "archive",
                        actor=effective_actor,
                        acquisition_method=req.acquisition_method,
                    )
                    artifacts.append(art_record)
            else:
                art_record = custody.defang_and_store_blob(
                    source_file_path=p,
                    case_id=req.case_id,
                    artifact_type=req.artifact_type or "file",
                    actor=effective_actor,
                    acquisition_method=req.acquisition_method,
                )
                artifacts.append(art_record)
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either 'evidence_path' or 'raw_content_b64' must be provided.",
        )

    # Optional auto-indexing with Dissect / fallback parsers
    if req.auto_index and artifacts:
        for art in artifacts:
            try:
                # Resolve blob or zero-copy file
                target_p = custody.resolve_artifact_file(art)
                parsed = dissect.parse_artifact_auto(
                    artifact_path=target_p,
                    artifact_record=art,
                    case_id=req.case_id,
                )
                if parsed:
                    store.insert_findings(parsed)
                findings_indexed += len(parsed)
            except Exception:
                # Keep resilient even if parsing fails for non-standard file
                pass

    recent_entries = custody.get_custody_chain(req.case_id)
    return OfflineIntakeResponse(
        status="success",
        case_id=req.case_id,
        artifacts=artifacts,
        findings_indexed_count=findings_indexed,
        custody_entries=recent_entries[-len(artifacts) :] if recent_entries else [],
    )


@router.post("/siem", response_model=SIEMIntakeResponse)
def intake_siem_query(
    req: SIEMIntakeRequest,
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst")),
) -> SIEMIntakeResponse:
    """Execute read-only query against SIEM connector (Elasticsearch, Wazuh, Splunk)."""
    case_auth = get_case_authorization_service()
    from backend.app.db.sqlite_store import get_llm_state_store
    sqlite_store = get_llm_state_store()
    if sqlite_store.get_case(req.case_id):
        case_auth.verify_case_access(current_user, req.case_id, "write")
    else:
        case_auth.ensure_case_registered(req.case_id, current_user.username)

    custody = get_custody_engine(req.case_id)
    store = get_storage(req.case_id)

    effective_actor = (
        f"{current_user.username} ({current_user.badge_id}) [{current_user.role}]"
        if current_user
        else req.actor
    )

    from backend.app.core.network_validator import sanitize_credentials

    cfg: Optional[SIEMConnectionConfig] = req.config
    if req.connection_id:
        from backend.app.core.credential_store import get_credential_store
        cred_store = get_credential_store()
        conn_data = cred_store.get_connection(req.connection_id, case_id=req.case_id, include_credentials=True)
        if not conn_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"SIEM connection '{req.connection_id}' not found for case '{req.case_id}'.",
            )
        creds = conn_data.get("credentials", {})
        try:
            cfg = SIEMConnectionConfig(
                siem_type=conn_data["siem_type"],
                endpoint_url=conn_data["endpoint_url"],
                api_key=creds.get("api_key"),
                username=creds.get("username") or conn_data.get("username"),
                password=creds.get("password"),
                token=creds.get("token"),
                verify_ssl=conn_data["verify_ssl"],
                timeout_seconds=conn_data["timeout_seconds"],
                index_pattern=conn_data.get("index_pattern"),
                headers=conn_data.get("headers") or {},
                allowed_hosts=conn_data.get("allowed_hosts"),
            )
        except Exception as e:
            clean_err = sanitize_credentials(str(e))
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid stored SIEM connection parameters: {clean_err}",
            )
    elif not cfg:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either 'connection_id' or 'config' must be provided.",
        )

    try:
        if cfg.siem_type == "elasticsearch":
            connector = ElasticsearchConnector(config=cfg)
        elif cfg.siem_type == "wazuh":
            connector = WazuhConnector(config=cfg)
        elif cfg.siem_type == "splunk":
            connector = SplunkConnector(config=cfg)
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported SIEM type: {cfg.siem_type}",
            )

        findings, snapshot = ingest_siem_query_findings(
            connector=connector,
            query=req.query,
            case_id=req.case_id,
            custody_engine=custody,
            forensic_store=store,
            actor=effective_actor,
            limit=req.limit,
        )
    except ReadOnlyViolationError as e:
        clean_err = sanitize_credentials(str(e))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Read-Only SIEM safety violation: {clean_err}",
        )
    except SSRFSecurityError as e:
        clean_err = sanitize_credentials(str(e))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"SSRF safety violation: {clean_err}",
        )
    except HTTPException:
        raise
    except Exception as e:
        clean_err = sanitize_credentials(str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"SIEM query execution error: {clean_err}",
        )

    return SIEMIntakeResponse(
        status="success",
        case_id=req.case_id,
        query_snapshot=snapshot,
        findings_count=len(findings),
        findings=findings,
    )


@router.get("/custody/{case_id}/export")
def export_custody_ledger(
    case_id: str,
    format: str = Query(default="jsonl", pattern="^(jsonl|json)$", description="Export format: jsonl or json"),
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst", "auditor")),
) -> Response:
    """Export append-only custody ledger in JSONL or JSON format as a downloadable attachment."""
    case_auth = get_case_authorization_service()
    case_auth.verify_case_access(current_user, case_id, "read")

    custody = get_custody_engine(case_id)
    entries = custody.get_custody_chain(case_id=case_id)

    clean_case_id = re.sub(r"[^a-zA-Z0-9_-]", "_", case_id)
    fmt = format.lower().strip()
    if fmt == "jsonl":
        lines = [json.dumps(entry.model_dump(), ensure_ascii=False) for entry in entries]
        content = "\n".join(lines) + ("\n" if lines else "")
        media_type = "application/x-ndjson; charset=utf-8"
        filename = f"custody_ledger_{clean_case_id}.jsonl"
    elif fmt == "json":
        content = json.dumps([entry.model_dump() for entry in entries], indent=2, ensure_ascii=False)
        media_type = "application/json; charset=utf-8"
        filename = f"custody_ledger_{clean_case_id}.json"
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Unsupported export format '{format}'.")

    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/custody/{case_id}", response_model=CustodyLedgerResponse)
def get_custody_ledger(
    case_id: str,
    current_user: UserRead = Depends(require_roles("lead_investigator", "soc_analyst", "auditor")),
) -> CustodyLedgerResponse:
    """Retrieve full append-only chain of custody and verify cryptographic tamper integrity."""
    case_auth = get_case_authorization_service()
    case_auth.verify_case_access(current_user, case_id, "read")

    custody = get_custody_engine(case_id)
    entries = custody.get_custody_chain(case_id=case_id)
    is_tamper_free = custody.verify_chain(case_id=case_id)

    return CustodyLedgerResponse(
        case_id=case_id,
        is_tamper_free=is_tamper_free,
        entry_count=len(entries),
        entries=entries,
    )
