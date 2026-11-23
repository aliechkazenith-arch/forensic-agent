"""Scope 1C: Target OS & Forensic Artifact Indexing Engine.

Standards:
- Zero Host OS Kernel Mounting (AGENTS.md Rule 2): Flat userspace inspection.
- Reads uploaded case files across Windows & Linux triage archives (.zip, .tar.gz)
  and individual artifacts (.evtx, Registry hives, .pcap/.pcapng, Linux /var/log, cron, systemd, shell histories).
- Cross-references Playbook steps to determine READY vs SKIPPED_NO_ARTIFACT status.
"""
from __future__ import annotations

import fnmatch
import os
import tarfile
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field

from backend.app.core.custody_engine import CustodyEngine
from backend.app.core.storage import ForensicStore
from backend.app.models.custody import ArtifactRecord
from backend.app.models.findings import ForensicFinding


class IndexedFile(BaseModel):
    artifact_id: str
    original_path: str
    artifact_type: str
    source_archive: Optional[str] = None
    target_os: str = "cross_platform"
    sha256: str = ""
    resolved_path: Optional[str] = None


class CaseArtifactIndex(BaseModel):
    """Normalized index of all digital artifacts available for a case."""
    case_id: str
    indexed_files: List[IndexedFile] = Field(default_factory=list)
    available_types: Set[str] = Field(default_factory=set)
    has_windows: bool = False
    has_linux: bool = False
    has_network: bool = False

    def matches_step(
        self,
        artifact_globs: List[str],
        required_artifact_types: List[str],
        target_os: str = "cross_platform",
    ) -> Tuple[bool, List[str]]:
        """Check if any indexed file satisfies the playbook step's globs or required types.

        Returns:
            Tuple of (matched_bool, list_of_matching_artifact_ids)
        """
        matched_ids: Set[str] = set()

        # 1. Match against individual indexed files and inner archive contents
        for item in self.indexed_files:
            file_name = Path(item.original_path).name.lower()
            orig_lower = item.original_path.lower()
            atype_lower = item.artifact_type.lower()

            # Check required artifact types
            type_match = False
            if required_artifact_types:
                for req_t in required_artifact_types:
                    req_l = req_t.lower()
                    if req_l == "all" or req_l == atype_lower:
                        type_match = True
                        break
                    # Broad taxonomy aliases
                    if req_l == "network" and atype_lower in ("network", "pcap"):
                        type_match = True
                        break
                    if req_l == "evtx" and atype_lower in ("evtx", "event_log"):
                        type_match = True
                        break
                    if req_l == "registry" and atype_lower in ("registry", "hive"):
                        type_match = True
                        break
                    if req_l in ("collector_log", "log") and atype_lower in ("collector_log", "log", "process", "file"):
                        type_match = True
                        break

            # Check globs
            glob_match = False
            if artifact_globs:
                for pat in artifact_globs:
                    pat_l = pat.lower()
                    if fnmatch.fnmatch(file_name, pat_l) or fnmatch.fnmatch(orig_lower, pat_l):
                        glob_match = True
                        break
                    if pat_l == "*" or pat_l == "*.*":
                        glob_match = True
                        break
            else:
                glob_match = True

            if type_match or glob_match:
                matched_ids.add(item.artifact_id)

        # 2. Check if general available types or findings satisfy requirement
        if not matched_ids and required_artifact_types:
            for req_t in required_artifact_types:
                req_l = req_t.lower()
                if req_l == "all" and self.indexed_files:
                    return True, [f.artifact_id for f in self.indexed_files[:5]]
                if req_l in self.available_types:
                    return True, [f"indexed-{req_l}"]
                if req_l == "network" and self.has_network:
                    return True, ["indexed-network"]
                if req_l == "evtx" and (self.has_windows or "evtx" in self.available_types):
                    return True, ["indexed-evtx"]
                if req_l in ("collector_log", "log") and (self.has_linux or "collector_log" in self.available_types):
                    return True, ["indexed-linux-log"]

        if matched_ids:
            return True, sorted(list(matched_ids))
        return False, []


def _detect_target_os(path_str: str, artifact_type: str) -> str:
    """Infer target operating system from file path and artifact type."""
    p_lower = path_str.lower()
    t_lower = artifact_type.lower()

    if t_lower in ("pcap", "network") or p_lower.endswith((".pcap", ".pcapng")):
        return "network"
    if t_lower in ("evtx", "event_log", "registry") or p_lower.endswith((".evtx", ".pf")):
        return "windows"
    if any(k in p_lower for k in ("system32", "windows", "sysmon", "ntuser.dat", "sam", "software", "system")):
        return "windows"
    if any(k in p_lower for k in ("/var/log", "/etc/", "auth.log", "syslog", "bash_history", "cron", "systemd")):
        return "linux"
    if t_lower in ("memory", "raw_image"):
        return "cross_platform"
    return "cross_platform"


def index_case_artifacts(
    case_id: str,
    custody_engine: Optional[CustodyEngine] = None,
    storage: Optional[ForensicStore] = None,
    extra_findings: Optional[List[ForensicFinding]] = None,
) -> CaseArtifactIndex:
    """Index all artifacts registered in custody engine, storage, or archives for a case."""
    indexed_files: List[IndexedFile] = []
    available_types: Set[str] = set()
    has_win = False
    has_lin = False
    has_net = False

    # 1. Inspect registered artifacts in CustodyEngine
    if custody_engine:
        try:
            records = custody_engine.get_artifacts(case_id=case_id)
            for rec in records:
                atype = rec.type or "file"
                available_types.add(atype.lower())
                tos = _detect_target_os(rec.original_path, atype)
                if tos == "windows":
                    has_win = True
                elif tos == "linux":
                    has_lin = True
                elif tos == "network":
                    has_net = True

                resolved_path = None
                try:
                    resolved_path = str(custody_engine.resolve_artifact_file(rec))
                except Exception:
                    pass

                indexed_files.append(
                    IndexedFile(
                        artifact_id=rec.artifact_id,
                        original_path=rec.original_path,
                        artifact_type=atype,
                        target_os=tos,
                        sha256=rec.sha256,
                        resolved_path=resolved_path,
                    )
                )

                # Inspect inner contents of triage archives (.zip, .tar.gz) without extraction
                if resolved_path and os.path.isfile(resolved_path):
                    orig_low = rec.original_path.lower()
                    if orig_low.endswith(".zip"):
                        try:
                            with zipfile.ZipFile(resolved_path, "r") as zf:
                                for name in zf.namelist():
                                    sub_os = _detect_target_os(name, "file")
                                    if sub_os == "windows":
                                        has_win = True
                                    elif sub_os == "linux":
                                        has_lin = True
                                    sub_type = "evtx" if name.lower().endswith(".evtx") else "file"
                                    available_types.add(sub_type)
                                    indexed_files.append(
                                        IndexedFile(
                                            artifact_id=f"{rec.artifact_id}::{name}",
                                            original_path=name,
                                            artifact_type=sub_type,
                                            source_archive=rec.original_path,
                                            target_os=sub_os,
                                            sha256=rec.sha256,
                                            resolved_path=resolved_path,
                                        )
                                    )
                        except Exception:
                            pass
                    elif orig_low.endswith((".tar.gz", ".tgz", ".tar")):
                        try:
                            with tarfile.open(resolved_path, "r:*") as tf:
                                for member in tf.getmembers():
                                    sub_os = _detect_target_os(member.name, "file")
                                    if sub_os == "windows":
                                        has_win = True
                                    elif sub_os == "linux":
                                        has_lin = True
                                    sub_type = "collector_log" if "log" in member.name.lower() else "file"
                                    available_types.add(sub_type)
                                    indexed_files.append(
                                        IndexedFile(
                                            artifact_id=f"{rec.artifact_id}::{member.name}",
                                            original_path=member.name,
                                            artifact_type=sub_type,
                                            source_archive=rec.original_path,
                                            target_os=sub_os,
                                            sha256=rec.sha256,
                                            resolved_path=resolved_path,
                                        )
                                    )
                        except Exception:
                            pass
        except Exception:
            pass

    # 2. Inspect existing findings in DuckDB storage
    if storage:
        try:
            findings = storage.query_structured_findings(case_id=case_id, limit=200)
            for f in findings:
                atype = f.artifact_type.lower()
                available_types.add(atype)
                tos = _detect_target_os(f.raw_reference or f.summary, atype)
                if tos == "windows" or atype in ("evtx", "registry"):
                    has_win = True
                elif tos == "linux" or atype in ("collector_log", "process") or "linux" in (f.host or "").lower():
                    has_lin = True
                elif tos == "network" or atype in ("network", "pcap"):
                    has_net = True

                indexed_files.append(
                    IndexedFile(
                        artifact_id=f.source_artifact_id or f.finding_id,
                        original_path=f.raw_reference or f"{f.artifact_type}_{f.category}",
                        artifact_type=atype,
                        target_os=tos,
                        sha256=f.source_artifact_hash,
                    )
                )
        except Exception:
            pass

    # 3. Inspect extra passed findings (e.g. from API or tests)
    if extra_findings:
        for f in extra_findings:
            atype = f.artifact_type.lower()
            available_types.add(atype)
            tos = _detect_target_os(f.raw_reference or f.summary, atype)
            if tos == "windows" or atype in ("evtx", "registry"):
                has_win = True
            elif tos == "linux" or atype in ("collector_log", "process") or "linux" in (f.host or "").lower():
                has_lin = True
            elif tos == "network" or atype in ("network", "pcap"):
                has_net = True

            indexed_files.append(
                IndexedFile(
                    artifact_id=f.source_artifact_id or f.finding_id,
                    original_path=f.raw_reference or f"{f.artifact_type}_{f.category}",
                    artifact_type=atype,
                    target_os=tos,
                    sha256=f.source_artifact_hash,
                )
            )

    return CaseArtifactIndex(
        case_id=case_id,
        indexed_files=indexed_files,
        available_types=available_types,
        has_windows=has_win,
        has_linux=has_lin,
        has_network=has_net,
    )
