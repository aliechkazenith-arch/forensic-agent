"""Deterministic Forensic Store Query Tools and Entity Pivot Extractors.

Standards:
- Deterministic Tooling Only (AGENTS.md Rule 1): Parsers & DuckDB produce facts;
  LLMs only orchestrate queries and summarize findings.
- Zero Silent Sampling: Scoped queries, timeline windows, and token search.
- Lightweight Pivots: Regex extraction of IPs, file paths, users, and timestamps.
"""
from __future__ import annotations

import os
import re
import socket
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union
from backend.app.core.playbook_registry import ScopedFilterParams
from backend.app.core.storage import ForensicStore
from backend.app.models.findings import ForensicFinding, NodeGoalResult
from backend.app.models.workflow import WorkflowEdgePayload

# Regex patterns for forensic entity extraction
IPV4_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
WINDOWS_PATH_REGEX = re.compile(r"[a-zA-Z]:\\(?:[^\s\"<>|?*]+[\\/])*[^\s\"<>|?*]+")
LINUX_PATH_REGEX = re.compile(r"(?:/[a-zA-Z0-9_\.\-]+){2,}")


def query_findings_tool(
    store: ForensicStore,
    case_id: str,
    filters: Optional[Dict[str, Any]] = None,
    pivots: Optional[Dict[str, Any]] = None,
    limit: int = 100,
    offset: int = 0,
    order_by: str = "timestamp_utc",
    ascending: bool = True,
) -> List[ForensicFinding]:
    """Deterministically query indexed findings using structured SQL filters and incoming pivots."""
    return store.query_structured_findings(
        case_id=case_id,
        filters=filters,
        pivots=pivots,
        limit=limit,
        offset=offset,
        order_by=order_by,
        ascending=ascending,
    )


def timeline_window_tool(
    store: ForensicStore,
    case_id: str,
    pivot_timestamp_utc: str,
    window_before_seconds: int = 300,
    window_after_seconds: int = 300,
    host: Optional[str] = None,
    limit: int = 100,
) -> List[ForensicFinding]:
    """Retrieve all findings occurring within a temporal window around a pivot timestamp."""
    return store.get_timeline_window(
        case_id=case_id,
        pivot_timestamp_utc=pivot_timestamp_utc,
        window_before_seconds=window_before_seconds,
        window_after_seconds=window_after_seconds,
        host=host,
        limit=limit,
    )


def hybrid_search_tool(
    store: ForensicStore,
    query: str,
    case_id: Optional[str] = None,
    artifact_type: Optional[str] = None,
    top_k: int = 10,
) -> List[ForensicFinding]:
    """Rank findings using term overlap and field-weighted scoring."""
    return store.hybrid_search(
        query=query,
        case_id=case_id,
        artifact_type=artifact_type,
        top_k=top_k,
    )


def create_view_tool(
    store: ForensicStore,
    view_name: str,
    query_filter: Dict[str, Any],
    case_id: Optional[str] = None,
) -> str:
    """Create a lightweight DuckDB view pointer for LangGraph DAG edges."""
    return store.create_dataset_view(
        view_name=view_name,
        query_filter=query_filter,
        case_id=case_id,
    )


def extract_pivots_from_findings(findings: List[ForensicFinding]) -> Dict[str, List[str]]:
    """Deterministically extract forensic entities (users, IPs, processes, file paths, hashes) from findings."""
    users: Set[str] = set()
    hosts: Set[str] = set()
    processes: Set[str] = set()
    timestamps: Set[str] = set()
    finding_ids: Set[str] = set()
    hashes: Set[str] = set()
    ips: Set[str] = set()
    file_paths: Set[str] = set()

    for f in findings:
        finding_ids.add(f.finding_id)
        if f.source_artifact_hash:
            hashes.add(f.source_artifact_hash)
        if f.user and f.user.strip():
            users.add(f.user.strip())
        if f.host and f.host.strip():
            hosts.add(f.host.strip())
        if f.process_name and f.process_name.strip():
            processes.add(f.process_name.strip())
        if f.timestamp_utc and f.timestamp_utc.strip():
            timestamps.add(f.timestamp_utc.strip())

        # Inspect command line, summary, and projected data for IPs and paths
        text_blobs = [f.summary or "", f.command_line or ""]
        if f.projected_data:
            text_blobs.extend(str(v) for v in f.projected_data.values())

        for text in text_blobs:
            for ip in IPV4_REGEX.findall(text):
                # Filter out standard non-routable broadcast or zero IPs if desired, or keep all
                if not ip.startswith("0.") and not ip.startswith("255."):
                    ips.add(ip)
            for p in WINDOWS_PATH_REGEX.findall(text):
                file_paths.add(p)
            for p in LINUX_PATH_REGEX.findall(text):
                file_paths.add(p)

    return {
        "compromised_users": sorted(list(users)),
        "hosts": sorted(list(hosts)),
        "process_names": sorted(list(processes)),
        "pivot_timestamps_utc": sorted(list(timestamps)),
        "source_ips": sorted(list(ips)),
        "file_paths": sorted(list(file_paths)),
        "verified_finding_ids": sorted(list(finding_ids)),
        "source_artifact_hashes": sorted(list(hashes)),
    }


def extract_pivots_from_goal_result(result: NodeGoalResult) -> Dict[str, List[str]]:
    """Extract and aggregate entity pivots from structured NodeGoalResult output."""
    pivots: Dict[str, List[str]] = {}

    for k, v in result.extracted_pivots.items():
        if v:
            pivots[k] = list(dict.fromkeys(v))

    # Also capture cited finding IDs and hashes
    cited_fids: Set[str] = set()
    cited_hashes: Set[str] = set()
    for claim in result.claims:
        cited_fids.update(claim.citing_finding_ids)
        cited_hashes.update(claim.source_artifact_hashes)

    if cited_fids:
        pivots["verified_finding_ids"] = sorted(list(cited_fids))
    if cited_hashes:
        pivots["source_artifact_hashes"] = sorted(list(cited_hashes))

    return pivots


def apply_scoped_filters(
    findings: List[ForensicFinding],
    filters: Optional[ScopedFilterParams] = None,
) -> List[ForensicFinding]:
    """Deterministically filter findings using Scope 4B ScopedFilterParams."""
    if not filters:
        return findings

    has_keywords = bool(filters.keywords_or_iocs)
    has_regex = bool(filters.regex_pattern)
    has_time_start = bool(filters.time_start_utc)
    has_time_end = bool(filters.time_end_utc)
    has_event_ids = bool(filters.event_ids)

    if not (has_keywords or has_regex or has_time_start or has_time_end or has_event_ids):
        return findings

    compiled_re = re.compile(filters.regex_pattern, re.IGNORECASE) if filters.regex_pattern else None
    kws_lower = [k.lower() for k in filters.keywords_or_iocs]
    target_event_ids = {str(eid) for eid in filters.event_ids}

    # Normalize filter timestamps
    start_dt: Optional[datetime] = None
    if filters.time_start_utc:
        try:
            start_dt = datetime.fromisoformat(filters.time_start_utc.replace("Z", "+00:00"))
        except Exception:
            pass

    end_dt: Optional[datetime] = None
    if filters.time_end_utc:
        try:
            end_dt = datetime.fromisoformat(filters.time_end_utc.replace("Z", "+00:00"))
        except Exception:
            pass

    filtered: List[ForensicFinding] = []
    for f in findings:
        # 1. Event ID check
        if has_event_ids:
            if not f.event_id or str(f.event_id) not in target_event_ids:
                continue

        # 2. Timestamp range check
        if (start_dt or end_dt) and f.timestamp_utc:
            try:
                f_dt = datetime.fromisoformat(f.timestamp_utc.replace("Z", "+00:00"))
                if start_dt and f_dt < start_dt:
                    # Also permit matching by time-of-day if dates differ
                    if not (start_dt.date() != f_dt.date() and f_dt.time() >= start_dt.time()):
                        continue
                if end_dt and f_dt > end_dt:
                    if not (end_dt.date() != f_dt.date() and f_dt.time() <= end_dt.time()):
                        continue
            except Exception:
                pass

        # 3. Text blobs for keyword and regex search
        text_blobs = [
            f.summary or "",
            f.command_line or "",
            f.process_name or "",
            f.user or "",
            f.host or "",
            f.category or "",
            f.artifact_type or "",
            f.raw_reference or "",
        ]
        if f.projected_data:
            text_blobs.extend(str(v) for v in f.projected_data.values())
        combined_text = " ".join(text_blobs).lower()

        # 4. Keyword / IOC check
        if has_keywords:
            matched_kw = any(kw in combined_text for kw in kws_lower)
            if not matched_kw:
                continue

        # 5. Regex check
        if compiled_re:
            if not compiled_re.search(" ".join(text_blobs)):
                continue

        filtered.append(f)

    return filtered


def parse_pcap_file(
    pcap_path: Union[str, Path],
    case_id: str,
    artifact_id: str,
    artifact_hash: str,
    max_packets: int = 1000,
) -> List[ForensicFinding]:
    """Lightweight, deterministic userspace PCAP/PCAPNG network stream parser."""
    path = Path(pcap_path).resolve()
    findings: List[ForensicFinding] = []
    if not path.is_file():
        return findings

    try:
        with open(path, "rb") as f:
            magic = f.read(4)
            if len(magic) < 4:
                return findings

            # Standard PCAP
            if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
                endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
                f.seek(24)  # Skip 24-byte global header
                packet_count = 0

                while packet_count < max_packets:
                    hdr = f.read(16)
                    if len(hdr) < 16:
                        break
                    ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{endian}IIII", hdr)
                    pkt_data = f.read(incl_len)
                    if len(pkt_data) < incl_len:
                        break
                    packet_count += 1

                    # Parse Ethernet IPv4 (Ethernet header is 14 bytes)
                    if len(pkt_data) >= 34 and pkt_data[12:14] == b"\x08\x00":
                        ip_hdr = pkt_data[14:]
                        proto_num = ip_hdr[9]
                        src_ip = socket.inet_ntoa(ip_hdr[12:16])
                        dst_ip = socket.inet_ntoa(ip_hdr[16:20])
                        proto_name = "TCP" if proto_num == 6 else "UDP" if proto_num == 17 else f"IP_{proto_num}"

                        src_port = 0
                        dst_port = 0
                        ihl = (ip_hdr[0] & 0x0F) * 4
                        if len(ip_hdr) >= ihl + 4:
                            src_port, dst_port = struct.unpack("!HH", ip_hdr[ihl : ihl + 4])

                        ts_utc = datetime.fromtimestamp(ts_sec, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                        summary = f"Network traffic {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({proto_name})"
                        if dst_port in (5938, 5939) or src_port in (5938, 5939):
                            summary += " [TeamViewer]"

                        findings.append(
                            ForensicFinding(
                                case_id=case_id,
                                source_artifact_id=artifact_id,
                                source_artifact_hash=artifact_hash,
                                tool_id="native_pcap_parser",
                                artifact_type="network",
                                category="network_connection",
                                timestamp_utc=ts_utc,
                                summary=summary,
                                projected_data={
                                    "src_ip": src_ip,
                                    "src_port": src_port,
                                    "dst_ip": dst_ip,
                                    "dst_port": dst_port,
                                    "protocol": proto_name,
                                },
                            )
                        )
    except Exception:
        pass

    return findings


def parse_linux_text_log(
    log_path: Union[str, Path],
    case_id: str,
    artifact_id: str,
    artifact_hash: str,
    max_lines: int = 2000,
) -> List[ForensicFinding]:
    """Deterministic parser for Linux auth.log, syslog, and shell histories."""
    path = Path(log_path).resolve()
    findings: List[ForensicFinding] = []
    if not path.is_file():
        return findings

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line_no, raw_line in enumerate(f, 1):
                if line_no > max_lines:
                    break
                line = raw_line.strip()
                if not line:
                    continue

                category = "log_entry"
                severity = "info"
                summary = line
                user = None
                host = None

                # Detect SSH / Auth events
                if "sshd" in line:
                    category = "authentication"
                    if "Accepted" in line:
                        severity = "low"
                        m_u = re.search(r"for\s+(?:invalid\s+)?(?:user\s+)?([a-zA-Z0-9_\-]+)", line)
                        if m_u:
                            user = m_u.group(1)
                    elif "Failed password" in line or "authentication failure" in line:
                        severity = "high"
                        m_u = re.search(r"for\s+(?:invalid\s+)?(?:user\s+)?([a-zA-Z0-9_\-]+)", line)
                        if m_u:
                            user = m_u.group(1)
                elif "sudo:" in line:
                    category = "privilege_escalation"
                    severity = "medium"
                elif "cron" in line.lower() or "crond" in line.lower():
                    category = "persistence"

                findings.append(
                    ForensicFinding(
                        case_id=case_id,
                        source_artifact_id=artifact_id,
                        source_artifact_hash=artifact_hash,
                        tool_id="native_log_parser",
                        artifact_type="collector_log",
                        category=category,
                        severity=severity,
                        user=user,
                        host=host,
                        raw_reference=f"line_{line_no}",
                        summary=summary[:300],
                        projected_data={"raw_line": line[:500]},
                    )
                )
    except Exception:
        pass

    return findings

