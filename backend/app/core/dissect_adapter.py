"""Tier A Built-in Pure-Python Dissect / Userspace Fallback Adapter.

Standards: Userspace Stream Parsing (Zero Host-OS Kernel Mounting),
RFC 3227, Offline Disk Image, EVTX, Registry, and Collector Artifact Parsing.
"""
from __future__ import annotations

import csv
import json
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Tuple, Union
from uuid import uuid4

from backend.app.core.column_projector import SmartColumnProjector
from backend.app.models.findings import ForensicFinding


class DissectAdapter:
    """Tier A Built-in parser for disk images, .evtx, registry, and collector artifacts."""

    def __init__(self, projector: Optional[SmartColumnProjector] = None):
        self.projector = projector or SmartColumnProjector()

    # --------------------------------------------------------------------------
    # 1. Disk & VM Images: Flat Userspace Stream Parsing (Zero Kernel Mount)
    # --------------------------------------------------------------------------
    def parse_disk_image_stream(
        self,
        image_path: Union[str, Path],
        case_id: str,
        artifact_id: str,
        artifact_hash: str,
        max_partitions: int = 16,
    ) -> List[ForensicFinding]:
        """Inspect disk image partitions in userspace without host OS kernel mounting."""
        path = Path(image_path).resolve()
        findings: List[ForensicFinding] = []

        if not path.is_file():
            raise FileNotFoundError(f"Evidence image not found: {path}")

        # Stream inspect MBR / GPT in flat userspace bytes
        with open(path, "rb") as f:
            mbr_header = f.read(512)
            if len(mbr_header) < 512:
                return findings

            # Check standard MBR boot signature (0x55AA)
            has_mbr_sig = mbr_header[510:512] == b"\x55\xaa"

            # Parse MBR partition table at offset 446 (4 entries of 16 bytes)
            if has_mbr_sig:
                for idx in range(4):
                    entry_offset = 446 + (idx * 16)
                    entry = mbr_header[entry_offset : entry_offset + 16]
                    boot_flag, _start_chs, part_type, _end_chs, start_lba, size_sectors = struct.unpack(
                        "<B3sB3sII", entry
                    )
                    if part_type != 0x00 and size_sectors > 0:
                        start_offset = start_lba * 512
                        size_bytes = size_sectors * 512
                        projected = {
                            "partition_index": idx + 1,
                            "type_hex": f"0x{part_type:02X}",
                            "start_lba": start_lba,
                            "start_offset": start_offset,
                            "size_bytes": size_bytes,
                            "bootable": (boot_flag == 0x80),
                        }
                        findings.append(
                            ForensicFinding(
                                case_id=case_id,
                                source_artifact_id=artifact_id,
                                source_artifact_hash=artifact_hash,
                                tool_id="dissect_disk_stream",
                                artifact_type="raw_image",
                                category="disk_partition",
                                severity="info",
                                raw_reference=f"MBR_Partition_{idx + 1}",
                                summary=f"MBR Partition {idx + 1}: type 0x{part_type:02X}, size {size_bytes} bytes",
                                projected_data=projected,
                            )
                        )

            # Check GPT Partition Header at LBA 1 (offset 512)
            f.seek(512)
            gpt_header = f.read(512)
            if len(gpt_header) >= 92 and gpt_header[:8] == b"EFI PART":
                findings.append(
                    ForensicFinding(
                        case_id=case_id,
                        source_artifact_id=artifact_id,
                        source_artifact_hash=artifact_hash,
                        tool_id="dissect_disk_stream",
                        artifact_type="raw_image",
                        category="disk_partition",
                        severity="info",
                        raw_reference="GPT_Header_LBA1",
                        summary="Valid GPT (GUID Partition Table) header identified at LBA 1",
                        projected_data={
                            "partition_table": "GPT",
                            "header_size": struct.unpack("<I", gpt_header[12:16])[0],
                            "current_lba": struct.unpack("<Q", gpt_header[24:32])[0],
                        },
                    )
                )

        return findings

    # --------------------------------------------------------------------------
    # 2. Windows Event Log (.evtx) Userspace Parser
    # --------------------------------------------------------------------------
    def parse_evtx(
        self,
        file_path: Union[str, Path],
        case_id: str,
        artifact_id: str,
        artifact_hash: str,
    ) -> List[ForensicFinding]:
        """Parse Windows Event Log (.evtx) file or fallback EVTX extracts."""
        path = Path(file_path).resolve()
        findings: List[ForensicFinding] = []

        if not path.is_file():
            raise FileNotFoundError(f"EVTX file not found: {path}")

        # Check binary EVTX file signature: "ElfFile\x00"
        with open(path, "rb") as f:
            header = f.read(4096)
            is_binary_evtx = header[:8] == b"ElfFile\x00"

        if is_binary_evtx:
            findings.extend(
                self._parse_binary_evtx_chunks(path, header, case_id, artifact_id, artifact_hash)
            )
        else:
            # Fallback for structured EVTX logs (JSONL/XML extracts)
            findings.extend(
                self._parse_evtx_text_fallback(path, case_id, artifact_id, artifact_hash)
            )

        return findings

    def _parse_binary_evtx_chunks(
        self,
        path: Path,
        header: bytes,
        case_id: str,
        artifact_id: str,
        artifact_hash: str,
    ) -> List[ForensicFinding]:
        """Inspect binary EVTX chunk headers ('ElfChnk\x00') and records."""
        findings: List[ForensicFinding] = []
        file_size = path.stat().st_size
        chunk_size = 65536  # Standard EVTX chunk is 64KB

        with open(path, "rb") as f:
            f.seek(4096)  # EVTX chunks start after 4096-byte file header
            chunk_idx = 0
            while f.tell() < file_size:
                chunk_data = f.read(chunk_size)
                if len(chunk_data) < 512:
                    break
                if chunk_data[:8] == b"ElfChnk\x00":
                    first_record_num, last_record_num = struct.unpack("<QQ", chunk_data[8:24])
                    record_count = (last_record_num - first_record_num + 1) if last_record_num >= first_record_num else 0
                    findings.append(
                        ForensicFinding(
                            case_id=case_id,
                            source_artifact_id=artifact_id,
                            source_artifact_hash=artifact_hash,
                            tool_id="dissect_evtx",
                            artifact_type="evtx",
                            category="event_log_chunk",
                            severity="info",
                            raw_reference=f"Chunk_{chunk_idx}",
                            summary=f"EVTX Chunk {chunk_idx}: records {first_record_num} to {last_record_num} ({record_count} events)",
                            projected_data={
                                "chunk_index": chunk_idx,
                                "first_record_number": first_record_num,
                                "last_record_number": last_record_num,
                                "record_count": record_count,
                            },
                        )
                    )
                chunk_idx += 1

        return findings

    def _parse_evtx_text_fallback(
        self,
        path: Path,
        case_id: str,
        artifact_id: str,
        artifact_hash: str,
    ) -> List[ForensicFinding]:
        """Parse structured text or JSONL EVTX representations."""
        findings: List[ForensicFinding] = []
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line_no, line in enumerate(f, start=1):
                line = line.strip()
                if not line or not (line.startswith("{") and line.endswith("}")):
                    continue
                try:
                    data = json.loads(line)
                    event_id = str(data.get("EventId") or data.get("event_id") or "")
                    ts = data.get("TimeCreated") or data.get("timestamp") or None
                    host = data.get("Computer") or data.get("host")
                    user = data.get("UserName") or data.get("user")
                    proc = data.get("ExecutableInfo") or data.get("process_name")
                    cmd = data.get("CommandLine") or data.get("command_line")

                    findings.append(
                        ForensicFinding(
                            case_id=case_id,
                            source_artifact_id=artifact_id,
                            source_artifact_hash=artifact_hash,
                            tool_id="dissect_evtx",
                            timestamp_utc=ts,
                            artifact_type="evtx",
                            category="event_log",
                            event_id=event_id,
                            severity="info",
                            host=host,
                            user=user,
                            process_name=proc,
                            command_line=cmd,
                            raw_reference=f"Line_{line_no}",
                            summary=data.get("Payload") or f"Event {event_id} from {host or 'unknown'}",
                            projected_data={
                                k: v for k, v in data.items()
                                if k in ("TimeCreated", "EventId", "Computer", "UserName", "CommandLine")
                            },
                        )
                    )
                except json.JSONDecodeError:
                    continue
        return findings

    # --------------------------------------------------------------------------
    # 3. Windows Registry Userspace Parser
    # --------------------------------------------------------------------------
    def parse_registry_hive(
        self,
        hive_path: Union[str, Path],
        case_id: str,
        artifact_id: str,
        artifact_hash: str,
    ) -> List[ForensicFinding]:
        """Parse Windows Registry hive ('regf' header) or exported hive entries."""
        path = Path(hive_path).resolve()
        findings: List[ForensicFinding] = []

        if not path.is_file():
            raise FileNotFoundError(f"Registry hive not found: {path}")

        with open(path, "rb") as f:
            header = f.read(4096)
            is_regf = header[:4] == b"regf"

        if is_regf:
            # Parse standard REGF header metadata
            last_written_raw = header[12:20]
            # Convert Windows FILETIME (100-nanosecond intervals since Jan 1, 1601) to ISO-8601
            ft = struct.unpack("<Q", last_written_raw)[0]
            iso_time = None
            if ft > 0:
                epoch_seconds = (ft - 116444736000000000) / 10000000
                if epoch_seconds > 0:
                    try:
                        iso_time = datetime.fromtimestamp(epoch_seconds, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                    except (OSError, OverflowError, ValueError):
                        pass

            findings.append(
                ForensicFinding(
                    case_id=case_id,
                    source_artifact_id=artifact_id,
                    source_artifact_hash=artifact_hash,
                    tool_id="dissect_registry",
                    timestamp_utc=iso_time,
                    artifact_type="registry",
                    category="registry_hive",
                    severity="info",
                    raw_reference="REGF_Header",
                    summary=f"Valid Windows Registry Hive ({path.name}) loaded in userspace",
                    projected_data={
                        "hive_name": path.name,
                        "file_size": path.stat().st_size,
                        "last_written_utc": iso_time,
                    },
                )
            )
        else:
            # Fallback for structured JSONL / text exported registry keys
            findings.extend(self._parse_registry_text_fallback(path, case_id, artifact_id, artifact_hash))

        return findings

    def _parse_registry_text_fallback(
        self,
        path: Path,
        case_id: str,
        artifact_id: str,
        artifact_hash: str,
    ) -> List[ForensicFinding]:
        """Parse structured text or JSONL registry extracts."""
        findings: List[ForensicFinding] = []
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line_no, line in enumerate(f, start=1):
                line = line.strip()
                if not line or not (line.startswith("{") and line.endswith("}")):
                    continue
                try:
                    data = json.loads(line)
                    key_path = data.get("KeyPath") or data.get("key_path")
                    val_name = data.get("ValueName") or data.get("value_name")
                    val_data = data.get("ValueData") or data.get("value_data")
                    ts = data.get("LastWriteTimestamp") or data.get("timestamp_utc")

                    findings.append(
                        ForensicFinding(
                            case_id=case_id,
                            source_artifact_id=artifact_id,
                            source_artifact_hash=artifact_hash,
                            tool_id="dissect_registry",
                            timestamp_utc=ts,
                            artifact_type="registry",
                            category="registry_key",
                            severity="info",
                            command_line=str(val_data) if val_data else None,
                            raw_reference=key_path or f"Line_{line_no}",
                            summary=f"Registry Value '{val_name}' in {key_path}",
                            projected_data={
                                "KeyPath": key_path,
                                "ValueName": val_name,
                                "ValueData": val_data,
                                "LastWriteTimestamp": ts,
                            },
                        )
                    )
                except json.JSONDecodeError:
                    continue
        return findings

    # --------------------------------------------------------------------------
    # 4. Collector Capsule JSONL / JSON Artifact Parser
    # --------------------------------------------------------------------------
    def parse_collector_artifact(
        self,
        file_path: Union[str, Path],
        case_id: str,
        artifact_id: str,
        artifact_hash: str,
    ) -> List[ForensicFinding]:
        """Parse JSON / JSONL output from collector capsules (e.g. processes, netstat, system_info)."""
        path = Path(file_path).resolve()
        findings: List[ForensicFinding] = []

        if not path.is_file():
            raise FileNotFoundError(f"Collector artifact not found: {path}")

        # Detect category from filename
        lower_name = path.name.lower()
        category = "endpoint_triage"
        artifact_type = "collector_artifact"
        if "process" in lower_name:
            category = "process_list"
            artifact_type = "process"
        elif "netstat" in lower_name or "network" in lower_name or "socket" in lower_name:
            category = "network_connection"
            artifact_type = "network"
        elif "autorun" in lower_name or "persist" in lower_name:
            category = "persistence"
            artifact_type = "registry"

        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read().strip()

        # Handle full JSON array/object or JSONL lines
        items: List[Dict[str, Any]] = []
        if content.startswith("[") and content.endswith("]"):
            try:
                items = json.loads(content)
            except json.JSONDecodeError:
                items = []
        elif content.startswith("{") and content.endswith("}") and "\n" not in content:
            try:
                items = [json.loads(content)]
            except json.JSONDecodeError:
                items = []
        else:
            # JSONL lines
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("{") and line.endswith("}"):
                    try:
                        items.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

        for idx, item in enumerate(items, start=1):
            ts = (
                item.get("timestamp_utc")
                or item.get("TimeCreated")
                or item.get("create_time")
                or item.get("CreateTime")
            )
            proc_name = (
                item.get("process_name")
                or item.get("ProcessName")
                or item.get("ImageFileName")
                or item.get("name")
            )
            cmd_line = (
                item.get("command_line")
                or item.get("CommandLine")
                or item.get("cmdline")
                or item.get("args")
            )
            user_val = item.get("user") or item.get("UserName") or item.get("username")
            host_val = item.get("host") or item.get("computer") or item.get("Computer")

            summary_text = f"Triage item from {path.name}"
            if proc_name:
                summary_text = f"Process {proc_name} (cmd: {cmd_line or 'none'})"
            elif "local_port" in item or "LocalPort" in item or "remote_address" in item:
                summary_text = f"Network socket {item.get('local_address', '')}:{item.get('local_port', '')} -> {item.get('remote_address', '')}:{item.get('remote_port', '')}"

            findings.append(
                ForensicFinding(
                    case_id=case_id,
                    source_artifact_id=artifact_id,
                    source_artifact_hash=artifact_hash,
                    tool_id="dissect_collector_adapter",
                    timestamp_utc=ts,
                    artifact_type=artifact_type,
                    category=category,
                    severity="info",
                    host=host_val,
                    user=user_val,
                    process_name=proc_name,
                    command_line=cmd_line,
                    raw_reference=f"{path.name}:{idx}",
                    summary=summary_text,
                    projected_data={k: v for k, v in item.items() if not k.startswith("_")},
                )
            )

        return findings
