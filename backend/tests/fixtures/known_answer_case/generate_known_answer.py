"""Deterministic Known-Answer Attack Fixture Generator for Phase 15-B E2E Investigation.

Produces:
1. software.hiv - Valid REGF binary registry hive with persistence Run key:
   HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\SystemUpdater = "C:\\Users\\Public\\updater.exe"
2. software_run.jsonl - JSONL export format of the persistence Run key for fallback/direct ingestion.
3. triage/ - Directory containing:
   - processes.jsonl: updater.exe (PID 4120, Parent PID 1024, user NT AUTHORITY\\SYSTEM, host WS-CORP-FINANCE)
   - network_connections.jsonl: outbound C2 connection to 198.51.100.45:4444 (TCP ESTABLISHED)
   - security_events.jsonl: Event 4624 (Logon) and Event 7045 (Service creation for updater.exe)
"""
from __future__ import annotations

import json
import struct
from pathlib import Path
from typing import Any, Dict

from backend.app.core.registry_parser import REG_SZ, compute_header_checksum

KNOWN_ANSWER_DIR = Path(__file__).resolve().parent
TRIAGE_DIR = KNOWN_ANSWER_DIR / "triage"


class SyntheticHiveBuilder:
    """Constructs valid binary REGF files for testing."""

    def __init__(self, hive_name: str = "SOFTWARE"):
        self.hive_name = hive_name
        self.bin_data = bytearray(8192)
        self.bin_data[:4] = b"hbin"
        struct.pack_into("<I", self.bin_data, 4, 0)
        struct.pack_into("<I", self.bin_data, 8, 8192)
        self.alloc_offset = 32

    def alloc_cell(self, data: bytes) -> int:
        cell_size = len(data) + 4
        if cell_size % 8 != 0:
            cell_size += 8 - (cell_size % 8)
        padding = cell_size - 4 - len(data)
        full_cell = struct.pack("<i", -cell_size) + data + (b"\x00" * padding)

        while self.alloc_offset + cell_size > len(self.bin_data):
            self.bin_data.extend(b"\x00" * 4096)
            struct.pack_into("<I", self.bin_data, 8, len(self.bin_data))

        offset = self.alloc_offset
        self.bin_data[offset : offset + cell_size] = full_cell
        self.alloc_offset += cell_size
        return offset

    def build_value(self, name: str, val_type: int, val_data: Any) -> int:
        raw_str = (str(val_data) + "\x00").encode("utf-16le")
        data_cell_off = self.alloc_cell(raw_str)
        data_len = len(raw_str)
        data_offset = data_cell_off

        name_b = name.encode("latin-1")
        vk_data = bytearray()
        vk_data += b"vk"
        vk_data += struct.pack("<H", len(name_b))
        vk_data += struct.pack("<I", data_len)
        vk_data += struct.pack("<I", data_offset)
        vk_data += struct.pack("<I", val_type)
        vk_data += struct.pack("<H", 1)  # ASCII name
        vk_data += struct.pack("<H", 0)  # unused
        vk_data += name_b
        return self.alloc_cell(bytes(vk_data))

    def build_key(
        self,
        name: str,
        key_dict: dict,
        is_root: bool = False,
    ) -> int:
        values_dict = key_dict.get("@values", {})
        vk_offsets = []
        for v_name, (v_type, v_val) in values_dict.items():
            vk_off = self.build_value(v_name, v_type, v_val)
            vk_offsets.append(vk_off)

        values_list_off = -1
        if vk_offsets:
            v_list_bytes = b"".join(struct.pack("<I", off) for off in vk_offsets)
            values_list_off = self.alloc_cell(v_list_bytes)

        child_keys = {k: v for k, v in key_dict.items() if not k.startswith("@")}
        child_nk_offsets = []
        for child_name, child_dict in child_keys.items():
            c_off = self.build_key(child_name, child_dict, is_root=False)
            child_nk_offsets.append((c_off, child_name))

        subkey_list_off = -1
        if child_nk_offsets:
            sk_bytes = bytearray(b"lf" + struct.pack("<H", len(child_nk_offsets)))
            for c_off, c_name in child_nk_offsets:
                hint = (c_name[:4].ljust(4, " ")).encode("latin-1")
                sk_bytes += struct.pack("<I", c_off) + hint
            subkey_list_off = self.alloc_cell(bytes(sk_bytes))

        name_b = name.encode("latin-1")
        flags = 0x0020  # ASCII name
        if is_root:
            flags |= 0x0004

        nk = bytearray()
        nk += b"nk"
        nk += struct.pack("<H", flags)
        nk += struct.pack("<Q", 133500000000000000)  # FILETIME ~2026
        nk += struct.pack("<I", 0)
        nk += struct.pack("<i", 0)
        nk += struct.pack("<I", len(child_nk_offsets))
        nk += struct.pack("<I", 0)
        nk += struct.pack("<i", subkey_list_off)
        nk += struct.pack("<i", -1)
        nk += struct.pack("<I", len(vk_offsets))
        nk += struct.pack("<i", values_list_off)
        nk += struct.pack("<i", -1)
        nk += struct.pack("<i", -1)
        nk += struct.pack("<I", 0)
        nk += struct.pack("<I", 0)
        nk += struct.pack("<I", 0)
        nk += struct.pack("<I", 0)
        nk += struct.pack("<I", 0)
        nk += struct.pack("<H", len(name_b))
        nk += struct.pack("<H", 0)
        nk += name_b
        return self.alloc_cell(bytes(nk))

    def build_bytes(self, tree: dict) -> bytes:
        root_off = self.build_key("Root", tree, is_root=True)
        header = bytearray(4096)
        header[:4] = b"regf"
        struct.pack_into("<I", header, 4, 1)
        struct.pack_into("<I", header, 8, 1)
        struct.pack_into("<Q", header, 12, 133500000000000000)
        struct.pack_into("<I", header, 20, 1)
        struct.pack_into("<I", header, 24, 5)
        struct.pack_into("<I", header, 36, root_off)
        struct.pack_into("<I", header, 40, len(self.bin_data))
        struct.pack_into("<I", header, 44, 1)
        name_bytes = self.hive_name.encode("utf-16le")
        header[48 : 48 + len(name_bytes)] = name_bytes

        chk = compute_header_checksum(header)
        struct.pack_into("<I", header, 508, chk)
        return bytes(header + self.bin_data)


def generate_known_answer_registry(output_dir: Path) -> Dict[str, Path]:
    """Generate both binary REGF software hive and JSONL export with Run persistence key."""
    output_dir.mkdir(parents=True, exist_ok=True)

    # 1. Binary REGF hive (software.hiv)
    builder = SyntheticHiveBuilder(hive_name="SOFTWARE")
    tree = {
        "Microsoft": {
            "Windows": {
                "CurrentVersion": {
                    "Run": {
                        "@values": {
                            "SystemUpdater": (REG_SZ, r"C:\Users\Public\updater.exe"),
                        }
                    }
                }
            }
        }
    }
    raw_hive = builder.build_bytes(tree)
    hiv_path = output_dir / "software.hiv"
    hiv_path.write_bytes(raw_hive)

    # 2. JSONL fallback export (software_run.jsonl)
    jsonl_path = output_dir / "software_run.jsonl"
    record = {
        "KeyPath": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "ValueName": "SystemUpdater",
        "ValueData": r"C:\Users\Public\updater.exe",
        "LastWriteTimestamp": "2026-11-20T10:00:00Z",
    }
    with open(jsonl_path, "w", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")

    return {"binary_hive": hiv_path, "jsonl_export": jsonl_path}


def generate_known_answer_triage(output_dir: Path) -> Path:
    """Generate triage directory with processes, network connections, and security events."""
    output_dir.mkdir(parents=True, exist_ok=True)

    # 1. Processes JSONL: updater.exe spawned from services.exe
    proc_path = output_dir / "processes.jsonl"
    processes = [
        {
            "timestamp_utc": "2026-11-20T09:50:00Z",
            "process_name": "services.exe",
            "command_line": r"C:\Windows\system32\services.exe",
            "pid": 1024,
            "parent_pid": 600,
            "user": "NT AUTHORITY\\SYSTEM",
            "host": "WS-CORP-FINANCE",
        },
        {
            "timestamp_utc": "2026-11-20T10:02:00Z",
            "process_name": "updater.exe",
            "command_line": r"C:\Users\Public\updater.exe -d",
            "pid": 4120,
            "parent_pid": 1024,
            "user": "NT AUTHORITY\\SYSTEM",
            "host": "WS-CORP-FINANCE",
        },
    ]
    with open(proc_path, "w", encoding="utf-8") as f:
        for p in processes:
            f.write(json.dumps(p) + "\n")

    # 2. Network Connections JSONL: updater.exe connecting to C2 198.51.100.45:4444
    net_path = output_dir / "network_connections.jsonl"
    connections = [
        {
            "timestamp_utc": "2026-11-20T10:02:30Z",
            "process_name": "updater.exe",
            "pid": 4120,
            "src_ip": "10.0.0.45",
            "src_port": 49182,
            "dest_ip": "198.51.100.45",
            "dest_port": 4444,
            "protocol": "TCP",
            "state": "ESTABLISHED",
            "host": "WS-CORP-FINANCE",
        },
    ]
    with open(net_path, "w", encoding="utf-8") as f:
        for c in connections:
            f.write(json.dumps(c) + "\n")

    # 3. Security Events JSONL: Logon 4624 and Service Creation 7045
    evts_path = output_dir / "security_events.jsonl"
    events = [
        {
            "timestamp_utc": "2026-11-20T09:45:00Z",
            "event_id": "4624",
            "category": "logon",
            "severity": "info",
            "host": "WS-CORP-FINANCE",
            "user": "CORP\\Administrator",
            "logon_type": 10,
            "ip_address": "10.0.0.99",
            "summary": "Successful Remote Interactive Logon (Type 10)",
        },
        {
            "timestamp_utc": "2026-11-20T10:01:30Z",
            "event_id": "7045",
            "category": "service_creation",
            "severity": "high",
            "host": "WS-CORP-FINANCE",
            "user": "NT AUTHORITY\\SYSTEM",
            "service_name": "SystemUpdaterSvc",
            "image_path": r"C:\Users\Public\updater.exe",
            "summary": "Suspicious service installed executing C:\\Users\\Public\\updater.exe",
        },
    ]
    with open(evts_path, "w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")

    return output_dir


def ensure_known_answer_fixtures() -> Dict[str, Any]:
    """Materialize all known-answer attack fixtures deterministically."""
    reg = generate_known_answer_registry(KNOWN_ANSWER_DIR)
    triage = generate_known_answer_triage(TRIAGE_DIR)
    return {
        "software_hiv": reg["binary_hive"],
        "software_run_jsonl": reg["jsonl_export"],
        "triage_dir": triage,
    }


if __name__ == "__main__":
    res = ensure_known_answer_fixtures()
    for k, v in res.items():
        print(f"Generated {k}: {v}")
