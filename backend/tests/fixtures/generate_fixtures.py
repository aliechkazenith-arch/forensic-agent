"""Deterministic Test Fixture Generator for Phase 15-A Forensic Integration Testing.

Generates:
1. minimal_mbr.raw - Valid 512-byte MBR sector with 2 partition entries and 0x55AA signature.
2. minimal_system.hiv - Valid 4096-byte Windows Registry REGF header with valid XOR-32 checksum.
3. triage_archive/ - Directory containing processes.jsonl, network_connections.jsonl, and security_events.jsonl.
4. minimal.pcap - Valid 24-byte libpcap global header + 1 sample Ethernet/IPv4 packet.
5. minimal.pcapng - Valid PCAPNG Section Header Block (SHB) + Interface Description Block (IDB).
"""
from __future__ import annotations

import json
import struct
from pathlib import Path

FIXTURES_DIR = Path(__file__).resolve().parent


def compute_regf_checksum(header_bytes: bytes) -> int:
    """Compute REGF Base Block XOR-32 checksum over the first 508 bytes (127 DWORDs)."""
    chk = 0
    for i in range(127):
        chk ^= struct.unpack_from("<I", header_bytes, i * 4)[0]
    if chk == 0:
        return 1
    elif chk == 0xFFFFFFFF:
        return 0xFFFFFFFE
    return chk


def generate_mbr_disk_image(output_path: Path) -> Path:
    """Generate minimal valid flat raw MBR disk image (4096 bytes, 8 sectors of 512 bytes)."""
    data = bytearray(4096)

    # Sector 0: MBR (512 bytes)
    # Partition 1 at offset 446 (16 bytes): Bootable NTFS partition
    # Format: <B 3s B 3s I I
    # boot_flag=0x80 (bootable), start_chs=0x000200, part_type=0x07 (NTFS/exFAT), end_chs=0x002000, start_lba=2048, size_sectors=20480
    struct.pack_into(
        "<B3sB3sII",
        data,
        446,
        0x80,
        b"\x00\x02\x00",
        0x07,
        b"\x00\x20\x00",
        2048,
        20480,
    )

    # Partition 2 at offset 462 (16 bytes): Linux native partition
    # boot_flag=0x00, start_chs=0x000200, part_type=0x83 (Linux), end_chs=0x002000, start_lba=22528, size_sectors=40960
    struct.pack_into(
        "<B3sB3sII",
        data,
        462,
        0x00,
        b"\x00\x02\x00",
        0x83,
        b"\x00\x20\x00",
        22528,
        40960,
    )

    # MBR Boot Signature at bytes 510:512 (0x55AA)
    data[510:512] = b"\x55\xaa"

    output_path.write_bytes(data)
    return output_path


def generate_registry_hive(output_path: Path) -> Path:
    """Generate valid 4096-byte REGF base block header with valid XOR-32 checksum."""
    data = bytearray(4096)
    # Magic
    data[0:4] = b"regf"
    # Sequences
    struct.pack_into("<II", data, 4, 1, 1)
    # Last written timestamp (approx 2026-01-01 in FILETIME: 133500000000000000)
    struct.pack_into("<Q", data, 12, 133500000000000000)
    # Major / Minor version: 1.3
    struct.pack_into("<II", data, 20, 1, 3)
    # File type: 0 (Normal), format: 1 (Direct memory)
    struct.pack_into("<II", data, 28, 0, 1)
    # Root cell offset: 0x20
    struct.pack_into("<I", data, 36, 0x20)
    # Hive bins data size: 4096
    struct.pack_into("<I", data, 40, 4096)
    # Clustering factor: 1
    struct.pack_into("<I", data, 44, 1)

    # Hive name in UTF-16LE at offset 48 (up to 64 bytes)
    hive_name = "SYSTEM".encode("utf-16le")
    data[48 : 48 + len(hive_name)] = hive_name

    # Checksum at offset 508 computed over first 508 bytes
    chk = compute_regf_checksum(bytes(data[:508]))
    struct.pack_into("<I", data, 508, chk)

    output_path.write_bytes(data)
    return output_path


def generate_triage_archive(output_dir: Path) -> Path:
    """Generate synthetic triage directory with JSONL collector extracts."""
    output_dir.mkdir(parents=True, exist_ok=True)

    # 1. Processes JSONL
    proc_path = output_dir / "processes.jsonl"
    processes = [
        {
            "timestamp_utc": "2026-11-20T10:00:00Z",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgA...",
            "pid": 4812,
            "parent_pid": 1024,
            "user": "DOMAIN\\Administrator",
            "host": "WS-FINANCE-01",
        },
        {
            "timestamp_utc": "2026-11-20T10:05:00Z",
            "process_name": "rundll32.exe",
            "command_line": "rundll32.exe C:\\Temp\\payload.dll,StartW",
            "pid": 5920,
            "parent_pid": 4812,
            "user": "DOMAIN\\Administrator",
            "host": "WS-FINANCE-01",
        },
    ]
    with open(proc_path, "w", encoding="utf-8") as f:
        for p in processes:
            f.write(json.dumps(p) + "\n")

    # 2. Network Connections JSONL
    net_path = output_dir / "network_connections.jsonl"
    connections = [
        {
            "timestamp_utc": "2026-11-20T10:01:00Z",
            "process_name": "powershell.exe",
            "src_ip": "10.0.0.15",
            "src_port": 49822,
            "dest_ip": "198.51.100.42",
            "dest_port": 443,
            "protocol": "TCP",
            "state": "ESTABLISHED",
            "host": "WS-FINANCE-01",
        },
    ]
    with open(net_path, "w", encoding="utf-8") as f:
        for c in connections:
            f.write(json.dumps(c) + "\n")

    # 3. Security Events JSONL
    evts_path = output_dir / "security_events.jsonl"
    events = [
        {
            "timestamp_utc": "2026-11-20T09:58:00Z",
            "event_id": "4624",
            "category": "logon",
            "severity": "info",
            "host": "WS-FINANCE-01",
            "user": "DOMAIN\\Administrator",
            "logon_type": 10,
            "ip_address": "10.0.0.99",
            "summary": "Successful Remote Interactive Logon (Type 10)",
        },
        {
            "timestamp_utc": "2026-11-20T10:06:00Z",
            "event_id": "7045",
            "category": "service_creation",
            "severity": "high",
            "host": "WS-FINANCE-01",
            "user": "NT AUTHORITY\\SYSTEM",
            "service_name": "EvilPersistenceSvc",
            "image_path": "C:\\Windows\\Temp\\evil.exe",
            "summary": "Suspicious service installed executing binary in Temp",
        },
    ]
    with open(evts_path, "w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")

    return output_dir


def generate_pcap(output_path: Path) -> Path:
    """Generate minimal valid 24-byte PCAP global header + 1 sample packet."""
    header = struct.pack(
        "<IHHiIII",
        0xA1B2C3D4,  # magic number (standard libpcap microsecond)
        2,           # version_major
        4,           # version_minor
        0,           # thiszone (GMT)
        0,           # sigfigs
        65535,       # snaplen
        1,           # network (LINKTYPE_ETHERNET)
    )

    # Ethernet packet payload (64 bytes):
    # Dest MAC (6), Src MAC (6), EtherType IPv4 0x0800 (2)
    eth_header = b"\x00\x0c\x29\x12\x34\x56\x00\x50\x56\xc0\x00\x08\x08\x00"
    # Minimal IPv4 header (20 bytes: 10.0.0.15 -> 198.51.100.42, protocol TCP 6)
    ip_header = bytes([
        0x45, 0x00, 0x00, 0x32,  # IPv4, IHL 5, Total length 50
        0x12, 0x34, 0x40, 0x00,  # ID 0x1234, Don't fragment
        0x40, 0x06, 0x00, 0x00,  # TTL 64, Protocol TCP (6), checksum 0
        10, 0, 0, 15,            # Src IP: 10.0.0.15
        198, 51, 100, 42,        # Dst IP: 198.51.100.42
    ])
    # Minimal TCP header (20 bytes: src port 49822, dst port 443, SYN flag)
    tcp_header = struct.pack(
        "!HHIIBBHHH",
        49822,       # src port
        443,         # dst port
        1000001,     # seq
        0,           # ack
        0x50,        # data offset (5 dwords)
        0x02,        # flags (SYN)
        64240,       # window size
        0,           # checksum
        0,           # urgent pointer
    )
    payload = eth_header + ip_header + tcp_header
    # Pad to 64 bytes
    if len(payload) < 64:
        payload += b"\x00" * (64 - len(payload))

    # Packet Header: ts_sec (4), ts_usec (4), incl_len (4), orig_len (4)
    packet_header = struct.pack("<IIII", 1700000000, 0, len(payload), len(payload))

    output_path.write_bytes(header + packet_header + payload)
    return output_path


def generate_pcapng(output_path: Path) -> Path:
    """Generate minimal valid PCAPNG Section Header Block (SHB) + Interface Description Block (IDB)."""
    # 1. Section Header Block (SHB) - 28 bytes
    shb = struct.pack(
        "<IIIIII",
        0x0A0D0D0A,  # Block Type (SHB)
        28,          # Block Total Length
        0x1A2B3C4D,  # Byte-Order Magic
        (1 << 16) | 0,  # Major (1), Minor (0)
        0xFFFFFFFFFFFFFFFF & 0xFFFFFFFF,  # Section Length (-1: not specified, low 32)
        28,          # Block Total Length trailing
    )

    # 2. Interface Description Block (IDB) - 20 bytes
    idb = struct.pack(
        "<IIHHI",
        0x00000001,  # Block Type (IDB)
        20,          # Block Total Length
        1,           # LinkType (1 = LINKTYPE_ETHERNET)
        0,           # Reserved
        65535,       # SnapLen
    )
    idb += struct.pack("<I", 20)  # Block Total Length trailing

    output_path.write_bytes(shb + idb)
    return output_path


def ensure_all_fixtures() -> Dict[str, Path]:
    """Generate all test fixtures if they do not exist."""
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    return {
        "mbr": generate_mbr_disk_image(FIXTURES_DIR / "minimal_mbr.raw"),
        "registry": generate_registry_hive(FIXTURES_DIR / "minimal_system.hiv"),
        "triage": generate_triage_archive(FIXTURES_DIR / "triage_archive"),
        "pcap": generate_pcap(FIXTURES_DIR / "minimal.pcap"),
        "pcapng": generate_pcapng(FIXTURES_DIR / "minimal.pcapng"),
    }


if __name__ == "__main__":
    fixtures = ensure_all_fixtures()
    for name, p in fixtures.items():
        print(f"Generated {name}: {p} ({p.stat().st_size if p.is_file() else 'dir'} bytes)")
