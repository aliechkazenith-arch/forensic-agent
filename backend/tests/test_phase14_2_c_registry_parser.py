"""Comprehensive Test Suite for Phase 14.2-C Windows Registry Hive Parser.

Covers all 32 requirements:
1. Valid hive identification
2. Invalid signature rejection
3. Truncated hive handling
4. Malformed header handling
5. Valid key parsing
6. Valid value parsing
7. Supported Registry data types (SZ, EXPAND_SZ, BINARY, DWORD, MULTI_SZ, QWORD)
8. Subkey traversal structures (lf, lh, li, ri)
9. Binary value preservation
10. Timestamp extraction (FILETIME to ISO-8601 UTC)
11. SYSTEM hive extraction
12. SOFTWARE hive extraction
13. SAM hive extraction & password hash redaction
14. SECURITY hive extraction & secrets redaction
15. NTUSER.DAT hive extraction (UserAssist ROT13, RunMRU, RecentDocs)
16. UsrClass.dat hive extraction (Shellbags)
17. Amcache.hve hive extraction (Inventory apps & files)
18. BCD hive extraction
19. Read-only verification
20. SHA-256 integrity
21. Corrupted key handling
22. Out-of-bounds cell offsets
23. Circular references / cycle detection
24. Oversized hive rejection
25. Deeply nested keys depth limit
26. Key count explosion limit
27. Timeout handling
28. Character encodings (ASCII & UTF-16LE)
29. DissectAdapter integration & provenance
30. Source key path in raw_reference
31. DuckDB storage and queryability
32. Intake endpoint classification
"""
import codecs
import hashlib
import os
import struct
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple
import pytest

from backend.app.api.intake import detect_artifact_type_from_name
from backend.app.core.config import get_settings
from backend.app.core.dissect_adapter import DissectAdapter
from backend.app.core.exceptions import (
    RegistryCorruptedError,
    RegistryInvalidSignatureError,
    RegistryParserError,
    RegistryResourceLimitError,
    RegistryTruncatedError,
)
from backend.app.core.registry_parser import (
    REG_BINARY,
    REG_DWORD,
    REG_EXPAND_SZ,
    REG_MULTI_SZ,
    REG_QWORD,
    REG_SZ,
    RegistryKey,
    WindowsRegistryHiveParser,
    compute_header_checksum,
    extract_forensic_artifacts,
    filetime_to_iso,
    identify_registry_hive,
    validate_hive_header,
)
from backend.app.core.storage import ForensicStore
from backend.app.models.findings import ForensicFinding


# --------------------------------------------------------------------------
# Synthetic Hive Generator Fixture / Helper
# --------------------------------------------------------------------------
class SyntheticHiveBuilder:
    """Constructs valid binary REGF files for testing."""

    def __init__(self, hive_name: str = "SYSTEM"):
        self.hive_name = hive_name
        self.bin_data = bytearray(8192)
        self.bin_data[:4] = b"hbin"
        struct.pack_into("<I", self.bin_data, 4, 0)
        struct.pack_into("<I", self.bin_data, 8, 8192)
        self.alloc_offset = 32  # Cells start after 32-byte hbin header

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
        if val_type == REG_DWORD:
            data_len = 4 | 0x80000000
            data_offset = val_data
        elif val_type in (REG_SZ, REG_EXPAND_SZ):
            raw_str = (str(val_data) + "\x00").encode("utf-16le")
            data_cell_off = self.alloc_cell(raw_str)
            data_len = len(raw_str)
            data_offset = data_cell_off
        elif val_type == REG_BINARY:
            raw_b = bytes(val_data)
            data_cell_off = self.alloc_cell(raw_b)
            data_len = len(raw_b)
            data_offset = data_cell_off
        elif val_type == REG_MULTI_SZ:
            raw_str = ("\x00".join(val_data) + "\x00\x00").encode("utf-16le")
            data_cell_off = self.alloc_cell(raw_str)
            data_len = len(raw_str)
            data_offset = data_cell_off
        elif val_type == REG_QWORD:
            raw_q = struct.pack("<Q", int(val_data))
            data_cell_off = self.alloc_cell(raw_q)
            data_len = 8
            data_offset = data_cell_off
        else:
            raw_b = bytes(val_data) if isinstance(val_data, (bytes, bytearray)) else str(val_data).encode("latin-1")
            data_cell_off = self.alloc_cell(raw_b)
            data_len = len(raw_b)
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
        subkey_list_type: str = "lf",
        name_encoding: str = "ascii",
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
            c_off = self.build_key(
                child_name, child_dict, is_root=False, subkey_list_type=subkey_list_type, name_encoding=name_encoding
            )
            child_nk_offsets.append((c_off, child_name))

        subkey_list_off = -1
        if child_nk_offsets:
            if subkey_list_type == "lf":
                sk_bytes = bytearray(b"lf" + struct.pack("<H", len(child_nk_offsets)))
                for c_off, c_name in child_nk_offsets:
                    hint = (c_name[:4].ljust(4, " ")).encode("latin-1")
                    sk_bytes += struct.pack("<I", c_off) + hint
                subkey_list_off = self.alloc_cell(bytes(sk_bytes))
            elif subkey_list_type == "lh":
                sk_bytes = bytearray(b"lh" + struct.pack("<H", len(child_nk_offsets)))
                for c_off, c_name in child_nk_offsets:
                    sk_bytes += struct.pack("<I", c_off) + struct.pack("<I", hash(c_name) & 0xFFFFFFFF)
                subkey_list_off = self.alloc_cell(bytes(sk_bytes))
            elif subkey_list_type == "li":
                sk_bytes = bytearray(b"li" + struct.pack("<H", len(child_nk_offsets)))
                for c_off, c_name in child_nk_offsets:
                    sk_bytes += struct.pack("<I", c_off)
                subkey_list_off = self.alloc_cell(bytes(sk_bytes))
            elif subkey_list_type == "ri":
                lf_bytes = bytearray(b"lf" + struct.pack("<H", len(child_nk_offsets)))
                for c_off, c_name in child_nk_offsets:
                    hint = (c_name[:4].ljust(4, " ")).encode("latin-1")
                    lf_bytes += struct.pack("<I", c_off) + hint
                lf_off = self.alloc_cell(bytes(lf_bytes))
                ri_bytes = bytearray(b"ri" + struct.pack("<H", 1) + struct.pack("<I", lf_off))
                subkey_list_off = self.alloc_cell(bytes(ri_bytes))

        # Build nk cell
        is_ascii = (name_encoding == "ascii")
        name_b = name.encode("latin-1") if is_ascii else name.encode("utf-16le")
        flags = 0x0020 if is_ascii else 0x0000
        if is_root:
            flags |= 0x0004

        nk = bytearray()
        nk += b"nk"
        nk += struct.pack("<H", flags)
        nk += struct.pack("<Q", 133500000000000000)  # FILETIME for approx 2026
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

    def build_bytes(
        self,
        tree: dict,
        subkey_list_type: str = "lf",
        name_encoding: str = "ascii",
        corrupt_checksum: bool = False,
    ) -> bytes:
        root_off = self.build_key(
            "Root", tree, is_root=True, subkey_list_type=subkey_list_type, name_encoding=name_encoding
        )
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
        if corrupt_checksum:
            chk ^= 0xDEADBEEF
        struct.pack_into("<I", header, 508, chk)
        return bytes(header + self.bin_data)


# --------------------------------------------------------------------------
# Test Cases 1 - 32
# --------------------------------------------------------------------------

def test_01_valid_hive_identification():
    """1. Valid hive identification: regf detected, header parsed correctly."""
    builder = SyntheticHiveBuilder(hive_name="SYSTEM")
    data = builder.build_bytes({"Select": {"@values": {"Current": (REG_DWORD, 1)}}})

    is_valid, family, hdr_info, detected_keys = identify_registry_hive(data)
    assert is_valid is True
    assert family == "SYSTEM"
    assert hdr_info["magic"] == "regf"
    assert hdr_info["checksum_valid"] is True
    assert "Select" in detected_keys


def test_02_invalid_signature_rejection():
    """2. Invalid signature rejection: non-regf files rejected with RegistryInvalidSignatureError."""
    bad_data = b"NOT_A_REGISTRY_HIVE" + (b"\x00" * 4096)
    parser = WindowsRegistryHiveParser()
    with pytest.raises(RegistryInvalidSignatureError):
        parser.parse_bytes(bad_data)


def test_03_truncated_hive_handling():
    """3. Truncated hive handling: files < 4096 bytes or truncated bins raise RegistryTruncatedError."""
    short_data = b"regf" + (b"\x00" * 100)
    parser = WindowsRegistryHiveParser()
    with pytest.raises(RegistryTruncatedError):
        parser.parse_bytes(short_data)


def test_04_malformed_header_handling():
    """4. Malformed header handling: corrupted header checksum raises RegistryCorruptedError."""
    builder = SyntheticHiveBuilder(hive_name="SYSTEM")
    corrupt_data = builder.build_bytes({"Test": {}}, corrupt_checksum=True)
    parser = WindowsRegistryHiveParser()
    with pytest.raises(RegistryCorruptedError):
        parser.parse_bytes(corrupt_data, validate_checksum=True)


def test_05_valid_key_parsing():
    """5. Valid key parsing: root key and nested keys correctly parsed."""
    tree = {
        "Level1": {
            "Level2": {
                "Level3": {
                    "@values": {"TargetVal": (REG_SZ, "Success")},
                }
            }
        }
    }
    raw = SyntheticHiveBuilder("SOFTWARE").build_bytes(tree)
    parser = WindowsRegistryHiveParser()
    root = parser.parse_bytes(raw)

    assert "Level1" in root.subkeys
    l2 = root.get_key(r"Level1\Level2")
    assert l2 is not None
    l3 = root.get_key(r"Level1\Level2\Level3")
    assert l3 is not None
    assert l3.get_value("TargetVal").data == "Success"


def test_06_valid_value_parsing():
    """6. Valid value parsing: values associated with keys correctly parsed."""
    tree = {
        "Config": {
            "@values": {
                "HostName": (REG_SZ, "forensics-vm"),
                "Port": (REG_DWORD, 8080),
            }
        }
    }
    raw = SyntheticHiveBuilder("SYSTEM").build_bytes(tree)
    parser = WindowsRegistryHiveParser()
    root = parser.parse_bytes(raw)

    cfg = root.get_key("Config")
    assert cfg is not None
    assert cfg.get_value("HostName").data == "forensics-vm"
    assert cfg.get_value("Port").data == 8080


def test_07_supported_registry_data_types():
    """7. Supported Registry data types (SZ, EXPAND_SZ, BINARY, DWORD, MULTI_SZ, QWORD)."""
    tree = {
        "TypesKey": {
            "@values": {
                "StringVal": (REG_SZ, "A standard string"),
                "ExpandVal": (REG_EXPAND_SZ, "%SystemRoot%\\System32"),
                "BinVal": (REG_BINARY, b"\xDE\xAD\xBE\xEF\x01\x02\x03\x04"),
                "DwordVal": (REG_DWORD, 1337),
                "MultiVal": (REG_MULTI_SZ, ["Line1", "Line2", "Line3"]),
                "QwordVal": (REG_QWORD, 0x1122334455667788),
            }
        }
    }
    raw = SyntheticHiveBuilder("SYSTEM").build_bytes(tree)
    parser = WindowsRegistryHiveParser()
    root = parser.parse_bytes(raw)

    k = root.get_key("TypesKey")
    assert k.get_value("StringVal").data == "A standard string"
    assert k.get_value("ExpandVal").data == "%SystemRoot%\\System32"
    assert k.get_value("BinVal").data == b"\xDE\xAD\xBE\xEF\x01\x02\x03\x04"
    assert k.get_value("DwordVal").data == 1337
    assert k.get_value("MultiVal").data == ["Line1", "Line2", "Line3"]
    assert k.get_value("QwordVal").data == 0x1122334455667788


@pytest.mark.parametrize("list_type", ["lf", "lh", "li", "ri"])
def test_08_subkey_traversal_structures(list_type):
    """8. Subkey traversal structures (lf, lh, li, ri) correctly traversed."""
    tree = {
        "Alpha": {"@values": {"idx": (REG_DWORD, 1)}},
        "Beta": {"@values": {"idx": (REG_DWORD, 2)}},
        "Gamma": {"@values": {"idx": (REG_DWORD, 3)}},
    }
    raw = SyntheticHiveBuilder("SYSTEM").build_bytes(tree, subkey_list_type=list_type)
    parser = WindowsRegistryHiveParser()
    root = parser.parse_bytes(raw)

    assert "Alpha" in root.subkeys
    assert "Beta" in root.subkeys
    assert "Gamma" in root.subkeys
    assert root.get_key("Beta").get_value("idx").data == 2


def test_09_binary_value_preservation():
    """9. Binary value preservation: REG_BINARY preserved byte-for-byte."""
    payload = bytes(range(256))  # All 256 byte values
    tree = {"BinCheck": {"@values": {"AllBytes": (REG_BINARY, payload)}}}
    raw = SyntheticHiveBuilder("SYSTEM").build_bytes(tree)
    parser = WindowsRegistryHiveParser()
    root = parser.parse_bytes(raw)

    val = root.get_key("BinCheck").get_value("AllBytes")
    assert val.data_raw == payload
    assert val.data == payload


def test_10_timestamp_extraction():
    """10. Timestamp extraction: FILETIME converted to ISO-8601 UTC."""
    # FILETIME 133500000000000000 = approx 2024-01-18T10:40:00Z
    iso = filetime_to_iso(133500000000000000)
    assert iso is not None
    assert iso.endswith("Z")
    assert "2024" in iso or "2023" in iso or "2025" in iso

    # 0 or negative FILETIME yields None
    assert filetime_to_iso(0) is None
    assert filetime_to_iso(-100) is None


def test_11_system_hive_extraction():
    """11. SYSTEM hive extraction: CurrentControlSet, ComputerName, TimeZone, Services & Drivers."""
    tree = {
        "Select": {"@values": {"Current": (REG_DWORD, 1)}},
        "ControlSet001": {
            "Control": {
                "ComputerName": {
                    "ComputerName": {"@values": {"ComputerName": (REG_SZ, "DFIR-INVESTIGATOR")}},
                },
                "TimeZoneInformation": {
                    "@values": {"TimeZoneKeyName": (REG_SZ, "UTC"), "ActiveTimeBias": (REG_DWORD, 0)},
                },
            },
            "Services": {
                "LegitSvc": {
                    "@values": {"ImagePath": (REG_SZ, "C:\\Windows\\System32\\svchost.exe"), "Start": (REG_DWORD, 2)},
                },
                "RansomwareSvc": {
                    "@values": {
                        "ImagePath": (REG_SZ, "C:\\Users\\Public\\Temp\\crypt.exe"),
                        "Start": (REG_DWORD, 2),
                    },
                },
            },
            "Enum": {
                "USBSTOR": {
                    "Disk&Ven_SanDisk": {
                        "0123456789": {"@values": {"FriendlyName": (REG_SZ, "SanDisk Ultra USB 3.0")}},
                    }
                }
            },
        },
    }
    raw = SyntheticHiveBuilder("SYSTEM").build_bytes(tree)
    parser = WindowsRegistryHiveParser()
    parser.parse_bytes(raw)

    findings = extract_forensic_artifacts(parser, parser.header, "case_sys", "art_sys", "hash_sys")
    categories = [f.category for f in findings]

    assert "registry_hive" in categories
    assert "system_config" in categories
    assert "service_installed" in categories
    assert "service_suspicious" in categories
    assert "usb_device" in categories

    susp = next(f for f in findings if f.category == "service_suspicious")
    assert susp.severity == "high"
    assert "RansomwareSvc" in susp.summary
    assert "C:\\Users\\Public\\Temp\\crypt.exe" in susp.command_line


def test_12_software_hive_extraction():
    """12. SOFTWARE hive extraction: OS build, installed software, Run/RunOnce persistence."""
    tree = {
        "Microsoft": {
            "Windows NT": {
                "CurrentVersion": {
                    "@values": {
                        "ProductName": (REG_SZ, "Windows 10 Pro"),
                        "CurrentBuild": (REG_SZ, "19045"),
                    }
                }
            },
            "Windows": {
                "CurrentVersion": {
                    "Uninstall": {
                        "Git": {
                            "@values": {
                                "DisplayName": (REG_SZ, "Git version 2.40"),
                                "DisplayVersion": (REG_SZ, "2.40.0"),
                            }
                        }
                    },
                    "Run": {
                        "@values": {
                            "EvilRun": (REG_SZ, "powershell.exe -enc AAAA"),
                        }
                    },
                }
            },
        }
    }
    raw = SyntheticHiveBuilder("SOFTWARE").build_bytes(tree)
    parser = WindowsRegistryHiveParser()
    parser.parse_bytes(raw)

    findings = extract_forensic_artifacts(parser, parser.header, "case_soft", "art_soft", "hash_soft")
    cats = [f.category for f in findings]

    assert "os_version" in cats
    assert "installed_program" in cats
    assert "persistence_registry" in cats

    persist = next(f for f in findings if f.category == "persistence_registry")
    assert persist.severity == "high"
    assert "powershell" in persist.command_line


def test_13_sam_hive_extraction_security():
    """13. SAM hive: user accounts, RIDs, last logon; password hashes NOT exposed."""
    tree = {
        "SAM": {
            "Domains": {
                "Account": {
                    "Users": {
                        "Names": {
                            "Administrator": {"@values": {}},
                        },
                        "000001F4": {
                            "@values": {
                                # Synthetic 'F' structure with last logon FILETIME at offset 8
                                "F": (REG_BINARY, b"\x00" * 8 + struct.pack("<Q", 133500000000000000) + b"\x00" * 40),
                                "V": (REG_BINARY, b"MOCK_USER_METADATA_NO_HASHES"),
                            }
                        },
                    }
                }
            }
        }
    }
    raw = SyntheticHiveBuilder("SAM").build_bytes(tree)
    parser = WindowsRegistryHiveParser()
    parser.parse_bytes(raw)

    findings = extract_forensic_artifacts(parser, parser.header, "case_sam", "art_sam", "hash_sam")
    sam_finds = [f for f in findings if f.category == "user_account_sam"]
    assert len(sam_finds) == 1
    f = sam_finds[0]

    assert f.projected_data["RID"] == 500  # 0x1F4 = 500
    assert f.projected_data["PasswordHashes"] == "REDACTED_BY_FORENSIC_SECURITY_POLICY"
    # Ensure no hashes in findings
    for find in findings:
        for k, v in find.projected_data.items():
            assert "hash" not in str(v).lower() or v == "REDACTED_BY_FORENSIC_SECURITY_POLICY"


def test_14_security_hive_extraction():
    """14. SECURITY hive: LSA secrets / policy metadata safely handled, secrets redacted."""
    tree = {
        "Policy": {
            "PolAdtEv": {
                "@values": {"AuditPolicy": (REG_BINARY, b"\x01\x00\x00\x00")},
            }
        }
    }
    raw = SyntheticHiveBuilder("SECURITY").build_bytes(tree)
    parser = WindowsRegistryHiveParser()
    parser.parse_bytes(raw)

    findings = extract_forensic_artifacts(parser, parser.header, "case_sec", "art_sec", "hash_sec")
    sec_finds = [f for f in findings if f.category == "security_policy"]
    assert len(sec_finds) == 1
    assert sec_finds[0].projected_data["Secrets"] == "REDACTED_BY_FORENSIC_SECURITY_POLICY"


def test_15_ntuser_hive_extraction():
    """15. NTUSER.DAT: RunMRU, RecentDocs, UserAssist (ROT13), TypedPaths, Run keys."""
    # ROT13 for "calc.exe" is "pnyc.rkr"
    rot13_calc = codecs.encode("calc.exe", "rot_13")
    # Synthetic 72-byte UserAssist entry with run count=5 at offset 4, FILETIME at offset 60
    ua_entry = bytearray(72)
    struct.pack_into("<I", ua_entry, 4, 5)  # 5 runs
    struct.pack_into("<Q", ua_entry, 60, 133500000000000000)

    tree = {
        "Software": {
            "Microsoft": {
                "Windows": {
                    "CurrentVersion": {
                        "Explorer": {
                            "RunMRU": {
                                "@values": {
                                    "MRUList": (REG_SZ, "ab"),
                                    "a": (REG_SZ, "cmd.exe\\1"),
                                    "b": (REG_SZ, "notepad.exe\\1"),
                                }
                            },
                            "RecentDocs": {
                                "@values": {
                                    "0": (REG_BINARY, "secret_report.docx\x00".encode("utf-16le")),
                                }
                            },
                            "UserAssist": {
                                "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}": {
                                    "Count": {
                                        "@values": {
                                            rot13_calc: (REG_BINARY, bytes(ua_entry)),
                                        }
                                    }
                                }
                            },
                            "TypedPaths": {
                                "@values": {
                                    "url1": (REG_SZ, "C:\\SecretProject"),
                                }
                            },
                        },
                        "Run": {
                            "@values": {
                                "UserBackdoor": (REG_SZ, "C:\\Users\\Bob\\AppData\\Roaming\\agent.exe"),
                            }
                        },
                    }
                }
            }
        }
    }
    raw = SyntheticHiveBuilder("NTUSER").build_bytes(tree)
    parser = WindowsRegistryHiveParser()
    parser.parse_bytes(raw)

    findings = extract_forensic_artifacts(parser, parser.header, "case_nt", "art_nt", "hash_nt")
    cats = [f.category for f in findings]

    assert "user_activity_runmru" in cats
    assert "user_activity_recent" in cats
    assert "userassist_execution" in cats
    assert "user_typed_path" in cats
    assert "persistence_registry_user" in cats

    ua = next(f for f in findings if f.category == "userassist_execution")
    assert ua.projected_data["DecodedProgramPath"] == "calc.exe"
    assert ua.projected_data["RunCount"] == 5


def test_16_usrclass_hive_extraction():
    """16. UsrClass.dat: Shellbags / user interaction artifacts."""
    tree = {
        "Local Settings": {
            "Software": {
                "Microsoft": {
                    "Windows": {
                        "Shell": {
                            "Bags": {
                                "1": {"@values": {"NodeSlot": (REG_DWORD, 1)}},
                            }
                        }
                    }
                }
            }
        }
    }
    raw = SyntheticHiveBuilder("USRCLASS").build_bytes(tree)
    parser = WindowsRegistryHiveParser()
    parser.parse_bytes(raw)

    findings = extract_forensic_artifacts(parser, parser.header, "case_usr", "art_usr", "hash_usr")
    cats = [f.category for f in findings]
    assert "shellbags_activity" in cats


def test_17_amcache_hive_extraction():
    """17. Amcache.hve: inventory applications, file execution records."""
    tree = {
        "Root": {
            "InventoryApplication": {
                "guid-1": {
                    "@values": {
                        "Name": (REG_SZ, "TargetSoftware"),
                        "Version": (REG_SZ, "1.2.3"),
                        "Publisher": (REG_SZ, "TargetCorp"),
                    }
                }
            },
            "InventoryApplicationFile": {
                "file-hash-1": {
                    "@values": {
                        "Name": (REG_SZ, "evil.exe"),
                        "LowerCaseLongPath": (REG_SZ, "c:\\temp\\evil.exe"),
                        "Sha1": (REG_SZ, "44a9f939e1026048d0cf4e98f7e53f18e5900593"),
                        "Size": (REG_DWORD, 40960),
                    }
                }
            },
        }
    }
    raw = SyntheticHiveBuilder("AMCACHE").build_bytes(tree)
    parser = WindowsRegistryHiveParser()
    parser.parse_bytes(raw)

    findings = extract_forensic_artifacts(parser, parser.header, "case_amc", "art_amc", "hash_amc")
    cats = [f.category for f in findings]
    assert "amcache_inventory_app" in cats
    assert "amcache_file_record" in cats


def test_18_bcd_hive_extraction():
    """18. BCD: boot objects correctly identified."""
    tree = {
        "Objects": {
            "{9dea862c-5cdd-4e70-acc1-f32b344d4795}": {
                "Elements": {"@values": {}},
            }
        }
    }
    raw = SyntheticHiveBuilder("BCD").build_bytes(tree)
    parser = WindowsRegistryHiveParser()
    parser.parse_bytes(raw)

    findings = extract_forensic_artifacts(parser, parser.header, "case_bcd", "art_bcd", "hash_bcd")
    cats = [f.category for f in findings]
    assert "bcd_boot_object" in cats


def test_19_readonly_verification(tmp_path):
    """19. Read-only verification: source evidence files are never modified."""
    tree = {"Key1": {"@values": {"Val1": (REG_SZ, "Test")}}}
    raw = SyntheticHiveBuilder("SYSTEM").build_bytes(tree)
    hive_path = tmp_path / "READONLY.hiv"
    hive_path.write_bytes(raw)

    # Set file read-only on filesystem
    os.chmod(hive_path, 0o400)

    adapter = DissectAdapter()
    findings = adapter.parse_registry_hive(hive_path, "c", "a", "h")
    assert len(findings) >= 1

    # Verify content still bit-identical
    assert hive_path.read_bytes() == raw


def test_20_sha256_integrity(tmp_path):
    """20. SHA-256 integrity: hash computed before and verified identical after parsing."""
    raw = SyntheticHiveBuilder("SYSTEM").build_bytes({"Test": {}})
    hive_path = tmp_path / "HASHCHECK.hiv"
    hive_path.write_bytes(raw)

    before_hash = hashlib.sha256(hive_path.read_bytes()).hexdigest()
    parser = WindowsRegistryHiveParser()
    parser.parse_file(hive_path)
    after_hash = hashlib.sha256(hive_path.read_bytes()).hexdigest()

    assert before_hash == after_hash


def test_21_corrupted_key_handling():
    """21. Corrupted key handling: corrupted subkey does not crash parser; warning recorded."""
    builder = SyntheticHiveBuilder("SYSTEM")
    # Allocate a corrupted cell with non-nk signature
    bad_cell_off = builder.alloc_cell(b"CORRUPTED_CELL_DATA")
    # Build lf list with bad cell pointer
    sk_bytes = bytearray(b"lf" + struct.pack("<H", 1))
    sk_bytes += struct.pack("<I", bad_cell_off) + b"BAD "
    lf_off = builder.alloc_cell(bytes(sk_bytes))

    # Manually pack root key pointing to bad subkey list
    root_nk = bytearray()
    root_nk += b"nk"
    root_nk += struct.pack("<H", 0x0024)
    root_nk += struct.pack("<Q", 133500000000000000)
    root_nk += struct.pack("<I", 0)
    root_nk += struct.pack("<i", 0)
    root_nk += struct.pack("<I", 1)  # 1 subkey
    root_nk += struct.pack("<I", 0)
    root_nk += struct.pack("<i", lf_off)  # points to list with bad cell
    root_nk += struct.pack("<i", -1)
    root_nk += struct.pack("<I", 0)
    root_nk += struct.pack("<i", -1)
    root_nk += struct.pack("<i", -1)
    root_nk += struct.pack("<i", -1)
    root_nk += struct.pack("<I", 0)
    root_nk += struct.pack("<I", 0)
    root_nk += struct.pack("<I", 0)
    root_nk += struct.pack("<I", 0)
    root_nk += struct.pack("<I", 0)
    root_nk += struct.pack("<H", 4)
    root_nk += struct.pack("<H", 0)
    root_nk += b"Root"
    root_off = builder.alloc_cell(bytes(root_nk))

    header = bytearray(4096)
    header[:4] = b"regf"
    struct.pack_into("<I", header, 36, root_off)
    struct.pack_into("<I", header, 40, len(builder.bin_data))
    chk = compute_header_checksum(header)
    struct.pack_into("<I", header, 508, chk)
    raw = bytes(header + builder.bin_data)

    parser = WindowsRegistryHiveParser()
    root = parser.parse_bytes(raw)
    assert root.name == "Root"
    # Corruption was handled gracefully and recorded in warnings
    assert len(parser.warnings) > 0


def test_22_out_of_bounds_cell_offsets():
    """22. Out-of-bounds cell offsets: handled gracefully without crashing parser."""
    builder = SyntheticHiveBuilder("SYSTEM")
    # Subkey list pointing to astronomical cell offset
    sk_bytes = bytearray(b"lf" + struct.pack("<H", 1))
    sk_bytes += struct.pack("<I", 999999999) + b"OOB "
    lf_off = builder.alloc_cell(bytes(sk_bytes))

    root_nk = bytearray()
    root_nk += b"nk"
    root_nk += struct.pack("<H", 0x0024)
    root_nk += struct.pack("<Q", 133500000000000000)
    root_nk += struct.pack("<I", 0)
    root_nk += struct.pack("<i", 0)
    root_nk += struct.pack("<I", 1)
    root_nk += struct.pack("<I", 0)
    root_nk += struct.pack("<i", lf_off)
    root_nk += struct.pack("<i", -1)
    root_nk += struct.pack("<I", 0)
    root_nk += struct.pack("<i", -1)
    root_nk += struct.pack("<i", -1)
    root_nk += struct.pack("<i", -1)
    root_nk += struct.pack("<I", 0)
    root_nk += struct.pack("<I", 0)
    root_nk += struct.pack("<I", 0)
    root_nk += struct.pack("<I", 0)
    root_nk += struct.pack("<I", 0)
    root_nk += struct.pack("<H", 4)
    root_nk += struct.pack("<H", 0)
    root_nk += b"Root"
    root_off = builder.alloc_cell(bytes(root_nk))

    header = bytearray(4096)
    header[:4] = b"regf"
    struct.pack_into("<I", header, 36, root_off)
    struct.pack_into("<I", header, 40, len(builder.bin_data))
    chk = compute_header_checksum(header)
    struct.pack_into("<I", header, 508, chk)
    raw = bytes(header + builder.bin_data)

    parser = WindowsRegistryHiveParser()
    root = parser.parse_bytes(raw)
    assert root.name == "Root"
    assert len(parser.warnings) > 0


def test_23_circular_references_cycle_detection():
    """23. Circular references / cycle detection: terminates safely without infinite loop."""
    builder = SyntheticHiveBuilder("SYSTEM")

    # Allocate root_nk first
    root_nk = bytearray()
    root_nk += b"nk"
    root_nk += struct.pack("<H", 0x0024)
    root_nk += struct.pack("<Q", 133500000000000000)
    root_nk += struct.pack("<I", 0)
    root_nk += struct.pack("<i", 0)
    root_nk += struct.pack("<I", 1)  # 1 subkey
    root_nk += struct.pack("<I", 0)
    root_nk += struct.pack("<i", -1)  # will patch after allocating lf
    root_nk += struct.pack("<i", -1)
    root_nk += struct.pack("<I", 0)
    root_nk += struct.pack("<i", -1)
    root_nk += struct.pack("<i", -1)
    root_nk += struct.pack("<i", -1)
    root_nk += struct.pack("<I", 0)
    root_nk += struct.pack("<I", 0)
    root_nk += struct.pack("<I", 0)
    root_nk += struct.pack("<I", 0)
    root_nk += struct.pack("<I", 0)
    root_nk += struct.pack("<H", 4)
    root_nk += struct.pack("<H", 0)
    root_nk += b"Root"
    actual_root_off = builder.alloc_cell(bytes(root_nk))

    # Allocate subkey list pointing back to actual_root_off
    sk_bytes = bytearray(b"lf" + struct.pack("<H", 1))
    sk_bytes += struct.pack("<I", actual_root_off) + b"CYCL"
    lf_off = builder.alloc_cell(bytes(sk_bytes))

    # Patch root's subkey_list_offset (offset 28 in nk data -> cell_data offset +4)
    struct.pack_into("<i", builder.bin_data, actual_root_off + 4 + 28, lf_off)

    header = bytearray(4096)
    header[:4] = b"regf"
    struct.pack_into("<I", header, 36, actual_root_off)
    struct.pack_into("<I", header, 40, len(builder.bin_data))
    chk = compute_header_checksum(header)
    struct.pack_into("<I", header, 508, chk)
    raw = bytes(header + builder.bin_data)

    parser = WindowsRegistryHiveParser()
    root = parser.parse_bytes(raw)
    assert root is not None
    # Cycle skipped without hanging
    assert any("Cycle detected" in w for w in parser.warnings)


def test_24_oversized_hive_rejection():
    """24. Oversized hive rejection: rejected if exceeding size limit."""
    raw = SyntheticHiveBuilder("SYSTEM").build_bytes({"Test": {}})
    # Set limit to 100 bytes
    parser = WindowsRegistryHiveParser(max_size_bytes=100)
    with pytest.raises(RegistryResourceLimitError):
        parser.parse_bytes(raw)


def test_25_deeply_nested_keys_depth_limit():
    """25. Deeply nested keys depth limit: recursion bounded by max depth limit."""
    # Build 10-level nested hierarchy
    curr = {"@values": {"leaf": (REG_SZ, "deep")}}
    for i in range(10):
        curr = {f"Level_{10 - i}": curr}

    raw = SyntheticHiveBuilder("SYSTEM").build_bytes(curr)
    # Set max depth to 3
    parser = WindowsRegistryHiveParser(max_depth=3)
    with pytest.raises(RegistryResourceLimitError):
        parser.parse_bytes(raw)


def test_26_key_count_explosion_limit():
    """26. Key count explosion limit: key count bounded by limit."""
    tree = {f"Key_{i}": {"@values": {"val": (REG_DWORD, i)}} for i in range(50)}
    raw = SyntheticHiveBuilder("SYSTEM").build_bytes(tree)
    # Limit max keys to 10
    parser = WindowsRegistryHiveParser(max_keys=10)
    with pytest.raises(RegistryResourceLimitError):
        parser.parse_bytes(raw)


def test_27_timeout_handling():
    """27. Timeout handling: long-running parse aborted by timeout."""
    tree = {f"Key_{i}": {} for i in range(20)}
    raw = SyntheticHiveBuilder("SYSTEM").build_bytes(tree)
    # Set max_parse_seconds to 0.0000001 (triggers timeout immediately)
    parser = WindowsRegistryHiveParser(max_parse_seconds=0.0000001)
    with pytest.raises(RegistryResourceLimitError):
        parser.parse_bytes(raw)


def test_28_character_encodings():
    """28. Character encodings: ASCII and UTF-16LE key and value names parsed correctly."""
    # Test UTF-16LE key names
    tree = {
        "Unicode_Key_テスト": {
            "@values": {
                "Val_Café": (REG_SZ, "Héllo Wörld"),
            }
        }
    }
    raw = SyntheticHiveBuilder("SOFTWARE").build_bytes(tree, name_encoding="utf16")
    parser = WindowsRegistryHiveParser()
    root = parser.parse_bytes(raw)

    found_key = next((k for k in root.subkeys.values() if "Unicode_Key" in k.name), None)
    assert found_key is not None
    val = found_key.get_value("Val_Café")
    assert val is not None
    assert val.data == "Héllo Wörld"


def test_29_dissect_adapter_integration(tmp_path):
    """29. DissectAdapter integration: parse_registry_hive returns ForensicFindings with provenance."""
    tree = {
        "Select": {"@values": {"Current": (REG_DWORD, 1)}},
        "ControlSet001": {
            "Control": {
                "ComputerName": {
                    "ComputerName": {"@values": {"ComputerName": (REG_SZ, "INTEGRATION-HOST")}},
                }
            }
        },
    }
    raw = SyntheticHiveBuilder("SYSTEM").build_bytes(tree)
    hive_path = tmp_path / "SYSTEM.hiv"
    hive_path.write_bytes(raw)

    adapter = DissectAdapter()
    findings = adapter.parse_registry_hive(
        hive_path=hive_path,
        case_id="case_integ_01",
        artifact_id="art_integ_01",
        artifact_hash="abc123hash",
    )

    assert len(findings) >= 2
    for f in findings:
        assert f.case_id == "case_integ_01"
        assert f.source_artifact_id == "art_integ_01"
        assert f.source_artifact_hash == "abc123hash"
        assert f.tool_id == "dissect_registry"
        assert f.artifact_type == "registry"


def test_30_source_key_path_provenance():
    """30. Source key path: each finding includes full key path in raw_reference."""
    tree = {
        "Select": {"@values": {"Current": (REG_DWORD, 1)}},
        "ControlSet001": {
            "Control": {
                "TimeZoneInformation": {"@values": {"TimeZoneKeyName": (REG_SZ, "UTC")}},
            }
        },
    }
    raw = SyntheticHiveBuilder("SYSTEM").build_bytes(tree)
    parser = WindowsRegistryHiveParser()
    parser.parse_bytes(raw)

    findings = extract_forensic_artifacts(parser, parser.header, "c", "a", "h")
    tz_find = next(f for f in findings if "TimeZoneInformation" in f.raw_reference)
    assert tz_find.raw_reference == r"HKLM\SYSTEM\ControlSet001\Control\TimeZoneInformation"


def test_31_duckdb_storage_queryability(tmp_path):
    """31. DuckDB queryability: registry findings can be inserted into ForensicStore and queried."""
    db_path = tmp_path / "forensic_test.duckdb"
    store = ForensicStore(db_path=db_path)

    finding = ForensicFinding(
        case_id="case_duck_01",
        source_artifact_id="art_duck_01",
        source_artifact_hash="hash_duck_01",
        tool_id="dissect_registry",
        tool_version="1.0.0",
        timestamp_utc="2026-03-30T12:00:00Z",
        artifact_type="registry",
        category="system_config",
        severity="info",
        raw_reference=r"HKLM\SYSTEM\Select",
        summary="Active Control Set resolved to ControlSet001",
        projected_data={"ActiveControlSet": "ControlSet001"},
    )

    store.insert_findings([finding])
    queried = store.query_structured_findings(case_id="case_duck_01")
    assert len(queried) == 1
    assert queried[0].category == "system_config"
    assert queried[0].raw_reference == r"HKLM\SYSTEM\Select"


def test_32_intake_endpoint_classification():
    """32. Intake endpoint: registry files ingested and correctly classified by intake.py."""
    assert detect_artifact_type_from_name("SYSTEM") == "registry"
    assert detect_artifact_type_from_name("SOFTWARE.hiv") == "registry"
    assert detect_artifact_type_from_name("SAM") == "registry"
    assert detect_artifact_type_from_name("SECURITY") == "registry"
    assert detect_artifact_type_from_name("NTUSER.DAT") == "registry"
    assert detect_artifact_type_from_name("UsrClass.dat") == "registry"
    assert detect_artifact_type_from_name("Amcache.hve") == "registry"
    assert detect_artifact_type_from_name("BCD") == "registry"
    assert detect_artifact_type_from_name("random.hve") == "registry"
    assert detect_artifact_type_from_name("arbitrary.dat") == "file"  # generic .dat remains file
