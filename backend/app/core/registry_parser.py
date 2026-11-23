"""Windows Registry Hive Binary Parser (Pure Python, Zero-Dependency, Offline DFIR).

Standards & Forensic Requirements:
- RFC 3227 & NIST SP 800-86
- REGF Base Block (4096 bytes) and XOR-32 checksum verification (offset 508)
- Hive Bins ('hbin') and cell-level allocation logic
- Named Key ('nk'), Value Key ('vk'), Subkey lists ('lf', 'lh', 'li', 'ri')
- Rich forensic artifact extraction across SYSTEM, SOFTWARE, SAM, SECURITY,
  NTUSER.DAT, UsrClass.dat, Amcache.hve, and BCD.
- Complete provenance: cryptographic hash binding, exact key path raw references,
  non-destructive read-only access.
- Security limits: bounds checking, cycle detection, max depth, max keys, timeout.
- Password hashes from SAM/SECURITY are NEVER exposed.
"""
from __future__ import annotations

import codecs
import hashlib
import logging
import os
import struct
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple, Union

from backend.app.core.config import get_settings
from backend.app.core.exceptions import (
    RegistryCorruptedError,
    RegistryInvalidSignatureError,
    RegistryParserError,
    RegistryResourceLimitError,
    RegistryTruncatedError,
)
from backend.app.models.findings import ForensicFinding

logger = logging.getLogger(__name__)

# Registry Data Types (WinNT.h)
REG_NONE = 0x0000
REG_SZ = 0x0001
REG_EXPAND_SZ = 0x0002
REG_BINARY = 0x0003
REG_DWORD = 0x0004
REG_DWORD_LITTLE_ENDIAN = 0x0004
REG_DWORD_BIG_ENDIAN = 0x0005
REG_LINK = 0x0006
REG_MULTI_SZ = 0x0007
REG_RESOURCE_LIST = 0x0008
REG_FULL_RESOURCE_DESCRIPTOR = 0x0009
REG_RESOURCE_REQUIREMENTS_LIST = 0x000A
REG_QWORD = 0x000B
REG_QWORD_LITTLE_ENDIAN = 0x000B

REG_TYPE_NAMES: Dict[int, str] = {
    REG_NONE: "REG_NONE",
    REG_SZ: "REG_SZ",
    REG_EXPAND_SZ: "REG_EXPAND_SZ",
    REG_BINARY: "REG_BINARY",
    REG_DWORD: "REG_DWORD",
    REG_DWORD_BIG_ENDIAN: "REG_DWORD_BIG_ENDIAN",
    REG_LINK: "REG_LINK",
    REG_MULTI_SZ: "REG_MULTI_SZ",
    REG_RESOURCE_LIST: "REG_RESOURCE_LIST",
    REG_FULL_RESOURCE_DESCRIPTOR: "REG_FULL_RESOURCE_DESCRIPTOR",
    REG_RESOURCE_REQUIREMENTS_LIST: "REG_RESOURCE_REQUIREMENTS_LIST",
    REG_QWORD: "REG_QWORD",
}


def data_type_to_name(dt: int) -> str:
    """Return descriptive name for Windows Registry data type ID."""
    return REG_TYPE_NAMES.get(dt, f"REG_UNKNOWN_{dt}")


def filetime_to_iso(ft: int) -> Optional[str]:
    """Convert Windows 64-bit FILETIME (100-ns intervals since 1601-01-01) to ISO-8601 UTC string."""
    if ft <= 0:
        return None
    # 116444736000000000 is 1601-01-01 to 1970-01-01 in 100-ns intervals
    epoch_seconds = (ft - 116444736000000000) / 10000000.0
    if epoch_seconds <= 0:
        return None
    try:
        dt = datetime.fromtimestamp(epoch_seconds, timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OSError, OverflowError, ValueError):
        return None


def compute_header_checksum(header_bytes: bytes) -> int:
    """Compute REGF Base Block XOR-32 checksum over the first 508 bytes (127 DWORDs).
    
    Edge-case handling per Microsoft Windows specification:
    - If XOR result is 0x0, checksum is 0x1.
    - If XOR result is 0xFFFFFFFF, checksum is 0xFFFFFFFE (-2).
    """
    if len(header_bytes) < 508:
        raise RegistryTruncatedError("Header is too short to compute checksum (< 508 bytes)")
    chk = 0
    for i in range(127):
        chk ^= struct.unpack_from("<I", header_bytes, i * 4)[0]
    if chk == 0:
        return 1
    elif chk == 0xFFFFFFFF:
        return 0xFFFFFFFE
    return chk


@dataclass
class RegistryHiveHeader:
    """Metadata parsed from 4096-byte REGF Base Block."""
    magic: bytes
    primary_seq: int
    secondary_seq: int
    last_written_utc: Optional[str]
    last_written_filetime: int
    major_version: int
    minor_version: int
    file_type: int
    file_format: int
    root_cell_offset: int
    hive_bins_data_size: int
    clustering_factor: int
    hive_name: str
    checksum: int
    calculated_checksum: int
    is_corrupted: bool = False
    hive_family: str = "UNKNOWN"


@dataclass
class RegistryValue:
    """Represents a Registry value ('vk' node)."""
    name: str
    data_type: int
    data_type_name: str
    data_raw: bytes
    data: Any
    is_inline: bool
    cell_offset: int


@dataclass
class RegistryKey:
    """Represents a Registry key ('nk' node) with its subkeys and values."""
    name: str
    path: str
    cell_offset: int
    last_written_utc: Optional[str]
    last_written_filetime: int
    values: Dict[str, RegistryValue] = field(default_factory=dict)
    subkeys: Dict[str, RegistryKey] = field(default_factory=dict)
    is_root: bool = False
    flags: int = 0

    def get_key(self, subpath: str) -> Optional[RegistryKey]:
        """Case-insensitive recursive subkey lookup by backslash or slash path."""
        parts = [p for p in subpath.replace("/", "\\").split("\\") if p]
        curr: Optional[RegistryKey] = self
        for part in parts:
            if curr is None:
                return None
            part_lower = part.lower()
            matched = None
            for k_name, k_obj in curr.subkeys.items():
                if k_name.lower() == part_lower:
                    matched = k_obj
                    break
            curr = matched
        return curr

    def get_value(self, val_name: Optional[str] = "") -> Optional[RegistryValue]:
        """Case-insensitive value lookup. Empty or None returns (Default) value."""
        target = (val_name or "").lower()
        for v_name, v_obj in self.values.items():
            if v_name.lower() == target:
                return v_obj
        return None

    def iter_all_keys(self) -> Iterator[RegistryKey]:
        """Yield self and all descendant keys depth-first."""
        yield self
        for child in self.subkeys.values():
            yield from child.iter_all_keys()


def validate_hive_header(data: bytes) -> RegistryHiveHeader:
    """Inspect and validate REGF Base Block (first 4096 bytes)."""
    if len(data) < 4096:
        raise RegistryTruncatedError(
            f"Registry hive data truncated: got {len(data)} bytes, expected minimum 4096 bytes"
        )

    magic = data[:4]
    if magic != b"regf":
        raise RegistryInvalidSignatureError(
            f"Invalid registry hive signature {magic!r}; expected b'regf'"
        )

    primary_seq, secondary_seq = struct.unpack_from("<II", data, 4)
    last_written_ft = struct.unpack_from("<Q", data, 12)[0]
    last_written_utc = filetime_to_iso(last_written_ft)
    major_ver, minor_ver = struct.unpack_from("<II", data, 20)
    file_type, file_fmt = struct.unpack_from("<II", data, 28)
    root_cell_offset = struct.unpack_from("<I", data, 36)[0]
    bins_data_size = struct.unpack_from("<I", data, 40)[0]
    clustering = struct.unpack_from("<I", data, 44)[0]

    # Extract hive name from header (offset 48, up to 64 bytes UTF-16LE)
    raw_name = data[48:112]
    hive_name = ""
    try:
        hive_name = raw_name.decode("utf-16le", errors="replace").split("\x00")[0].strip()
    except Exception:
        pass

    stored_chk = struct.unpack_from("<I", data, 508)[0]
    calculated_chk = compute_header_checksum(data[:508])

    is_corrupted = (stored_chk != calculated_chk)

    return RegistryHiveHeader(
        magic=magic,
        primary_seq=primary_seq,
        secondary_seq=secondary_seq,
        last_written_utc=last_written_utc,
        last_written_filetime=last_written_ft,
        major_version=major_ver,
        minor_version=minor_ver,
        file_type=file_type,
        file_format=file_fmt,
        root_cell_offset=root_cell_offset,
        hive_bins_data_size=bins_data_size,
        clustering_factor=clustering,
        hive_name=hive_name,
        checksum=stored_chk,
        calculated_checksum=calculated_chk,
        is_corrupted=is_corrupted,
    )


class WindowsRegistryHiveParser:
    """Forensic binary parser for Windows Registry hive files ('regf')."""

    def __init__(
        self,
        max_size_bytes: Optional[int] = None,
        max_keys: Optional[int] = None,
        max_depth: Optional[int] = None,
        max_parse_seconds: Optional[float] = None,
    ):
        settings = get_settings()
        self.max_size_bytes = max_size_bytes or settings.max_registry_hive_size_bytes
        self.max_keys = max_keys or settings.max_registry_keys
        self.max_depth = max_depth or settings.max_registry_depth
        self.max_parse_seconds = max_parse_seconds or settings.max_registry_parse_seconds

        self.header: Optional[RegistryHiveHeader] = None
        self.root_key: Optional[RegistryKey] = None
        self.warnings: List[str] = []
        self._data: bytes = b""
        self._visited_cells: Set[int] = set()
        self._key_count: int = 0
        self._start_time: float = 0.0

    def parse_file(self, file_path: Union[str, Path], validate_checksum: bool = True) -> RegistryKey:
        """Parse registry hive from a file path."""
        p = Path(file_path).resolve()
        if not p.is_file():
            raise FileNotFoundError(f"Registry hive file not found: {p}")

        file_size = p.stat().st_size
        if file_size > self.max_size_bytes:
            raise RegistryResourceLimitError(
                f"Hive size {file_size} bytes exceeds configured limit {self.max_size_bytes} bytes"
            )

        with open(p, "rb") as f:
            data = f.read()

        return self.parse_bytes(data, validate_checksum=validate_checksum)

    def parse_bytes(self, data: bytes, validate_checksum: bool = True) -> RegistryKey:
        """Parse registry hive from memory buffer."""
        if len(data) > self.max_size_bytes:
            raise RegistryResourceLimitError(
                f"Hive data size {len(data)} bytes exceeds limit {self.max_size_bytes} bytes"
            )

        self._data = data
        self._visited_cells.clear()
        self._key_count = 0
        self.warnings.clear()
        self._start_time = time.monotonic()

        self.header = validate_hive_header(data)
        if validate_checksum and self.header.is_corrupted:
            raise RegistryCorruptedError(
                f"Registry Base Block checksum mismatch: expected {self.header.checksum:#010x}, "
                f"calculated {self.header.calculated_checksum:#010x}"
            )

        # A bare 4096-byte header file with no hive bins
        if len(data) == 4096:
            # Create synthetic root key representing header metadata
            self.root_key = RegistryKey(
                name="Root",
                path="Root",
                cell_offset=self.header.root_cell_offset,
                last_written_utc=self.header.last_written_utc,
                last_written_filetime=self.header.last_written_filetime,
                is_root=True,
            )
            return self.root_key

        # Traverse hive bins and root cell
        root_offset = self.header.root_cell_offset
        try:
            self.root_key = self._parse_nk(root_offset, parent_path="", depth=0)
        except Exception as e:
            if isinstance(e, (RegistryResourceLimitError, RegistryTruncatedError, RegistryCorruptedError)):
                raise
            raise RegistryParserError(f"Failed to parse root key node at offset {root_offset}: {e}") from e

        return self.root_key

    def parse(self, source: Union[str, Path, bytes], validate_checksum: bool = True) -> RegistryKey:
        """Universal parse entry point for either path or bytes."""
        if isinstance(source, (str, Path)):
            return self.parse_file(source, validate_checksum=validate_checksum)
        return self.parse_bytes(source, validate_checksum=validate_checksum)

    def _check_resource_limits(self, depth: int) -> None:
        """Check depth, key count, and execution time limits."""
        if depth > self.max_depth:
            raise RegistryResourceLimitError(f"Maximum registry key recursion depth ({self.max_depth}) exceeded")
        if self._key_count > self.max_keys:
            raise RegistryResourceLimitError(f"Maximum registry key count ({self.max_keys}) exceeded")
        if (time.monotonic() - self._start_time) > self.max_parse_seconds:
            raise RegistryResourceLimitError(f"Registry parsing exceeded timeout of {self.max_parse_seconds} seconds")

    def _resolve_cell(self, cell_offset: int) -> Tuple[int, bytes]:
        """Locate and return (cell_size, cell_data) given relative cell offset (relative to 4096)."""
        file_offset = 4096 + cell_offset
        if cell_offset < 0 or file_offset + 4 > len(self._data):
            raise RegistryTruncatedError(
                f"Cell offset {cell_offset} (file offset {file_offset}) out of bounds (file len {len(self._data)})"
            )

        raw_size = struct.unpack_from("<i", self._data, file_offset)[0]
        # Negative size = allocated cell; positive size = free cell
        abs_size = abs(raw_size)
        if abs_size < 4 or file_offset + abs_size > len(self._data):
            raise RegistryTruncatedError(
                f"Cell at offset {cell_offset} has invalid size {raw_size} extending beyond file"
            )

        # Cell data begins right after 4-byte size header
        cell_data = self._data[file_offset + 4: file_offset + abs_size]
        return abs_size, cell_data

    def _parse_nk(self, cell_offset: int, parent_path: str, depth: int) -> RegistryKey:
        """Parse Named Key cell ('nk')."""
        self._check_resource_limits(depth)

        if cell_offset in self._visited_cells:
            self.warnings.append(f"Cycle detected at key cell offset {cell_offset}; skipping recursion")
            return RegistryKey(name="<CYCLE>", path=f"{parent_path}\\<CYCLE>", cell_offset=cell_offset, last_written_utc=None, last_written_filetime=0)

        self._visited_cells.add(cell_offset)
        self._key_count += 1

        abs_size, cell_data = self._resolve_cell(cell_offset)
        if len(cell_data) < 76:
            raise RegistryTruncatedError(f"nk cell at offset {cell_offset} is too small ({len(cell_data)} < 76 bytes)")

        sig = cell_data[:2]
        if sig != b"nk":
            raise RegistryCorruptedError(f"Expected 'nk' signature at cell offset {cell_offset}, got {sig!r}")

        flags = struct.unpack_from("<H", cell_data, 2)[0]
        last_written_ft = struct.unpack_from("<Q", cell_data, 4)[0]
        last_written_utc = filetime_to_iso(last_written_ft)

        subkeys_count = struct.unpack_from("<I", cell_data, 20)[0]
        subkeys_list_offset = struct.unpack_from("<i", cell_data, 28)[0]

        values_count = struct.unpack_from("<I", cell_data, 36)[0]
        values_list_offset = struct.unpack_from("<i", cell_data, 40)[0]

        name_len = struct.unpack_from("<H", cell_data, 72)[0]
        name_bytes = cell_data[76: 76 + name_len]

        # Name encoding: if bit 5 (0x0020) is set, ASCII/Latin-1; otherwise UTF-16LE
        is_ascii = bool(flags & 0x0020)
        try:
            if is_ascii:
                key_name = name_bytes.decode("latin-1", errors="replace")
            else:
                key_name = name_bytes.decode("utf-16le", errors="replace")
        except Exception:
            key_name = name_bytes.decode("latin-1", errors="replace")

        # Root key or empty name
        is_root = bool(flags & 0x0004) or (not parent_path and (key_name in ("", "Root") or depth == 0))
        if not key_name:
            key_name = "Root" if is_root else f"Key_{cell_offset}"

        curr_path = key_name if not parent_path else f"{parent_path}\\{key_name}"

        key_obj = RegistryKey(
            name=key_name,
            path=curr_path,
            cell_offset=cell_offset,
            last_written_utc=last_written_utc,
            last_written_filetime=last_written_ft,
            is_root=is_root,
            flags=flags,
        )

        # Parse Values
        if values_count > 0 and values_list_offset >= 0:
            try:
                key_obj.values = self._parse_values_list(values_list_offset, values_count)
            except RegistryResourceLimitError:
                raise
            except Exception as e:
                self.warnings.append(f"Error parsing values at key {curr_path}: {e}")

        # Parse Subkeys
        if subkeys_count > 0 and subkeys_list_offset >= 0:
            try:
                key_obj.subkeys = self._parse_subkeys_list(
                    subkeys_list_offset, subkeys_count, curr_path, depth + 1
                )
            except RegistryResourceLimitError:
                raise
            except Exception as e:
                self.warnings.append(f"Error parsing subkeys at key {curr_path}: {e}")

        return key_obj

    def _parse_subkeys_list(
        self, list_offset: int, expected_count: int, parent_path: str, depth: int
    ) -> Dict[str, RegistryKey]:
        """Parse subkey list cell ('lf', 'lh', 'li', or 'ri')."""
        subkeys: Dict[str, RegistryKey] = {}
        if list_offset < 0 or list_offset in self._visited_cells:
            return subkeys

        try:
            _, cell_data = self._resolve_cell(list_offset)
        except Exception as e:
            self.warnings.append(f"Cannot resolve subkey list cell at {list_offset}: {e}")
            return subkeys

        if len(cell_data) < 4:
            return subkeys

        sig = cell_data[:2]
        count = struct.unpack_from("<H", cell_data, 2)[0]

        if sig in (b"lf", b"lh"):
            # Elements are 8 bytes: (nk_offset: uint32, name_hint_or_hash: 4 bytes)
            for i in range(count):
                elem_offset = 4 + (i * 8)
                if elem_offset + 4 > len(cell_data):
                    break
                nk_offset = struct.unpack_from("<I", cell_data, elem_offset)[0]
                try:
                    child = self._parse_nk(nk_offset, parent_path, depth)
                    subkeys[child.name] = child
                except RegistryResourceLimitError:
                    raise
                except Exception as e:
                    self.warnings.append(f"Error parsing subkey child at offset {nk_offset}: {e}")

        elif sig == b"li":
            # Elements are 4 bytes: (nk_offset: uint32)
            for i in range(count):
                elem_offset = 4 + (i * 4)
                if elem_offset + 4 > len(cell_data):
                    break
                nk_offset = struct.unpack_from("<I", cell_data, elem_offset)[0]
                try:
                    child = self._parse_nk(nk_offset, parent_path, depth)
                    subkeys[child.name] = child
                except RegistryResourceLimitError:
                    raise
                except Exception as e:
                    self.warnings.append(f"Error parsing subkey child at offset {nk_offset}: {e}")

        elif sig == b"ri":
            # Root index: elements are 4 bytes pointing to other subkey lists (lf/lh/li/ri)
            for i in range(count):
                elem_offset = 4 + (i * 4)
                if elem_offset + 4 > len(cell_data):
                    break
                sublist_offset = struct.unpack_from("<I", cell_data, elem_offset)[0]
                nested = self._parse_subkeys_list(sublist_offset, expected_count, parent_path, depth)
                subkeys.update(nested)

        else:
            self.warnings.append(f"Unknown subkey list signature {sig!r} at offset {list_offset}")

        return subkeys

    def _parse_values_list(self, list_offset: int, count: int) -> Dict[str, RegistryValue]:
        """Parse values list cell containing an array of 'vk' cell offsets."""
        values: Dict[str, RegistryValue] = {}
        if list_offset < 0:
            return values

        try:
            _, cell_data = self._resolve_cell(list_offset)
        except Exception as e:
            self.warnings.append(f"Cannot resolve values list cell at {list_offset}: {e}")
            return values

        for i in range(count):
            elem_offset = i * 4
            if elem_offset + 4 > len(cell_data):
                break
            vk_offset = struct.unpack_from("<I", cell_data, elem_offset)[0]
            try:
                val = self._parse_vk(vk_offset)
                if val is not None:
                    values[val.name] = val
            except Exception as e:
                self.warnings.append(f"Error parsing vk cell at offset {vk_offset}: {e}")

        return values

    def _parse_vk(self, cell_offset: int) -> Optional[RegistryValue]:
        """Parse Value Key cell ('vk')."""
        abs_size, cell_data = self._resolve_cell(cell_offset)
        if len(cell_data) < 20:
            return None

        sig = cell_data[:2]
        if sig != b"vk":
            self.warnings.append(f"Expected 'vk' signature at cell offset {cell_offset}, got {sig!r}")
            return None

        name_len = struct.unpack_from("<H", cell_data, 2)[0]
        data_len = struct.unpack_from("<I", cell_data, 4)[0]
        data_offset = struct.unpack_from("<I", cell_data, 8)[0]
        data_type = struct.unpack_from("<I", cell_data, 12)[0]
        flags = struct.unpack_from("<H", cell_data, 16)[0]

        # Extract name
        name_bytes = cell_data[20: 20 + name_len]
        is_ascii = bool(flags & 0x0001)
        if name_len == 0:
            val_name = ""  # (Default) value
        else:
            try:
                if is_ascii:
                    val_name = name_bytes.decode("latin-1", errors="replace")
                else:
                    val_name = name_bytes.decode("utf-16le", errors="replace")
            except Exception:
                val_name = name_bytes.decode("latin-1", errors="replace")

        # Determine inline data vs cell offset
        is_inline = bool(data_len & 0x80000000)
        actual_len = data_len & 0x7FFFFFFF

        raw_data = b""
        if is_inline:
            # Data is stored directly in the 4 bytes of data_offset
            packed = struct.pack("<I", data_offset)
            raw_data = packed[: min(actual_len, 4)]
        else:
            if actual_len > 0 and data_offset >= 0:
                try:
                    _, target_data = self._resolve_cell(data_offset)
                    # Check if 'db' (big data cell)
                    if len(target_data) >= 4 and target_data[:2] == b"db":
                        # db cell contains sub-cell references
                        db_count = struct.unpack_from("<H", target_data, 2)[0]
                        db_list_offset = struct.unpack_from("<I", target_data, 4)[0]
                        _, seg_list = self._resolve_cell(db_list_offset)
                        combined = bytearray()
                        for seg_idx in range(db_count):
                            if (seg_idx * 4) + 4 <= len(seg_list):
                                seg_off = struct.unpack_from("<I", seg_list, seg_idx * 4)[0]
                                _, seg_data = self._resolve_cell(seg_off)
                                combined.extend(seg_data)
                        raw_data = bytes(combined[:actual_len])
                    else:
                        raw_data = target_data[:actual_len]
                except Exception as e:
                    self.warnings.append(f"Cannot read external data cell at {data_offset}: {e}")
                    raw_data = b""

        decoded = self._decode_value(data_type, raw_data)

        return RegistryValue(
            name=val_name,
            data_type=data_type,
            data_type_name=data_type_to_name(data_type),
            data_raw=raw_data,
            data=decoded,
            is_inline=is_inline,
            cell_offset=cell_offset,
        )

    def _decode_value(self, data_type: int, raw: bytes) -> Any:
        """Decode raw bytes into Python object according to REG_* type."""
        if not raw:
            if data_type in (REG_DWORD, REG_DWORD_BIG_ENDIAN, REG_QWORD):
                return 0
            if data_type in (REG_SZ, REG_EXPAND_SZ, REG_LINK):
                return ""
            if data_type == REG_MULTI_SZ:
                return []
            return b""

        try:
            if data_type in (REG_SZ, REG_EXPAND_SZ, REG_LINK):
                # UTF-16LE string, null-terminated
                decoded = raw.decode("utf-16le", errors="replace")
                return decoded.rstrip("\x00")

            elif data_type == REG_DWORD:
                if len(raw) >= 4:
                    return struct.unpack("<I", raw[:4])[0]
                padded = raw.ljust(4, b"\x00")
                return struct.unpack("<I", padded)[0]

            elif data_type == REG_DWORD_BIG_ENDIAN:
                if len(raw) >= 4:
                    return struct.unpack(">I", raw[:4])[0]
                padded = raw.rjust(4, b"\x00")
                return struct.unpack(">I", padded)[0]

            elif data_type == REG_QWORD:
                if len(raw) >= 8:
                    return struct.unpack("<Q", raw[:8])[0]
                padded = raw.ljust(8, b"\x00")
                return struct.unpack("<Q", padded)[0]

            elif data_type == REG_MULTI_SZ:
                decoded = raw.decode("utf-16le", errors="replace")
                parts = [p for p in decoded.split("\x00") if p]
                return parts

            elif data_type == REG_BINARY:
                return raw

            else:
                return raw

        except Exception:
            return raw


def identify_registry_hive(
    data_or_path: Union[str, Path, bytes]
) -> Tuple[bool, str, Dict[str, Any], List[str]]:
    """Inspect header and key structures to detect validity, family, and top-level keys without relying on filenames.
    
    Returns:
        (is_valid, hive_family, header_info, detected_keys)
        where hive_family is one of:
        "SYSTEM", "SOFTWARE", "SAM", "SECURITY", "NTUSER", "USRCLASS", "AMCACHE", "BCD", or "UNKNOWN".
    """
    if isinstance(data_or_path, (str, Path)):
        p = Path(data_or_path).resolve()
        if not p.is_file():
            return False, "UNKNOWN", {}, []
        with open(p, "rb") as f:
            header_bytes = f.read(4096)
    else:
        header_bytes = data_or_path[:4096]

    if len(header_bytes) < 4096 or header_bytes[:4] != b"regf":
        return False, "UNKNOWN", {}, []

    try:
        hdr = validate_hive_header(header_bytes)
    except Exception:
        return False, "UNKNOWN", {}, []

    header_info = {
        "magic": "regf",
        "primary_sequence": hdr.primary_seq,
        "secondary_sequence": hdr.secondary_seq,
        "last_written_utc": hdr.last_written_utc,
        "major_version": hdr.major_version,
        "minor_version": hdr.minor_version,
        "root_cell_offset": hdr.root_cell_offset,
        "hive_bins_data_size": hdr.hive_bins_data_size,
        "hive_name": hdr.hive_name,
        "checksum_valid": not hdr.is_corrupted,
    }

    # Best-effort family identification from embedded hive name or top-level keys
    detected_family = "UNKNOWN"
    hive_name_upper = hdr.hive_name.upper()

    if "SYSTEM" in hive_name_upper:
        detected_family = "SYSTEM"
    elif "SOFTWARE" in hive_name_upper:
        detected_family = "SOFTWARE"
    elif "SAM" in hive_name_upper:
        detected_family = "SAM"
    elif "SECURITY" in hive_name_upper:
        detected_family = "SECURITY"
    elif "NTUSER" in hive_name_upper:
        detected_family = "NTUSER"
    elif "USRCLASS" in hive_name_upper:
        detected_family = "USRCLASS"
    elif "AMCACHE" in hive_name_upper:
        detected_family = "AMCACHE"
    elif "BCD" in hive_name_upper:
        detected_family = "BCD"

    detected_keys: List[str] = []
    # If full data available, parse top-level keys to confirm or identify family
    try:
        full_data = data_or_path if isinstance(data_or_path, bytes) else open(Path(data_or_path), "rb").read()
        if len(full_data) > 4096:
            parser = WindowsRegistryHiveParser(max_depth=3, max_keys=200)
            root = parser.parse_bytes(full_data, validate_checksum=False)
            detected_keys = list(root.subkeys.keys())
            lower_keys = [k.lower() for k in detected_keys]

            if any(k in lower_keys for k in ("select", "controlset001", "currentcontrolset")):
                detected_family = "SYSTEM"
            elif any(k in lower_keys for k in ("microsoft", "classes", "policies", "clients")):
                detected_family = "SOFTWARE"
            elif any(k in lower_keys for k in ("domains", "sam")):
                detected_family = "SAM"
            elif any(k in lower_keys for k in ("policy", "cache", "rxact")):
                detected_family = "SECURITY"
            elif any(k in lower_keys for k in ("software", "console", "environment", "printers")):
                # Check for NTUSER vs USRCLASS
                if root.get_key("Local Settings"):
                    detected_family = "USRCLASS"
                else:
                    detected_family = "NTUSER"
            elif any(k in lower_keys for k in ("root", "inventoryapplication", "file")):
                detected_family = "AMCACHE"
            elif any(k in lower_keys for k in ("objects", "description")):
                detected_family = "BCD"
    except Exception:
        pass

    return True, detected_family, header_info, detected_keys


# --------------------------------------------------------------------------
# Forensic Artifact Extractors
# --------------------------------------------------------------------------

def _extract_system_artifacts(
    root: RegistryKey, case_id: str, art_id: str, art_hash: str
) -> List[ForensicFinding]:
    """Extract SYSTEM hive artifacts: ComputerName, TimeZone, Services/Drivers, USBSTOR, Interfaces."""
    findings: List[ForensicFinding] = []

    # 1. Determine CurrentControlSet
    cs_name = "ControlSet001"
    select_key = root.get_key("Select")
    if select_key:
        curr_val = select_key.get_value("Current")
        if curr_val and isinstance(curr_val.data, int):
            cs_name = f"ControlSet{curr_val.data:03d}"
            findings.append(
                ForensicFinding(
                    case_id=case_id,
                    source_artifact_id=art_id,
                    source_artifact_hash=art_hash,
                    tool_id="dissect_registry",
                    tool_version="1.0.0",
                    timestamp_utc=select_key.last_written_utc,
                    artifact_type="registry",
                    category="system_config",
                    severity="info",
                    raw_reference=r"HKLM\SYSTEM\Select",
                    summary=f"Active Control Set resolved to {cs_name} (Current: {curr_val.data})",
                    projected_data={"ActiveControlSet": cs_name, "Current": curr_val.data},
                )
            )

    cs_key = root.get_key(cs_name) or root.get_key("ControlSet001") or root.get_key("CurrentControlSet")
    if not cs_key:
        return findings

    # 2. ComputerName
    comp_key = cs_key.get_key(r"Control\ComputerName\ComputerName") or cs_key.get_key(r"Control\ComputerName\ActiveComputerName")
    if comp_key:
        c_val = comp_key.get_value("ComputerName")
        if c_val and c_val.data:
            findings.append(
                ForensicFinding(
                    case_id=case_id,
                    source_artifact_id=art_id,
                    source_artifact_hash=art_hash,
                    tool_id="dissect_registry",
                    tool_version="1.0.0",
                    timestamp_utc=comp_key.last_written_utc,
                    artifact_type="registry",
                    category="system_config",
                    severity="info",
                    host=str(c_val.data),
                    raw_reference=f"HKLM\\SYSTEM\\{cs_name}\\Control\\ComputerName\\ComputerName",
                    summary=f"System ComputerName configured as '{c_val.data}'",
                    projected_data={"ComputerName": str(c_val.data)},
                )
            )

    # 3. TimeZoneInformation
    tz_key = cs_key.get_key(r"Control\TimeZoneInformation")
    if tz_key:
        tz_name_val = tz_key.get_value("TimeZoneKeyName") or tz_key.get_value("StandardName")
        bias_val = tz_key.get_value("ActiveTimeBias") or tz_key.get_value("Bias")
        findings.append(
            ForensicFinding(
                case_id=case_id,
                source_artifact_id=art_id,
                source_artifact_hash=art_hash,
                tool_id="dissect_registry",
                tool_version="1.0.0",
                timestamp_utc=tz_key.last_written_utc,
                artifact_type="registry",
                category="system_config",
                severity="info",
                raw_reference=f"HKLM\\SYSTEM\\{cs_name}\\Control\\TimeZoneInformation",
                summary=f"System TimeZone configured as '{tz_name_val.data if tz_name_val else 'Unknown'}'",
                projected_data={
                    "TimeZone": str(tz_name_val.data) if tz_name_val else None,
                    "ActiveTimeBiasMinutes": bias_val.data if bias_val else None,
                },
            )
        )

    # 4. Services & Drivers
    services_key = cs_key.get_key("Services")
    if services_key:
        suspicious_keywords = ["\\temp\\", "\\appdata\\", "\\users\\public\\", "powershell", "cmd.exe", "rundll32", "certutil", "wscript", "cscript", "bitsadmin"]
        for svc_name, svc_k in services_key.subkeys.items():
            img_val = svc_k.get_value("ImagePath")
            start_val = svc_k.get_value("Start")
            type_val = svc_k.get_value("Type")
            desc_val = svc_k.get_value("Description") or svc_k.get_value("DisplayName")

            img_path = str(img_val.data) if img_val and img_val.data else ""
            img_lower = img_path.lower()

            is_suspicious = any(kw in img_lower for kw in suspicious_keywords)
            sev = "high" if is_suspicious else "info"
            cat = "service_suspicious" if is_suspicious else "service_installed"

            summary_text = (
                f"Suspicious Service '{svc_name}' with anomalous ImagePath: {img_path}"
                if is_suspicious
                else f"Service '{svc_name}' (Start: {start_val.data if start_val else 'N/A'})"
            )

            findings.append(
                ForensicFinding(
                    case_id=case_id,
                    source_artifact_id=art_id,
                    source_artifact_hash=art_hash,
                    tool_id="dissect_registry",
                    tool_version="1.0.0",
                    timestamp_utc=svc_k.last_written_utc,
                    artifact_type="registry",
                    category=cat,
                    severity=sev,
                    command_line=img_path or None,
                    raw_reference=f"HKLM\\SYSTEM\\{cs_name}\\Services\\{svc_name}",
                    summary=summary_text,
                    projected_data={
                        "ServiceName": svc_name,
                        "ImagePath": img_path,
                        "StartType": start_val.data if start_val else None,
                        "ServiceType": type_val.data if type_val else None,
                        "DisplayName": str(desc_val.data) if desc_val else None,
                        "SuspiciousFlag": is_suspicious,
                    },
                )
            )

    # 5. USB Devices (USBSTOR)
    usbstor_key = cs_key.get_key(r"Enum\USBSTOR")
    if usbstor_key:
        for dev_type, dev_k in usbstor_key.subkeys.items():
            for serial, ser_k in dev_k.subkeys.items():
                friendly_val = ser_k.get_value("FriendlyName")
                findings.append(
                    ForensicFinding(
                        case_id=case_id,
                        source_artifact_id=art_id,
                        source_artifact_hash=art_hash,
                        tool_id="dissect_registry",
                        tool_version="1.0.0",
                        timestamp_utc=ser_k.last_written_utc,
                        artifact_type="registry",
                        category="usb_device",
                        severity="info",
                        raw_reference=f"HKLM\\SYSTEM\\{cs_name}\\Enum\\USBSTOR\\{dev_type}\\{serial}",
                        summary=f"USB Storage device connected: {friendly_val.data if friendly_val else dev_type} (S/N: {serial})",
                        projected_data={
                            "DeviceType": dev_type,
                            "SerialNumber": serial,
                            "FriendlyName": str(friendly_val.data) if friendly_val else None,
                        },
                    )
                )

    # 6. Network Interfaces
    net_key = cs_key.get_key(r"Services\Tcpip\Parameters\Interfaces")
    if net_key:
        for guid, if_k in net_key.subkeys.items():
            ip_val = if_k.get_value("DhcpIPAddress") or if_k.get_value("IPAddress")
            mask_val = if_k.get_value("DhcpSubnetMask") or if_k.get_value("SubnetMask")
            gw_val = if_k.get_value("DhcpDefaultGateway") or if_k.get_value("DefaultGateway")
            if ip_val and ip_val.data and ip_val.data != "0.0.0.0":
                findings.append(
                    ForensicFinding(
                        case_id=case_id,
                        source_artifact_id=art_id,
                        source_artifact_hash=art_hash,
                        tool_id="dissect_registry",
                        tool_version="1.0.0",
                        timestamp_utc=if_k.last_written_utc,
                        artifact_type="registry",
                        category="network_config",
                        severity="info",
                        raw_reference=f"HKLM\\SYSTEM\\{cs_name}\\Services\\Tcpip\\Parameters\\Interfaces\\{guid}",
                        summary=f"Network Interface {guid} configured with IP: {ip_val.data}",
                        projected_data={
                            "InterfaceGUID": guid,
                            "IPAddress": str(ip_val.data),
                            "SubnetMask": str(mask_val.data) if mask_val else None,
                            "DefaultGateway": str(gw_val.data) if gw_val else None,
                        },
                    )
                )

    return findings


def _extract_software_artifacts(
    root: RegistryKey, case_id: str, art_id: str, art_hash: str
) -> List[ForensicFinding]:
    """Extract SOFTWARE hive artifacts: OS Version, Installed Apps, Run/RunOnce persistence."""
    findings: List[ForensicFinding] = []

    # 1. Windows Build / Version Info
    cv_key = root.get_key(r"Microsoft\Windows NT\CurrentVersion")
    if cv_key:
        prod_val = cv_key.get_value("ProductName")
        build_val = cv_key.get_value("CurrentBuild") or cv_key.get_value("CurrentBuildNumber")
        rel_val = cv_key.get_value("DisplayVersion") or cv_key.get_value("ReleaseId")
        install_val = cv_key.get_value("InstallDate")

        install_utc = None
        if install_val and isinstance(install_val.data, int):
            try:
                install_utc = datetime.fromtimestamp(install_val.data, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            except Exception:
                pass

        findings.append(
            ForensicFinding(
                case_id=case_id,
                source_artifact_id=art_id,
                source_artifact_hash=art_hash,
                tool_id="dissect_registry",
                tool_version="1.0.0",
                timestamp_utc=cv_key.last_written_utc,
                artifact_type="registry",
                category="os_version",
                severity="info",
                raw_reference=r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                summary=f"Operating System: {prod_val.data if prod_val else 'Windows'} (Build {build_val.data if build_val else 'N/A'})",
                projected_data={
                    "ProductName": str(prod_val.data) if prod_val else None,
                    "CurrentBuild": str(build_val.data) if build_val else None,
                    "ReleaseId": str(rel_val.data) if rel_val else None,
                    "InstallDateUTC": install_utc,
                },
            )
        )

    # 2. Installed Applications (Uninstall Keys)
    uninstall_keys = [
        r"Microsoft\Windows\CurrentVersion\Uninstall",
        r"WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ]
    for uninst_path in uninstall_keys:
        u_key = root.get_key(uninst_path)
        if not u_key:
            continue
        for app_id, app_k in u_key.subkeys.items():
            name_val = app_k.get_value("DisplayName")
            if not name_val or not name_val.data:
                continue
            ver_val = app_k.get_value("DisplayVersion")
            pub_val = app_k.get_value("Publisher")
            loc_val = app_k.get_value("InstallLocation")
            dt_val = app_k.get_value("InstallDate")

            findings.append(
                ForensicFinding(
                    case_id=case_id,
                    source_artifact_id=art_id,
                    source_artifact_hash=art_hash,
                    tool_id="dissect_registry",
                    tool_version="1.0.0",
                    timestamp_utc=app_k.last_written_utc,
                    artifact_type="registry",
                    category="installed_program",
                    severity="info",
                    raw_reference=f"HKLM\\SOFTWARE\\{uninst_path}\\{app_id}",
                    summary=f"Installed Application: {name_val.data} (v{ver_val.data if ver_val else 'N/A'})",
                    projected_data={
                        "DisplayName": str(name_val.data),
                        "DisplayVersion": str(ver_val.data) if ver_val else None,
                        "Publisher": str(pub_val.data) if pub_val else None,
                        "InstallLocation": str(loc_val.data) if loc_val else None,
                        "InstallDate": str(dt_val.data) if dt_val else None,
                    },
                )
            )

    # 3. Persistence: Run / RunOnce keys
    run_paths = [
        r"Microsoft\Windows\CurrentVersion\Run",
        r"Microsoft\Windows\CurrentVersion\RunOnce",
        r"Microsoft\Windows\CurrentVersion\RunServices",
        r"Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        r"WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        r"WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    ]
    for r_path in run_paths:
        rk = root.get_key(r_path)
        if not rk:
            continue
        for v_name, v_obj in rk.values.items():
            cmd = str(v_obj.data)
            cmd_lower = cmd.lower()
            is_susp = any(kw in cmd_lower for kw in ["\\temp\\", "\\appdata\\", "powershell", "cmd.exe", "rundll32", "mshta", "wscript"])
            sev = "high" if is_susp else "medium"
            findings.append(
                ForensicFinding(
                    case_id=case_id,
                    source_artifact_id=art_id,
                    source_artifact_hash=art_hash,
                    tool_id="dissect_registry",
                    tool_version="1.0.0",
                    timestamp_utc=rk.last_written_utc,
                    artifact_type="registry",
                    category="persistence_registry",
                    severity=sev,
                    command_line=cmd,
                    raw_reference=f"HKLM\\SOFTWARE\\{r_path} -> {v_name}",
                    summary=f"Registry Persistence ({r_path.split('\\')[-1]}): '{v_name}' -> {cmd}",
                    projected_data={
                        "KeyPath": f"HKLM\\SOFTWARE\\{r_path}",
                        "ValueName": v_name,
                        "CommandLine": cmd,
                        "SuspiciousFlag": is_susp,
                    },
                )
            )

    return findings


def _extract_ntuser_artifacts(
    root: RegistryKey, case_id: str, art_id: str, art_hash: str
) -> List[ForensicFinding]:
    """Extract NTUSER.DAT artifacts: RunMRU, RecentDocs, UserAssist (ROT13), TypedPaths, Run keys."""
    findings: List[ForensicFinding] = []

    # 1. RunMRU
    run_mru = root.get_key(r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU")
    if run_mru:
        mru_list_val = run_mru.get_value("MRUList")
        mru_order = str(mru_list_val.data) if mru_list_val else ""
        for v_name, v_obj in run_mru.values.items():
            if v_name.lower() == "mrulist":
                continue
            cmd = str(v_obj.data).rstrip("\\1")
            findings.append(
                ForensicFinding(
                    case_id=case_id,
                    source_artifact_id=art_id,
                    source_artifact_hash=art_hash,
                    tool_id="dissect_registry",
                    tool_version="1.0.0",
                    timestamp_utc=run_mru.last_written_utc,
                    artifact_type="registry",
                    category="user_activity_runmru",
                    severity="info",
                    command_line=cmd,
                    raw_reference=f"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU -> {v_name}",
                    summary=f"Run Dialog MRU ({v_name}): '{cmd}'",
                    projected_data={"Entry": v_name, "Command": cmd, "MRUOrder": mru_order},
                )
            )

    # 2. RecentDocs
    recent_docs = root.get_key(r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs")
    if recent_docs:
        for v_name, v_obj in recent_docs.values.items():
            if v_name.lower() == "mrulistex":
                continue
            # RecentDocs values are null-terminated UTF-16LE strings or structures
            raw = v_obj.data_raw
            doc_name = ""
            try:
                doc_name = raw.decode("utf-16le", errors="replace").split("\x00")[0]
            except Exception:
                pass
            if doc_name:
                findings.append(
                    ForensicFinding(
                        case_id=case_id,
                        source_artifact_id=art_id,
                        source_artifact_hash=art_hash,
                        tool_id="dissect_registry",
                        tool_version="1.0.0",
                        timestamp_utc=recent_docs.last_written_utc,
                        artifact_type="registry",
                        category="user_activity_recent",
                        severity="info",
                        raw_reference=f"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs -> {v_name}",
                        summary=f"Recent Document opened: '{doc_name}'",
                        projected_data={"DocumentName": doc_name, "ValueIndex": v_name},
                    )
                )

    # 3. UserAssist (ROT13)
    user_assist = root.get_key(r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist")
    if user_assist:
        for guid, ua_k in user_assist.subkeys.items():
            count_k = ua_k.get_key("Count")
            if not count_k:
                continue
            for enc_name, v_obj in count_k.values.items():
                try:
                    dec_name = codecs.decode(enc_name, "rot_13")
                except Exception:
                    dec_name = enc_name

                raw = v_obj.data_raw
                run_count = 0
                last_exec_utc = None
                # Win7+ 72-byte UserAssist entry
                if len(raw) >= 72:
                    run_count = struct.unpack_from("<I", raw, 4)[0]
                    last_exec_ft = struct.unpack_from("<Q", raw, 60)[0]
                    last_exec_utc = filetime_to_iso(last_exec_ft)
                elif len(raw) >= 16:
                    run_count = struct.unpack_from("<I", raw, 4)[0]

                findings.append(
                    ForensicFinding(
                        case_id=case_id,
                        source_artifact_id=art_id,
                        source_artifact_hash=art_hash,
                        tool_id="dissect_registry",
                        tool_version="1.0.0",
                        timestamp_utc=last_exec_utc or count_k.last_written_utc,
                        artifact_type="registry",
                        category="userassist_execution",
                        severity="info",
                        process_name=Path(dec_name).name if ("\\" in dec_name or "/" in dec_name) else dec_name,
                        raw_reference=f"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{guid}\\Count -> {enc_name}",
                        summary=f"UserAssist Execution: '{dec_name}' (Run Count: {run_count})",
                        projected_data={
                            "DecodedProgramPath": dec_name,
                            "Rot13Raw": enc_name,
                            "RunCount": run_count,
                            "LastExecutionUTC": last_exec_utc,
                            "GUID": guid,
                        },
                    )
                )

    # 4. TypedPaths
    typed = root.get_key(r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths")
    if typed:
        for v_name, v_obj in typed.values.items():
            path_str = str(v_obj.data)
            findings.append(
                ForensicFinding(
                    case_id=case_id,
                    source_artifact_id=art_id,
                    source_artifact_hash=art_hash,
                    tool_id="dissect_registry",
                    tool_version="1.0.0",
                    timestamp_utc=typed.last_written_utc,
                    artifact_type="registry",
                    category="user_typed_path",
                    severity="info",
                    raw_reference=f"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths -> {v_name}",
                    summary=f"User Typed Path in Explorer: '{path_str}'",
                    projected_data={"TypedPath": path_str, "Entry": v_name},
                )
            )

    # 5. User Persistence (Run / RunOnce)
    for r_sub in ["Run", "RunOnce"]:
        rk = root.get_key(rf"Software\Microsoft\Windows\CurrentVersion\{r_sub}")
        if rk:
            for v_name, v_obj in rk.values.items():
                cmd = str(v_obj.data)
                cmd_lower = cmd.lower()
                is_susp = any(kw in cmd_lower for kw in ["\\temp\\", "\\appdata\\", "powershell", "cmd.exe", "rundll32"])
                findings.append(
                    ForensicFinding(
                        case_id=case_id,
                        source_artifact_id=art_id,
                        source_artifact_hash=art_hash,
                        tool_id="dissect_registry",
                        tool_version="1.0.0",
                        timestamp_utc=rk.last_written_utc,
                        artifact_type="registry",
                        category="persistence_registry_user",
                        severity="high" if is_susp else "medium",
                        command_line=cmd,
                        raw_reference=f"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\{r_sub} -> {v_name}",
                        summary=f"User Registry Persistence ({r_sub}): '{v_name}' -> {cmd}",
                        projected_data={"ValueName": v_name, "CommandLine": cmd, "Suspicious": is_susp},
                    )
                )

    return findings


def _extract_sam_artifacts(
    root: RegistryKey, case_id: str, art_id: str, art_hash: str
) -> List[ForensicFinding]:
    """Extract SAM hive user metadata, RIDs, logon stats.
    
    CRITICAL SECURITY RULE: Password hashes must NEVER be exposed or parsed.
    """
    findings: List[ForensicFinding] = []

    # Map username names to RIDs via SAM\Domains\Account\Users\Names
    names_key = root.get_key(r"SAM\Domains\Account\Users\Names") or root.get_key(r"Domains\Account\Users\Names")
    users_key = root.get_key(r"SAM\Domains\Account\Users") or root.get_key(r"Domains\Account\Users")

    user_rid_map: Dict[str, str] = {}
    if names_key:
        for uname, u_k in names_key.subkeys.items():
            # Value type of default value points to RID hex
            rid_hex = f"{u_k.flags:08X}"
            user_rid_map[uname] = rid_hex

    if users_key:
        for rid_str, rid_k in users_key.subkeys.items():
            if rid_str.lower() == "names":
                continue
            try:
                rid_int = int(rid_str, 16)
            except ValueError:
                rid_int = 0

            # Match username
            matched_uname = next((un for un, rh in user_rid_map.items() if rh.upper() == rid_str.upper()), f"User_{rid_str}")

            # Parse 'F' value for last logon timestamp and account flags (DO NOT TOUCH PASSWORD HASHES)
            f_val = rid_k.get_value("F")
            last_logon_utc = None
            acct_flags = None
            if f_val and len(f_val.data_raw) >= 48:
                last_logon_ft = struct.unpack_from("<Q", f_val.data_raw, 8)[0]
                last_logon_utc = filetime_to_iso(last_logon_ft)
                acct_flags = struct.unpack_from("<H", f_val.data_raw, 56)[0] if len(f_val.data_raw) >= 58 else None

            # Parse 'V' value for user full name / comment (strictly metadata, NO HASHES)
            v_val = rid_k.get_value("V")
            comment = None
            if v_val and len(v_val.data_raw) >= 48:
                # V structure header contains offset and length for username, full name, comment
                pass

            findings.append(
                ForensicFinding(
                    case_id=case_id,
                    source_artifact_id=art_id,
                    source_artifact_hash=art_hash,
                    tool_id="dissect_registry",
                    tool_version="1.0.0",
                    timestamp_utc=last_logon_utc or rid_k.last_written_utc,
                    artifact_type="registry",
                    category="user_account_sam",
                    severity="info",
                    user=matched_uname,
                    raw_reference=f"SAM\\Domains\\Account\\Users\\{rid_str}",
                    summary=f"Local User Account: '{matched_uname}' (RID: {rid_int})",
                    projected_data={
                        "UserName": matched_uname,
                        "RID": rid_int,
                        "RID_Hex": rid_str,
                        "LastLogonUTC": last_logon_utc,
                        "AccountFlags": acct_flags,
                        # Password hashes are strictly omitted
                        "PasswordHashes": "REDACTED_BY_FORENSIC_SECURITY_POLICY",
                    },
                )
            )

    return findings


def _extract_security_artifacts(
    root: RegistryKey, case_id: str, art_id: str, art_hash: str
) -> List[ForensicFinding]:
    """Extract SECURITY hive policy and LSA metadata. Hashes/secrets redacted."""
    findings: List[ForensicFinding] = []

    pol_key = root.get_key(r"Policy\PolAdtEv") or root.get_key("Policy")
    if pol_key:
        findings.append(
            ForensicFinding(
                case_id=case_id,
                source_artifact_id=art_id,
                source_artifact_hash=art_hash,
                tool_id="dissect_registry",
                tool_version="1.0.0",
                timestamp_utc=pol_key.last_written_utc,
                artifact_type="registry",
                category="security_policy",
                severity="info",
                raw_reference="SECURITY\\Policy",
                summary="Windows Security & Audit Policy Configuration Record",
                projected_data={
                    "PolicyRecord": "AuditPolicyPresent",
                    "Secrets": "REDACTED_BY_FORENSIC_SECURITY_POLICY",
                },
            )
        )

    return findings


def _extract_amcache_artifacts(
    root: RegistryKey, case_id: str, art_id: str, art_hash: str
) -> List[ForensicFinding]:
    """Extract Amcache.hve application inventory and execution records."""
    findings: List[ForensicFinding] = []

    # InventoryApplication
    inv_app = root.get_key(r"Root\InventoryApplication") or root.get_key("InventoryApplication")
    if inv_app:
        for app_id, app_k in inv_app.subkeys.items():
            name_val = app_k.get_value("Name")
            ver_val = app_k.get_value("Version")
            pub_val = app_k.get_value("Publisher")
            install_val = app_k.get_value("InstallDate")

            app_name = str(name_val.data) if name_val else app_id
            findings.append(
                ForensicFinding(
                    case_id=case_id,
                    source_artifact_id=art_id,
                    source_artifact_hash=art_hash,
                    tool_id="dissect_registry",
                    tool_version="1.0.0",
                    timestamp_utc=app_k.last_written_utc,
                    artifact_type="registry",
                    category="amcache_inventory_app",
                    severity="info",
                    raw_reference=f"Amcache\\Root\\InventoryApplication\\{app_id}",
                    summary=f"Amcache Application: {app_name} (v{ver_val.data if ver_val else 'N/A'})",
                    projected_data={
                        "ProgramId": app_id,
                        "Name": app_name,
                        "Version": str(ver_val.data) if ver_val else None,
                        "Publisher": str(pub_val.data) if pub_val else None,
                    },
                )
            )

    # InventoryApplicationFile or File
    inv_file = root.get_key(r"Root\InventoryApplicationFile") or root.get_key(r"Root\File") or root.get_key("File")
    if inv_file:
        for file_id, file_k in inv_file.subkeys.items():
            name_val = file_k.get_value("Name")
            path_val = file_k.get_value("LowerCaseLongPath") or file_k.get_value("Path")
            sha1_val = file_k.get_value("FileId") or file_k.get_value("Sha1")
            size_val = file_k.get_value("Size")

            f_name = str(name_val.data) if name_val else file_id
            findings.append(
                ForensicFinding(
                    case_id=case_id,
                    source_artifact_id=art_id,
                    source_artifact_hash=art_hash,
                    tool_id="dissect_registry",
                    tool_version="1.0.0",
                    timestamp_utc=file_k.last_written_utc,
                    artifact_type="registry",
                    category="amcache_file_record",
                    severity="info",
                    process_name=f_name,
                    raw_reference=f"Amcache\\Root\\InventoryApplicationFile\\{file_id}",
                    summary=f"Amcache File Record: {f_name} (SHA1: {sha1_val.data if sha1_val else 'N/A'})",
                    projected_data={
                        "FileName": f_name,
                        "Path": str(path_val.data) if path_val else None,
                        "SHA1": str(sha1_val.data) if sha1_val else None,
                        "Size": size_val.data if size_val else None,
                    },
                )
            )

    return findings


def _extract_usrclass_artifacts(
    root: RegistryKey, case_id: str, art_id: str, art_hash: str
) -> List[ForensicFinding]:
    """Extract UsrClass.dat Shellbags and user interaction artifacts."""
    findings: List[ForensicFinding] = []

    bags_key = (
        root.get_key(r"Local Settings\Software\Microsoft\Windows\Shell\Bags")
        or root.get_key(r"Local Settings\Software\Microsoft\Windows\Shell\BagMRU")
    )
    if bags_key:
        findings.append(
            ForensicFinding(
                case_id=case_id,
                source_artifact_id=art_id,
                source_artifact_hash=art_hash,
                tool_id="dissect_registry",
                tool_version="1.0.0",
                timestamp_utc=bags_key.last_written_utc,
                artifact_type="registry",
                category="shellbags_activity",
                severity="info",
                raw_reference=r"UsrClass\Local Settings\Software\Microsoft\Windows\Shell\Bags",
                summary="User Shellbags folder interaction artifact detected",
                projected_data={"ArtifactType": "Shellbags", "Key": bags_key.path},
            )
        )

    return findings


def _extract_bcd_artifacts(
    root: RegistryKey, case_id: str, art_id: str, art_hash: str
) -> List[ForensicFinding]:
    """Extract BCD (Boot Configuration Data) boot objects."""
    findings: List[ForensicFinding] = []

    objects_key = root.get_key("Objects")
    if objects_key:
        for obj_guid, obj_k in objects_key.subkeys.items():
            findings.append(
                ForensicFinding(
                    case_id=case_id,
                    source_artifact_id=art_id,
                    source_artifact_hash=art_hash,
                    tool_id="dissect_registry",
                    tool_version="1.0.0",
                    timestamp_utc=obj_k.last_written_utc,
                    artifact_type="registry",
                    category="bcd_boot_object",
                    severity="info",
                    raw_reference=f"BCD\\Objects\\{obj_guid}",
                    summary=f"BCD Boot Object: {obj_guid}",
                    projected_data={"BootObjectGUID": obj_guid},
                )
            )

    return findings


def extract_forensic_artifacts(
    parser_or_root: Union[WindowsRegistryHiveParser, RegistryKey],
    header: Optional[RegistryHiveHeader],
    case_id: str,
    artifact_id: str,
    artifact_hash: str,
) -> List[ForensicFinding]:
    """Extract high-fidelity, family-specific forensic artifacts from parsed registry hierarchy."""
    if isinstance(parser_or_root, WindowsRegistryHiveParser):
        root = parser_or_root.root_key
        header = header or parser_or_root.header
    else:
        root = parser_or_root

    if root is None:
        return []

    findings: List[ForensicFinding] = []

    # 1. Base Block Header Finding
    header_utc = header.last_written_utc if header else root.last_written_utc
    findings.append(
        ForensicFinding(
            case_id=case_id,
            source_artifact_id=artifact_id,
            source_artifact_hash=artifact_hash,
            tool_id="dissect_registry",
            tool_version="1.0.0",
            timestamp_utc=header_utc,
            artifact_type="registry",
            category="registry_hive",
            severity="info",
            raw_reference="REGF_Header",
            summary=f"Valid Windows Registry Hive ({header.hive_name or root.name}) loaded",
            projected_data={
                "hive_name": header.hive_name if header else root.name,
                "last_written_utc": header_utc,
                "primary_seq": header.primary_seq if header else 1,
                "secondary_seq": header.secondary_seq if header else 1,
                "major_version": header.major_version if header else 1,
                "minor_version": header.minor_version if header else 5,
            },
        )
    )

    # 2. Identify Hive Family
    lower_keys = [k.lower() for k in root.subkeys.keys()]

    if any(k in lower_keys for k in ("select", "controlset001", "currentcontrolset")):
        findings.extend(_extract_system_artifacts(root, case_id, artifact_id, artifact_hash))

    elif any(k in lower_keys for k in ("microsoft", "classes", "policies", "clients")):
        findings.extend(_extract_software_artifacts(root, case_id, artifact_id, artifact_hash))

    elif any(k in lower_keys for k in ("domains", "sam")):
        findings.extend(_extract_sam_artifacts(root, case_id, artifact_id, artifact_hash))

    elif any(k in lower_keys for k in ("policy", "cache", "rxact")):
        findings.extend(_extract_security_artifacts(root, case_id, artifact_id, artifact_hash))

    elif any(k in lower_keys for k in ("local settings", "software", "console", "environment", "printers")):
        if root.get_key("Local Settings") or "local settings" in lower_keys:
            findings.extend(_extract_usrclass_artifacts(root, case_id, artifact_id, artifact_hash))
        else:
            findings.extend(_extract_ntuser_artifacts(root, case_id, artifact_id, artifact_hash))

    elif any(k in lower_keys for k in ("root", "inventoryapplication", "file")):
        findings.extend(_extract_amcache_artifacts(root, case_id, artifact_id, artifact_hash))

    elif any(k in lower_keys for k in ("objects", "description")):
        findings.extend(_extract_bcd_artifacts(root, case_id, artifact_id, artifact_hash))

    else:
        # Generic registry keys: emit findings for top-level keys
        for sk_name, sk_k in root.subkeys.items():
            findings.append(
                ForensicFinding(
                    case_id=case_id,
                    source_artifact_id=artifact_id,
                    source_artifact_hash=artifact_hash,
                    tool_id="dissect_registry",
                    tool_version="1.0.0",
                    timestamp_utc=sk_k.last_written_utc,
                    artifact_type="registry",
                    category="registry_key",
                    severity="info",
                    raw_reference=sk_k.path,
                    summary=f"Registry Key '{sk_name}'",
                    projected_data={"KeyPath": sk_k.path, "ValueCount": len(sk_k.values)},
                )
            )

    return findings
