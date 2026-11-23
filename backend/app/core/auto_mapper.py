"""Visual Tool Dry-Run Auto-Mapper Service.

Inspects sample rows from forensic tools and automatically suggests field_map
and ai_keep_fields with confidence scoring.
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from backend.app.models.plugins import DryRunAutoMapperResult


# Heuristic patterns for column name matching
FIELD_NAME_PATTERNS = {
    "timestamp_utc": [
        r"^timestamp(_utc)?$",
        r"^(time|date)$",
        r"^time_?created$",
        r"^last_?write(_?timestamp)?$",
        r"^event_?time$",
        r"^create_?time$",
        r"^datetime$",
    ],
    "event_id": [
        r"^event_?id$",
        r"^eventid$",
        r"^rule_?id$",
        r"^(audit_)?code$",
    ],
    "host": [
        r"^computer(_?name)?$",
        r"^host(_?name)?$",
        r"^system$",
        r"^machine$",
        r"^fqdn$",
        r"^hive_?name$",
    ],
    "user": [
        r"^user(_?name)?$",
        r"^subject_?user(_?name)?$",
        r"^target_?user(_?name)?$",
        r"^account$",
        r"^author$",
        r"^actor$",
    ],
    "process_name": [
        r"^process(_?name)?$",
        r"^image(_?file_?name)?$",
        r"^executable(_?info)?$",
        r"^binary$",
        r"^app(_?name)?$",
    ],
    "command_line": [
        r"^command_?line$",
        r"^cmd_?line$",
        r"^args?$",
        r"^arguments?$",
        r"^value_?data$",
        r"^script$",
    ],
    "severity": [
        r"^severity$",
        r"^level$",
        r"^priority$",
        r"^criticality$",
        r"^risk$",
    ],
    "summary": [
        r"^summary$",
        r"^message$",
        r"^description$",
        r"^payload$",
        r"^rule$",
        r"^value_?name$",
        r"^name$",
        r"^title$",
    ],
    "raw_reference": [
        r"^record_?number$",
        r"^record_?id$",
        r"^key_?path$",
        r"^offset(\(v\))?$",
        r"^pid$",
        r"^target$",
    ],
}

# High-signal terms to retain in ai_keep_fields
HIGH_SIGNAL_TERMS = {
    "parent", "ppid", "hash", "sha256", "md5", "ip", "port", "url", "domain",
    "path", "file", "target", "tag", "meta", "strings", "document", "hive",
    "category", "status", "exit", "session"
}

# Low-signal noise terms to exclude from ai_keep_fields
LOW_SIGNAL_TERMS = {
    "guid", "chunk", "version", "opcode", "raw", "hex", "reserved", "padding",
    "internal", "blob_bytes", "struct_id"
}


def is_timestamp_value(val: Any) -> bool:
    """Check if value looks like a timestamp string or epoch number."""
    if isinstance(val, (int, float)):
        # Epoch seconds (1e9 to 2e9 corresponds to ~2001 to ~2033)
        return 1_000_000_000 <= val <= 2_500_000_000
    if isinstance(val, str) and len(val) >= 10:
        # Check standard ISO or datetime patterns
        iso_pattern = r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}"
        return bool(re.match(iso_pattern, val))
    return False


def is_event_id_value(val: Any) -> bool:
    """Check if value looks like a Windows Event ID or numeric alert code."""
    if isinstance(val, int) and 0 < val < 100_000:
        return True
    if isinstance(val, str) and val.isdigit() and len(val) <= 6:
        return True
    return False


class DryRunAutoMapper:
    """Analyzes 5 sample rows from a new forensic tool and suggests mapping & projection."""

    def analyze_sample_rows(
        self,
        sample_rows: List[Dict[str, Any]],
        max_rows_to_inspect: int = 5,
    ) -> DryRunAutoMapperResult:
        """Inspect sample rows and generate suggested field_map and ai_keep_fields."""
        if not sample_rows:
            return DryRunAutoMapperResult()

        rows_to_inspect = sample_rows[:max_rows_to_inspect]
        all_columns: Set[str] = set()
        for r in rows_to_inspect:
            all_columns.update(r.keys())

        suggested_field_map: Dict[str, str] = {}
        confidence_scores: Dict[str, float] = {}

        # 1. Evaluate each standard target field
        for target_field, regex_list in FIELD_NAME_PATTERNS.items():
            best_col = None
            best_score = 0.0

            for col in all_columns:
                score = 0.0
                norm_col = col.lower().strip()

                # Regex pattern matching on column name
                for pat in regex_list:
                    if re.match(pat, norm_col, re.IGNORECASE):
                        score += 0.65
                        break
                    elif re.search(pat, norm_col, re.IGNORECASE):
                        score += 0.40
                        break

                # Value inspection boost
                sample_values = [r.get(col) for r in rows_to_inspect if r.get(col) is not None]
                if sample_values:
                    if target_field == "timestamp_utc" and any(is_timestamp_value(v) for v in sample_values):
                        score += 0.30
                    elif target_field == "event_id" and any(is_event_id_value(v) for v in sample_values):
                        score += 0.25
                    elif target_field in ("host", "user", "process_name") and any(isinstance(v, str) and len(v) > 1 for v in sample_values):
                        score += 0.15
                    elif target_field == "command_line" and any(isinstance(v, str) and (" " in v or "/" in v or "\\" in v) for v in sample_values):
                        score += 0.20

                score = min(score, 0.99)
                if score > best_score and score >= 0.50:
                    best_score = score
                    best_col = col

            if best_col and best_col not in suggested_field_map:
                suggested_field_map[best_col] = target_field
                confidence_scores[best_col] = round(best_score, 2)

        # 2. Determine suggested ai_keep_fields
        suggested_ai_keep_fields: Set[str] = set()

        # Always keep fields that were mapped
        for col in suggested_field_map.keys():
            suggested_ai_keep_fields.add(col)

        # Inspect remaining columns for high-signal vs low-signal indicators
        for col in all_columns:
            norm_col = col.lower()
            if any(term in norm_col for term in LOW_SIGNAL_TERMS):
                continue
            if any(term in norm_col for term in HIGH_SIGNAL_TERMS):
                suggested_ai_keep_fields.add(col)

        # 3. Detect artifact type heuristically
        detected_artifact_type = "unknown"
        joined_cols = " ".join(c.lower() for c in all_columns)
        if "eventid" in joined_cols or "timecreated" in joined_cols or "channel" in joined_cols:
            detected_artifact_type = "evtx"
        elif "hive" in joined_cols or "keypath" in joined_cols or "valname" in joined_cols:
            detected_artifact_type = "registry"
        elif "pid" in joined_cols or "process" in joined_cols or "ppid" in joined_cols:
            detected_artifact_type = "process"
        elif "ip" in joined_cols or "port" in joined_cols or "socket" in joined_cols:
            detected_artifact_type = "network"
        elif "rule" in joined_cols and ("strings" in joined_cols or "meta" in joined_cols):
            detected_artifact_type = "yara"

        # 4. Generate sample projected rows
        sample_projected_rows: List[Dict[str, Any]] = []
        for r in rows_to_inspect:
            projected = {k: v for k, v in r.items() if k in suggested_ai_keep_fields}
            sample_projected_rows.append(projected)

        return DryRunAutoMapperResult(
            suggested_field_map=suggested_field_map,
            suggested_ai_keep_fields=sorted(list(suggested_ai_keep_fields)),
            confidence_scores=confidence_scores,
            sample_raw_rows=rows_to_inspect,
            sample_projected_rows=sample_projected_rows,
            total_columns_inspected=len(all_columns),
            detected_artifact_type=detected_artifact_type,
        )


ToolAutoMapperService = DryRunAutoMapper
