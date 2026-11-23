"""Forensic Store: DuckDB-backed indexed store for ForensicFindings.

Provides:
- High-performance indexed storage for ForensicFinding models.
- Fast structured pivoting (users, IPs, processes, file paths).
- Forensic timeline windowing around pivot timestamps.
- Hybrid keyword and semantic scoring search.
- Dynamic dataset view pointer creation for LangGraph DAG edges.
- Citation existence verification for anti-hallucination guardrails.

Standards: RFC 3227, NIST SP 800-86, Zero Silent Sampling.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
import duckdb

from backend.app.core.exceptions import StorageError
from backend.app.models.findings import FindingSeverity, ForensicFinding

ALLOWED_FINDING_COLUMNS: Set[str] = {
    "finding_id",
    "case_id",
    "source_artifact_id",
    "source_artifact_hash",
    "tool_id",
    "tool_version",
    "timestamp_utc",
    "artifact_type",
    "category",
    "event_id",
    "severity",
    "host",
    "user_name",
    "user",
    "process_name",
    "command_line",
    "raw_reference",
    "summary",
    "projected_data",
    "raw_data_path",
    "search_tokens",
}


FINDINGS_SELECT_COLS = (
    "finding_id, case_id, source_artifact_id, source_artifact_hash, tool_id, tool_version, "
    "timestamp_utc, artifact_type, category, event_id, severity, host, user_name, "
    "process_name, command_line, raw_reference, summary, projected_data, raw_data_path, search_tokens"
)


class ForensicStore:
    """DuckDB-backed forensic data store for structured findings."""

    def __init__(self, db_path: Optional[Union[str, Path]] = None):
        """Initialize the store. If db_path is None or ':memory:', uses in-memory DuckDB."""
        if db_path is None or str(db_path) == ":memory:":
            self._db_path = ":memory:"
        else:
            p = Path(db_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            self._db_path = str(p)

        try:
            self._conn = duckdb.connect(database=self._db_path)
            self._init_schema()
        except Exception as e:
            raise StorageError(f"Failed to initialize DuckDB storage at '{self._db_path}': {e}") from e

    def _init_schema(self) -> None:
        """Create findings table and necessary indexes."""
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                finding_id VARCHAR PRIMARY KEY,
                case_id VARCHAR NOT NULL,
                source_artifact_id VARCHAR NOT NULL,
                source_artifact_hash VARCHAR NOT NULL,
                tool_id VARCHAR NOT NULL,
                tool_version VARCHAR,
                timestamp_utc VARCHAR,
                artifact_type VARCHAR NOT NULL,
                category VARCHAR NOT NULL,
                event_id VARCHAR,
                severity VARCHAR NOT NULL,
                host VARCHAR,
                user_name VARCHAR,
                process_name VARCHAR,
                command_line VARCHAR,
                raw_reference VARCHAR,
                summary VARCHAR NOT NULL,
                projected_data VARCHAR,
                raw_data_path VARCHAR,
                search_tokens VARCHAR
            );
            """
        )
        try:
            self._conn.execute("ALTER TABLE findings ADD COLUMN IF NOT EXISTS tool_version VARCHAR;")
        except Exception:
            pass
        # Create indexes for fast lookup and pivoting
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_fnd_case ON findings(case_id);")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_fnd_host ON findings(host);")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_fnd_user ON findings(user_name);")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_fnd_ts ON findings(timestamp_utc);")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_fnd_hash ON findings(source_artifact_hash);")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_fnd_art_type ON findings(artifact_type);")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_fnd_cat ON findings(category);")

    @staticmethod
    def _build_search_tokens(f: ForensicFinding) -> str:
        """Create searchable concatenated token string for hybrid matching."""
        parts = [
            f.summary or "",
            f.process_name or "",
            f.command_line or "",
            f.user or "",
            f.host or "",
            f.category or "",
            f.artifact_type or "",
            f.event_id or "",
            json.dumps(f.projected_data, ensure_ascii=False) if f.projected_data else "",
        ]
        return " ".join(parts).lower()

    @staticmethod
    def _row_to_finding(row: Tuple[Any, ...]) -> ForensicFinding:
        """Convert a database tuple row to a ForensicFinding instance."""
        tool_version = None
        if len(row) >= 20:
            # Detect whether row[5] is timestamp_utc (legacy altered table) or tool_version
            if isinstance(row[5], str) and ("T" in row[5] or ":" in row[5]) and not (isinstance(row[6], str) and ("T" in row[6] or ":" in row[6])):
                (
                    finding_id,
                    case_id,
                    source_artifact_id,
                    source_artifact_hash,
                    tool_id,
                    timestamp_utc,
                    artifact_type,
                    category,
                    event_id,
                    severity,
                    host,
                    user_name,
                    process_name,
                    command_line,
                    raw_reference,
                    summary,
                    projected_data_str,
                    raw_data_path,
                    _,
                    tool_version,
                ) = row[:20]
            else:
                (
                    finding_id,
                    case_id,
                    source_artifact_id,
                    source_artifact_hash,
                    tool_id,
                    tool_version,
                    timestamp_utc,
                    artifact_type,
                    category,
                    event_id,
                    severity,
                    host,
                    user_name,
                    process_name,
                    command_line,
                    raw_reference,
                    summary,
                    projected_data_str,
                    raw_data_path,
                    _,
                ) = row[:20]
        else:
            (
                finding_id,
                case_id,
                source_artifact_id,
                source_artifact_hash,
                tool_id,
                timestamp_utc,
                artifact_type,
                category,
                event_id,
                severity,
                host,
                user_name,
                process_name,
                command_line,
                raw_reference,
                summary,
                projected_data_str,
                raw_data_path,
                _,
            ) = row

        projected_data = {}
        if projected_data_str:
            try:
                projected_data = json.loads(projected_data_str)
            except Exception:
                projected_data = {}

        return ForensicFinding(
            finding_id=finding_id,
            case_id=case_id,
            source_artifact_id=source_artifact_id,
            source_artifact_hash=source_artifact_hash,
            tool_id=tool_id,
            tool_version=tool_version,
            timestamp_utc=timestamp_utc,
            artifact_type=artifact_type,
            category=category,
            event_id=event_id,
            severity=severity,
            host=host,
            user=user_name,
            process_name=process_name,
            command_line=command_line,
            raw_reference=raw_reference,
            summary=summary,
            projected_data=projected_data,
            raw_data_path=raw_data_path,
        )

    def insert_findings(self, findings: List[ForensicFinding]) -> int:
        """Batch insert or replace ForensicFinding records. Returns number of inserted rows."""
        if not findings:
            return 0

        rows = []
        for f in findings:
            search_tokens = self._build_search_tokens(f)
            proj_str = json.dumps(f.projected_data, ensure_ascii=False) if f.projected_data else "{}"
            rows.append(
                (
                    f.finding_id,
                    f.case_id,
                    f.source_artifact_id,
                    f.source_artifact_hash,
                    f.tool_id,
                    f.tool_version,
                    f.timestamp_utc,
                    f.artifact_type,
                    f.category,
                    f.event_id,
                    f.severity,
                    f.host,
                    f.user,
                    f.process_name,
                    f.command_line,
                    f.raw_reference,
                    f.summary,
                    proj_str,
                    f.raw_data_path,
                    search_tokens,
                )
            )

        try:
            self._conn.executemany(
                """
                INSERT OR REPLACE INTO findings (
                    finding_id, case_id, source_artifact_id, source_artifact_hash, tool_id, tool_version,
                    timestamp_utc, artifact_type, category, event_id, severity,
                    host, user_name, process_name, command_line, raw_reference,
                    summary, projected_data, raw_data_path, search_tokens
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                rows,
            )
            return len(rows)
        except Exception as e:
            raise StorageError(f"Failed to batch insert findings: {e}") from e

    def get_finding(self, finding_id: str, case_id: Optional[str] = None) -> Optional[ForensicFinding]:
        """Retrieve a single finding by finding_id, optionally scoped to a specific case_id."""
        if case_id:
            cursor = self._conn.execute(
                f"SELECT {FINDINGS_SELECT_COLS} FROM findings WHERE finding_id = ? AND case_id = ? LIMIT 1;",
                [finding_id, case_id],
            )
        else:
            cursor = self._conn.execute(
                f"SELECT {FINDINGS_SELECT_COLS} FROM findings WHERE finding_id = ? LIMIT 1;",
                [finding_id],
            )
        row = cursor.fetchone()
        return self._row_to_finding(row) if row else None

    def get_findings_by_ids(self, finding_ids: List[str], case_id: Optional[str] = None) -> List[ForensicFinding]:
        """Retrieve multiple findings by IDs, optionally scoped to a specific case_id."""
        if not finding_ids:
            return []
        placeholders = ", ".join(["?"] * len(finding_ids))
        sql = f"SELECT {FINDINGS_SELECT_COLS} FROM findings WHERE finding_id IN ({placeholders})"
        params: List[Any] = list(finding_ids)
        if case_id:
            sql += " AND case_id = ?"
            params.append(case_id)
        cursor = self._conn.execute(sql, params)
        return [self._row_to_finding(r) for r in cursor.fetchall()]

    def check_citations_exist(
        self,
        finding_ids: List[str],
        artifact_hashes: List[str],
        case_id: Optional[str] = None,
    ) -> Tuple[Set[str], Set[str]]:
        """Verify presence of cited finding IDs and artifact hashes in the store.

        Returns (verified_finding_ids, verified_artifact_hashes).
        """
        verified_findings: Set[str] = set()
        verified_hashes: Set[str] = set()

        if finding_ids:
            placeholders = ", ".join(["?"] * len(finding_ids))
            sql = f"SELECT finding_id, source_artifact_hash, case_id FROM findings WHERE finding_id IN ({placeholders})"
            params: List[Any] = list(finding_ids)
            if case_id:
                sql += " AND case_id = ?"
                params.append(case_id)
            cursor = self._conn.execute(sql, params)
            for row in cursor.fetchall():
                f_id, f_hash, _ = row
                verified_findings.add(f_id)
                # Any hash referenced by existing finding is also verified
                if f_hash in artifact_hashes:
                    verified_hashes.add(f_hash)

        if artifact_hashes:
            missing_hashes = set(artifact_hashes) - verified_hashes
            if missing_hashes:
                placeholders = ", ".join(["?"] * len(missing_hashes))
                sql = f"SELECT DISTINCT source_artifact_hash FROM findings WHERE source_artifact_hash IN ({placeholders})"
                params = list(missing_hashes)
                if case_id:
                    sql += " AND case_id = ?"
                    params.append(case_id)
                cursor = self._conn.execute(sql, params)
                for (h,) in cursor.fetchall():
                    verified_hashes.add(h)

        return verified_findings, verified_hashes

    def query_structured_findings(
        self,
        case_id: Optional[str] = None,
        filters: Optional[Dict[str, Any]] = None,
        pivots: Optional[Dict[str, Any]] = None,
        limit: int = 100,
        offset: int = 0,
        order_by: str = "timestamp_utc",
        ascending: bool = True,
    ) -> List[ForensicFinding]:
        """Perform structured querying with optional filters and pivots."""
        where_clauses: List[str] = []
        params: List[Any] = []

        if order_by not in ALLOWED_FINDING_COLUMNS:
            raise StorageError(f"Invalid or unauthorized order_by column: '{order_by}'")

        if case_id:
            where_clauses.append("case_id = ?")
            params.append(case_id)

        if filters:
            for field, val in filters.items():
                if val is None:
                    continue
                if field not in ALLOWED_FINDING_COLUMNS:
                    raise StorageError(f"Invalid or unauthorized filter field: '{field}'")
                db_col = "user_name" if field == "user" else field
                if isinstance(val, (list, tuple, set)):
                    if not val:
                        continue
                    phs = ", ".join(["?"] * len(val))
                    where_clauses.append(f"{db_col} IN ({phs})")
                    params.extend(list(val))
                else:
                    where_clauses.append(f"{db_col} = ?")
                    params.append(str(val))

        if pivots:
            # Handle incoming workflow edge pivots
            users = pivots.get("compromised_users") or pivots.get("users")
            if users:
                user_list = [users] if isinstance(users, str) else list(users)
                phs = ", ".join(["?"] * len(user_list))
                where_clauses.append(f"user_name IN ({phs})")
                params.extend(user_list)

            processes = pivots.get("process_names") or pivots.get("processes")
            if processes:
                proc_list = [processes] if isinstance(processes, str) else list(processes)
                phs = ", ".join(["?"] * len(proc_list))
                where_clauses.append(f"process_name IN ({phs})")
                params.extend(proc_list)

            hosts = pivots.get("hosts")
            if hosts:
                host_list = [hosts] if isinstance(hosts, str) else list(hosts)
                phs = ", ".join(["?"] * len(host_list))
                where_clauses.append(f"host IN ({phs})")
                params.extend(host_list)

            verified_ids = pivots.get("verified_finding_ids")
            if verified_ids:
                id_list = [verified_ids] if isinstance(verified_ids, str) else list(verified_ids)
                phs = ", ".join(["?"] * len(id_list))
                where_clauses.append(f"finding_id IN ({phs})")
                params.extend(id_list)

            ips = pivots.get("source_ips") or pivots.get("ips")
            if ips:
                ip_list = [ips] if isinstance(ips, str) else list(ips)
                ip_conds = []
                for ip in ip_list:
                    ip_conds.append("(search_tokens LIKE ? OR host = ?)")
                    params.extend([f"%{ip.lower()}%", ip])
                where_clauses.append(f"({' OR '.join(ip_conds)})")

        where_stmt = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
        col_name = "user_name" if order_by == "user" else order_by
        direction = "ASC" if ascending else "DESC"

        sql = f"SELECT {FINDINGS_SELECT_COLS} FROM findings {where_stmt} ORDER BY {col_name} {direction} LIMIT ? OFFSET ?;"
        params.extend([limit, offset])

        try:
            cursor = self._conn.execute(sql, params)
            return [self._row_to_finding(r) for r in cursor.fetchall()]
        except Exception as e:
            raise StorageError(f"Failed to query structured findings: {e}") from e

    def get_timeline_window(
        self,
        case_id: str,
        pivot_timestamp_utc: str,
        window_before_seconds: int = 300,
        window_after_seconds: int = 300,
        host: Optional[str] = None,
        limit: int = 200,
    ) -> List[ForensicFinding]:
        """Retrieve findings occurring within a temporal window around a pivot timestamp."""
        try:
            clean_ts = pivot_timestamp_utc.replace("Z", "+00:00")
            dt = datetime.fromisoformat(clean_ts)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
        except Exception as e:
            raise StorageError(f"Invalid pivot timestamp format '{pivot_timestamp_utc}': {e}") from e

        min_dt = dt - timedelta(seconds=window_before_seconds)
        max_dt = dt + timedelta(seconds=window_after_seconds)

        min_ts = min_dt.isoformat()
        max_ts = max_dt.isoformat()

        sql = f"""
            SELECT {FINDINGS_SELECT_COLS} FROM findings
            WHERE case_id = ?
              AND timestamp_utc IS NOT NULL
              AND timestamp_utc >= ?
              AND timestamp_utc <= ?
        """
        params: List[Any] = [case_id, min_ts, max_ts]
        if host:
            sql += " AND host = ?"
            params.append(host)

        sql += " ORDER BY timestamp_utc ASC LIMIT ?;"
        params.append(limit)

        try:
            cursor = self._conn.execute(sql, params)
            return [self._row_to_finding(r) for r in cursor.fetchall()]
        except Exception as e:
            raise StorageError(f"Failed to query timeline window: {e}") from e

    def hybrid_search(
        self,
        query: str,
        case_id: Optional[str] = None,
        artifact_type: Optional[str] = None,
        top_k: int = 10,
    ) -> List[ForensicFinding]:
        """Perform hybrid search over findings using term overlap and field-weighted ranking."""
        if not query or not query.strip():
            return []

        raw_tokens = re.findall(r"\w+", query.lower())
        if not raw_tokens:
            return []

        # Filter candidates matching any token in search_tokens
        where_clauses: List[str] = []
        params: List[Any] = []

        if case_id:
            where_clauses.append("case_id = ?")
            params.append(case_id)

        if artifact_type:
            where_clauses.append("artifact_type = ?")
            params.append(artifact_type)

        token_clauses = []
        for token in raw_tokens:
            token_clauses.append("search_tokens LIKE ?")
            params.append(f"%{token}%")

        where_clauses.append(f"({' OR '.join(token_clauses)})")
        where_stmt = f"WHERE {' AND '.join(where_clauses)}"

        sql = f"SELECT {FINDINGS_SELECT_COLS} FROM findings {where_stmt} LIMIT 300;"
        try:
            cursor = self._conn.execute(sql, params)
            rows = cursor.fetchall()
        except Exception as e:
            raise StorageError(f"Hybrid search query failed: {e}") from e

        # Python-side weighted ranking
        scored_findings: List[Tuple[float, ForensicFinding]] = []
        query_lower = query.lower()

        for r in rows:
            finding = self._row_to_finding(r)
            score = 0.0

            summary_lower = (finding.summary or "").lower()
            cmd_lower = (finding.command_line or "").lower()
            proc_lower = (finding.process_name or "").lower()
            user_lower = (finding.user or "").lower()
            host_lower = (finding.host or "").lower()
            tokens_lower = (r[18] or "").lower()

            # Exact phrase match boost
            if query_lower in summary_lower:
                score += 10.0
            if query_lower in cmd_lower:
                score += 15.0
            if query_lower in proc_lower:
                score += 12.0

            # Individual token matches
            for token in raw_tokens:
                if token in cmd_lower:
                    score += 4.0
                if token in proc_lower:
                    score += 3.5
                if token in summary_lower:
                    score += 2.5
                if token in user_lower or token in host_lower:
                    score += 2.0
                if token in tokens_lower:
                    score += 1.0

            # Severity boost
            if finding.severity in ("critical", "high"):
                score *= 1.25

            scored_findings.append((score, finding))

        scored_findings.sort(key=lambda item: item[0], reverse=True)
        return [f for _, f in scored_findings[:top_k]]

    def create_dataset_view(self, view_name: str, query_filter: Dict[str, Any], case_id: Optional[str] = None) -> str:
        """Create a queryable DuckDB view pointer for LangGraph DAG edges."""
        # Sanitize view name to prevent SQL injection
        safe_name = re.sub(r"[^a-zA-Z0-9_]", "_", view_name)
        where_clauses = []
        params = []

        if case_id:
            if not re.match(r"^[a-zA-Z0-9_-]+$", case_id):
                raise StorageError(f"Invalid case_id format: '{case_id}'")
            where_clauses.append(f"case_id = '{case_id}'")

        for k, v in query_filter.items():
            if k not in ALLOWED_FINDING_COLUMNS:
                raise StorageError(f"Invalid or unauthorized column in query_filter: '{k}'")
            col = "user_name" if k == "user" else k
            if isinstance(v, str):
                escaped = v.replace("'", "''")
                where_clauses.append(f"{col} = '{escaped}'")
            elif isinstance(v, (int, float)):
                where_clauses.append(f"{col} = {v}")
            elif isinstance(v, (list, tuple)):
                items = [f"'{str(item).replace('\'', '\'\'')}'" for item in v]
                where_clauses.append(f"{col} IN ({', '.join(items)})")

        where_stmt = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
        sql = f"CREATE OR REPLACE VIEW {safe_name} AS SELECT * FROM findings {where_stmt};"

        try:
            self._conn.execute(sql)
            return safe_name
        except Exception as e:
            raise StorageError(f"Failed to create dataset view '{safe_name}': {e}") from e

    def count_findings(self, case_id: Optional[str] = None) -> int:
        """Count findings in store, optionally scoped by case_id."""
        if case_id:
            res = self._conn.execute("SELECT COUNT(*) FROM findings WHERE case_id = ?;", [case_id]).fetchone()
        else:
            res = self._conn.execute("SELECT COUNT(*) FROM findings;").fetchone()
        return res[0] if res else 0

    def close(self) -> None:
        """Close database connection."""
        if hasattr(self, "_conn") and self._conn:
            self._conn.close()

    def __enter__(self) -> ForensicStore:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
