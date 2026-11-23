"""SQLite Persistence Store for LLM Runtime Settings, Smoke-Test Status & Audit Logging.

Standards:
- Local-first SQLite store (defaulting to vault/llm_state.db or :memory: for tests).
- Thread-safe connection pooling with check_same_thread=False.
- Strict Zero Secret Leakage: API keys are NEVER written to SQLite tables.
- Append-only audit logging tracking every model switch and smoke test with cloud transmission flag.
"""
from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union


def sanitize_session_data(data: Any) -> Any:
    """Recursively strip credentials, passwords, tokens, and secrets from persisted session data (SEC-UI-001)."""
    if isinstance(data, dict):
        cleaned = {}
        for k, v in data.items():
            norm_k = str(k).lower().replace("_", "").replace("-", "")
            if norm_k in {
                "siemapikey",
                "apikey",
                "password",
                "passwd",
                "token",
                "secret",
                "credentials",
            }:
                continue
            cleaned[k] = sanitize_session_data(v)
        return cleaned
    elif isinstance(data, list):
        return [sanitize_session_data(item) for item in data]
    return data


class LLMStateStore:
    """Thread-safe SQLite store for LLM runtime settings, smoke-test history, and audit logs."""

    def __init__(self, db_path: Optional[Union[str, Path]] = None):
        """Initialize LLMStateStore. Uses ':memory:' if db_path is None or ':memory:'."""
        if db_path is None or str(db_path) == ":memory:":
            self._db_path = ":memory:"
        else:
            p = Path(db_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            self._db_path = str(p)

        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        if self._db_path != ":memory:":
            try:
                if os.name != "nt" and os.path.exists(self._db_path):
                    os.chmod(self._db_path, 0o600)
            except Exception:
                pass
        self._init_tables()

    def _init_tables(self) -> None:
        """Create the 3 core tables: runtime settings, smoke-test status, and audit log."""
        with self._conn:
            # 1. Runtime Settings (persists active provider selection across server restarts)
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS llm_runtime_settings (
                    key TEXT PRIMARY KEY,
                    active_provider_id TEXT NOT NULL,
                    updated_at_utc TEXT NOT NULL
                );
                """
            )

            # 2. Smoke-Test Status (persists per-provider test latency and status)
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS llm_smoke_test_status (
                    provider_id TEXT PRIMARY KEY,
                    last_success INTEGER NOT NULL,
                    last_latency_ms INTEGER NOT NULL,
                    response_preview TEXT,
                    error_detail TEXT,
                    tested_at_utc TEXT NOT NULL
                );
                """
            )

            # 3. Provider Audit Log (append-only forensic record of all switches and tests)
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS llm_provider_audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    provider_id TEXT NOT NULL,
                    is_cloud_transmission INTEGER NOT NULL,
                    details TEXT,
                    timestamp_utc TEXT NOT NULL
                );
                """
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_llm_audit_timestamp ON llm_provider_audit_log(timestamp_utc DESC);"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_llm_audit_provider ON llm_provider_audit_log(provider_id);"
            )

            # 4. Evidence Intake Uploads (metadata log of streaming evidence uploads)
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS evidence_intake_uploads (
                    upload_id TEXT PRIMARY KEY,
                    filename TEXT NOT NULL,
                    stored_path TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    sha256 TEXT NOT NULL,
                    sha512 TEXT NOT NULL,
                    artifact_type TEXT NOT NULL,
                    uploaded_at_utc TEXT NOT NULL
                );
                """
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_evidence_upload_sha256 ON evidence_intake_uploads(sha256);"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_evidence_upload_time ON evidence_intake_uploads(uploaded_at_utc DESC);"
            )

            # 5. Investigation Sessions (persists wizard inputs and workflow state across reloads/restarts)
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS investigation_sessions (
                    case_id TEXT PRIMARY KEY,
                    wizard_state TEXT NOT NULL,
                    workflow_state TEXT NOT NULL,
                    active_tab TEXT NOT NULL DEFAULT 'wizard',
                    updated_at_utc TEXT NOT NULL
                );
                """
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_investigation_sessions_time ON investigation_sessions(updated_at_utc DESC);"
            )

            # 6. Forensic Cases Registry & Vault Sharing
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cases (
                    case_id TEXT PRIMARY KEY,
                    case_name TEXT NOT NULL,
                    organization_name TEXT NOT NULL,
                    investigation_goal TEXT,
                    lead_analyst TEXT NOT NULL,
                    active_provider_id TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'OPEN',
                    is_shared_to_vault INTEGER NOT NULL DEFAULT 0,
                    created_at_utc TEXT NOT NULL,
                    updated_at_utc TEXT NOT NULL,
                    serialized_state TEXT
                );
                """
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_cases_updated ON cases(updated_at_utc DESC);"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_cases_vault ON cases(is_shared_to_vault);"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_cases_org ON cases(organization_name);"
            )

            # 7. Autonomous Investigation States (Phase 06)
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS investigation_states (
                    investigation_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    investigator TEXT NOT NULL,
                    lifecycle_state TEXT NOT NULL,
                    objective TEXT NOT NULL,
                    plan_json TEXT NOT NULL,
                    current_iteration INTEGER NOT NULL DEFAULT 0,
                    budget_json TEXT NOT NULL,
                    pivots_json TEXT NOT NULL,
                    evidence_scope_json TEXT NOT NULL,
                    hypotheses_json TEXT NOT NULL,
                    evidence_gaps_json TEXT NOT NULL,
                    completed_actions_json TEXT NOT NULL,
                    pending_actions_json TEXT NOT NULL,
                    execution_ids_json TEXT NOT NULL,
                    findings_count INTEGER NOT NULL DEFAULT 0,
                    errors_json TEXT NOT NULL,
                    pause_reason TEXT,
                    started_at_utc TEXT NOT NULL,
                    created_at_utc TEXT NOT NULL,
                    updated_at_utc TEXT NOT NULL
                );
                """
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_inv_state_case ON investigation_states(case_id);"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_inv_state_lifecycle ON investigation_states(lifecycle_state);"
            )

            # 8. Investigation Step Execution Traces (Phase 06)
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS investigation_traces (
                    trace_id TEXT PRIMARY KEY,
                    investigation_id TEXT NOT NULL,
                    case_id TEXT NOT NULL,
                    iteration INTEGER NOT NULL,
                    step_name TEXT NOT NULL,
                    inputs_json TEXT NOT NULL,
                    outputs_json TEXT NOT NULL,
                    executed_queries_json TEXT NOT NULL,
                    cited_finding_ids_json TEXT NOT NULL,
                    tool_executions_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    duration_seconds REAL NOT NULL DEFAULT 0.0,
                    created_at_utc TEXT NOT NULL
                );
                """
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_inv_traces_inv ON investigation_traces(investigation_id);"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_inv_traces_case ON investigation_traces(case_id);"
            )

            # 9. Encrypted SIEM Connections & Credential Store (Phase 14.2-B / SEC-UI-001)
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS siem_connections (
                    connection_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    siem_type TEXT NOT NULL,
                    endpoint_url TEXT NOT NULL,
                    index_pattern TEXT,
                    allowed_hosts_json TEXT,
                    headers_json TEXT,
                    verify_ssl INTEGER NOT NULL DEFAULT 1,
                    timeout_seconds REAL NOT NULL DEFAULT 30.0,
                    encrypted_credentials TEXT NOT NULL,
                    has_password INTEGER NOT NULL DEFAULT 0,
                    has_api_key INTEGER NOT NULL DEFAULT 0,
                    has_token INTEGER NOT NULL DEFAULT 0,
                    username TEXT,
                    created_by TEXT NOT NULL,
                    created_at_utc TEXT NOT NULL,
                    updated_at_utc TEXT NOT NULL
                );
                """
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_siem_conn_case ON siem_connections(case_id);"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_siem_conn_updated ON siem_connections(updated_at_utc DESC);"
            )

            # 10. Consumed Approval Tokens & Hash Chaining (Phase 14.3)
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS consumed_approval_tokens (
                    token_id TEXT PRIMARY KEY,
                    approval_id TEXT NOT NULL,
                    case_id TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    parameter_digest TEXT NOT NULL,
                    consumed_by TEXT NOT NULL,
                    consumed_at_utc TEXT NOT NULL,
                    previous_hash TEXT NOT NULL DEFAULT '',
                    current_hash TEXT NOT NULL DEFAULT ''
                );
                """
            )
            # Safe schema migrations for existing databases
            existing_consumed_cols = {row[1] for row in self._conn.execute("PRAGMA table_info(consumed_approval_tokens)").fetchall()}
            if "previous_hash" not in existing_consumed_cols:
                self._conn.execute("ALTER TABLE consumed_approval_tokens ADD COLUMN previous_hash TEXT NOT NULL DEFAULT ''")
            if "current_hash" not in existing_consumed_cols:
                self._conn.execute("ALTER TABLE consumed_approval_tokens ADD COLUMN current_hash TEXT NOT NULL DEFAULT ''")

            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_consumed_appr_id ON consumed_approval_tokens(approval_id);")
            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_consumed_case ON consumed_approval_tokens(case_id);")

            # 11. Hash-Chained Approval Audit Log (Phase 14.3)
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS approval_audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT UNIQUE NOT NULL,
                    case_id TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target TEXT NOT NULL,
                    requesting_principal_id TEXT,
                    approving_principal_id TEXT,
                    details_json TEXT NOT NULL,
                    timestamp_utc TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    current_hash TEXT NOT NULL
                );
                """
            )
            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_approval_audit_case ON approval_audit_log(case_id);")
            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_approval_audit_timestamp ON approval_audit_log(timestamp_utc DESC);")
            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_approval_audit_action ON approval_audit_log(action);")

    def get_active_provider_id(self, default: str = "lm_studio_local") -> str:
        """Retrieve the persisted active provider ID, or return default if not set."""
        cursor = self._conn.execute(
            "SELECT active_provider_id FROM llm_runtime_settings WHERE key = 'active_selection';"
        )
        row = cursor.fetchone()
        return row[0] if row else default

    def set_active_provider_id(self, provider_id: str) -> None:
        """Persist the currently selected active provider ID in SQLite."""
        now_utc = datetime.now(timezone.utc).isoformat()
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO llm_runtime_settings (key, active_provider_id, updated_at_utc)
                VALUES ('active_selection', ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    active_provider_id = excluded.active_provider_id,
                    updated_at_utc = excluded.updated_at_utc;
                """,
                (provider_id, now_utc),
            )

    def get_smoke_test_status(self, provider_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve persisted smoke-test status for a specific provider."""
        cursor = self._conn.execute(
            """
            SELECT provider_id, last_success, last_latency_ms, response_preview, error_detail, tested_at_utc
            FROM llm_smoke_test_status
            WHERE provider_id = ?;
            """,
            (provider_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        return {
            "provider_id": row[0],
            "last_success": bool(row[1]),
            "last_latency_ms": row[2],
            "response_preview": row[3],
            "error_detail": row[4],
            "tested_at_utc": row[5],
        }

    def get_all_smoke_test_statuses(self) -> Dict[str, Dict[str, Any]]:
        """Retrieve all persisted smoke-test statuses keyed by provider_id."""
        cursor = self._conn.execute(
            """
            SELECT provider_id, last_success, last_latency_ms, response_preview, error_detail, tested_at_utc
            FROM llm_smoke_test_status;
            """
        )
        results: Dict[str, Dict[str, Any]] = {}
        for row in cursor.fetchall():
            results[row[0]] = {
                "provider_id": row[0],
                "last_success": bool(row[1]),
                "last_latency_ms": row[2],
                "response_preview": row[3],
                "error_detail": row[4],
                "tested_at_utc": row[5],
            }
        return results

    def record_smoke_test(
        self,
        provider_id: str,
        success: bool,
        latency_ms: int,
        response_preview: Optional[str] = None,
        error_detail: Optional[str] = None,
    ) -> None:
        """Persist or update the smoke-test outcome for a provider."""
        now_utc = datetime.now(timezone.utc).isoformat()
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO llm_smoke_test_status (
                    provider_id, last_success, last_latency_ms, response_preview, error_detail, tested_at_utc
                )
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(provider_id) DO UPDATE SET
                    last_success = excluded.last_success,
                    last_latency_ms = excluded.last_latency_ms,
                    response_preview = excluded.response_preview,
                    error_detail = excluded.error_detail,
                    tested_at_utc = excluded.tested_at_utc;
                """,
                (
                    provider_id,
                    1 if success else 0,
                    latency_ms,
                    response_preview,
                    error_detail,
                    now_utc,
                ),
            )

    def record_audit_log(
        self,
        event_type: str,
        provider_id: str,
        is_cloud_transmission: bool,
        details: Optional[str] = None,
    ) -> None:
        """Append an entry to the forensic provider audit log."""
        now_utc = datetime.now(timezone.utc).isoformat()
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO llm_provider_audit_log (
                    event_type, provider_id, is_cloud_transmission, details, timestamp_utc
                )
                VALUES (?, ?, ?, ?, ?);
                """,
                (
                    event_type,
                    provider_id,
                    1 if is_cloud_transmission else 0,
                    details,
                    now_utc,
                ),
            )

    def get_audit_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve recent audit log entries in reverse chronological order."""
        cursor = self._conn.execute(
            """
            SELECT id, event_type, provider_id, is_cloud_transmission, details, timestamp_utc
            FROM llm_provider_audit_log
            ORDER BY id DESC
            LIMIT ?;
            """,
            (limit,),
        )
        logs = []
        for row in cursor.fetchall():
            logs.append(
                {
                    "id": row[0],
                    "event_type": row[1],
                    "provider_id": row[2],
                    "is_cloud_transmission": bool(row[3]),
                    "details": row[4],
                    "timestamp_utc": row[5],
                }
            )
        return logs

    def record_evidence_upload(
        self,
        upload_id: str,
        filename: str,
        stored_path: str,
        size_bytes: int,
        sha256: str,
        sha512: str,
        artifact_type: str,
    ) -> None:
        """Record uploaded evidence file metadata in SQLite."""
        now_utc = datetime.now(timezone.utc).isoformat()
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO evidence_intake_uploads (
                    upload_id, filename, stored_path, size_bytes, sha256, sha512, artifact_type, uploaded_at_utc
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(upload_id) DO UPDATE SET
                    filename = excluded.filename,
                    stored_path = excluded.stored_path,
                    size_bytes = excluded.size_bytes,
                    sha256 = excluded.sha256,
                    sha512 = excluded.sha512,
                    artifact_type = excluded.artifact_type,
                    uploaded_at_utc = excluded.uploaded_at_utc;
                """,
                (
                    upload_id,
                    filename,
                    stored_path,
                    size_bytes,
                    sha256,
                    sha512,
                    artifact_type,
                    now_utc,
                ),
            )

    def get_evidence_upload(self, upload_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve upload record by upload_id."""
        cursor = self._conn.execute(
            """
            SELECT upload_id, filename, stored_path, size_bytes, sha256, sha512, artifact_type, uploaded_at_utc
            FROM evidence_intake_uploads
            WHERE upload_id = ?;
            """,
            (upload_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        return {
            "upload_id": row[0],
            "filename": row[1],
            "stored_path": row[2],
            "size_bytes": row[3],
            "sha256": row[4],
            "sha512": row[5],
            "artifact_type": row[6],
            "uploaded_at_utc": row[7],
        }

    def list_evidence_uploads(self, limit: int = 50) -> List[Dict[str, Any]]:
        """List recent evidence intake uploads."""
        cursor = self._conn.execute(
            """
            SELECT upload_id, filename, stored_path, size_bytes, sha256, sha512, artifact_type, uploaded_at_utc
            FROM evidence_intake_uploads
            ORDER BY uploaded_at_utc DESC
            LIMIT ?;
            """,
            (limit,),
        )
        uploads = []
        for row in cursor.fetchall():
            uploads.append(
                {
                    "upload_id": row[0],
                    "filename": row[1],
                    "stored_path": row[2],
                    "size_bytes": row[3],
                    "sha256": row[4],
                    "sha512": row[5],
                    "artifact_type": row[6],
                    "uploaded_at_utc": row[7],
                }
            )
        return uploads

    def save_investigation_session(
        self,
        case_id: str,
        wizard_state: Union[Dict[str, Any], str],
        workflow_state: Union[Dict[str, Any], str],
        active_tab: str = "wizard",
    ) -> Dict[str, Any]:
        """Persist or update top-level investigation wizard and workflow state in SQLite."""
        now_utc = datetime.now(timezone.utc).isoformat()
        try:
            raw_wiz = json.loads(wizard_state) if isinstance(wizard_state, str) else wizard_state
        except Exception:
            raw_wiz = {}
        try:
            raw_wf = json.loads(workflow_state) if isinstance(workflow_state, str) else workflow_state
        except Exception:
            raw_wf = {}

        # SEC-UI-001: Strip any credentials, passwords, or tokens prior to storage
        clean_wiz = sanitize_session_data(raw_wiz)
        clean_wf = sanitize_session_data(raw_wf)

        wiz_str = json.dumps(clean_wiz, ensure_ascii=False)
        wf_str = json.dumps(clean_wf, ensure_ascii=False)

        with self._conn:
            self._conn.execute(
                """
                INSERT INTO investigation_sessions (case_id, wizard_state, workflow_state, active_tab, updated_at_utc)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(case_id) DO UPDATE SET
                    wizard_state = excluded.wizard_state,
                    workflow_state = excluded.workflow_state,
                    active_tab = excluded.active_tab,
                    updated_at_utc = excluded.updated_at_utc;
                """,
                (case_id, wiz_str, wf_str, active_tab, now_utc),
            )
        return {
            "case_id": case_id,
            "wizard_state": clean_wiz,
            "workflow_state": clean_wf,
            "active_tab": active_tab,
            "updated_at_utc": now_utc,
        }

    def get_investigation_session(self, case_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve persisted investigation session for a case, decoding stored JSON objects."""
        cursor = self._conn.execute(
            """
            SELECT case_id, wizard_state, workflow_state, active_tab, updated_at_utc
            FROM investigation_sessions
            WHERE case_id = ?;
            """,
            (case_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None

        try:
            wiz = sanitize_session_data(json.loads(row[1])) if row[1] else {}
        except Exception:
            wiz = {}
        try:
            wf = sanitize_session_data(json.loads(row[2])) if row[2] else {}
        except Exception:
            wf = {}

        return {
            "case_id": row[0],
            "wizard_state": wiz,
            "workflow_state": wf,
            "active_tab": row[3],
            "updated_at_utc": row[4],
        }

    def list_investigation_sessions(self, limit: int = 50) -> List[Dict[str, Any]]:
        """List all active/persisted investigation sessions ordered by last update."""
        cursor = self._conn.execute(
            """
            SELECT case_id, wizard_state, workflow_state, active_tab, updated_at_utc
            FROM investigation_sessions
            ORDER BY updated_at_utc DESC
            LIMIT ?;
            """,
            (limit,),
        )
        sessions = []
        for row in cursor.fetchall():
            try:
                wiz = json.loads(row[1]) if row[1] else {}
            except Exception:
                wiz = {}
            try:
                wf = json.loads(row[2]) if row[2] else {}
            except Exception:
                wf = {}
            sessions.append(
                {
                    "case_id": row[0],
                    "wizard_state": wiz,
                    "workflow_state": wf,
                    "active_tab": row[3],
                    "updated_at_utc": row[4],
                }
            )
        return sessions

    def delete_investigation_session(self, case_id: str) -> bool:
        """Delete an investigation session from SQLite."""
        with self._conn:
            cursor = self._conn.execute(
                "DELETE FROM investigation_sessions WHERE case_id = ?;",
                (case_id,),
            )
            return cursor.rowcount > 0

    # =========================================================================
    # Case Registry & Forensic Case Vault Methods
    # =========================================================================
    def create_or_update_case(self, case_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create or update a case in SQLite."""
        case_id = case_data["case_id"]
        now_utc = datetime.now(timezone.utc).isoformat()
        existing = self.get_case(case_id)

        case_name = case_data.get("case_name") or (existing["case_name"] if existing else f"Case {case_id}")
        org_name = case_data.get("organization_name") or (existing["organization_name"] if existing else "Default Organization")
        goal = case_data.get("investigation_goal") if "investigation_goal" in case_data else (existing.get("investigation_goal") if existing else None)
        analyst = case_data.get("lead_analyst") or (existing["lead_analyst"] if existing else "analyst_lead")
        provider = case_data.get("active_provider_id") or (existing["active_provider_id"] if existing else self.get_active_provider_id())
        status = case_data.get("status") or (existing["status"] if existing else "OPEN")
        is_shared = int(case_data.get("is_shared_to_vault", existing["is_shared_to_vault"] if existing else 0))
        created_at = existing["created_at_utc"] if existing else now_utc

        state = case_data.get("serialized_state")
        if state is None and existing:
            raw_s = existing.get("serialized_state", {})
            state_str = json.dumps(sanitize_session_data(raw_s))
        elif isinstance(state, dict):
            state_str = json.dumps(sanitize_session_data(state))
        elif isinstance(state, str):
            try:
                parsed_s = json.loads(state)
                state_str = json.dumps(sanitize_session_data(parsed_s))
            except Exception:
                state_str = state
        else:
            state_str = "{}"

        with self._conn:
            self._conn.execute(
                """
                INSERT INTO cases (
                    case_id, case_name, organization_name, investigation_goal,
                    lead_analyst, active_provider_id, status, is_shared_to_vault,
                    created_at_utc, updated_at_utc, serialized_state
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(case_id) DO UPDATE SET
                    case_name = excluded.case_name,
                    organization_name = excluded.organization_name,
                    investigation_goal = excluded.investigation_goal,
                    lead_analyst = excluded.lead_analyst,
                    active_provider_id = excluded.active_provider_id,
                    status = excluded.status,
                    is_shared_to_vault = excluded.is_shared_to_vault,
                    updated_at_utc = excluded.updated_at_utc,
                    serialized_state = excluded.serialized_state;
                """,
                (
                    case_id,
                    case_name,
                    org_name,
                    goal,
                    analyst,
                    provider,
                    status,
                    is_shared,
                    created_at,
                    now_utc,
                    state_str,
                ),
            )

        return self.get_case(case_id)  # type: ignore

    def get_case(self, case_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single case by ID with decoded serialized state."""
        cursor = self._conn.execute(
            """
            SELECT case_id, case_name, organization_name, investigation_goal,
                   lead_analyst, active_provider_id, status, is_shared_to_vault,
                   created_at_utc, updated_at_utc, serialized_state
            FROM cases
            WHERE case_id = ?;
            """,
            (case_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None

        try:
            state = json.loads(row[10]) if row[10] else {}
        except Exception:
            state = {}

        return {
            "case_id": row[0],
            "case_name": row[1],
            "organization_name": row[2],
            "investigation_goal": row[3],
            "lead_analyst": row[4],
            "active_provider_id": row[5],
            "status": row[6],
            "is_shared_to_vault": bool(row[7]),
            "created_at_utc": row[8],
            "updated_at_utc": row[9],
            "serialized_state": state,
        }

    def list_cases(
        self,
        search: Optional[str] = None,
        status: Optional[str] = None,
        vault_only: bool = False,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Query and list cases with optional search and status filtering."""
        clauses = []
        params: List[Any] = []

        if vault_only:
            clauses.append("is_shared_to_vault = 1")

        if status and status.upper() != "ALL":
            clauses.append("status = ?")
            params.append(status.upper())

        if search and search.strip():
            term = f"%{search.strip().lower()}%"
            clauses.append(
                "(LOWER(case_id) LIKE ? OR LOWER(case_name) LIKE ? OR LOWER(organization_name) LIKE ? OR LOWER(investigation_goal) LIKE ?)"
            )
            params.extend([term, term, term, term])

        where_stmt = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"""
            SELECT case_id, case_name, organization_name, investigation_goal,
                   lead_analyst, active_provider_id, status, is_shared_to_vault,
                   created_at_utc, updated_at_utc, serialized_state
            FROM cases
            {where_stmt}
            ORDER BY updated_at_utc DESC
            LIMIT ?;
        """
        params.append(limit)

        cursor = self._conn.execute(sql, params)
        results = []
        for row in cursor.fetchall():
            try:
                state = json.loads(row[10]) if row[10] else {}
            except Exception:
                state = {}
            results.append(
                {
                    "case_id": row[0],
                    "case_name": row[1],
                    "organization_name": row[2],
                    "investigation_goal": row[3],
                    "lead_analyst": row[4],
                    "active_provider_id": row[5],
                    "status": row[6],
                    "is_shared_to_vault": bool(row[7]),
                    "created_at_utc": row[8],
                    "updated_at_utc": row[9],
                    "serialized_state": state,
                }
            )
        return results

    def toggle_case_vault_share(self, case_id: str, is_shared: bool) -> bool:
        """Toggle case sharing to the Forensic Case Vault."""
        now_utc = datetime.now(timezone.utc).isoformat()
        with self._conn:
            cursor = self._conn.execute(
                """
                UPDATE cases
                SET is_shared_to_vault = ?, updated_at_utc = ?
                WHERE case_id = ?;
                """,
                (1 if is_shared else 0, now_utc, case_id),
            )
            return cursor.rowcount > 0

    def delete_case(self, case_id: str) -> bool:
        """Delete a case from SQLite."""
        with self._conn:
            cursor = self._conn.execute("DELETE FROM cases WHERE case_id = ?;", (case_id,))
            return cursor.rowcount > 0

    # --------------------------------------------------------------------------
    # Autonomous Investigation Persistence (Phase 06)
    # --------------------------------------------------------------------------
    def save_investigation_state(self, record: Any) -> None:
        """Persist or update an autonomous investigation state in SQLite."""
        now_utc = datetime.now(timezone.utc).isoformat()
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO investigation_states (
                    investigation_id, case_id, investigator, lifecycle_state, objective,
                    plan_json, current_iteration, budget_json, pivots_json, evidence_scope_json,
                    hypotheses_json, evidence_gaps_json, completed_actions_json, pending_actions_json,
                    execution_ids_json, findings_count, errors_json, pause_reason,
                    started_at_utc, created_at_utc, updated_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(investigation_id) DO UPDATE SET
                    lifecycle_state = excluded.lifecycle_state,
                    objective = excluded.objective,
                    plan_json = excluded.plan_json,
                    current_iteration = excluded.current_iteration,
                    budget_json = excluded.budget_json,
                    pivots_json = excluded.pivots_json,
                    evidence_scope_json = excluded.evidence_scope_json,
                    hypotheses_json = excluded.hypotheses_json,
                    evidence_gaps_json = excluded.evidence_gaps_json,
                    completed_actions_json = excluded.completed_actions_json,
                    pending_actions_json = excluded.pending_actions_json,
                    execution_ids_json = excluded.execution_ids_json,
                    findings_count = excluded.findings_count,
                    errors_json = excluded.errors_json,
                    pause_reason = excluded.pause_reason,
                    updated_at_utc = excluded.updated_at_utc;
                """,
                (
                    record.investigation_id,
                    record.case_id,
                    record.investigator,
                    record.lifecycle_state.value if hasattr(record.lifecycle_state, "value") else str(record.lifecycle_state),
                    record.objective,
                    record.plan.model_dump_json() if hasattr(record.plan, "model_dump_json") else json.dumps(record.plan),
                    record.current_iteration,
                    record.budget.model_dump_json() if hasattr(record.budget, "model_dump_json") else json.dumps(record.budget),
                    record.pivots.model_dump_json() if hasattr(record.pivots, "model_dump_json") else json.dumps(record.pivots),
                    json.dumps(record.authorized_evidence_scope),
                    json.dumps([h.model_dump() if hasattr(h, "model_dump") else h for h in record.hypotheses]),
                    json.dumps([g.model_dump() if hasattr(g, "model_dump") else g for g in record.evidence_gaps]),
                    json.dumps([a.model_dump() if hasattr(a, "model_dump") else a for a in record.completed_actions]),
                    json.dumps([a.model_dump() if hasattr(a, "model_dump") else a for a in record.pending_actions]),
                    json.dumps(record.execution_ids),
                    record.findings_count,
                    json.dumps(record.errors),
                    record.pause_reason,
                    record.started_at_utc,
                    record.created_at_utc,
                    now_utc,
                ),
            )

    def get_investigation_state(self, investigation_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve an investigation state by ID as a raw dictionary."""
        cursor = self._conn.execute(
            """
            SELECT
                investigation_id, case_id, investigator, lifecycle_state, objective,
                plan_json, current_iteration, budget_json, pivots_json, evidence_scope_json,
                hypotheses_json, evidence_gaps_json, completed_actions_json, pending_actions_json,
                execution_ids_json, findings_count, errors_json, pause_reason,
                started_at_utc, created_at_utc, updated_at_utc
            FROM investigation_states
            WHERE investigation_id = ?;
            """,
            (investigation_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        return {
            "investigation_id": row[0],
            "case_id": row[1],
            "investigator": row[2],
            "lifecycle_state": row[3],
            "objective": row[4],
            "plan": json.loads(row[5]),
            "current_iteration": row[6],
            "budget": json.loads(row[7]),
            "pivots": json.loads(row[8]),
            "authorized_evidence_scope": json.loads(row[9]),
            "hypotheses": json.loads(row[10]),
            "evidence_gaps": json.loads(row[11]),
            "completed_actions": json.loads(row[12]),
            "pending_actions": json.loads(row[13]),
            "execution_ids": json.loads(row[14]),
            "findings_count": row[15],
            "errors": json.loads(row[16]),
            "pause_reason": row[17],
            "started_at_utc": row[18],
            "created_at_utc": row[19],
            "updated_at_utc": row[20],
        }

    def list_investigation_states(self, case_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """List investigation states, optionally filtered by case_id."""
        if case_id:
            cursor = self._conn.execute(
                """
                SELECT
                    investigation_id, case_id, investigator, lifecycle_state, objective,
                    plan_json, current_iteration, budget_json, pivots_json, evidence_scope_json,
                    hypotheses_json, evidence_gaps_json, completed_actions_json, pending_actions_json,
                    execution_ids_json, findings_count, errors_json, pause_reason,
                    started_at_utc, created_at_utc, updated_at_utc
                FROM investigation_states
                WHERE case_id = ?
                ORDER BY updated_at_utc DESC;
                """,
                (case_id,),
            )
        else:
            cursor = self._conn.execute(
                """
                SELECT
                    investigation_id, case_id, investigator, lifecycle_state, objective,
                    plan_json, current_iteration, budget_json, pivots_json, evidence_scope_json,
                    hypotheses_json, evidence_gaps_json, completed_actions_json, pending_actions_json,
                    execution_ids_json, findings_count, errors_json, pause_reason,
                    started_at_utc, created_at_utc, updated_at_utc
                FROM investigation_states
                ORDER BY updated_at_utc DESC;
                """
            )
        results = []
        for row in cursor.fetchall():
            results.append(
                {
                    "investigation_id": row[0],
                    "case_id": row[1],
                    "investigator": row[2],
                    "lifecycle_state": row[3],
                    "objective": row[4],
                    "plan": json.loads(row[5]),
                    "current_iteration": row[6],
                    "budget": json.loads(row[7]),
                    "pivots": json.loads(row[8]),
                    "authorized_evidence_scope": json.loads(row[9]),
                    "hypotheses": json.loads(row[10]),
                    "evidence_gaps": json.loads(row[11]),
                    "completed_actions": json.loads(row[12]),
                    "pending_actions": json.loads(row[13]),
                    "execution_ids": json.loads(row[14]),
                    "findings_count": row[15],
                    "errors": json.loads(row[16]),
                    "pause_reason": row[17],
                    "started_at_utc": row[18],
                    "created_at_utc": row[19],
                    "updated_at_utc": row[20],
                }
            )
        return results

    def save_investigation_trace(self, trace: Any) -> None:
        """Persist an investigation step execution trace in SQLite."""
        with self._conn:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO investigation_traces (
                    trace_id, investigation_id, case_id, iteration, step_name,
                    inputs_json, outputs_json, executed_queries_json, cited_finding_ids_json,
                    tool_executions_json, status, duration_seconds, created_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    trace.trace_id,
                    trace.investigation_id,
                    trace.case_id,
                    trace.iteration,
                    trace.step_name,
                    json.dumps(trace.inputs),
                    json.dumps(trace.outputs),
                    json.dumps(trace.executed_queries),
                    json.dumps(trace.cited_finding_ids),
                    json.dumps(trace.tool_executions),
                    trace.status,
                    trace.duration_seconds,
                    trace.created_at_utc,
                ),
            )

    def get_investigation_traces(self, investigation_id: str) -> List[Dict[str, Any]]:
        """Retrieve all execution traces for an investigation, ordered chronologically."""
        cursor = self._conn.execute(
            """
            SELECT
                trace_id, investigation_id, case_id, iteration, step_name,
                inputs_json, outputs_json, executed_queries_json, cited_finding_ids_json,
                tool_executions_json, status, duration_seconds, created_at_utc
            FROM investigation_traces
            WHERE investigation_id = ?
            ORDER BY iteration ASC, created_at_utc ASC;
            """,
            (investigation_id,),
        )
        results = []
        for row in cursor.fetchall():
            results.append(
                {
                    "trace_id": row[0],
                    "investigation_id": row[1],
                    "case_id": row[2],
                    "iteration": row[3],
                    "step_name": row[4],
                    "inputs": json.loads(row[5]),
                    "outputs": json.loads(row[6]),
                    "executed_queries": json.loads(row[7]),
                    "cited_finding_ids": json.loads(row[8]),
                    "tool_executions": json.loads(row[9]),
                    "status": row[10],
                    "duration_seconds": row[11],
                    "created_at_utc": row[12],
                }
            )
        return results

    # =========================================================================
    # Encrypted SIEM Connections & Credential Store (Phase 14.2-B / SEC-UI-001)
    # =========================================================================
    def create_siem_connection_record(
        self,
        connection_id: str,
        case_id: str,
        siem_type: str,
        endpoint_url: str,
        index_pattern: Optional[str],
        allowed_hosts_json: Optional[str],
        headers_json: Optional[str],
        verify_ssl: int,
        timeout_seconds: float,
        encrypted_credentials: str,
        has_password: int,
        has_api_key: int,
        has_token: int,
        username: Optional[str],
        created_by: str,
        created_at_utc: str,
        updated_at_utc: str,
    ) -> None:
        """Insert a new encrypted SIEM connection record."""
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO siem_connections (
                    connection_id, case_id, siem_type, endpoint_url,
                    index_pattern, allowed_hosts_json, headers_json,
                    verify_ssl, timeout_seconds, encrypted_credentials,
                    has_password, has_api_key, has_token, username,
                    created_by, created_at_utc, updated_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    connection_id,
                    case_id,
                    siem_type,
                    endpoint_url,
                    index_pattern,
                    allowed_hosts_json,
                    headers_json,
                    verify_ssl,
                    timeout_seconds,
                    encrypted_credentials,
                    has_password,
                    has_api_key,
                    has_token,
                    username,
                    created_by,
                    created_at_utc,
                    updated_at_utc,
                ),
            )

    def get_siem_connection_record(self, connection_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a SIEM connection record by connection_id."""
        cursor = self._conn.execute(
            """
            SELECT
                connection_id, case_id, siem_type, endpoint_url,
                index_pattern, allowed_hosts_json, headers_json,
                verify_ssl, timeout_seconds, encrypted_credentials,
                has_password, has_api_key, has_token, username,
                created_by, created_at_utc, updated_at_utc
            FROM siem_connections
            WHERE connection_id = ?;
            """,
            (connection_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        return {
            "connection_id": row[0],
            "case_id": row[1],
            "siem_type": row[2],
            "endpoint_url": row[3],
            "index_pattern": row[4],
            "allowed_hosts_json": row[5],
            "headers_json": row[6],
            "verify_ssl": row[7],
            "timeout_seconds": row[8],
            "encrypted_credentials": row[9],
            "has_password": row[10],
            "has_api_key": row[11],
            "has_token": row[12],
            "username": row[13],
            "created_by": row[14],
            "created_at_utc": row[15],
            "updated_at_utc": row[16],
        }

    def list_siem_connection_records(self, case_id: str) -> List[Dict[str, Any]]:
        """List all SIEM connections for a specific case."""
        cursor = self._conn.execute(
            """
            SELECT
                connection_id, case_id, siem_type, endpoint_url,
                index_pattern, allowed_hosts_json, headers_json,
                verify_ssl, timeout_seconds, encrypted_credentials,
                has_password, has_api_key, has_token, username,
                created_by, created_at_utc, updated_at_utc
            FROM siem_connections
            WHERE case_id = ?
            ORDER BY updated_at_utc DESC;
            """,
            (case_id,),
        )
        results = []
        for row in cursor.fetchall():
            results.append({
                "connection_id": row[0],
                "case_id": row[1],
                "siem_type": row[2],
                "endpoint_url": row[3],
                "index_pattern": row[4],
                "allowed_hosts_json": row[5],
                "headers_json": row[6],
                "verify_ssl": row[7],
                "timeout_seconds": row[8],
                "encrypted_credentials": row[9],
                "has_password": row[10],
                "has_api_key": row[11],
                "has_token": row[12],
                "username": row[13],
                "created_by": row[14],
                "created_at_utc": row[15],
                "updated_at_utc": row[16],
            })
        return results

    def update_siem_connection_record(
        self,
        connection_id: str,
        siem_type: str,
        endpoint_url: str,
        index_pattern: Optional[str],
        allowed_hosts_json: Optional[str],
        headers_json: Optional[str],
        verify_ssl: int,
        timeout_seconds: float,
        encrypted_credentials: str,
        has_password: int,
        has_api_key: int,
        has_token: int,
        username: Optional[str],
        updated_at_utc: str,
    ) -> None:
        """Update an existing SIEM connection record in SQLite."""
        with self._conn:
            self._conn.execute(
                """
                UPDATE siem_connections SET
                    siem_type = ?,
                    endpoint_url = ?,
                    index_pattern = ?,
                    allowed_hosts_json = ?,
                    headers_json = ?,
                    verify_ssl = ?,
                    timeout_seconds = ?,
                    encrypted_credentials = ?,
                    has_password = ?,
                    has_api_key = ?,
                    has_token = ?,
                    username = ?,
                    updated_at_utc = ?
                WHERE connection_id = ?;
                """,
                (
                    siem_type,
                    endpoint_url,
                    index_pattern,
                    allowed_hosts_json,
                    headers_json,
                    verify_ssl,
                    timeout_seconds,
                    encrypted_credentials,
                    has_password,
                    has_api_key,
                    has_token,
                    username,
                    updated_at_utc,
                    connection_id,
                ),
            )

    def delete_siem_connection_record(self, connection_id: str) -> bool:
        """Delete a SIEM connection record by connection_id."""
        with self._conn:
            cursor = self._conn.execute(
                "DELETE FROM siem_connections WHERE connection_id = ?;",
                (connection_id,),
            )
            return cursor.rowcount > 0

    def export_encrypted_vault(
        self,
        export_path: Union[str, Path],
        passphrase: str,
        kdf: str = "pbkdf2",
        iterations: int = 600000,
    ) -> Path:
        """Export complete SQLite database to an authenticated AES-256-GCM encrypted package."""
        try:
            self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
        except Exception:
            pass
        from backend.app.core.crypto import export_encrypted_vault
        return export_encrypted_vault(self, export_path, passphrase, kdf=kdf, iterations=iterations)

    def import_encrypted_vault(
        self,
        import_path: Union[str, Path],
        passphrase: str,
    ) -> Dict[str, Any]:
        """Import and decrypt an authenticated AES-256-GCM encrypted vault package."""
        from backend.app.core.crypto import import_encrypted_vault
        return import_encrypted_vault(self, import_path, passphrase)

    def get_approval_audit_logs(
        self,
        case_id: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Retrieve recent approval audit log entries, optionally filtered by case_id."""
        query = """
            SELECT id, event_id, case_id, actor, action, target,
                   requesting_principal_id, approving_principal_id, details_json,
                   timestamp_utc, previous_hash, current_hash
            FROM approval_audit_log
        """
        params: List[Any] = []
        if case_id:
            query += " WHERE case_id = ?"
            params.append(case_id)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        cur = self._conn.execute(query, tuple(params))
        rows = cur.fetchall()

        results = []
        for row in rows:
            results.append({
                "id": row[0],
                "event_id": row[1],
                "case_id": row[2],
                "actor": row[3],
                "action": row[4],
                "target": row[5],
                "requesting_principal_id": row[6],
                "approving_principal_id": row[7],
                "details_json": row[8],
                "timestamp_utc": row[9],
                "previous_hash": row[10],
                "current_hash": row[11],
            })
        return results

    def close(self) -> None:
        """Close SQLite database connection."""
        try:
            self._conn.close()
        except Exception:
            pass


_llm_state_store_instance: Optional[LLMStateStore] = None


def get_llm_state_store(db_path: Optional[Union[str, Path]] = None) -> LLMStateStore:
    """Retrieve or initialize the singleton LLMStateStore instance."""
    global _llm_state_store_instance
    if _llm_state_store_instance is None:
        resolved_path = db_path
        if resolved_path is None:
            vault_dir = os.getenv("FORENSICOPS_VAULT_DIR", "vault")
            resolved_path = Path(vault_dir) / "llm_state.db"
        _llm_state_store_instance = LLMStateStore(resolved_path)
    return _llm_state_store_instance


def reset_llm_state_store(store: Optional[LLMStateStore] = None) -> None:
    """Reset the singleton instance for testing isolation, optionally injecting a test store."""
    global _llm_state_store_instance
    if _llm_state_store_instance is not None:
        _llm_state_store_instance.close()
    _llm_state_store_instance = store


# Semantic aliases for SQLite Investigation Session Store
SessionStore = LLMStateStore
get_session_store = get_llm_state_store
reset_session_store = reset_llm_state_store


def export_encrypted_vault(
    store: LLMStateStore,
    export_path: Union[str, Path],
    passphrase: str,
    kdf: str = "pbkdf2",
    iterations: int = 600000,
) -> Path:
    """Convenience helper to export an encrypted vault from LLMStateStore."""
    return store.export_encrypted_vault(export_path, passphrase, kdf=kdf, iterations=iterations)


def import_encrypted_vault(
    store: LLMStateStore,
    import_path: Union[str, Path],
    passphrase: str,
) -> Dict[str, Any]:
    """Convenience helper to import an encrypted vault into LLMStateStore."""
    return store.import_encrypted_vault(import_path, passphrase)

