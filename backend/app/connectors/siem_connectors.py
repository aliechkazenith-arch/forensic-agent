"""Read-Only Hybrid SIEM Connectors (Elasticsearch, Wazuh, Splunk).

Standards:
- RFC 3227 (Forensic Integrity & Auditability)
- Non-Negotiable Read-Only Query Adapters (Zero Mutating Operations)
- Canonical SHA-256 Query-Snapshot Hashing for Anti-Hallucination Citation Verification
- ECS & ForensicFinding Schema Normalization
"""
from __future__ import annotations

import abc
from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any, Dict, List, Optional, Tuple, Union
from uuid import uuid4
import httpx

from backend.app.core.custody_engine import CustodyEngine
from backend.app.core.exceptions import (
    ReadOnlyViolationError,
    SIEMQueryError,
    SSRFSecurityError,
)
from backend.app.core.network_validator import (
    create_pinned_siem_client,
    sanitize_credentials,
    validate_url_ssrf,
)
from backend.app.core.storage import ForensicStore
from backend.app.models.connectors import (
    SIEMConnectionConfig,
    SIEMQuerySnapshot,
    SIEMType,
    get_current_utc,
)
from backend.app.models.custody import ArtifactRecord, canonical_json_dump
from backend.app.models.findings import FindingSeverity, ForensicFinding

# Patterns that indicate mutating / data-modifying queries
MUTATING_ES_TERMS = re.compile(
    r"(_delete|_bulk|_update|_reindex|_shrink|_split|_rollover|_close|delete_by_query|update_by_query|^\s*(post|put|delete)\s+|(\b|_)(drop|truncate|alter)(\b|_))",
    re.IGNORECASE,
)
MUTATING_SPLUNK_COMMANDS = re.compile(
    r"(^|[|;])\s*(delete|outputcsv|outputlookup|collect|sendalert|run|script|tscollect|redistribute)\b",
    re.IGNORECASE,
)
MUTATING_WAZUH_TERMS = re.compile(
    r"\b(delete|remove|purge|restart|stop|create|update|insert)\b",
    re.IGNORECASE,
)


def normalize_iso_timestamp(ts: Optional[Union[str, int, float]]) -> Optional[str]:
    """Normalize timestamps (ISO strings, epoch seconds/ms) to ISO-8601 UTC."""
    if not ts:
        return None
    if isinstance(ts, (int, float)):
        # Handle epoch seconds vs epoch milliseconds
        epoch = float(ts)
        if epoch > 1e11:  # Milliseconds
            epoch = epoch / 1000.0
        return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    ts_str = str(ts).strip()
    # Replace space with T if needed
    if " " in ts_str and "T" not in ts_str:
        ts_str = ts_str.replace(" ", "T")
    if not ts_str.endswith("Z") and "+" not in ts_str and "-" not in ts_str[-6:]:
        ts_str = f"{ts_str}Z"
    return ts_str


def map_severity(val: Optional[Union[str, int]]) -> FindingSeverity:
    """Map arbitrary log severity or rule level to FindingSeverity."""
    if val is None:
        return "info"
    if isinstance(val, int):
        if val >= 12:
            return "critical"
        elif val >= 8:
            return "high"
        elif val >= 4:
            return "medium"
        elif val >= 2:
            return "low"
        return "info"

    s = str(val).lower()
    if s in ("critical", "fatal", "emerg", "alert", "sev1", "1"):
        return "critical"
    elif s in ("high", "err", "error", "sev2", "2"):
        return "high"
    elif s in ("medium", "warn", "warning", "sev3", "3"):
        return "medium"
    elif s in ("low", "notice", "sev4", "4"):
        return "low"
    return "info"


class BaseSIEMConnector(abc.ABC):
    """Abstract base class for all read-only SIEM connectors."""

    def __init__(
        self,
        config: SIEMConnectionConfig,
        http_client: Optional[httpx.Client] = None,
    ):
        self.config = config
        validate_url_ssrf(config.endpoint_url, allowed_targets=config.allowed_hosts)
        self._client = http_client or create_pinned_siem_client(
            verify_ssl=config.verify_ssl,
            timeout_seconds=config.timeout_seconds,
            allowed_targets=config.allowed_hosts,
            allow_private=False,
            follow_redirects=False,
        )

    @property
    @abc.abstractmethod
    def siem_type(self) -> SIEMType:
        """Connector type identifier."""
        pass

    @property
    @abc.abstractmethod
    def tool_id(self) -> str:
        """ForensicOps tool identifier."""
        pass

    @abc.abstractmethod
    def validate_query_read_only(self, query: str) -> None:
        """Enforce strict read-only query semantics.
        
        Raises ReadOnlyViolationError if query contains mutating operations.
        """
        pass

    @abc.abstractmethod
    def test_connection(self) -> bool:
        """Verify reachability and authentication to SIEM endpoint."""
        pass

    @abc.abstractmethod
    def search(
        self,
        query: str,
        case_id: str,
        limit: int = 100,
        **kwargs,
    ) -> Tuple[List[ForensicFinding], SIEMQuerySnapshot]:
        """Execute read-only query and return normalized findings with SHA-256 snapshot."""
        pass

    def compute_query_snapshot(
        self,
        query: str,
        case_id: str,
        raw_results: Any,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[SIEMQuerySnapshot, bytes]:
        """Compute cryptographic query-snapshot hash over query parameters and raw results.
        
        This hash anchors every ForensicFinding back to verified SIEM telemetry.
        """
        snapshot_payload = {
            "siem_type": self.siem_type,
            "case_id": case_id,
            "query": query,
            "timestamp_utc": get_current_utc(),
            "results": raw_results,
            "metadata": metadata or {},
        }
        canonical_bytes = canonical_json_dump(snapshot_payload).encode("utf-8")
        snapshot_sha256 = hashlib.sha256(canonical_bytes).hexdigest()

        count = len(raw_results) if isinstance(raw_results, list) else 1
        snapshot = SIEMQuerySnapshot(
            case_id=case_id,
            siem_type=self.siem_type,
            query_string=query,
            snapshot_sha256=snapshot_sha256,
            record_count=count,
            timestamp_utc=get_current_utc(),
            metadata=metadata or {},
        )
        return snapshot, canonical_bytes

    def close(self) -> None:
        """Close underlying HTTP client connection."""
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class ElasticsearchConnector(BaseSIEMConnector):
    """Read-only Elasticsearch query adapter conforming to Elastic Common Schema (ECS)."""

    @property
    def siem_type(self) -> SIEMType:
        return "elasticsearch"

    @property
    def tool_id(self) -> str:
        return "siem_elasticsearch"

    def _get_headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json", **self.config.headers}
        if self.config.api_key:
            headers["Authorization"] = f"ApiKey {self.config.api_key}"
        elif self.config.token:
            headers["Authorization"] = f"Bearer {self.config.token}"
        return headers

    def _get_auth(self) -> Optional[Tuple[str, str]]:
        if self.config.username and self.config.password:
            return (self.config.username, self.config.password)
        return None

    def validate_query_read_only(self, query: str) -> None:
        if MUTATING_ES_TERMS.search(query):
            raise ReadOnlyViolationError(
                f"Elasticsearch query contains prohibited mutating operation: '{query}'"
            )

    def test_connection(self) -> bool:
        url = self.config.endpoint_url.rstrip("/")
        secrets = [s for s in [self.config.password, self.config.api_key, self.config.token] if s]
        try:
            resp = self._client.get(
                url,
                headers=self._get_headers(),
                auth=self._get_auth(),
            )
            return resp.status_code == 200
        except SSRFSecurityError:
            raise
        except Exception as e:
            sanitized = sanitize_credentials(str(e), secrets)
            raise SIEMQueryError(f"Elasticsearch connection failed: {sanitized}") from e

    def search(
        self,
        query: str,
        case_id: str,
        limit: int = 100,
        index_pattern: Optional[str] = None,
        **kwargs,
    ) -> Tuple[List[ForensicFinding], SIEMQuerySnapshot]:
        self.validate_query_read_only(query)
        secrets = [s for s in [self.config.password, self.config.api_key, self.config.token] if s]

        idx = index_pattern or self.config.index_pattern or "_all"
        url = f"{self.config.endpoint_url.rstrip('/')}/{idx}/_search"

        body = {
            "size": limit,
            "query": {
                "query_string": {
                    "query": query,
                    "analyze_wildcard": True,
                }
            },
        }

        try:
            resp = self._client.post(
                url,
                json=body,
                headers=self._get_headers(),
                auth=self._get_auth(),
            )
        except SSRFSecurityError:
            raise
        except Exception as e:
            sanitized = sanitize_credentials(str(e), secrets)
            raise SIEMQueryError(f"Elasticsearch query request failed: {sanitized}") from e

        if resp.status_code != 200:
            sanitized_body = sanitize_credentials(resp.text, secrets)
            raise SIEMQueryError(
                f"Elasticsearch query returned HTTP {resp.status_code}: {sanitized_body}"
            )

        data = resp.json()
        hits = data.get("hits", {}).get("hits", [])

        # Compute query snapshot hash
        snapshot, _ = self.compute_query_snapshot(
            query=query,
            case_id=case_id,
            raw_results=hits,
            metadata={"index": idx, "total_hits": data.get("hits", {}).get("total", {})},
        )

        findings: List[ForensicFinding] = []
        for hit in hits:
            source = hit.get("_source", {})
            hit_id = hit.get("_id", str(uuid4()))
            hit_index = hit.get("_index", idx)

            # ECS mappings
            timestamp = (
                source.get("@timestamp")
                or source.get("timestamp")
                or source.get("event", {}).get("created")
            )
            event_id = (
                source.get("winlog", {}).get("event_id")
                or source.get("event", {}).get("code")
                or source.get("event_id")
            )
            category = (
                source.get("event", {}).get("category")
                or source.get("event", {}).get("action")
                or "siem_event"
            )
            if isinstance(category, list):
                category = category[0] if category else "siem_event"

            severity = map_severity(
                source.get("event", {}).get("severity")
                or source.get("log", {}).get("level")
            )

            host = (
                source.get("host", {}).get("name")
                or source.get("host", {}).get("hostname")
                or source.get("agent", {}).get("name")
            )
            user = (
                source.get("user", {}).get("name")
                or source.get("user", {}).get("target", {}).get("name")
                or source.get("winlog", {}).get("user", {}).get("name")
            )
            process_name = (
                source.get("process", {}).get("name")
                or source.get("process", {}).get("executable")
            )
            command_line = source.get("process", {}).get("command_line")

            summary = (
                source.get("message")
                or f"Elasticsearch hit in {hit_index} (Event: {event_id or category})"
            )

            # High-signal projected data for AI
            projected = {
                "index": hit_index,
                "hit_id": hit_id,
                "source_ip": source.get("source", {}).get("ip"),
                "destination_ip": source.get("destination", {}).get("ip"),
                "rule_name": source.get("rule", {}).get("name"),
                "event_action": source.get("event", {}).get("action"),
            }
            projected = {k: v for k, v in projected.items() if v is not None}

            finding = ForensicFinding(
                finding_id=f"fnd-es-{hit_id}",
                case_id=case_id,
                source_artifact_id=f"es-{hit_index}-{hit_id}",
                source_artifact_hash=snapshot.snapshot_sha256,
                tool_id=self.tool_id,
                timestamp_utc=normalize_iso_timestamp(timestamp),
                artifact_type="siem_event",
                category=str(category),
                event_id=str(event_id) if event_id is not None else None,
                severity=severity,
                host=str(host) if host else None,
                user=str(user) if user else None,
                process_name=str(process_name) if process_name else None,
                command_line=str(command_line) if command_line else None,
                raw_reference=f"{hit_index}/{hit_id}",
                summary=summary[:500],
                projected_data=projected,
            )
            findings.append(finding)

        return findings, snapshot


class WazuhConnector(BaseSIEMConnector):
    """Read-only Wazuh API query adapter normalizing alert records."""

    @property
    def siem_type(self) -> SIEMType:
        return "wazuh"

    @property
    def tool_id(self) -> str:
        return "siem_wazuh"

    def _get_headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json", **self.config.headers}
        if self.config.token:
            headers["Authorization"] = f"Bearer {self.config.token}"
        elif self.config.api_key:
            headers["X-API-Key"] = self.config.api_key
        return headers

    def validate_query_read_only(self, query: str) -> None:
        if MUTATING_WAZUH_TERMS.search(query):
            raise ReadOnlyViolationError(
                f"Wazuh query contains prohibited mutating operation: '{query}'"
            )

    def test_connection(self) -> bool:
        url = f"{self.config.endpoint_url.rstrip('/')}/"
        secrets = [s for s in [self.config.password, self.config.api_key, self.config.token] if s]
        try:
            resp = self._client.get(url, headers=self._get_headers())
            return resp.status_code in (200, 401)
        except SSRFSecurityError:
            raise
        except Exception as e:
            sanitized = sanitize_credentials(str(e), secrets)
            raise SIEMQueryError(f"Wazuh connection failed: {sanitized}") from e

    def search(
        self,
        query: str,
        case_id: str,
        limit: int = 100,
        **kwargs,
    ) -> Tuple[List[ForensicFinding], SIEMQuerySnapshot]:
        self.validate_query_read_only(query)
        secrets = [s for s in [self.config.password, self.config.api_key, self.config.token] if s]

        # Support both Wazuh REST API (/alerts) and Wazuh Indexer OpenSearch search
        url = f"{self.config.endpoint_url.rstrip('/')}/alerts"
        params = {"q": query, "limit": limit}

        try:
            resp = self._client.get(
                url,
                params=params,
                headers=self._get_headers(),
            )
        except SSRFSecurityError:
            raise
        except Exception as e:
            sanitized = sanitize_credentials(str(e), secrets)
            raise SIEMQueryError(f"Wazuh alerts request failed: {sanitized}") from e

        if resp.status_code != 200:
            sanitized_body = sanitize_credentials(resp.text, secrets)
            raise SIEMQueryError(f"Wazuh API returned HTTP {resp.status_code}: {sanitized_body}")

        data = resp.json()
        raw_items = data.get("data", {}).get("affected_items", [])
        if not raw_items and isinstance(data, list):
            raw_items = data
        elif not raw_items and "hits" in data:
            raw_items = [h.get("_source", {}) for h in data.get("hits", {}).get("hits", [])]

        snapshot, _ = self.compute_query_snapshot(
            query=query,
            case_id=case_id,
            raw_results=raw_items,
            metadata={"wazuh_alerts_count": len(raw_items)},
        )

        findings: List[ForensicFinding] = []
        for alert in raw_items:
            alert_id = alert.get("id") or str(uuid4())
            rule = alert.get("rule", {})
            rule_id = str(rule.get("id", ""))
            rule_level = rule.get("level", 3)
            rule_desc = rule.get("description", "Wazuh Alert")

            agent = alert.get("agent", {})
            host = agent.get("name") or agent.get("id") or alert.get("manager", {}).get("name")

            # Extract user and process details
            sys_data = alert.get("data", {})
            user = (
                sys_data.get("win", {}).get("system", {}).get("userName")
                or sys_data.get("srcuser")
                or sys_data.get("dstuser")
            )
            process_name = (
                sys_data.get("win", {}).get("eventdata", {}).get("image")
                or sys_data.get("process", {}).get("name")
            )
            command_line = (
                sys_data.get("win", {}).get("eventdata", {}).get("commandLine")
                or sys_data.get("process", {}).get("cmd")
            )

            category = rule.get("groups", ["wazuh_alert"])[0] if rule.get("groups") else "wazuh_alert"
            timestamp = alert.get("timestamp") or alert.get("@timestamp")

            projected = {
                "rule_id": rule_id,
                "rule_level": rule_level,
                "mitre_id": rule.get("mitre", {}).get("id"),
                "mitre_tactic": rule.get("mitre", {}).get("tactic"),
                "agent_id": agent.get("id"),
                "srcip": sys_data.get("srcip"),
                "dstip": sys_data.get("dstip"),
            }
            projected = {k: v for k, v in projected.items() if v is not None}

            finding = ForensicFinding(
                finding_id=f"fnd-wazuh-{alert_id}",
                case_id=case_id,
                source_artifact_id=f"wazuh-{alert_id}",
                source_artifact_hash=snapshot.snapshot_sha256,
                tool_id=self.tool_id,
                timestamp_utc=normalize_iso_timestamp(timestamp),
                artifact_type="siem_wazuh_alert",
                category=str(category),
                event_id=rule_id if rule_id else None,
                severity=map_severity(rule_level),
                host=str(host) if host else None,
                user=str(user) if user else None,
                process_name=str(process_name) if process_name else None,
                command_line=str(command_line) if command_line else None,
                raw_reference=f"alert/{alert_id}",
                summary=rule_desc,
                projected_data=projected,
            )
            findings.append(finding)

        return findings, snapshot


class SplunkConnector(BaseSIEMConnector):
    """Read-only Splunk REST API query adapter with strict SPL read-only verification."""

    @property
    def siem_type(self) -> SIEMType:
        return "splunk"

    @property
    def tool_id(self) -> str:
        return "siem_splunk"

    def _get_headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/x-www-form-urlencoded", **self.config.headers}
        if self.config.token:
            headers["Authorization"] = f"Splunk {self.config.token}"
        return headers

    def _get_auth(self) -> Optional[Tuple[str, str]]:
        if self.config.username and self.config.password:
            return (self.config.username, self.config.password)
        return None

    def validate_query_read_only(self, query: str) -> None:
        """Enforce that SPL query does not contain mutating commands."""
        clean_q = query.strip()
        if MUTATING_SPLUNK_COMMANDS.search(clean_q):
            raise ReadOnlyViolationError(
                f"Splunk SPL query contains prohibited mutating command: '{query}'"
            )

    def test_connection(self) -> bool:
        url = f"{self.config.endpoint_url.rstrip('/')}/services/server/info?output_mode=json"
        secrets = [s for s in [self.config.password, self.config.token] if s]
        try:
            resp = self._client.get(
                url,
                headers=self._get_headers(),
                auth=self._get_auth(),
            )
            return resp.status_code == 200
        except SSRFSecurityError:
            raise
        except Exception as e:
            sanitized = sanitize_credentials(str(e), secrets)
            raise SIEMQueryError(f"Splunk connection failed: {sanitized}") from e

    def search(
        self,
        query: str,
        case_id: str,
        limit: int = 100,
        **kwargs,
    ) -> Tuple[List[ForensicFinding], SIEMQuerySnapshot]:
        self.validate_query_read_only(query)
        secrets = [s for s in [self.config.password, self.config.token] if s]

        # Splunk requires search command prefix
        clean_spl = query.strip()
        if not clean_spl.startswith("search ") and not clean_spl.startswith("|"):
            clean_spl = f"search {clean_spl}"

        # Splunk export endpoint streams JSON results
        url = f"{self.config.endpoint_url.rstrip('/')}/services/search/jobs/export"
        payload = {
            "search": clean_spl,
            "output_mode": "json",
            "count": str(limit),
        }

        try:
            resp = self._client.post(
                url,
                data=payload,
                headers=self._get_headers(),
                auth=self._get_auth(),
            )
        except SSRFSecurityError:
            raise
        except Exception as e:
            sanitized = sanitize_credentials(str(e), secrets)
            raise SIEMQueryError(f"Splunk export request failed: {sanitized}") from e

        if resp.status_code != 200:
            sanitized_body = sanitize_credentials(resp.text, secrets)
            raise SIEMQueryError(f"Splunk search returned HTTP {resp.status_code}: {sanitized_body}")

        # Splunk export streams newline-delimited JSON objects
        raw_events: List[Dict[str, Any]] = []
        for line in resp.text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
                result = item.get("result", item)
                if result:
                    raw_events.append(result)
            except Exception:
                continue

        snapshot, _ = self.compute_query_snapshot(
            query=clean_spl,
            case_id=case_id,
            raw_results=raw_events,
            metadata={"splunk_result_count": len(raw_events)},
        )

        findings: List[ForensicFinding] = []
        for i, ev in enumerate(raw_events):
            event_id = ev.get("EventCode") or ev.get("event_id") or ev.get("event_code")
            timestamp = ev.get("_time") or ev.get("timestamp")
            host = ev.get("host") or ev.get("dest_nt_host") or ev.get("dvc")
            user = ev.get("user") or ev.get("dest_user") or ev.get("AccountName")
            process_name = ev.get("Image") or ev.get("NewProcessName") or ev.get("process_name") or ev.get("app")
            command_line = ev.get("CommandLine") or ev.get("cmd")
            category = ev.get("action") or ev.get("category") or "splunk_event"

            raw_body = ev.get("_raw") or ev.get("message") or json.dumps(ev)
            summary = raw_body[:300] if raw_body else f"Splunk event from {host or 'unknown'}"

            projected = {
                "sourcetype": ev.get("sourcetype"),
                "index": ev.get("index"),
                "src_ip": ev.get("src_ip") or ev.get("src"),
                "dest_ip": ev.get("dest_ip") or ev.get("dest"),
            }
            projected = {k: v for k, v in projected.items() if v is not None}

            finding = ForensicFinding(
                finding_id=f"fnd-splunk-{i}-{uuid4().hex[:8]}",
                case_id=case_id,
                source_artifact_id=f"splunk-ev-{i}",
                source_artifact_hash=snapshot.snapshot_sha256,
                tool_id=self.tool_id,
                timestamp_utc=normalize_iso_timestamp(timestamp),
                artifact_type="siem_splunk_event",
                category=str(category),
                event_id=str(event_id) if event_id is not None else None,
                severity=map_severity(ev.get("severity") or ev.get("level")),
                host=str(host) if host else None,
                user=str(user) if user else None,
                process_name=str(process_name) if process_name else None,
                command_line=str(command_line) if command_line else None,
                raw_reference=f"row/{i}",
                summary=summary,
                projected_data=projected,
            )
            findings.append(finding)

        return findings, snapshot


def ingest_siem_query_findings(
    connector: BaseSIEMConnector,
    query: str,
    case_id: str,
    custody_engine: Optional[CustodyEngine] = None,
    forensic_store: Optional[ForensicStore] = None,
    actor: str = "analyst",
    limit: int = 100,
    **kwargs,
) -> Tuple[List[ForensicFinding], SIEMQuerySnapshot]:
    """Execute SIEM query, anchor in custody chain, and insert into forensic store.
    
    1. Executes read-only query and computes SHA-256 query snapshot hash.
    2. If custody_engine provided: records INGEST_SIEM_QUERY_SNAPSHOT in chain of custody.
    3. If forensic_store provided: indexes normalized ForensicFinding records.
    """
    findings, snapshot = connector.search(query=query, case_id=case_id, limit=limit, **kwargs)

    # 1. Chain of custody registration
    if custody_engine is not None:
        custody_engine.append_custody_entry(
            case_id=case_id,
            actor=actor,
            action="INGEST_SIEM_QUERY_SNAPSHOT",
            artifact_sha256=snapshot.snapshot_sha256,
            tool_id=connector.tool_id,
        )

    # 2. Store indexing
    if forensic_store is not None:
        forensic_store.insert_findings(findings)

    return findings, snapshot
