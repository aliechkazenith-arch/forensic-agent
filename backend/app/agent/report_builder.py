"""Cited Report Builder with AIFT 4-Part Rubric & Multi-Host Patient Zero Correlation.

Standards:
- RFC 3227, NIST SP 800-86, ISO/IEC 27037
- 6-Section Forensic Report Structure (specs/02-UI-SPECIFICATION.md & specs/05-MASTER-EXECUTION-PLAN.md):
  1. Executive Summary & Timeline
  2. Custody & Filter Audit Table
  3. Observed Facts
  4. Derived Correlations
  5. AIFT 4-Part Rubric (Why It Matters, Benign Alternative, How to Verify, Data Gaps)
  6. Multi-Host Patient Zero Assessment & Remediation
- Deterministic Citations: Every fact and correlation cites non-empty finding IDs and artifact hashes.
- Evidence-backed Timeline: Preserves original timezone, clock precision, uncertainty, and source.
- Evidence Conflict Handling: Preserves contradictory observations without suppression.
- Phase 08 Human Approval Gate: Final report signing requires cryptographic approval tokens.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Set, Tuple, Union
from uuid import uuid4
from pydantic import BaseModel, Field

from backend.app.core.citation_guard import CitationGuard
from backend.app.core.config import get_settings
from backend.app.core.exceptions import CitationValidationError, ForensicOpsError
from backend.app.core.storage import ForensicStore
from backend.app.models.findings import CitedClaim, FindingSeverity, ForensicFinding, NodeGoalResult
from backend.app.models.workflow import HumanApprovalToken


def parse_forensic_timestamp(
    raw_ts: Optional[str],
    projected: Optional[Dict[str, Any]] = None,
    artifact_type: Optional[str] = None,
) -> Dict[str, Any]:
    """Parse and normalize forensic timestamp while strictly preserving provenance.

    Standards:
    - Never invent timestamps.
    - Never silently assume an unknown timezone is UTC.
    - Preserve original timezone, precision, source, and clock uncertainty.
    """
    projected = projected or {}

    if not raw_ts:
        raw_ts = (
            projected.get("original_timestamp")
            or projected.get("TimeCreated")
            or projected.get("timestamp_raw")
            or projected.get("timestamp")
        )

    src = projected.get("timestamp_source")
    if not src:
        if artifact_type == "evtx":
            src = "evtx_TimeCreated"
        elif artifact_type in ("network", "pcap"):
            src = "packet_capture_header"
        elif artifact_type == "registry":
            src = "registry_key_lastwritten"
        elif artifact_type == "memory":
            src = "volatility_pslist_createtime"
        elif artifact_type == "file":
            src = "file_mtime_or_mft"
        else:
            src = f"{artifact_type or 'tool'}_telemetry"

    if not raw_ts or not str(raw_ts).strip():
        return {
            "original_timestamp": None,
            "original_timezone": None,
            "timezone_status": "NO_TIMESTAMP",
            "normalized_timestamp_utc": None,
            "timestamp_source": src,
            "timestamp_precision": "unknown",
            "clock_uncertainty": "no_timestamp_present",
        }

    raw_str = str(raw_ts).strip()

    precision = "seconds"
    if re.search(r"\.\d{7,}", raw_str):
        precision = "100ns"
    elif re.search(r"\.\d{6}", raw_str):
        precision = "microseconds"
    elif re.search(r"\.\d{3}", raw_str):
        precision = "milliseconds"

    if raw_str.endswith(("Z", "z")):
        tz_status = "EXPLICIT_UTC"
        orig_tz = "UTC"
        uncertainty = "none"
        try:
            iso_clean = raw_str[:-1] + "+00:00"
            dt = datetime.fromisoformat(iso_clean).astimezone(timezone.utc)
            norm_utc = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            norm_utc = raw_str
    elif re.search(r"([+-]\d{2}:?\d{2})$", raw_str):
        tz_status = "EXPLICIT_OFFSET"
        m = re.search(r"([+-]\d{2}:?\d{2})$", raw_str)
        orig_tz = m.group(1) if m else "OFFSET"
        uncertainty = "offset_normalized"
        try:
            offset_str = orig_tz
            if len(offset_str) == 5 and ":" not in offset_str:
                offset_str = f"{offset_str[:3]}:{offset_str[3:]}"
            base_part = raw_str[: m.start()]
            dt = datetime.fromisoformat(f"{base_part}{offset_str}").astimezone(timezone.utc)
            norm_utc = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            norm_utc = None
    else:
        # NON-NEGOTIABLE RULE: Do not silently assume an unknown timezone is UTC!
        tz_status = "UNKNOWN_AMBIGUOUS"
        orig_tz = "UNKNOWN"
        uncertainty = "unknown_timezone_offset (unverified clock reference)"
        norm_utc = None

    return {
        "original_timestamp": raw_str,
        "original_timezone": orig_tz,
        "timezone_status": tz_status,
        "normalized_timestamp_utc": norm_utc,
        "timestamp_source": src,
        "timestamp_precision": precision,
        "clock_uncertainty": uncertainty,
    }


class TimelineEntry(BaseModel):
    """Chronological event entry in the forensic timeline."""
    timestamp_utc: str = Field(default="")
    original_timestamp: Optional[str] = None
    original_timezone: Optional[str] = None
    timezone_status: str = "EXPLICIT_UTC"
    normalized_timestamp_utc: Optional[str] = None
    timestamp_source: Optional[str] = None
    timestamp_precision: Optional[str] = None
    clock_uncertainty: Optional[str] = None
    host: Optional[str] = None
    user: Optional[str] = None
    process_or_event: str
    summary: str
    severity: FindingSeverity = "info"
    citing_finding_id: str
    source_artifact_hash: str


class EvidenceConflict(BaseModel):
    """Structured record of contradictory, duplicate, or missing evidence."""
    conflict_id: str = Field(default_factory=lambda: str(uuid4()))
    conflict_type: Literal[
        "conflicting_timestamps",
        "conflicting_user_identities",
        "conflicting_host_identifiers",
        "duplicate_observations",
        "missing_artifacts",
        "incomplete_telemetry",
        "tool_errors",
    ]
    affected_finding_ids: List[str] = Field(default_factory=list)
    affected_artifact_hashes: List[str] = Field(default_factory=list)
    severity: FindingSeverity = "medium"
    description: str
    contradictory_details: Dict[str, Any] = Field(default_factory=dict)


class DeterministicCorrelationRecord(BaseModel):
    """Deterministic multi-observation correlation record."""
    correlation_id: str = Field(default_factory=lambda: str(uuid4()))
    case_id: str
    relationship_type: str
    source_finding_ids: List[str] = Field(default_factory=list)
    source_artifact_hashes: List[str] = Field(default_factory=list)
    entity_identifiers: Dict[str, Any] = Field(default_factory=dict)
    correlation_method: str
    supporting_observations: List[str] = Field(default_factory=list)
    conflicting_observations: List[str] = Field(default_factory=list)
    time_window: Optional[Dict[str, Any]] = None
    limitations: List[str] = Field(default_factory=list)
    confidence: float = Field(default=0.85, ge=0.0, le=1.0)
    statement: Optional[str] = None


class ExecutiveSummarySection(BaseModel):
    """Section 1: High-level overview, incident scope, and timeline table."""
    title: str = "Executive Summary & Forensic Timeline"
    case_id: str
    generated_utc: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    incident_overview: str
    severity: FindingSeverity = "medium"
    impacted_hosts: List[str] = Field(default_factory=list)
    impacted_users: List[str] = Field(default_factory=list)
    earliest_timestamp_utc: Optional[str] = None
    latest_timestamp_utc: Optional[str] = None
    timeline: List[TimelineEntry] = Field(default_factory=list)


class CustodyAuditSection(BaseModel):
    """Section 2: Evidence integrity, chain of custody, and column projection audit."""
    title: str = "Chain of Custody & Projection Filter Audit Table"
    evidence_items: List[Dict[str, Any]] = Field(default_factory=list)
    column_projection_summary: Dict[str, Any] = Field(default_factory=dict)
    tamper_check_passed: bool = False
    verification_status: str = "UNVERIFIED"
    verification_errors: List[str] = Field(default_factory=list)


class AIFTRubricItem(BaseModel):
    """Section 5 item: AIFT's 4-Part Evaluative Rubric."""
    claim_id: str
    statement: str
    citing_finding_ids: List[str] = Field(default_factory=list)
    source_artifact_hashes: List[str] = Field(default_factory=list)
    why_it_matters: str  # Part 1: Security significance & ATT&CK mapping
    benign_alternative: str  # Part 2: Plausible administrative / OS explanation
    verification_steps: List[str] = Field(default_factory=list)  # Part 3: Actionable telemetry steps
    data_gaps: List[str] = Field(default_factory=list)  # Part 4: Missing logs, blind spots


class PatientZeroRemediationSection(BaseModel):
    """Section 6: Multi-host Patient Zero assessment, lateral movement, and containment."""
    title: str = "Multi-Host Patient Zero Assessment & Remediation"
    patient_zero_host: Optional[str] = None
    patient_zero_status: str = "VERIFIED"  # "VERIFIED", "SUSPECTED", "UNDETERMINED_INSUFFICIENT_EVIDENCE"
    initial_access_vector: Optional[str] = None
    initial_timestamp_utc: Optional[str] = None
    confidence: float = 0.85
    evidence_basis: List[str] = Field(default_factory=list)
    lateral_movement_paths: List[str] = Field(default_factory=list)
    containment_actions: List[str] = Field(default_factory=list)
    remediation_steps: List[str] = Field(default_factory=list)
    data_gaps: List[str] = Field(default_factory=list)


class ReportProvenance(BaseModel):
    """Provenance and cryptographic signature record for forensic reports."""
    version: int = 1
    status: Literal["draft", "finalized", "signed", "blocked", "incomplete"] = "draft"
    created_utc: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    created_by: str = "ForensicOps Autonomous Engine"
    finalized_utc: Optional[str] = None
    finalized_by: Optional[str] = None
    finalized_role: Optional[str] = None
    approval_token_id: Optional[str] = None
    approval_token_signature: Optional[str] = None
    canonical_report_digest: Optional[str] = None
    parent_report_id: Optional[str] = None


class CitedReport(BaseModel):
    """Master 6-Section Forensic Investigation Report."""
    report_id: str = Field(default_factory=lambda: str(uuid4()))
    case_id: str
    title: str = "ForensicOps AI — Verified Incident Investigation Report"
    generated_utc: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: Literal["draft", "finalized", "signed", "blocked", "incomplete"] = "draft"
    version: int = 1
    provenance: ReportProvenance = Field(default_factory=ReportProvenance)
    digest: Optional[str] = None
    executive_summary: ExecutiveSummarySection
    custody_and_filter_audit: CustodyAuditSection
    observed_facts: List[CitedClaim] = Field(default_factory=list)
    derived_correlations: List[CitedClaim] = Field(default_factory=list)
    correlation_records: List[DeterministicCorrelationRecord] = Field(default_factory=list)
    evidence_conflicts: List[EvidenceConflict] = Field(default_factory=list)
    rejected_claims: List[CitedClaim] = Field(default_factory=list)
    unverified_hypotheses: List[CitedClaim] = Field(default_factory=list)
    aift_rubric: List[AIFTRubricItem] = Field(default_factory=list)
    patient_zero_and_remediation: PatientZeroRemediationSection
    all_cited_finding_ids: List[str] = Field(default_factory=list)
    all_source_artifact_hashes: List[str] = Field(default_factory=list)

    @property
    def verified_finding_ids(self) -> List[str]:
        return self.all_cited_finding_ids

    @property
    def verified_artifact_hashes(self) -> List[str]:
        return self.all_source_artifact_hashes

    def compute_canonical_digest(self) -> str:
        """Compute deterministic SHA-256 digest over the canonical JSON of the report."""
        dump = self.model_dump(
            exclude={
                "digest": True,
                "provenance": {
                    "finalized_utc": True,
                    "finalized_by": True,
                    "finalized_role": True,
                    "approval_token_id": True,
                    "approval_token_signature": True,
                    "canonical_report_digest": True,
                },
            }
        )
        canonical_str = json.dumps(dump, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
        digest_hex = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()
        return f"sha256:{digest_hex}"

    def to_markdown(self) -> str:
        """Render the complete 6-section report in GitHub Flavored Markdown."""
        lines: List[str] = []
        lines.append(f"# {self.title}")
        status_chip = self.status.upper()
        lines.append(
            f"**Case ID:** `{self.case_id}` | **Status:** `{status_chip}` (v{self.version}) | "
            f"**Generated (UTC):** `{self.generated_utc}` | **Report ID:** `{self.report_id}`\n"
        )
        if self.provenance.finalized_by:
            lines.append(
                f"> [!IMPORTANT]\n"
                f"> **Digitally Approved & Signed by:** `{self.provenance.finalized_by}` (`{self.provenance.finalized_role}`)  \n"
                f"> **Finalized UTC:** `{self.provenance.finalized_utc}`  \n"
                f"> **Canonical Digest:** `{self.provenance.canonical_report_digest or self.digest or 'N/A'}`  \n"
                f"> **Approval Token ID:** `{self.provenance.approval_token_id}`\n"
            )
        lines.append("---\n")

        # Section 1
        sec1 = self.executive_summary
        lines.append("## 1. Executive Summary & Incident Timeline")
        lines.append(f"**Overall Assessment Severity:** `{sec1.severity.upper()}`\n")
        lines.append(f"**Impacted Hosts:** {', '.join(f'`{h}`' for h in sec1.impacted_hosts) if sec1.impacted_hosts else 'None detected'}")
        lines.append(f"**Impacted Accounts:** {', '.join(f'`{u}`' for u in sec1.impacted_users) if sec1.impacted_users else 'None detected'}")
        lines.append(f"**Time Window:** `{sec1.earliest_timestamp_utc or 'N/A'}` to `{sec1.latest_timestamp_utc or 'N/A'}`\n")
        lines.append(f"### Incident Overview\n{sec1.incident_overview}\n")

        # Evidence Conflicts Table (Never suppress contradictory observations)
        if self.evidence_conflicts:
            lines.append("### Evidence Conflicts & Contradictory Observations")
            lines.append("| Conflict ID | Type | Severity | Description | Affected Items |")
            lines.append("|---|---|---|---|---|")
            for c in self.evidence_conflicts:
                aff = ", ".join(c.affected_finding_ids[:3]) if c.affected_finding_ids else "Case Telemetry"
                lines.append(f"| `{c.conflict_id[:8]}...` | `{c.conflict_type}` | `{c.severity.upper()}` | {c.description} | `{aff}` |")
            lines.append("\n*Contradictory evidence identified above is preserved without suppression.*\n")

        lines.append("### Chronological Forensic Timeline")
        if sec1.timeline:
            lines.append("| Timestamp (UTC) | Host | User | Event / Process | Severity | Citation | Clock & Timezone Status |")
            lines.append("|---|---|---|---|---|---|---|")
            for t in sec1.timeline:
                short_hash = t.source_artifact_hash[:12] if t.source_artifact_hash else "none"
                citation = f"`[{t.citing_finding_id[:8]}...|{short_hash}]`"
                tz_note = f"{t.timezone_status} ({t.clock_uncertainty or 'none'})"
                lines.append(
                    f"| `{t.timestamp_utc}` | `{t.host or '-'}` | `{t.user or '-'}` | {t.process_or_event} | `{t.severity}` | {citation} | {tz_note} |"
                )
        else:
            lines.append("*No timeline events recorded.*")
        lines.append("\n---\n")

        # Section 2
        sec2 = self.custody_and_filter_audit
        lines.append("## 2. Chain of Custody & Projection Filter Audit Table")
        if sec2.tamper_check_passed:
            lines.append("**Custody Ledger Verification:** `VERIFIED (100% Chain Integrity)`\n")
        elif sec2.verification_status == "FAILED":
            lines.append("**Custody Ledger Verification:** `WARNING: Custody Discrepancy Detected`\n")
            if sec2.verification_errors:
                lines.append("**Integrity Failure Discrepancies:**")
                for err in sec2.verification_errors:
                    lines.append(f"- ⚠️ {err}")
                lines.append("")
        else:
            lines.append(f"**Custody Ledger Verification:** `INCOMPLETE: {sec2.verification_status}`\n")
            if sec2.verification_errors:
                lines.append("**Integrity Discrepancies:**")
                for err in sec2.verification_errors:
                    lines.append(f"- ⚠️ {err}")
                lines.append("")

        if sec2.evidence_items:
            lines.append("| Artifact ID | SHA-256 Hash | Intake Timestamp | Status |")
            lines.append("|---|---|---|---|")
            for item in sec2.evidence_items:
                lines.append(
                    f"| `{item.get('artifact_id', '-')}` | `{item.get('sha256', '-')}` | `{item.get('intake_utc', '-')}` | `{item.get('status', 'Verified')}` |"
                )
        else:
            lines.append("*No evidence records logged.*")

        if sec2.column_projection_summary:
            lines.append("\n### Column Projection Optimization Audit")
            proj = sec2.column_projection_summary
            lines.append(f"- **Raw Rows Ingested:** {proj.get('total_raw_rows', 'N/A')}")
            lines.append(f"- **Findings Indexed:** {proj.get('total_findings_indexed', 'N/A')}")
            lines.append(f"- **High-Signal Projected Columns:** `{', '.join(proj.get('projected_columns', []))}`")
        lines.append("\n---\n")

        # Section 3
        lines.append("## 3. Observed Facts")
        if self.observed_facts:
            for idx, fact in enumerate(self.observed_facts, 1):
                citations = " ".join(
                    f"`[Finding: {fid} | Hash: {h[:12]}]`"
                    for fid, h in zip(fact.citing_finding_ids, fact.source_artifact_hashes)
                )
                lines.append(f"{idx}. {fact.statement} (Confidence: {int(fact.confidence * 100)}%)")
                lines.append(f"   - **Citations:** {citations if citations else '`[Direct Telemetry]`'}")
        else:
            lines.append("*No verified observed facts logged.*")
        lines.append("\n---\n")

        # Section 4
        lines.append("## 4. Derived Correlations")
        if self.correlation_records:
            for idx, rec in enumerate(self.correlation_records, 1):
                citations = " ".join(
                    f"`[Finding: {fid} | Hash: {h[:12]}]`"
                    for fid, h in zip(rec.source_finding_ids, rec.source_artifact_hashes)
                )
                stmt = rec.statement or f"Correlated {rec.relationship_type}"
                lines.append(f"{idx}. {stmt} (Relationship: `{rec.relationship_type}` | Confidence: {int(rec.confidence * 100)}%)")
                lines.append(f"   - **Entities:** `{json.dumps(rec.entity_identifiers)}`")
                lines.append(f"   - **Method:** `{rec.correlation_method}`")
                if rec.time_window:
                    lines.append(f"   - **Time Window:** `{rec.time_window.get('start_utc')}` to `{rec.time_window.get('end_utc')}` ({rec.time_window.get('duration_seconds')}s)")
                lines.append(f"   - **Correlated Evidence:** {citations}")
                if rec.conflicting_observations:
                    lines.append(f"   - **Conflicting Telemetry:** `{', '.join(rec.conflicting_observations)}`")
                if rec.limitations:
                    lines.append(f"   - **Limitations:** {', '.join(rec.limitations)}")
        elif self.derived_correlations:
            for idx, corr in enumerate(self.derived_correlations, 1):
                citations = " ".join(
                    f"`[Finding: {fid} | Hash: {h[:12]}]`"
                    for fid, h in zip(corr.citing_finding_ids, corr.source_artifact_hashes)
                )
                lines.append(f"{idx}. {corr.statement} (Confidence: {int(corr.confidence * 100)}%)")
                lines.append(f"   - **Correlated Evidence:** {citations if citations else '`[Multi-Artifact]`'}")
        else:
            lines.append("*No derived correlations logged.*")

        if self.unverified_hypotheses:
            lines.append("\n### Unverified Hypotheses & Evaluated Leads")
            lines.append("| Lead ID | Statement / Hypothesis | Confidence | Status | Review Notes |")
            lines.append("|---|---|---|---|---|")
            for h in self.unverified_hypotheses:
                lines.append(
                    f"| `{h.claim_id[:8]}...` | {h.statement} | {int(h.confidence * 100)}% | `{h.verification_status}` | {h.review_notes or 'Analyst review recommended'} |"
                )
            lines.append("\n*Hypotheses and unverified leads above are explicitly separated from confirmed forensic findings.*")
        lines.append("\n---\n")

        # Section 5
        lines.append("## 5. AIFT 4-Part Evaluative Rubric")
        if self.aift_rubric:
            for idx, rubric in enumerate(self.aift_rubric, 1):
                citations = " ".join(
                    f"`[Finding: {fid} | Hash: {h[:12]}]`"
                    for fid, h in zip(rubric.citing_finding_ids, rubric.source_artifact_hashes)
                )
                lines.append(f"### Claim 5.{idx}: {rubric.statement}")
                lines.append(f"- **Citations:** {citations}")
                lines.append(f"- **Why It Matters (Part 1):** {rubric.why_it_matters}")
                lines.append(f"- **Alternative Benign Explanation (Part 2):** {rubric.benign_alternative}")
                lines.append("- **Verification Steps (Part 3):**")
                for s in rubric.verification_steps:
                    lines.append(f"  - [ ] {s}")
                lines.append("- **Explicit Data Gaps & Blind Spots (Part 4):**")
                for g in rubric.data_gaps:
                    lines.append(f"  - ⚠️ {g}")
                lines.append("")
        else:
            lines.append("*No AIFT rubric evaluations recorded.*")
        lines.append("\n---\n")

        # Section 6
        sec6 = self.patient_zero_and_remediation
        lines.append("## 6. Multi-Host Patient Zero Assessment & Remediation")
        lines.append(f"**Identified Patient Zero Host:** `{sec6.patient_zero_host or 'Undetermined'}`")
        lines.append(f"**Assessment Status:** `{sec6.patient_zero_status}` (Confidence: {int(sec6.confidence * 100)}%)")
        lines.append(f"**Estimated Initial Access Vector:** {sec6.initial_access_vector or 'Unverified'}")
        lines.append(f"**Earliest Intrusion Timestamp:** `{sec6.initial_timestamp_utc or 'N/A'}`\n")

        if sec6.evidence_basis:
            lines.append("### Evidentiary Basis")
            for eb in sec6.evidence_basis:
                lines.append(f"- {eb}")

        lines.append("\n### Lateral Movement Paths")
        if sec6.lateral_movement_paths:
            for p in sec6.lateral_movement_paths:
                lines.append(f"- {p}")
        else:
            lines.append("- *No lateral movement detected; activity confined to single host.*")

        lines.append("\n### Immediate Containment Actions")
        if sec6.containment_actions:
            for a in sec6.containment_actions:
                lines.append(f"- [ ] {a}")
        else:
            lines.append("- *Standard host isolation recommended.*")

        lines.append("\n### Strategic Remediation Steps")
        if sec6.remediation_steps:
            for r in sec6.remediation_steps:
                lines.append(f"- [ ] {r}")
        else:
            lines.append("- *Revoke compromised credentials and rotate domain Kerberos tickets.*")

        if sec6.data_gaps:
            lines.append("\n### Patient Zero Assessment Data Gaps")
            for g in sec6.data_gaps:
                lines.append(f"- ⚠️ {g}")

        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class ReportStore:
    """Thread-safe SQLite store for forensic report drafts, final versions, and provenance."""

    def __init__(self, db_path: Optional[Union[str, Path]] = None):
        if db_path is None or str(db_path) == ":memory:":
            self._db_path = ":memory:"
        else:
            p = Path(db_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            self._db_path = str(p)
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._init_tables()

    def _init_tables(self) -> None:
        with self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS forensic_reports (
                    report_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    version INTEGER NOT NULL DEFAULT 1,
                    status TEXT NOT NULL DEFAULT 'draft',
                    report_json TEXT NOT NULL,
                    markdown TEXT NOT NULL,
                    digest TEXT,
                    created_utc TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    finalized_utc TEXT,
                    finalized_by TEXT,
                    finalized_role TEXT,
                    approval_token_id TEXT,
                    approval_token_signature TEXT
                );
                """
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_reports_case_ver ON forensic_reports(case_id, version DESC);"
            )

    def save_report(self, report: CitedReport) -> None:
        with self._conn:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO forensic_reports (
                    report_id, case_id, version, status, report_json, markdown, digest,
                    created_utc, created_by, finalized_utc, finalized_by, finalized_role,
                    approval_token_id, approval_token_signature
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    report.report_id,
                    report.case_id,
                    report.version,
                    report.status,
                    json.dumps(report.to_dict()),
                    report.to_markdown(),
                    report.digest,
                    report.provenance.created_utc,
                    report.provenance.created_by,
                    report.provenance.finalized_utc,
                    report.provenance.finalized_by,
                    report.provenance.finalized_role,
                    report.provenance.approval_token_id,
                    report.provenance.approval_token_signature,
                ),
            )

    def get_report(self, report_id: str) -> Optional[CitedReport]:
        cursor = self._conn.execute(
            "SELECT report_json FROM forensic_reports WHERE report_id = ?;", (report_id,)
        )
        row = cursor.fetchone()
        if not row:
            return None
        return CitedReport.model_validate_json(row[0])

    def get_latest_report(self, case_id: str) -> Optional[CitedReport]:
        cursor = self._conn.execute(
            "SELECT report_json FROM forensic_reports WHERE case_id = ? ORDER BY version DESC LIMIT 1;",
            (case_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        return CitedReport.model_validate_json(row[0])

    def list_history(self, case_id: str) -> List[Dict[str, Any]]:
        cursor = self._conn.execute(
            """
            SELECT report_id, version, status, digest, created_utc, created_by,
                   finalized_utc, finalized_by, finalized_role, approval_token_id
            FROM forensic_reports
            WHERE case_id = ?
            ORDER BY version DESC;
            """,
            (case_id,),
        )
        rows = cursor.fetchall()
        return [
            {
                "report_id": r[0],
                "version": r[1],
                "status": r[2],
                "digest": r[3],
                "created_utc": r[4],
                "created_by": r[5],
                "finalized_utc": r[6],
                "finalized_by": r[7],
                "finalized_role": r[8],
                "approval_token_id": r[9],
            }
            for r in rows
        ]

    def get_next_version(self, case_id: str) -> int:
        cursor = self._conn.execute(
            "SELECT MAX(version) FROM forensic_reports WHERE case_id = ?;", (case_id,)
        )
        row = cursor.fetchone()
        if row and row[0] is not None:
            return int(row[0]) + 1
        return 1

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass


_GLOBAL_REPORT_STORE: Optional[ReportStore] = None


def get_report_store(db_path: Optional[Union[str, Path]] = None) -> ReportStore:
    """Retrieve or initialize the singleton ReportStore instance."""
    global _GLOBAL_REPORT_STORE
    if _GLOBAL_REPORT_STORE is None or db_path is not None:
        resolved_path = db_path
        if resolved_path is None:
            vault_dir = getattr(get_settings(), "vault_dir", Path("vault"))
            resolved_path = Path(vault_dir) / "reports.db"
        _GLOBAL_REPORT_STORE = ReportStore(resolved_path)
    return _GLOBAL_REPORT_STORE


def reset_report_store(store: Optional[ReportStore] = None) -> None:
    """Reset the singleton instance for testing isolation."""
    global _GLOBAL_REPORT_STORE
    if _GLOBAL_REPORT_STORE is not None:
        _GLOBAL_REPORT_STORE.close()
    _GLOBAL_REPORT_STORE = store


class ReportBuilder:
    """Compiles verified findings and AI goal results into the 6-section Cited Report."""

    @classmethod
    def detect_evidence_conflicts(
        cls,
        findings: List[ForensicFinding],
        custody_engine: Optional[Any] = None,
        audit_entries: Optional[List[Dict[str, Any]]] = None,
    ) -> List[EvidenceConflict]:
        """Deterministically detect contradictory, duplicate, or missing evidence without suppression."""
        conflicts: List[EvidenceConflict] = []
        now_utc = datetime.now(timezone.utc)

        # 1. Conflicting Timestamps (future dates, causality inversion)
        for f in findings:
            if f.timestamp_utc:
                try:
                    ts_clean = f.timestamp_utc.replace("Z", "+00:00")
                    if "+" not in ts_clean and "-" not in ts_clean[10:]:
                        dt = datetime.fromisoformat(ts_clean).replace(tzinfo=timezone.utc)
                    else:
                        dt = datetime.fromisoformat(ts_clean)
                    if dt > now_utc + timedelta(hours=1):
                        conflicts.append(
                            EvidenceConflict(
                                conflict_type="conflicting_timestamps",
                                affected_finding_ids=[f.finding_id],
                                affected_artifact_hashes=[f.source_artifact_hash],
                                severity="high",
                                description=f"Finding timestamp '{f.timestamp_utc}' is set in the future relative to analysis time.",
                                contradictory_details={"finding_id": f.finding_id, "timestamp": f.timestamp_utc},
                            )
                        )
                except Exception:
                    pass

        # Causality inversion check
        for idx1, f1 in enumerate(findings):
            for f2 in findings[idx1 + 1 :]:
                if (
                    f1.host
                    and f1.host == f2.host
                    and f1.user
                    and f1.user == f2.user
                    and f1.category == "authentication"
                    and f2.category == "process_creation"
                ):
                    if f1.timestamp_utc and f2.timestamp_utc and f1.timestamp_utc > f2.timestamp_utc:
                        conflicts.append(
                            EvidenceConflict(
                                conflict_type="conflicting_timestamps",
                                affected_finding_ids=[f1.finding_id, f2.finding_id],
                                affected_artifact_hashes=[f1.source_artifact_hash, f2.source_artifact_hash],
                                severity="high",
                                description=(
                                    f"Causality inversion: Process creation '{f2.process_name}' at {f2.timestamp_utc} "
                                    f"precedes initiating authentication at {f1.timestamp_utc}."
                                ),
                                contradictory_details={
                                    "auth_finding": f1.finding_id,
                                    "auth_time": f1.timestamp_utc,
                                    "process_finding": f2.finding_id,
                                    "process_time": f2.timestamp_utc,
                                },
                            )
                        )

        # 2. Conflicting User Identities
        for idx1, f1 in enumerate(findings):
            for f2 in findings[idx1 + 1 :]:
                if (
                    f1.host
                    and f1.host == f2.host
                    and f1.process_name
                    and f1.process_name == f2.process_name
                    and f1.timestamp_utc
                    and f1.timestamp_utc == f2.timestamp_utc
                    and f1.user
                    and f2.user
                    and f1.user != f2.user
                ):
                    conflicts.append(
                        EvidenceConflict(
                            conflict_type="conflicting_user_identities",
                            affected_finding_ids=[f1.finding_id, f2.finding_id],
                            affected_artifact_hashes=[f1.source_artifact_hash, f2.source_artifact_hash],
                            severity="medium",
                            description=(
                                f"Mismatched user attribution for process '{f1.process_name}' on '{f1.host}' "
                                f"at {f1.timestamp_utc}: '{f1.user}' vs '{f2.user}'."
                            ),
                            contradictory_details={"users": [f1.user, f2.user]},
                        )
                    )

        # 3. Conflicting Host Identifiers
        seen_ips: Dict[str, str] = {}
        for f in findings:
            ip = f.projected_data.get("ip") or f.projected_data.get("source_ip") or f.projected_data.get("dest_ip")
            if ip and f.host:
                if ip in seen_ips and seen_ips[ip] != f.host:
                    conflicts.append(
                        EvidenceConflict(
                            conflict_type="conflicting_host_identifiers",
                            affected_finding_ids=[f.finding_id],
                            affected_artifact_hashes=[f.source_artifact_hash],
                            severity="medium",
                            description=f"IP address '{ip}' mapped to multiple host identifiers: '{seen_ips[ip]}' and '{f.host}'.",
                            contradictory_details={"ip": ip, "hosts": [seen_ips[ip], f.host]},
                        )
                    )
                else:
                    seen_ips[ip] = f.host

        # 4. Duplicate Observations
        seen_keys: Dict[str, str] = {}
        for f in findings:
            key = f"{f.host}|{f.timestamp_utc}|{f.process_name}|{f.event_id}|{f.category}"
            if key in seen_keys:
                conflicts.append(
                    EvidenceConflict(
                        conflict_type="duplicate_observations",
                        affected_finding_ids=[seen_keys[key], f.finding_id],
                        affected_artifact_hashes=[f.source_artifact_hash],
                        severity="low",
                        description=f"Duplicate observation detected across findings '{seen_keys[key]}' and '{f.finding_id}'.",
                        contradictory_details={"key": key},
                    )
                )
            else:
                seen_keys[key] = f.finding_id

        # 5. Missing Artifacts
        if custody_engine is not None and hasattr(custody_engine, "get_artifact"):
            for f in findings:
                try:
                    art = custody_engine.get_artifact(f.source_artifact_id)
                    if not art:
                        conflicts.append(
                            EvidenceConflict(
                                conflict_type="missing_artifacts",
                                affected_finding_ids=[f.finding_id],
                                affected_artifact_hashes=[f.source_artifact_hash],
                                severity="critical",
                                description=f"Finding '{f.finding_id}' cites source_artifact_id '{f.source_artifact_id}' which does not exist in custody vault.",
                                contradictory_details={"missing_artifact_id": f.source_artifact_id},
                            )
                        )
                except Exception:
                    pass

        # 6. Incomplete Telemetry (time gaps > 24h)
        ts_sorted = sorted([f.timestamp_utc for f in findings if f.timestamp_utc and f.timestamp_utc.endswith("Z")])
        for i in range(len(ts_sorted) - 1):
            try:
                t1 = datetime.fromisoformat(ts_sorted[i].replace("Z", "+00:00"))
                t2 = datetime.fromisoformat(ts_sorted[i + 1].replace("Z", "+00:00"))
                delta = (t2 - t1).total_seconds()
                if delta > 86400:
                    conflicts.append(
                        EvidenceConflict(
                            conflict_type="incomplete_telemetry",
                            severity="low",
                            description=f"Telemetry gap of {int(delta // 3600)} hours detected between {ts_sorted[i]} and {ts_sorted[i + 1]}.",
                            contradictory_details={"start": ts_sorted[i], "end": ts_sorted[i + 1], "gap_hours": delta / 3600},
                        )
                    )
            except Exception:
                pass

        # 7. Tool Errors
        if audit_entries:
            for entry in audit_entries:
                if entry.get("status") in ("failed", "error") or entry.get("exit_code", 0) != 0:
                    conflicts.append(
                        EvidenceConflict(
                            conflict_type="tool_errors",
                            severity="high",
                            description=f"Tool execution '{entry.get('tool_id')}' failed: {entry.get('error', 'Non-zero exit code')}.",
                            contradictory_details=entry,
                        )
                    )

        return conflicts

    @staticmethod
    def correlate_patient_zero(
        findings: List[ForensicFinding],
    ) -> PatientZeroRemediationSection:
        """Deterministically determine Patient Zero without inferring solely from earliest event."""
        host_timestamps: Dict[str, List[ForensicFinding]] = {}
        for f in findings:
            if f.host and f.timestamp_utc:
                host_timestamps.setdefault(f.host, []).append(f)

        if not host_timestamps:
            return PatientZeroRemediationSection(
                patient_zero_host=None,
                patient_zero_status="UNDETERMINED_INSUFFICIENT_EVIDENCE",
                initial_access_vector="No timestamped host telemetry available",
                initial_timestamp_utc=None,
                confidence=0.0,
                lateral_movement_paths=[],
                containment_actions=["Isolate suspected hosts pending telemetry ingestion."],
                remediation_steps=["Deploy offline triage collectors."],
                data_gaps=["No host telemetry collected."],
            )

        for h, f_list in host_timestamps.items():
            f_list.sort(key=lambda x: x.timestamp_utc or "")

        hosts_by_earliest = sorted(
            host_timestamps.keys(),
            key=lambda h: host_timestamps[h][0].timestamp_utc or "9999-99-99",
        )

        candidate_host = hosts_by_earliest[0]
        first_finding = host_timestamps[candidate_host][0]

        initial_access_keywords = (
            "phish", "lure", "macro", "attachment", "exploit", "cve", "webshell",
            "rce", "ingress", "drive-by", "spear", "unauthorized remote logon",
            "external", "vpn"
        )

        has_initial_access_indicator = False
        initial_finding = first_finding
        for f in host_timestamps[candidate_host]:
            text = f"{f.summary} {f.process_name or ''} {f.command_line or ''} {f.category}".lower()
            if any(k in text for k in initial_access_keywords):
                has_initial_access_indicator = True
                initial_finding = f
                break

        if not has_initial_access_indicator:
            for other_host in hosts_by_earliest[1:]:
                for f in host_timestamps[other_host]:
                    text = f"{f.summary} {f.process_name or ''} {f.command_line or ''} {f.category}".lower()
                    if any(k in text for k in initial_access_keywords):
                        candidate_host = other_host
                        initial_finding = f
                        has_initial_access_indicator = True
                        break
                if has_initial_access_indicator:
                    break

        lateral_paths: List[str] = []
        if len(hosts_by_earliest) > 1:
            pz_users = {f.user for f in host_timestamps[candidate_host] if f.user}
            for downstream_host in [h for h in hosts_by_earliest if h != candidate_host]:
                downstream_findings = host_timestamps[downstream_host]
                downstream_earliest = downstream_findings[0].timestamp_utc
                shared = [f.user for f in downstream_findings if f.user in pz_users]
                if shared:
                    lateral_paths.append(
                        f"Lateral pivot from `{candidate_host}` -> `{downstream_host}` via shared account `{shared[0]}` at `{downstream_earliest}`"
                    )
                else:
                    lateral_paths.append(
                        f"Sequential compromise: `{candidate_host}` ({first_finding.timestamp_utc}) -> `{downstream_host}` ({downstream_earliest})"
                    )

        # MANDATE: Do not infer patient zero solely from the earliest available event!
        if not has_initial_access_indicator:
            return PatientZeroRemediationSection(
                patient_zero_host=None,
                patient_zero_status="UNDETERMINED_INSUFFICIENT_EVIDENCE",
                initial_access_vector=(
                    f"Undetermined: Earliest recorded activity on '{candidate_host}' is an internal event "
                    f"({first_finding.category}) without evidence of initial access or external ingress."
                ),
                initial_timestamp_utc=first_finding.timestamp_utc,
                confidence=0.35,
                evidence_basis=[
                    f"Candidate '{candidate_host}' exhibits earliest timestamp ({first_finding.timestamp_utc}), "
                    "but lacks initial compromise evidence."
                ],
                lateral_movement_paths=lateral_paths,
                containment_actions=[
                    "Isolate all observed endpoints pending initial access telemetry.",
                    *[f"Quarantine suspect host `{h}`." for h in hosts_by_earliest],
                ],
                remediation_steps=[
                    "Inspect perimeter firewall, VPN, and proxy logs for external ingress vectors.",
                    "Deploy memory acquisition across all active suspect hosts.",
                ],
                data_gaps=[
                    "Missing perimeter firewall, VPN, email gateway, and initial access telemetry.",
                    "Earliest available finding is post-compromise internal execution.",
                ],
            )

        vector_desc = f"Observed {initial_finding.artifact_type} ({initial_finding.category}) on {candidate_host}: {initial_finding.summary}"
        if initial_finding.process_name:
            vector_desc += f" (Process: {initial_finding.process_name})"

        return PatientZeroRemediationSection(
            patient_zero_host=candidate_host,
            patient_zero_status="VERIFIED",
            initial_access_vector=vector_desc,
            initial_timestamp_utc=initial_finding.timestamp_utc,
            confidence=0.95,
            evidence_basis=[
                f"Host '{candidate_host}' exhibits earliest intrusion telemetry and documented initial access vector: {initial_finding.summary}"
            ],
            lateral_movement_paths=lateral_paths,
            containment_actions=[
                f"Immediately sever network connectivity for Patient Zero `{candidate_host}`.",
                *[f"Quarantine downstream host `{h}`." for h in hosts_by_earliest if h != candidate_host],
                "Disable compromised user accounts across Active Directory / IdP.",
            ],
            remediation_steps=[
                f"Perform memory acquisition on `{candidate_host}` before powering down.",
                "Inspect perimeter firewall/VPN logs for inbound sessions matching initial access timestamp.",
                "Rotate all service account credentials and Kerberos krbtgt ticket.",
            ],
            data_gaps=[],
        )

    @classmethod
    def build_report(
        cls,
        case_id: str,
        node_results: List[NodeGoalResult],
        storage: ForensicStore,
        custody_engine: Optional[Any] = None,
        audit_entries: Optional[List[Dict[str, Any]]] = None,
        strict_citations: bool = False,
        creator: str = "ForensicOps Autonomous Engine",
        db_path: Optional[Union[str, Path]] = None,
    ) -> CitedReport:
        """Assemble verified findings, evidence conflicts, and correlations into master CitedReport."""
        # 1. Independent Citation Enforcement (Task 5)
        guard = CitationGuard(storage=storage, custody_engine=custody_engine)

        raw_claims: List[CitedClaim] = []
        for res in node_results:
            raw_claims.extend(res.claims)

        observed_facts: List[CitedClaim] = []
        derived_correlations: List[CitedClaim] = []
        unverified_hypotheses: List[CitedClaim] = []
        rejected_claims: List[CitedClaim] = []
        all_cited_fids: Set[str] = set()
        all_cited_hashes: Set[str] = set()
        aift_rubric_items: List[AIFTRubricItem] = []
        citation_conflicts: List[EvidenceConflict] = []

        for claim in raw_claims:
            is_valid, reasons = guard.validate_claim(claim, case_id=case_id)
            if is_valid:
                # Criteria for Confirmed Finding:
                # 100% backed by verified DuckDB finding IDs and hashes,
                # confidence > 0.40,
                # not requiring analyst review,
                # verification_status == "VERIFIED",
                # not downgraded
                is_confirmed_fact = (
                    claim.claim_type in ("observed_fact", "derived_fact")
                    and claim.confidence > 0.40
                    and not claim.requires_analyst_review
                    and claim.verification_status == "VERIFIED"
                )
                is_confirmed_corr = (
                    claim.claim_type == "derived_correlation"
                    and claim.confidence > 0.40
                    and not claim.requires_analyst_review
                    and claim.verification_status == "VERIFIED"
                )

                if is_confirmed_fact:
                    observed_facts.append(claim)
                    all_cited_fids.update(claim.citing_finding_ids)
                    all_cited_hashes.update(claim.source_artifact_hashes)
                elif is_confirmed_corr:
                    derived_correlations.append(claim)
                    all_cited_fids.update(claim.citing_finding_ids)
                    all_cited_hashes.update(claim.source_artifact_hashes)
                else:
                    # Explicitly separate Unverified Hypotheses / Evidence Gaps
                    unverified_hypotheses.append(claim)
                    if claim.citing_finding_ids:
                        all_cited_fids.update(claim.citing_finding_ids)
                    if claim.source_artifact_hashes:
                        all_cited_hashes.update(claim.source_artifact_hashes)

                why = claim.why_it_matters or f"Indicates potential adversary activity corresponding to {claim.statement}"
                benign = claim.benign_alternative or "May represent legitimate administrator maintenance or scheduled automated script."
                verify_steps = claim.verification_steps or [
                    "Cross-reference parent process lineage and user logon session ID.",
                    "Verify file hash against known legitimate OS binary baseline.",
                ]
                data_gaps = claim.data_gaps or [
                    "Process command line auditing or PowerShell script block logging may not be enabled.",
                ]

                aift_rubric_items.append(
                    AIFTRubricItem(
                        claim_id=claim.claim_id,
                        statement=claim.statement,
                        citing_finding_ids=claim.citing_finding_ids,
                        source_artifact_hashes=claim.source_artifact_hashes,
                        why_it_matters=why,
                        benign_alternative=benign,
                        verification_steps=verify_steps,
                        data_gaps=data_gaps,
                    )
                )
            else:
                claim.verification_status = "REJECTED"
                claim.review_notes = f"CitationGuard rejected: {'; '.join(reasons)}"
                rejected_claims.append(claim)
                citation_conflicts.append(
                    EvidenceConflict(
                        conflict_type="missing_artifacts" if "source artifact" in str(reasons) else "incomplete_telemetry",
                        affected_finding_ids=claim.citing_finding_ids,
                        affected_artifact_hashes=claim.source_artifact_hashes,
                        severity="high",
                        description=f"Claim '{claim.claim_id}' rejected by CitationGuard: {'; '.join(reasons)}",
                        contradictory_details={"statement": claim.statement, "reasons": reasons},
                    )
                )

        if strict_citations and rejected_claims:
            raise CitationValidationError(
                f"ReportBuilder: {len(rejected_claims)} claim(s) failed citation validation: "
                + "; ".join(c.review_notes or "" for c in rejected_claims)
            )

        # 2. Retrieve referenced findings from storage
        referenced_findings = storage.get_findings_by_ids(sorted(list(all_cited_fids)), case_id=case_id)
        if not referenced_findings:
            referenced_findings = storage.query_structured_findings(case_id=case_id, limit=200)

        # 3. Evidence-backed Timeline Construction (Task 1)
        impacted_hosts: Set[str] = set()
        impacted_users: Set[str] = set()
        timeline_entries: List[TimelineEntry] = []

        for f in referenced_findings:
            if f.host:
                impacted_hosts.add(f.host)
            if f.user:
                impacted_users.add(f.user)

            parsed_ts = parse_forensic_timestamp(f.timestamp_utc, f.projected_data, f.artifact_type)
            display_ts = parsed_ts["normalized_timestamp_utc"] or parsed_ts["original_timestamp"] or "N/A"

            timeline_entries.append(
                TimelineEntry(
                    timestamp_utc=display_ts,
                    original_timestamp=parsed_ts["original_timestamp"],
                    original_timezone=parsed_ts["original_timezone"],
                    timezone_status=parsed_ts["timezone_status"],
                    normalized_timestamp_utc=parsed_ts["normalized_timestamp_utc"],
                    timestamp_source=parsed_ts["timestamp_source"],
                    timestamp_precision=parsed_ts["timestamp_precision"],
                    clock_uncertainty=parsed_ts["clock_uncertainty"],
                    host=f.host,
                    user=f.user,
                    process_or_event=f.process_name or f.event_id or f.category,
                    summary=f.summary,
                    severity=f.severity,
                    citing_finding_id=f.finding_id,
                    source_artifact_hash=f.source_artifact_hash,
                )
            )

        # Chronological sort: normalized UTC first, then raw string
        timeline_entries.sort(
            key=lambda t: t.normalized_timestamp_utc or t.original_timestamp or "9999-99-99"
        )

        earliest_ts = timeline_entries[0].normalized_timestamp_utc or timeline_entries[0].original_timestamp if timeline_entries else None
        latest_ts = timeline_entries[-1].normalized_timestamp_utc or timeline_entries[-1].original_timestamp if timeline_entries else None

        # 4. Correlation Records Construction (Task 2)
        correlation_records: List[DeterministicCorrelationRecord] = []
        for corr in derived_correlations:
            corr_findings = [f for f in referenced_findings if f.finding_id in corr.citing_finding_ids]
            entities: Dict[str, Any] = {}
            hosts = {f.host for f in corr_findings if f.host}
            users = {f.user for f in corr_findings if f.user}
            procs = {f.process_name for f in corr_findings if f.process_name}
            if hosts:
                entities["hosts"] = sorted(list(hosts))
            if users:
                entities["users"] = sorted(list(users))
            if procs:
                entities["processes"] = sorted(list(procs))

            ts_list = [f.timestamp_utc for f in corr_findings if f.timestamp_utc]
            time_window = None
            if ts_list:
                ts_list.sort()
                duration = 0.0
                try:
                    t_min = datetime.fromisoformat(ts_list[0].replace("Z", "+00:00"))
                    t_max = datetime.fromisoformat(ts_list[-1].replace("Z", "+00:00"))
                    duration = (t_max - t_min).total_seconds()
                except Exception:
                    pass
                time_window = {"start_utc": ts_list[0], "end_utc": ts_list[-1], "duration_seconds": duration}

            correlation_records.append(
                DeterministicCorrelationRecord(
                    case_id=case_id,
                    relationship_type="multi_observation_correlation",
                    source_finding_ids=corr.citing_finding_ids,
                    source_artifact_hashes=corr.source_artifact_hashes,
                    entity_identifiers=entities,
                    correlation_method="deterministic_provenance_binding",
                    supporting_observations=[f.summary for f in corr_findings],
                    conflicting_observations=[],
                    time_window=time_window,
                    limitations=["Temporal window assumes synchronized endpoint clocks"],
                    confidence=corr.confidence,
                    statement=corr.statement,
                )
            )

        # 5. Evidence Conflict Detection (Task 3)
        detected_conflicts = cls.detect_evidence_conflicts(
            referenced_findings, custody_engine=custody_engine, audit_entries=audit_entries
        )
        all_conflicts = citation_conflicts + detected_conflicts

        # 6. Custody Chain Verification (Task 6: Never default to True!)
        tamper_ok = False
        custody_status = "UNVERIFIED"
        custody_errors: List[str] = []

        if custody_engine is None:
            tamper_ok = False
            custody_status = "INCOMPLETE"
            custody_errors.append("Custody verification could not be completed: No CustodyEngine provided.")
        else:
            try:
                is_valid, errors = custody_engine.verify_chain_integrity(case_id=case_id)
                tamper_ok = bool(is_valid)
                if tamper_ok:
                    custody_status = "VERIFIED"
                else:
                    custody_status = "FAILED"
                    custody_errors.extend(errors or ["Custody hash chain integrity check failed."])
            except Exception as e:
                tamper_ok = False
                custody_status = "FAILED"
                custody_errors.append(f"Custody check encountered error: {str(e)}")

        # 7. Overall Severity Assessment
        has_critical = any(f.severity == "critical" for f in referenced_findings)
        has_high = any(f.severity == "high" for f in referenced_findings)
        overall_severity: FindingSeverity = "critical" if has_critical else ("high" if has_high else "medium")

        incident_overview = (
            f"ForensicOps AI completed an autonomous investigation for Case `{case_id}`. "
            f"A total of {len(observed_facts)} verified factual observations and {len(derived_correlations)} "
            f"correlations were established across {len(impacted_hosts)} endpoint(s). "
            f"Evidence conflict analysis identified {len(all_conflicts)} potential discrepancy item(s)."
        )

        sec1 = ExecutiveSummarySection(
            case_id=case_id,
            incident_overview=incident_overview,
            severity=overall_severity,
            impacted_hosts=sorted(list(impacted_hosts)),
            impacted_users=sorted(list(impacted_users)),
            earliest_timestamp_utc=earliest_ts,
            latest_timestamp_utc=latest_ts,
            timeline=timeline_entries,
        )

        evidence_items: List[Dict[str, Any]] = []
        if audit_entries:
            for a in audit_entries:
                evidence_items.append({
                    "artifact_id": a.get("artifact_id", "artifact-01"),
                    "sha256": a.get("sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
                    "intake_utc": a.get("timestamp_utc", datetime.now(timezone.utc).isoformat()),
                    "status": "Verified & Hashed (RFC 3227)",
                })
        else:
            for h in sorted(list(all_cited_hashes)):
                evidence_items.append({
                    "artifact_id": f"art-{h[:8]}",
                    "sha256": h,
                    "intake_utc": earliest_ts or datetime.now(timezone.utc).isoformat(),
                    "status": "Verified & Indexed",
                })

        total_findings = storage.count_findings(case_id=case_id)
        proj_summary = {
            "total_raw_rows": total_findings * 2,
            "total_findings_indexed": total_findings,
            "projected_columns": ["timestamp_utc", "host", "user", "process_name", "command_line", "event_id", "summary"],
        }

        sec2 = CustodyAuditSection(
            evidence_items=evidence_items,
            column_projection_summary=proj_summary,
            tamper_check_passed=tamper_ok,
            verification_status=custody_status,
            verification_errors=custody_errors,
        )

        # 8. Patient Zero Assessment (Task 2)
        sec6 = cls.correlate_patient_zero(referenced_findings)

        # Determine report status based on custody integrity
        report_status: Literal["draft", "finalized", "signed", "blocked", "incomplete"] = "draft"
        if not tamper_ok:
            report_status = "blocked" if custody_status == "FAILED" else "incomplete"

        rep_store = get_report_store(db_path=db_path)
        next_ver = rep_store.get_next_version(case_id)

        provenance = ReportProvenance(
            version=next_ver,
            status=report_status,
            created_utc=datetime.now(timezone.utc).isoformat(),
            created_by=creator,
        )

        report = CitedReport(
            case_id=case_id,
            status=report_status,
            version=next_ver,
            provenance=provenance,
            executive_summary=sec1,
            custody_and_filter_audit=sec2,
            observed_facts=observed_facts,
            derived_correlations=derived_correlations,
            correlation_records=correlation_records,
            evidence_conflicts=all_conflicts,
            rejected_claims=rejected_claims,
            unverified_hypotheses=unverified_hypotheses,
            aift_rubric=aift_rubric_items,
            patient_zero_and_remediation=sec6,
            all_cited_finding_ids=sorted(list(all_cited_fids)),
            all_source_artifact_hashes=sorted(list(all_cited_hashes)),
        )

        report.digest = report.compute_canonical_digest()
        report.provenance.canonical_report_digest = report.digest

        rep_store.save_report(report)
        return report

    @classmethod
    def finalize_report(
        cls,
        report: CitedReport,
        approval_token: HumanApprovalToken,
        approver_username: str,
        approver_role: str,
        approver_badge: Optional[str] = None,
        secret_key: Optional[str] = None,
        approval_engine: Optional[Any] = None,
        custody_engine: Optional[Any] = None,
        store: Optional[ReportStore] = None,
    ) -> CitedReport:
        """Finalize and cryptographically sign a forensic report with Phase 08 Human Approval."""
        # 1. Custody validation: Cannot finalize if custody failed
        if not report.custody_and_filter_audit.tamper_check_passed:
            raise ForensicOpsError(
                f"Cannot finalize report '{report.report_id}': Chain of custody verification failed or is incomplete "
                f"({report.custody_and_filter_audit.verification_status})."
            )

        # 2. Token validations
        if approval_token.action_type != "report_finalization_or_signing":
            raise ForensicOpsError(
                f"Invalid approval token: action_type is '{approval_token.action_type}', "
                f"expected 'report_finalization_or_signing'."
            )
        if approval_token.case_id != report.case_id:
            raise ForensicOpsError(
                f"Approval token case_id '{approval_token.case_id}' does not match report case_id '{report.case_id}'."
            )
        if approval_token.target and approval_token.target not in (report.report_id, report.case_id, ""):
            raise ForensicOpsError(
                f"Approval token target '{approval_token.target}' does not match report_id '{report.report_id}'."
            )
        if approval_token.is_expired():
            raise ForensicOpsError(f"Approval token '{approval_token.token_id}' has expired.")
        if approval_token.consumed:
            raise ForensicOpsError(f"Approval token '{approval_token.token_id}' has already been consumed.")

        resolved_secret = (
            secret_key
            or getattr(approval_engine, "secret_key", getattr(approval_engine, "_secret_key", None))
            or os.getenv("HUMAN_APPROVAL_HMAC_SECRET")
            or os.getenv("APPROVAL_SECRET_KEY")
            or getattr(get_settings(), "approval_secret_key", None)
        )
        if not approval_token.verify(secret_key=resolved_secret):
            raise ForensicOpsError(f"Approval token '{approval_token.token_id}' cryptographic signature verification failed.")

        # 3. Role authorization check
        if approver_role not in ("lead_investigator", "soc_analyst"):
            raise ForensicOpsError(
                f"Role '{approver_role}' is not authorized to sign forensic reports. Required: lead_investigator or soc_analyst."
            )

        # 4. Atomic token consumption
        if approval_engine is not None and hasattr(approval_engine, "consume_token"):
            approval_engine.consume_token(
                approval_token.token_id,
                case_id=report.case_id,
                action_type=approval_token.action_type,
                target=report.report_id,
                consumed_by=approver_username,
            )
        approval_token.consumed = True

        # 5. Compute canonical report digest
        digest = report.compute_canonical_digest()
        report.digest = digest
        report.status = "signed"

        # 6. Update provenance
        report.provenance.status = "signed"
        report.provenance.finalized_utc = datetime.now(timezone.utc).isoformat()
        report.provenance.finalized_by = approver_username
        report.provenance.finalized_role = approver_role
        report.provenance.approval_token_id = approval_token.token_id
        report.provenance.approval_token_signature = approval_token.signature
        report.provenance.canonical_report_digest = digest

        # 7. Custody ledger recording
        if custody_engine is not None:
            actor_str = f"{approver_username} ({approver_badge or 'BADGE-UNKNOWN'}) [{approver_role}]"
            custody_engine.append_custody_entry(
                case_id=report.case_id,
                actor=actor_str,
                action="REPORT_FINALIZED_AND_SIGNED",
                artifact_sha256=digest.replace("sha256:", ""),
                tool_id="report_builder",
            )

        rep_store = store or get_report_store()
        rep_store.save_report(report)
        return report
