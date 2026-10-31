"""Deterministic Post-LLM Citation Validator (CitationGuard).

Standards:
- RFC 3227, NIST SP 800-86
- Non-Negotiable Anti-Hallucination Gate: Rejects any fabricated finding_id or source_artifact_hash.
- Cross-Case Contamination Shield: Prevents citations from bleeding across disparate cases.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field

from backend.app.core.exceptions import CitationValidationError
from backend.app.core.storage import ForensicStore
from backend.app.models.findings import CitedClaim, NodeGoalResult


class CitationValidationReport(BaseModel):
    """Detailed report of citation verification across node claims."""
    is_valid: bool
    verified_finding_ids: List[str] = Field(default_factory=list)
    missing_finding_ids: List[str] = Field(default_factory=list)
    missing_artifact_hashes: List[str] = Field(default_factory=list)
    mismatched_hashes: List[Dict[str, str]] = Field(default_factory=list)
    cross_case_violations: List[str] = Field(default_factory=list)
    rejection_reasons: List[str] = Field(default_factory=list)
    valid_claims: List[CitedClaim] = Field(default_factory=list)
    rejected_claims: List[CitedClaim] = Field(default_factory=list)
    sanitized_result: Optional[NodeGoalResult] = None


class CitationGuard:
    """Deterministic post-LLM validation gatekeeper."""

    def __init__(self, storage: ForensicStore):
        self._storage = storage

    def validate_claim(
        self,
        claim: CitedClaim,
        case_id: Optional[str] = None,
    ) -> Tuple[bool, List[str]]:
        """Validate a single CitedClaim against storage.

        Returns (is_valid, list_of_error_reasons).
        """
        reasons: List[str] = []

        is_factual = claim.claim_type in ("observed_fact", "derived_correlation")

        if is_factual:
            if not claim.citing_finding_ids:
                reasons.append(f"Claim '{claim.claim_id}' ({claim.claim_type}) has empty citing_finding_ids.")
            if not claim.source_artifact_hashes:
                reasons.append(f"Claim '{claim.claim_id}' ({claim.claim_type}) has empty source_artifact_hashes.")

        # Check all cited finding IDs
        for fid in claim.citing_finding_ids:
            finding = self._storage.get_finding(fid)
            if finding is None:
                reasons.append(f"Claim '{claim.claim_id}' cites non-existent finding_id '{fid}'.")
                continue

            if case_id and finding.case_id != case_id:
                reasons.append(
                    f"Claim '{claim.claim_id}' cites finding_id '{fid}' from foreign case '{finding.case_id}' (active case: '{case_id}')."
                )

            # Ensure the source artifact hash recorded for this finding is cited in the claim
            if finding.source_artifact_hash not in claim.source_artifact_hashes:
                reasons.append(
                    f"Finding '{fid}' requires source artifact hash '{finding.source_artifact_hash}', "
                    f"which was not cited in claim '{claim.claim_id}'."
                )

        # Check all declared artifact hashes
        if claim.source_artifact_hashes:
            _, verified_hashes = self._storage.check_citations_exist(
                finding_ids=claim.citing_finding_ids,
                artifact_hashes=claim.source_artifact_hashes,
                case_id=case_id,
            )
            for h in claim.source_artifact_hashes:
                if h not in verified_hashes:
                    reasons.append(f"Claim '{claim.claim_id}' cites unverified source_artifact_hash '{h}'.")

        return len(reasons) == 0, reasons

    def validate_node_result(
        self,
        result: NodeGoalResult,
        case_id: Optional[str] = None,
        strict: bool = True,
    ) -> CitationValidationReport:
        """Validate all claims in a NodeGoalResult against the forensic store.

        If strict=True, raises CitationValidationError on any verification failure.
        If strict=False, filters invalid claims and returns a sanitized result.
        """
        all_reasons: List[str] = []
        verified_fids: Set[str] = set()
        missing_fids: Set[str] = set()
        missing_hashes: Set[str] = set()
        mismatched_hashes: List[Dict[str, str]] = []
        cross_case_violations: List[str] = []

        valid_claims: List[CitedClaim] = []
        rejected_claims: List[CitedClaim] = []

        for claim in result.claims:
            is_valid, reasons = self.validate_claim(claim, case_id=case_id)
            if is_valid:
                valid_claims.append(claim)
                verified_fids.update(claim.citing_finding_ids)
            else:
                rejected_claims.append(claim)
                all_reasons.extend(reasons)
                for fid in claim.citing_finding_ids:
                    f = self._storage.get_finding(fid)
                    if f is None:
                        missing_fids.add(fid)
                    elif case_id and f.case_id != case_id:
                        cross_case_violations.append(fid)
                    elif f.source_artifact_hash not in claim.source_artifact_hashes:
                        mismatched_hashes.append({
                            "finding_id": fid,
                            "expected_hash": f.source_artifact_hash,
                            "cited_hashes": str(claim.source_artifact_hashes),
                        })

                for h in claim.source_artifact_hashes:
                    _, verified = self._storage.check_citations_exist([], [h], case_id=case_id)
                    if h not in verified:
                        missing_hashes.add(h)

        is_overall_valid = len(rejected_claims) == 0

        if not is_overall_valid and strict:
            formatted_reasons = "\n- ".join(all_reasons)
            raise CitationValidationError(
                f"CitationGuard rejected NodeGoalResult for node '{result.node_id}':\n- {formatted_reasons}"
            )

        sanitized_result: Optional[NodeGoalResult] = None
        if not is_overall_valid:
            new_status = "needs_more_data" if result.status == "success" else result.status
            new_summary = f"{result.summary} [Note: {len(rejected_claims)} unverified claim(s) suppressed by CitationGuard]"
            sanitized_result = NodeGoalResult(
                node_id=result.node_id,
                status=new_status,
                summary=new_summary,
                claims=valid_claims,
                extracted_pivots=result.extracted_pivots,
                recommended_next_actions=result.recommended_next_actions,
                confidence_score=result.confidence_score * (len(valid_claims) / max(len(result.claims), 1)),
            )
        else:
            sanitized_result = result

        return CitationValidationReport(
            is_valid=is_overall_valid,
            verified_finding_ids=sorted(list(verified_fids)),
            missing_finding_ids=sorted(list(missing_fids)),
            missing_artifact_hashes=sorted(list(missing_hashes)),
            mismatched_hashes=mismatched_hashes,
            cross_case_violations=cross_case_violations,
            rejection_reasons=all_reasons,
            valid_claims=valid_claims,
            rejected_claims=rejected_claims,
            sanitized_result=sanitized_result,
        )
