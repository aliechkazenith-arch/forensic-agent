"""Deterministic Post-LLM Citation Validator (CitationGuard).

Standards:
- RFC 3227, NIST SP 800-86
- Non-Negotiable Anti-Hallucination Gate: Rejects any fabricated finding_id or source_artifact_hash.
- Cross-Case Contamination Shield: Prevents citations from bleeding across disparate cases.
"""
from __future__ import annotations

import re
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
    downgraded_claims: List[CitedClaim] = Field(default_factory=list)
    claims_needing_review: List[CitedClaim] = Field(default_factory=list)
    sanitized_result: Optional[NodeGoalResult] = None


class CitationGuard:
    """Deterministic post-LLM validation gatekeeper."""

    def __init__(self, storage: ForensicStore, custody_engine: Optional[Any] = None):
        self._storage = storage
        self._custody_engine = custody_engine

    @staticmethod
    def downgrade_claim_to_hypothesis(
        claim: CitedClaim,
        reasons: Optional[List[str]] = None,
    ) -> CitedClaim:
        """Downgrade an ungrounded or unverifiable factual claim to an unverified hypothesis.

        Preserves investigative visibility while stripping false factual authority.
        """
        err_msg = "; ".join(reasons) if reasons else "Unverified citations or loose keyword support"
        return claim.model_copy(
            update={
                "claim_type": "hypothesis",
                "verification_status": "UNVERIFIED",
                "requires_analyst_review": True,
                "review_notes": f"Downgraded from {claim.claim_type} to hypothesis: {err_msg}",
                "confidence": min(getattr(claim, "confidence", 1.0), 0.40),
            }
        )

    def validate_claim(
        self,
        claim: CitedClaim,
        case_id: Optional[str] = None,
    ) -> Tuple[bool, List[str]]:
        """Validate a single CitedClaim against storage and provenance.

        Returns (is_valid, list_of_error_reasons).
        """
        reasons: List[str] = []

        is_factual = claim.claim_type in ("observed_fact", "derived_fact", "derived_correlation")

        if is_factual:
            if not claim.citing_finding_ids:
                reasons.append(f"Claim '{claim.claim_id}' ({claim.claim_type}) has empty citing_finding_ids.")
            if not claim.source_artifact_hashes:
                reasons.append(f"Claim '{claim.claim_id}' ({claim.claim_type}) has empty source_artifact_hashes.")

        if claim.claim_type == "derived_correlation":
            unique_fids = set(claim.citing_finding_ids)
            if len(unique_fids) < 2:
                reasons.append(
                    f"Claim '{claim.claim_id}' (derived_correlation) requires at least two distinct citing finding IDs, got {len(unique_fids)}."
                )

        has_strong_structural_grounding = False
        has_loose_keyword_overlap = False

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
                continue

            # Ensure the source artifact hash recorded for this finding is cited in the claim
            if finding.source_artifact_hash not in claim.source_artifact_hashes:
                reasons.append(
                    f"Finding '{fid}' requires source artifact hash '{finding.source_artifact_hash}', "
                    f"which was not cited in claim '{claim.claim_id}'."
                )

            # Verify physical existence of artifact file on disk if custody engine is configured
            if self._custody_engine is not None:
                try:
                    artifact = self._custody_engine.get_artifact(finding.source_artifact_id, case_id=case_id)
                    if artifact is None:
                        # Try lookup by hash
                        artifact_path = getattr(self._custody_engine, "blobs_dir", None)
                        if artifact_path:
                            blob_file = artifact_path / finding.source_artifact_hash[:2] / f"{finding.source_artifact_hash}.blob"
                            if not blob_file.exists():
                                reasons.append(
                                    f"Source artifact blob '{finding.source_artifact_hash}' does not exist on disk."
                                )
                    else:
                        is_ok, disk_err = self._custody_engine.verify_artifact_file(artifact)
                        if not is_ok:
                            reasons.append(
                                f"Source artifact for finding '{fid}' failed disk integrity check: {disk_err}"
                            )
                except Exception:
                    pass

            # Grounding and Semantic Support Check
            if is_factual:
                stmt_lower = claim.statement.lower()
                why_lower = (claim.why_it_matters or "").lower()
                combined_text = f"{stmt_lower} {why_lower}"

                # 1. Strong structural entity candidates
                strong_candidates: Set[str] = set()
                if finding.host and len(finding.host.strip()) >= 3:
                    strong_candidates.add(finding.host.lower().strip())
                if finding.user and len(finding.user.strip()) >= 3:
                    strong_candidates.add(finding.user.lower().strip())
                if finding.process_name and len(finding.process_name.strip()) >= 3:
                    strong_candidates.add(finding.process_name.lower().strip())
                if finding.event_id and len(str(finding.event_id).strip()) >= 3:
                    strong_candidates.add(str(finding.event_id).strip())
                if finding.command_line:
                    for token in re.findall(r"[A-Za-z0-9_\-\.]{4,}", finding.command_line):
                        strong_candidates.add(token.lower())

                # 2. General summary/category tokens
                summary_candidates: Set[str] = set()
                if finding.category and len(finding.category.strip()) >= 3:
                    summary_candidates.add(finding.category.lower().strip())
                if finding.summary:
                    stop_words = {
                        "this", "that", "with", "from", "were", "been", "have", "what",
                        "when", "where", "which", "into", "their", "there", "then", "some",
                        "about", "event", "detected", "artifact", "activity", "system"
                    }
                    for word in re.findall(r"[A-Za-z0-9_\-\.]{4,}", finding.summary):
                        w = word.lower()
                        if w not in stop_words and not w.isdigit():
                            summary_candidates.add(w)

                strong_match = any(c in combined_text for c in strong_candidates)
                summary_match = any(c in combined_text for c in summary_candidates)

                if strong_match:
                    has_strong_structural_grounding = True
                elif summary_match:
                    has_loose_keyword_overlap = True
                else:
                    reasons.append(
                        f"Claim '{claim.claim_id}' statement has no semantic entity or keyword overlap with cited finding '{fid}'."
                    )

        # Update claim verification status based on structural provenance vs loose keywords
        if is_factual and len(reasons) == 0:
            if has_strong_structural_grounding:
                claim.verification_status = "VERIFIED"
                claim.requires_analyst_review = False
            elif has_loose_keyword_overlap:
                # Substring match alone is not proof of semantic support: require analyst review
                claim.verification_status = "NEEDS_REVIEW"
                claim.requires_analyst_review = True
                claim.review_notes = (
                    "Semantic correlation supported only by loose keyword overlap; requires analyst review."
                )
            else:
                claim.verification_status = "UNVERIFIED"

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
        downgrade_ungrounded: bool = False,
    ) -> CitationValidationReport:
        """Validate all claims in a NodeGoalResult against the forensic store.

        If strict=True, raises CitationValidationError on any verification failure.
        If strict=False:
            - If downgrade_ungrounded=True, downgrades unverifiable factual claims to hypotheses.
            - If downgrade_ungrounded=False, filters invalid claims and returns a sanitized result.
        """
        all_reasons: List[str] = []
        verified_fids: Set[str] = set()
        missing_fids: Set[str] = set()
        missing_hashes: Set[str] = set()
        mismatched_hashes: List[Dict[str, str]] = []
        cross_case_violations: List[str] = []

        valid_claims: List[CitedClaim] = []
        rejected_claims: List[CitedClaim] = []
        downgraded_claims: List[CitedClaim] = []
        claims_needing_review: List[CitedClaim] = []

        for claim in result.claims:
            is_valid, reasons = self.validate_claim(claim, case_id=case_id)
            if is_valid:
                valid_claims.append(claim)
                if claim.requires_analyst_review:
                    claims_needing_review.append(claim)
                verified_fids.update(claim.citing_finding_ids)
            else:
                claim.verification_status = "REJECTED"
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

                if downgrade_ungrounded and not strict:
                    downgraded = self.downgrade_claim_to_hypothesis(claim, reasons)
                    downgraded_claims.append(downgraded)
                    valid_claims.append(downgraded)
                    claims_needing_review.append(downgraded)

        is_overall_valid = len(rejected_claims) == 0

        if not is_overall_valid and strict:
            formatted_reasons = "\n- ".join(all_reasons)
            raise CitationValidationError(
                f"CitationGuard rejected NodeGoalResult for node '{result.node_id}':\n- {formatted_reasons}"
            )

        sanitized_result: Optional[NodeGoalResult] = None
        if not is_overall_valid:
            new_status = "needs_more_data" if result.status in ("success", "completed") else result.status
            if downgraded_claims:
                new_summary = f"{result.summary} [Note: {len(downgraded_claims)} unverified claim(s) downgraded to hypotheses by CitationGuard]"
            else:
                new_summary = f"{result.summary} [Note: {len(rejected_claims)} unverified claim(s) suppressed by CitationGuard]"
            calibrated_score = round(
                result.confidence_score * (len(valid_claims) / max(len(result.claims), 1)), 2
            )
            sanitized_result = NodeGoalResult(
                node_id=result.node_id,
                status=new_status,
                summary=new_summary,
                claims=valid_claims,
                extracted_pivots=result.extracted_pivots,
                recommended_next_actions=result.recommended_next_actions,
                confidence_score=calibrated_score,
            )
        elif claims_needing_review:
            # Calibrate confidence score when analyst review is required
            review_ratio = len(claims_needing_review) / max(len(result.claims), 1)
            calibrated_score = round(max(0.0, result.confidence_score * (1.0 - 0.3 * review_ratio)), 2)
            new_summary = f"{result.summary} [Note: {len(claims_needing_review)} claim(s) require analyst review]"
            sanitized_result = NodeGoalResult(
                node_id=result.node_id,
                status=result.status,
                summary=new_summary,
                claims=valid_claims,
                extracted_pivots=result.extracted_pivots,
                recommended_next_actions=result.recommended_next_actions + [
                    f"Perform manual analyst review on {len(claims_needing_review)} ungrounded claim(s)."
                ],
                confidence_score=calibrated_score,
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
            downgraded_claims=downgraded_claims,
            claims_needing_review=claims_needing_review,
            sanitized_result=sanitized_result,
        )
