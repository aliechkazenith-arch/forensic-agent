"""Phase 15-A Regression Suite: Case Isolation, CitationGuard Downgrades & Controller Report.

Validates:
1. Strict case_id isolation in ForensicStore queries (findings, citations, hashes).
2. CitationGuard cross-case isolation preventing Case A findings from satisfying Case B claims.
3. CitationGuard downgrade_ungrounded_to_hypothesis transforming ungrounded claims into reviewed hypotheses.
4. InvestigationController compile_report end-to-end integration with CitationGuard and ReportBuilder.
"""
import pytest
from backend.app.core.storage import ForensicStore
from backend.app.core.citation_guard import CitationGuard
from backend.app.models.findings import ForensicFinding, CitedClaim, NodeGoalResult
from backend.app.agent.investigation_controller import InvestigationController
from backend.app.core.custody_engine import CustodyEngine


@pytest.fixture
def multi_case_store():
    store = ForensicStore(":memory:")
    findings_case_a = [
        ForensicFinding(
            finding_id="fnd-case-a-1",
            case_id="case-A",
            source_artifact_id="art-a-1",
            source_artifact_hash="hash-a-1" + "0" * 56,
            tool_id="dissect",
            artifact_type="evtx",
            category="authentication",
            host="HOST-ALPHA",
            user="alice",
            summary="Alice logon on Alpha",
        ),
        ForensicFinding(
            finding_id="fnd-case-a-2",
            case_id="case-A",
            source_artifact_id="art-a-2",
            source_artifact_hash="hash-a-2" + "0" * 56,
            tool_id="dissect",
            artifact_type="evtx",
            category="process_creation",
            host="HOST-ALPHA",
            user="alice",
            process_name="cmd.exe",
            summary="Alice cmd on Alpha",
        ),
    ]
    findings_case_b = [
        ForensicFinding(
            finding_id="fnd-case-b-1",
            case_id="case-B",
            source_artifact_id="art-b-1",
            source_artifact_hash="hash-b-1" + "0" * 56,
            tool_id="dissect",
            artifact_type="registry",
            category="persistence",
            host="HOST-BETA",
            user="bob",
            summary="Bob persistence on Beta",
        ),
    ]
    store.insert_findings(findings_case_a + findings_case_b)
    yield store
    store.close()


def test_case_isolation_queries(multi_case_store: ForensicStore):
    """Findings from Case A cannot be retrieved when querying Case B."""
    # 1. get_finding
    res_a = multi_case_store.get_finding("fnd-case-a-1", case_id="case-A")
    assert res_a is not None
    assert res_a.finding_id == "fnd-case-a-1"

    res_cross = multi_case_store.get_finding("fnd-case-a-1", case_id="case-B")
    assert res_cross is None

    # 2. get_findings_by_ids
    all_fids = ["fnd-case-a-1", "fnd-case-b-1"]
    b_only = multi_case_store.get_findings_by_ids(all_fids, case_id="case-B")
    assert len(b_only) == 1
    assert b_only[0].finding_id == "fnd-case-b-1"
    assert b_only[0].case_id == "case-B"

    # 3. check_citations_exist
    verified_fids, verified_hashes = multi_case_store.check_citations_exist(
        finding_ids=all_fids,
        artifact_hashes=["hash-a-1" + "0" * 56, "hash-b-1" + "0" * 56],
        case_id="case-B",
    )
    assert verified_fids == {"fnd-case-b-1"}
    assert verified_hashes == {"hash-b-1" + "0" * 56}


def test_citation_guard_cross_case_isolation(multi_case_store: ForensicStore):
    """CitationGuard rejects claims citing findings or artifact hashes from another case."""
    guard = CitationGuard(multi_case_store)

    # Claim in Case B citing finding from Case A
    leak_claim = CitedClaim(
        claim_type="observed_fact",
        statement="Host HOST-ALPHA recorded interactive logon for user alice",
        citing_finding_ids=["fnd-case-a-1"],
        source_artifact_hashes=["hash-a-1" + "0" * 56],
    )

    is_valid, reasons = guard.validate_claim(leak_claim, case_id="case-B")
    assert is_valid is False
    assert any("foreign case 'case-A'" in r for r in reasons)
    assert any("unverified source_artifact_hash" in r for r in reasons)


def test_citation_guard_downgrade_ungrounded_to_hypothesis(multi_case_store: ForensicStore):
    """Ungrounded claims can be downgraded to hypotheses in CitationGuard."""
    guard = CitationGuard(multi_case_store)

    ungrounded_claim = CitedClaim.model_construct(
        claim_id="claim-ungrounded",
        claim_type="observed_fact",
        statement="Attacker used mimikatz to dump hashes",
        citing_finding_ids=["fnd-nonexistent"],
        source_artifact_hashes=["hash-nonexistent" + "0" * 48],
        confidence=0.9,
    )

    result = NodeGoalResult(
        node_id="test_node",
        status="completed",
        summary="Analysis complete",
        claims=[ungrounded_claim],
    )

    report = guard.validate_node_result(
        result,
        case_id="case-A",
        strict=False,
        downgrade_ungrounded=True,
    )

    assert report.is_valid is False
    assert len(report.downgraded_claims) == 1
    downgraded = report.downgraded_claims[0]
    assert downgraded.claim_type == "hypothesis"
    assert downgraded.verification_status == "UNVERIFIED"
    assert downgraded.requires_analyst_review is True
    assert downgraded.confidence <= 0.40
    assert "Downgraded from observed_fact to hypothesis" in downgraded.review_notes

    # Sanitized result contains the downgraded claim as a hypothesis
    assert len(report.sanitized_result.claims) == 1
    assert report.sanitized_result.claims[0].claim_type == "hypothesis"


def test_investigation_controller_compile_report(multi_case_store: ForensicStore, tmp_path):
    """InvestigationController can compile verified report using CitationGuard and ReportBuilder."""
    custody = CustodyEngine(vault_root=tmp_path / "vault", case_id="case-A")
    # Register the source artifact in custody so it is verified physically
    sample_file = tmp_path / "evidence_a1.evtx"
    sample_file.write_bytes(b"evtx payload")
    custody.ingest_artifact(
        case_id="case-A",
        source_path=sample_file,
        artifact_type="evtx",
        actor="alice",
    )
    # Get registered artifact
    arts = custody.get_artifacts("case-A")
    art = arts[0]

    # Insert a finding tied to this real registered artifact
    real_finding = ForensicFinding(
        finding_id="fnd-real-a-1",
        case_id="case-A",
        source_artifact_id=art.artifact_id,
        source_artifact_hash=art.sha256,
        tool_id="dissect",
        artifact_type="evtx",
        category="authentication",
        host="HOST-ALPHA",
        user="alice",
        summary="Interactive logon by alice on HOST-ALPHA",
    )
    multi_case_store.insert_findings([real_finding])

    ctrl = InvestigationController(
        case_id="case-A",
        investigator="alice",
        storage=multi_case_store,
        custody_engine=custody,
    )
    ctrl.initialize()

    report = ctrl.compile_report(strict_citations=False)
    assert report is not None
    assert report.case_id == "case-A"
    assert len(report.observed_facts) >= 1
    for fact in report.observed_facts:
        for fid in fact.citing_finding_ids:
            f = multi_case_store.get_finding(fid)
            assert f.case_id == "case-A"
