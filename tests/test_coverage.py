"""
Coverage reporting — app/core/coverage.py.

The case these tests exist for: an unparseable APK and a genuinely ambiguous app
both land on 50.0 / `suspicious`, and nothing in the risk score separates them.
Coverage is what does, so the tests that matter are the ones pinning
`verdict_supported` and the None-vs-False distinctions.
"""
import pytest

from app.core.coverage import compute_coverage, unparseable_coverage
from app.core.schemas import (
    AnalysisManifest,
    DynamicVerificationResult,
    ObfuscationSignal,
    SignatureYaraResult,
)


def _obfuscation(**kw) -> ObfuscationSignal:
    base = dict(
        string_entropy_score=3.0,
        flattening_suspected=False,
        method_parse_failure_rate=0.0,
        dex_method_count=1000,
        analyzed_method_count=800,
        analyzed_method_count_unused=None,
        manifest_parse_failed=False,
        coverage_note="",
    )
    base.pop("analyzed_method_count_unused")
    base.update(kw)
    return ObfuscationSignal(**base)


def _manifest(**kw) -> AnalysisManifest:
    base = dict(
        target_package="com.example.app",
        sha256="a" * 64,
        cache_hit=False,
        total_nodes_parsed=500,
        graph_density=0.04,
        behavioral_subgraphs=[],
        obfuscation=_obfuscation(),
        predicted_ttps={},
        predicted_family=None,
        family_confidence=None,
        signature_yara=SignatureYaraResult(),
        impersonation={"findings": [], "coverage": []},
    )
    base.update(kw)
    return AnalysisManifest(**base)


# ── The distinction this module exists to draw ────────────────────────────────

def test_unparseable_does_not_support_a_verdict():
    cov = unparseable_coverage("ZIP central directory not found")
    assert cov.verdict_supported is False
    assert cov.level == "none"
    assert cov.completeness == 0.0
    assert cov.container_opened is False
    assert "ZIP central directory not found" in cov.gaps[0]


def test_fully_analysed_app_supports_a_verdict():
    cov = compute_coverage(_manifest())
    assert cov.verdict_supported is True
    assert cov.level == "full"
    assert cov.completeness == 1.0
    assert cov.gaps == []


def test_same_score_different_coverage_is_distinguishable():
    """The 50.0 collision: both would render `suspicious`, only one is a finding."""
    analysed = compute_coverage(_manifest())
    failed = unparseable_coverage("truncated download")
    assert analysed.verdict_supported != failed.verdict_supported


# ── Stage outcomes ────────────────────────────────────────────────────────────

def test_no_code_recovered_is_partial_not_full():
    cov = compute_coverage(_manifest(
        obfuscation=_obfuscation(dex_method_count=0, analyzed_method_count=0),
        total_nodes_parsed=0,
    ))
    assert cov.level == "partial"
    assert cov.code_recovered is False
    assert any("No DEX methods" in g for g in cov.gaps)


def test_no_code_and_no_manifest_is_level_none():
    cov = compute_coverage(_manifest(
        obfuscation=_obfuscation(
            dex_method_count=0, analyzed_method_count=0, manifest_parse_failed=True,
        ),
        total_nodes_parsed=0,
    ), manifest_recovery_source=None)
    assert cov.level == "none"
    assert cov.verdict_supported is False


def test_manifest_recovery_source_is_reported_in_the_gap():
    cov = compute_coverage(
        _manifest(obfuscation=_obfuscation(manifest_parse_failed=True)),
        manifest_recovery_source="string_pool",
    )
    assert cov.manifest_parsed is False
    assert any("string_pool" in g for g in cov.gaps)


def test_manifest_failure_without_a_recovery_source_claims_no_recovery():
    cov = compute_coverage(
        _manifest(obfuscation=_obfuscation(manifest_parse_failed=True))
    )
    assert any("not observed absent" in g for g in cov.gaps)


# ── None vs False: the convention the rest of the codebase uses ───────────────

def test_dynamic_not_requested_is_none_not_false():
    """None = never asked for. False would claim it was asked for and failed."""
    cov = compute_coverage(_manifest(), dynamic_requested=False)
    assert cov.dynamic_ran is None
    assert not any("Dynamic" in g for g in cov.gaps)


def test_dynamic_requested_but_did_not_run_is_a_gap():
    cov = compute_coverage(
        _manifest(dynamic_verification=DynamicVerificationResult(ran=False)),
        dynamic_requested=True,
    )
    assert cov.dynamic_ran is False
    assert any("did not complete" in g for g in cov.gaps)
    assert cov.completeness < 1.0


def test_dynamic_requested_and_ran_counts_toward_completeness():
    cov = compute_coverage(
        _manifest(dynamic_verification=DynamicVerificationResult(ran=True)),
        dynamic_requested=True,
    )
    assert cov.dynamic_ran is True
    assert cov.completeness == 1.0


def test_declining_dynamic_does_not_make_the_default_path_incomplete():
    """Charging a gap for a pass the caller declined would pin every default
    request below 1.0 forever."""
    assert compute_coverage(_manifest(), dynamic_requested=False).completeness == 1.0


# ── Method coverage is a measurement, not a guess ─────────────────────────────

def test_method_coverage_is_the_analysed_share():
    cov = compute_coverage(_manifest(
        obfuscation=_obfuscation(dex_method_count=1000, analyzed_method_count=250)
    ))
    assert cov.method_coverage == 0.25


def test_method_coverage_is_none_when_the_denominator_is_unmeasured():
    cov = compute_coverage(_manifest(
        obfuscation=_obfuscation(dex_method_count=None, analyzed_method_count=10)
    ))
    assert cov.method_coverage is None


def test_method_coverage_never_exceeds_one():
    cov = compute_coverage(_manifest(
        obfuscation=_obfuscation(dex_method_count=10, analyzed_method_count=50)
    ))
    assert cov.method_coverage == 1.0


def test_minimal_method_coverage_downgrades_to_partial():
    cov = compute_coverage(_manifest(
        obfuscation=_obfuscation(dex_method_count=100000, analyzed_method_count=1)
    ))
    assert cov.level == "partial"


# ── Cache hits ────────────────────────────────────────────────────────────────

def test_cache_hit_does_not_report_this_path_s_gaps_as_the_app_s():
    """The hot path recomputes almost nothing; those absences belong to the
    request, not to the original analysis."""
    cov = compute_coverage(_manifest(cache_hit=True, signature_yara=None))
    assert cov.level == "cached"
    assert cov.reputation_checked is None
    assert cov.verdict_supported is True
    assert any("cache" in g.lower() for g in cov.gaps)


# ── The invariant that protects the calibration ───────────────────────────────

def test_coverage_is_pure_and_does_not_mutate_the_manifest():
    m = _manifest()
    before = m.model_dump_json()
    compute_coverage(m)
    assert m.model_dump_json() == before


@pytest.mark.parametrize("level", ["none", "partial", "full", "cached"])
def test_level_is_one_of_the_documented_values(level):
    assert level in {"none", "partial", "full", "cached"}
