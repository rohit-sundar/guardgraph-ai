"""
Analysis coverage — how much of the APK the analyser was actually able to read.

This exists because the risk score alone cannot distinguish two very different
states that produce the same number. An unparseable APK returns
UNPARSEABLE_RISK_SCORE (50.0, `suspicious`) with every component None; a real
app that scores 50.0 got there through seven components that all fired. Same
number, same band, opposite epistemic status. Coverage is what separates
"we analysed this thoroughly and it is genuinely ambiguous" from "we never got
the lid open".

Everything here is an OBSERVED FACT, never an estimate. Did the manifest parse?
How many of the DEX's methods did the CFG stage actually analyse? Did the
dynamic pass run? Those are countable and cannot be wrong. This module
deliberately does NOT produce a probabilistic confidence ("73% sure this is
malicious") — that would be an inferred claim requiring calibration against
labelled ground truth this project does not have, and it would be the one
number in the system not backed by a measurement.

**Coverage does not affect the risk score.** It is reported alongside it and
nothing reads it back into scoring. The band boundaries in app/reports/scoring.py
were calibrated over a 991-APK corpus; feeding a coverage term into the total
would invalidate that calibration and every figure derived from it. If a future
change wants coverage to move the score, that change must re-derive the bands
with scripts/score_corpus.py first.

`verdict_supported` is the field a caller should branch on: False means the
band is an artefact of the analysis failing, not a finding about the app.
"""
from typing import Optional

from app.core.schemas import AnalysisCoverage, AnalysisManifest


# Share of DEX methods below which the CFG stage is treated as having covered
# too little of the app for its silence to mean anything. Not a tuned constant —
# a reported threshold, kept low so it only fires on genuine collapse rather
# than on cfg.py's ordinary relevance pre-filter, which legitimately analyses a
# small fraction of a large app.
MINIMAL_METHOD_COVERAGE = 0.01


def compute_coverage(
    manifest: AnalysisManifest,
    dynamic_requested: bool = False,
    manifest_recovery_source: Optional[str] = None,
) -> AnalysisCoverage:
    """
    Derive coverage from what the manifest already records. Pure function of its
    input — it observes, it does not re-run anything.

    `dynamic_requested` distinguishes "Phase 8 was asked for and did not
    complete" (a real gap) from "Phase 8 was never asked for" (a choice, and the
    default). The manifest cannot tell these apart on its own: both leave
    `dynamic_verification` unhelpful, one as None and one as ran=False.

    `manifest_recovery_source` is passed in rather than read off the manifest
    because it lives on IngestionResult and never reaches AnalysisManifest.
    Callers without an IngestionResult to hand (the historical-reconstruction
    path) leave it None, and the gap text then says only that the parse failed —
    which is what is actually known there.
    """
    obf = manifest.obfuscation
    gaps: list[str] = []

    # Cache hits recompute almost nothing, so most stages below would read as
    # gaps that belong to this path rather than to the original analysis. Report
    # that honestly instead of manufacturing a coverage figure from fields the
    # hot path never populated — the same convention RiskScoreBreakdown uses,
    # where None means "not recomputed here", not "looked and found nothing".
    if manifest.cache_hit:
        return AnalysisCoverage(
            container_opened=True,
            manifest_parsed=not obf.manifest_parse_failed,
            code_recovered=(obf.dex_method_count or 0) > 0,
            # Unknown, not False: total_nodes_parsed is not persisted, so a cache
            # hit reads 0 for a sample whose original analysis built a full graph.
            cfg_built=None,
            reputation_checked=None,
            identity_checked=manifest.impersonation is not None,
            dynamic_ran=None,
            dex_method_count=obf.dex_method_count,
            analyzed_method_count=obf.analyzed_method_count,
            method_coverage=_method_coverage(obf.dex_method_count,
                                             obf.analyzed_method_count),
            method_parse_failure_rate=obf.method_parse_failure_rate,
            completeness=1.0,
            level="cached",
            gaps=["Served from cache - stage coverage reflects the original "
                  "analysis, not this request."],
            verdict_supported=True,
        )

    # ── Cold path: every stage below is observed on this run ──────────────────
    manifest_parsed = not obf.manifest_parse_failed
    dex_methods = obf.dex_method_count or 0
    analyzed = obf.analyzed_method_count or 0
    code_recovered = dex_methods > 0
    cfg_built = manifest.total_nodes_parsed > 0
    reputation_checked = manifest.signature_yara is not None
    identity_checked = manifest.impersonation is not None

    dynamic_ran: Optional[bool] = None
    if dynamic_requested:
        dynamic_ran = bool(
            manifest.dynamic_verification and manifest.dynamic_verification.ran
        )

    if not manifest_parsed:
        if manifest_recovery_source:
            gaps.append(
                f"AndroidManifest.xml failed to parse; fields recovered via "
                f"{manifest_recovery_source} fallback."
            )
        else:
            gaps.append(
                "AndroidManifest.xml failed to parse - permissions, components "
                "and signing identity were not observed, not observed absent."
            )
    if not code_recovered:
        gaps.append("No DEX methods were recovered - nothing to match anchors against.")
    elif not cfg_built:
        gaps.append("Code was recovered but no control-flow graph was built.")
    if obf.method_parse_failure_rate > 0:
        gaps.append(
            f"{obf.method_parse_failure_rate:.0%} of methods failed CFG parsing."
        )
    if not reputation_checked:
        gaps.append("Signature/YARA scanning did not run.")
    if not identity_checked:
        gaps.append("Brand-impersonation checks did not run.")
    if dynamic_requested and not dynamic_ran:
        gaps.append(
            "Dynamic verification was requested but did not complete - this is "
            "not the same as observing no malicious runtime behaviour."
        )

    # Stages that ran, over stages that were applicable. Dynamic counts only when
    # it was asked for; charging a gap for a pass the caller declined would make
    # the default path permanently incomplete.
    stages = [manifest_parsed, code_recovered, cfg_built,
              reputation_checked, identity_checked]
    if dynamic_requested:
        stages.append(bool(dynamic_ran))
    completeness = sum(1 for s in stages if s) / len(stages)

    method_coverage = _method_coverage(dex_methods or None, analyzed or None)

    # `none` is the case this module exists for: the container yielded no code
    # and no manifest, so every quiet component is quiet because nothing was
    # read. A band computed on that is an artefact of the failure.
    if not code_recovered and not manifest_parsed:
        level = "none"
    elif (
        not code_recovered
        or not cfg_built
        or (method_coverage is not None and method_coverage < MINIMAL_METHOD_COVERAGE)
        or not manifest_parsed
    ):
        level = "partial"
    else:
        level = "full"

    return AnalysisCoverage(
        container_opened=True,
        manifest_parsed=manifest_parsed,
        code_recovered=code_recovered,
        cfg_built=cfg_built,
        reputation_checked=reputation_checked,
        identity_checked=identity_checked,
        dynamic_ran=dynamic_ran,
        dex_method_count=obf.dex_method_count,
        analyzed_method_count=obf.analyzed_method_count,
        method_coverage=method_coverage,
        method_parse_failure_rate=obf.method_parse_failure_rate,
        completeness=round(completeness, 3),
        level=level,
        gaps=gaps,
        verdict_supported=level != "none",
    )


def unparseable_coverage(reason: str) -> AnalysisCoverage:
    """
    Coverage for the path where the APK could not be opened at all
    (routes.UNPARSEABLE_RISK_SCORE). Constructed directly rather than derived,
    because there is no manifest to derive from — every stage is a known
    negative, not an unknown.
    """
    return AnalysisCoverage(
        container_opened=False,
        manifest_parsed=False,
        code_recovered=False,
        cfg_built=False,
        reputation_checked=False,
        identity_checked=False,
        dynamic_ran=None,
        dex_method_count=None,
        analyzed_method_count=None,
        method_coverage=None,
        method_parse_failure_rate=1.0,
        completeness=0.0,
        level="none",
        gaps=[f"The APK could not be opened: {reason}"],
        verdict_supported=False,
    )


def _method_coverage(dex_methods: Optional[int],
                     analyzed: Optional[int]) -> Optional[float]:
    """Share of the DEX's methods the CFG stage analysed. None when either count
    is unmeasured — a ratio over an unknown denominator is not a measurement."""
    if not dex_methods or analyzed is None:
        return None
    return round(min(analyzed / dex_methods, 1.0), 4)
