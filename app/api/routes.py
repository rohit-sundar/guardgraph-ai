"""
Main /analyze endpoint. Orchestrates the full cold/hot path pipeline:

  upload -> hash -> cache lookup (hot path) OR
  ingest -> CFG/ACFG -> anchor detection -> topology -> obfuscation ->
  classify -> score -> GraphRAG report (cold path)

This is intentionally synchronous for the prototype — no Celery/queue.
A cold-path analysis on a real APK will take several seconds; that's
acceptable for a demo. Do not "optimize" this before it's needed.

Changes vs. original skeleton:
- §9.1: hot path now truly short-circuits before build_all_method_cfgs.
- §9.2: predicted_ttps derived from FAMILY_TO_TTPS bridge, not raw family names.
- §9.3: matched_anchor_behaviors passed to compute_risk_score directly.
- §9.4: graph_density now computed as mean per-method density (not global sum).
- §9.5/9.6: method_parse_failure_rate threaded from cfg.py → obfuscation signal.
- §9.7: subgraph_size_ratio recorded per BehavioralSubgraph for tuning data.
- The TTP classifier only votes when the analysis actually observed something —
  it was trained without a benign class and answers confidently regardless.
"""
import os
import shutil
import tempfile
import uuid

from fastapi import APIRouter, UploadFile, File, HTTPException
from loguru import logger

from app.graph.cache import lookup_signature, store_signature, find_related_samples, get_threat_landscape
from app.graph.ontology import get_technique_context
from app.reports.scoring import compute_risk_score, _band_for
from app.core.config import settings
from app.core.schemas import AnalysisManifest, AnalysisReport, ObfuscationSignal, RiskScoreBreakdown, SignatureYaraResult

router = APIRouter()


def _build_ttp_context(predicted_ttps: dict[str, float]) -> list[dict]:
    """
    Merges predicted_ttps (technique_id -> probability) with MITRE ATT&CK Mobile
    ontology facts (name/tactic/description) via the same get_technique_context()
    GraphRAG grounds its narrative in — so the UI can never show a technique name
    the LLM wasn't also given. Sorted by probability descending.
    """
    if not predicted_ttps:
        return []
    context = get_technique_context(list(predicted_ttps.keys()))
    rows = [
        {**ctx, "probability": predicted_ttps.get(ctx["technique_id"], 0.0)}
        for ctx in context
    ]
    rows.sort(key=lambda r: r["probability"], reverse=True)
    return rows

# Score assigned when the APK cannot be parsed at all. Deliberately mid-band
# ("suspicious") rather than 0: a file that defeats Androguard's AXML parser or
# carries a corrupted ZIP central directory is usually doing so on purpose, and
# reporting "low" on an anti-analysis sample is the worse error. It is not scored
# higher either, because nothing was actually observed — no anchors, no
# permissions, no IoCs. The band says "look at this by hand", which is the truth.
# Still true with the `medium` band in between `low` and `suspicious`
# (scoring.BAND_MEDIUM_CEILING = 40.0): 50.0 sits above it, so this constant keeps
# reading "suspicious", not "medium" — pinned by
# test_unparseable_score_still_reads_suspicious.
UNPARSEABLE_RISK_SCORE = 50.0


@router.get("/graph/landscape")
async def graph_landscape(limit: int = 30):
    """
    Cytoscape-ready snapshot of the whole correlation graph (Sample/
    MalwareFamily/Technique/C2Indicator/Certificate) for the UI's "Threat
    Landscape" tab — not tied to any single analysis run.
    """
    return get_threat_landscape(limit=limit)


@router.post("/analyze", response_model=AnalysisReport)
async def analyze(file: UploadFile = File(...)):
    if not file.filename.endswith(".apk"):
        raise HTTPException(400, "Only .apk files are supported in this prototype.")

    tmp_dir = tempfile.mkdtemp()
    tmp_path = os.path.join(tmp_dir, f"{uuid.uuid4()}.apk")

    try:
        content = await file.read()
        with open(tmp_path, "wb") as f:
            f.write(content)

        try:
            result = _run_analysis(tmp_path)
        except HTTPException:
            raise
        except Exception as exc:
            logger.error(f"Unparseable APK fallback triggered: {exc}")
            result = _unparseable_report(tmp_path, exc)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    return result


@router.post("/analyze_sample", response_model=AnalysisReport)
async def analyze_sample():
    sample_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "guardgraph_test", "guardgraph_test.apk"))
    if not os.path.exists(sample_path):
        raise HTTPException(404, f"Sample file not found at {sample_path}")
    return _run_analysis(sample_path)


def _unparseable_report(filepath: str, exc: BaseException) -> AnalysisReport:
    """
    Builds the verdict returned when static analysis cannot complete.

    The SHA-256 is recomputed from the raw bytes — it needs no parsing and is the
    one fact still available, so the analyst can pivot to threat intel on the hash
    even though nothing was extracted from the file. The sample is NOT cached: a
    parse failure is a property of this analyzer, not a verdict worth replaying on
    the hot path after the underlying cause is fixed.
    """
    from app.analysis.ingest import compute_sha256
    from app.analysis.failure_diagnostics import probable_cause

    try:
        sha256 = compute_sha256(filepath)
    except Exception:  # unreadable temp file — nothing left to report on
        sha256 = ""

    label, explanation = probable_cause(exc)
    raw_reason = f"{type(exc).__name__}: {exc}"
    obfuscation = ObfuscationSignal(
        string_entropy_score=0.0,
        flattening_suspected=False,
        flattening_outlier_nodes=[],
        reflection_call_count=0,
        unresolved_reflection_targets=0,
        method_parse_failure_rate=1.0,  # nothing parsed — 100% of the app is a gap
        coverage_note=(
            f"static analysis aborted — probable cause: {label}. {explanation} "
            f"(raw error: {raw_reason})"
        ),
    )
    manifest = AnalysisManifest(
        target_package=None,
        sha256=sha256,
        cache_hit=False,
        total_nodes_parsed=0,
        graph_density=0.0,
        behavioral_subgraphs=[],
        obfuscation=obfuscation,
        predicted_ttps={},
        predicted_family=None,
        family_confidence=None,
        signature_yara=None,
    )
    risk_score = RiskScoreBreakdown(
        # Every component is None, not 0.0 — the same distinction the hot path
        # draws. Nothing was computed; asserting "we looked and found nothing"
        # about a file we could not open would be a lie.
        classifier_confidence_component=None,
        permission_api_component=None,
        ttp_severity_component=None,
        forensic_anchor_component=None,
        obfuscation_component=None,
        reputation_component=None,
        ioc_component=None,
        total_score=UNPARSEABLE_RISK_SCORE,
        verdict_band=_band_for(UNPARSEABLE_RISK_SCORE),
        zero_day_indicator=False,
    )

    # coverage_note (above) already carries the probable-cause explanation and
    # raw error, and generate_report's own limitations list leads with it —
    # these two just add framing that isn't in the coverage note itself.
    limitations = [
        "ANALYSIS INCOMPLETE: the APK could not be parsed, so no permissions, "
        "forensic anchors, IoCs or TTPs were extracted. Every field in this "
        "manifest is empty because nothing was observed, not because nothing "
        "is there.",
        f"Score fixed at {UNPARSEABLE_RISK_SCORE} — not derived from evidence.",
    ]

    # Still run the LLM report instead of a hardcoded placeholder — the
    # grounding prompt's "say not observed, don't invent evidence" rule
    # applies just as well to an empty manifest as a full one, and an
    # analyst gets a written explanation of what's known and why instead of
    # a dead end. run_phase7_reporting already has its own fallback if
    # Ollama itself is unreachable, so this never raises.
    from app.core.pipeline import AnalysisPipeline
    narrative, report_limitations = AnalysisPipeline.run_phase7_reporting(manifest, risk_score)
    limitations = limitations + report_limitations

    return AnalysisReport(
        manifest=manifest,
        risk_score=risk_score,
        narrative_report=narrative,
        limitations=limitations,
    )


from app.core.pipeline import (
    AnalysisPipeline,
    has_deterministic_evidence,
    NO_CLASSIFIER_EVIDENCE_NOTE,
)

def _run_analysis(filepath: str) -> AnalysisReport:
    # --- Phase 1: Ingestion & Metadata (+ Android malware static enrichments) ---
    ingestion, apk_obj, dvm, analysis_obj, yara_targets = (
        AnalysisPipeline.run_phase1_ingestion(filepath)
    )

    # --- Hot path: cache lookup ---
    cached = lookup_signature(ingestion.sha256)
    cache_hit = cached is not None

    if cache_hit:
        # A cache hit means "we already reached a verdict on this SHA-256" —
        # return that verdict, not one recomputed from emptied inputs. A prior
        # version called compute_risk_score() with predicted_ttps={}, no
        # anchors and no obfuscation signal, so 81.65 of an 86.14 "malicious"
        # score was discarded and the hot path answered "low" for known-bad
        # malware — while the *cached narrative in the same response* still
        # said 86.14.
        cached_score = cached.get("base_score")
        cached_ttps = cached.get("ttps") or {}
        total_score = cached_score if cached_score is not None else 0.0

        # Reconstruct risk score — use cached component breakdown if available
        rc = cached.get("risk_components") or {}
        risk_score = RiskScoreBreakdown(
            classifier_confidence_component=rc.get("classifier_confidence_component"),
            permission_api_component=rc.get("permission_api_component"),
            ttp_severity_component=rc.get("ttp_severity_component"),
            forensic_anchor_component=rc.get("forensic_anchor_component"),
            obfuscation_component=rc.get("obfuscation_component"),
            reputation_component=rc.get("reputation_component"),
            ioc_component=rc.get("ioc_component"),
            total_score=total_score,
            verdict_band=_band_for(total_score),
            zero_day_indicator=rc.get("zero_day_indicator", False),
        )

        # Reconstruct signature_yara from cache if available
        cached_sig_yara_data = cached.get("signature_yara_data")
        if cached_sig_yara_data:
            cached_sig_yara = SignatureYaraResult(**cached_sig_yara_data)
        else:
            cached_sig_yara = None

        # Reconstruct obfuscation from cache if available
        cached_obf_data = cached.get("obfuscation_data")
        if cached_obf_data:
            obfuscation = ObfuscationSignal(**cached_obf_data)
        else:
            obfuscation = _empty_obfuscation_signal()

        # Use cached permissions, falling back to ingestion
        cached_permissions = cached.get("permissions") or ingestion.permissions

        manifest = AnalysisManifest(
            target_package=ingestion.package_name,
            sha256=ingestion.sha256,
            cache_hit=True,
            total_nodes_parsed=0,
            graph_density=0.0,
            behavioral_subgraphs=[],
            obfuscation=obfuscation,
            predicted_ttps=cached_ttps,
            predicted_family=cached.get("family"),
            family_confidence=None,
            ttp_context=_build_ttp_context(cached_ttps),
            related_samples=find_related_samples(
                list(cached_ttps.keys()), ingestion.c2_indicators,
                exclude_sha256=ingestion.sha256,
                cert_thumbprint=ingestion.cert_thumbprint,
            ),
            signature_yara=cached_sig_yara,
            permissions=cached_permissions,
            c2_indicators=ingestion.c2_indicators,
            cert_anomalies=ingestion.cert_anomalies,
            permission_matrix_flags=ingestion.permission_matrix_flags,
            secondary_dex_count=ingestion.secondary_dex_count,
            accessibility_flags=ingestion.accessibility_flags,
            exported_risks=ingestion.exported_risks,
            payload_assets=ingestion.payload_assets,
            dropper_signals=ingestion.dropper_signals,
        )
        narrative = cached.get("narrative", "")
        limitations = cached.get("limitations", [])

        if cached_score is None:
            limitations = limitations + ["cache hit had no stored score — reporting 0/low"]
        if not narrative:
            narrative = "[Narrative not found in cache. Cached score only.]"
            limitations = limitations + ["analysis skipped — known sample (cache hit)"]

        return AnalysisReport(
            manifest=manifest,
            risk_score=risk_score,
            narrative_report=narrative,
            limitations=limitations,
        )

    # --- Phase 1.5: Signature Detection & YARA (APK + uncompressed DEX/assets) ---
    sig_yara = AnalysisPipeline.run_phase1b_signature_yara(
        filepath, ingestion, yara_targets=yara_targets
    )

    # --- Phase 2: Graph Representation ---
    cfgs, parse_failure_rate = AnalysisPipeline.run_phase2_graph_construction(analysis_obj)

    # --- Phase 3: Forensic Matching & Subgraph Extraction ---
    all_matches, behavioral_subgraphs, all_strings = AnalysisPipeline.run_phase3_forensic_matching(cfgs, ingestion)

    # Merge C2 IoCs found in DEX string literals into ingestion
    ingestion = AnalysisPipeline.merge_c2_from_strings(ingestion, all_strings)

    # --- Phase 3.5: Reverse-Engineering Deep Dive (crypto/DCL/WebView/native) ---
    resolved_crypto, resolved_dcl, resolved_webview, resolved_native = (
        AnalysisPipeline.run_phase3b_re_deepdive(cfgs, ingestion, apk_obj=apk_obj, analysis_obj=analysis_obj)
    )

    # --- Phase 4: Feature Engineering (family 35-vec + multi-label TTP 181-vec) ---
    obfuscation, feature_vector, ttp_feature_vector, mean_density, total_nodes = (
        AnalysisPipeline.run_phase4_feature_engineering(
            ingestion, cfgs, all_matches, behavioral_subgraphs, all_strings, parse_failure_rate,
            sig_yara=sig_yara,
        )
    )

    # --- Classifier evidence gate ---
    # The TTP model was trained without a benign class, so it answers confidently
    # even when handed nothing. Decide ONCE here whether the analysis actually
    # observed anything, and apply that decision to Phase 5, Phase 6 and the
    # analyst-facing limitations alike.
    classifier_evidence = has_deterministic_evidence(
        cfg_count=len(cfgs),
        matched_behaviors=set(all_matches),
        ttp_feature_vector=ttp_feature_vector,
    )

    # --- Phase 5: Multi-label TTP Classification (direct) + auxiliary family label ---
    predicted_ttps, predicted_family, family_confidence = AnalysisPipeline.run_phase5_ml_classification(
        ttp_feature_vector, feature_vector, evidence_present=classifier_evidence
    )

    # --- Phase 5.5: Brand impersonation (identity, not payload) ---
    impersonation = AnalysisPipeline.run_phase5b_impersonation(ingestion)

    manifest = AnalysisManifest(
        target_package=ingestion.package_name,
        sha256=ingestion.sha256,
        cache_hit=cache_hit,
        total_nodes_parsed=total_nodes,
        graph_density=round(mean_density, 6),
        behavioral_subgraphs=behavioral_subgraphs,
        obfuscation=obfuscation,
        predicted_ttps=predicted_ttps,
        predicted_family=predicted_family,
        family_confidence=family_confidence,
        ttp_context=_build_ttp_context(predicted_ttps),
        related_samples=find_related_samples(
            list(predicted_ttps.keys()), ingestion.c2_indicators,
            exclude_sha256=ingestion.sha256,
            cert_thumbprint=ingestion.cert_thumbprint,
        ),
        signature_yara=sig_yara,
        permissions=ingestion.permissions,
        c2_indicators=ingestion.c2_indicators,
        cert_anomalies=ingestion.cert_anomalies,
        permission_matrix_flags=ingestion.permission_matrix_flags,
        secondary_dex_count=ingestion.secondary_dex_count,
        accessibility_flags=ingestion.accessibility_flags,
        exported_risks=ingestion.exported_risks,
        payload_assets=ingestion.payload_assets,
        dropper_signals=ingestion.dropper_signals,
        resolved_crypto_configs=resolved_crypto,
        resolved_dcl_targets=resolved_dcl,
        resolved_webview_bridges=resolved_webview,
        resolved_native_bridges=resolved_native,
        app_label=ingestion.app_label,
        icon_phash=ingestion.icon_phash,
        impersonation=impersonation,
    )

    # --- Phase 6: Risk Scoring (includes static malware anchors) ---
    risk_score = AnalysisPipeline.run_phase6_risk_scoring(
        predicted_ttps, ingestion.permissions, obfuscation, all_matches, cache_hit, None,
        sig_yara=sig_yara,
        ingestion=ingestion,
        classifier_evidence_present=classifier_evidence,
        impersonation=impersonation,
    )

    # --- Phase 7: Explainable Reporting ---
    narrative, limitations = AnalysisPipeline.run_phase7_reporting(manifest, risk_score)

    if not classifier_evidence:
        limitations = list(limitations) + [NO_CLASSIFIER_EVIDENCE_NOTE]

    # Always persist after a cold-path run so the hot path fires on the next
    # request for the same SHA-256. predicted_family may be None when the
    # auxiliary family classifier is untrained — that's fine, store "" and
    # let lookup_signature gate on SHA-256 presence instead of family.
    if not cache_hit:
        store_signature(
            sha256=ingestion.sha256,
            family=predicted_family or "",
            risk_score=risk_score.total_score,
            ttps=predicted_ttps,
            narrative=narrative,
            limitations=limitations,
            signature_yara_data=sig_yara.model_dump() if sig_yara else None,
            permissions=ingestion.permissions,
            risk_components=risk_score.model_dump(),
            obfuscation_data=obfuscation.model_dump(),
            package_name=ingestion.package_name,
            c2_indicators=ingestion.c2_indicators,
            cert_thumbprint=ingestion.cert_thumbprint,
        )

    return AnalysisReport(
        manifest=manifest,
        risk_score=risk_score,
        narrative_report=narrative,
        limitations=limitations,
    )


def _empty_topological_invariants() -> dict[str, float]:
    from app.analysis.topology import compute_topological_invariants
    import networkx as nx
    return compute_topological_invariants(nx.DiGraph())


def _empty_obfuscation_signal() -> ObfuscationSignal:
    """Returns a no-signal ObfuscationSignal for hot-path cache hits."""
    return ObfuscationSignal(
        string_entropy_score=0.0,
        flattening_suspected=False,
        flattening_outlier_nodes=[],
        reflection_call_count=0,
        unresolved_reflection_targets=0,
        method_parse_failure_rate=0.0,
        coverage_note="analysis skipped — known sample (cache hit)",
    )
