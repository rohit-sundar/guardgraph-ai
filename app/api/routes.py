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
"""
import os
import shutil
import tempfile
import uuid

from fastapi import APIRouter, UploadFile, File, HTTPException

from app.graph.cache import lookup_signature, store_signature
from app.reports.scoring import compute_risk_score, _band_for
from app.core.config import settings
from app.core.schemas import AnalysisManifest, AnalysisReport, ObfuscationSignal, RiskScoreBreakdown

router = APIRouter()


@router.post("/analyze", response_model=AnalysisReport)
async def analyze(file: UploadFile = File(...)):
    if not file.filename.endswith(".apk"):
        raise HTTPException(400, "Only .apk files are supported in this prototype.")

    tmp_dir = tempfile.mkdtemp()
    tmp_path = os.path.join(tmp_dir, f"{uuid.uuid4()}.apk")

    try:
        with open(tmp_path, "wb") as f:
            shutil.copyfileobj(file.file, f)

        result = _run_analysis(tmp_path)
        return result

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


from app.core.pipeline import AnalysisPipeline

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
        empty_obfuscation = _empty_obfuscation_signal()
        cached_score = cached.get("base_score")
        cached_ttps = cached.get("ttps") or {}
        total_score = cached_score if cached_score is not None else 0.0
        risk_score = RiskScoreBreakdown(
            # Not recomputed on this path — None, not 0.0, which would falsely
            # assert "we looked and found no evidence".
            classifier_confidence_component=None,
            permission_api_component=None,
            ttp_severity_component=None,
            forensic_anchor_component=None,
            obfuscation_component=None,
            reputation_component=None,
            ioc_component=None,
            total_score=total_score,
            verdict_band=_band_for(total_score),
            zero_day_indicator=False,
        )
        manifest = AnalysisManifest(
            target_package=ingestion.package_name,
            sha256=ingestion.sha256,
            cache_hit=True,
            total_nodes_parsed=0,
            graph_density=0.0,
            behavioral_subgraphs=[],
            obfuscation=empty_obfuscation,
            predicted_ttps=cached_ttps,
            predicted_family=cached.get("family"),
            family_confidence=None,
            signature_yara=None,  # skipped on hot path
            permissions=ingestion.permissions,
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
    all_matches, behavioral_subgraphs, all_strings = AnalysisPipeline.run_phase3_forensic_matching(cfgs)

    # Merge C2 IoCs found in DEX string literals into ingestion
    ingestion = AnalysisPipeline.merge_c2_from_strings(ingestion, all_strings)

    # --- Phase 4: Feature Engineering (family 33-vec + multi-label TTP 179-vec) ---
    obfuscation, feature_vector, ttp_feature_vector, mean_density, total_nodes = (
        AnalysisPipeline.run_phase4_feature_engineering(
            ingestion, cfgs, all_matches, behavioral_subgraphs, all_strings, parse_failure_rate,
            sig_yara=sig_yara,
        )
    )

    # --- Phase 5: Multi-label TTP Classification (direct) + auxiliary family label ---
    predicted_ttps, predicted_family, family_confidence = AnalysisPipeline.run_phase5_ml_classification(
        ttp_feature_vector, feature_vector
    )

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
    )

    # --- Phase 6: Risk Scoring (includes static malware anchors) ---
    risk_score = AnalysisPipeline.run_phase6_risk_scoring(
        predicted_ttps, ingestion.permissions, obfuscation, all_matches, cache_hit, None,
        sig_yara=sig_yara,
        ingestion=ingestion,
    )

    # --- Phase 7: Explainable Reporting ---
    narrative, limitations = AnalysisPipeline.run_phase7_reporting(manifest, risk_score)

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
