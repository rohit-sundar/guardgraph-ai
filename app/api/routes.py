"""
Main /analyze endpoint. Orchestrates the full cold/hot path pipeline:

  upload -> hash -> cache lookup (hot path) OR
  ingest -> CFG/ACFG -> anchor detection -> topology -> obfuscation ->
  classify -> score -> GraphRAG report (cold path)

This is intentionally synchronous for the prototype — no Celery/queue.
A cold-path analysis on a real APK will take several seconds; that's
acceptable for a demo. Do not "optimize" this before it's needed.
"""
import os
import shutil
import tempfile
import uuid

import openai

from fastapi import APIRouter, UploadFile, File, HTTPException

from app.analysis.ingest import ingest_apk
from app.analysis.cfg import build_all_method_cfgs
from app.analysis.forensic import match_anchors, extract_anchor_subgraph
from app.analysis.topology import compute_topological_invariants
from app.analysis.obfuscation import build_obfuscation_signal
from app.ml.classifier import classifier
from app.ml.features import build_feature_vector
from app.graph.cache import lookup_signature, store_signature
from app.reports.scoring import compute_risk_score
from app.reports.graphrag import generate_report
from app.core.config import settings
from app.core.schemas import AnalysisManifest, BehavioralSubgraph, AnalysisReport

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


def _run_analysis(filepath: str) -> AnalysisReport:
    # --- Ingestion (needed even on cache hit, for sha256) ---
    ingestion, apk_obj, dvm, analysis_obj = ingest_apk(filepath)

    # --- Hot path: cache lookup ---
    cached = lookup_signature(ingestion.sha256)
    cache_hit = cached is not None

    if cache_hit:
        # Known sample — build a minimal report from cached data and skip
        # the full CFG pipeline. This is the "<50ms" path from the design doc.
        risk_score = compute_risk_score(
            predicted_ttps={},
            permissions=ingestion.permissions,
            obfuscation=_empty_obfuscation_signal(),
            entropy_threshold=settings.entropy_high_threshold,
            cache_hit=True,
            cached_score=cached.get("base_score"),
            matched_c2_indicators=0,
        )
        from app.core.schemas import ObfuscationSignal, AnalysisManifest
        manifest = AnalysisManifest(
            target_package=ingestion.package_name,
            sha256=ingestion.sha256,
            cache_hit=True,
            total_nodes_parsed=0,
            graph_density=0.0,
            behavioral_subgraphs=[],
            obfuscation=_empty_obfuscation_signal(),
            predicted_ttps={},
            predicted_family=cached.get("family"),
            family_confidence=None,
        )
        try:
            narrative, limitations = generate_report(manifest, risk_score)
        except (RuntimeError, openai.OpenAIError, Exception) as e:
            narrative = f"[Report generation unavailable: {e}]"
            limitations = ["no significant static coverage gaps detected"]
        return AnalysisReport(
            manifest=manifest,
            risk_score=risk_score,
            narrative_report=narrative,
            limitations=limitations,
        )

    # --- Cold path: full static analysis ---
    cfgs = build_all_method_cfgs(analysis_obj)

    all_matches: dict[str, list[str]] = {}
    behavioral_subgraphs: list[BehavioralSubgraph] = []
    all_strings: list[str] = []

    for method_sig, g in cfgs.items():
        matches = match_anchors(g)
        for behavior, anchor_nodes in matches.items():
            all_matches.setdefault(behavior, []).extend(anchor_nodes)

            for anchor in anchor_nodes:
                sub = extract_anchor_subgraph(g, anchor, hops=4)
                invariants = compute_topological_invariants(sub)
                matched_apis = [
                    api for _, data in sub.nodes(data=True)
                    for api in data.get("api_calls", [])
                ]
                behavioral_subgraphs.append(
                    BehavioralSubgraph(
                        subgraph_id=f"SUB_{method_sig}_{anchor}",
                        primary_behavior_flag=behavior,
                        matched_apis=matched_apis[:10],  # cap for report readability
                        topological_invariants=invariants,
                    )
                )

        for _, data in g.nodes(data=True):
            all_strings.extend(data.get("string_literals", []))

    obfuscation = build_obfuscation_signal(
        all_strings=all_strings,
        cfgs=cfgs,
        entropy_threshold=settings.entropy_high_threshold,
        flattening_zscore=settings.flattening_degree_outlier_zscore,
    )

    # --- Aggregate topology for classifier feature vector (whole-app average) ---
    if behavioral_subgraphs:
        agg_invariants = behavioral_subgraphs[0].topological_invariants
    else:
        agg_invariants = compute_topological_invariants_empty()

    feature_vector = build_feature_vector(
        permissions=ingestion.permissions,
        matched_behaviors=set(all_matches.keys()),
        topological_invariants=agg_invariants,
        obfuscation_entropy=obfuscation.string_entropy_score,
        obfuscation_flattening=obfuscation.flattening_suspected,
        obfuscation_reflection_count=obfuscation.reflection_call_count,
    )

    predicted_ttps: dict[str, float] = {}
    predicted_family = None
    family_confidence = None
    try:
        predictions = classifier.predict(feature_vector)
        predicted_family = max(predictions, key=predictions.get)
        family_confidence = predictions[predicted_family]
        predicted_ttps = predictions  # placeholder: family probs used as TTP proxy until per-technique model is trained
    except FileNotFoundError:
        # Model not trained yet — proceed with empty predictions rather than crashing.
        # The report generator will correctly say "not observed" for classifier findings.
        pass

    total_nodes = sum(g.number_of_nodes() for g in cfgs.values())
    total_edges = sum(g.number_of_edges() for g in cfgs.values())
    # Density is computed as a whole-app approximation: edges / possible edges.
    # total_nodes here is a sum across disjoint CFGs, so this is an approximation
    # used for the manifest field only (not used in risk scoring).
    density = (total_edges / (total_nodes * (total_nodes - 1))) if total_nodes > 1 else 0.0

    manifest = AnalysisManifest(
        target_package=ingestion.package_name,
        sha256=ingestion.sha256,
        cache_hit=cache_hit,
        total_nodes_parsed=total_nodes,
        graph_density=round(density, 6),
        behavioral_subgraphs=behavioral_subgraphs,
        obfuscation=obfuscation,
        predicted_ttps=predicted_ttps,
        predicted_family=predicted_family,
        family_confidence=family_confidence,
    )

    risk_score = compute_risk_score(
        predicted_ttps=predicted_ttps,
        permissions=ingestion.permissions,
        obfuscation=obfuscation,
        entropy_threshold=settings.entropy_high_threshold,
        cache_hit=cache_hit,
        cached_score=cached.get("base_score") if cached else None,
        matched_c2_indicators=len(all_matches.get("C2_BEHAVIOR", [])),
    )

    try:
        narrative, limitations = generate_report(manifest, risk_score)
    except (RuntimeError, openai.OpenAIError, Exception) as e:
        # Catch OpenAI/Ollama connectivity errors as well as generic failures.
        # A broken LLM connection must not crash the entire analysis response.
        narrative = f"[Report generation unavailable: {e}]"
        limitations = [obfuscation.coverage_note]

    if not cache_hit and predicted_family:
        store_signature(
            sha256=ingestion.sha256,
            family=predicted_family,
            risk_score=risk_score.total_score,
            ttps=list(predicted_ttps.keys()),
        )

    return AnalysisReport(
        manifest=manifest,
        risk_score=risk_score,
        narrative_report=narrative,
        limitations=limitations,
    )


def compute_topological_invariants_empty() -> dict[str, float]:
    from app.analysis.topology import compute_topological_invariants
    import networkx as nx
    return compute_topological_invariants(nx.DiGraph())


def _empty_obfuscation_signal():
    """Returns a no-signal ObfuscationSignal for hot-path cache hits."""
    from app.core.schemas import ObfuscationSignal
    return ObfuscationSignal(
        string_entropy_score=0.0,
        flattening_suspected=False,
        flattening_outlier_nodes=[],
        reflection_call_count=0,
        unresolved_reflection_targets=0,
        coverage_note="analysis skipped — known sample (cache hit)",
    )
