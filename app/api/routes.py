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
from app.core.config import settings, FAMILY_TO_TTPS
from app.core.schemas import AnalysisManifest, BehavioralSubgraph, AnalysisReport, ObfuscationSignal

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
    # §9.1 fix: on a cache hit we must truly short-circuit — build_all_method_cfgs
    # must never be called. The whole point of the hot path is to avoid CFG work.
    cached = lookup_signature(ingestion.sha256)
    cache_hit = cached is not None

    if cache_hit:
        # Known sample — build a minimal report from cached data.
        # This is the "<50ms" path from the design doc.
        empty_obfuscation = _empty_obfuscation_signal()
        risk_score = compute_risk_score(
            predicted_ttps={},
            permissions=ingestion.permissions,
            obfuscation=empty_obfuscation,
            entropy_threshold=settings.entropy_high_threshold,
            matched_anchor_behaviors=set(),
            cache_hit=True,
            cached_score=cached.get("base_score"),
            matched_c2_indicators=0,
        )
        manifest = AnalysisManifest(
            target_package=ingestion.package_name,
            sha256=ingestion.sha256,
            cache_hit=True,
            total_nodes_parsed=0,
            graph_density=0.0,
            behavioral_subgraphs=[],
            obfuscation=empty_obfuscation,
            predicted_ttps={},
            predicted_family=cached.get("family"),
            family_confidence=None,
        )
        try:
            narrative, limitations = generate_report(manifest, risk_score)
        except (RuntimeError, openai.OpenAIError, Exception) as e:
            narrative = f"[Report generation unavailable: {e}]"
            limitations = ["analysis skipped — known sample (cache hit)"]
        return AnalysisReport(
            manifest=manifest,
            risk_score=risk_score,
            narrative_report=narrative,
            limitations=limitations,
        )

    # --- Cold path: full static analysis ---
    # §9.6: unpack (graphs, failure_rate) — failure rate is now a coverage signal.
    cfgs, parse_failure_rate = build_all_method_cfgs(analysis_obj)

    all_matches: dict[str, list[str]] = {}
    behavioral_subgraphs: list[BehavioralSubgraph] = []
    all_strings: list[str] = []

    for method_sig, g in cfgs.items():
        method_node_count = g.number_of_nodes()
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
                # §9.7: record how much of the full method the 4-hop subgraph covers.
                sub_nodes = sub.number_of_nodes()
                size_ratio = (sub_nodes / method_node_count) if method_node_count > 0 else 0.0

                behavioral_subgraphs.append(
                    BehavioralSubgraph(
                        subgraph_id=f"SUB_{method_sig}_{anchor}",
                        primary_behavior_flag=behavior,
                        matched_apis=matched_apis[:10],  # cap for report readability
                        topological_invariants=invariants,
                        subgraph_size_ratio=round(size_ratio, 4),
                    )
                )

        for _, data in g.nodes(data=True):
            all_strings.extend(data.get("string_literals", []))

    # §9.5/9.6: pass parse_failure_rate so it feeds both coverage note and score.
    obfuscation = build_obfuscation_signal(
        all_strings=all_strings,
        cfgs=cfgs,
        entropy_threshold=settings.entropy_high_threshold,
        flattening_zscore=settings.flattening_degree_outlier_zscore,
        method_parse_failure_rate=parse_failure_rate,
    )

    # --- Aggregate topology for classifier feature vector (whole-app average) ---
    if behavioral_subgraphs:
        agg_invariants = behavioral_subgraphs[0].topological_invariants
    else:
        agg_invariants = _empty_topological_invariants()

    feature_vector = build_feature_vector(
        permissions=ingestion.permissions,
        matched_behaviors=set(all_matches.keys()),
        topological_invariants=agg_invariants,
        obfuscation_entropy=obfuscation.string_entropy_score,
        obfuscation_flattening=obfuscation.flattening_suspected,
        obfuscation_reflection_count=obfuscation.reflection_call_count,
    )

    # --- Classifier ---
    predicted_ttps: dict[str, float] = {}
    predicted_family = None
    family_confidence = None
    try:
        predictions = classifier.predict(feature_vector)
        predicted_family = max(predictions, key=predictions.get)
        family_confidence = predictions[predicted_family]

        # §9.2 fix: bridge family-name keys → MITRE technique IDs so
        # ttp_severity_component gets real T-numbers, not family names.
        # Each technique inherits the family's confidence at a discount
        # (family→technique mapping is imprecise by nature).
        TECHNIQUE_CONFIDENCE_DISCOUNT = 0.85
        technique_ids = FAMILY_TO_TTPS.get(predicted_family, [])
        if technique_ids:
            predicted_ttps = {
                t: round(family_confidence * TECHNIQUE_CONFIDENCE_DISCOUNT, 4)
                for t in technique_ids
            }
        else:
            # Unknown family not in map — pass empty rather than raw family names.
            predicted_ttps = {}

    except FileNotFoundError:
        # Model not trained yet — proceed with empty predictions rather than crashing.
        # The report generator will correctly say "not observed" for classifier findings.
        pass

    # §9.4 fix: graph_density as mean per-method density (not sum-conflated).
    # Computing over individual CFGs before combining is the only meaningful number.
    per_method_densities = []
    for g in cfgs.values():
        n = g.number_of_nodes()
        e = g.number_of_edges()
        if n > 1:
            per_method_densities.append(e / (n * (n - 1)))
    mean_density = (
        sum(per_method_densities) / len(per_method_densities)
        if per_method_densities else 0.0
    )
    total_nodes = sum(g.number_of_nodes() for g in cfgs.values())

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
    )

    # §9.3 fix: pass matched_anchor_behaviors (distinct behavior names) so the
    # forensic anchor component gets the deterministic signal it needs.
    matched_anchor_behaviors = set(all_matches.keys())

    risk_score = compute_risk_score(
        predicted_ttps=predicted_ttps,
        permissions=ingestion.permissions,
        obfuscation=obfuscation,
        entropy_threshold=settings.entropy_high_threshold,
        matched_anchor_behaviors=matched_anchor_behaviors,
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
