"""
Modular processing pipeline for GuardGraph AI static analysis.
Provides explicit phases for cold path analysis:
- Phase 1: Ingestion & Metadata Extraction
- Phase 2: Graph Representation (CFGs & ACFGs)
- Phase 3: Forensic Anchor Matching & Subgraph Extraction
- Phase 4: Feature Engineering (Topology & Obfuscation)
- Phase 5: Machine Learning Classification & Intelligence mapping
- Phase 6: Risk Scoring & Verdict Formulation
- Phase 7: Explainable Report Generation (GraphRAG)
"""
import time
from typing import Tuple, Dict, List, Set, Any, Optional
import networkx as nx
import openai
from loguru import logger

from app.analysis.ingest import ingest_apk
from app.analysis.cfg import build_all_method_cfgs
from app.analysis.forensic import match_anchors, extract_anchor_subgraph
from app.analysis.topology import compute_topological_invariants
from app.analysis.obfuscation import build_obfuscation_signal
from app.ml.classifier import classifier
from app.ml.features import build_feature_vector
from app.reports.scoring import compute_risk_score
from app.reports.graphrag import generate_report
from app.core.config import settings, FAMILY_TO_TTPS
from app.core.schemas import (
    IngestionResult,
    AnalysisManifest,
    BehavioralSubgraph,
    RiskScoreBreakdown,
    ObfuscationSignal,
    AnalysisReport
)

class AnalysisPipeline:
    @staticmethod
    def run_phase1_ingestion(filepath: str) -> Tuple[IngestionResult, Any, Any, Any]:
        """Phase 1: Hashing, certificate extraction, and basic structure identification."""
        logger.info("[Phase 1] Starting Ingestion & Metadata Extraction...")
        start_time = time.time()
        ingestion, apk_obj, dvm, analysis_obj = ingest_apk(filepath)
        duration = time.time() - start_time
        logger.info(f"[Phase 1] Completed in {duration:.3f}s. Package: {ingestion.package_name}")
        return ingestion, apk_obj, dvm, analysis_obj

    @staticmethod
    def run_phase2_graph_construction(analysis_obj: Any) -> Tuple[Dict[str, nx.DiGraph], float]:
        """Phase 2: Build control flow graphs and attributes per method."""
        logger.info("[Phase 2] Starting Graph Representation (CFG & ACFG construction)...")
        start_time = time.time()
        cfgs, parse_failure_rate = build_all_method_cfgs(analysis_obj)
        duration = time.time() - start_time
        logger.info(f"[Phase 2] Completed in {duration:.3f}s. Built CFGs for {len(cfgs)} methods. Parse failure rate: {parse_failure_rate * 100:.1f}%")
        return cfgs, parse_failure_rate

    @staticmethod
    def run_phase3_forensic_matching(cfgs: Dict[str, nx.DiGraph]) -> Tuple[Dict[str, List[str]], List[BehavioralSubgraph], List[str]]:
        """Phase 3: Match suspicious anchor APIs and extract bounded 4-hop subgraphs."""
        logger.info("[Phase 3] Starting Forensic Anchor Matching & Subgraph Extraction...")
        start_time = time.time()
        all_matches: Dict[str, List[str]] = {}
        behavioral_subgraphs: List[BehavioralSubgraph] = []
        all_strings: List[str] = []

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
                    size_ratio = (sub.number_of_nodes() / method_node_count) if method_node_count > 0 else 0.0

                    behavioral_subgraphs.append(
                        BehavioralSubgraph(
                            subgraph_id=f"SUB_{method_sig}_{anchor}",
                            primary_behavior_flag=behavior,
                            matched_apis=matched_apis[:10],
                            topological_invariants=invariants,
                            subgraph_size_ratio=round(size_ratio, 4),
                        )
                    )

            for _, data in g.nodes(data=True):
                all_strings.extend(data.get("string_literals", []))

        duration = time.time() - start_time
        logger.info(f"[Phase 3] Completed in {duration:.3f}s. Matched {len(behavioral_subgraphs)} suspicious behavioral subgraphs.")
        return all_matches, behavioral_subgraphs, all_strings

    @staticmethod
    def run_phase4_feature_engineering(
        ingestion: IngestionResult,
        cfgs: Dict[str, nx.DiGraph],
        all_matches: Dict[str, List[str]],
        behavioral_subgraphs: List[BehavioralSubgraph],
        all_strings: List[str],
        parse_failure_rate: float
    ) -> Tuple[ObfuscationSignal, List[float], float, int]:
        """Phase 4: Calculate topological invariants and entropy/flattening/reflection obfuscation signals."""
        logger.info("[Phase 4] Starting Feature Engineering (Topology & Obfuscation analysis)...")
        start_time = time.time()
        
        obfuscation = build_obfuscation_signal(
            all_strings=all_strings,
            cfgs=cfgs,
            entropy_threshold=settings.entropy_high_threshold,
            flattening_zscore=settings.flattening_degree_outlier_zscore,
            method_parse_failure_rate=parse_failure_rate,
        )

        if behavioral_subgraphs:
            agg_invariants = behavioral_subgraphs[0].topological_invariants
        else:
            agg_invariants = AnalysisPipeline._empty_topological_invariants()

        feature_vector = build_feature_vector(
            permissions=ingestion.permissions,
            matched_behaviors=set(all_matches.keys()),
            topological_invariants=agg_invariants,
            obfuscation_entropy=obfuscation.string_entropy_score,
            obfuscation_flattening=obfuscation.flattening_suspected,
            obfuscation_reflection_count=obfuscation.reflection_call_count,
        )

        per_method_densities = []
        for g in cfgs.values():
            n = g.number_of_nodes()
            e = g.number_of_edges()
            if n > 1:
                per_method_densities.append(e / (n * (n - 1)))
        mean_density = sum(per_method_densities) / len(per_method_densities) if per_method_densities else 0.0
        total_nodes = sum(g.number_of_nodes() for g in cfgs.values())

        duration = time.time() - start_time
        logger.info(f"[Phase 4] Completed in {duration:.3f}s. Entropy: {obfuscation.string_entropy_score:.2f}, Suspected Flattening: {obfuscation.flattening_suspected}")
        return obfuscation, feature_vector, mean_density, total_nodes

    @staticmethod
    def run_phase5_ml_classification(feature_vector: List[float]) -> Tuple[Dict[str, float], Optional[str], Optional[float]]:
        """Phase 5: Run XGBoost inference and map to MITRE ATT&CK Mobile techniques."""
        logger.info("[Phase 5] Starting ML Classification...")
        start_time = time.time()
        predicted_ttps: Dict[str, float] = {}
        predicted_family = None
        family_confidence = None

        try:
            predictions = classifier.predict(feature_vector)
            predicted_family = max(predictions, key=predictions.get)
            family_confidence = predictions[predicted_family]

            TECHNIQUE_CONFIDENCE_DISCOUNT = 0.85
            technique_ids = FAMILY_TO_TTPS.get(predicted_family, [])
            if technique_ids:
                predicted_ttps = {
                    t: round(family_confidence * TECHNIQUE_CONFIDENCE_DISCOUNT, 4)
                    for t in technique_ids
                }
        except FileNotFoundError:
            logger.warning("[Phase 5] Classifier model not found. Proceeding with empty predictions.")

        duration = time.time() - start_time
        logger.info(f"[Phase 5] Completed in {duration:.3f}s. Family: {predicted_family} (Confidence: {family_confidence})")
        return predicted_ttps, predicted_family, family_confidence

    @staticmethod
    def run_phase6_risk_scoring(
        predicted_ttps: Dict[str, float],
        permissions: List[str],
        obfuscation: ObfuscationSignal,
        all_matches: Dict[str, List[str]],
        cache_hit: bool = False,
        cached_score: Optional[float] = None
    ) -> RiskScoreBreakdown:
        """Phase 6: Calculate weighted risk score component breakdown and verdict."""
        logger.info("[Phase 6] Starting Risk Scoring...")
        start_time = time.time()
        matched_anchor_behaviors = set(all_matches.keys())
        
        risk_score = compute_risk_score(
            predicted_ttps=predicted_ttps,
            permissions=permissions,
            obfuscation=obfuscation,
            entropy_threshold=settings.entropy_high_threshold,
            matched_anchor_behaviors=matched_anchor_behaviors,
            cache_hit=cache_hit,
            cached_score=cached_score,
            matched_c2_indicators=len(all_matches.get("C2_BEHAVIOR", [])),
        )
        duration = time.time() - start_time
        logger.info(f"[Phase 6] Completed in {duration:.3f}s. Risk Score: {risk_score.total_score} ({risk_score.verdict_band})")
        return risk_score

    @staticmethod
    def run_phase7_reporting(manifest: AnalysisManifest, risk_score: RiskScoreBreakdown) -> Tuple[str, List[str]]:
        """Phase 7: Generate narrative analyst report via GraphRAG (local Ollama)."""
        logger.info("[Phase 7] Starting GraphRAG Reporting...")
        start_time = time.time()
        try:
            narrative, limitations = generate_report(manifest, risk_score)
        except (RuntimeError, openai.OpenAIError, Exception) as e:
            logger.error(f"[Phase 7] LLM report generation failed: {e}")
            narrative = f"[Report generation unavailable: {e}]"
            limitations = [manifest.obfuscation.coverage_note]

        duration = time.time() - start_time
        logger.info(f"[Phase 7] Completed in {duration:.3f}s.")
        return narrative, limitations

    @staticmethod
    def _empty_topological_invariants() -> Dict[str, float]:
        return compute_topological_invariants(nx.DiGraph())
