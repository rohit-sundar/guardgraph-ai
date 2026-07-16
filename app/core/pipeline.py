"""
Modular processing pipeline for GuardGraph AI static analysis.
Provides explicit phases for cold path analysis:
- Phase 1:   Ingestion & Metadata Extraction
- Phase 1.5: Signature Detection & YARA Scanning
- Phase 2:   Graph Representation (CFGs & ACFGs)
- Phase 3:   Forensic Anchor Matching & Subgraph Extraction
- Phase 4:   Feature Engineering (Topology & Obfuscation)
- Phase 5:   Machine Learning Classification & Intelligence mapping
- Phase 6:   Risk Scoring & Verdict Formulation
- Phase 7:   Explainable Report Generation (GraphRAG)
"""
import time
from typing import Tuple, Dict, List, Set, Any, Optional
import networkx as nx
import openai
from loguru import logger

from app.analysis.ingest import ingest_apk
from app.analysis.cfg import build_all_method_cfgs
from app.analysis.forensic import match_anchors, extract_anchor_subgraph
from app.analysis.topology import compute_topological_invariants, aggregate_subgraph_invariants
from app.analysis.obfuscation import build_obfuscation_signal
from app.analysis.signatures import match_signatures
from app.analysis.yara_engine import scan_file as yara_scan_file
from app.ml.classifier import classifier, ttp_classifier
from app.ml.features import build_feature_vector, build_ttp_feature_vector
from app.reports.scoring import compute_risk_score
from app.reports.graphrag import generate_report
from app.core.config import settings

# Min technique probability for a TTP to count as "predicted" in the manifest.
# Probabilities are retained for risk scoring; this only gates what surfaces.
TTP_PREDICT_THRESHOLD = 0.5
from app.core.schemas import (
    IngestionResult,
    AnalysisManifest,
    BehavioralSubgraph,
    RiskScoreBreakdown,
    ObfuscationSignal,
    SignatureMatch,
    YaraMatch,
    SignatureYaraResult,
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
    def run_phase1b_signature_yara(filepath: str, ingestion: IngestionResult) -> SignatureYaraResult:
        """Phase 1.5: Run signature hash/cert matching and YARA rule scanning."""
        logger.info("[Phase 1.5] Starting Signature Detection & YARA Scanning...")
        start_time = time.time()

        # Signature matching (hash + cert)
        sig_matches_raw = match_signatures(
            sha256=ingestion.sha256,
            cert_thumbprint=ingestion.cert_thumbprint,
            db_path=settings.signature_db_path,
        )
        sig_matches = [
            SignatureMatch(**m) for m in sig_matches_raw
        ]

        # YARA scanning (APK binary)
        yara_matches_raw = yara_scan_file(filepath, rules_dir=settings.yara_rules_dir)
        yara_matches = [
            YaraMatch(**m) for m in yara_matches_raw
        ]

        # Determine if this is a known-malware sample (any hash match)
        is_known = any(m.match_type == "sha256" for m in sig_matches)

        # Combined severity = max across all matches
        all_severities = (
            [m.severity for m in sig_matches] +
            [m.severity for m in yara_matches]
        )
        combined_severity = max(all_severities) if all_severities else 0.0

        result = SignatureYaraResult(
            signature_matches=sig_matches,
            yara_matches=yara_matches,
            is_known_malware=is_known,
            combined_severity=round(combined_severity, 4),
        )

        duration = time.time() - start_time
        logger.info(
            f"[Phase 1.5] Completed in {duration:.3f}s. "
            f"Signature matches: {len(sig_matches)}, YARA matches: {len(yara_matches)}, "
            f"Known malware: {is_known}"
        )
        return result

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
        parse_failure_rate: float,
        sig_yara: Optional[SignatureYaraResult] = None,
    ) -> Tuple[ObfuscationSignal, List[float], List[float], float, int]:
        """
        Phase 4: topological invariants + obfuscation signals + feature vectors.

        Builds TWO feature vectors:
          - `feature_vector` (33)     — legacy family model (unchanged semantics).
          - `ttp_feature_vector` (179) — multi-label TTP model; GUARD topology stats
            aggregated across ALL anchor subgraphs (not just the first), plus the
            DroidTTP-style manifest/API presence vocab.
        """
        logger.info("[Phase 4] Starting Feature Engineering (Topology & Obfuscation analysis)...")
        start_time = time.time()

        obfuscation = build_obfuscation_signal(
            all_strings=all_strings,
            cfgs=cfgs,
            entropy_threshold=settings.entropy_high_threshold,
            flattening_zscore=settings.flattening_degree_outlier_zscore,
            method_parse_failure_rate=parse_failure_rate,
        )

        # Legacy family (33) vector — unchanged: first-subgraph invariants.
        if behavioral_subgraphs:
            agg_invariants = behavioral_subgraphs[0].topological_invariants
        else:
            agg_invariants = AnalysisPipeline._empty_topological_invariants()

        # Extract sig/YARA features (shared by both vectors)
        sig_match_count = 0
        yara_match_count = 0
        yara_max_severity = 0.0
        if sig_yara is not None:
            sig_match_count = len(sig_yara.signature_matches)
            yara_match_count = len(sig_yara.yara_matches)
            if sig_yara.yara_matches:
                yara_max_severity = max(m.severity for m in sig_yara.yara_matches)

        feature_vector = build_feature_vector(
            permissions=ingestion.permissions,
            matched_behaviors=set(all_matches.keys()),
            topological_invariants=agg_invariants,
            obfuscation_entropy=obfuscation.string_entropy_score,
            obfuscation_flattening=obfuscation.flattening_suspected,
            obfuscation_reflection_count=obfuscation.reflection_call_count,
            signature_match_count=sig_match_count,
            yara_rule_match_count=yara_match_count,
            yara_max_severity=yara_max_severity,
        )

        # Multi-label TTP (179) vector. GUARD topology aggregated across ALL anchor
        # subgraphs; sensitive-API presence over every API call observed in the CFGs.
        # Keep this construction in sync with scripts/build_ttp_dataset.py::extract_ttp_row.
        all_apis: Set[str] = set()
        for g in cfgs.values():
            for _, data in g.nodes(data=True):
                all_apis.update(data.get("api_calls", []))
        ttp_agg_invariants = aggregate_subgraph_invariants(
            [bs.topological_invariants for bs in behavioral_subgraphs]
        )
        ttp_feature_vector = build_ttp_feature_vector(
            permissions=ingestion.permissions,
            intent_actions=ingestion.intent_actions,
            api_calls=all_apis,
            num_activities=len(ingestion.activities),
            num_services=len(ingestion.services),
            num_receivers=len(ingestion.receivers),
            matched_behaviors=set(all_matches.keys()),
            topological_invariants=ttp_agg_invariants,
            obfuscation_entropy=obfuscation.string_entropy_score,
            obfuscation_flattening=obfuscation.flattening_suspected,
            obfuscation_reflection_count=obfuscation.reflection_call_count,
            signature_match_count=sig_match_count,
            yara_rule_match_count=yara_match_count,
            yara_max_severity=yara_max_severity,
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
        return obfuscation, feature_vector, ttp_feature_vector, mean_density, total_nodes

    @staticmethod
    def run_phase5_ml_classification(
        ttp_feature_vector: List[float],
        family_feature_vector: List[float],
    ) -> Tuple[Dict[str, float], Optional[str], Optional[float]]:
        """
        Phase 5: multi-label MITRE ATT&CK Mobile TTP classification.

        PRIMARY: the Binary-Relevance TTP model predicts technique probabilities
        DIRECTLY (no FAMILY_TO_TTPS proxy). Techniques at/above TTP_PREDICT_THRESHOLD
        surface in `predicted_ttps` (probabilities retained for risk scoring).
        AUXILIARY: the legacy family model still supplies `predicted_family` for the
        report/reputation when trained. Both degrade gracefully if untrained.
        """
        logger.info("[Phase 5] Starting Multi-label TTP Classification...")
        start_time = time.time()
        predicted_ttps: Dict[str, float] = {}
        predicted_family = None
        family_confidence = None

        # Primary: direct multi-label technique prediction.
        try:
            ttp_preds = ttp_classifier.predict(ttp_feature_vector)
            predicted_ttps = {
                t: p for t, p in ttp_preds.items() if p >= TTP_PREDICT_THRESHOLD
            }
        except FileNotFoundError:
            logger.warning("[Phase 5] TTP model not found. Proceeding with empty TTP predictions.")

        # Auxiliary: legacy family label (best-effort; often untrained in the prototype).
        try:
            predictions = classifier.predict(family_feature_vector)
            predicted_family = max(predictions, key=predictions.get)
            family_confidence = predictions[predicted_family]
        except FileNotFoundError:
            logger.warning("[Phase 5] Family model not found (auxiliary). No family label.")

        duration = time.time() - start_time
        logger.info(
            f"[Phase 5] Completed in {duration:.3f}s. "
            f"Predicted TTPs: {sorted(predicted_ttps)} | Family: {predicted_family}"
        )
        return predicted_ttps, predicted_family, family_confidence

    @staticmethod
    def run_phase6_risk_scoring(
        predicted_ttps: Dict[str, float],
        permissions: List[str],
        obfuscation: ObfuscationSignal,
        all_matches: Dict[str, List[str]],
        cache_hit: bool = False,
        cached_score: Optional[float] = None,
        sig_yara: Optional[SignatureYaraResult] = None,
    ) -> RiskScoreBreakdown:
        """Phase 6: Calculate weighted risk score component breakdown and verdict."""
        logger.info("[Phase 6] Starting Risk Scoring...")
        start_time = time.time()
        matched_anchor_behaviors = set(all_matches.keys())

        # Extract sig/YARA signals for risk scoring
        sig_match_count = 0
        yara_match_count = 0
        yara_max_severity = 0.0
        is_known_malware = False
        if sig_yara is not None:
            sig_match_count = len(sig_yara.signature_matches)
            yara_match_count = len(sig_yara.yara_matches)
            if sig_yara.yara_matches:
                yara_max_severity = max(m.severity for m in sig_yara.yara_matches)
            is_known_malware = sig_yara.is_known_malware

        risk_score = compute_risk_score(
            predicted_ttps=predicted_ttps,
            permissions=permissions,
            obfuscation=obfuscation,
            entropy_threshold=settings.entropy_high_threshold,
            matched_anchor_behaviors=matched_anchor_behaviors,
            cache_hit=cache_hit,
            cached_score=cached_score,
            matched_c2_indicators=len(all_matches.get("C2_BEHAVIOR", [])),
            signature_match_count=sig_match_count,
            yara_match_count=yara_match_count,
            yara_max_severity=yara_max_severity,
            is_known_malware=is_known_malware,
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
