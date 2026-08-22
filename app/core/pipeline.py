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
from app.analysis.forensic import ManifestContext, match_anchors, extract_anchor_subgraph
from app.analysis.topology import compute_topological_invariants, aggregate_subgraph_invariants
from app.analysis.obfuscation import build_obfuscation_signal, count_reflection_calls
from app.analysis.signatures import match_signatures
from app.analysis.yara_engine import scan_apk_with_payloads
from app.analysis.apk_static import extract_c2_indicators
from app.ml.classifier import classifier, ttp_classifier
from app.ml.features import build_feature_vector, build_ttp_feature_vector
from app.reports.scoring import compute_risk_score
from app.reports.graphrag import generate_report
from app.core.config import settings

# Default min technique probability for a TTP to count as "predicted" in the
# manifest. Probabilities are retained for risk scoring; this only gates what
# surfaces. A trained bundle may carry per-label thresholds calibrated on a
# validation split (train_model.py --target ttp), which override this per
# technique — with prevalences from 0.02 to 0.75 one global cut cannot serve
# every label. This value remains the fallback for uncalibrated labels.
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

# Limitation text surfaced to the analyst when the gate below fires.
def _format_resolved_reflection(entry: Dict[str, str]) -> str:
    """Renders a resolved reflection-target record as a readable "before -> after" call."""
    short_api = entry["target_api"].replace("L", "", 1).replace(";->", ".").replace("/", ".")
    return f'{short_api}("{entry["resolved_value"]}") [reflection target resolved]'


NO_CLASSIFIER_EVIDENCE_NOTE = (
    "TTP classifier suppressed — no methods were parsed and no forensic anchors "
    "matched, so its predictions would reflect the training-set label prior rather "
    "than evidence from this sample. Score reflects deterministic signals only."
)


def has_deterministic_evidence(
    cfg_count: int,
    matched_behaviors: Set[str],
    ttp_feature_vector: List[float],
) -> bool:
    """
    Does the static analysis give the TTP classifier anything to reason about?

    The model is trained on 134 all-malware samples with no benign class, so it
    cannot represent "nothing suspicious here" — an all-zeros feature vector lands
    in positive leaves and yields 9 techniques at >= 0.5. Confirmed end to end: a
    ZIP holding one 35-byte text file renamed `.apk` (no AndroidManifest.xml, 0
    methods, 0 CFGs, 0 subgraphs) scored 33.92 / `suspicious`, 24.10 of it from
    classifier confidence alone.

    So we require the analysis to have actually observed something before the
    model's opinion counts: at least one parsed method CFG or one matched anchor
    behavior, and a feature vector that is not identically zero. A manifest-only
    APK whose DEX failed to parse gets no vote either — permissions alone are far
    outside the distribution every estimator was fitted on.

    This is an interim mitigation. The real fix is a benign class in the training
    set; see `scripts/build_ttp_dataset.py --benign-dir`.
    """
    if not any(v != 0.0 for v in ttp_feature_vector):
        return False
    return cfg_count > 0 or bool(matched_behaviors)


class AnalysisPipeline:
    @staticmethod
    def run_phase1_ingestion(
        filepath: str,
    ) -> Tuple[IngestionResult, Any, Any, Any, List[Tuple[str, bytes]]]:
        """Phase 1: Hashing, cert, structure, and Android malware static enrichments."""
        logger.info("[Phase 1] Starting Ingestion & Metadata Extraction...")
        start_time = time.time()
        ingestion, apk_obj, dvm, analysis_obj, yara_targets = ingest_apk(filepath)
        duration = time.time() - start_time
        logger.info(
            f"[Phase 1] Completed in {duration:.3f}s. Package: {ingestion.package_name} | "
            f"C2={len(ingestion.c2_indicators)} matrix={ingestion.permission_matrix_flags} "
            f"secondary_dex={ingestion.secondary_dex_count}"
        )
        return ingestion, apk_obj, dvm, analysis_obj, yara_targets

    @staticmethod
    def run_phase1b_signature_yara(
        filepath: str,
        ingestion: IngestionResult,
        yara_targets: Optional[List[Tuple[str, bytes]]] = None,
    ) -> SignatureYaraResult:
        """
        Phase 1.5: Signature hash/cert matching + YARA over the APK *and*
        uncompressed inner DEX/asset streams (ZIP compression evasion guard).
        """
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

        # YARA: outer APK + uncompressed DEX/asset payloads
        yara_matches_raw, scan_targets = scan_apk_with_payloads(
            filepath,
            payload_targets=yara_targets or [],
            rules_dir=settings.yara_rules_dir,
        )
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
            yara_scan_targets=scan_targets,
        )

        duration = time.time() - start_time
        logger.info(
            f"[Phase 1.5] Completed in {duration:.3f}s. "
            f"Signature matches: {len(sig_matches)}, YARA matches: {len(yara_matches)}, "
            f"YARA targets: {len(scan_targets)}, Known malware: {is_known}"
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
    def run_phase3_forensic_matching(
        cfgs: Dict[str, nx.DiGraph],
        ingestion: IngestionResult,
    ) -> Tuple[Dict[str, List[str]], List[BehavioralSubgraph], List[str]]:
        """
        Phase 3: Match suspicious anchor APIs and extract bounded 4-hop subgraphs.

        `ingestion` supplies the manifest declarations the gated rules read (N1):
        a behavior whose capability the app never declared cannot fire.
        """
        logger.info("[Phase 3] Starting Forensic Anchor Matching & Subgraph Extraction...")
        start_time = time.time()
        manifest = ManifestContext.from_ingestion(ingestion)
        all_matches: Dict[str, List[str]] = {}
        behavioral_subgraphs: List[BehavioralSubgraph] = []
        all_strings: List[str] = []

        # Resolved reflection targets (Class.forName / getMethod / etc. that traced
        # back to a literal), grouped by method so DYNAMIC_REFLECTION subgraphs can
        # surface the human-readable call instead of a raw invoke instruction.
        _, _, resolved_reflection = count_reflection_calls(cfgs)
        resolved_by_method: Dict[str, List[Dict[str, str]]] = {}
        for entry in resolved_reflection:
            resolved_by_method.setdefault(entry["method_sig"], []).append(entry)

        for method_sig, g in cfgs.items():
            method_node_count = g.number_of_nodes()
            matches = match_anchors(g, manifest)
            for behavior, anchor_nodes in matches.items():
                all_matches.setdefault(behavior, []).extend(anchor_nodes)

                for anchor in anchor_nodes:
                    sub = extract_anchor_subgraph(g, anchor, hops=4)
                    invariants = compute_topological_invariants(sub)
                    matched_apis = [
                        api for _, data in sub.nodes(data=True)
                        for api in data.get("api_calls", [])
                    ]
                    if behavior == "DYNAMIC_REFLECTION":
                        sub_node_ids = set(sub.nodes())
                        resolved_calls = [
                            _format_resolved_reflection(entry)
                            for entry in resolved_by_method.get(method_sig, [])
                            if entry["node_id"] in sub_node_ids
                        ]
                        # Resolved calls go first so they survive the [:10] cap below.
                        matched_apis = resolved_calls + matched_apis
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
    def merge_c2_from_strings(ingestion: IngestionResult, all_strings: List[str]) -> IngestionResult:
        """
        Re-run C2 regex extraction over CFG string literals and merge into
        ingestion.c2_indicators (assets were already scanned at ingest time).
        """
        extra = extract_c2_indicators(all_strings)
        if not extra:
            return ingestion
        merged = sorted(set(list(ingestion.c2_indicators) + extra))
        if merged != list(ingestion.c2_indicators):
            logger.info(f"[Phase 3+] Merged C2 IoCs from DEX strings: {merged}")
            return ingestion.model_copy(update={"c2_indicators": merged})
        return ingestion

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
          - `feature_vector` (35)     — legacy family model (unchanged semantics).
          - `ttp_feature_vector` (181) — multi-label TTP model; GUARD topology stats
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
            dex_method_count=ingestion.dex_method_count,
            declared_component_count=(
                len(ingestion.activities) + len(ingestion.services)
                + len(ingestion.receivers)
            ),
        )

        # Legacy family (35) vector — unchanged: first-subgraph invariants.
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

        # Multi-label TTP (181) vector. GUARD topology aggregated across ALL anchor
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
        evidence_present: bool = True,
    ) -> Tuple[Dict[str, float], Optional[str], Optional[float]]:
        """
        Phase 5: multi-label MITRE ATT&CK Mobile TTP classification.

        PRIMARY: the Binary-Relevance TTP model predicts technique probabilities
        DIRECTLY (no FAMILY_TO_TTPS proxy). Techniques at/above their calibrated
        threshold (falling back to TTP_PREDICT_THRESHOLD) surface in `predicted_ttps`;
        probabilities are retained for risk scoring.
        AUXILIARY: the legacy family model still supplies `predicted_family` for the
        report/reputation when trained. Both degrade gracefully if untrained.

        `evidence_present=False` (see has_deterministic_evidence) suppresses the TTP
        model entirely rather than only discounting it downstream, so prior-driven
        techniques never reach the manifest, the narrative or the signature cache.
        """
        logger.info("[Phase 5] Starting Multi-label TTP Classification...")
        start_time = time.time()
        predicted_ttps: Dict[str, float] = {}
        predicted_family = None
        family_confidence = None

        # Primary: direct multi-label technique prediction.
        if not evidence_present:
            logger.warning(f"[Phase 5] {NO_CLASSIFIER_EVIDENCE_NOTE}")
        else:
            try:
                ttp_preds = ttp_classifier.predict(ttp_feature_vector)
                thresholds = ttp_classifier.thresholds()
                predicted_ttps = {
                    t: p for t, p in ttp_preds.items()
                    if p >= thresholds.get(t, TTP_PREDICT_THRESHOLD)
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
        except (ValueError, Exception) as e:
            logger.warning(f"[Phase 5] Family model inference failed (auxiliary): {e}")

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
        ingestion: Optional[IngestionResult] = None,
        classifier_evidence_present: bool = True,
    ) -> RiskScoreBreakdown:
        """Phase 6: Calculate weighted risk score component breakdown and verdict.

        `classifier_evidence_present=False` zeroes the two model-derived components
        (see has_deterministic_evidence). Phase 5 already empties `predicted_ttps` in
        that case, so this is belt-and-braces for callers that score without going
        through Phase 5.
        """
        logger.info("[Phase 6] Starting Risk Scoring...")
        start_time = time.time()
        matched_anchor_behaviors = set(all_matches.keys())

        # N8: the scorer rescales each technique probability against the boundary the
        # model was calibrated to, so it needs the same per-label thresholds Phase 5
        # filtered on. Read here rather than in scoring.py, which stays model-free; an
        # untrained bundle yields {} and the scorer falls back to its global default.
        try:
            ttp_thresholds = ttp_classifier.thresholds()
        except (FileNotFoundError, KeyError, Exception) as e:
            logger.warning(f"[Phase 6] Per-label TTP thresholds unavailable: {e}")
            ttp_thresholds = {}

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

        # Advanced static anchors from ingestion (C2 IoCs, cert, dropper, matrix)
        matrix_flags: List[str] = []
        extracted_c2 = 0
        cert_anoms = 0
        secondary_dex = 0
        dropper_sigs = 0
        if ingestion is not None:
            matrix_flags = list(ingestion.permission_matrix_flags or [])
            extracted_c2 = len(ingestion.c2_indicators or [])
            cert_anoms = len(ingestion.cert_anomalies or [])
            secondary_dex = int(ingestion.secondary_dex_count or 0)
            dropper_sigs = len(ingestion.dropper_signals or [])

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
            permission_matrix_flags=matrix_flags,
            extracted_c2_count=extracted_c2,
            cert_anomaly_count=cert_anoms,
            secondary_dex_count=secondary_dex,
            dropper_signal_count=dropper_sigs,
            classifier_evidence_present=classifier_evidence_present,
            ttp_thresholds=ttp_thresholds,
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
