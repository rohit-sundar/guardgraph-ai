"""
Modular processing pipeline for GuardGraph AI static analysis.
Provides explicit phases for cold path analysis:
- Phase 1:   Ingestion & Metadata Extraction
- Phase 1.5: Signature Detection & YARA Scanning
- Phase 2:   Graph Representation (CFGs & ACFGs)
- Phase 3:   Forensic Anchor Matching & Subgraph Extraction
- Phase 3.5: Reverse-Engineering Deep Dive (crypto/DCL/WebView/native resolution)
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
from app.analysis.cfg import build_all_method_cfgs, method_key, split_method_signature
from app.analysis.forensic import ManifestContext, match_anchors, extract_anchor_subgraph
from app.analysis.topology import (
    compute_topological_invariants,
    aggregate_subgraph_invariants,
    detect_flattening_outlier,
)
from app.analysis.obfuscation import build_obfuscation_signal, count_reflection_calls
from app.analysis.signatures import match_signatures
from app.analysis.yara_engine import scan_apk_with_payloads
from app.analysis.apk_static import extract_c2_indicators
from app.analysis.crypto_recovery import recover_crypto_configs
from app.analysis.dcl_tracing import trace_dcl_targets
from app.analysis.webview_bridge import map_webview_bridges
from app.analysis.native_bridge import resolve_native_bridges
from app.analysis.impersonation import detect_impersonation
from app.analysis.dynamic_verification import run_dynamic_verification
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
    CFGEdge,
    CFGNode,
    RiskScoreBreakdown,
    ObfuscationSignal,
    SignatureMatch,
    SubgraphTopology,
    YaraMatch,
    SignatureYaraResult,
    AnalysisReport
)

# How many behavioral subgraphs carry serialized topology. Every anchor produces a
# subgraph, and a large APK produces hundreds; shipping blocks and edges for all of
# them would dominate the response for no analytic gain, since the explorer draws a
# bounded number anyway. Selection favours behavioral *breadth* — see
# _select_topology_subgraphs.
MAX_TOPOLOGY_SUBGRAPHS = 12

# Block cap per serialized subgraph. A 4-hop window on a large method can run to
# hundreds of blocks, which is unreadable as a drawing and heavy as JSON.
MAX_TOPOLOGY_NODES = 40

# Per-block api_calls / string_literals kept for the node tooltip, and the length
# each literal is truncated to.
_MAX_NODE_DETAILS = 3
_MAX_LITERAL_CHARS = 120

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


def _short_api_label(api_call: str) -> str:
    """
    Condenses an Androguard invoke operand into something readable on a node.

    The operand looks like `v2, Ljava/lang/reflect/Field;->setAccessible(Z)V`; the
    method name is the only part that fits on a graph node.
    """
    target = api_call.split("->")[-1] if "->" in api_call else api_call
    name = target.split("(")[0].strip()
    return name or api_call.strip()


def _serialize_topology(
    sub: nx.DiGraph,
    method_sig: str,
    anchor: str,
    outlier_nodes: Set[str],
    max_nodes: int = MAX_TOPOLOGY_NODES,
) -> SubgraphTopology:
    """
    Converts the extracted 4-hop subgraph into the wire format the explorer draws.

    Node ids are qualified by cfg.method_key() so blocks that share an offset across
    methods stay distinct — the frontend keys its node set by id, and bare offsets
    used to collapse unrelated blocks into one.

    Over `max_nodes`, keep the anchor and its nearest neighbours by hop distance and
    re-induce, rather than truncating the node list. Truncation would leave edges
    pointing at blocks that were never serialized, which draws as fragments.
    """
    if sub.number_of_nodes() == 0:
        return SubgraphTopology()

    if sub.number_of_nodes() > max_nodes and anchor in sub:
        distances = nx.single_source_shortest_path_length(sub.to_undirected(), anchor)
        nearest = sorted(distances, key=lambda n: (distances[n], str(n)))[:max_nodes]
        sub = sub.subgraph(nearest).copy()

    key = method_key(method_sig)

    nodes: List[CFGNode] = []
    for node_id, data in sub.nodes(data=True):
        api_calls = list(data.get("api_calls", []))
        offset = data.get("start")
        if offset is None:
            offset = int(node_id) if str(node_id).isdigit() else 0

        # Prefer naming the block by what it calls; fall back to its offset.
        label = _short_api_label(api_calls[0]) if api_calls else f"0x{int(offset):x}"

        # These exist to populate a hover tooltip, so a few entries per block is
        # enough. Literals are truncated because an obfuscated app's string pool is
        # full of multi-kilobyte base64 blobs that would dominate the response.
        literals = [
            (s[:_MAX_LITERAL_CHARS] + "…") if len(s) > _MAX_LITERAL_CHARS else s
            for s in data.get("string_literals", [])[:_MAX_NODE_DETAILS]
        ]

        nodes.append(
            CFGNode(
                id=f"{key}#{node_id}",
                block_offset=int(offset),
                label=label,
                api_calls=api_calls[:_MAX_NODE_DETAILS],
                string_literals=literals,
                is_anchor=(node_id == anchor),
                is_outlier=(node_id in outlier_nodes),
            )
        )

    edges = [
        CFGEdge(source=f"{key}#{u}", target=f"{key}#{v}")
        for u, v in sub.edges()
    ]

    return SubgraphTopology(nodes=nodes, edges=edges)


def _select_topology_subgraphs(
    subgraphs: List[BehavioralSubgraph],
    block_counts: List[int],
    limit: int = MAX_TOPOLOGY_SUBGRAPHS,
) -> List[int]:
    """
    Chooses which subgraphs get topology, returning their indices.

    Breadth before depth: one representative per distinct behavior flag first (the
    largest window for that behavior), then fill remaining slots by size. A single
    reflection-heavy app otherwise spends every slot on DYNAMIC_REFLECTION anchors
    and the explorer shows the same behavior a dozen times over.

    Ranked on absolute block count, deliberately not on `subgraph_size_ratio`: that
    field is sub_nodes/method_nodes, so a one-block method scores a perfect 1.0 and
    outranks a genuinely informative window. Measured on a real sample, ratio-ranking
    filled most slots with single-block subgraphs that draw as isolated dots.
    """
    if not subgraphs:
        return []

    ranked = sorted(
        range(len(subgraphs)),
        key=lambda i: block_counts[i],
        reverse=True,
    )

    selected: List[int] = []
    seen_behaviors: Set[str] = set()
    for i in ranked:
        flag = subgraphs[i].primary_behavior_flag
        if flag not in seen_behaviors:
            seen_behaviors.add(flag)
            selected.append(i)
        if len(selected) >= limit:
            return selected

    for i in ranked:
        if i not in selected:
            selected.append(i)
        if len(selected) >= limit:
            break

    return selected


class AnalysisPipeline:
    @staticmethod
    def run_phase1_ingestion(
        filepath: str, skip_dex_analysis: bool = False
    ) -> Tuple[IngestionResult, Any, Any, Any, List[Tuple[str, bytes]]]:
        """
        Phase 1: Hashing, cert, structure, and Android malware static enrichments.

        `skip_dex_analysis` is for the hot path only — see ingest_apk. It returns
        no DalvikVMFormat/Analysis object, so a caller that goes on to build a CFG
        must not use it.
        """
        logger.info("[Phase 1] Starting Ingestion & Metadata Extraction...")
        start_time = time.time()
        ingestion, apk_obj, dvm, analysis_obj, yara_targets = ingest_apk(
            filepath, skip_dex_analysis=skip_dex_analysis
        )
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
        # Keeps the extracted subgraph alongside its BehavioralSubgraph so the
        # topology post-pass can serialize the ones it selects without re-extracting.
        pending_topology: List[Tuple[nx.DiGraph, str, str, Set[str]]] = []

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
            if not matches:
                # Nothing to attribute in this method — skip the outlier scan too.
                for _, data in g.nodes(data=True):
                    all_strings.extend(data.get("string_literals", []))
                continue

            # An anchor and a flattening dispatcher are nodes of this same graph, so
            # whether the behavior sits inside a flattened region is a membership
            # test, not a guess. Computed once per method however many anchors it has.
            _, outlier_list = detect_flattening_outlier(
                g, settings.flattening_degree_outlier_zscore
            )
            method_outliers = set(outlier_list)

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
                    class_name, method_name = split_method_signature(method_sig)
                    contained_outliers = [n for n in sub.nodes if n in method_outliers]

                    pending_topology.append((sub, method_sig, anchor, method_outliers))
                    behavioral_subgraphs.append(
                        BehavioralSubgraph(
                            subgraph_id=f"SUB_{method_sig}_{anchor}",
                            method_signature=method_sig,
                            class_name=class_name,
                            method_name=method_name,
                            anchor_node=anchor,
                            contains_outlier_nodes=contained_outliers,
                            primary_behavior_flag=behavior,
                            matched_apis=matched_apis[:10],
                            topological_invariants=invariants,
                            subgraph_size_ratio=round(size_ratio, 4),
                        )
                    )

            for _, data in g.nodes(data=True):
                all_strings.extend(data.get("string_literals", []))

        # Serialize real blocks and edges for a bounded, behaviorally diverse subset.
        # Everything else keeps topology=None, which means "not serialized" rather
        # than "empty subgraph".
        block_counts = [sub.number_of_nodes() for sub, _, _, _ in pending_topology]
        for i in _select_topology_subgraphs(behavioral_subgraphs, block_counts):
            sub, method_sig, anchor, method_outliers = pending_topology[i]
            behavioral_subgraphs[i].topology = _serialize_topology(
                sub, method_sig, anchor, method_outliers
            )

        duration = time.time() - start_time
        drawn = sum(1 for bs in behavioral_subgraphs if bs.topology is not None)
        logger.info(
            f"[Phase 3] Completed in {duration:.3f}s. Matched {len(behavioral_subgraphs)} "
            f"suspicious behavioral subgraphs ({drawn} with serialized topology)."
        )
        return all_matches, behavioral_subgraphs, all_strings

    @staticmethod
    def run_phase3b_re_deepdive(
        cfgs: Dict[str, nx.DiGraph],
        ingestion: IngestionResult,
        apk_obj: Any = None,
        analysis_obj: Any = None,
    ) -> Tuple[List[str], List[str], List[str], List[str]]:
        """
        Phase 3.5: reverse-engineering deep dive built on the shared
        static_resolution engine — crypto config recovery, dynamic
        code-loading target tracing, WebView JS-interface bridge mapping, and
        JNI/native library symbol correlation. Each returns a list of
        already-formatted, human-readable finding strings for the manifest
        and GraphRAG (see each module's dataclass `describe()`).

        apk_obj/analysis_obj are Androguard's raw APK and Analysis objects
        from Phase 1 — needed here (unlike reflection resolution) because
        native-bridge resolution reads .so files out of the APK zip and
        WebView bridge mapping looks up a class's declared methods.
        """
        logger.info("[Phase 3.5] Starting Reverse-Engineering Deep Dive...")
        start_time = time.time()

        crypto_findings = [f.describe() for f in recover_crypto_configs(cfgs)]
        dcl_findings = [
            f.describe() for f in trace_dcl_targets(cfgs, payload_assets=ingestion.payload_assets)
        ]
        webview_findings = [f.describe() for f in map_webview_bridges(cfgs, analysis_obj=analysis_obj)]
        native_findings = [
            f.describe() for f in resolve_native_bridges(cfgs, apk_obj=apk_obj, analysis_obj=analysis_obj)
        ]

        duration = time.time() - start_time
        logger.info(
            f"[Phase 3.5] Completed in {duration:.3f}s. "
            f"crypto={len(crypto_findings)} dcl={len(dcl_findings)} "
            f"webview={len(webview_findings)} native={len(native_findings)}"
        )
        return crypto_findings, dcl_findings, webview_findings, native_findings

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
            manifest_parse_failed=ingestion.manifest_parse_failed,
            manifest_recovery_source=ingestion.manifest_recovery_source,
            container_anomalies=ingestion.container_anomalies,
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
    def run_phase5b_impersonation(ingestion: IngestionResult) -> dict:
        """
        Phase 5.5: is this app pretending to be a different, legitimate app?

        Separate from the malware phases on purpose. Every other phase asks how
        malicious the code is; this one asks who the app claims to be, and the two
        answers are independent — a cloned banking app can carry an unremarkable
        payload and still be the most damaging thing in the queue.

        Never raises: a missing or malformed reference table costs the checks, not
        the analysis.
        """
        logger.info("[Phase 5.5] Starting Brand Impersonation Checks...")
        start_time = time.time()
        try:
            phash = ingestion.icon_phash
            result = detect_impersonation(
                package_name=ingestion.package_name,
                app_label=ingestion.app_label,
                cert_sha256=ingestion.cert_thumbprint,
                icon_phash=int(phash, 16) if phash else None,
            ).to_dict()
        except Exception as e:
            logger.error(f"[Phase 5.5] Impersonation checks failed: {e}")
            result = {
                "findings": [], "coverage": [f"impersonation checks failed: {e}"],
                "brands_checked": 0, "max_severity": 0.0,
            }

        duration = time.time() - start_time
        findings = result.get("findings") or []
        if findings:
            logger.warning(
                f"[Phase 5.5] Completed in {duration:.3f}s. IMPERSONATION DETECTED: "
                + "; ".join(f"{f['kind']} of {f['brand']}" for f in findings)
            )
        else:
            logger.info(
                f"[Phase 5.5] Completed in {duration:.3f}s. No impersonation of the "
                f"{result.get('brands_checked', 0)} protected brands checked."
            )
        return result

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
        impersonation: Optional[dict] = None,
        dynamic_verification: Optional[dict] = None,
    ) -> RiskScoreBreakdown:
        """Phase 6: Calculate weighted risk score component breakdown and verdict.

        `classifier_evidence_present=False` zeroes the two model-derived components
        (see has_deterministic_evidence). Phase 5 already empties `predicted_ttps` in
        that case, so this is belt-and-braces for callers that score without going
        through Phase 5.

        `dynamic_verification` (Phase 8's output, or None when that phase didn't
        run) feeds compute_risk_score's dynamic-confirmation floor — see
        DYNAMIC_CONFIRMATION_SCORE_FLOOR in scoring.py.
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
        container_anomalies: List[str] = []
        if ingestion is not None:
            matrix_flags = list(ingestion.permission_matrix_flags or [])
            extracted_c2 = len(ingestion.c2_indicators or [])
            cert_anoms = len(ingestion.cert_anomalies or [])
            secondary_dex = int(ingestion.secondary_dex_count or 0)
            dropper_sigs = len(ingestion.dropper_signals or [])
            container_anomalies = list(ingestion.container_anomalies or [])

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
            container_anomalies=container_anomalies,
            classifier_evidence_present=classifier_evidence_present,
            ttp_thresholds=ttp_thresholds,
            impersonation_findings=(impersonation or {}).get("findings"),
            dynamic_verification=dynamic_verification,
        )
        duration = time.time() - start_time
        logger.info(f"[Phase 6] Completed in {duration:.3f}s. Risk Score: {risk_score.total_score} ({risk_score.verdict_band})")
        return risk_score

    @staticmethod
    def run_phase8_dynamic_verification(
        filepath: str,
        ingestion: IngestionResult,
        resolved_dcl_targets: List[str],
        enabled: bool,
        resolved_native_targets: List[str] | None = None,
    ) -> dict:
        """
        Phase 8: scoped dynamic verification, opt-in only (see
        app/analysis/dynamic_verification.py's module docstring for why this
        is narrow-by-design rather than a general sandbox). `enabled` is the
        AND of the request's `enable_dynamic` flag and
        settings.dynamic_analysis_enabled — checked by the caller so this
        method has one clean early-return rather than duplicating that gate.

        static_predictions passed in only carries fields this module actually
        uses (c2_indicators, dcl_targets, native_targets, intent_actions,
        activities, services) —
        resolved_dcl_targets/resolved_native_targets are human-readable
        "ClassName(\"path\")" / 'System.loadLibrary("x") -> ...' describe()
        strings from dcl_tracing.py/native_bridge.py, so only a resolved
        fragment is useful for substring matching against a
        dynamically-observed class/library name; the raw describe() string is
        kept as a fallback since a caller can't always cheaply re-extract just
        the fragment. ingestion.intent_actions (the app's own declared
        intent-filter actions) lets a headless/receiver-only sample still get
        activated when it has no launcher activity — see
        _broadcast_declared_actions.
        """
        logger.info("[Phase 8] Starting Dynamic Verification...")
        if not enabled:
            logger.info("[Phase 8] Skipped — dynamic analysis disabled for this request.")
            return {"ran": False, "coverage_note": "dynamic analysis not requested"}

        start_time = time.time()
        result = run_dynamic_verification(
            apk_path=filepath,
            package_name=ingestion.package_name,
            static_predictions={
                "c2_indicators": ingestion.c2_indicators,
                "dcl_targets": resolved_dcl_targets,
                "native_targets": resolved_native_targets or [],
                "intent_actions": ingestion.intent_actions,
                # Declared activities/services let a sample with no LAUNCHER
                # category still be started explicitly by component name —
                # see _start_declared_components.
                "activities": ingestion.activities,
                "services": ingestion.services,
            },
            sha256=ingestion.sha256,
        )
        duration = time.time() - start_time
        logger.info(
            f"[Phase 8] Completed in {duration:.3f}s. ran={result.get('ran')} "
            f"network_confirmed={result.get('network_confirmed')} "
            f"dcl_payload_executed={result.get('dcl_payload_executed')} "
            f"native_library_confirmed={result.get('native_library_confirmed')}"
        )
        return result

    @staticmethod
    def run_phase7_reporting(
        manifest: AnalysisManifest, risk_score: RiskScoreBreakdown, skip_llm: bool = False
    ) -> Tuple[str, List[str], Optional[dict]]:
        """Phase 7: Generate narrative analyst report via GraphRAG (local Ollama).

        skip_llm forwards to generate_report() — see its docstring. Default
        False preserves full report generation for every existing caller.
        """
        logger.info("[Phase 7] Starting GraphRAG Reporting...")
        start_time = time.time()
        grounding = None
        try:
            narrative, limitations, grounding = generate_report(
                manifest, risk_score, skip_llm=skip_llm
            )
        except (RuntimeError, openai.OpenAIError, Exception) as e:
            logger.error(f"[Phase 7] LLM report generation failed: {e}")
            narrative = f"[Report generation unavailable: {e}]"
            limitations = [manifest.obfuscation.coverage_note]

        duration = time.time() - start_time
        if grounding:
            logger.info(
                f"[Phase 7] Completed in {duration:.3f}s. Grounding: "
                f"{grounding['passed_count']}/{grounding['total_count']} checks passed."
            )
        else:
            logger.info(f"[Phase 7] Completed in {duration:.3f}s.")
        return narrative, limitations, grounding

    @staticmethod
    def _empty_topological_invariants() -> Dict[str, float]:
        return compute_topological_invariants(nx.DiGraph())
