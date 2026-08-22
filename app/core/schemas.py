"""
API contract schemas. Keep these in sync with the JSON manifest contract
described in the design doc — downstream report generation depends on
field names not silently drifting.
"""
from typing import Optional
# pyrefly: ignore [missing-import]
from pydantic import BaseModel


class IngestionResult(BaseModel):
    sha256: str
    package_name: Optional[str] = None
    cert_thumbprint: Optional[str] = None
    permissions: list[str] = []
    activities: list[str] = []
    services: list[str] = []
    receivers: list[str] = []
    # Declared intent-filter actions across all components (additive — used by the
    # multi-label TTP feature vector's intent vocabulary). Empty when extraction
    # fails; the legacy 33-feature family model does not read this field.
    intent_actions: list[str] = []
    # Advanced Android malware static anchors (banking trojans / droppers / OTP theft)
    c2_indicators: list[str] = []
    cert_anomalies: list[str] = []
    permission_matrix_flags: list[str] = []
    secondary_dex_count: int = 0
    # Total methods Androguard recovered from the DEX(es), before cfg.py's relevance
    # pre-filter. Feeds ObfuscationSignal.dex_method_count so the scorer can tell
    # "no code was recovered" apart from "no method was relevant" (N7).
    dex_method_count: int = 0
    accessibility_flags: list[str] = []
    exported_risks: list[str] = []
    payload_assets: list[str] = []
    dropper_signals: list[str] = []


class BehavioralSubgraph(BaseModel):
    subgraph_id: str
    primary_behavior_flag: str
    matched_apis: list[str]
    topological_invariants: dict[str, float]
    # Ratio of subgraph nodes to full method nodes (§9.7 instrumentation).
    # Use this to validate whether the 4-hop constant is under/over-capturing
    # on real APKs. 1.0 = subgraph covers entire method (hops too wide);
    # very low = likely cutting off the behavior chain (hops too narrow).
    subgraph_size_ratio: float = 0.0


class ObfuscationSignal(BaseModel):
    string_entropy_score: float
    flattening_suspected: bool
    flattening_outlier_nodes: list[str] = []
    reflection_call_count: int = 0
    unresolved_reflection_targets: int = 0
    # Rate of methods that failed CFG parsing — 0.0 to 1.0 (§9.6 fix).
    # A high failure rate is itself an analysis-coverage gap and raises the
    # obfuscation score, since heavily obfuscated APKs often break parsers.
    method_parse_failure_rate: float = 0.0
    # N7: `flattening_suspected` is an existential over every analysed method, so on
    # an app with hundreds of them it is true almost by construction — measured, it
    # fired on 30/30 clean apps against 23/28 malware, i.e. a constant pointing the
    # wrong way. These three carry the same evidence as a *prevalence*, which is what
    # scoring.obfuscation_component reads. The boolean stays because it is one of the
    # three OBFUSCATION_FEATURES in the frozen 35/181 vectors.
    flattening_method_count: int = 0
    analyzed_method_count: int = 0
    flattening_method_ratio: float = 0.0
    # Methods present in the DEX at all, from ingestion. Distinguishes "the relevance
    # pre-filter selected nothing" (large dex_method_count, small analyzed count) from
    # "there was no code to analyse" — only the latter is an anti-analysis signal.
    # `None` means not measured, and is scored as absence of evidence rather than as
    # evidence of absence: a caller that builds this signal by hand must not be
    # charged the anti-analysis penalty for leaving the field out.
    dex_method_count: int | None = None
    # Activities + services + receivers the manifest declares. Read together with
    # dex_method_count: a DEX too small to implement the components its own manifest
    # declares is a loader stub, and that is the one anti-analysis signal that
    # measurably separates the corpus. `None` = not measured.
    declared_component_count: int | None = None
    coverage_note: str  # e.g. "3 native libraries not analyzed"


# ── Signature Detection & YARA Scanning Results ─────────────────────────

class SignatureMatch(BaseModel):
    """A single hash-based or certificate-based signature match."""
    match_type: str          # "sha256" | "certificate"
    matched_value: str       # the hex digest that matched
    family: Optional[str] = None
    severity: float          # 0.0-1.0
    source: str              # attribution source (e.g. "MalwareBazaar")
    description: str = ""
    report_url: Optional[str] = None       # clickable link to the full report
    detection_ratio: Optional[str] = None  # e.g. "23/73 engines"


class YaraMatch(BaseModel):
    """A single YARA rule match against the APK/DEX binary."""
    rule_name: str
    tags: list[str] = []
    severity: float          # 0.0-1.0 from rule meta
    description: str = ""
    category: str = "unknown"
    matched_strings: list[str] = []  # which string identifiers triggered
    # Which scan target produced the hit (apk file path, dex:classes.dex, etc.)
    scan_target: str = "apk"


class SignatureYaraResult(BaseModel):
    """Combined result from signature detection and YARA scanning."""
    signature_matches: list[SignatureMatch] = []
    yara_matches: list[YaraMatch] = []
    is_known_malware: bool = False   # any signature hash hit → true
    combined_severity: float = 0.0   # max severity across all matches
    # Targets scanned (apk + uncompressed DEX/asset streams)
    yara_scan_targets: list[str] = []


class AnalysisManifest(BaseModel):
    target_package: Optional[str]
    sha256: str
    cache_hit: bool
    total_nodes_parsed: int
    graph_density: float
    behavioral_subgraphs: list[BehavioralSubgraph]
    obfuscation: ObfuscationSignal
    predicted_ttps: dict[str, float]  # technique_id -> confidence
    predicted_family: Optional[str]
    family_confidence: Optional[float]
    # Signature detection + YARA scanning results (Phase 1.5).
    # None on hot-path cache hits (scanning is skipped).
    signature_yara: Optional[SignatureYaraResult] = None
    # Declared manifest permissions (e.g. "android.permission.CAMERA"). Fed to
    # GraphRAG so the LLM has real permissions to cite instead of back-deriving
    # a plausible-looking list from predicted TTPs (RECORD_AUDIO was
    # fabricated this way in one prior report).
    permissions: list[str] = []
    # Advanced Android malware static anchors (fed to GraphRAG + risk scoring)
    c2_indicators: list[str] = []
    cert_anomalies: list[str] = []
    permission_matrix_flags: list[str] = []
    secondary_dex_count: int = 0
    accessibility_flags: list[str] = []
    exported_risks: list[str] = []
    payload_assets: list[str] = []
    dropper_signals: list[str] = []
    # Reverse-engineering findings from static_resolution.py's shared register/
    # class propagation engine — resolved crypto configs (Cipher/SecretKeySpec/
    # IvParameterSpec), traced DexClassLoader-family targets, WebView
    # addJavascriptInterface bridge exposure, and JNI/native library symbol
    # correlation. Each entry is a human-readable, already-formatted finding
    # string (see the respective module's `describe()`); empty on a cache hit,
    # since these are cold-path-only enrichments.
    resolved_crypto_configs: list[str] = []
    resolved_dcl_targets: list[str] = []
    resolved_webview_bridges: list[str] = []
    resolved_native_bridges: list[str] = []


class RiskScoreBreakdown(BaseModel):
    # Component fields are Optional: a cache-hit hot path returns the cached
    # verdict verbatim without recomputing any component, so None here means
    # "not recomputed on this path" — distinct from 0.0, which would falsely
    # assert "we looked and found no evidence".
    classifier_confidence_component: Optional[float] = None
    permission_api_component: Optional[float] = None
    ttp_severity_component: Optional[float] = None
    # Deterministic behavioral evidence component (§9.3 fix).
    # Weighted on matched forensic-dictionary behaviors (proven API presence),
    # not classifier probability — these are the strongest static predictors
    # per GUARD paper SHAP analysis.
    forensic_anchor_component: Optional[float] = None
    obfuscation_component: Optional[float] = None
    reputation_component: Optional[float] = None
    ioc_component: Optional[float] = None
    total_score: float
    verdict_band: str  # low / medium / suspicious / high / malicious
    # Zero-day / novel-variant flag: strong deterministic (forensic anchor) and/or
    # structural (obfuscation/coverage) evidence while model familiarity is low.
    # A model-free escalation signal for first-seen samples the classifier hasn't
    # learned — see scoring.compute_risk_score.
    zero_day_indicator: bool = False


class AnalysisReport(BaseModel):
    manifest: AnalysisManifest
    risk_score: RiskScoreBreakdown
    narrative_report: str
    limitations: list[str]
