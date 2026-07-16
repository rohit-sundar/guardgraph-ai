"""
API contract schemas. Keep these in sync with the JSON manifest contract
described in the design doc — downstream report generation depends on
field names not silently drifting.
"""
from typing import Optional
from pydantic import BaseModel


class IngestionResult(BaseModel):
    sha256: str
    package_name: Optional[str] = None
    cert_thumbprint: Optional[str] = None
    permissions: list[str] = []
    activities: list[str] = []
    services: list[str] = []
    receivers: list[str] = []


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


class SignatureYaraResult(BaseModel):
    """Combined result from signature detection and YARA scanning."""
    signature_matches: list[SignatureMatch] = []
    yara_matches: list[YaraMatch] = []
    is_known_malware: bool = False   # any signature hash hit → true
    combined_severity: float = 0.0   # max severity across all matches


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


class RiskScoreBreakdown(BaseModel):
    classifier_confidence_component: float
    permission_api_component: float
    ttp_severity_component: float
    # Deterministic behavioral evidence component (§9.3 fix).
    # Weighted on matched forensic-dictionary behaviors (proven API presence),
    # not classifier probability — these are the strongest static predictors
    # per GUARD paper SHAP analysis.
    forensic_anchor_component: float
    obfuscation_component: float
    reputation_component: float
    ioc_component: float
    total_score: float
    verdict_band: str  # low / suspicious / high / malicious


class AnalysisReport(BaseModel):
    manifest: AnalysisManifest
    risk_score: RiskScoreBreakdown
    narrative_report: str
    limitations: list[str]
