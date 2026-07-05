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


class ObfuscationSignal(BaseModel):
    string_entropy_score: float
    flattening_suspected: bool
    flattening_outlier_nodes: list[str] = []
    reflection_call_count: int = 0
    unresolved_reflection_targets: int = 0
    coverage_note: str  # e.g. "3 native libraries not analyzed"


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


class RiskScoreBreakdown(BaseModel):
    classifier_confidence_component: float
    permission_api_component: float
    ttp_severity_component: float
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
