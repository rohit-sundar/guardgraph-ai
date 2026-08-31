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
    # True when AndroidManifest.xml failed to parse (Androguard's apk.APK()
    # construction raised) and ingestion fell back to manifest-independent
    # DEX/CFG extraction straight off the ZIP. A deliberately corrupted
    # manifest (junk bytes between AXML chunk headers) is a known
    # anti-analysis technique — see ingest.py's fallback path. All
    # manifest-derived fields above (permissions, activities/services/
    # receivers, cert_thumbprint, accessibility_flags, permission_matrix_flags,
    # intent_actions) are empty in this state, not "observed absent".
    manifest_parse_failed: bool = False
    # Which fallback filled the manifest-derived fields above, when one did:
    # "tree" (tolerant AXML parse) or "string_pool" (pool harvest, components
    # unattributed). None means no recovery was attempted or none succeeded.
    # See app/analysis/axml_recovery.py.
    manifest_recovery_source: Optional[str] = None
    # Component class names recovered from the AXML string pool, which records
    # that a name is present but not which element declared it. Kept apart from
    # activities/services/receivers so the classified lists never carry a guess.
    recovered_components: list[str] = []
    # Ways the ZIP container itself departs from what a build tool produces —
    # fake encryption flags, compression methods Android cannot inflate,
    # duplicate and path-poisoned entry names. Measured 0/533 on the clean
    # corpus against 122/499 malware (scripts/measure_container_anomalies.py),
    # which is why these reach the scorer as attributable evidence rather than
    # as one more circumstantial heuristic. See app/analysis/apk_container.py.
    container_anomalies: list[str] = []
    # Share of the archive's uncompressed bytes sitting in high-entropy assets
    # that failed the validity check for the format their header claims. Read
    # with dex_method_count: opaque bulk matters when there is no code to match.
    opaque_asset_ratio: float = 0.0
    # App identity, for brand-impersonation detection (app/analysis/impersonation.py).
    # `app_label` is what the victim reads on the home screen; `icon_phash` is the
    # 64-bit perceptual hash of the launcher icon as a hex string, or None when the
    # icon is an adaptive (XML) drawable with no pixels to hash — a coverage gap the
    # impersonation result reports rather than treating as "no match".
    app_label: Optional[str] = None
    icon_phash: Optional[str] = None


class CFGNode(BaseModel):
    """
    One basic block of a method's control-flow graph, as drawn by the UI.

    `id` is method-qualified ("<method_key>#<block_offset>") because block offsets
    are only unique *within* a method — offset 4 exists in almost every method, so
    a bare offset collapses unrelated blocks into one node downstream. The key is
    cfg.method_key(): a short digest, not the signature itself, which would repeat
    ~180 characters once per block and twice per edge. The readable signature
    travels once, on the owning BehavioralSubgraph / OutlierNode.
    """
    id: str
    block_offset: int
    label: str                    # short display label, e.g. "setAccessible" or "0x1c"
    api_calls: list[str] = []
    string_literals: list[str] = []
    is_anchor: bool = False       # carries the forensic evidence this subgraph matched
    is_outlier: bool = False      # this block is also a flattening dispatcher


class CFGEdge(BaseModel):
    """A real control transition (fallthrough, branch, or exception) between blocks."""
    source: str
    target: str


class SubgraphTopology(BaseModel):
    """
    The induced 4-hop subgraph itself. Before this existed the API shipped only
    scalars, so the explorer had no edges to draw and manufactured them client-side.
    """
    nodes: list[CFGNode] = []
    edges: list[CFGEdge] = []


class OutlierNode(BaseModel):
    """
    A flattening dispatcher block, with the method attribution that
    `flattening_outlier_nodes` (a bare list of offsets) cannot carry.
    """
    node_id: str                  # "<method_key>#<block_offset>"
    method_signature: str
    class_name: str
    method_name: str
    block_offset: int
    degree: int


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
    # Attribution. `subgraph_id` has always packed these three together as
    # "SUB_<method_sig>_<anchor>"; split out so consumers need not parse it.
    method_signature: str = ""
    class_name: str = ""
    method_name: str = ""
    anchor_node: str = ""
    # The real blocks and edges. None on subgraphs beyond MAX_TOPOLOGY_SUBGRAPHS —
    # absent topology means "not serialized", never "the subgraph was empty".
    topology: Optional[SubgraphTopology] = None
    # Flattening dispatcher blocks that fall inside this 4-hop window. Non-empty
    # means the behavior is wrapped in obfuscated control flow: two independent
    # signals landing on the same basic blocks. Reported, not scored.
    contains_outlier_nodes: list[str] = []


class ObfuscationSignal(BaseModel):
    string_entropy_score: float
    flattening_suspected: bool
    # Bare block offsets, ambiguous across methods. Kept as-is: it is one of the
    # frozen feature-vector inputs. `flattening_outlier_details` carries the same
    # nodes with the method attribution this field structurally cannot hold.
    flattening_outlier_nodes: list[str] = []
    flattening_outlier_details: list[OutlierNode] = []
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
    # AndroidManifest.xml failed to parse (apk.APK() raised) — see ingest.py's
    # fallback path. Unlike entropy/flattening, this has no plausible benign
    # explanation: no legitimate build tool produces a structurally corrupted
    # manifest, so scoring.obfuscation_component weights it directly rather
    # than requiring corpus measurement first (see that function's docstring
    # for why every other signal here does require it).
    manifest_parse_failed: bool = False
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


class FeedbackRequest(BaseModel):
    """Body for POST /analyses/{sha256}/feedback — an analyst's correction."""
    verdict: str            # free-form label, e.g. "false_positive", "confirmed"
    note: Optional[str] = None


class SignatureYaraResult(BaseModel):
    """Combined result from signature detection and YARA scanning."""
    signature_matches: list[SignatureMatch] = []
    yara_matches: list[YaraMatch] = []
    is_known_malware: bool = False   # any signature hash hit → true
    combined_severity: float = 0.0   # max severity across all matches
    # Targets scanned (apk + uncompressed DEX/asset streams)
    yara_scan_targets: list[str] = []


class DynamicVerificationResult(BaseModel):
    """
    Phase 8 (opt-in) — see app/analysis/dynamic_verification.py. `ran=False`
    means the dynamic pass did not complete (no AVD, install failure, etc.);
    it must never be read as "no dynamic evidence found" — that is what an
    all-empty `ran=True` result means. Every list/bool here is a diff against
    a static prediction already computed earlier in the pipeline, not a
    free-standing dynamic finding — see the module docstring for the mapping.
    """
    ran: bool = False
    duration_s: float = 0.0
    network_confirmed: list[str] = []
    network_predicted_not_seen: list[str] = []
    # Every host:port actually contacted, regardless of whether it matched a
    # static prediction — the confirm/refute fields above only ever cover
    # what the static pass predicted; this is the full unfiltered record.
    network_observed_all: list[str] = []
    sms_api_invoked: bool = False
    dcl_payload_executed: bool = False
    dcl_classes_loaded: list[str] = []
    accessibility_bound: bool = False
    crypto_invoked: bool = False
    # native_bridge.py statically resolves System.loadLibrary("x") call sites
    # to their .so/JNI symbols but can never confirm the call actually ran —
    # this is that confirmation, the same "predicted vs confirmed" treatment
    # dcl_payload_executed already gets.
    native_libraries_loaded: list[str] = []
    native_library_confirmed: bool = False
    # IoC-oriented findings, standalone — not diffed against a static
    # prediction the way the fields above are, since there usually isn't one
    # to diff against. Reported the way any dynamic-analysis sandbox would:
    # full URLs requested, files written to the app's own sandbox (a
    # dropper's payload lands here), shell commands executed.
    urls_accessed: list[str] = []
    files_written: list[str] = []
    commands_executed: list[str] = []
    # sms_api_invoked/accessibility_bound/crypto_invoked above are booleans;
    # these carry the actual value the hook captured (destination number,
    # service class name, cipher algorithm) — a premium-rate SMS number or a
    # weak cipher (DES/ECB) is a specific IoC, not just a yes/no.
    sms_destinations: list[str] = []
    accessibility_services: list[str] = []
    crypto_algorithms: list[str] = []
    # Cheap substitute for real parameterized string-decryption — the actual
    # Cipher.doFinal() return value, captured live and truncated (see
    # hooks.js's hookCrypto), plus Cipher.init's encrypt/decrypt mode.
    # Independent observations, not correlated per-Cipher-instance.
    crypto_outputs: list[dict] = []
    crypto_modes_observed: list[str] = []
    # Incoming-SMS interception (the real OTP-theft path — sms_api_invoked
    # above only ever covered the app SENDING a message). A simulated inbound
    # SMS is injected mid-capture (see dynamic_verification.py's
    # _run_capture_window_with_stimuli) since an AVD has no real carrier.
    sms_intercepted: list[str] = []
    # Overlay-attack detection (WindowManager.addView with a system/overlay
    # window type — a fake login screen drawn over the real app). Mechanically
    # verified installing cleanly on this project's AVD image; NOT yet
    # confirmed firing against a real overlay attack in this codebase's own
    # testing — see dynamic_verification.py's DynamicVerificationOutcome
    # docstring before treating a `false` here as a confident negative.
    overlay_detected: bool = False
    overlay_window_types: list[str] = []
    # Contacts/call-log/SMS-history ContentResolver reads, and clipboard
    # reads (crypto-clipper malware swaps a copied wallet address).
    sensitive_content_queries: list[str] = []
    clipboard_read: bool = False
    # Every event above, unfiltered and ordered by t (ms since agent load) —
    # the per-kind fields lose ordering; this is what lets a report
    # eventually say "contacted C2 3.2s after launch" instead of just
    # "at some point during the window".
    timeline: list[dict] = []
    # /static/screenshots/{sha256}_final.png — a live capture of the app's
    # actual foreground UI at the end of the capture window. None if capture
    # failed. Secondary to screenshot_reaction_url for before/after comparison.
    screenshot_url: Optional[str] = None
    # /static/screenshots/{sha256}_reaction.png — captured a few seconds after
    # the SMS/tap stimuli fire mid-window, while the app is most likely
    # actually reacting. This is the primary useful capture.
    screenshot_reaction_url: Optional[str] = None
    # Screenshots taken the instant a crucial event fired (overlay drawn, SMS
    # intercepted, accessibility bound, DCL payload class loaded). Each entry:
    # {"kind": <triggering event kind>, "url": ..., "t": <ms since agent load>}.
    event_screenshots: list[dict] = []
    # Last ~50 logcat lines captured the moment the target process crashed
    # mid-capture — substantiates the "possible anti-analysis
    # self-termination" coverage-note inference with the actual
    # exception/reason. Empty unless a crash actually happened.
    crash_logcat_tail: list[str] = []
    # Raw agent event counts by kind (network, sms_send, dcl_class_load,
    # accessibility_bound, crypto_invoked, url_accessed, file_written,
    # command_executed, hook_installed, hook_error, target_crashed) — gives
    # the report something concrete to say even when nothing happened to
    # match a static prediction.
    event_summary: dict[str, int] = {}
    coverage_note: str = "dynamic analysis did not run"


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
    # App identity, and what the brand-impersonation checks made of it. `app_label`
    # and `icon_phash` are reported even when nothing matched, so an analyst can see
    # WHAT was compared. `impersonation` carries findings plus the coverage notes
    # explaining which of the four checks could not run and why — an empty findings
    # list with a full coverage list means "not assessed", not "clean".
    app_label: Optional[str] = None
    icon_phash: Optional[str] = None
    impersonation: Optional[dict] = None
    # MITRE ATT&CK Mobile context for predicted_ttps — same ontology lookup
    # GraphRAG grounds its narrative in (app/graph/ontology.get_technique_context),
    # so the UI's technique names/tactics/descriptions can never drift from what
    # the LLM was told. Each entry: {technique_id, name, tactic, description,
    # probability}, sorted by probability descending. Empty when predicted_ttps
    # is empty (nothing predicted, or classifier evidence gate withheld a verdict).
    ttp_context: list[dict] = []
    # Other previously-cached samples correlated via shared MITRE techniques,
    # shared C2 infrastructure, and/or a reused signing certificate — a
    # graph-native query over Neo4j (app/graph/cache.find_related_samples)
    # that a flat JSON cache can't do cheaply. Each entry: {sha256, app_name,
    # family, risk_score, shared_techniques, shared_c2, shared_cert}. Empty
    # when nothing in the graph overlaps, or when Neo4j is unreachable (fails
    # closed, same as the rest of cache.py).
    related_samples: list[dict] = []
    # Phase 8, opt-in only (see DynamicVerificationResult). None when the
    # request did not ask for it (the default) — distinct from a populated
    # result with ran=False, which means it was requested but didn't complete.
    dynamic_verification: Optional[DynamicVerificationResult] = None


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
    # True when brand-impersonation evidence raised the verdict above what the
    # weighted components alone produced (scoring.IMPERSONATION_SCORE_FLOOR). The
    # distinction matters to an analyst: a cloned banking app can be near-inert code
    # scoring in the teens, and without this flag the report would read as though the
    # behaviour earned the verdict.
    impersonation_floor_applied: bool = False
    # True when archive-integrity tampering raised the verdict above the weighted
    # components (scoring.CONTAINER_TAMPER_SCORE_FLOOR). Same distinction as
    # impersonation_floor_applied: the report must not read as though quiet
    # components earned this score when what earned it was a ZIP built to make
    # those components read quiet.
    container_tamper_floor_applied: bool = False
    # Same distinction as impersonation_floor_applied, for the Phase 8 dynamic-
    # confirmation floor (see DYNAMIC_CONFIRMATION_SCORE_FLOOR) — true when a
    # confirmed C2 contact or executed DCL payload raised the verdict above what
    # the weighted components alone produced. Both flags can be true at once.
    dynamic_confirmation_floor_applied: bool = False
    # Same distinction again, for OPAQUE_REPUTATION_SCORE_FLOOR — true when the
    # sample is externally flagged as known malware AND static parsing recovered
    # nothing, so the weighted components could not speak. Tells an analyst the
    # verdict rests on external reputation plus opacity, not on anything this
    # pipeline observed itself, which is a materially weaker claim.
    opaque_reputation_floor_applied: bool = False
    # The weighted total before any floor. Equal to total_score unless a floor moved
    # it. None on the hot path, where no component was recomputed.
    weighted_score: Optional[float] = None


class AnalysisCoverage(BaseModel):
    """
    How much of the APK the analyser actually read. Every field is observed, not
    estimated — see app/core/coverage.py for why this is deliberately not a
    probabilistic confidence score, and why it does not feed the risk score.

    The distinction it draws is the one the score cannot: an unparseable APK and
    a genuinely ambiguous app both land on 50.0 / `suspicious`, and only coverage
    says which is which.
    """
    # Stage outcomes. Optional ones use None for "not run on this path" — the
    # same convention as RiskScoreBreakdown's components, never 0/False, which
    # would assert a negative result the pipeline never established.
    container_opened: bool
    manifest_parsed: bool
    code_recovered: bool
    # Optional because the hot path cannot know it: total_nodes_parsed is not
    # persisted in the cached record, so a cache hit reports None rather than
    # False, which would deny a CFG the original analysis did build.
    cfg_built: Optional[bool] = None
    reputation_checked: Optional[bool] = None
    identity_checked: Optional[bool] = None
    # None = Phase 8 was not requested (the default). False = it was requested
    # and did not complete, which is a real gap. Mirrors
    # DynamicVerificationResult.ran, which must never read as "nothing found".
    dynamic_ran: Optional[bool] = None
    # Quantitative code coverage. `method_coverage` is analysed/present, and is
    # None when either count is unmeasured rather than 0.0, which would claim a
    # measured absence.
    dex_method_count: Optional[int] = None
    analyzed_method_count: Optional[int] = None
    method_coverage: Optional[float] = None
    method_parse_failure_rate: float = 0.0
    # Share of applicable stages that succeeded. A ratio of observed outcomes,
    # NOT a probability that the verdict is correct.
    completeness: float
    # none | partial | full | cached
    level: str
    gaps: list[str] = []
    # False when the verdict band is an artefact of the analysis failing rather
    # than a finding about the app. A caller that renders a band without checking
    # this will present "suspicious" for a file it never opened.
    verdict_supported: bool


class AnalysisReport(BaseModel):
    manifest: AnalysisManifest
    risk_score: RiskScoreBreakdown
    # Required, with no default, on purpose: there are four AnalysisReport
    # construction sites and a defaulted field would let a fifth silently ship
    # without coverage. Pydantic raises here instead.
    coverage: AnalysisCoverage
    narrative_report: str
    limitations: list[str]
    # Which post-generation fabrication checks ran over the narrative, and whether
    # each passed. None when no narrative was generated (LLM unreachable) — the
    # checks did not run, which is not the same as passing, and the UI must not
    # render an absent result as a green badge.
    grounding: Optional[dict] = None
