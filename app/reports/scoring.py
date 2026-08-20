"""
Deterministic risk score, 0-100, per the design doc's weighted formula.

Original formula (paper spec):
    0.30 * classifier_probability
  + 0.20 * permission_api_risk
  + 0.20 * ttp_severity
  + 0.15 * graph_obfuscation_score
  + 0.10 * reputation_score
  + 0.05 * ioc_score

Revised formula (§9.3 fix — forensic anchors added as first-class component):
    0.25 * classifier_confidence
  + 0.20 * permission_api_risk
  + 0.15 * ttp_severity
  + 0.15 * forensic_anchor          ← NEW: deterministic behavioral evidence
  + 0.15 * obfuscation / coverage
  + 0.05 * reputation
  + 0.05 * ioc

Rationale for rebalancing: GUARD paper SHAP analysis (§10.1) found that
deterministic behavioral flags are the strongest predictors in a structurally
comparable system — weighted at least as heavily as classifier confidence.
Classifier weight reduced from 0.30→0.25 to make room; ttp_severity reduced
from 0.20→0.15 (it was already dead-weight before the FAMILY_TO_TTPS fix);
obfuscation raised from 0.15→0.15 (unchanged); reputation reduced 0.10→0.05.

Every component function below is a real, if simple, calculation — not a
placeholder returning a constant. Tune the internals as you validate
against your demo set, but the formula weights themselves shouldn't drift
without a documented reason.
"""
import math

from app.core.config import TTP_SEVERITY_WEIGHTS, TACTIC_SEVERITY
from app.core.schemas import RiskScoreBreakdown, ObfuscationSignal
from app.ml.labels import TECHNIQUE_TACTIC

# Zero-day indicator thresholds (§zero-day): strong deterministic/structural evidence
# while model familiarity is low ⇒ flag as a possible novel/first-seen variant.
ZERO_DAY_ANCHOR_MIN = 0.5   # forensic_anchor_component (0-1) at/above this = strong proven evidence
ZERO_DAY_OBF_MIN = 0.5      # obfuscation_component (0-1) at/above this = strong evasion/coverage signal
ZERO_DAY_CONF_MAX = 0.4     # classifier_confidence_component (0-1) below this = weak model familiarity

# ── Calibration constants (N6-N8) ─────────────────────────────────────────────
# Every number in this block was picked by measuring the 353-APK corpus
# (220 F-Droid benign / 133 MalwareBazaar malware), not by intuition. Re-derive
# them with `python scripts/score_corpus.py` after any change to the analysis
# stages; the script prints the same tables the values below were chosen from.

# classifier_confidence_component (N8). Fallback decision boundary for a technique
# the trained bundle carries no calibrated threshold for — matches
# pipeline.TTP_PREDICT_THRESHOLD, which decides what reaches this function.
DEFAULT_TTP_THRESHOLD = 0.5
# Summed threshold margin at which confidence reaches 1 - 1/e ≈ 0.63. Malware
# predicts a median of 8 techniques (mass well past this); the 7 clean apps that
# predict anything at all mostly predict one or two.
CONFIDENCE_SATURATION_MASS = 2.5

# obfuscation_component (N7). Measured over the corpus, all four original inputs
# were useless: string-pool entropy tops out at 3.47 against a 7.2 threshold and runs
# the wrong way (benign 3.28 vs malware 2.78); `flattening_suspected` is an
# existential over every analysed method and fired on 30/30 sampled clean apps;
# `unresolved_reflection_targets` is a documented stub pinned at 0;
# `method_parse_failure_rate` was 0.0 on all 353. So the component was a constant
# 6.00/15 for 216 of 220 clean apps and 108 of 133 malware — 39.3% of cap for benign
# against 32.5% for malware, an inverted constant.
#
# Reading flattening as a prevalence instead does not rescue it: over the full corpus
# the share of analysed methods that look flattened is benign p75 0.119 against
# malware p75 0.118, and every candidate threshold from 0.05 to 0.50 gives a lift
# between 0.79 and 1.07. It is measured and reported, and it is not scored.
#
# What is left is the thing the component exists for: evidence that the analyser was
# denied the code.
CODE_NOT_RECOVERED_WEIGHT = 0.60
# An Android class that exists at all costs a constructor and at least one lifecycle
# override, so a manifest declaring N components needs on the order of 2N methods
# before anything else. Below that the recovered DEX cannot be the app the manifest
# describes — a loader stub whose payload is decrypted at runtime. Measured, the
# lowest ratio in the 219-app clean corpus is 56.85 methods per declared component,
# 28x above this floor; on the malware side 12 samples fall below it, one of them
# declaring 539 activities, 42 services and 49 receivers with 57 methods in its DEX.
MIN_METHODS_PER_DECLARED_COMPONENT = 2.0
PARSE_FAILURE_MIN = 0.10            # below this, CFG failures are ordinary noise
PARSE_FAILURE_WEIGHT = 2.0          # rate * this, capped at PARSE_FAILURE_CAP
PARSE_FAILURE_CAP = 0.40
UNRESOLVED_REFLECTION_WEIGHT = 0.10

# ioc_component (N6). The old tiers let three weak signals saturate the cap: a
# YARA term of severity * 0.3 * min(n, 3) paid 0.765 to any app matching three
# rules at severity 0.85, and clean apps match a mean of 10.8 community rules at
# exactly that severity. Rule-declared severity is author metadata, not a measure of
# specificity, so YARA breadth no longer multiplies. Evidence is split: signals that
# identify *this* sample can reach the cap alone; ubiquitous ones share a small
# allowance and can never carry a verdict by themselves.
IOC_SIGNATURE_WEIGHT = 0.50         # per hash/cert signature hit
IOC_EXTRACTED_C2_WEIGHT = 0.35      # per exact extracted IoC (bot token, .onion, …)
IOC_EXTRACTED_C2_CAP = 0.70
IOC_SECONDARY_DEX_WEIGHT = 0.20     # per hidden/secondary DEX payload
IOC_SECONDARY_DEX_CAP = 0.40
IOC_YARA_WEIGHT = 0.25              # * max rule severity, no count multiplier
IOC_CERT_ANOMALY_WEIGHT = 0.10
IOC_DROPPER_WEIGHT = 0.10
IOC_FORENSIC_C2_WEIGHT = 0.10
IOC_CIRCUMSTANTIAL_CAP = 0.35       # joint ceiling on the four weak terms above

# ── Verdict band boundaries ───────────────────────────────────────────────────
# Each boundary answers a different question, so each is set by its own criterion
# rather than by cutting 0-100 into four. Measured *after* the N5-N8 component fixes,
# over two full corpus runs; reproduce with `python scripts/score_corpus.py`.
#
#   clean corpus:   median 11.81, p95 26.73, max 53.33     (220 apps)
#   malware corpus: p25 64.33-65.99, median 69.15-72.64     (133 samples)
#
# The malware range is given as a span across the two runs on purpose. Phase 1.5
# queries VirusTotal and MalwareBazaar live, so `signature_match_count` — and through
# it `ioc_component` and `reputation_component` — depends on what those services
# answered that day: mean signature hits per malware sample were 0.80 in one run and
# 0.15 in the next, moving malware totals by about four points. Boundaries are chosen
# to be insensitive to that; the clean side does not move (0.02 hits either run).
#
# `low` — "costs no analyst time". Above the clean corpus's 95th percentile (26.73),
# leaving 212 of 220 clean apps here. 5-14 malware land here too; every one of them
# recovered no forensic evidence at all, which is a limit on analysis depth that no
# boundary can move.
BAND_LOW_CEILING = 30.0
# `suspicious` — the ceiling below which the tool never asserts a verdict. Above the
# *highest* score any app in the 220-app clean corpus reaches (53.33), so `high` is a
# band the clean corpus never enters, with 6.67 points of margin. Youden's J peaks far
# lower, at 27.0 (J=0.921); that difference is deliberately spent on never showing an
# analyst a clean app marked `high`.
BAND_SUSPICIOUS_CEILING = 60.0
# `high` — the strongest claim, so it is placed where a few points of third-party
# lookup variance cannot move dozens of samples across it. Below the malware first
# quartile in both runs (64.33 / 65.99), which puts 98-102 of 133 samples (74-77%) at
# `malicious` either way; at 70 the same two runs gave 55 and 85, because 70 falls
# inside the distribution's mode. 11.7 points clear of the highest clean-corpus score.
# Was 80.0, where only 12 of 133 malware reached `malicious` at all.
BAND_HIGH_CEILING = 65.0

RISKY_PERMISSIONS = {
    "android.permission.BIND_ACCESSIBILITY_SERVICE": 1.0,
    "android.permission.READ_SMS": 0.8,
    "android.permission.RECEIVE_SMS": 0.8,
    "android.permission.SEND_SMS": 0.7,
    "android.permission.SYSTEM_ALERT_WINDOW": 0.6,
    "android.permission.REQUEST_INSTALL_PACKAGES": 0.5,
    "android.permission.PACKAGE_USAGE_STATS": 0.55,
    "android.permission.QUERY_ALL_PACKAGES": 0.5,
    "android.permission.BIND_DEVICE_ADMIN": 0.7,
    "android.permission.RECEIVE_BOOT_COMPLETED": 0.35,
}

# Per-behavior severity weights for the forensic anchor component (§9.3).
# Higher = more directly indicative of active banking fraud capability.
BEHAVIOR_SEVERITY = {
    "STEALTH_SMS_INTERCEPTION": 1.0,  # proven SMS interception API present
    "OTP_INTERCEPTION":         0.95,  # OTP theft string + SMS permissions
    "CREDENTIAL_HARVESTING":    0.9,   # accessibility/webview overlay pattern
    "ACCESSIBILITY_ABUSE":      0.9,   # keylogging / gesture control capability
    "C2_BEHAVIOR":              0.75,  # high-signal C2 channels (telegram/firebase/onion)
    "DYNAMIC_CODE_LOADING":     0.7,   # dropper / stage-2 loading
    "DYNAMIC_REFLECTION":       0.6,   # evasion capability
    "CRYPTOGRAPHY_USAGE":       0.4,   # present in many benign apps too
}

# Permission-matrix flag severity (banking-trojan combo patterns from apk_static).
MATRIX_FLAG_SEVERITY = {
    "OVERLAY_ATTACK_PATTERN":         0.95,
    "OVERLAY_BOOT_PERSISTENCE":       0.8,
    "SMS_OTP_STEALER_PATTERN":        1.0,
    "SMS_OTP_SENDER_PATTERN":         0.9,
    "DROPPER_STAGE2_PATTERN":         0.85,
    "DEVICE_ADMIN_PERSISTENCE":       0.75,
    "BANKING_TARGET_ENUMERATION":     0.7,
    "ACCESSIBILITY_FULL_CONTROL":     0.95,
    "ACCESSIBILITY_WINDOW_CONTENT":   0.9,
    "ACCESSIBILITY_GESTURE_CONTROL":  0.85,
    "ACCESSIBILITY_KEYLOGGING_MASK":  0.95,
}


def classifier_confidence_component(
    predicted_ttps: dict[str, float],
    evidence_present: bool = True,
    ttp_thresholds: dict[str, float] | None = None,
) -> float:
    """
    Turns the multi-label TTP model's output into one calibrated 0-1 confidence.

    `evidence_present=False` zeroes the component outright. The model has a benign
    class now, but it still cannot be asked "is this malware?" — it answers "which
    techniques does this sample exhibit?" — so a sample that yielded no parsed code
    and no forensic anchors gets no vote at all rather than the label prior's
    opinion (see pipeline.has_deterministic_evidence).

    N8: this used to return `max(predicted_ttps.values())`, which discards the two
    things that actually distinguish a real TTP profile from a lucky label:

      * **Where the probability sits relative to its own decision boundary.** The
        per-label thresholds calibrated at training time range from 0.10 to 0.90
        (`ttp_metrics.json`), because label prevalence ranges from 0.02 to 0.75. A
        0.98 on T1516, whose boundary is 0.10, is not the same evidence as a 0.98
        on T1471, whose boundary is 0.90. Each probability is therefore rescaled to
        its margin past its own threshold.
      * **Breadth.** Measured over the 353-sample corpus, malware predicts a median
        of 8 techniques and 213 of 220 clean apps predict none. One technique, however
        confident, is a thin basis for a 25-point component — `com.symeonchen.wakeupscreen`
        drew 24.57 of 25 from a single label. Margins are summed into an evidence
        mass and squashed, so confidence grows with corroborating techniques and
        saturates once there are enough of them.

    A clean app that the model genuinely reads as multi-technique malware still scores
    high here; that is a training-data problem (the negatives are 220 F-Droid
    utilities) and no scoring function can talk it out of its own prediction.
    """
    if not evidence_present or not predicted_ttps:
        return 0.0

    thresholds = ttp_thresholds or {}
    mass = 0.0
    for technique, prob in predicted_ttps.items():
        thr = thresholds.get(technique, DEFAULT_TTP_THRESHOLD)
        headroom = max(1e-6, 1.0 - thr)
        mass += min(1.0, max(0.0, (prob - thr) / headroom))

    return 1.0 - math.exp(-mass / CONFIDENCE_SATURATION_MASS)


def permission_api_risk_component(
    permissions: list[str],
    permission_matrix_flags: list[str] | None = None,
) -> float:
    """
    Single-permission risk plus multi-permission matrix combos
    (overlay attack, OTP stealer, dropper patterns from apk_static).
    """
    if not permissions and not permission_matrix_flags:
        return 0.0
    scores = [RISKY_PERMISSIONS.get(p, 0.0) for p in (permissions or [])]
    matched = [s for s in scores if s > 0]
    base = 0.0
    if matched:
        base = min(1.0, sum(matched) / len(matched) + 0.1 * (len(matched) - 1))

    # Matrix flags are stronger than individual perms — boost toward 1.0
    matrix_boost = 0.0
    for flag in permission_matrix_flags or []:
        matrix_boost = max(matrix_boost, MATRIX_FLAG_SEVERITY.get(flag, 0.6))
    if matrix_boost > 0:
        # Blend: matrix evidence dominates when present
        return min(1.0, max(base, 0.55 * base + 0.55 * matrix_boost))
    return base


def _technique_severity(ttp: str) -> float:
    """
    Severity for one technique: per-technique override first, then a tactic-derived
    fallback (so EVERY Mobile technique the multi-label model can predict gets a
    principled weight), then DEFAULT.
    """
    if ttp in TTP_SEVERITY_WEIGHTS:
        return TTP_SEVERITY_WEIGHTS[ttp]
    tactic = TECHNIQUE_TACTIC.get(ttp)
    if tactic and tactic in TACTIC_SEVERITY:
        return TACTIC_SEVERITY[tactic]
    return TTP_SEVERITY_WEIGHTS["DEFAULT"]


def ttp_severity_component(predicted_ttps: dict[str, float]) -> float:
    """
    Fed by MITRE technique IDs predicted DIRECTLY by the multi-label TTP classifier
    (cold path) or the FAMILY_TO_TTPS bridge (legacy/hot path). Severity now covers
    the full Mobile technique space via _technique_severity, not just 5 hardcoded IDs.
    """
    if not predicted_ttps:
        return 0.0
    weighted = [prob * _technique_severity(ttp) for ttp, prob in predicted_ttps.items()]
    return min(1.0, sum(weighted) / len(weighted))


def forensic_anchor_component(matched_anchor_behaviors: set[str]) -> float:
    """
    §9.3 fix: score deterministic forensic-dictionary matches directly.

    Unlike the classifier (probabilistic), these are grounded in proven API
    presence in the binary — the strongest static predictor per GUARD SHAP.
    Scaled by per-behavior severity weights so a confirmed SMS interception
    anchor counts more than a generic crypto usage hit.
    """
    if not matched_anchor_behaviors:
        return 0.0
    weights = [
        BEHAVIOR_SEVERITY.get(b, 0.5) for b in matched_anchor_behaviors
    ]
    # Mean severity of matched behaviors, with a bonus for breadth
    # (multiple distinct behaviors signal more sophisticated malware).
    breadth_bonus = min(0.2, 0.05 * (len(weights) - 1))
    return min(1.0, (sum(weights) / len(weights)) + breadth_bonus)


def obfuscation_component(
    obfuscation: ObfuscationSignal,
    entropy_threshold: float | None = None,
) -> float:
    """
    §9.5: coverage gaps raise the score, not just the narrative text. An APK that
    evades analysis is *more* suspicious than a fully transparent one, all else equal.

    N7 rewrite. The four old inputs measured, over the 353-APK corpus:

      | input                            | benign          | malware        |
      |----------------------------------|-----------------|----------------|
      | `string_entropy_score` >= 7.2    | never (max 3.47)| never          |
      | `flattening_suspected`           | 30/30 sampled   | 23/28 sampled  |
      | `unresolved_reflection_targets`  | 0 (stub)        | 0 (stub)       |
      | `method_parse_failure_rate` >=.1 | 0/353           | 0/353          |

    Three were dead and the fourth was a near-constant pointing the wrong way, which
    is why the component read exactly 6.00/15 for 216 of 220 clean apps and 108 of
    133 malware — 39.3% of cap for benign against 32.5% for malware, an inverted
    constant occupying 15% of the score.

    * Mean per-string Shannon entropy cannot reach 7.2 bits: that needs ~147 distinct
      characters per string. It is also inverted, because large clean apps carry
      longer, more varied literals than a packed stub does. It stays on
      ObfuscationSignal — it is one of the three frozen OBFUSCATION_FEATURES and the
      coverage note still reports it — but it no longer moves the score.
      `entropy_threshold` is kept in the signature so call sites need not change.
    * Flattening prevalence is measured and reported but not scored: benign p75 0.119
      against malware p75 0.118, and no threshold from 0.05 to 0.50 gives a lift
      outside 0.79-1.07. Paying points for it is paying for noise.
    * Manifest-vs-code is new, and is what the component now rests on: a DEX that
      cannot possibly implement the manifest it ships with. Twelve corpus malware fail
      that test — including a sample declaring 539 activities, 42 services and 49
      receivers with 57 methods — and no clean app comes within 28x of it. Those
      samples used to score 0.0 here, because an empty CFG set has nothing that can
      look flattened: the component that exists to measure evasion read zero on
      exactly the samples that defeated the analyser.

    On this corpus that leaves the component at 0.0 for every clean app and non-zero
    only where the code genuinely could not be reached. A component that is silent
    when it has nothing to say beats one that pays 6.00 to everybody.
    """
    score = 0.0

    # The recovered code cannot account for the app the manifest describes — packed,
    # encrypted, or staged at runtime. `None` on either field means "not measured",
    # which earns nothing: only a measurement is evidence.
    declared = obfuscation.declared_component_count
    recovered = obfuscation.dex_method_count
    if recovered is not None:
        if recovered == 0 or (
            declared
            and recovered < MIN_METHODS_PER_DECLARED_COMPONENT * declared
        ):
            score += CODE_NOT_RECOVERED_WEIGHT

    # Methods that broke Androguard's block parser, over those attempted.
    if obfuscation.method_parse_failure_rate >= PARSE_FAILURE_MIN:
        score += min(
            PARSE_FAILURE_CAP,
            PARSE_FAILURE_WEIGHT * obfuscation.method_parse_failure_rate,
        )

    # Reflection targets that constant propagation could not resolve. Still a stub in
    # obfuscation.count_reflection_calls (always 0); wired so that implementing the
    # taint pass turns it on rather than requiring a second change here.
    if obfuscation.unresolved_reflection_targets > 0:
        score += UNRESOLVED_REFLECTION_WEIGHT

    return min(1.0, score)


def reputation_component(
    cache_hit: bool,
    cached_score: float | None,
    is_known_malware: bool = False,
) -> float:
    """
    If we got a cache hit, reputation is informed by prior known score.
    If no cache hit (first-seen sample), reputation defaults to neutral —
    it's neither vouched-for nor known-bad on this axis alone.

    §sig: if the sample matches a known-malware signature hash, reputation
    jumps to near-maximum regardless of cache state.
    """
    if is_known_malware:
        return 0.95  # known-bad sample — near-maximum reputation risk
    if cache_hit and cached_score is not None:
        return min(1.0, cached_score / 100.0)
    return 0.3  # neutral-low prior for unknown samples


def ioc_component(
    matched_c2_indicators: int,
    signature_match_count: int = 0,
    yara_match_count: int = 0,
    yara_max_severity: float = 0.0,
    extracted_c2_count: int = 0,
    cert_anomaly_count: int = 0,
    secondary_dex_count: int = 0,
    dropper_signal_count: int = 0,
) -> float:
    """
    IOC score — signature detection, YARA results, extracted C2 indicators,
    certificate anomalies, and dropper payload signals.

    N6 rewrite. The old tiers summed everything into one `min(1.0, ...)`, which let
    ubiquitous evidence saturate the cap on its own. Measured, clean apps drew 93.4%
    of the 5-point cap against malware's 97.6% — a component with no information in
    it. Two causes, in order of size:

      * **YARA.** `severity * 0.3 * min(n, 3)` paid 0.765 to anything matching three
        rules at severity 0.85, and a clean app matches a mean of 10.8 of the 498
        loaded community rules, at exactly that severity (`IP`, `domain`,
        `contains_base64` and friends). Rule-declared severity is metadata written by
        the rule's author, not a measurement of how specific the rule is, so breadth
        across a generic corpus no longer multiplies: YARA contributes
        `IOC_YARA_WEIGHT * max_severity`, once. See T11 for the corpus skew itself.
      * **`self_signed`** on every APK, worth 0.15 — fixed upstream in
        apk_static.analyze_certificate_anomalies.

    Evidence is now split by whether it identifies *this* sample:

      * **Attributable** — a signature hash/cert hit, an exact extracted IoC, a hidden
        DEX payload. Any of these can carry the component to its cap alone, because
        each names something specific about this file.
      * **Circumstantial** — YARA, certificate anomalies, dropper heuristics, forensic
        C2 strings. Jointly capped at IOC_CIRCUMSTANTIAL_CAP, so no pile of generic
        hits can imply a verdict on its own.

    Caveat for anyone reading corpus numbers: `signature_match_count` is 1 for every
    malware sample in `data/ttp_apks/` because those hashes came from MalwareBazaar
    and are in the signature DB. On this corpus it is a tautology, not a measurement.
    """
    attributable = 0.0
    attributable += signature_match_count * IOC_SIGNATURE_WEIGHT
    attributable += min(
        IOC_EXTRACTED_C2_CAP, extracted_c2_count * IOC_EXTRACTED_C2_WEIGHT
    )
    attributable += min(
        IOC_SECONDARY_DEX_CAP, secondary_dex_count * IOC_SECONDARY_DEX_WEIGHT
    )

    circumstantial = 0.0
    if yara_match_count > 0:
        circumstantial += IOC_YARA_WEIGHT * yara_max_severity
    circumstantial += cert_anomaly_count * IOC_CERT_ANOMALY_WEIGHT
    circumstantial += dropper_signal_count * IOC_DROPPER_WEIGHT
    circumstantial += matched_c2_indicators * IOC_FORENSIC_C2_WEIGHT

    return min(1.0, attributable + min(IOC_CIRCUMSTANTIAL_CAP, circumstantial))


def _band_for(total: float) -> str:
    """Verdict band thresholds, shared so a cache hit reports the same band
    a cold-path run would have for the same total_score."""
    if total <= BAND_LOW_CEILING:
        return "low"
    if total <= BAND_SUSPICIOUS_CEILING:
        return "suspicious"
    if total <= BAND_HIGH_CEILING:
        return "high"
    return "malicious"


def compute_risk_score(
    predicted_ttps: dict[str, float],
    permissions: list[str],
    obfuscation: ObfuscationSignal,
    # Retained for call-site compatibility and no longer read: string-pool entropy
    # stopped contributing to the score in N7 — see obfuscation_component. It still
    # drives the coverage note in build_obfuscation_signal, which is where the
    # threshold does its remaining work.
    entropy_threshold: float,
    matched_anchor_behaviors: set[str] | None = None,
    cache_hit: bool = False,
    cached_score: float | None = None,
    matched_c2_indicators: int = 0,
    # Signature detection & YARA scanning inputs
    signature_match_count: int = 0,
    yara_match_count: int = 0,
    yara_max_severity: float = 0.0,
    is_known_malware: bool = False,
    # Advanced Android static anchors
    permission_matrix_flags: list[str] | None = None,
    extracted_c2_count: int = 0,
    cert_anomaly_count: int = 0,
    secondary_dex_count: int = 0,
    dropper_signal_count: int = 0,
    # See classifier_confidence_component.
    classifier_evidence_present: bool = True,
    ttp_thresholds: dict[str, float] | None = None,
) -> RiskScoreBreakdown:
    if matched_anchor_behaviors is None:
        matched_anchor_behaviors = set()

    # Both model-derived components are gated together: if the classifier had no
    # grounds for an opinion, the severity of the techniques it named is just as
    # ungrounded. The deterministic components (permissions, anchors, obfuscation,
    # IOC) are untouched — they are measurements, not predictions.
    c1 = classifier_confidence_component(
        predicted_ttps,
        evidence_present=classifier_evidence_present,
        ttp_thresholds=ttp_thresholds,
    )
    c2 = permission_api_risk_component(
        permissions, permission_matrix_flags=permission_matrix_flags
    )
    c3 = ttp_severity_component(predicted_ttps) if classifier_evidence_present else 0.0
    c4 = forensic_anchor_component(matched_anchor_behaviors)
    c5 = obfuscation_component(obfuscation)
    c6 = reputation_component(cache_hit, cached_score, is_known_malware)
    c7 = ioc_component(
        matched_c2_indicators,
        signature_match_count=signature_match_count,
        yara_match_count=yara_match_count,
        yara_max_severity=yara_max_severity,
        extracted_c2_count=extracted_c2_count,
        cert_anomaly_count=cert_anomaly_count,
        secondary_dex_count=secondary_dex_count,
        dropper_signal_count=dropper_signal_count,
    )

    # Revised weights (§9.3): 0.25 + 0.20 + 0.15 + 0.15 + 0.15 + 0.05 + 0.05 = 1.00
    total = (
        0.25 * c1 + 0.20 * c2 + 0.15 * c3 + 0.15 * c4 + 0.15 * c5 + 0.05 * c6 + 0.05 * c7
    ) * 100

    band = _band_for(total)

    # Zero-day / novel-variant signal: the model-free components (deterministic
    # forensic anchors, structural obfuscation/coverage) carry strong evidence while
    # the classifier is unfamiliar (low confidence / empty predictions). This is
    # exactly the first-seen sample the family/TTP model has not learned yet. It does
    # not change the numeric weights — the deterministic components already provide
    # the score floor — it surfaces the situation for the analyst / report.
    zero_day_indicator = (
        (c4 >= ZERO_DAY_ANCHOR_MIN or c5 >= ZERO_DAY_OBF_MIN)
        and c1 < ZERO_DAY_CONF_MAX
        and not cache_hit
    )

    return RiskScoreBreakdown(
        classifier_confidence_component=round(c1 * 25, 2),
        permission_api_component=round(c2 * 20, 2),
        ttp_severity_component=round(c3 * 15, 2),
        forensic_anchor_component=round(c4 * 15, 2),
        obfuscation_component=round(c5 * 15, 2),
        reputation_component=round(c6 * 5, 2),
        ioc_component=round(c7 * 5, 2),
        total_score=round(total, 2),
        verdict_band=band,
        zero_day_indicator=zero_day_indicator,
    )
