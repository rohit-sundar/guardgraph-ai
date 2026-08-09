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
from app.core.config import TTP_SEVERITY_WEIGHTS, TACTIC_SEVERITY
from app.core.schemas import RiskScoreBreakdown, ObfuscationSignal
from app.ml.labels import TECHNIQUE_TACTIC

# Zero-day indicator thresholds (§zero-day): strong deterministic/structural evidence
# while model familiarity is low ⇒ flag as a possible novel/first-seen variant.
ZERO_DAY_ANCHOR_MIN = 0.5   # forensic_anchor_component (0-1) at/above this = strong proven evidence
ZERO_DAY_OBF_MIN = 0.5      # obfuscation_component (0-1) at/above this = strong evasion/coverage signal
ZERO_DAY_CONF_MAX = 0.4     # classifier_confidence_component (0-1) below this = weak model familiarity

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
) -> float:
    """
    Uses the max class confidence as the classifier signal.

    `evidence_present=False` zeroes the component outright. The TTP model is
    trained on 134 samples that are *all* malware — no benign class — so
    it has learned label priors as much as evidence: an all-zeros 179-feature
    vector still predicts 9 techniques at >= 0.5, several of them well above their
    training prevalence (T1471 at 0.5446 against 0.097). A sample that yielded no
    parsed code and no forensic anchors produces exactly that vector, and the
    prior alone was worth 24.10 of the 33.92 "suspicious" score a 35-byte text
    file renamed `.apk` received. Until the training set gains a benign class
    (`scripts/build_ttp_dataset.py --benign-dir`), the classifier gets no vote
    when it had nothing to look at.
    """
    if not evidence_present or not predicted_ttps:
        return 0.0
    return max(predicted_ttps.values())


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


def obfuscation_component(obfuscation: ObfuscationSignal, entropy_threshold: float) -> float:
    """
    §9.5 fix: coverage gaps now raise the score, not just the narrative text.
    An APK that evades analysis (via native libs, reflection, parse failures)
    is *more* suspicious than a fully-transparent one, all else equal.
    """
    score = 0.0
    if obfuscation.string_entropy_score >= entropy_threshold:
        score += 0.5
    if obfuscation.flattening_suspected:
        score += 0.4
    if obfuscation.unresolved_reflection_targets > 0:
        score += 0.1
    # §9.5/9.6: parse failure rate > 10% → additional evasion signal
    if obfuscation.method_parse_failure_rate >= 0.10:
        score += min(0.3, obfuscation.method_parse_failure_rate)
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
    IOC score — combines C2 network indicators with signature detection,
    YARA scan results, certificate anomalies, and dropper payload signals.

    Scoring tiers:
    - Signature hit: +0.5 per match (hash match = near-certain bad)
    - YARA hit: +severity * 0.3 per match (rule-severity-weighted)
    - Extracted C2 IoCs (telegram/firebase/onion/raw IP): +0.35 each
    - Forensic C2_BEHAVIOR string hits: +0.2 each (weaker than exact IoCs)
    - Certificate anomalies (debug key / self-signed junk): +0.15 each
    - Secondary/hidden DEX payloads: +0.2 each (capped)
    - Dropper signals: +0.1 each (capped)
    """
    score = 0.0

    # Signature matches — strongest IOC signal
    score += signature_match_count * 0.5

    # YARA matches — severity-weighted
    if yara_match_count > 0:
        score += yara_max_severity * 0.3 * min(yara_match_count, 3)

    # Exact extracted C2 IoCs (telegram bot tokens, firebase, etc.)
    score += min(0.7, extracted_c2_count * 0.35)

    # Forensic dictionary C2_BEHAVIOR string hits (weaker)
    score += min(0.3, matched_c2_indicators * 0.2)

    # Certificate anomalies
    score += min(0.4, cert_anomaly_count * 0.15)

    # Hidden / secondary DEX payloads
    score += min(0.4, secondary_dex_count * 0.2)

    # Dropper / dynload / overlay-template signals
    score += min(0.3, dropper_signal_count * 0.1)

    return min(1.0, score)


def _band_for(total: float) -> str:
    """Verdict band thresholds, shared so a cache hit reports the same band
    a cold-path run would have for the same total_score."""
    if total <= 30:
        return "low"
    if total <= 60:
        return "suspicious"
    if total <= 80:
        return "high"
    return "malicious"


def compute_risk_score(
    predicted_ttps: dict[str, float],
    permissions: list[str],
    obfuscation: ObfuscationSignal,
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
) -> RiskScoreBreakdown:
    if matched_anchor_behaviors is None:
        matched_anchor_behaviors = set()

    # Both model-derived components are gated together: if the classifier had no
    # grounds for an opinion, the severity of the techniques it named is just as
    # ungrounded. The deterministic components (permissions, anchors, obfuscation,
    # IOC) are untouched — they are measurements, not predictions.
    c1 = classifier_confidence_component(
        predicted_ttps, evidence_present=classifier_evidence_present
    )
    c2 = permission_api_risk_component(
        permissions, permission_matrix_flags=permission_matrix_flags
    )
    c3 = ttp_severity_component(predicted_ttps) if classifier_evidence_present else 0.0
    c4 = forensic_anchor_component(matched_anchor_behaviors)
    c5 = obfuscation_component(obfuscation, entropy_threshold)
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
