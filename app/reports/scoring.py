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
from app.core.config import TTP_SEVERITY_WEIGHTS
from app.core.schemas import RiskScoreBreakdown, ObfuscationSignal

RISKY_PERMISSIONS = {
    "android.permission.BIND_ACCESSIBILITY_SERVICE": 1.0,
    "android.permission.READ_SMS": 0.8,
    "android.permission.RECEIVE_SMS": 0.8,
    "android.permission.SEND_SMS": 0.7,
    "android.permission.SYSTEM_ALERT_WINDOW": 0.6,
    "android.permission.REQUEST_INSTALL_PACKAGES": 0.5,
}

# Per-behavior severity weights for the forensic anchor component (§9.3).
# Higher = more directly indicative of active banking fraud capability.
BEHAVIOR_SEVERITY = {
    "STEALTH_SMS_INTERCEPTION": 1.0,  # proven SMS interception API present
    "OTP_INTERCEPTION":         0.95,  # OTP theft string + SMS permissions
    "CREDENTIAL_HARVESTING":    0.9,   # accessibility/webview overlay pattern
    "C2_BEHAVIOR":              0.7,   # network contact (also benign, lower weight)
    "DYNAMIC_REFLECTION":       0.6,   # evasion capability
    "CRYPTOGRAPHY_USAGE":       0.4,   # present in many benign apps too
}


def classifier_confidence_component(predicted_ttps: dict[str, float]) -> float:
    """Uses the max class confidence as the classifier signal."""
    if not predicted_ttps:
        return 0.0
    return max(predicted_ttps.values())


def permission_api_risk_component(permissions: list[str]) -> float:
    if not permissions:
        return 0.0
    scores = [RISKY_PERMISSIONS.get(p, 0.0) for p in permissions]
    # normalize: average of matched risky permissions, capped at 1.0
    matched = [s for s in scores if s > 0]
    if not matched:
        return 0.0
    return min(1.0, sum(matched) / len(matched) + 0.1 * (len(matched) - 1))


def ttp_severity_component(predicted_ttps: dict[str, float]) -> float:
    """
    Now fed by MITRE technique IDs (via FAMILY_TO_TTPS bridge in routes.py)
    instead of raw family-name keys — fixes the §9.2 silent dead-weight.
    """
    if not predicted_ttps:
        return 0.0
    weighted = [
        prob * TTP_SEVERITY_WEIGHTS.get(ttp, TTP_SEVERITY_WEIGHTS["DEFAULT"])
        for ttp, prob in predicted_ttps.items()
    ]
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


def reputation_component(cache_hit: bool, cached_score: float | None) -> float:
    """
    If we got a cache hit, reputation is informed by prior known score.
    If no cache hit (first-seen sample), reputation defaults to neutral —
    it's neither vouched-for nor known-bad on this axis alone.
    """
    if cache_hit and cached_score is not None:
        return min(1.0, cached_score / 100.0)
    return 0.3  # neutral-low prior for unknown samples


def ioc_component(matched_c2_indicators: int) -> float:
    """Simple IOC score — scales with number of matched C2/network indicators."""
    return min(1.0, matched_c2_indicators * 0.3)


def compute_risk_score(
    predicted_ttps: dict[str, float],
    permissions: list[str],
    obfuscation: ObfuscationSignal,
    entropy_threshold: float,
    matched_anchor_behaviors: set[str] | None = None,
    cache_hit: bool = False,
    cached_score: float | None = None,
    matched_c2_indicators: int = 0,
) -> RiskScoreBreakdown:
    if matched_anchor_behaviors is None:
        matched_anchor_behaviors = set()

    c1 = classifier_confidence_component(predicted_ttps)
    c2 = permission_api_risk_component(permissions)
    c3 = ttp_severity_component(predicted_ttps)
    c4 = forensic_anchor_component(matched_anchor_behaviors)
    c5 = obfuscation_component(obfuscation, entropy_threshold)
    c6 = reputation_component(cache_hit, cached_score)
    c7 = ioc_component(matched_c2_indicators)

    # Revised weights (§9.3): 0.25 + 0.20 + 0.15 + 0.15 + 0.15 + 0.05 + 0.05 = 1.00
    total = (
        0.25 * c1 + 0.20 * c2 + 0.15 * c3 + 0.15 * c4 + 0.15 * c5 + 0.05 * c6 + 0.05 * c7
    ) * 100

    if total <= 30:
        band = "low"
    elif total <= 60:
        band = "suspicious"
    elif total <= 80:
        band = "high"
    else:
        band = "malicious"

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
    )
