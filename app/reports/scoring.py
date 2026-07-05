"""
Deterministic risk score, 0-100, per the design doc's weighted formula:

    0.30 * classifier_probability
  + 0.20 * permission_api_risk
  + 0.20 * ttp_severity
  + 0.15 * graph_obfuscation_score
  + 0.10 * reputation_score
  + 0.05 * ioc_score

Every component function below is a real, if simple, calculation — not a
placeholder returning a constant. Tune the internals as you validate
against your demo set, but the formula weights themselves match the spec
and shouldn't drift without a documented reason.
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
    if not predicted_ttps:
        return 0.0
    weighted = [
        prob * TTP_SEVERITY_WEIGHTS.get(ttp, TTP_SEVERITY_WEIGHTS["DEFAULT"])
        for ttp, prob in predicted_ttps.items()
    ]
    return min(1.0, sum(weighted) / len(weighted))


def obfuscation_component(obfuscation: ObfuscationSignal, entropy_threshold: float) -> float:
    score = 0.0
    if obfuscation.string_entropy_score >= entropy_threshold:
        score += 0.5
    if obfuscation.flattening_suspected:
        score += 0.4
    if obfuscation.unresolved_reflection_targets > 0:
        score += 0.1
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
    cache_hit: bool = False,
    cached_score: float | None = None,
    matched_c2_indicators: int = 0,
) -> RiskScoreBreakdown:
    c1 = classifier_confidence_component(predicted_ttps)
    c2 = permission_api_risk_component(permissions)
    c3 = ttp_severity_component(predicted_ttps)
    c4 = obfuscation_component(obfuscation, entropy_threshold)
    c5 = reputation_component(cache_hit, cached_score)
    c6 = ioc_component(matched_c2_indicators)

    total = (
        0.30 * c1 + 0.20 * c2 + 0.20 * c3 + 0.15 * c4 + 0.10 * c5 + 0.05 * c6
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
        classifier_confidence_component=round(c1 * 30, 2),
        permission_api_component=round(c2 * 20, 2),
        ttp_severity_component=round(c3 * 20, 2),
        obfuscation_component=round(c4 * 15, 2),
        reputation_component=round(c5 * 10, 2),
        ioc_component=round(c6 * 5, 2),
        total_score=round(total, 2),
        verdict_band=band,
    )
