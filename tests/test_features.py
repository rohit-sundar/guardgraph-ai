"""
Smoke test: ensures build_feature_vector always produces a vector matching
FEATURE_NAMES length. This is the single most important invariant in the
codebase — a silent mismatch here corrupts every prediction downstream
without raising an error at inference time.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.ml.features import (
    build_feature_vector, FEATURE_NAMES,
    build_ttp_feature_vector, TTP_FEATURE_NAMES,
)


def test_feature_vector_length():
    vec = build_feature_vector(
        permissions=["android.permission.READ_SMS"],
        matched_behaviors={"OTP_INTERCEPTION"},
        topological_invariants={},
        obfuscation_entropy=6.5,
        obfuscation_flattening=False,
        obfuscation_reflection_count=2,
        signature_match_count=1,
        yara_rule_match_count=2,
        yara_max_severity=0.85,
    )
    assert len(vec) == len(FEATURE_NAMES)
    assert len(vec) == 33
    print(f"OK: feature vector length {len(vec)} matches FEATURE_NAMES (33)")


def test_ttp_feature_vector_length():
    """The multi-label TTP feature vector must always match TTP_FEATURE_NAMES —
    the same class of invariant as the 33-vector, and just as fatal if it drifts."""
    # No duplicate column names (a silent duplicate corrupts XGBoost columns).
    assert len(set(TTP_FEATURE_NAMES)) == len(TTP_FEATURE_NAMES), "duplicate TTP feature names"

    empty = build_ttp_feature_vector(permissions=[])
    assert len(empty) == len(TTP_FEATURE_NAMES)

    populated = build_ttp_feature_vector(
        permissions=["android.permission.READ_SMS", "android.permission.SYSTEM_ALERT_WINDOW"],
        intent_actions=["android.provider.Telephony.SMS_RECEIVED"],
        api_calls=["Landroid/telephony/SmsManager;->sendTextMessage(...)"],
        num_activities=3, num_services=2, num_receivers=99,  # exercises the count cap
        matched_behaviors={"OTP_INTERCEPTION", "C2_BEHAVIOR"},
        topological_invariants={"degree_centrality_mean": 0.4},
        obfuscation_entropy=7.5, obfuscation_flattening=True, obfuscation_reflection_count=5,
        signature_match_count=1, yara_rule_match_count=2, yara_max_severity=0.9,
    )
    assert len(populated) == len(TTP_FEATURE_NAMES)
    assert 50.0 in populated, "component-count cap (50) not applied"
    print(f"OK: TTP feature vector length {len(populated)} matches TTP_FEATURE_NAMES ({len(TTP_FEATURE_NAMES)})")


if __name__ == "__main__":
    test_feature_vector_length()
    test_ttp_feature_vector_length()
