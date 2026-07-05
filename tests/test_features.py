"""
Smoke test: ensures build_feature_vector always produces a vector matching
FEATURE_NAMES length. This is the single most important invariant in the
codebase — a silent mismatch here corrupts every prediction downstream
without raising an error at inference time.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.ml.features import build_feature_vector, FEATURE_NAMES


def test_feature_vector_length():
    vec = build_feature_vector(
        permissions=["android.permission.READ_SMS"],
        matched_behaviors={"OTP_INTERCEPTION"},
        topological_invariants={},
        obfuscation_entropy=6.5,
        obfuscation_flattening=False,
        obfuscation_reflection_count=2,
    )
    assert len(vec) == len(FEATURE_NAMES)
    print(f"OK: feature vector length {len(vec)} matches FEATURE_NAMES")


if __name__ == "__main__":
    test_feature_vector_length()
