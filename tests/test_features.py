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
    assert len(vec) == 35
    print(f"OK: feature vector length {len(vec)} matches FEATURE_NAMES (35)")


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


def test_ttp_label_space_is_57():
    """
    The label space is the third length invariant, and the only one not asserted
    until now (35 and 181 both are).

    It matters for the same reason as the other two: TTP_LABELS is what the
    multi-label model's output columns are read against, so adding or removing a
    technique silently re-indexes every prediction. It is also the denominator the
    README and the model-accuracy panel both quote ("34 of 57 trained, 23 dropped"),
    so a change here falsifies published numbers as well as predictions.
    """
    from app.ml.labels import TTP_LABELS

    assert len(TTP_LABELS) == 57, (
        f"TTP label space changed: {len(TTP_LABELS)} != 57. If this is intentional, "
        "retrain (scripts/train_model.py --target ttp) and update the 'of 57' figures "
        "in README.md — they are not derived at runtime."
    )
    assert len(set(TTP_LABELS)) == len(TTP_LABELS), "duplicate technique IDs in TTP_LABELS"
    print(f"OK: TTP label space is {len(TTP_LABELS)} techniques")


def test_shipped_metrics_partition_the_label_space():
    """
    The shipped model's trained + dropped labels must together be exactly TTP_LABELS.

    This is the D1 failure mode applied to labels rather than features: an artifact
    that disagrees with the code's label list produces confident, wrongly-indexed
    output with no error. Skipped rather than failed when the metrics file is absent,
    since a fresh clone has no trained artifact yet.
    """
    import json
    import os

    from app.ml.labels import TTP_LABELS

    path = os.path.join(os.path.dirname(__file__), "..", "data", "models", "ttp_metrics.json")
    if not os.path.exists(path):
        print("SKIP: no ttp_metrics.json — nothing trained yet")
        return

    with open(path, encoding="utf-8") as fh:
        metrics = json.load(fh)

    trained = set(metrics.get("trained_labels") or [])
    dropped = set(metrics.get("dropped_labels") or [])

    assert not (trained & dropped), f"labels both trained and dropped: {sorted(trained & dropped)}"

    covered = trained | dropped
    expected = set(TTP_LABELS)
    assert covered == expected, (
        f"shipped metrics do not partition TTP_LABELS — "
        f"missing from artifact: {sorted(expected - covered)}, "
        f"unknown to the code: {sorted(covered - expected)}"
    )
    print(f"OK: {len(trained)} trained + {len(dropped)} dropped == {len(expected)} TTP_LABELS")


def test_behavior_features_cover_the_forensic_dictionary():
    """
    Every behavior Phase 3 can match must reach the feature vectors.

    DYNAMIC_CODE_LOADING and ACCESSIBILITY_ABUSE were matched by Phase 3 and
    weighted in BEHAVIOR_SEVERITY (0.70 and 0.90) yet appeared in neither vector,
    so ACCESSIBILITY_ABUSE — the second-highest behavior weight and the single
    most characteristic banking-trojan signal — was scored and reported but could
    never influence a prediction. A behavior added to FORENSIC_DICTIONARY without
    being added here reintroduces exactly that silent gap.
    """
    from app.analysis.forensic import FORENSIC_DICTIONARY
    from app.ml.features import BEHAVIOR_FEATURES

    missing = set(FORENSIC_DICTIONARY) - set(BEHAVIOR_FEATURES)
    assert not missing, (
        f"{sorted(missing)} can be matched by Phase 3 but reach no feature vector. "
        "Add them to BEHAVIOR_FEATURES, then rebuild the dataset and retrain — "
        "the vector lengths are frozen contracts."
    )
    # The reverse direction would produce a column that is always 0.
    unmatched = set(BEHAVIOR_FEATURES) - set(FORENSIC_DICTIONARY)
    assert not unmatched, f"{sorted(unmatched)} are features nothing can ever set"
    print(f"OK: all {len(FORENSIC_DICTIONARY)} forensic behaviors reach the feature vectors")


def _train_toy_family_model(columns):
    """A 2-tree XGBoost model fitted on `columns`, so its booster carries them."""
    import pandas as pd
    import xgboost as xgb
    from app.core.config import MODEL_LABEL_MAP

    rows = len(MODEL_LABEL_MAP) * 2
    X = pd.DataFrame(
        [[float(i % 3) for _ in columns] for i in range(rows)], columns=list(columns)
    )
    y = [i % len(MODEL_LABEL_MAP) for i in range(rows)]
    model = xgb.XGBClassifier(
        objective="multi:softprob", num_class=len(MODEL_LABEL_MAP),
        n_estimators=2, max_depth=2, tree_method="hist", random_state=42,
    )
    model.fit(X, y)
    return model


def test_family_model_rejects_a_middle_inserted_schema(tmp_path):
    """
    The guard that would have caught the real defect.

    guardgraph_xgb_v1.json was fitted on the 33-column, 6-behavior schema. When
    BEHAVIOR_FEATURES grew to 8 the two new columns landed at indices 12-13, in
    the MIDDLE — so a 35-vector sliced to 33 kept its length and shifted every
    column from 12 onward by two. XGBoost cannot see that, so it returned
    confident, wrong families for months. Length checks pass this case; only a
    column-NAME check catches it.
    """
    from app.ml.classifier import MalwareClassifier

    old_schema = [c for c in FEATURE_NAMES
                  if c not in ("DYNAMIC_CODE_LOADING", "ACCESSIBILITY_ABUSE")]
    assert len(old_schema) == 33, "this test reconstructs the historical 33-col schema"

    path = tmp_path / "misaligned.json"
    _train_toy_family_model(old_schema).save_model(str(path))

    clf = MalwareClassifier(model_path=str(path))
    try:
        clf.predict([0.0] * len(FEATURE_NAMES))
        raise AssertionError("misaligned model was accepted — the guard is not working")
    except ValueError as e:
        assert "column 12" in str(e), f"guard should name the divergence point: {e}"
        assert "DYNAMIC_CODE_LOADING" in str(e)
    print("OK: middle-inserted schema drift is refused, not silently sliced")


def test_family_model_accepts_a_trailing_append(tmp_path):
    """
    The backward-compat case the old slicing shim existed for must still work:
    a model whose columns are a true PREFIX of the current schema (the schema
    grew by appending) is safe to slice down to, and must still predict.
    """
    from app.ml.classifier import MalwareClassifier
    from app.core.config import MODEL_LABEL_MAP

    prefix = FEATURE_NAMES[:-3]  # as if SIGNATURE_YARA_FEATURES were appended later
    path = tmp_path / "prefix.json"
    _train_toy_family_model(prefix).save_model(str(path))

    probs = MalwareClassifier(model_path=str(path)).predict([0.0] * len(FEATURE_NAMES))
    assert set(probs) == set(MODEL_LABEL_MAP)
    assert abs(sum(probs.values()) - 1.0) < 1e-3, "probabilities should sum to 1"
    print("OK: trailing-append backward compatibility preserved")


def test_shipped_family_model_matches_the_feature_schema():
    """
    Guards the ARTIFACT, not just the code path: if a family model is on disk it
    must have been trained on the current schema. Skipped when absent, which is
    the documented loud-stub state (predicted_family is None and the report says so).
    """
    import os
    import xgboost as xgb
    from app.core.config import settings

    if not os.path.exists(settings.model_path):
        print(f"SKIP: no family model at {settings.model_path} (loud-stub state)")
        return

    model = xgb.XGBClassifier()
    model.load_model(settings.model_path)
    trained = model.get_booster().feature_names
    assert trained is not None, (
        f"{settings.model_path} carries no column names, so alignment is unverifiable"
    )
    assert list(trained) == FEATURE_NAMES[: len(trained)], (
        f"{settings.model_path} was trained on a schema that is not a prefix of "
        "FEATURE_NAMES — its predictions would come from misaligned columns"
    )
    print(f"OK: shipped family model aligns with FEATURE_NAMES ({len(trained)} cols)")


if __name__ == "__main__":
    test_feature_vector_length()
    test_ttp_feature_vector_length()
    test_behavior_features_cover_the_forensic_dictionary()
    test_shipped_family_model_matches_the_feature_schema()
