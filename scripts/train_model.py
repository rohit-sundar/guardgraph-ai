"""
Training script skeleton for the XGBoost multi-class classifier.

USAGE NOTE (per tonight's plan): train v1 on permission/API/manifest
features ONLY. Topological features require running your CFG pipeline
across the whole dataset, which is a separate, slower job — don't block
tonight's run on it. Set the TOPOLOGY_FEATURES columns to 0.0 for this
run and retrain once app/analysis/cfg.py has been run over your dataset.

This script assumes you've already preprocessed CICMalDroid2020 into a
CSV/DataFrame with one row per sample and columns matching
app.ml.features.FEATURE_NAMES (topology columns can be zero-filled for v1).
Adjust the data loading section to match your actual preprocessing output.
"""
import argparse
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pandas as pd
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

from app.ml.features import FEATURE_NAMES
from app.core.config import MODEL_LABEL_MAP

DATA_PATH = "data/cicmaldroid_features.csv"  # <-- point this at your preprocessed dataset
LABEL_COLUMN = "family"
OUTPUT_MODEL_PATH = "data/models/guardgraph_xgb_v1.json"

# ── Multi-label TTP training (--target ttp) ──
TTP_DATA_PATH = "data/ttp_dataset.csv"          # produced by scripts/build_ttp_dataset.py
TTP_METRICS_OUT = "data/models/ttp_metrics.json"
MIN_TTP_POSITIVES = 3   # labels with fewer positives are skipped by the trainer

# ── Per-label threshold calibration ──
# One global 0.5 cut cannot serve labels whose prevalence spans 0.02–0.75, so each
# label's threshold is chosen on a held-out validation split. A label needs at least
# this many validation positives for the search to mean anything; below that it keeps
# the global default rather than fitting a threshold to one or two samples.
DEFAULT_TTP_THRESHOLD = 0.5
MIN_VAL_POSITIVES_TO_CALIBRATE = 2
THRESHOLD_GRID = [round(0.05 * i, 2) for i in range(2, 19)]   # 0.10 … 0.90


def main():
    if not os.path.exists(DATA_PATH):
        print(f"ERROR: {DATA_PATH} not found.")
        print("Preprocess CICMalDroid2020 into a CSV with columns matching")
        print("app.ml.features.FEATURE_NAMES plus a 'family' label column first.")
        sys.exit(1)

    df = pd.read_csv(DATA_PATH)

    missing_cols = [c for c in FEATURE_NAMES if c not in df.columns]
    if missing_cols:
        print(f"ERROR: dataset is missing expected feature columns: {missing_cols}")
        print("Either add these columns (zero-fill topology features for v1) or")
        print("update app/ml/features.py to match your actual dataset — but if you")
        print("do the latter, remember inference code must match exactly too.")
        sys.exit(1)

    X = df[FEATURE_NAMES]
    y_raw = df[LABEL_COLUMN]

    # Map string labels to indices matching MODEL_LABEL_MAP order.
    label_to_idx = {label: i for i, label in enumerate(MODEL_LABEL_MAP)}
    unmapped = set(y_raw.unique()) - set(label_to_idx.keys())
    if unmapped:
        print(f"WARNING: dataset has labels not in MODEL_LABEL_MAP: {unmapped}")
        print("These rows will be dropped. Update MODEL_LABEL_MAP in app/core/config.py")
        print("if these should be included.")
        df = df[y_raw.isin(label_to_idx.keys())]
        X = df[FEATURE_NAMES]
        y_raw = df[LABEL_COLUMN]

    y = y_raw.map(label_to_idx)

    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.3, stratify=y, random_state=42
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.5, stratify=y_temp, random_state=42
    )

    model = xgb.XGBClassifier(
        objective="multi:softprob",
        num_class=len(MODEL_LABEL_MAP),
        n_estimators=1000,
        early_stopping_rounds=30,
        eval_metric=["mlogloss", "merror"],
        tree_method="hist",
        random_state=42,
    )

    print(f"Training on {len(X_train)} samples, validating on {len(X_val)}...")
    model.fit(
        X_train, y_train,
        eval_set=[(X_val, y_val)],
        verbose=10,
    )

    os.makedirs(os.path.dirname(OUTPUT_MODEL_PATH), exist_ok=True)
    model.save_model(OUTPUT_MODEL_PATH)
    print(f"Model saved to {OUTPUT_MODEL_PATH}")

    print("\n--- Test set evaluation ---")
    y_pred = model.predict(X_test)
    print(classification_report(
        y_test, y_pred,
        target_names=MODEL_LABEL_MAP,
        zero_division=0,
    ))
    print("Confusion matrix (rows=true, cols=predicted):")
    print(MODEL_LABEL_MAP)
    print(confusion_matrix(y_test, y_pred))


def _multilabel_split(X, Y, test_size: float = 0.3):
    """Multi-label stratified split when iterative-stratification is available; else random."""
    try:
        from iterstrat.ml_stratifiers import MultilabelStratifiedShuffleSplit
        msss = MultilabelStratifiedShuffleSplit(n_splits=1, test_size=test_size, random_state=42)
        train_idx, test_idx = next(msss.split(X, Y))
        return X[train_idx], X[test_idx], Y[train_idx], Y[test_idx]
    except Exception:
        print("WARNING: iterative-stratification not available — using a random split. "
              "Install `iterative-stratification` for label-balanced folds.")
        return train_test_split(X, Y, test_size=test_size, random_state=42)


def _ml_metrics(Y_true, Y_pred) -> dict:
    """DroidTTP's multi-label metrics: micro/macro F1, sample Jaccard, Hamming loss."""
    from sklearn.metrics import f1_score, jaccard_score, hamming_loss
    return {
        "micro_f1": round(float(f1_score(Y_true, Y_pred, average="micro", zero_division=0)), 4),
        "macro_f1": round(float(f1_score(Y_true, Y_pred, average="macro", zero_division=0)), 4),
        "jaccard_samples": round(float(jaccard_score(Y_true, Y_pred, average="samples", zero_division=0)), 4),
        "hamming_loss": round(float(hamming_loss(Y_true, Y_pred)), 4),
    }


def _calibrate_thresholds(model, X_val, Y_val, labels: list[str]) -> dict[str, float]:
    """
    Pick each label's decision threshold by maximising validation F1.

    Labels with too few validation positives keep DEFAULT_TTP_THRESHOLD — a threshold
    fitted to one or two samples is noise dressed up as calibration. Ties go to the
    higher threshold, which is the conservative choice for a detector whose training
    set has no benign class to teach it when to stay quiet.
    """
    from sklearn.metrics import f1_score

    proba = model.predict_proba_matrix(X_val)
    thresholds: dict[str, float] = {}
    for i, label in enumerate(labels):
        y = Y_val[:, i]
        if int(y.sum()) < MIN_VAL_POSITIVES_TO_CALIBRATE:
            thresholds[label] = DEFAULT_TTP_THRESHOLD
            continue
        best_t, best_f1 = DEFAULT_TTP_THRESHOLD, -1.0
        for t in THRESHOLD_GRID:
            f1 = f1_score(y, (proba[:, i] >= t).astype(int), zero_division=0)
            if f1 > best_f1 or (f1 == best_f1 and t > best_t):
                best_t, best_f1 = t, float(f1)
        thresholds[label] = best_t
    return thresholds


def _pr_auc(model, X_te, Y_te, labels: list[str]) -> dict:
    """
    Per-label PR-AUC (average precision) plus its macro mean.

    Reported alongside F1 because F1 at a fixed threshold hides what a rare label is
    actually doing, and every headline metric this project has quoted so far was
    measured inside an all-malware distribution. Labels with no positives in the test
    split are omitted — average precision is undefined there, not zero.
    """
    from sklearn.metrics import average_precision_score

    proba = model.predict_proba_matrix(X_te)
    per_label: dict[str, float] = {}
    for i, label in enumerate(labels):
        if int(Y_te[:, i].sum()) == 0:
            continue
        per_label[label] = round(float(average_precision_score(Y_te[:, i], proba[:, i])), 4)
    macro = round(sum(per_label.values()) / len(per_label), 4) if per_label else None
    return {"macro_pr_auc": macro, "per_label": per_label}


def _zero_vector_sanity_check(model, n_features: int, labels: list[str],
                              thresholds: dict[str, float]) -> dict[str, float]:
    """
    What does the model predict when shown *nothing*?

    An all-zeros vector carries no permissions, no intents, no APIs and no topology.
    A model that has learned evidence answers "no techniques"; a model that has
    learned label priors answers with its most frequent labels. The current shipped
    model does the latter — 9 techniques at >= 0.5 — which is exactly why the runtime
    gate in app/core/pipeline.has_deterministic_evidence exists.

    Returns {label: probability} for every label that fires, empty when clean.
    """
    import numpy as np

    proba = model.predict_proba_matrix(np.zeros((1, n_features), dtype=float))[0]
    return {
        label: round(float(p), 4)
        for label, p in zip(labels, proba)
        if p >= thresholds.get(label, DEFAULT_TTP_THRESHOLD)
    }


def _label_powerset_fit_predict(X_tr, Y_tr, X_te, xgb_params):
    """DroidTTP's best in-distribution strategy — benchmarked here for comparison only."""
    import numpy as np
    combos: dict[tuple, int] = {}
    y_enc = []
    for row in Y_tr:
        key = tuple(int(v) for v in row.tolist())
        combos.setdefault(key, len(combos))
        y_enc.append(combos[key])
    if len(combos) < 2:
        raise ValueError("Label Powerset needs >=2 distinct label combinations in the training set.")
    inv = {v: k for k, v in combos.items()}
    clf = xgb.XGBClassifier(**xgb_params)
    clf.fit(X_tr, np.array(y_enc))
    pred_classes = clf.predict(X_te)
    out = np.zeros((X_te.shape[0], Y_tr.shape[1]), dtype=int)
    for i, c in enumerate(pred_classes):
        out[i] = np.array(inv[int(c)])
    return out


def train_ttp(allow_prior_only: bool = False):
    """
    Trains the multi-label MITRE ATT&CK Mobile TTP classifier.

    Default = Binary Relevance (saved as the shipped model). Classifier Chains and
    Label Powerset are benchmarked and reported for a DroidTTP-style comparison, but
    NOT shipped — BR is the zero-day-robust choice (can emit unseen label combos).

    Three splits, not two: fit / validation / test. Thresholds are
    calibrated on validation and the reported metrics come from test, so the numbers
    are not measured on data that chose the thresholds. The model is NOT refitted on
    fit+validation afterwards — that would ship a different model from the one the
    thresholds were calibrated against, and the point of this rework is that the
    headline metrics should mean what they claim.

    Training aborts if the all-zeros sanity check fails unless
    --allow-prior-only is passed.
    """
    import json
    import numpy as np
    import joblib
    from sklearn.multioutput import ClassifierChain

    from app.ml.features import TTP_FEATURE_NAMES
    from app.ml.labels import TTP_LABELS
    from app.ml.classifier import BinaryRelevanceXGB, TTP_MODEL_PATH

    if not os.path.exists(TTP_DATA_PATH):
        print(f"ERROR: {TTP_DATA_PATH} not found.")
        print("Build it first: python scripts/build_ttp_dataset.py")
        sys.exit(1)

    df = pd.read_csv(TTP_DATA_PATH)

    missing_feats = [c for c in TTP_FEATURE_NAMES if c not in df.columns]
    if missing_feats:
        print(f"ERROR: dataset missing TTP feature columns: {missing_feats[:8]}...")
        sys.exit(1)

    label_cols = [t for t in TTP_LABELS if t in df.columns]
    # Labels the data cannot train are excluded here rather than occupying output
    # slots and inflating the macro average with free zeros.
    dropped_labels = [t for t in label_cols if int(df[t].sum()) < MIN_TTP_POSITIVES]
    trained_labels = [t for t in label_cols if int(df[t].sum()) >= MIN_TTP_POSITIVES]
    if not trained_labels:
        print(f"ERROR: no technique has >= {MIN_TTP_POSITIVES} positive samples. "
              "Collect more data (scripts/build_ttp_dataset.py) before training.")
        sys.exit(1)

    # A detector trained only on malware has never been asked to say "no". Every
    # metric below is measured inside whatever distribution the dataset happens to
    # cover, so state the balance up front rather than burying it.
    n_benign = int((df[label_cols].sum(axis=1) == 0).sum())
    n_positive = int(len(df) - n_benign)
    if n_benign == 0:
        print("\n" + "!" * 78)
        print("WARNING: dataset has NO all-negative (benign) rows. The model can only")
        print("learn label priors, not the difference between malicious and clean. F1")
        print("measured on this split says nothing about whether a prediction means")
        print("anything. Collect 150-300 clean APKs and rerun:")
        print("    python scripts/build_ttp_dataset.py --stage c --benign-dir data/benign_apks")
        print("!" * 78 + "\n")
    else:
        print(f"Class balance: {n_positive} labeled-positive rows, {n_benign} benign rows "
              f"({n_benign / len(df):.1%} benign)")

    print(f"Training TTP model on {len(df)} samples, {len(trained_labels)} technique labels "
          f"(>= {MIN_TTP_POSITIVES} positives): {trained_labels}")
    if dropped_labels:
        print(f"Dropped {len(dropped_labels)} untrainable labels (< {MIN_TTP_POSITIVES} "
              f"positives): {dropped_labels}")

    X = df[TTP_FEATURE_NAMES].to_numpy(dtype=float)
    Y = df[trained_labels].to_numpy(dtype=int)
    X_fit_val, X_te, Y_fit_val, Y_te = _multilabel_split(X, Y, test_size=0.3)
    X_tr, X_val, Y_tr, Y_val = _multilabel_split(X_fit_val, Y_fit_val, test_size=0.25)
    print(f"Split: {len(X_tr)} fit / {len(X_val)} validation (thresholds) / {len(X_te)} test")

    xgb_params = dict(
        n_estimators=200, max_depth=4, learning_rate=0.1,
        subsample=0.9, colsample_bytree=0.9, tree_method="hist",
        eval_metric="logloss", random_state=42,
    )

    metrics: dict = {
        "n_samples": int(len(df)),
        "n_benign_rows": n_benign,
        "n_positive_rows": n_positive,
        "n_labels": len(trained_labels),
        "trained_labels": trained_labels,
        "dropped_labels": dropped_labels,
        "split": {"fit": len(X_tr), "validation": len(X_val), "test": len(X_te)},
    }

    # Binary Relevance — the shipped default.
    br = BinaryRelevanceXGB(trained_labels, **xgb_params).fit(X_tr, Y_tr)

    # Calibrate on validation, then report on test at those thresholds.
    label_thresholds = _calibrate_thresholds(br, X_val, Y_val, trained_labels)
    thr_vec = np.array([label_thresholds[t] for t in trained_labels])
    Y_pred = (br.predict_proba_matrix(X_te) >= thr_vec).astype(int)

    metrics["label_thresholds"] = label_thresholds
    metrics["binary_relevance"] = _ml_metrics(Y_te, Y_pred)
    metrics["binary_relevance_at_0.5"] = _ml_metrics(Y_te, br.predict(X_te))
    metrics["pr_auc"] = _pr_auc(br, X_te, Y_te, trained_labels)

    # The model must not have an opinion about an empty sample.
    zero_preds = _zero_vector_sanity_check(
        br, len(TTP_FEATURE_NAMES), trained_labels, label_thresholds
    )
    metrics["zero_vector_predictions"] = zero_preds
    metrics["zero_vector_sanity_check"] = "FAILED" if zero_preds else "passed"

    # Classifier Chains benchmark.
    try:
        cc = ClassifierChain(xgb.XGBClassifier(**xgb_params), order="random", random_state=42)
        cc.fit(X_tr, Y_tr)
        metrics["classifier_chains"] = _ml_metrics(Y_te, np.asarray(cc.predict(X_te)))
    except Exception as e:
        metrics["classifier_chains"] = {"error": str(e)}

    # Label Powerset benchmark (DroidTTP's in-distribution best; not shipped).
    try:
        metrics["label_powerset"] = _ml_metrics(Y_te, _label_powerset_fit_predict(X_tr, Y_tr, X_te, xgb_params))
    except Exception as e:
        metrics["label_powerset"] = {"error": str(e)}

    if zero_preds:
        print("\n" + "!" * 78)
        print(f"SANITY CHECK FAILED — an all-zeros feature vector predicts "
              f"{len(zero_preds)} techniques: {json.dumps(zero_preds, indent=2)}")
        print("The model has learned label priors, not evidence. Add benign samples")
        print("(scripts/build_ttp_dataset.py --stage c --benign-dir ...) and retrain.")
        print("!" * 78)
        if not allow_prior_only:
            os.makedirs(os.path.dirname(TTP_METRICS_OUT), exist_ok=True)
            with open(TTP_METRICS_OUT, "w", encoding="utf-8") as f:
                json.dump(metrics, f, indent=2)
            print(f"\nModel NOT saved — {TTP_MODEL_PATH} left untouched.")
            print(f"Metrics (including the failure) written to {TTP_METRICS_OUT}.")
            print("Rerun with --allow-prior-only to ship it anyway; the runtime gate in "
                  "app/core/pipeline.has_deterministic_evidence will suppress its output "
                  "on samples with no parsed code or anchors.")
            sys.exit(1)
        print("\n--allow-prior-only: shipping the model despite the failed check.\n")

    os.makedirs(os.path.dirname(TTP_MODEL_PATH), exist_ok=True)
    joblib.dump(
        {"model": br, "feature_names": TTP_FEATURE_NAMES,
         "trained_labels": trained_labels, "strategy": "binary_relevance",
         "label_thresholds": label_thresholds},
        TTP_MODEL_PATH,
    )
    with open(TTP_METRICS_OUT, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    print(f"\nTTP model (Binary Relevance) saved to {TTP_MODEL_PATH}")
    print(f"Metrics written to {TTP_METRICS_OUT}:")
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Train GuardGraph classifiers.")
    ap.add_argument("--target", choices=["family", "ttp"], default="family",
                    help="family = legacy multiclass model (default); ttp = multi-label TTP model")
    ap.add_argument("--allow-prior-only", action="store_true",
                    help="Ship the TTP model even if the all-zeros sanity check fails "
                         "(i.e. it predicts techniques for a sample with no features). "
                         "Use only while the training set still lacks a benign class.")
    args = ap.parse_args()

    if args.target == "ttp":
        train_ttp(allow_prior_only=args.allow_prior_only)
    else:
        main()
