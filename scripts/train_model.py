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


def train_ttp():
    """
    Trains the multi-label MITRE ATT&CK Mobile TTP classifier.

    Default = Binary Relevance (saved as the shipped model). Classifier Chains and
    Label Powerset are benchmarked and reported for a DroidTTP-style comparison, but
    NOT shipped — BR is the zero-day-robust choice (can emit unseen label combos).
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
    trained_labels = [t for t in label_cols if int(df[t].sum()) >= MIN_TTP_POSITIVES]
    if not trained_labels:
        print(f"ERROR: no technique has >= {MIN_TTP_POSITIVES} positive samples. "
              "Collect more data (scripts/build_ttp_dataset.py) before training.")
        sys.exit(1)

    print(f"Training TTP model on {len(df)} samples, {len(trained_labels)} technique labels "
          f"(>= {MIN_TTP_POSITIVES} positives): {trained_labels}")

    X = df[TTP_FEATURE_NAMES].to_numpy(dtype=float)
    Y = df[trained_labels].to_numpy(dtype=int)
    X_tr, X_te, Y_tr, Y_te = _multilabel_split(X, Y)

    xgb_params = dict(
        n_estimators=200, max_depth=4, learning_rate=0.1,
        subsample=0.9, colsample_bytree=0.9, tree_method="hist",
        eval_metric="logloss", random_state=42,
    )

    metrics: dict = {"n_samples": int(len(df)), "n_labels": len(trained_labels),
                     "trained_labels": trained_labels}

    # Binary Relevance — the shipped default.
    br = BinaryRelevanceXGB(trained_labels, **xgb_params).fit(X_tr, Y_tr)
    metrics["binary_relevance"] = _ml_metrics(Y_te, br.predict(X_te))

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

    os.makedirs(os.path.dirname(TTP_MODEL_PATH), exist_ok=True)
    joblib.dump(
        {"model": br, "feature_names": TTP_FEATURE_NAMES,
         "trained_labels": trained_labels, "strategy": "binary_relevance"},
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
    args = ap.parse_args()

    if args.target == "ttp":
        train_ttp()
    else:
        main()
