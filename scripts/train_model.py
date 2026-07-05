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


if __name__ == "__main__":
    main()
