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

# ── Family-held-out evaluation (N10) ──
# Stage A labels every malware row from its FAMILY's ATT&CK software entry, so all 15
# Cerberus samples carry one identical label vector, all 15 FluBot another. A split
# stratified on labels — which is what MultilabelStratifiedShuffleSplit does — then
# places identical vectors on BOTH sides by construction, and the resulting micro-F1
# measures family re-recognition rather than technique inference.
#
# So the shipped metrics now carry two numbers per model. The stratified one is kept
# because it is comparable to what DroidTTP-style papers report; the family-held-out
# one is the number to quote. Every fold holds out whole families, so a technique can
# only be predicted from structure the model saw on OTHER families.
#
# Benign rows are NOT grouped: each clean app is an independent package that shares no
# label vector with any other (they are all-zero by construction, not by family), so
# grouping them would hold out 220 samples at once and starve the negative class.
FAMILY_CV_SPLITS = 5
# Average precision computed over one or two positives is not a measurement — it is a
# property of where those points landed. Below this it is reported as null with its
# support, rather than as a number that looks like a result.
MIN_TEST_POSITIVES_FOR_PR_AUC = 5


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


def _group_key(df) -> "pd.Series":
    """
    Group label per row for family-held-out CV.

    Malware rows group by `source_family`, so a family is never split across the
    train/test boundary. Benign rows each get their own group — see FAMILY_CV_SPLITS
    for why they must stay independent. Rows with no recorded family fall back to a
    unique group rather than silently merging into one bucket named "nan".
    """
    families = df.get("source_family")
    keys = []
    for i in range(len(df)):
        source = df["label_source"].iloc[i]
        fam = None if families is None else families.iloc[i]
        if source == "benign" or not isinstance(fam, str) or not fam or fam == "benign":
            keys.append(f"__row_{i}")
        else:
            keys.append(f"fam:{fam}")
    return pd.Series(keys, index=df.index)


def _family_held_out_metrics(X, Y, groups, labels: list[str], xgb_params: dict) -> dict:
    """
    GroupKFold CV in which every fold holds out whole malware families.

    Thresholds are recalibrated inside each fold (on a further group-aware split of
    that fold's training data), so no fold's thresholds are chosen on rows it is
    scored against. Predictions are pooled across folds and scored once, which means
    every sample is predicted exactly once by a model that never saw its family.

    Returns the pooled metrics plus the fold layout, or an explanation of why the
    evaluation could not run.
    """
    import numpy as np
    from sklearn.model_selection import GroupKFold

    from app.ml.classifier import BinaryRelevanceXGB

    n_families = len({g for g in groups if g.startswith("fam:")})
    if n_families < 2:
        return {"error": f"only {n_families} malware family group(s) — "
                         "family-held-out evaluation needs at least 2."}

    n_splits = min(FAMILY_CV_SPLITS, n_families)
    groups = np.asarray(groups)
    Y_pooled = np.zeros_like(Y)
    fold_layout = []

    for fold, (tr_idx, te_idx) in enumerate(GroupKFold(n_splits=n_splits).split(X, Y, groups)):
        X_tr_all, Y_tr_all, g_tr = X[tr_idx], Y[tr_idx], groups[tr_idx]

        # Inner group-aware split for threshold calibration. If the fold's training
        # portion cannot be split by group (too few families left), calibrate on the
        # whole of it — biased toward the training data, but never toward the rows
        # this fold is scored on, which is the leak that matters here.
        inner = _group_split(X_tr_all, Y_tr_all, g_tr, test_size=0.25)
        if inner is None:
            X_fit, Y_fit, X_val, Y_val = X_tr_all, Y_tr_all, X_tr_all, Y_tr_all
        else:
            X_fit, Y_fit, X_val, Y_val = inner

        model = BinaryRelevanceXGB(labels, **xgb_params).fit(X_fit, Y_fit)
        thresholds = _calibrate_thresholds(model, X_val, Y_val, labels)
        thr_vec = np.array([thresholds[t] for t in labels])
        Y_pooled[te_idx] = (model.predict_proba_matrix(X[te_idx]) >= thr_vec).astype(int)

        held_out = sorted({g[4:] for g in groups[te_idx] if g.startswith("fam:")})
        fold_layout.append({"fold": fold, "n_test": int(len(te_idx)),
                            "families_held_out": held_out})
        print(f"  fold {fold}: {len(tr_idx):>3} train / {len(te_idx):>3} test — "
              f"held out {', '.join(held_out) or '(benign only)'}")

    out = _ml_metrics(Y, Y_pooled)
    out["n_splits"] = n_splits
    out["n_family_groups"] = n_families
    out["folds"] = fold_layout
    return out


def _group_split(X, Y, groups, test_size: float = 0.25):
    """One group-aware split, or None when the groups cannot support one."""
    import numpy as np
    from sklearn.model_selection import GroupShuffleSplit

    if len(set(groups)) < 2:
        return None
    try:
        gss = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=42)
        a_idx, b_idx = next(gss.split(X, Y, groups))
    except ValueError:
        return None
    if len(a_idx) == 0 or len(b_idx) == 0:
        return None
    return X[a_idx], Y[a_idx], X[b_idx], Y[b_idx]


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

    N10: labels below MIN_TEST_POSITIVES_FOR_PR_AUC are now reported as null WITH their
    support instead of as a number. The previous output printed 0.4909 for T1417, T1624
    and T1629 alike and 0.4419 for T1575 and T1630 — identical values because each had
    a single positive in the test split, so average precision degenerated to a function
    of where that one point ranked. Three identical "measurements" are the signature of
    that, and the macro mean was averaging them in as if they were real. The macro is
    now taken over the supported labels only, and reports how many it covered.
    """
    from sklearn.metrics import average_precision_score

    proba = model.predict_proba_matrix(X_te)
    per_label: dict[str, float | None] = {}
    support: dict[str, int] = {}
    supported: list[float] = []
    for i, label in enumerate(labels):
        pos = int(Y_te[:, i].sum())
        if pos == 0:
            continue
        support[label] = pos
        if pos < MIN_TEST_POSITIVES_FOR_PR_AUC:
            per_label[label] = None
            continue
        value = round(float(average_precision_score(Y_te[:, i], proba[:, i])), 4)
        per_label[label] = value
        supported.append(value)

    return {
        "macro_pr_auc": round(sum(supported) / len(supported), 4) if supported else None,
        "macro_over_n_labels": len(supported),
        "min_test_positives": MIN_TEST_POSITIVES_FOR_PR_AUC,
        "underpowered_labels": sorted(l for l, v in per_label.items() if v is None),
        "test_positives": support,
        "per_label": per_label,
    }


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

    groups = _group_key(df).to_numpy()
    family_sizes = df[df["label_source"] != "benign"]["source_family"].value_counts()
    print(f"\nFamily groups: {len(family_sizes)} malware families "
          f"(largest {int(family_sizes.max()) if len(family_sizes) else 0}, "
          f"smallest {int(family_sizes.min()) if len(family_sizes) else 0}), "
          f"{int((df['label_source'] == 'benign').sum())} independent benign rows")

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

    # The honest number. See FAMILY_CV_SPLITS — the stratified split above shares
    # identical family label vectors across the boundary by construction, so it
    # cannot distinguish inference from memorisation. This one holds out whole
    # families and is what the model is worth on a family it has never seen.
    print("\nFamily-held-out cross-validation (no family appears in both sides):")
    metrics["family_held_out"] = _family_held_out_metrics(
        X, Y, groups, trained_labels, xgb_params
    )

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
    _print_headline(metrics)


def _print_headline(metrics: dict) -> None:
    """
    The two evaluations side by side, last, so the gap between them is the thing left
    on screen. The stratified column is comparable to published DroidTTP-style
    numbers; the family-held-out column is the one to quote about this model.
    """
    strat = metrics.get("binary_relevance") or {}
    group = metrics.get("family_held_out") or {}
    print("\n" + "=" * 72)
    print("HEADLINE — quote the right-hand column")
    print("=" * 72)
    if "error" in group:
        print(f"  family-held-out evaluation did not run: {group['error']}")
        return

    print(f"  {'metric':<20} {'stratified (leaky)':<20} {'family-held-out':<18} delta")
    for key in ("micro_f1", "macro_f1", "jaccard_samples", "hamming_loss"):
        a, b = strat.get(key), group.get(key)
        if a is None or b is None:
            continue
        print(f"  {key:<20} {a:<20.4f} {b:<18.4f} {b - a:+.4f}")

    pr = metrics.get("pr_auc") or {}
    under = pr.get("underpowered_labels") or []
    print(f"\n  PR-AUC macro is over {pr.get('macro_over_n_labels', 0)} labels with "
          f">= {pr.get('min_test_positives')} test positives.")
    if under:
        print(f"  {len(under)} label(s) reported as null for lack of support: "
              f"{', '.join(under)}")
    print(
        "\n  jaccard_samples is the per-sample number; micro_f1 and hamming_loss are\n"
        "  both flattered by the all-zero benign rows, so neither belongs in a headline."
    )


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
