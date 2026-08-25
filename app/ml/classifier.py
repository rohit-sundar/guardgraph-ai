"""
XGBoost inference wrapper. Loads the model trained by scripts/train_model.py.

STUB STATUS: this will raise FileNotFoundError until you drop your trained
model at the configured path. That's intentional — a silently-stubbed
classifier that returns fake confidence scores would be worse than a loud
failure, since it'd corrupt the risk scoring formula downstream without
anyone noticing during the demo.
"""
import os
import numpy as np
import pandas as pd
import xgboost as xgb

from app.core.config import settings, MODEL_LABEL_MAP
from app.ml.features import FEATURE_NAMES


class MalwareClassifier:
    def __init__(self, model_path: str | None = None):
        self.model_path = model_path or settings.model_path
        self._model: xgb.XGBClassifier | None = None

    def is_loaded(self) -> bool:
        return self._model is not None

    def load(self):
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(
                f"Model not found at {self.model_path}. "
                "Train it with scripts/train_model.py and drop the output here, "
                "or update MODEL_PATH in .env."
            )
        model = xgb.XGBClassifier()
        model.load_model(self.model_path)
        self._model = model

    def predict(self, feature_vector: list[float]) -> dict[str, float]:
        """
        Returns dict of label -> probability. Caller is responsible for
        deciding what confidence threshold counts as "predicted family".

        Backward-compat, by column NAME rather than by length. Models trained
        before SIGNATURE_YARA_FEATURES was appended expect 30 dims against a
        live 35, and slicing the extra dims off is correct *only* when the
        trained columns are a leading prefix of the current schema — i.e. the
        schema grew by appending.

        Length alone cannot tell that safe case from the dangerous one. When
        BEHAVIOR_FEATURES grew 6 -> 8 (DYNAMIC_CODE_LOADING, ACCESSIBILITY_ABUSE)
        the schema grew in the MIDDLE, so a 35-vector sliced to a 33-column
        model kept the length and shifted every column from index 12 onward by
        two: the model received DYNAMIC_CODE_LOADING where it was fitted on
        degree_centrality_mean. XGBoost cannot detect that — it has no concept
        of column names at inference time — so it returned confident, wrong
        families with no error, which is exactly the silent failure
        app.ml.features warns about in its module docstring.

        train_model.py fits on a DataFrame (`X = df[FEATURE_NAMES]`), so every
        model this project produces carries its column names in the booster.
        A model without them cannot be verified, and an unverifiable model is
        refused rather than trusted — same loud-stub contract as a missing one.
        """
        if self._model is None:
            self.load()

        vec = list(feature_vector)
        trained = self._model.get_booster().feature_names

        if trained is None:
            raise ValueError(
                f"Family model at {self.model_path} carries no feature names, so its "
                "column order cannot be checked against FEATURE_NAMES. Retrain it with "
                "`python scripts/train_model.py --target family`, which fits on a named "
                "DataFrame and records them."
            )

        if list(trained) != FEATURE_NAMES[: len(trained)]:
            mismatch = next(
                (
                    i
                    for i, name in enumerate(trained)
                    if i >= len(FEATURE_NAMES) or name != FEATURE_NAMES[i]
                ),
                0,
            )
            raise ValueError(
                f"Family model at {self.model_path} was trained on a different feature "
                f"schema than app.ml.features.FEATURE_NAMES: first divergence at column "
                f"{mismatch} (model has "
                f"{trained[mismatch] if mismatch < len(trained) else '<end>'!r}, current "
                f"schema has "
                f"{FEATURE_NAMES[mismatch] if mismatch < len(FEATURE_NAMES) else '<end>'!r}). "
                "Predictions would be computed from misaligned columns. Retrain with "
                "`python scripts/train_model.py --target family`."
            )

        # Trained columns are a verified prefix of the current schema, so anything
        # past them is a later append and is safe to drop.
        vec = vec[: len(trained)]

        # Passed as a named DataFrame, matching how train_model.py fitted it, so
        # XGBoost validates the column names itself instead of trusting position.
        X = pd.DataFrame([vec], columns=list(trained))
        probs = self._model.predict_proba(X)[0]

        if len(probs) != len(MODEL_LABEL_MAP):
            raise ValueError(
                f"Model outputs {len(probs)} classes but MODEL_LABEL_MAP has "
                f"{len(MODEL_LABEL_MAP)} entries. Update MODEL_LABEL_MAP in "
                "app/core/config.py to match your training label order."
            )

        return {label: float(p) for label, p in zip(MODEL_LABEL_MAP, probs)}


# Module-level singleton — load once, reuse across requests.
classifier = MalwareClassifier()


# ══════════════════════════════════════════════════════════════════════════
# MULTI-LABEL MITRE ATT&CK MOBILE TTP CLASSIFIER (Binary Relevance)
#
# Additive — the family MalwareClassifier above is unchanged. This predicts MITRE
# ATT&CK Mobile technique probabilities DIRECTLY (over app/ml/labels.TTP_LABELS),
# replacing the FAMILY_TO_TTPS proxy on the cold path. Binary Relevance (one XGBoost
# per technique) is the default because — unlike Label Powerset — it can emit
# technique combinations never seen in training, which is exactly what a zero-day
# engine needs. Same loud-stub contract: FileNotFoundError until trained.
# ══════════════════════════════════════════════════════════════════════════
import joblib

from app.ml.labels import TTP_LABELS

TTP_MODEL_PATH = "data/models/guardgraph_ttp_br_v1.joblib"


class BinaryRelevanceXGB:
    """
    One XGBoost binary classifier per technique. Handles class imbalance with a
    per-label scale_pos_weight, and degenerate (single-class) label columns by
    storing a constant probability instead of fitting an un-trainable estimator.
    Serialized whole via joblib — defined here so it is importable at load time.
    """

    def __init__(self, labels: list[str], **xgb_params):
        self.labels = list(labels)
        self.xgb_params = xgb_params
        self.estimators: dict[str, xgb.XGBClassifier] = {}
        self.constants: dict[str, float] = {}  # label -> constant P(1) for degenerate columns

    def fit(self, X, Y):
        Y = np.asarray(Y)
        for i, label in enumerate(self.labels):
            y = Y[:, i]
            pos = int(y.sum())
            neg = int(len(y) - pos)
            if pos == 0 or neg == 0:
                # Can't train a binary classifier on one class — store the constant.
                self.constants[label] = 1.0 if pos > 0 else 0.0
                continue
            clf = xgb.XGBClassifier(scale_pos_weight=(neg / pos), **self.xgb_params)
            clf.fit(X, y)
            self.estimators[label] = clf
        return self

    def predict_proba_matrix(self, X):
        n = X.shape[0]
        out = np.zeros((n, len(self.labels)), dtype=float)
        for i, label in enumerate(self.labels):
            if label in self.estimators:
                out[:, i] = self.estimators[label].predict_proba(X)[:, 1]
            else:
                out[:, i] = self.constants.get(label, 0.0)
        return out

    def predict(self, X, threshold: float = 0.5):
        return (self.predict_proba_matrix(X) >= threshold).astype(int)


class TTPClassifier:
    """Loads a Binary-Relevance TTP bundle and predicts per-technique probabilities."""

    def __init__(self, model_path: str | None = None):
        self.model_path = model_path or TTP_MODEL_PATH
        self._bundle: dict | None = None

    def is_loaded(self) -> bool:
        return self._bundle is not None

    def load(self):
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(
                f"TTP model not found at {self.model_path}. Train it with "
                "`python scripts/train_model.py --target ttp` and drop the output here."
            )
        self._bundle = joblib.load(self.model_path)

    def thresholds(self) -> dict[str, float]:
        """
        Per-label decision thresholds calibrated on the validation split at training
        time ({} for bundles trained before calibration existed — the caller then
        falls back to its global threshold). A single 0.5 cut cannot serve labels
        whose prevalence ranges from 0.02 to 0.75.
        """
        if self._bundle is None:
            self.load()
        return dict(self._bundle.get("label_thresholds") or {})

    def predict(self, feature_vector: list[float]) -> dict[str, float]:
        """
        Returns {technique_id: probability} for EVERY label in TTP_LABELS (untrained
        or degenerate labels return their constant / 0.0). Caller decides the
        "predicted" threshold. Raises FileNotFoundError if the model is not trained.
        """
        if self._bundle is None:
            self.load()

        model: BinaryRelevanceXGB = self._bundle["model"]
        feat_names = self._bundle.get("feature_names")
        if feat_names is not None and len(feature_vector) != len(feat_names):
            raise ValueError(
                f"TTP feature vector length {len(feature_vector)} != trained feature "
                f"count {len(feat_names)}. Rebuild the vector with build_ttp_feature_vector."
            )

        X = np.array([feature_vector], dtype=float)
        proba = model.predict_proba_matrix(X)[0]

        result = {t: 0.0 for t in TTP_LABELS}
        for label, p in zip(model.labels, proba):
            result[label] = round(float(p), 4)
        return result


# Module-level singleton — load once, reuse across requests.
ttp_classifier = TTPClassifier()
