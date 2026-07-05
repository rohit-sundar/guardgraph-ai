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
import xgboost as xgb

from app.core.config import settings, MODEL_LABEL_MAP


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
        """
        if self._model is None:
            self.load()

        X = np.array([feature_vector])
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
