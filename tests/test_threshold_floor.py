"""
Per-label threshold calibration must never select a cut at or below what the model
predicts for an all-zeros feature vector.

The failure this prevents, observed on the 633-sample corpus: T1418 (Software
Discovery) scores 0.5418 on an all-zeros vector, and maximising validation F1 alone
selected a threshold of 0.15 — against a median of 0.65 across labels and 0.6-0.9 for
its similarly-prevalent peers. That reads as "assert this technique unless something
contradicts it". It happens when a label carries no learnable signal: T1418 is
family-constant (varies between samples in 0 of 21 families) and its defining API
appears in 1.5% of positive rows against 0.7% of negatives, so "always yes" genuinely
maximises F1.

The same label trained at 0.8 on the older 364-sample corpus and passed the gate, so
the defect was latent rather than new — which is why the fix belongs where the number
is CHOSEN, not only in the audit that runs afterwards.

Fully offline: the model is a stub, no training and no artifacts.
"""
import os
import sys
import unittest

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from train_model import (  # noqa: E402
    DEFAULT_TTP_THRESHOLD,
    THRESHOLD_GRID,
    _calibrate_thresholds,
    _zero_vector_sanity_check,
)


class StubModel:
    """Returns a fixed probability per label, and `zero_row` for an all-zeros input."""

    def __init__(self, val_proba, zero_row):
        self._val = np.asarray(val_proba, dtype=float)
        self._zero = np.asarray(zero_row, dtype=float)

    def predict_proba_matrix(self, X):
        X = np.asarray(X, dtype=float)
        if X.shape[0] == 1 and not X.any():
            return self._zero.reshape(1, -1)
        return self._val


class TestThresholdFloor(unittest.TestCase):

    LABELS = ["T1418", "T1429"]

    def _calibrate(self, zero_row, val_proba, Y_val):
        model = StubModel(val_proba, zero_row)
        X_val = np.ones((len(val_proba), 4), dtype=float)
        return _calibrate_thresholds(model, X_val, np.asarray(Y_val), self.LABELS)

    def test_threshold_never_sits_at_or_below_the_no_evidence_probability(self):
        """
        The T1418 shape: a prevalent label the model asserts at 0.54 on nothing, where
        unconstrained F1 would pick the bottom of the grid because saying yes to
        everything scores well.
        """
        val = [[0.9, 0.9], [0.8, 0.1], [0.7, 0.1], [0.6, 0.1]]
        Y = [[1, 1], [1, 0], [1, 0], [1, 0]]
        thresholds = self._calibrate([0.5418, 0.02], val, Y)

        self.assertGreater(thresholds["T1418"], 0.5418,
                           "threshold sits at or below the all-zeros probability")
        # The unconstrained answer for an all-positive label is the grid floor.
        self.assertNotEqual(thresholds["T1418"], min(THRESHOLD_GRID))

    def test_a_label_with_a_low_floor_is_left_alone(self):
        """The floor must not disturb labels that were already evidence-driven."""
        val = [[0.9, 0.9], [0.1, 0.8], [0.1, 0.2], [0.1, 0.1]]
        Y = [[1, 1], [0, 1], [0, 0], [0, 0]]
        thresholds = self._calibrate([0.01, 0.02], val, Y)
        for label in self.LABELS:
            self.assertIn(thresholds[label], THRESHOLD_GRID)

    def test_the_floor_also_applies_to_uncalibrated_labels(self):
        """
        A label with too few validation positives keeps the global default — but the
        default is 0.5, and a label whose no-evidence probability is above 0.5 would
        still fire on nothing.
        """
        val = [[0.9, 0.9], [0.8, 0.1]]
        Y = [[0, 0], [0, 0]]           # zero positives -> no calibration
        thresholds = self._calibrate([0.77, 0.02], val, Y)

        self.assertGreater(thresholds["T1418"], 0.77)
        self.assertEqual(thresholds["T1429"], DEFAULT_TTP_THRESHOLD)

    def test_a_label_asserted_above_the_whole_grid_is_pinned_not_dropped(self):
        """
        If the no-evidence probability exceeds every grid value, no grid threshold can
        make the label evidence-driven. It is pinned just above its own floor so it
        effectively never fires — truthful for a label the model asserts
        unconditionally — rather than silently keeping a cut it is always above.
        """
        val = [[0.99, 0.9], [0.98, 0.1], [0.97, 0.1], [0.96, 0.1]]
        Y = [[1, 1], [1, 0], [1, 0], [1, 0]]
        thresholds = self._calibrate([0.95, 0.02], val, Y)

        self.assertGreater(thresholds["T1418"], 0.95)
        self.assertLess(thresholds["T1418"], 1.0)

    def test_the_gate_passes_for_every_threshold_this_function_returns(self):
        """
        The end-to-end property: calibration and the sanity check agree by
        construction, so the gate can no longer fail on a threshold choice.
        """
        for zero_row in ([0.5418, 0.02], [0.77, 0.60], [0.95, 0.99], [0.01, 0.01]):
            val = [[0.9, 0.9], [0.8, 0.7], [0.7, 0.3], [0.6, 0.1]]
            Y = [[1, 1], [1, 1], [1, 0], [1, 0]]
            thresholds = self._calibrate(zero_row, val, Y)
            fired = _zero_vector_sanity_check(
                StubModel(val, zero_row), 4, self.LABELS, thresholds
            )
            self.assertEqual(fired, {}, f"gate fired for zero_row={zero_row}: {fired}")


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestUnreachableThresholdIsIntentional(unittest.TestCase):
    """
    `_above` is deliberately not clamped to 1.0. Clamping a 0.99 floor to 0.99 leaves
    `p >= threshold` true, which reintroduces the assertion-on-nothing the floor
    exists to stop — caught by the end-to-end property test above.
    """

    def test_a_floor_at_the_top_of_the_range_yields_an_unreachable_threshold(self):
        from train_model import _above

        for floor in (0.95, 0.99, 1.0):
            self.assertGreater(_above(floor), floor)
        self.assertGreater(_above(1.0), 1.0,
                           "a label asserted at certainty must be unreachable, not clamped")
