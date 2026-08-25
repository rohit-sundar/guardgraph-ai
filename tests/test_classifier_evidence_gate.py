"""
Regression tests for the classifier evidence gate.

The rule: when static analysis recovered no deterministic evidence — no CFGs, no
forensic anchors, no behavioural features — the classifier gets no vote, and
`classifier_confidence_component` contributes nothing to the risk score.

**Why this is a code-level guarantee and not a training concern.** Any multi-label
model learns each label's prior alongside its features, so an input the analyser
learned nothing from does not yield "no prediction" — it yields the prior, which is
indistinguishable from a finding by the time it reaches a score. Training data that
includes a benign class suppresses this, but the model is *data*, not code: it can
be retrained, rebalanced or swapped without any change to this repository, and the
scoring path cannot inspect the corpus behind whatever `.joblib` it loads. The gate
is where the guarantee belongs because it is the part that ships with the code.

**`train_model.py`'s `zero_vector_sanity_check` is the complement, not a
replacement.** It refuses to save a model that predicts anything for an all-zero
feature vector, which covers exactly one input. The gate covers every input where
the analysis observed nothing, including partial recoveries that are not all-zero.

This was never hypothetical: an earlier model trained with no benign class at all
scored a ZIP holding one renamed text file as `suspicious`, almost entirely on
classifier confidence. The corpus behind the model has changed since, more than
once. The reason for the gate has not, which is why these tests assert the
behaviour rather than any particular model's numbers.

Fully offline — no model, no Neo4j, no Ollama.
"""
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.core.pipeline import (
    AnalysisPipeline,
    has_deterministic_evidence,
    NO_CLASSIFIER_EVIDENCE_NOTE,
)
from app.core.schemas import ObfuscationSignal
from app.ml.features import FEATURE_NAMES, TTP_FEATURE_NAMES
from app.reports.scoring import classifier_confidence_component, compute_risk_score

N_TTP_FEATURES = len(TTP_FEATURE_NAMES)


def _obfuscation(entropy: float = 0.0) -> ObfuscationSignal:
    return ObfuscationSignal(
        string_entropy_score=entropy,
        flattening_suspected=False,
        coverage_note="test",
        method_parse_failure_rate=0.0,
    )


# ─── The evidence predicate ─────────────────────────────────────────────────

class TestHasDeterministicEvidence(unittest.TestCase):

    def test_all_zero_vector_is_not_evidence(self):
        """The exact input that produced 9 confident techniques from nothing."""
        self.assertFalse(
            has_deterministic_evidence(
                cfg_count=0, matched_behaviors=set(),
                ttp_feature_vector=[0.0] * N_TTP_FEATURES,
            )
        )

    def test_no_cfgs_and_no_anchors_is_not_evidence(self):
        """A manifest-only APK still has permission features, but the model was
        fitted on samples with code — permissions alone are out of distribution."""
        vec = [0.0] * N_TTP_FEATURES
        vec[0] = 1.0  # e.g. a declared permission
        self.assertFalse(
            has_deterministic_evidence(
                cfg_count=0, matched_behaviors=set(), ttp_feature_vector=vec
            )
        )

    def test_parsed_methods_are_evidence(self):
        vec = [0.0] * N_TTP_FEATURES
        vec[5] = 3.0
        self.assertTrue(
            has_deterministic_evidence(
                cfg_count=347, matched_behaviors=set(), ttp_feature_vector=vec
            )
        )

    def test_matched_anchors_are_evidence(self):
        vec = [0.0] * N_TTP_FEATURES
        vec[5] = 1.0
        self.assertTrue(
            has_deterministic_evidence(
                cfg_count=0, matched_behaviors={"OTP_INTERCEPTION"},
                ttp_feature_vector=vec,
            )
        )

    def test_real_sample_shape_is_evidence(self):
        """The test.apk case: 347 CFGs, 4 anchor behaviors. Must be unaffected."""
        self.assertTrue(
            has_deterministic_evidence(
                cfg_count=347,
                matched_behaviors={"ACCESSIBILITY_ABUSE", "DYNAMIC_REFLECTION",
                                   "C2_BEHAVIOR", "OTP_INTERCEPTION"},
                ttp_feature_vector=[0.5] * N_TTP_FEATURES,
            )
        )


# ─── Scoring: the model-derived components are gated ────────────────────────

class TestClassifierComponentGate(unittest.TestCase):

    def test_component_is_zero_without_evidence(self):
        ttps = {"T1418": 0.9639, "T1582": 0.8207, "T1471": 0.5446}
        self.assertEqual(classifier_confidence_component(ttps, evidence_present=False), 0.0)

    def test_component_is_nonzero_with_evidence(self):
        """The gate only zeroes the component; with evidence the model still votes."""
        ttps = {"T1429": 0.9912, "T1616": 0.9909}
        self.assertGreater(
            classifier_confidence_component(ttps, evidence_present=True), 0.0
        )

    def test_breadth_raises_confidence_monotonically(self):
        """
        N8: confidence is an evidence mass over techniques, not `max(probability)`.
        Two decisive techniques must outrank one, and both must stay below the cap —
        `com.symeonchen.wakeupscreen` drew 24.57/25 from a single label under the old
        max() rule.
        """
        thresholds = {"T1429": 0.5, "T1616": 0.5, "T1471": 0.5}
        one = classifier_confidence_component(
            {"T1429": 0.99}, ttp_thresholds=thresholds
        )
        two = classifier_confidence_component(
            {"T1429": 0.99, "T1616": 0.99}, ttp_thresholds=thresholds
        )
        three = classifier_confidence_component(
            {"T1429": 0.99, "T1616": 0.99, "T1471": 0.99}, ttp_thresholds=thresholds
        )
        self.assertLess(one, two)
        self.assertLess(two, three)
        self.assertLess(three, 1.0)
        # One confident technique must no longer be worth most of the 25-point cap.
        self.assertLess(one, 0.5)

    def test_confidence_is_measured_against_the_calibrated_threshold(self):
        """
        A probability barely past its own boundary is weak evidence; the same
        probability far past a low boundary is strong. The per-label thresholds in
        the trained bundle span 0.10 to 0.90, so an uncalibrated max() conflates the
        two.
        """
        barely = classifier_confidence_component(
            {"T1471": 0.91}, ttp_thresholds={"T1471": 0.9}
        )
        decisively = classifier_confidence_component(
            {"T1516": 0.91}, ttp_thresholds={"T1516": 0.1}
        )
        self.assertLess(barely, decisively)

    def test_missing_thresholds_fall_back_to_the_global_default(self):
        """An untrained bundle yields {}; the component must still be scoreable."""
        self.assertGreater(classifier_confidence_component({"T1429": 0.99}), 0.0)
        self.assertEqual(classifier_confidence_component({"T1429": 0.5}, ttp_thresholds={}), 0.0)

    def test_empty_file_no_longer_scores_suspicious(self):
        """
        The measured failure: a 35-byte text file renamed .apk scored 33.92 /
        `suspicious`, 24.10 of it from classifier confidence. With the gate the
        model contributes nothing and the verdict falls back to what was actually
        observed — nothing.
        """
        ungated = compute_risk_score(
            predicted_ttps={"T1418": 0.9639, "T1582": 0.8207, "T1646": 0.8030},
            permissions=[],
            obfuscation=_obfuscation(),
            entropy_threshold=4.5,
        )
        gated = compute_risk_score(
            predicted_ttps={"T1418": 0.9639, "T1582": 0.8207, "T1646": 0.8030},
            permissions=[],
            obfuscation=_obfuscation(),
            entropy_threshold=4.5,
            classifier_evidence_present=False,
        )
        self.assertEqual(gated.classifier_confidence_component, 0.0)
        self.assertEqual(gated.ttp_severity_component, 0.0)
        self.assertLess(gated.total_score, ungated.total_score)
        self.assertEqual(gated.verdict_band, "low")

    def test_gate_does_not_touch_deterministic_components(self):
        """Permissions, anchors and IOCs are measurements, not predictions — a
        suppressed classifier must never suppress real evidence."""
        kwargs = dict(
            predicted_ttps={"T1418": 0.96},
            permissions=["android.permission.READ_SMS", "android.permission.SEND_SMS"],
            obfuscation=_obfuscation(),
            entropy_threshold=4.5,
            matched_anchor_behaviors={"OTP_INTERCEPTION"},
            cert_anomaly_count=2,
        )
        ungated = compute_risk_score(**kwargs)
        gated = compute_risk_score(**kwargs, classifier_evidence_present=False)
        for field in ("permission_api_component", "forensic_anchor_component",
                      "ioc_component", "reputation_component"):
            self.assertEqual(
                getattr(gated, field), getattr(ungated, field),
                f"{field} must be unaffected by the classifier gate",
            )


# ─── Phase 5: suppression happens at the source ─────────────────────────────

class TestPhase5Suppression(unittest.TestCase):

    def test_model_is_not_consulted_without_evidence(self):
        """Suppress before predicting, so prior-driven techniques never reach the
        manifest, the narrative or the signature cache."""
        import app.core.pipeline as p
        with patch.object(p.ttp_classifier, "predict") as mock_predict, \
             patch.object(p.classifier, "predict", side_effect=FileNotFoundError):
            ttps, family, conf = AnalysisPipeline.run_phase5_ml_classification(
                [0.0] * N_TTP_FEATURES, [0.0] * 33, evidence_present=False
            )
        mock_predict.assert_not_called()
        self.assertEqual(ttps, {})

    def test_predictions_flow_when_evidence_is_present(self):
        import app.core.pipeline as p
        preds = {"T1429": 0.9912, "T1616": 0.9909, "T1471": 0.12}
        with patch.object(p.ttp_classifier, "predict", return_value=preds), \
             patch.object(p.ttp_classifier, "thresholds", return_value={}), \
             patch.object(p.classifier, "predict", side_effect=FileNotFoundError):
            ttps, _, _ = AnalysisPipeline.run_phase5_ml_classification(
                [0.5] * N_TTP_FEATURES, [0.0] * 33, evidence_present=True
            )
        self.assertEqual(sorted(ttps), ["T1429", "T1616"])

    def test_calibrated_thresholds_override_the_global_cut(self):
        """A bundle carrying per-label thresholds must beat the global 0.5 — one
        cut cannot serve labels whose prevalence spans 0.02 to 0.75."""
        import app.core.pipeline as p
        preds = {"T1471": 0.60, "T1418": 0.55}
        with patch.object(p.ttp_classifier, "predict", return_value=preds), \
             patch.object(p.ttp_classifier, "thresholds",
                          return_value={"T1471": 0.85, "T1418": 0.50}), \
             patch.object(p.classifier, "predict", side_effect=FileNotFoundError):
            ttps, _, _ = AnalysisPipeline.run_phase5_ml_classification(
                [0.5] * N_TTP_FEATURES, [0.0] * 33, evidence_present=True
            )
        self.assertEqual(sorted(ttps), ["T1418"],
                         "T1471 at 0.60 is below its calibrated 0.85 threshold")

    def test_uncalibrated_bundle_falls_back_to_global_threshold(self):
        import app.core.pipeline as p
        with patch.object(p.ttp_classifier, "predict", return_value={"T1429": 0.51}), \
             patch.object(p.ttp_classifier, "thresholds", return_value={}), \
             patch.object(p.classifier, "predict", side_effect=FileNotFoundError):
            ttps, _, _ = AnalysisPipeline.run_phase5_ml_classification(
                [0.5] * N_TTP_FEATURES, [0.0] * 33, evidence_present=True
            )
        self.assertEqual(sorted(ttps), ["T1429"])


# ─── The analyst is told, not just the log ──────────────────────────────────

class TestSuppressionReachesTheReport(unittest.TestCase):

    def test_limitation_is_surfaced_when_the_gate_fires(self):
        from app.core.schemas import IngestionResult, SignatureYaraResult, RiskScoreBreakdown

        ingestion = IngestionResult(sha256="dd" * 32, package_name="com.empty", permissions=[])
        risk = RiskScoreBreakdown(
            classifier_confidence_component=0.0, permission_api_component=0.0,
            ttp_severity_component=0.0, forensic_anchor_component=0.0,
            obfuscation_component=0.0, reputation_component=1.5, ioc_component=0.0,
            total_score=1.5, verdict_band="low",
        )
        obf = _obfuscation()

        # _run_analysis hashes the file before deciding whether to parse it,
        # so the hash is its own dependency now, not something the mocked
        # pipeline supplies. The value does not matter (lookup_signature is
        # patched) but the read is real, and /fake/test.apk does not exist.
        with patch("app.api.routes.AnalysisPipeline") as mp, \
             patch("app.api.routes.compute_sha256", return_value="dd" * 32), \
             patch("app.api.routes.lookup_signature", return_value=None), \
             patch("app.api.routes.store_signature"):
            mp.run_phase1_ingestion.return_value = (
                ingestion, MagicMock(), MagicMock(), MagicMock(), []
            )
            mp.run_phase1b_signature_yara.return_value = SignatureYaraResult()
            mp.run_phase2_graph_construction.return_value = ({}, 0.0)   # 0 CFGs
            mp.run_phase3_forensic_matching.return_value = ({}, [], []) # 0 anchors
            mp.run_phase3b_re_deepdive.return_value = ([], [], [], [])
            mp.run_phase4_feature_engineering.return_value = (
                obf, [0.0] * len(FEATURE_NAMES), [0.0] * N_TTP_FEATURES, 0.0, 0
            )
            mp.run_phase5_ml_classification.return_value = ({}, None, None)
            mp.run_phase6_risk_scoring.return_value = risk
            mp.run_phase7_reporting.return_value = ("narrative", [], None)
            # Phase 5.5 returns a plain dict (AnalysisManifest.impersonation is a
            # dict field); a bare MagicMock fails schema validation.
            mp.run_phase5b_impersonation.return_value = {
                "findings": [], "coverage": [], "brands_checked": 0, "max_severity": 0.0,
            }
            mp.merge_c2_from_strings.return_value = ingestion

            from app.api.routes import _run_analysis
            report = _run_analysis("/fake/empty.apk")

        self.assertIn(NO_CLASSIFIER_EVIDENCE_NOTE, report.limitations)
        # Phase 5 and Phase 6 must both have been told.
        self.assertFalse(
            mp.run_phase5_ml_classification.call_args[1]["evidence_present"]
        )
        self.assertFalse(
            mp.run_phase6_risk_scoring.call_args[1]["classifier_evidence_present"]
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
