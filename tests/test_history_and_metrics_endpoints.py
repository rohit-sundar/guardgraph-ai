"""
Tests for three additions to app/api/routes.py:

  1. _build_ttp_context now carries each technique's calibrated decision
     threshold, not just its probability — this is what lets the MITRE tab draw
     a tick mark at the boundary that actually governed whether a row surfaced,
     instead of rendering a 0.98-past-a-0.10-threshold hit identically to a
     0.98-past-a-0.90-threshold one.
  2. GET /model/metrics — serves the TTP classifier's own family-held-out vs.
     stratified evaluation, independent of any analysis run.
  3. GET /analyses and GET /analyses/{sha256} — the Analysis History panel's
     backend: a listing of past verdicts and a per-sample reconstruction built
     ENTIRELY from what Neo4j has stored, with no APK file involved.

Fully offline — Neo4j and the classifier bundle are mocked/patched; no live
services, no network.
"""
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi.testclient import TestClient

from app.api import routes as routes_module
from app.main import app


class TestBuildTtpContextThreshold(unittest.TestCase):
    """_build_ttp_context (app/api/routes.py) — the threshold field itself."""

    def test_each_row_carries_its_own_threshold(self):
        with patch.object(
            routes_module, "get_technique_context",
            return_value=[{"technique_id": "T1417", "name": "Input Capture", "tactic": "Collection"}],
        ), patch.object(routes_module, "_ttp_thresholds", return_value={"T1417": 0.9}):
            rows = routes_module._build_ttp_context({"T1417": 0.95})
        self.assertEqual(rows[0]["threshold"], 0.9)

    def test_falls_back_to_the_global_default_when_uncalibrated(self):
        """A label the trained bundle carries no per-technique threshold for
        (or an untrained bundle, thresholds() == {}) falls back to
        TTP_PREDICT_THRESHOLD, not to a missing/None field the UI would choke on."""
        with patch.object(
            routes_module, "get_technique_context",
            return_value=[{"technique_id": "T9999", "name": "?", "tactic": "?"}],
        ), patch.object(routes_module, "_ttp_thresholds", return_value={}):
            rows = routes_module._build_ttp_context({"T9999": 0.6})
        self.assertEqual(rows[0]["threshold"], routes_module.TTP_PREDICT_THRESHOLD)

    def test_empty_predictions_return_empty_list(self):
        self.assertEqual(routes_module._build_ttp_context({}), [])

    def test_ttp_thresholds_never_raises_on_an_untrained_bundle(self):
        """_ttp_thresholds wraps ttp_classifier.thresholds() — an untrained bundle
        raises FileNotFoundError there, and this must degrade to {}, not propagate."""
        with patch.object(
            routes_module.ttp_classifier, "thresholds", side_effect=FileNotFoundError("no bundle")
        ):
            self.assertEqual(routes_module._ttp_thresholds(), {})


class TestModelMetricsEndpoint(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_returns_trained_false_when_the_metrics_file_is_absent(self):
        with patch.object(routes_module.os.path, "exists", return_value=False):
            resp = self.client.get("/model/metrics")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {"trained": False})

    def test_serves_both_evaluations_side_by_side(self):
        fake_metrics = {
            "n_samples": 364, "n_labels": 32,
            "trained_labels": ["T1406", "T1417"], "dropped_labels": ["T1636"],
            "binary_relevance": {"micro_f1": 0.81, "jaccard_samples": 0.31},
            "family_held_out": {
                "micro_f1": 0.35, "jaccard_samples": 0.08,
                "n_splits": 5, "n_family_groups": 15,
                "folds": [{"fold": 0, "families_held_out": ["Cerberus"]}],
            },
        }
        with patch.object(routes_module.os.path, "exists", return_value=True), \
             patch("builtins.open", unittest.mock.mock_open(read_data="{}")), \
             patch.object(routes_module.json, "load", return_value=fake_metrics):
            resp = self.client.get("/model/metrics")

        body = resp.json()
        self.assertTrue(body["trained"])
        self.assertEqual(body["stratified"]["micro_f1"], 0.81)
        self.assertEqual(body["family_held_out"]["micro_f1"], 0.35)
        # The per-fold detail is dropped from the API response — it's a training
        # artifact, not something a judge-facing panel needs to render.
        self.assertNotIn("folds", body["family_held_out"])

    def test_family_held_out_error_surfaces_instead_of_a_crash(self):
        """train_model.py's _family_held_out_metrics can itself report an error
        (too few family groups to evaluate) rather than a metrics dict — the
        endpoint must pass that through, not assume the key is always numeric."""
        fake_metrics = {
            "n_samples": 10, "n_labels": 2, "trained_labels": ["T1406"], "dropped_labels": [],
            "binary_relevance": {"micro_f1": 0.5},
            "family_held_out": {"error": "only 1 malware family group(s)"},
        }
        with patch.object(routes_module.os.path, "exists", return_value=True), \
             patch("builtins.open", unittest.mock.mock_open(read_data="{}")), \
             patch.object(routes_module.json, "load", return_value=fake_metrics):
            resp = self.client.get("/model/metrics")

        body = resp.json()
        self.assertTrue(body["trained"])
        self.assertIsNone(body["family_held_out"])
        self.assertIn("only 1", body["family_held_out_error"])


class TestAnalysesListEndpoint(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_empty_history_returns_empty_list(self):
        with patch.object(routes_module, "list_recent_samples", return_value=[]):
            resp = self.client.get("/analyses")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), [])

    def test_row_shape_and_band_derivation(self):
        with patch.object(routes_module, "list_recent_samples", return_value=[
            {"sha256": "aa" * 32, "app_name": "evil.apk", "package_name": "com.evil",
             "family": "banker", "risk_score": 76.94, "analyzed_at": 1700000000000},
        ]):
            resp = self.client.get("/analyses")
        row = resp.json()[0]
        self.assertEqual(row["sha256"], "aa" * 32)
        self.assertEqual(row["app_name"], "evil.apk")
        self.assertEqual(row["verdict_band"], "malicious")

    def test_falls_back_to_package_name_then_sha_when_app_name_is_missing(self):
        with patch.object(routes_module, "list_recent_samples", return_value=[
            {"sha256": "bb" * 32, "app_name": None, "package_name": "com.x",
             "family": None, "risk_score": 10.0, "analyzed_at": None},
        ]):
            resp = self.client.get("/analyses")
        self.assertEqual(resp.json()[0]["app_name"], "com.x")

    def test_no_score_yields_no_band_rather_than_a_default_low(self):
        """A None risk_score (should not happen given the WHERE clause in
        list_recent_samples, but defend anyway) must not silently render `low`."""
        with patch.object(routes_module, "list_recent_samples", return_value=[
            {"sha256": "cc" * 32, "app_name": "x", "package_name": None,
             "family": None, "risk_score": None, "analyzed_at": None},
        ]):
            resp = self.client.get("/analyses")
        self.assertIsNone(resp.json()[0]["verdict_band"])


class TestGetAnalysisEndpoint(unittest.TestCase):
    """GET /analyses/{sha256} — reconstructed from Neo4j alone, no APK file."""

    def setUp(self):
        self.client = TestClient(app)
        self.sha = "dd" * 32

    def test_unknown_sha_returns_404(self):
        with patch.object(routes_module, "lookup_signature", return_value=None):
            resp = self.client.get(f"/analyses/{self.sha}")
        self.assertEqual(resp.status_code, 404)

    def test_reconstructs_score_and_narrative_from_the_stored_record(self):
        cached = {
            "sha256": self.sha, "family": "banker", "base_score": 76.94,
            "ttps": {"T1417": 0.9}, "narrative": "stored narrative text",
            "limitations": ["prior limitation"],
            "risk_components": {"total_score": 76.94, "classifier_confidence_component": 24.18},
            "obfuscation_data": None, "signature_yara_data": None,
            "permissions": ["android.permission.SEND_SMS"],
            "c2_indicators": [], "cert_thumbprint": None, "package_name": "com.evil",
        }
        with patch.object(routes_module, "lookup_signature", return_value=cached), \
             patch.object(routes_module, "find_related_samples", return_value=[]), \
             patch.object(routes_module, "get_technique_context", return_value=[]):
            resp = self.client.get(f"/analyses/{self.sha}")

        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["risk_score"]["total_score"], 76.94)
        self.assertEqual(body["risk_score"]["verdict_band"], "malicious")
        self.assertEqual(body["narrative_report"], "stored narrative text")
        self.assertEqual(body["manifest"]["target_package"], "com.evil")
        self.assertEqual(body["manifest"]["cache_hit"], True)

    def test_flags_itself_as_a_historical_record_in_limitations(self):
        """The response must say plainly that file-dependent fields (cert
        anomalies, impersonation, resolved crypto/DCL/etc.) are not recoverable
        here — silence would read as "this APK has none of those", which is a
        different and false claim."""
        cached = {
            "sha256": self.sha, "family": None, "base_score": 10.0, "ttps": {},
            "narrative": "n", "limitations": [], "risk_components": {},
            "obfuscation_data": None, "signature_yara_data": None,
            "permissions": [], "c2_indicators": [], "cert_thumbprint": None,
            "package_name": None,
        }
        with patch.object(routes_module, "lookup_signature", return_value=cached), \
             patch.object(routes_module, "find_related_samples", return_value=[]), \
             patch.object(routes_module, "get_technique_context", return_value=[]):
            resp = self.client.get(f"/analyses/{self.sha}")

        self.assertTrue(any("HISTORICAL RECORD" in l for l in resp.json()["limitations"]))

    def test_missing_narrative_gets_a_placeholder_not_an_empty_string(self):
        cached = {
            "sha256": self.sha, "family": None, "base_score": 5.0, "ttps": {},
            "narrative": "", "limitations": [], "risk_components": {},
            "obfuscation_data": None, "signature_yara_data": None,
            "permissions": [], "c2_indicators": [], "cert_thumbprint": None,
            "package_name": None,
        }
        with patch.object(routes_module, "lookup_signature", return_value=cached), \
             patch.object(routes_module, "find_related_samples", return_value=[]), \
             patch.object(routes_module, "get_technique_context", return_value=[]):
            resp = self.client.get(f"/analyses/{self.sha}")
        self.assertIn("No narrative stored", resp.json()["narrative_report"])


if __name__ == "__main__":
    unittest.main()
