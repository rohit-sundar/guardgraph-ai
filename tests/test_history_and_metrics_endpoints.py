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
        with patch.object(routes_module, "list_history", return_value=[]):
            resp = self.client.get("/analyses")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), [])

    def test_row_shape_and_band_derivation(self):
        with patch.object(routes_module, "list_history", return_value=[
            {"sha256": "aa" * 32, "app_name": "evil.apk",
             "family": "banker", "risk_score": 76.94, "analyzed_at": 1700000000000},
        ]):
            resp = self.client.get("/analyses")
        row = resp.json()[0]
        self.assertEqual(row["sha256"], "aa" * 32)
        self.assertEqual(row["app_name"], "evil.apk")
        self.assertEqual(row["verdict_band"], "malicious")

    def test_falls_back_to_the_sha_when_no_name_was_recovered(self):
        """An APK that failed to parse has no package name to record, so the row
        still has to identify itself — by hash rather than by a blank cell."""
        with patch.object(routes_module, "list_history", return_value=[
            {"sha256": "bb" * 32, "app_name": None,
             "family": None, "risk_score": 10.0, "analyzed_at": None},
        ]):
            resp = self.client.get("/analyses")
        self.assertEqual(resp.json()[0]["app_name"], "bb" * 32)

    def test_no_score_yields_no_band_rather_than_a_default_low(self):
        """A None risk_score must not silently render as `low` — the mildest
        verdict is the worst possible thing to show for an unknown one."""
        with patch.object(routes_module, "list_history", return_value=[
            {"sha256": "cc" * 32, "app_name": "x",
             "family": None, "risk_score": None, "analyzed_at": None},
        ]):
            resp = self.client.get("/analyses")
        self.assertIsNone(resp.json()[0]["verdict_band"])

    def test_history_is_not_backed_by_the_whole_graph(self):
        """The panel must show what THIS instance analysed, not every Sample node.
        The graph also holds bulk-loaded corpus samples nobody uploaded here, and
        listing those claimed hundreds of analyses that never happened."""
        with patch.object(routes_module, "list_history", return_value=[]) as listed:
            self.client.get("/analyses?limit=5")
        listed.assert_called_once_with(limit=5)
        self.assertFalse(hasattr(routes_module, "list_recent_samples"))


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


# ─── The on-disk history log (app/core/history.py) ──────────────────────────
# Split out of Neo4j because the graph answers a different question. It holds a
# Sample node for every corpus APK the population scripts loaded, so using it to
# populate "Analysis History" told the operator they had analysed hundreds of
# files they had never uploaded — and restarting the server changed nothing,
# since the graph is persistent by design.

class TestHistoryStore(unittest.TestCase):

    def setUp(self):
        import tempfile
        from pathlib import Path
        from app.core import history as history_module
        self.history = history_module
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self._patch = patch.object(
            history_module, "_HISTORY_PATH", Path(self._tmp.name) / "analysis_history.json"
        )
        self._patch.start()
        self.addCleanup(self._patch.stop)

    def test_missing_file_reads_as_empty_not_an_error(self):
        self.assertEqual(self.history.list_history(), [])

    def test_records_and_returns_newest_first(self):
        self.history.record_analysis("aa" * 32, "com.first", None, 10.0)
        self.history.record_analysis("bb" * 32, "com.second", "Cerberus", 80.0)
        rows = self.history.list_history()
        self.assertEqual([r["app_name"] for r in rows], ["com.second", "com.first"])

    def test_reanalysis_moves_the_row_up_without_duplicating_it(self):
        """The panel answers 'what have I looked at', not 'how many times did I
        press upload'."""
        self.history.record_analysis("aa" * 32, "com.first", None, 10.0)
        self.history.record_analysis("bb" * 32, "com.second", None, 20.0)
        self.history.record_analysis("aa" * 32, "com.first", None, 55.0)
        rows = self.history.list_history()
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["sha256"], "aa" * 32)
        self.assertEqual(rows[0]["risk_score"], 55.0)

    def test_survives_a_corrupt_file_instead_of_failing_the_analysis(self):
        """Recording history is best-effort by contract: a damaged log must never
        take down an analysis that has otherwise fully succeeded."""
        self.history._HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
        self.history._HISTORY_PATH.write_text("{not json at all", encoding="utf-8")
        self.assertEqual(self.history.list_history(), [])
        self.history.record_analysis("aa" * 32, "com.x", None, 1.0)
        self.assertEqual(len(self.history.list_history()), 1)

    def test_entry_count_is_bounded(self):
        for i in range(self.history._MAX_ENTRIES + 25):
            self.history.record_analysis(f"{i:064x}", f"com.app{i}", None, float(i))
        self.assertEqual(len(self.history.list_history(limit=10_000)),
                         self.history._MAX_ENTRIES)

    def test_clear_empties_the_log_and_reports_what_it_held(self):
        """The returned hashes are what lets the caller drop the matching cached
        verdicts — clearing the list alone would leave an empty panel whose
        samples still answer from cache."""
        self.history.record_analysis("aa" * 32, "com.first", None, 10.0)
        self.history.record_analysis("bb" * 32, "com.second", None, 20.0)
        cleared = self.history.clear_history()
        self.assertCountEqual(cleared, ["aa" * 32, "bb" * 32])
        self.assertEqual(self.history.list_history(), [])

    def test_clearing_an_empty_log_is_not_an_error(self):
        self.assertEqual(self.history.clear_history(), [])


class TestClearAnalysesEndpoint(unittest.TestCase):
    """DELETE /analyses — clears the panel AND the cached verdicts behind it."""

    def setUp(self):
        self.client = TestClient(app)

    def test_drops_the_cached_verdict_for_every_cleared_row(self):
        with patch.object(routes_module, "clear_history",
                          return_value=["aa" * 32, "bb" * 32]), \
             patch.object(routes_module, "delete_sample", return_value=True) as deleted:
            resp = self.client.delete("/analyses")
        self.assertEqual(resp.status_code, 200)
        # corpus_samples_dropped reports how many of the cleared rows the graph
        # records as corpus-loaded — see tests/test_history_clear_scope.py.
        self.assertEqual(resp.json(), {"cleared": 2, "cached_verdicts_dropped": 2,
                                       "corpus_samples_dropped": 0})
        self.assertEqual(deleted.call_count, 2)

    def test_one_failed_deletion_does_not_abort_the_rest(self):
        """The log is emptied before any node is dropped, so bailing out midway
        would strand cached verdicts with no list left pointing at them."""
        with patch.object(routes_module, "clear_history",
                          return_value=["aa" * 32, "bb" * 32, "cc" * 32]), \
             patch.object(routes_module, "delete_sample",
                          side_effect=[True, RuntimeError("neo4j down"), True]) as deleted:
            resp = self.client.delete("/analyses")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["cleared"], 3)
        self.assertEqual(resp.json()["cached_verdicts_dropped"], 2)
        self.assertEqual(deleted.call_count, 3)

    def test_clearing_an_empty_history_succeeds(self):
        with patch.object(routes_module, "clear_history", return_value=[]), \
             patch.object(routes_module, "delete_sample") as deleted:
            resp = self.client.delete("/analyses")
        self.assertEqual(resp.json(), {"cleared": 0, "cached_verdicts_dropped": 0,
                                       "corpus_samples_dropped": 0})
        deleted.assert_not_called()


if __name__ == "__main__":
    unittest.main()
