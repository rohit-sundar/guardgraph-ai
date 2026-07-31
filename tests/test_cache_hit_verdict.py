"""
Regression test: hot-path cache hit rescored known malware from emptied inputs.

  compute_risk_score() was
  called with predicted_ttps={}, matched_anchor_behaviors=set() and a blank
  ObfuscationSignal, so cached_score only entered the total via
  reputation_component at weight 0.05 — an 86.14/"malicious" cold-path verdict
  came back as 27.81/"low" on the very next upload of the same sample, while
  the cached narrative in that same response still said 86.14.

Fix: a cache hit now returns the cached total_score and verdict band
verbatim (component sub-scores are None — "not recomputed on this path",
not 0.0 — and the cached technique-probability map, not {}).

Fully offline — no Neo4j or Ollama required.
"""
import sys
import os
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class TestCacheHitPreservesVerdict(unittest.TestCase):

    def _run_hot_path(self, cached_row):
        from app.core.schemas import IngestionResult, SignatureYaraResult
        ingestion = IngestionResult(
            sha256="dd" * 32, package_name="com.nexus.pay", permissions=[]
        )

        with patch("app.api.routes.AnalysisPipeline") as mp, \
             patch("app.api.routes.lookup_signature", return_value=cached_row):
            mp.run_phase1_ingestion.return_value = (
                ingestion, MagicMock(), MagicMock(), MagicMock(), MagicMock()
            )

            from app.api.routes import _run_analysis
            return _run_analysis("/fake/test.apk")

    def test_known_malicious_sample_stays_malicious_on_cache_hit(self):
        """The exact regression: 86.14/malicious must NOT come back as 27.81/low."""
        cached_row = {
            "sha256": "dd" * 32,
            "family": "banker",
            "base_score": 86.14,
            "narrative": "Total Score: 86.14 ...",
            "limitations": [],
            "ttps": {"T1429": 0.9912, "T1616": 0.9909},
        }
        result = self._run_hot_path(cached_row)

        self.assertEqual(result.risk_score.total_score, 86.14)
        self.assertEqual(result.risk_score.verdict_band, "malicious")
        self.assertEqual(result.manifest.predicted_ttps, {"T1429": 0.9912, "T1616": 0.9909})

    def test_component_subscores_are_none_not_zero(self):
        """None means 'not recomputed on this path' — 0.0 would falsely claim
        'we looked and found no evidence'."""
        cached_row = {
            "sha256": "dd" * 32, "family": "", "base_score": 50.0,
            "narrative": "n", "limitations": [], "ttps": {},
        }
        result = self._run_hot_path(cached_row)

        self.assertIsNone(result.risk_score.classifier_confidence_component)
        self.assertIsNone(result.risk_score.permission_api_component)
        self.assertIsNone(result.risk_score.ttp_severity_component)
        self.assertIsNone(result.risk_score.forensic_anchor_component)
        self.assertIsNone(result.risk_score.obfuscation_component)
        self.assertIsNone(result.risk_score.reputation_component)
        self.assertIsNone(result.risk_score.ioc_component)

    def test_verdict_band_matches_score_at_every_boundary(self):
        for score, expected_band in [(10.0, "low"), (45.0, "suspicious"),
                                      (70.0, "high"), (95.0, "malicious")]:
            cached_row = {
                "sha256": "dd" * 32, "family": "", "base_score": score,
                "narrative": "n", "limitations": [], "ttps": {},
            }
            result = self._run_hot_path(cached_row)
            self.assertEqual(result.risk_score.total_score, score)
            self.assertEqual(result.risk_score.verdict_band, expected_band)


if __name__ == "__main__":
    unittest.main(verbosity=2)
