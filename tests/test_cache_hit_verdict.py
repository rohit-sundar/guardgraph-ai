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
            # The cache-hit path now runs impersonation checks fresh (cheap —
            # Phase 1 ingestion alone is enough) rather than relying on a
            # possibly-absent cached copy; the mocked AnalysisPipeline needs a
            # real dict here or AnalysisManifest's validation rejects the bare
            # MagicMock.
            mp.run_phase5b_impersonation.return_value = {
                "findings": [], "coverage": [], "brands_checked": 0, "max_severity": 0.0,
            }

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
        """
        One sample per band, derived from the boundaries rather than hard-coded, so
        recalibrating them stays a one-line change in scoring.py. The point of this
        test is that the hot path bands a cached score exactly as the cold path would,
        not that any particular number is a boundary.
        """
        from app.reports.scoring import (
            BAND_HIGH_CEILING, BAND_LOW_CEILING, BAND_MEDIUM_CEILING,
            BAND_SUSPICIOUS_CEILING,
        )

        for score, expected_band in [
            (BAND_LOW_CEILING / 2, "low"),
            ((BAND_LOW_CEILING + BAND_MEDIUM_CEILING) / 2, "medium"),
            ((BAND_MEDIUM_CEILING + BAND_SUSPICIOUS_CEILING) / 2, "suspicious"),
            ((BAND_SUSPICIOUS_CEILING + BAND_HIGH_CEILING) / 2, "high"),
            ((BAND_HIGH_CEILING + 100.0) / 2, "malicious"),
        ]:
            cached_row = {
                "sha256": "dd" * 32, "family": "", "base_score": score,
                "narrative": "n", "limitations": [], "ttps": {},
            }
            result = self._run_hot_path(cached_row)
            self.assertEqual(result.risk_score.total_score, score)
            self.assertEqual(result.risk_score.verdict_band, expected_band)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestCachedRecordSurvivesRestart(unittest.TestCase):
    """
    N12: store_signature wrote eleven fields to _MEMORY_CACHE but only five to Neo4j.
    Risk components, obfuscation, YARA results and permissions lived only in the
    in-process dict, so after a restart a cache hit served a total score with EVERY
    component None, no permissions and no signature panel — while the cached
    narrative in the same response still described all of them.

    These tests clear _MEMORY_CACHE between write and read, which is what a process
    restart looks like to this module.
    """

    SHA = "c0ffee11" * 8

    def setUp(self):
        from app.graph.cache import _MEMORY_CACHE

        _MEMORY_CACHE.pop(self.SHA, None)

    def test_encode_decode_roundtrip_without_neo4j(self):
        """The serialisation itself, independent of whether a database is reachable."""
        from app.graph.cache import _encode_record, _decode_record

        payload = {
            "risk_components": {"ioc_component": 4.2, "total_score": 73.5},
            "obfuscation_data": {"string_entropy_score": 3.1},
            "signature_yara_data": {"yara_matches": [{"rule_name": "r"}]},
            "permissions": ["android.permission.READ_SMS"],
            "c2_indicators": ["telegram:bot123"],
            "cert_thumbprint": "ab" * 32,
            "package_name": "com.test.clone",
        }
        decoded = _decode_record(_encode_record(payload), self.SHA)
        for key, value in payload.items():
            self.assertEqual(decoded[key], value, f"{key} did not survive the round trip")

    def test_record_written_before_this_field_existed_decodes_to_empty(self):
        """
        Older Sample nodes carry no record_json. They genuinely have no breakdown to
        recover, so the correct answer is {} — the caller then reports the gap rather
        than substituting zeros, which would assert "we looked and found nothing".
        """
        from app.graph.cache import _decode_record

        self.assertEqual(_decode_record(None, self.SHA), {})
        self.assertEqual(_decode_record("", self.SHA), {})

    def test_unreadable_record_does_not_raise(self):
        from app.graph.cache import _decode_record

        self.assertEqual(_decode_record("{not json", self.SHA), {})

    def test_none_valued_fields_are_dropped_not_resurrected_as_null(self):
        """
        A None component means "not computed". It must not come back as a key whose
        value is None and shadow a real fallback — absent and null are different.
        """
        from app.graph.cache import _encode_record, _decode_record

        decoded = _decode_record(
            _encode_record({"permissions": ["p"], "risk_components": None}), self.SHA
        )
        self.assertIn("permissions", decoded)
        self.assertNotIn("risk_components", decoded)


class TestCacheHitCompletenessSecondPass(unittest.TestCase):
    """
    N15 — the first "hollow cache-hit" fix (record_json persistence) only covered
    the fields that existed in the manifest at the time it was written: risk
    components, obfuscation, permissions, YARA/signature, C2, cert. Everything
    ADDED after that commit — resolved crypto/DCL/WebView/native findings, the
    grounding result, brand impersonation, app identity — still went hollow on a
    cache hit, because "cache hit" was never re-audited against the full current
    manifest shape, just against what _RECORD_FIELDS happened to list.

    Found live: a real cached sample rendered N/A across every risk component,
    0 YARA matches, and "no narrative was generated" (false — a cached narrative
    was displayed) on the Risk Scoring and GraphRAG tabs simultaneously. All three
    traced to the same root cause under different labels — this class asserts the
    fix at the two different sources of truth those symptoms actually come from:
    persisted record_json (crypto/DCL/WebView/native, grounding) and fresh
    Phase 1 re-ingestion (impersonation, app_label, icon_phash).
    """

    def _run_hot_path(self, cached_row, ingestion=None):
        from app.core.schemas import IngestionResult

        if ingestion is None:
            ingestion = IngestionResult(
                sha256="dd" * 32, package_name="com.nexus.pay", permissions=[],
                app_label="Nexus Pay", icon_phash="abc123",
            )

        with patch("app.api.routes.AnalysisPipeline") as mp, \
             patch("app.api.routes.lookup_signature", return_value=cached_row):
            mp.run_phase1_ingestion.return_value = (
                ingestion, MagicMock(), MagicMock(), MagicMock(), MagicMock()
            )
            mp.run_phase5b_impersonation.return_value = {
                "findings": [{"kind": "certificate_mismatch", "brand": "TestBank"}],
                "coverage": [], "brands_checked": 12, "max_severity": 1.0,
            }
            from app.api.routes import _run_analysis
            return _run_analysis("/fake/test.apk")

    def test_resolved_findings_survive_a_cache_hit_when_persisted(self):
        cached_row = {
            "sha256": "dd" * 32, "family": "banker", "base_score": 70.0,
            "narrative": "n", "limitations": [], "ttps": {},
            "resolved_crypto_configs": ["AES/ECB/NoPadding [WEAK: no IV]"],
            "resolved_dcl_targets": ["/data/data/com.x/payload.dex"],
            "resolved_webview_bridges": ["JSBridge.exec"],
            "resolved_native_bridges": ["libnative.so::doEvil"],
            "grounding": {"passed": True, "passed_count": 3, "total_count": 3, "checks": []},
        }
        result = self._run_hot_path(cached_row)

        self.assertEqual(result.manifest.resolved_crypto_configs, ["AES/ECB/NoPadding [WEAK: no IV]"])
        self.assertEqual(result.manifest.resolved_dcl_targets, ["/data/data/com.x/payload.dex"])
        self.assertEqual(result.manifest.resolved_webview_bridges, ["JSBridge.exec"])
        self.assertEqual(result.manifest.resolved_native_bridges, ["libnative.so::doEvil"])
        self.assertIsNotNone(result.grounding)
        self.assertTrue(result.grounding["passed"])

    def test_older_records_read_empty_not_absent_and_are_flagged(self):
        """A record cached before this fix has none of these keys at all — the
        response must still validate (empty lists, grounding=None) AND say so in
        limitations, rather than silently rendering as "checked, found nothing"."""
        cached_row = {
            "sha256": "dd" * 32, "family": "banker", "base_score": 70.0,
            "narrative": "a real cached narrative", "limitations": [], "ttps": {},
        }
        result = self._run_hot_path(cached_row)

        self.assertEqual(result.manifest.resolved_crypto_configs, [])
        self.assertIsNone(result.grounding)
        joined = " ".join(result.limitations)
        self.assertIn("predates reverse-engineering persistence", joined)
        self.assertIn("predates grounding-check persistence", joined)

    def test_impersonation_runs_fresh_on_every_cache_hit(self):
        """Unlike the resolved_* fields, impersonation/app_label/icon_phash are
        NOT read from the cache at all — they come from Phase 1 ingestion, which
        already re-runs on every request. A finding must appear even though
        nothing about it was ever stored in cached_row."""
        cached_row = {
            "sha256": "dd" * 32, "family": "banker", "base_score": 70.0,
            "narrative": "n", "limitations": [], "ttps": {},
        }
        result = self._run_hot_path(cached_row)

        self.assertEqual(result.manifest.app_label, "Nexus Pay")
        self.assertEqual(result.manifest.icon_phash, "abc123")
        self.assertIsNotNone(result.manifest.impersonation)
        self.assertEqual(
            result.manifest.impersonation["findings"][0]["kind"], "certificate_mismatch"
        )

    def test_no_stale_gap_limitations_when_the_record_is_fully_populated(self):
        """The two honesty notes are additive, not unconditional — a fully
        populated cache hit must not carry warnings about gaps it doesn't have."""
        cached_row = {
            "sha256": "dd" * 32, "family": "banker", "base_score": 70.0,
            "narrative": "n", "limitations": [], "ttps": {},
            "resolved_crypto_configs": [], "resolved_dcl_targets": [],
            "resolved_webview_bridges": [], "resolved_native_bridges": [],
            "grounding": {"passed": True, "passed_count": 1, "total_count": 1, "checks": []},
        }
        result = self._run_hot_path(cached_row)
        joined = " ".join(result.limitations)
        self.assertNotIn("predates reverse-engineering persistence", joined)
        self.assertNotIn("predates grounding-check persistence", joined)
