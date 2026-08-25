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

        # _run_analysis hashes the file before deciding whether to parse it,
        # so the hash is its own dependency now, not something the mocked
        # pipeline supplies. The value does not matter (lookup_signature is
        # patched) but the read is real, and /fake/test.apk does not exist.
        with patch("app.api.routes.AnalysisPipeline") as mp, \
             patch("app.api.routes.compute_sha256", return_value="dd" * 32), \
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


class TestColdAndHotPathAgreeOnFamily(unittest.TestCase):
    """
    The family shown on a first analysis must be the family shown when the same
    APK is re-uploaded.

    The auxiliary family classifier is usually untrained, so the cold path's
    `predicted_family` is None — but a third-party signature lookup often names
    the family outright, and that name is what gets persisted. Deciding the
    family only at the cache write left the cold path reporting "unclassified"
    for a sample that came back as "Cerberus" on the very next upload, since the
    hot path reads the stored value.

    Fully offline — no Neo4j, no Ollama, no APK.
    """

    def _run_cold_path(self, signature_family, classifier_family=None):
        """Runs _run_analysis on a cache miss, returning (report, stored_family)."""
        from app.core.schemas import (
            IngestionResult, ObfuscationSignal, RiskScoreBreakdown,
            SignatureMatch, SignatureYaraResult,
        )

        ingestion = IngestionResult(
            sha256="ee" * 32, package_name="com.nexus.pay", permissions=[]
        )
        sig_yara = SignatureYaraResult(
            signature_matches=[SignatureMatch(
                match_type="sha256", matched_value="ee" * 32, family=signature_family,
                severity=0.95, source="MalwareBazaar", description="hit",
            )],
            yara_matches=[], is_known_malware=True, combined_severity=0.95,
            yara_scan_targets=[],
        )
        obfuscation = ObfuscationSignal(
            string_entropy_score=0.0, flattening_suspected=False,
            flattening_outlier_nodes=[], reflection_call_count=0,
            unresolved_reflection_targets=0, method_parse_failure_rate=0.0,
            coverage_note="none",
        )
        risk = RiskScoreBreakdown(
            total_score=70.0, verdict_band="high", zero_day_indicator=False
        )

        # _run_analysis hashes the file before deciding whether to parse it,
        # so the hash is its own dependency now, not something the mocked
        # pipeline supplies. The value does not matter (lookup_signature is
        # patched) but the read is real, and /fake/test.apk does not exist.
        with patch("app.api.routes.AnalysisPipeline") as mp, \
             patch("app.api.routes.compute_sha256", return_value="dd" * 32), \
             patch("app.api.routes.lookup_signature", return_value=None), \
             patch("app.api.routes.find_related_samples", return_value=[]), \
             patch("app.api.routes._build_ttp_context", return_value=[]), \
             patch("app.api.routes.store_signature") as store:
            mp.run_phase1_ingestion.return_value = (
                ingestion, MagicMock(), MagicMock(), MagicMock(), []
            )
            mp.run_phase1b_signature_yara.return_value = sig_yara
            mp.run_phase2_graph_construction.return_value = ({}, 0.0)
            mp.run_phase3_forensic_matching.return_value = ({}, [], [])
            mp.merge_c2_from_strings.return_value = ingestion
            mp.run_phase3b_re_deepdive.return_value = ([], [], [], [])
            mp.run_phase4_feature_engineering.return_value = (
                obfuscation, [], [], 0.0, 0
            )
            # The classifier's own answer — None whenever it is untrained.
            mp.run_phase5_ml_classification.return_value = ({}, classifier_family, None)
            mp.run_phase5b_impersonation.return_value = {
                "findings": [], "coverage": [], "brands_checked": 0, "max_severity": 0.0,
            }
            mp.run_phase6_risk_scoring.return_value = risk
            mp.run_phase7_reporting.return_value = ("narrative", [], None)

            from app.api.routes import _run_analysis
            report = _run_analysis("/fake/test.apk")

        self.assertTrue(store.called, "cold path must persist the verdict")
        return report, store.call_args.kwargs["family"]

    def test_signature_family_reaches_the_manifest_not_just_the_cache(self):
        """The regression: manifest said None while the cache stored 'Cerberus'."""
        report, stored = self._run_cold_path(signature_family="Cerberus")

        self.assertEqual(report.manifest.predicted_family, "Cerberus")
        self.assertEqual(stored, "Cerberus")
        # A hash match is not a probability — the classifier's confidence field
        # must not be borrowed to describe it.
        self.assertIsNone(report.manifest.family_confidence)

    def test_signature_family_is_normalised_before_use(self):
        """A VirusTotal detection label must not reach the graph verbatim."""
        report, stored = self._run_cold_path(signature_family="trojan.sharkbot/andr")

        self.assertEqual(report.manifest.predicted_family, "sharkbot")
        self.assertEqual(stored, "sharkbot")

    def test_placeholder_family_does_not_displace_the_classifier(self):
        """'unknown' names no family, so the classifier's answer still stands."""
        report, stored = self._run_cold_path(
            signature_family="unknown", classifier_family="banker"
        )

        self.assertEqual(report.manifest.predicted_family, "banker")
        self.assertEqual(stored, "banker")

    def test_no_family_anywhere_stores_empty_not_a_placeholder(self):
        report, stored = self._run_cold_path(signature_family="unknown")

        self.assertIsNone(report.manifest.predicted_family)
        self.assertEqual(stored, "")


class TestSkippedReportDoesNotPoisonTheCache(unittest.TestCase):
    """
    `skip_report=true` bypasses the ~2-minute LLM call for bulk population runs.
    generate_report returns a placeholder string in that case, and storing it put
    a TRUTHY narrative in the cache: the hot path's `if not narrative` guard never
    fired, so every later upload of that sample rendered
    "[Report generation skipped ...]" in the report tab as though it were the
    analyst report. store_signature only runs on a cache MISS, so the text stuck
    permanently — re-uploading could not fix it.

    An empty narrative is the truthful record, and every consumer already handles
    it. Regenerating on the hot path is NOT the answer: the cache-hit manifest
    carries total_nodes_parsed=0 and behavioral_subgraphs=[] because the CFG is
    never rebuilt there, so a narrative written from it would state that no
    behavioral subgraphs were observed for a sample that had hundreds.
    """

    def _cold_path_with_skip(self, skip_report):
        from app.core.schemas import (
            IngestionResult, ObfuscationSignal, RiskScoreBreakdown,
        )

        ingestion = IngestionResult(
            sha256="ab" * 32, package_name="com.nexus.pay", permissions=[]
        )
        obfuscation = ObfuscationSignal(
            string_entropy_score=0.0, flattening_suspected=False,
            flattening_outlier_nodes=[], reflection_call_count=0,
            unresolved_reflection_targets=0, method_parse_failure_rate=0.0,
            coverage_note="none",
        )
        risk = RiskScoreBreakdown(
            total_score=70.0, verdict_band="high", zero_day_indicator=False
        )
        placeholder = "[Report generation skipped — bulk population run]"

        # _run_analysis hashes the file before deciding whether to parse it,
        # so the hash is its own dependency now, not something the mocked
        # pipeline supplies. The value does not matter (lookup_signature is
        # patched) but the read is real, and /fake/test.apk does not exist.
        with patch("app.api.routes.AnalysisPipeline") as mp, \
             patch("app.api.routes.compute_sha256", return_value="dd" * 32), \
             patch("app.api.routes.lookup_signature", return_value=None), \
             patch("app.api.routes.find_related_samples", return_value=[]), \
             patch("app.api.routes._build_ttp_context", return_value=[]), \
             patch("app.api.routes.store_signature") as store:
            mp.run_phase1_ingestion.return_value = (
                ingestion, MagicMock(), MagicMock(), MagicMock(), []
            )
            mp.run_phase1b_signature_yara.return_value = None
            mp.run_phase2_graph_construction.return_value = ({}, 0.0)
            mp.run_phase3_forensic_matching.return_value = ({}, [], [])
            mp.merge_c2_from_strings.return_value = ingestion
            mp.run_phase3b_re_deepdive.return_value = ([], [], [], [])
            mp.run_phase4_feature_engineering.return_value = (
                obfuscation, [], [], 0.0, 0
            )
            mp.run_phase5_ml_classification.return_value = ({}, None, None)
            mp.run_phase5b_impersonation.return_value = {
                "findings": [], "coverage": [], "brands_checked": 0, "max_severity": 0.0,
            }
            mp.run_phase6_risk_scoring.return_value = risk
            mp.run_phase7_reporting.return_value = (
                (placeholder, [], None) if skip_report else ("Real prose.", [], {"passed": True})
            )

            from app.api.routes import _run_analysis
            report = _run_analysis("/fake/test.apk", skip_report=skip_report)

        return report, store.call_args.kwargs["narrative"]

    def test_skipped_report_is_stored_as_empty_not_a_placeholder(self):
        report, stored = self._cold_path_with_skip(skip_report=True)

        self.assertEqual(stored, "", "the placeholder must not enter the cache")
        # The immediate response still says so plainly — the caller asked for it.
        self.assertIn("skipped", report.narrative_report.lower())

    def test_a_real_narrative_is_stored_verbatim(self):
        report, stored = self._cold_path_with_skip(skip_report=False)

        self.assertEqual(stored, "Real prose.")
        self.assertEqual(report.narrative_report, "Real prose.")

    def test_cache_hit_without_a_narrative_says_how_to_get_one(self):
        """
        The analyst must be told the report is obtainable, and how. A cache hit
        cannot generate it — only a fresh cold path can.
        """
        cached_row = {
            "sha256": "dd" * 32, "family": "Cerberus", "base_score": 70.0,
            "narrative": "", "limitations": [], "ttps": {},
            "resolved_crypto_configs": [],
        }
        # _run_analysis hashes the file before deciding whether to parse it,
        # so the hash is its own dependency now, not something the mocked
        # pipeline supplies. The value does not matter (lookup_signature is
        # patched) but the read is real, and /fake/test.apk does not exist.
        with patch("app.api.routes.AnalysisPipeline") as mp, \
             patch("app.api.routes.compute_sha256", return_value="dd" * 32), \
             patch("app.api.routes.lookup_signature", return_value=cached_row):
            from app.core.schemas import IngestionResult
            mp.run_phase1_ingestion.return_value = (
                IngestionResult(sha256="dd" * 32, package_name="com.a", permissions=[]),
                MagicMock(), MagicMock(), MagicMock(), MagicMock(),
            )
            mp.run_phase5b_impersonation.return_value = {
                "findings": [], "coverage": [], "brands_checked": 0, "max_severity": 0.0,
            }
            from app.api.routes import _run_analysis
            result = _run_analysis("/fake/test.apk")

        joined = " ".join(result.limitations)
        self.assertIn("clear_sample.py", joined)
        self.assertIn("report generation disabled", joined)
        # The grounding-persistence line diagnoses a DIFFERENT problem (an old
        # record) and must not fire when the record simply has no narrative.
        self.assertNotIn("predates grounding-check persistence", joined)

    def test_grounding_persistence_note_still_fires_for_a_real_old_record(self):
        """The gate added above must not silence the case it was written for."""
        cached_row = {
            "sha256": "dd" * 32, "family": "Cerberus", "base_score": 70.0,
            "narrative": "An older narrative with no stored grounding.",
            "limitations": [], "ttps": {}, "resolved_crypto_configs": [],
        }
        # _run_analysis hashes the file before deciding whether to parse it,
        # so the hash is its own dependency now, not something the mocked
        # pipeline supplies. The value does not matter (lookup_signature is
        # patched) but the read is real, and /fake/test.apk does not exist.
        with patch("app.api.routes.AnalysisPipeline") as mp, \
             patch("app.api.routes.compute_sha256", return_value="dd" * 32), \
             patch("app.api.routes.lookup_signature", return_value=cached_row):
            from app.core.schemas import IngestionResult
            mp.run_phase1_ingestion.return_value = (
                IngestionResult(sha256="dd" * 32, package_name="com.a", permissions=[]),
                MagicMock(), MagicMock(), MagicMock(), MagicMock(),
            )
            mp.run_phase5b_impersonation.return_value = {
                "findings": [], "coverage": [], "brands_checked": 0, "max_severity": 0.0,
            }
            from app.api.routes import _run_analysis
            result = _run_analysis("/fake/test.apk")

        self.assertIn("predates grounding-check persistence", " ".join(result.limitations))


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

        # _run_analysis hashes the file before deciding whether to parse it,
        # so the hash is its own dependency now, not something the mocked
        # pipeline supplies. The value does not matter (lookup_signature is
        # patched) but the read is real, and /fake/test.apk does not exist.
        with patch("app.api.routes.AnalysisPipeline") as mp, \
             patch("app.api.routes.compute_sha256", return_value="dd" * 32), \
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


class TestHotPathDoesNotPayForTheParseItDiscards(unittest.TestCase):
    """
    The cache is keyed on the SHA-256 of the raw bytes, but the lookup used to sit
    BEHIND a full Androguard pass — so answering "known sample, here is the stored
    verdict" still paid the entire cost of analysing it. Measured on a 7.5 MB APK:
    AnalyzeAPK 13.42s of a 13.6s ingestion, against 0.013s to hash and 0.006s to
    query Neo4j warm.

    Two things have to stay true for that to keep working, and neither is visible
    in a response body — which is why they are asserted on the call itself.
    """

    def _run(self, cached_row):
        from app.core.schemas import IngestionResult
        ingestion = IngestionResult(sha256="dd" * 32, package_name="com.x", permissions=[])

        with patch("app.api.routes.AnalysisPipeline") as mp, \
             patch("app.api.routes.compute_sha256", return_value="ab" * 32) as mock_hash, \
             patch("app.api.routes.lookup_signature", return_value=cached_row) as mock_lookup, \
             patch("app.api.routes.store_signature"):
            mp.run_phase1_ingestion.return_value = (
                ingestion, MagicMock(), MagicMock(), MagicMock(), []
            )
            mp.run_phase5b_impersonation.return_value = {
                "findings": [], "coverage": [], "brands_checked": 0, "max_severity": 0.0,
            }
            from app.api.routes import _run_analysis
            try:
                _run_analysis("/fake/test.apk", skip_report=True)
            except Exception:
                # A cache MISS runs the rest of the cold path against mocks and may
                # fail further down; irrelevant here — the assertions below are about
                # what happened before that point.
                pass
            return mock_hash, mock_lookup, mp

    def test_the_cache_is_queried_with_the_raw_hash_before_anything_is_parsed(self):
        """
        The lookup must use the independently computed hash, not
        ingestion.sha256 — reading it off the ingestion result is what forced the
        parse to happen first. The two are deliberately different values here so
        the wrong source cannot pass by coincidence.
        """
        mock_hash, mock_lookup, mp = self._run({"sha256": "ab" * 32, "base_score": 70.0,
                                                "narrative": "n", "ttps": {}})
        mock_hash.assert_called_once_with("/fake/test.apk")
        mock_lookup.assert_called_once_with("ab" * 32)

    def test_a_cache_hit_skips_the_dex_analysis_pass(self):
        _, _, mp = self._run({"sha256": "ab" * 32, "base_score": 70.0,
                              "narrative": "n", "ttps": {}})
        _, kwargs = mp.run_phase1_ingestion.call_args
        self.assertTrue(kwargs["skip_dex_analysis"],
                        "hot path rebuilt the DEX cross-reference graph it never reads")

    def test_a_cache_miss_still_runs_the_full_pass(self):
        """
        The other half of the guard. The cold path builds CFGs from the Analysis
        object, so skipping it there would not be an optimisation — it would
        silently produce an analysis with no graph in it.
        """
        _, _, mp = self._run(None)
        _, kwargs = mp.run_phase1_ingestion.call_args
        self.assertFalse(kwargs["skip_dex_analysis"])


class TestManifestOnlyIngestionKeepsWhatTheHotPathReads(unittest.TestCase):
    """
    Parity check against a real APK, because the hot path's correctness now
    depends on skip_dex_analysis populating everything except the DEX method
    count. In particular it must still recover app_label, icon_phash and
    cert_thumbprint: the impersonation check re-runs on every cache hit so an
    updated brand table applies to already-cached samples, and it reads exactly
    those three fields.
    """

    APK = os.path.join(os.path.dirname(__file__), "..", "guardgraph_test", "guardgraph_test.apk")

    @classmethod
    def setUpClass(cls):
        if not os.path.exists(cls.APK):
            raise unittest.SkipTest(f"test APK not present at {cls.APK}")
        from app.analysis.ingest import ingest_apk
        cls.fast, _, cls.fast_dvm, cls.fast_analysis, _ = ingest_apk(
            cls.APK, skip_dex_analysis=True
        )
        cls.full, _, _, _, _ = ingest_apk(cls.APK)

    def test_no_dex_objects_are_built(self):
        self.assertIsNone(self.fast_dvm)
        self.assertIsNone(self.fast_analysis)

    def test_identity_fields_the_impersonation_check_needs_survive(self):
        for field in ("sha256", "package_name", "app_label", "icon_phash", "cert_thumbprint"):
            self.assertEqual(getattr(self.fast, field), getattr(self.full, field),
                             f"{field} differs without the DEX pass")

    def test_manifest_and_payload_fields_survive(self):
        for field in ("permissions", "activities", "services", "receivers",
                      "intent_actions", "c2_indicators", "cert_anomalies",
                      "permission_matrix_flags", "secondary_dex_count",
                      "accessibility_flags", "payload_assets", "dropper_signals"):
            self.assertEqual(getattr(self.fast, field), getattr(self.full, field),
                             f"{field} differs without the DEX pass")

    def test_the_method_count_is_the_one_documented_casualty(self):
        """
        Counting methods needs the pass we skipped, so it reports 0. Asserted
        rather than tolerated: if a future change starts reading dex_method_count
        on the hot path, this is the test that should have to be updated first.
        """
        self.assertEqual(self.fast.dex_method_count, 0)
        self.assertGreater(self.full.dex_method_count, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestImpersonationFloorAppliesOnTheHotPath(unittest.TestCase):
    """
    Phase 5.5 deliberately re-runs on every cache hit so an updated brand table
    reaches already-cached samples without re-analysis. But the score came from the
    cached components, so the fresh finding could not move the verdict — the App
    Identity tab read "impersonates Bank of India" above a verdict of `medium`.

    The floor IS the mechanism by which impersonation reaches a verdict, so running
    the check without re-applying it made the fresh run decorative.
    """

    def _run(self, cached_score, findings):
        from app.core.schemas import IngestionResult
        ingestion = IngestionResult(sha256="dd" * 32, package_name="com.x", permissions=[])
        cached_row = {
            "sha256": "dd" * 32, "family": "", "base_score": cached_score,
            "narrative": "n", "limitations": [], "ttps": {},
            "risk_components": {"impersonation_floor_applied": False},
        }
        with patch("app.api.routes.AnalysisPipeline") as mp, \
             patch("app.api.routes.compute_sha256", return_value="dd" * 32), \
             patch("app.api.routes.lookup_signature", return_value=cached_row):
            mp.run_phase1_ingestion.return_value = (
                ingestion, MagicMock(), MagicMock(), MagicMock(), MagicMock()
            )
            mp.run_phase5b_impersonation.return_value = {
                "findings": findings, "coverage": [], "brands_checked": 15,
                "max_severity": max((f.get("severity", 0.0) for f in findings), default=0.0),
            }
            from app.api.routes import _run_analysis
            return _run_analysis("/fake/test.apk")

    def test_a_newly_added_brand_moves_a_cached_verdict(self):
        from app.reports.scoring import IMPERSONATION_SCORE_FLOOR

        result = self._run(35.62, [{"kind": "package_namespace_squat", "brand": "Telegram"}])
        self.assertEqual(result.risk_score.total_score,
                         IMPERSONATION_SCORE_FLOOR["package_namespace_squat"])
        self.assertEqual(result.risk_score.verdict_band, "high")
        self.assertTrue(result.risk_score.impersonation_floor_applied)

    def test_the_floor_never_lowers_a_cached_score(self):
        """
        A floor below the cached total must leave it alone. The hot path returns the
        stored verdict verbatim; this may only ever raise it.
        """
        result = self._run(86.14, [{"kind": "label_impersonation", "brand": "WhatsApp"}])
        self.assertEqual(result.risk_score.total_score, 86.14)
        self.assertEqual(result.risk_score.verdict_band, "malicious")
        self.assertFalse(result.risk_score.impersonation_floor_applied)

    def test_no_findings_leaves_the_cached_verdict_untouched(self):
        result = self._run(35.62, [])
        self.assertEqual(result.risk_score.total_score, 35.62)
        self.assertFalse(result.risk_score.impersonation_floor_applied)


class TestImpersonationFloorAppliesOnTheHotPath(unittest.TestCase):
    """
    Phase 5.5 deliberately re-runs on every cache hit so an updated brand table
    applies to already-cached samples without re-analysis. But the score came
    straight from the cached components, so a newly added brand produced a finding
    in the App Identity tab above a verdict that still read whatever was cached —
    "impersonates Bank of India" sitting on top of a `medium`.

    The floor is the entire mechanism by which impersonation reaches a verdict, so
    re-running the check without re-applying it made the fresh run decorative.
    """

    def _run(self, cached_score, findings):
        from app.core.schemas import IngestionResult
        ingestion = IngestionResult(sha256="dd" * 32, package_name="com.x", permissions=[])
        cached_row = {
            "sha256": "dd" * 32, "family": "", "base_score": cached_score,
            "narrative": "n", "limitations": [], "ttps": {},
            "risk_components": {"impersonation_floor_applied": False},
        }
        # _run_analysis hashes the file before deciding whether to parse it,
        # so the hash is its own dependency now, not something the mocked
        # pipeline supplies. The value does not matter (lookup_signature is
        # patched) but the read is real, and /fake/test.apk does not exist.
        with patch("app.api.routes.AnalysisPipeline") as mp, \
             patch("app.api.routes.compute_sha256", return_value="dd" * 32), \
             patch("app.api.routes.lookup_signature", return_value=cached_row):
            mp.run_phase1_ingestion.return_value = (
                ingestion, MagicMock(), MagicMock(), MagicMock(), MagicMock()
            )
            mp.run_phase5b_impersonation.return_value = {
                "findings": findings, "coverage": [], "brands_checked": 15,
                "max_severity": max((f.get("severity", 0.0) for f in findings), default=0.0),
            }
            from app.api.routes import _run_analysis
            return _run_analysis("/fake/test.apk")

    def test_a_newly_detected_clone_raises_a_cached_verdict(self):
        report = self._run(35.62, [{"kind": "certificate_mismatch", "brand": "Bank of India"}])
        self.assertEqual(report.risk_score.verdict_band, "malicious")
        self.assertTrue(report.risk_score.impersonation_floor_applied)

    def test_the_weakest_finding_still_moves_the_band(self):
        """label_impersonation floors at `suspicious` — the BOI sample in the corpus."""
        report = self._run(20.0, [{"kind": "label_impersonation", "brand": "Bank of India"}])
        self.assertEqual(report.risk_score.verdict_band, "suspicious")
        self.assertTrue(report.risk_score.impersonation_floor_applied)

    def test_the_floor_never_lowers_a_cached_score(self):
        """
        A floor below the cached total must change nothing. Impersonation raises a
        verdict; it is not a re-scoring, and a cached `malicious` must not be talked
        down to `high` by a weaker fresh finding.
        """
        report = self._run(92.0, [{"kind": "package_typosquat", "brand": "Telegram"}])
        self.assertEqual(report.risk_score.total_score, 92.0)
        self.assertEqual(report.risk_score.verdict_band, "malicious")

    def test_no_findings_leaves_the_cached_verdict_untouched(self):
        report = self._run(35.62, [])
        self.assertEqual(report.risk_score.total_score, 35.62)
        self.assertFalse(report.risk_score.impersonation_floor_applied)
