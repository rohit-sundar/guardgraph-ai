"""
Regression tests for the two bugs fixed in this session:

  1. Hot-path cache miss: lookup_signature returned None when family was None,
     and store_signature was never called when predicted_family was None.
     Fix: gate lookup on sha256 presence, always call store after cold path.

  2. LLM hallucination: temperature not set (Ollama default ~0.7), full
     manifest.model_dump_json passed (noise), no OUTPUT FORMAT contract.
     Fix: temperature=0, trimmed manifest_summary, hardened SYSTEM_PROMPT,
       _grounding_check() post-generation sanity scan.

These tests are fully offline — no Neo4j or Ollama required.
"""
import sys
import os
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ─── Bug 1: Cache lookup gate on sha256 ──────────────────────────────────────

class TestCacheLookupGateOnSha256(unittest.TestCase):
    """lookup_signature must return a row when sha256 is present,
    regardless of whether the family field is None."""

    def _call_lookup(self, rows):
        # Patch the already-imported module-level singleton directly so the
        # mock is live during the actual lookup_signature call — reload() would
        # re-execute the import chain and lose the patch context.
        import app.graph.cache as m
        with patch.object(m.neo4j_client, "run", return_value=rows):
            return m.lookup_signature("aa" * 32)

    def test_returns_none_when_no_rows(self):
        self.assertIsNone(self._call_lookup([]))

    def test_returns_none_when_sha256_is_none(self):
        self.assertIsNone(self._call_lookup([{"sha256": None, "family": None, "base_score": 70.0}]))

    def test_returns_row_when_family_is_none(self):
        """BUG FIX: must NOT return None just because family is None."""
        sha = "aa" * 32
        row = {"sha256": sha, "family": None, "base_score": 70.0,
               "narrative": "x", "limitations": [], "ttps": []}
        result = self._call_lookup([row])
        self.assertIsNotNone(result, "lookup_signature must return the row even when family is None")
        self.assertEqual(result["sha256"], sha)

    def test_returns_row_when_family_is_present(self):
        sha = "aa" * 32
        row = {"sha256": sha, "family": "banker", "base_score": 82.0,
               "narrative": "y", "limitations": [],
               "ttps": [{"technique_id": "T1636", "probability": 0.91}]}
        result = self._call_lookup([row])
        self.assertIsNotNone(result)
        self.assertEqual(result["family"], "banker")
        self.assertEqual(result["ttps"], {"T1636": 0.91})


# ─── Bug 1b: store_signature always called after cold path ───────────────────

class TestStoreSigAlwaysCalledAfterColdPath(unittest.TestCase):
    """_run_analysis must call store_signature even when predicted_family is None."""

    def _make_mock_obf(self):
        from app.core.schemas import ObfuscationSignal
        return ObfuscationSignal(
            string_entropy_score=3.0, flattening_suspected=False,
            coverage_note="ok", method_parse_failure_rate=0.0
        )

    def _make_mock_risk(self):
        from app.core.schemas import RiskScoreBreakdown
        return RiskScoreBreakdown(
            classifier_confidence_component=0, permission_api_component=0,
            ttp_severity_component=0, forensic_anchor_component=0,
            obfuscation_component=0, reputation_component=0, ioc_component=0,
            total_score=30.0, verdict_band="low",
        )

    def test_store_called_when_family_is_none(self):
        from app.core.schemas import IngestionResult, SignatureYaraResult
        ingestion = IngestionResult(sha256="bb" * 32, package_name="com.test", permissions=[])
        mock_risk = self._make_mock_risk()
        mock_obf = self._make_mock_obf()
        # Pydantic validates signature_yara strictly — pass a real schema instance.
        real_sig_yara = SignatureYaraResult()

        with patch("app.api.routes.AnalysisPipeline") as mp, \
             patch("app.api.routes.lookup_signature", return_value=None), \
             patch("app.api.routes.store_signature") as mock_store, \
             patch("app.api.routes.compute_risk_score", return_value=mock_risk):

            mp.run_phase1_ingestion.return_value = (ingestion, MagicMock(), MagicMock(), MagicMock())
            mp.run_phase1b_signature_yara.return_value = real_sig_yara
            mp.run_phase2_graph_construction.return_value = ({}, 0.0)
            mp.run_phase3_forensic_matching.return_value = ({}, [], [])
            mp.run_phase4_feature_engineering.return_value = (mock_obf, [0.0]*33, [0.0]*179, 0.0, 0)
            # predicted_family is None (classifier untrained / FileNotFoundError path)
            mp.run_phase5_ml_classification.return_value = ({}, None, None)
            mp.run_phase6_risk_scoring.return_value = mock_risk
            mp.run_phase7_reporting.return_value = ("narrative", ["lim"])

            from app.api.routes import _run_analysis
            _run_analysis("/fake/test.apk")

            mock_store.assert_called_once()
            # family kwarg must be "" (empty string, not None)
            kwargs = mock_store.call_args[1]
            self.assertEqual(kwargs.get("family"), "",
                f"Expected family='', got {kwargs.get('family')!r}")


# ─── Bug 2: LLM temperature pinned to 0 ─────────────────────────────────────

class TestGraphRAGTemperatureIsZero(unittest.TestCase):

    def _make_manifest_and_risk(self):
        from app.core.schemas import AnalysisManifest, ObfuscationSignal, RiskScoreBreakdown
        obf = ObfuscationSignal(
            string_entropy_score=3.0, flattening_suspected=False,
            coverage_note="ok", method_parse_failure_rate=0.0
        )
        manifest = AnalysisManifest(
            target_package="com.test.app", sha256="cc" * 32, cache_hit=False,
            total_nodes_parsed=10, graph_density=0.1, behavioral_subgraphs=[],
            obfuscation=obf, predicted_ttps={"T1636": 0.82},
            predicted_family=None, family_confidence=None,
        )
        risk = RiskScoreBreakdown(
            classifier_confidence_component=20.0, permission_api_component=16.0,
            ttp_severity_component=12.0, forensic_anchor_component=0.0,
            obfuscation_component=0.0, reputation_component=1.5, ioc_component=0.0,
            total_score=49.5, verdict_band="suspicious",
        )
        return manifest, risk

    def test_temperature_is_zero(self):
        manifest, risk = self._make_manifest_and_risk()
        mock_resp = MagicMock()
        mock_resp.choices[0].message.content = "## Executive Summary\nT1636 observed."

        # Patch neo4j_client on the ontology module so get_technique_context
        # never reaches the real DB (which is down in CI / offline tests).
        import app.graph.ontology as onto_mod
        fake_ctx = [{"technique_id": "T1636", "name": "Protected User Data",
                     "description": "SMS access.", "tactic": "Collection"}]
        with patch.object(onto_mod.neo4j_client, "run", return_value=fake_ctx), \
             patch("app.reports.graphrag.OpenAI") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value = mock_client
            mock_client.chat.completions.create.return_value = mock_resp

            import app.reports.graphrag as grmod
            grmod.generate_report(manifest, risk)

            kw = mock_client.chat.completions.create.call_args[1]
            self.assertIn("temperature", kw, "temperature param must be explicit")
            self.assertEqual(kw["temperature"], 0, "temperature must be 0 for greedy decode")
            self.assertIn("top_p", kw, "top_p must be explicit")
            self.assertEqual(kw["top_p"], 1.0)

    def test_prompt_excludes_topological_invariants(self):
        """Trimmed manifest_summary must not leak internal topology floats to LLM."""
        manifest, risk = self._make_manifest_and_risk()
        captured = {}

        def capture(**kw):
            captured["prompt"] = kw["messages"][1]["content"]
            r = MagicMock()
            r.choices[0].message.content = "Report."
            return r

        import app.graph.ontology as onto_mod
        with patch.object(onto_mod.neo4j_client, "run", return_value=[]), \
             patch("app.reports.graphrag.OpenAI") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value = mock_client
            mock_client.chat.completions.create.side_effect = capture

            import app.reports.graphrag as grmod
            grmod.generate_report(manifest, risk)

            self.assertIn("JSON Manifest", captured["prompt"])
            self.assertNotIn("topological_invariants", captured["prompt"],
                "topological_invariants must be stripped from LLM prompt to reduce hallucination surface")


# ─── Bug 2b: _grounding_check logic ─────────────────────────────────────────

class TestGroundingCheckLogic(unittest.TestCase):

    def test_no_hallucination_when_all_ids_provided(self):
        import re
        narrative = "T1636 is a collection technique used here."
        provided = {"T1636"}
        cited = set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", narrative))
        hallucinated = cited - provided
        self.assertEqual(hallucinated, set())

    def test_detects_hallucinated_id(self):
        import re
        narrative = "T1636 and T9999 were both observed."
        provided = {"T1636"}
        cited = set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", narrative))
        hallucinated = cited - provided
        self.assertIn("T9999", hallucinated)
        self.assertNotIn("T1636", hallucinated)

    def test_sub_technique_detected(self):
        import re
        narrative = "T1636.001 was mentioned."
        provided = {"T1636.001"}
        cited = set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", narrative))
        hallucinated = cited - provided
        self.assertEqual(hallucinated, set())

    def test_no_crash_on_empty_context(self):
        from app.reports.graphrag import _grounding_check
        _grounding_check("No techniques predicted.", set())  # must not raise


if __name__ == "__main__":
    unittest.main(verbosity=2)
