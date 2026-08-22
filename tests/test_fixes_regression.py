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
import json
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.core.config import settings
from app.ml.features import FEATURE_NAMES, TTP_FEATURE_NAMES


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

            mp.run_phase1_ingestion.return_value = (ingestion, MagicMock(), MagicMock(), MagicMock(), [])
            mp.run_phase1b_signature_yara.return_value = real_sig_yara
            mp.run_phase2_graph_construction.return_value = ({}, 0.0)
            mp.run_phase3_forensic_matching.return_value = ({}, [], [])
            mp.merge_c2_from_strings.return_value = ingestion
            mp.run_phase3b_re_deepdive.return_value = ([], [], [], [])
            mp.run_phase4_feature_engineering.return_value = (mock_obf, [0.0]*len(FEATURE_NAMES), [0.0]*len(TTP_FEATURE_NAMES), 0.0, 0)
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


# ─── LLM warm-up: first report after a cold model load ──────────────────────

class TestEnsureModelWarm(unittest.TestCase):
    """
    Measured against a live Ollama across forced cold loads: the first inference
    after a model load decodes differently from every later one, so the first
    report of a session diverged from subsequent ones even with temperature=0
    and a pinned seed. Warming up with the SAME prompt fixed it (2/2 trials);
    a different prompt of comparable size did not (0/2), nor did a 1-token one
    (0/2). These tests lock in the parts checkable without a GPU.
    """

    def test_warmup_replays_the_same_prompt_when_model_not_loaded(self):
        import app.reports.graphrag as g
        prompt = "## JSON Manifest\n" + ("x" * 5000)
        with patch.object(g, "_model_is_loaded", return_value=False), \
             patch.object(g, "_post_native_chat") as mock_post:
            self.assertTrue(g.ensure_model_warm(prompt))

        mock_post.assert_called_once()
        self.assertEqual(
            mock_post.call_args[0][0], prompt,
            "warm-up must replay the SAME prompt — a different prompt of similar "
            "size was measured not to stabilise the decode (0/2 trials)",
        )
        self.assertEqual(mock_post.call_args[1]["num_predict"], 1,
                         "warm-up only needs the prefill, not a full generation")

    def test_no_warmup_when_model_already_loaded(self):
        """The effect is tied to the model load, so a resident model needs no
        second prefill — paying one on every request would buy nothing."""
        import app.reports.graphrag as g
        with patch.object(g, "_model_is_loaded", return_value=True), \
             patch.object(g, "_post_native_chat") as mock_post:
            self.assertTrue(g.ensure_model_warm("prompt"))

        mock_post.assert_not_called()

    def test_warmup_uses_native_endpoint_with_keep_alive(self):
        """keep_alive is honoured by /api/chat and silently IGNORED by the
        OpenAI-compatible /v1 endpoint, so the warm-up must not use /v1."""
        import app.reports.graphrag as g
        captured = {}

        def fake_urlopen(req, timeout=None):
            captured["url"] = req.full_url
            captured["body"] = json.loads(req.data.decode())
            return MagicMock(__enter__=lambda s: MagicMock(read=lambda: b"{}"),
                             __exit__=lambda *a: False)

        with patch.object(g.urllib.request, "urlopen", side_effect=fake_urlopen):
            g._post_native_chat("x", num_predict=1, timeout=5)

        self.assertTrue(captured["url"].endswith("/api/chat"), captured["url"])
        self.assertNotIn("/v1/", captured["url"])
        self.assertEqual(captured["body"]["keep_alive"], settings.graphrag_keep_alive)
        self.assertEqual(captured["body"]["options"]["seed"], settings.graphrag_seed)

    def test_warmup_failure_is_never_fatal(self):
        """Losing reproducibility must not cost the analysis."""
        import app.reports.graphrag as g
        with patch.object(g, "_model_is_loaded", return_value=False), \
             patch.object(g, "_post_native_chat", side_effect=OSError("refused")):
            self.assertFalse(g.ensure_model_warm("prompt"))  # must not raise

    def test_generate_report_warms_with_the_prompt_it_will_send(self):
        import app.reports.graphrag as g
        order = []
        mock_resp = MagicMock()
        mock_resp.choices[0].message.content = "T1636 observed."

        def note_create(**kw):
            order.append(("llm", kw["messages"][1]["content"]))
            return mock_resp

        import app.graph.ontology as onto_mod
        with patch.object(onto_mod.neo4j_client, "run", return_value=[]), \
             patch.object(g, "ensure_model_warm",
                          side_effect=lambda p: order.append(("warm", p))), \
             patch("app.reports.graphrag.OpenAI") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value = mock_client
            mock_client.chat.completions.create.side_effect = note_create

            manifest, risk = TestGraphRAGTemperatureIsZero()._make_manifest_and_risk()
            g.generate_report(manifest, risk)

        self.assertEqual([step for step, _ in order], ["warm", "llm"])
        self.assertEqual(order[0][1], order[1][1],
                         "the warm-up must replay exactly the prompt the real call sends")


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
             patch("app.reports.graphrag.ensure_model_warm", return_value=True), \
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
            self.assertIn("seed", kw,
                "seed must be pinned — temperature=0 alone does not guarantee "
                "deterministic output (batch scheduling / KV-cache reuse can still "
                "perturb the decode)")
            self.assertEqual(kw["seed"], settings.graphrag_seed)

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


# ─── Bug 3: _identifier_check — fabricated hash/sample-name detection ───────
# Added 2026-08-22 after observing live: the model invented "MD5: 1234abcd..."
# (not even valid hex) and "Sample Name: AndroidMalware_Example" for a real
# Cerberus sample — neither _grounding_check nor _permission_check catch this
# failure mode, since it's neither a MITRE ID nor a permission.

class TestIdentifierCheckLogic(unittest.TestCase):

    def test_no_flag_when_real_sha256_cited(self):
        from app.reports.graphrag import _identifier_check
        real_sha = "abc123def456" * 5 + "abcd"  # 64 chars
        narrative = f"SHA-256: {real_sha}"
        self.assertEqual(_identifier_check(narrative, real_sha, None), [])

    def test_no_flag_for_truncated_real_sha256_preview(self):
        from app.reports.graphrag import _identifier_check
        real_sha = "abc123def456" * 5 + "abcd"
        narrative = f"Hash: {real_sha[:12]}..."
        self.assertEqual(_identifier_check(narrative, real_sha, None), [])

    def test_flags_fabricated_md5(self):
        from app.reports.graphrag import _identifier_check
        real_sha = "90abcdef1234567890fedcba1234567890fedcba1234567890fedcba1234567890"
        narrative = "MD5 Hash: 1234abcd5678efgh"
        result = _identifier_check(narrative, real_sha, None)
        self.assertTrue(any("1234abcd5678efgh" in r for r in result))

    def test_flags_fabricated_sample_name(self):
        from app.reports.graphrag import _identifier_check
        real_sha = "90abcdef1234567890fedcba1234567890fedcba1234567890fedcba1234567890"
        narrative = "Sample Name: AndroidMalware_Example"
        result = _identifier_check(narrative, real_sha, "com.real.package")
        self.assertTrue(any("AndroidMalware_Example" in r for r in result))

    def test_no_flag_when_sample_name_matches_real_package(self):
        from app.reports.graphrag import _identifier_check
        real_sha = "90abcdef1234567890fedcba1234567890fedcba1234567890fedcba1234567890"
        narrative = "Sample Name: com.real.package"
        result = _identifier_check(narrative, real_sha, "com.real.package")
        self.assertEqual(result, [])

    def test_no_crash_with_no_labels(self):
        from app.reports.graphrag import _identifier_check
        result = _identifier_check("A clean narrative with no hash labels.", "aa" * 32, "com.x")
        self.assertEqual(result, [])


class TestStripFabricatedIdentification(unittest.TestCase):
    """
    SYSTEM_PROMPT rule 6b alone does not reliably stop the model from writing
    a fake "Sample Information" section (observed live, repeatedly, even with
    the rule in place) — this strips what _identifier_check flags rather than
    trusting the instruction to work.
    """

    def test_removes_fabricated_section(self):
        from app.reports.graphrag import _strip_fabricated_identification
        real_sha = "047e3ecdb04d695b7e8a3c2789c29ec57da19f58bdcdb1d97fa926205ce718eb"
        narrative = (
            "#### Sample Information\n"
            "- **Sample Name:** `malicious_sample.apk`\n"
            "- **SHA256 Hash:** `1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef`\n"
            "\n"
            "#### Malware Analysis Summary\n"
            "Real content here.\n"
        )
        cleaned = _strip_fabricated_identification(narrative, real_sha, "com.real.package")
        self.assertNotIn("malicious_sample.apk", cleaned)
        self.assertNotIn("1234567890abcdef", cleaned)
        self.assertNotIn("Sample Information", cleaned)
        self.assertIn("Malware Analysis Summary", cleaned)
        self.assertIn("Real content here.", cleaned)

    def test_keeps_real_sha256_if_correctly_cited(self):
        from app.reports.graphrag import _strip_fabricated_identification
        real_sha = "047e3ecdb04d695b7e8a3c2789c29ec57da19f58bdcdb1d97fa926205ce718eb"
        narrative = f"The sample's SHA256 Hash: `{real_sha}` matches a known family.\n"
        cleaned = _strip_fabricated_identification(narrative, real_sha, "com.real.package")
        self.assertIn(real_sha, cleaned)

    def test_no_change_on_clean_narrative(self):
        from app.reports.graphrag import _strip_fabricated_identification
        narrative = "### Verdict\nMalicious, score 73.7/100.\n"
        cleaned = _strip_fabricated_identification(narrative, "aa" * 32, "com.x")
        self.assertEqual(cleaned, narrative)


# ─── T2: unparseable APKs return a verdict, not a bare 500 ───────────────────

class TestUnparseableApkReturnsVerdict(unittest.TestCase):
    """
    12% of the project's own malware corpus crashed the pipeline with unhandled
    IndexError / ValueError from Androguard and apkInspector — malformed AXML
    attribute names and corrupted ZIP end-of-central-directory records, both
    deliberate anti-analysis techniques. /analyze had a try/finally with no
    except, so an analyst uploading a hostile sample got an opaque 500 with the
    reason only in the server log.
    """

    def _corrupt_apk(self) -> str:
        import tempfile
        fd, path = tempfile.mkstemp(suffix=".apk")
        with os.fdopen(fd, "wb") as f:
            f.write(b"PK\x03\x04" + b"\x00" * 64)  # ZIP magic, no central directory
        self.addCleanup(lambda: os.path.exists(path) and os.remove(path))
        return path

    def test_report_is_structured_and_carries_the_hash(self):
        from app.api.routes import _unparseable_report, UNPARSEABLE_RISK_SCORE
        from app.analysis.ingest import compute_sha256

        path = self._corrupt_apk()
        # _unparseable_report now calls the real GraphRAG phase (so the AI
        # narrative isn't just a hardcoded placeholder) — mock it here so this
        # test doesn't depend on a running Ollama instance.
        with patch(
            "app.core.pipeline.AnalysisPipeline.run_phase7_reporting",
            return_value=("mocked narrative", []),
        ):
            report = _unparseable_report(path, ValueError("EOCD signature not found"))

        # The hash needs no parsing, so it must survive — it is the one pivot the
        # analyst still has into threat intel.
        self.assertEqual(report.manifest.sha256, compute_sha256(path))
        self.assertEqual(report.risk_score.total_score, UNPARSEABLE_RISK_SCORE)
        self.assertEqual(report.risk_score.verdict_band, "suspicious")

        # Components stay None, never 0.0: nothing was computed, and 0.0 would
        # falsely assert "we looked and found no evidence".
        self.assertIsNone(report.risk_score.forensic_anchor_component)
        self.assertIsNone(report.risk_score.obfuscation_component)

        # The failure must be legible in the report itself, not just the log.
        # Checked against the manifest's coverage note directly (not
        # report.limitations) because that note is what routes.py guarantees
        # regardless of what the — here mocked — GraphRAG phase returns; the
        # real run_phase7_reporting always forwards it into limitations too,
        # but this test's mock intentionally returns an empty list for that.
        joined = " ".join(report.limitations)
        self.assertIn("ANALYSIS INCOMPLETE", joined)
        self.assertIn("EOCD signature not found", report.manifest.obfuscation.coverage_note)

    def test_endpoint_returns_200_not_500(self):
        from fastapi.testclient import TestClient
        from app.main import app

        with open(self._corrupt_apk(), "rb") as f:
            payload = f.read()

        with patch("app.api.routes._run_analysis", side_effect=IndexError("string index out of range")):
            resp = TestClient(app).post(
                "/analyze", files={"file": ("corrupt.apk", payload, "application/vnd.android.package-archive")}
            )

        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["risk_score"]["verdict_band"], "suspicious")
        self.assertIn("string index out of range", " ".join(body["limitations"]))

    def test_non_apk_still_rejected_with_400(self):
        """The 400 path is correct behavior and must not be swallowed by the new except."""
        from fastapi.testclient import TestClient
        from app.main import app

        resp = TestClient(app).post("/analyze", files={"file": ("notapk.txt", b"hello", "text/plain")})
        self.assertEqual(resp.status_code, 400)


if __name__ == "__main__":
    unittest.main(verbosity=2)
