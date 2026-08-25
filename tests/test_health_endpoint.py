"""
Tests for the dependency health reporting behind GET /health and the two header
status pills.

What is being defended here is not "the endpoint returns 200" — it is the exact
failure that motivated the change. Every Neo4j caller in the app degrades
silently on purpose: lookup_signature falls back to a process-local dict,
find_related_samples and get_threat_landscape return empty, get_technique_context
falls through to the local JSON ontology. Each is individually correct, and
together they make a dead database indistinguishable from a clean sample with no
correlations. The pills were hardcoded green through a 43-minute outage.

So the cases that matter are the unhappy ones: unreachable must not read as
healthy, reachable-but-unloaded must be distinguishable from both, and neither
health probe may raise — a diagnostic that throws when its subject is broken is
worse than none, because it takes the page down with it.

Fully offline: Neo4j and Ollama are patched out; no live services, no network.
"""
import os
import sys
import unittest
import urllib.error
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi.testclient import TestClient

from app.graph import ontology as ontology_module
from app.reports import graphrag as graphrag_module
from app.main import app


class TestGraphHealth(unittest.TestCase):
    """app/graph/ontology.py :: graph_health()"""

    def test_unreachable_neo4j_reports_unreachable_and_does_not_raise(self):
        with patch.object(
            ontology_module.neo4j_client, "run",
            side_effect=RuntimeError("Neo4j connection failed (bolt://localhost:7687)"),
        ):
            h = ontology_module.graph_health()
        self.assertFalse(h["reachable"])
        self.assertEqual(h["grounded_techniques"], 0)
        self.assertEqual(h["cached_samples"], 0)
        # The detail is the operator's next action, not a stack trace.
        self.assertIn("docker compose up -d", h["detail"])

    def test_reachable_but_empty_is_reported_as_reachable_with_no_grounding(self):
        """
        The state after `docker compose up` without load_ontology.py. It is NOT a
        connection failure, and calling it one would send someone to restart a
        container that is already fine.
        """
        with patch.object(ontology_module.neo4j_client, "run",
                          return_value=[{"grounded": 0, "samples": 0}]):
            h = ontology_module.graph_health()
        self.assertTrue(h["reachable"])
        self.assertEqual(h["grounded_techniques"], 0)
        self.assertIn("load_ontology.py", h["detail"])

    def test_loaded_graph_reports_both_counts(self):
        with patch.object(ontology_module.neo4j_client, "run",
                          return_value=[{"grounded": 124, "samples": 306}]):
            h = ontology_module.graph_health()
        self.assertTrue(h["reachable"])
        self.assertEqual(h["grounded_techniques"], 124)
        self.assertEqual(h["cached_samples"], 306)


class TestOllamaHealth(unittest.TestCase):
    """app/reports/graphrag.py :: ollama_health()"""

    def test_unreachable_ollama_does_not_raise(self):
        with patch.object(graphrag_module.urllib.request, "urlopen",
                          side_effect=urllib.error.URLError("connection refused")):
            h = graphrag_module.ollama_health()
        self.assertFalse(h["reachable"])
        self.assertFalse(h["model_resident"])
        self.assertIn("ollama serve", h["detail"])

    def test_reachable_with_a_cold_model_is_not_a_failure(self):
        """
        Residency is a latency fact, not an availability one — a reachable Ollama
        with an unloaded model still produces reports. Reporting it as down would
        make the pill red for a system that works.
        """
        with patch.object(graphrag_module, "_native_base_url", return_value="http://x"), \
             patch.object(graphrag_module.urllib.request, "urlopen") as mock_open:
            mock_open.return_value.__enter__.return_value.read.return_value = b'{"models": []}'
            h = graphrag_module.ollama_health()
        self.assertTrue(h["reachable"])
        self.assertFalse(h["model_resident"])

    def test_the_configured_model_must_be_the_one_found_resident(self):
        """A different model being loaded is not this model being loaded."""
        other = b'{"models": [{"name": "llama3:8b"}]}'
        with patch.object(graphrag_module, "_native_base_url", return_value="http://x"), \
             patch.object(graphrag_module.urllib.request, "urlopen") as mock_open:
            mock_open.return_value.__enter__.return_value.read.return_value = other
            h = graphrag_module.ollama_health()
        self.assertTrue(h["reachable"])
        self.assertFalse(h["model_resident"])

        loaded = ('{"models": [{"name": "%s"}]}' % graphrag_module.settings.ollama_model).encode()
        with patch.object(graphrag_module, "_native_base_url", return_value="http://x"), \
             patch.object(graphrag_module.urllib.request, "urlopen") as mock_open:
            mock_open.return_value.__enter__.return_value.read.return_value = loaded
            h = graphrag_module.ollama_health()
        self.assertTrue(h["model_resident"])


class TestHealthEndpoint(unittest.TestCase):
    """GET /health — what the status pills read."""

    UP_GRAPH = {"reachable": True, "grounded_techniques": 124, "cached_samples": 306, "detail": "ok"}
    DOWN_GRAPH = {"reachable": False, "grounded_techniques": 0, "cached_samples": 0, "detail": "down"}
    UP_LLM = {"reachable": True, "model_resident": True, "model": "m", "detail": "ok"}
    DOWN_LLM = {"reachable": False, "model_resident": False, "model": "m", "detail": "down"}

    def _get(self, graph, llm):
        with patch("app.graph.ontology.graph_health", return_value=graph), \
             patch("app.reports.graphrag.ollama_health", return_value=llm):
            return TestClient(app).get("/health").json()

    def test_both_up_is_ok(self):
        body = self._get(self.UP_GRAPH, self.UP_LLM)
        self.assertEqual(body["status"], "ok")
        self.assertEqual(body["neo4j"]["cached_samples"], 306)

    def test_neo4j_down_is_degraded_not_ok(self):
        """
        The regression under test. Analysis genuinely still works without Neo4j,
        so this is not "down" — but it must never come back "ok", because "ok"
        is what painted the pill green while the database was gone.
        """
        body = self._get(self.DOWN_GRAPH, self.UP_LLM)
        self.assertEqual(body["status"], "degraded")
        self.assertFalse(body["neo4j"]["reachable"])

    def test_ollama_down_is_down(self):
        body = self._get(self.UP_GRAPH, self.DOWN_LLM)
        self.assertEqual(body["status"], "down")

    def test_the_probe_survives_a_dependency_that_raises(self):
        """
        /health is read on a 30s poll by every open page. If a probe could throw,
        the endpoint would 500 exactly when it is most needed and the pills would
        go blank instead of red.
        """
        with patch.object(ontology_module.neo4j_client, "run", side_effect=RuntimeError("boom")), \
             patch.object(graphrag_module.urllib.request, "urlopen", side_effect=OSError("boom")):
            resp = TestClient(app).get("/health")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["status"], "down")
        self.assertFalse(body["neo4j"]["reachable"])
        self.assertFalse(body["ollama"]["reachable"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
