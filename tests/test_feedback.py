"""
Tests for the analyst-feedback loop: app/graph/cache.py's record_feedback
and POST /analyses/{sha256}/feedback (app/api/routes.py). This is the first
half of an active-learning loop (see scripts/export_feedback_for_training.py
for the second half) — recording a correction, not retraining anything.

Fully offline — Neo4j is mocked/patched; no live services, no network.
"""
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi.testclient import TestClient

from app.api import routes as routes_module
from app.graph import cache as cache_module
from app.main import app


class TestRecordFeedback(unittest.TestCase):
    """app/graph/cache.py's record_feedback — the storage layer, Neo4j mocked."""

    def setUp(self):
        cache_module._MEMORY_CACHE.clear()

    def tearDown(self):
        cache_module._MEMORY_CACHE.clear()

    def test_writes_to_neo4j_and_returns_true_when_sample_exists(self):
        with patch.object(
            cache_module.neo4j_client, "run", return_value=[{"sha256": "aa" * 32}]
        ) as mock_run:
            found = cache_module.record_feedback("aa" * 32, verdict="false_positive", note="clean app")
        self.assertTrue(found)
        _, kwargs = mock_run.call_args
        self.assertEqual(kwargs["sha256"], "aa" * 32)
        self.assertEqual(kwargs["verdict"], "false_positive")
        self.assertEqual(kwargs["note"], "clean app")

    def test_returns_false_when_no_sample_node_exists_and_not_in_memory(self):
        with patch.object(cache_module.neo4j_client, "run", return_value=[]):
            found = cache_module.record_feedback("bb" * 32, verdict="confirmed")
        self.assertFalse(found)

    def test_neo4j_unreachable_still_returns_true_when_present_in_memory_cache(self):
        """A sample analysed this process lifetime is in _MEMORY_CACHE even if
        Neo4j is down for this call — feedback should still be recorded there,
        not lost just because the durable store is briefly unreachable."""
        cache_module._MEMORY_CACHE["cc" * 32] = {"sha256": "cc" * 32}
        with patch.object(cache_module.neo4j_client, "run", side_effect=Exception("neo4j down")):
            found = cache_module.record_feedback("cc" * 32, verdict="confirmed")
        self.assertTrue(found)
        self.assertEqual(cache_module._MEMORY_CACHE["cc" * 32]["analyst_verdict"], "confirmed")

    def test_neo4j_unreachable_and_unknown_to_memory_cache_returns_false(self):
        with patch.object(cache_module.neo4j_client, "run", side_effect=Exception("neo4j down")):
            found = cache_module.record_feedback("dd" * 32, verdict="confirmed")
        self.assertFalse(found)


class TestFeedbackEndpoint(unittest.TestCase):
    """POST /analyses/{sha256}/feedback."""

    def setUp(self):
        self.client = TestClient(app)
        self.sha = "ee" * 32

    def test_unknown_sha_returns_404(self):
        with patch.object(routes_module, "record_feedback", return_value=False):
            resp = self.client.post(f"/analyses/{self.sha}/feedback", json={"verdict": "false_positive"})
        self.assertEqual(resp.status_code, 404)

    def test_known_sha_records_and_returns_confirmation(self):
        with patch.object(routes_module, "record_feedback", return_value=True) as mock_record:
            resp = self.client.post(
                f"/analyses/{self.sha}/feedback",
                json={"verdict": "false_positive", "note": "this is a clean utility app"},
            )
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["sha256"], self.sha)
        self.assertEqual(body["verdict"], "false_positive")
        self.assertTrue(body["recorded"])
        mock_record.assert_called_once_with(
            self.sha, verdict="false_positive", note="this is a clean utility app"
        )

    def test_note_is_optional(self):
        with patch.object(routes_module, "record_feedback", return_value=True) as mock_record:
            resp = self.client.post(f"/analyses/{self.sha}/feedback", json={"verdict": "confirmed"})
        self.assertEqual(resp.status_code, 200)
        mock_record.assert_called_once_with(self.sha, verdict="confirmed", note=None)

    def test_missing_verdict_is_a_422_not_a_500(self):
        resp = self.client.post(f"/analyses/{self.sha}/feedback", json={})
        self.assertEqual(resp.status_code, 422)


if __name__ == "__main__":
    unittest.main()
