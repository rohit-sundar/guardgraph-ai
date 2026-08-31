"""
What the Analysis History "Clear" button is allowed to delete.

Two requirements pull against each other and both are real:

  1. Clearing must drop the Neo4j cache for every sample in the history, or the
     next upload answers from cache and the operator never gets the cold path
     they cleared in order to get.
  2. Clearing must not destroy the corpus knowledge base.

It once failed (2) badly: the population scripts drive every corpus APK through
POST /analyze, which recorded history like any operator upload, so 493 of 500
history rows were corpus samples and "Clear" deleted all of them from the graph.

The fix is upstream — population now passes `record_history=false`, so those rows
never appear. Requirement (1) is therefore honoured literally: every sha in the
history is dropped, corpus-provenance or not, because an operator who analysed a
corpus sample by hand is entitled to re-run it cold. What remains here is a
tripwire on *scale*, which catches the pollution bug returning without ever
standing between the operator and their own work.
"""
import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from fastapi.testclient import TestClient

import app.api.routes as routes
import app.graph.cache as cache_module
from app.graph.cache import (
    SAMPLE_SOURCE_CORPUS,
    SAMPLE_SOURCE_OPERATOR,
    delete_sample,
)
from app.main import app

SHA = "cc" * 32


class TestDeleteSampleIsUnconditional:
    """
    The per-sample delete has no provenance opinion, deliberately. A guard here
    would silently refuse the cold path an operator explicitly asked for, and it
    cannot see the only thing that distinguishes an accident from intent: how
    many samples are going at once.
    """

    def test_deletes_regardless_of_provenance(self):
        for source in (SAMPLE_SOURCE_OPERATOR, SAMPLE_SOURCE_CORPUS, None):
            calls = []

            def fake_run(query, **params):
                calls.append(query)
                return [{"sha256": SHA}] if "RETURN s.sha256" in query else []

            with patch.object(cache_module.neo4j_client, "run", side_effect=fake_run):
                assert delete_sample(SHA) is True
            assert any("DETACH DELETE" in q for q in calls), source

    def test_absent_sample_reports_false(self):
        with patch.object(cache_module.neo4j_client, "run", return_value=[]):
            assert delete_sample(SHA) is False

    def test_the_in_process_cache_is_evicted_too(self):
        """A cached copy left behind would keep answering for a sample the graph
        no longer has, which is the cold path failing to happen by another route."""
        cache_module._MEMORY_CACHE[SHA] = {"sha256": SHA}
        try:
            with patch.object(cache_module.neo4j_client, "run",
                              return_value=[{"sha256": SHA}]):
                delete_sample(SHA)
            assert SHA not in cache_module._MEMORY_CACHE
        finally:
            cache_module._MEMORY_CACHE.pop(SHA, None)


def _client():
    return TestClient(app)


class TestClearEndpointScope:

    def test_every_history_row_is_dropped_from_the_graph(self):
        """Requirement (1): clear means cold path next time, for all of them."""
        shas = ["aa" * 32, "bb" * 32, "dd" * 32]
        dropped = []
        with patch.object(routes, "peek_history_shas", return_value=shas), \
             patch.object(routes, "clear_history", return_value=shas), \
             patch.object(routes, "_corpus_provenance_count", return_value=0), \
             patch.object(routes, "delete_sample",
                          side_effect=lambda s: dropped.append(s) or True):
            resp = _client().delete("/analyses")
        assert resp.status_code == 200
        assert resp.json()["cleared"] == 3
        assert resp.json()["cached_verdicts_dropped"] == 3
        assert dropped == shas

    def test_a_corpus_sample_the_operator_analysed_is_still_dropped(self):
        """
        The case the first version of this fix got wrong. Re-analysing a corpus
        sample by hand puts it in the history; clearing must then give a cold
        path on it, even though the graph records it as corpus-loaded.
        """
        shas = ["aa" * 32]
        dropped = []
        with patch.object(routes, "peek_history_shas", return_value=shas), \
             patch.object(routes, "clear_history", return_value=shas), \
             patch.object(routes, "_corpus_provenance_count", return_value=1), \
             patch.object(routes, "delete_sample",
                          side_effect=lambda s: dropped.append(s) or True):
            resp = _client().delete("/analyses")
        assert resp.status_code == 200
        assert dropped == shas
        assert resp.json()["corpus_samples_dropped"] == 1

    def test_one_failed_delete_does_not_abort_the_rest(self):
        shas = ["aa" * 32, "bb" * 32, "dd" * 32]
        seen = []

        def flaky(sha):
            seen.append(sha)
            if sha.startswith("bb"):
                raise RuntimeError("neo4j blip")
            return True

        with patch.object(routes, "peek_history_shas", return_value=shas), \
             patch.object(routes, "clear_history", return_value=shas), \
             patch.object(routes, "_corpus_provenance_count", return_value=0), \
             patch.object(routes, "delete_sample", side_effect=flaky):
            resp = _client().delete("/analyses")
        assert resp.status_code == 200
        assert seen == shas
        assert resp.json()["cached_verdicts_dropped"] == 2


class TestPollutionTripwire:

    def test_a_polluted_history_is_refused(self):
        """The 493-row catastrophe, caught before anything is deleted."""
        shas = ["%064x" % i for i in range(500)]
        dropped = []
        with patch.object(routes, "peek_history_shas", return_value=shas), \
             patch.object(routes, "_corpus_provenance_count", return_value=493), \
             patch.object(routes, "clear_history") as cleared, \
             patch.object(routes, "delete_sample",
                          side_effect=lambda s: dropped.append(s) or True):
            resp = _client().delete("/analyses")
        assert resp.status_code == 409
        assert dropped == []
        # The list must survive the refusal — it is the evidence the operator
        # needs, and emptying it would leave them with neither.
        cleared.assert_not_called()
        assert "record_history=false" in resp.json()["detail"]

    def test_force_overrides_the_tripwire(self):
        shas = ["%064x" % i for i in range(500)]
        dropped = []
        with patch.object(routes, "peek_history_shas", return_value=shas), \
             patch.object(routes, "_corpus_provenance_count", return_value=493), \
             patch.object(routes, "clear_history", return_value=shas), \
             patch.object(routes, "delete_sample",
                          side_effect=lambda s: dropped.append(s) or True):
            resp = _client().delete("/analyses?force=true")
        assert resp.status_code == 200
        assert len(dropped) == 500

    def test_an_ordinary_session_never_trips_it(self):
        """The gap between a normal clear and the bug is wide; stay well inside it."""
        assert routes.HISTORY_CLEAR_CORPUS_ALARM >= 25
        shas = ["%064x" % i for i in range(40)]
        with patch.object(routes, "peek_history_shas", return_value=shas), \
             patch.object(routes, "clear_history", return_value=shas), \
             patch.object(routes, "_corpus_provenance_count",
                          return_value=routes.HISTORY_CLEAR_CORPUS_ALARM), \
             patch.object(routes, "delete_sample", return_value=True):
            resp = _client().delete("/analyses")
        assert resp.status_code == 200

    def test_an_unreachable_graph_does_not_block_the_clear(self):
        """A local file must stay clearable when Neo4j is down."""
        with patch.object(routes.neo4j_client, "run",
                          side_effect=Exception("neo4j down")):
            assert routes._corpus_provenance_count(["aa" * 32]) == 0

    def test_empty_history_needs_no_query(self):
        assert routes._corpus_provenance_count([]) == 0


class TestProvenanceIsWrittenOnce:

    def test_store_signature_defaults_to_operator(self):
        import inspect
        sig = inspect.signature(cache_module.store_signature)
        assert sig.parameters["source"].default == SAMPLE_SOURCE_OPERATOR

    def test_provenance_is_coalesced_not_overwritten(self):
        """
        A corpus sample an operator re-analyses stays flagged corpus. It is still
        deleted by a clear — provenance is a tripwire input, not a veto — but the
        graph must keep recording where the sample originally came from, or the
        tripwire loses the signal it counts.
        """
        captured = {}

        def fake_run(query, **params):
            if "MERGE (s:Sample" in query:
                captured["query"] = query
                captured["source"] = params.get("source")
            return []

        with patch.object(cache_module.neo4j_client, "run", side_effect=fake_run):
            cache_module.store_signature(
                SHA, "", 10.0, {}, source=SAMPLE_SOURCE_OPERATOR
            )
        assert "coalesce(s.source, $source)" in captured["query"]
        assert captured["source"] == SAMPLE_SOURCE_OPERATOR
