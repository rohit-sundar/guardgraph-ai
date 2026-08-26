"""
Tests for populate_corpus.persisted — the check that stops a bulk population
run from recording a sample as done when nothing actually reached the graph.

/analyze answers HTTP 200 even when static analysis aborts (it returns the
mid-band unparseable verdict and deliberately does not cache it), so the status
code alone is not evidence of persistence. Trusting it cost 3 of 30 samples on
a live run: they went into the progress file, and a later --resume skipped them
forever while the run reported failed=0.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scripts import populate_corpus


class _FakeClient:
    def __init__(self, result):
        self._result = result
        self.calls = []

    def run(self, query, **params):
        self.calls.append((query, params))
        if isinstance(self._result, Exception):
            raise self._result
        return self._result


def test_present_sample_counts_as_persisted(monkeypatch):
    monkeypatch.setattr(populate_corpus, "neo4j_client", _FakeClient([{"c": 1}]))
    assert populate_corpus.persisted("a" * 64) is True


def test_absent_sample_is_not_persisted(monkeypatch):
    """The unparseable-verdict case: 200 came back, no node was written."""
    monkeypatch.setattr(populate_corpus, "neo4j_client", _FakeClient([{"c": 0}]))
    assert populate_corpus.persisted("b" * 64) is False


def test_unreachable_neo4j_is_not_persisted(monkeypatch):
    """
    Fail closed. If the graph cannot be queried it certainly cannot have been
    written, and recording progress on a guess is how samples go missing.
    """
    monkeypatch.setattr(
        populate_corpus, "neo4j_client", _FakeClient(RuntimeError("connection refused"))
    )
    assert populate_corpus.persisted("c" * 64) is False


def test_empty_result_set_is_not_persisted(monkeypatch):
    monkeypatch.setattr(populate_corpus, "neo4j_client", _FakeClient([]))
    assert populate_corpus.persisted("d" * 64) is False


def test_lookup_is_keyed_on_the_sha_parameter(monkeypatch):
    """Parameterised, not string-formatted, so a sha can never alter the query."""
    fake = _FakeClient([{"c": 1}])
    monkeypatch.setattr(populate_corpus, "neo4j_client", fake)
    populate_corpus.persisted("e" * 64)
    query, params = fake.calls[0]
    assert params == {"sha": "e" * 64}
    assert "e" * 64 not in query


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
