"""
Suite-wide fixtures.

`settings.brand_live_lookup_enabled` defaults to True in production
(app/core/config.py) — unlike the VirusTotal/MalwareBazaar lookups in
app/analysis/signatures.py, it needs no API key, so it has no natural gate
keeping a test/CI run off the real network. Every other test file in this
suite assumes it never makes outbound HTTP calls; without this fixture, any
test that runs detect_impersonation() on a fixture APK not present in the
static brand table would attempt a real request to play.google.com.

Tests that specifically exercise the live path re-enable it and monkeypatch
app.analysis.brand_lookup's HTTP seam (see tests/test_brand_lookup.py and
the live-lookup cases in tests/test_impersonation.py).

The history fixture exists for the same class of reason: the analysis endpoints
record every completed analysis to an on-disk log, so any test that posts to
/analyze writes into the operator's real Analysis History. Running the suite
should never leave rows like "com.test" in a panel someone is about to demo.
"""
import pytest

from app.core.config import settings


@pytest.fixture(autouse=True)
def _brand_live_lookup_disabled_by_default(monkeypatch):
    monkeypatch.setattr(settings, "brand_live_lookup_enabled", False)


@pytest.fixture(autouse=True)
def _history_log_redirected_to_tmp(monkeypatch, tmp_path):
    """Point the on-disk history log at a per-test temp file.

    Autouse and suite-wide deliberately. The write happens deep inside the
    request path — record_analysis is called by /analyze, /analyze/start and the
    unparseable fallback — so any test exercising an endpoint hits it, including
    tests that have nothing to do with history and would never think to patch it.
    Opting in per-test would mean remembering to, and the failure mode is silent
    pollution of a real user-facing file rather than a red test.
    """
    from app.core import history as history_module
    monkeypatch.setattr(
        history_module, "_HISTORY_PATH", tmp_path / "analysis_history.json"
    )
