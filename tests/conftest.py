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
"""
import pytest

from app.core.config import settings


@pytest.fixture(autouse=True)
def _brand_live_lookup_disabled_by_default(monkeypatch):
    monkeypatch.setattr(settings, "brand_live_lookup_enabled", False)
