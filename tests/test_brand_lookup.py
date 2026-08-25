"""
Tests for app/analysis/brand_lookup.py — live Google Play identity checks.

Fully offline: the one seam that would touch the real network, `_http_get`,
is monkeypatched in every test here. None of these tests make a real HTTP
request — the live pipeline was verified separately against the real Play
Store (see the shape of the responses asserted below, which mirror real
HTML captured 2026-08-25 from play.google.com).
"""
import time

import pytest

from app.analysis import brand_lookup
from app.core.config import settings


@pytest.fixture(autouse=True)
def _isolated_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(brand_lookup, "CACHE_PATH", str(tmp_path / "play_lookup_cache.json"))
    brand_lookup.reset_cache()
    monkeypatch.setattr(settings, "brand_live_lookup_enabled", True)
    yield
    brand_lookup.reset_cache()


def _details_html(title, image=None):
    image_tag = f'<meta property="og:image" content="{image}">' if image else ""
    return (
        f'<html><head><meta property="og:title" content="{title}">{image_tag}'
        f"</head></html>"
    ).encode()


def _search_html(results):
    tiles = "".join(
        f'<a href="/store/apps/details?id={pkg}" aria-label="{title}">x</a>'
        for pkg, title in results
    )
    return f"<html><body>{tiles}</body></html>".encode()


def _search_html_no_aria_label(results):
    """
    The second real Play layout, confirmed live 2026-08-25 (querying "Customer
    Support" hit this shape): no aria-label on the anchor at all, title text
    sits in a <span> a few tags later, separated only by image elements.
    """
    tiles = "".join(
        f'<a href="/store/apps/details?id={pkg}">'
        f'<img src="https://icon" alt="Icon" />'
        f'<div><span class="SomeMinifiedClass">{title}</span></div>'
        f"</a>"
        for pkg, title in results
    )
    return f"<html><body>{tiles}</body></html>".encode()


# ── fetch_play_listing ──────────────────────────────────────────────────

def test_fetch_play_listing_parses_title_and_icon(monkeypatch):
    calls = []

    def fake_get(url, timeout):
        calls.append(url)
        return _details_html("PhonePe UPI Payments, Loan App", "https://example/icon.png"), 200

    monkeypatch.setattr(brand_lookup, "_http_get", fake_get)

    listing, status = brand_lookup.fetch_play_listing("com.phonepe.app")
    assert status == "found"
    assert listing.title == "PhonePe UPI Payments, Loan App"
    assert listing.icon_url == "https://example/icon.png"
    assert len(calls) == 1


def test_fetch_play_listing_404_is_not_found_not_an_error(monkeypatch):
    monkeypatch.setattr(brand_lookup, "_http_get", lambda url, timeout: (None, 404))

    listing, status = brand_lookup.fetch_play_listing("com.totally.fake.nonexistent")
    assert listing is None
    assert status == "not_found"


def test_fetch_play_listing_network_failure_is_unavailable_not_not_found(monkeypatch):
    monkeypatch.setattr(brand_lookup, "_http_get", lambda url, timeout: (None, None))

    listing, status = brand_lookup.fetch_play_listing("com.phonepe.app")
    assert listing is None
    assert status == "unavailable"


def test_fetch_play_listing_disabled_never_calls_network(monkeypatch):
    monkeypatch.setattr(settings, "brand_live_lookup_enabled", False)
    calls = []
    monkeypatch.setattr(brand_lookup, "_http_get", lambda url, timeout: calls.append(url))

    listing, status = brand_lookup.fetch_play_listing("com.phonepe.app")
    assert status == "disabled"
    assert listing is None
    assert calls == []


def test_fetch_play_listing_is_cached_across_calls(monkeypatch):
    calls = []

    def fake_get(url, timeout):
        calls.append(url)
        return _details_html("PhonePe UPI Payments, Loan App"), 200

    monkeypatch.setattr(brand_lookup, "_http_get", fake_get)

    brand_lookup.fetch_play_listing("com.phonepe.app")
    brand_lookup.fetch_play_listing("com.phonepe.app")
    assert len(calls) == 1


def test_not_found_is_cached_too(monkeypatch):
    calls = []

    def fake_get(url, timeout):
        calls.append(url)
        return None, 404

    monkeypatch.setattr(brand_lookup, "_http_get", fake_get)

    brand_lookup.fetch_play_listing("com.totally.fake")
    listing, status = brand_lookup.fetch_play_listing("com.totally.fake")
    assert status == "not_found"
    assert len(calls) == 1


def test_cache_entry_expires_after_ttl(monkeypatch):
    calls = []

    def fake_get(url, timeout):
        calls.append(url)
        return _details_html("PhonePe UPI Payments, Loan App"), 200

    monkeypatch.setattr(brand_lookup, "_http_get", fake_get)

    brand_lookup.fetch_play_listing("com.phonepe.app")
    cache = brand_lookup._load_cache()
    cache["listings"]["com.phonepe.app"]["fetched_at"] = (
        time.time() - brand_lookup.CACHE_TTL_SECONDS - 1
    )

    brand_lookup.fetch_play_listing("com.phonepe.app")
    assert len(calls) == 2  # stale entry triggers a real re-fetch


# ── search_play_by_title ─────────────────────────────────────────────────

def test_search_play_by_title_parses_result_tiles(monkeypatch):
    monkeypatch.setattr(
        brand_lookup,
        "_http_get",
        lambda url, timeout: (
            _search_html(
                [
                    ("com.phonepe.app", "PhonePe UPI Payments, Loan App"),
                    ("com.flipkart.android", "Flipkart Online Shopping App"),
                ]
            ),
            200,
        ),
    )

    results, status = brand_lookup.search_play_by_title("PhonePe")
    assert status == "ok"
    assert [r.package_name for r in results] == ["com.phonepe.app", "com.flipkart.android"]


def test_search_play_by_title_network_failure_returns_empty_unavailable(monkeypatch):
    monkeypatch.setattr(brand_lookup, "_http_get", lambda url, timeout: (None, None))

    results, status = brand_lookup.search_play_by_title("PhonePe")
    assert results == []
    assert status == "unavailable"


def test_search_play_by_title_disabled_never_calls_network(monkeypatch):
    monkeypatch.setattr(settings, "brand_live_lookup_enabled", False)
    calls = []
    monkeypatch.setattr(brand_lookup, "_http_get", lambda url, timeout: calls.append(url))

    results, status = brand_lookup.search_play_by_title("PhonePe")
    assert status == "disabled"
    assert results == []
    assert calls == []


def test_search_is_cached_across_calls(monkeypatch):
    calls = []

    def fake_get(url, timeout):
        calls.append(url)
        return _search_html([("com.phonepe.app", "PhonePe UPI Payments, Loan App")]), 200

    monkeypatch.setattr(brand_lookup, "_http_get", fake_get)

    brand_lookup.search_play_by_title("PhonePe")
    brand_lookup.search_play_by_title("PhonePe")
    assert len(calls) == 1


def test_search_play_by_title_handles_layout_without_aria_label(monkeypatch):
    """
    Regression test for the real bug found live 2026-08-25: querying "Customer
    Support" returned 11 real matches in the raw HTML but the aria-label-only
    parser found zero, because that layout has no aria-label at all.
    """
    monkeypatch.setattr(
        brand_lookup,
        "_http_get",
        lambda url, timeout: (
            _search_html_no_aria_label(
                [
                    ("com.fts", "Customer Support System"),
                    ("com.zoho.assist.agent", "Customer App - Zoho Assist"),
                ]
            ),
            200,
        ),
    )

    results, status = brand_lookup.search_play_by_title("Customer Support")
    assert status == "ok"
    assert [r.package_name for r in results] == ["com.fts", "com.zoho.assist.agent"]
    assert results[0].title == "Customer Support System"


def test_search_play_by_title_handles_mixed_layouts_on_one_page(monkeypatch):
    """Real Play pages can mix both tile shapes on the same results page."""
    mixed_html = (
        b"<html><body>"
        b'<a href="/store/apps/details?id=com.aria.app" aria-label="Aria Labeled App">x</a>'
        b'<a href="/store/apps/details?id=com.text.app">'
        b'<img alt="icon"/><span>Text Node App</span></a>'
        b"</body></html>"
    )
    monkeypatch.setattr(brand_lookup, "_http_get", lambda url, timeout: (mixed_html, 200))

    results, status = brand_lookup.search_play_by_title("whatever")
    assert status == "ok"
    assert {(r.package_name, r.title) for r in results} == {
        ("com.aria.app", "Aria Labeled App"),
        ("com.text.app", "Text Node App"),
    }


def test_search_respects_max_results(monkeypatch):
    monkeypatch.setattr(
        brand_lookup,
        "_http_get",
        lambda url, timeout: (
            _search_html([(f"com.example.app{i}", f"App {i}") for i in range(10)]),
            200,
        ),
    )

    results, status = brand_lookup.search_play_by_title("App", max_results=3)
    assert status == "ok"
    assert len(results) == 3


# ── labels_plausibly_match ───────────────────────────────────────────────

def test_labels_plausibly_match_absorbs_play_taglines():
    assert brand_lookup.labels_plausibly_match("PhonePe", "PhonePe UPI Payments, Loan App")


def test_labels_plausibly_match_rejects_unrelated_names():
    assert not brand_lookup.labels_plausibly_match("PhonePe", "Flipkart Online Shopping App")


def test_labels_plausibly_match_exact_equal():
    assert brand_lookup.labels_plausibly_match("WhatsApp", "WhatsApp")
