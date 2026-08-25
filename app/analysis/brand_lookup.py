"""
Live Google Play Store identity verification — a THIRD, independent signal
alongside the static brands table in data/reference/protected_brands.json
(see app/analysis/impersonation.py's module docstring for the other two).

Two things Play's public pages can answer without authentication, at
analysis time, for ANY app — not just the ones someone remembered to add to
the static table:

  - does a listing exist under this exact package name, and what does Play
    say the app is actually called (the details page)?
  - what real apps share this display name (the search page)?

One thing they cannot answer: another developer's signing certificate. Play
does not expose that through any public page, and getting it for real means
downloading the actual APK from an official install — which is what
scripts/build_brand_reference.py does, and stays a manually-verified, cached
fact in protected_brands.json. See that file's own `warning` field for why
a mirror-sourced APK would invert the check rather than merely fail to run
it. This module does not attempt that; it only extends the name/label side.

Same offline-first shape as the VirusTotal/MalwareBazaar lookups in
app/analysis/signatures.py: stdlib urllib only (no new HTTP dependency),
a short timeout, and every failure degrades to "checked nothing" rather
than raising or blocking analysis. Results are cached to disk
(data/cache/play_lookup_cache.json, 30-day TTL) since brand identity is
about the most stable fact there is — a given package name or search title
is fetched from the real internet at most once, ever, not once per upload.
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Optional

from loguru import logger

from app.core.config import settings

CACHE_PATH = os.path.join("data", "cache", "play_lookup_cache.json")
# Brand identity is about the most stable fact there is. 30 days is generous
# headroom, not a tight budget — the point is "practically forever, without
# literally never re-checking if a package ever gets delisted/renamed".
CACHE_TTL_SECONDS = 30 * 24 * 3600

# A bare urllib request identifies itself as "Python-urllib/3.x", which Play
# serves a stripped-down response for. A realistic desktop-browser UA is
# required to get the real server-rendered page — confirmed live 2026-08-25
# against play.google.com (curl with this UA returned the full listing/search
# HTML; a bare request would not have).
_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)

_DETAILS_URL = "https://play.google.com/store/apps/details?id={package}&hl=en"
_SEARCH_URL = "https://play.google.com/store/search?q={query}&c=apps&hl=en"


@dataclass
class PlayListing:
    package_name: str
    title: str
    icon_url: Optional[str] = None


# ── HTTP seam ────────────────────────────────────────────────────────────
# A single choke point, so tests can monkeypatch one function instead of
# mocking urllib globally, and so every caller gets identical timeout/error
# handling for free.

def _http_get(url: str, timeout: float) -> tuple[Optional[bytes], Optional[int]]:
    """
    Returns (body, status). `status` is the real HTTP status Play responded
    with (e.g. 404 for "no such app") when the server answered at all, or
    None when the request never got a response (timeout/DNS/connection
    refused) — the two are NOT the same and callers must not conflate them:
    404 is a confirmed fact, None is "we don't know".
    """
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.read(), response.status
    except urllib.error.HTTPError as exc:
        return None, exc.code
    except Exception as exc:
        logger.debug(f"[brand_lookup] request to {url} failed: {exc}")
        return None, None


# ── HTML parsing ─────────────────────────────────────────────────────────
# stdlib html.parser only — no new bs4/lxml dependency for pulling two
# attributes off two known tag shapes.

class _DetailsPageParser(HTMLParser):
    """Pulls og:title / og:image off a Play listing page's <meta> tags."""

    def __init__(self):
        super().__init__()
        self.title: Optional[str] = None
        self.icon_url: Optional[str] = None

    def handle_starttag(self, tag, attrs):
        if tag != "meta":
            return
        attrs_d = dict(attrs)
        prop = attrs_d.get("property")
        content = attrs_d.get("content")
        if not content:
            return
        if prop == "og:title" and self.title is None:
            self.title = content
        elif prop == "og:image" and self.icon_url is None:
            self.icon_url = content


class _SearchResultsParser(HTMLParser):
    """
    Pulls (package_id, title) pairs off a Play search-results page.

    Play renders search results in at least two different DOM shapes —
    confirmed live 2026-08-25: querying "PhonePe" returned card tiles with
    the title in the anchor's `aria-label`, while querying "Customer
    Support" returned compact list rows with NO aria-label at all, title
    text instead sitting inside a `<span>` a few tags after the anchor.
    Keying off a specific CSS class for that second shape isn't safe either
    — Play's classes are minified and churn on any redesign.

    Instead: once inside a details anchor with no aria-label, take the
    FIRST real text seen before the next details anchor starts, wherever it
    lives in the DOM. In both observed layouts, everything between the
    anchor and the title text is an image (attributes only, no text nodes),
    so this holds without needing to know the exact tag or class — and it
    is why the "Customer Support" query silently returned zero results
    before this fix while the underlying HTML clearly had 11 real matches.

    If a future Play layout breaks this too, the failure mode stays the
    same as before: zero results, not a crash — fail closed, same as the
    rest of this analysis package.
    """

    _HREF_RE = re.compile(r"^/store/apps/details\?id=([A-Za-z0-9_.]+)")

    def __init__(self, max_results: int):
        super().__init__()
        self.results: list[PlayListing] = []
        self._max_results = max_results
        self._seen: set[str] = set()
        self._pending_package: Optional[str] = None

    def handle_starttag(self, tag, attrs):
        if len(self.results) >= self._max_results:
            return
        if tag != "a":
            return
        attrs_d = dict(attrs)
        match = self._HREF_RE.match(attrs_d.get("href") or "")
        if not match or match.group(1) in self._seen:
            return
        package = match.group(1)
        label = attrs_d.get("aria-label")
        if label:
            self._seen.add(package)
            self.results.append(PlayListing(package_name=package, title=label))
            self._pending_package = None
        else:
            # No aria-label on this anchor — wait for the next real text node,
            # which handle_data() below treats as this tile's title.
            self._pending_package = package

    def handle_data(self, data):
        if self._pending_package is None:
            return
        text = data.strip()
        if not text:
            return
        self._seen.add(self._pending_package)
        self.results.append(PlayListing(package_name=self._pending_package, title=text))
        self._pending_package = None


# ── on-disk cache ────────────────────────────────────────────────────────
# One JSON file, loaded once per process (module-global, same pattern as
# _SIGNATURE_DB in app/analysis/signatures.py), write-through on every fresh
# fetch. A corrupt or missing file degrades to an empty cache rather than
# ever raising — losing the cache costs latency on the next lookup, never
# correctness.

_CACHE: Optional[dict] = None


def _load_cache() -> dict:
    global _CACHE
    if _CACHE is not None:
        return _CACHE
    if os.path.exists(CACHE_PATH):
        try:
            with open(CACHE_PATH, encoding="utf-8") as handle:
                _CACHE = json.load(handle)
                _CACHE.setdefault("listings", {})
                _CACHE.setdefault("searches", {})
                return _CACHE
        except Exception as exc:
            logger.warning(
                f"[brand_lookup] cache at {CACHE_PATH} is unreadable, starting fresh: {exc}"
            )
    _CACHE = {"listings": {}, "searches": {}}
    return _CACHE


def _save_cache() -> None:
    if _CACHE is None:
        return
    try:
        os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
        with open(CACHE_PATH, "w", encoding="utf-8") as handle:
            json.dump(_CACHE, handle, indent=2, sort_keys=True)
    except Exception as exc:
        # A cache write failure is a side effect, not the point of the call —
        # it must never fail the analysis that triggered the lookup.
        logger.warning(f"[brand_lookup] could not persist cache to {CACHE_PATH}: {exc}")


def _is_fresh(entry: dict) -> bool:
    return (time.time() - entry.get("fetched_at", 0)) < CACHE_TTL_SECONDS


def reset_cache() -> None:
    """Clears the in-process cache. For tests — production never needs this."""
    global _CACHE
    _CACHE = None


# ── public API ───────────────────────────────────────────────────────────

def fetch_play_listing(
    package_name: str, timeout: Optional[float] = None
) -> tuple[Optional[PlayListing], str]:
    """
    Looks up `package_name`'s real Play listing.

    Returns (listing, status) where status is one of:
      "disabled"    — brand_live_lookup_enabled is off; no request attempted.
      "found"       — a listing exists; `listing` is populated.
      "not_found"   — Play answered 404: this package is confirmed absent.
      "unavailable" — the lookup could not be completed (network failure,
                       unparseable response). NOT the same as "not_found" —
                       callers must not treat an outage as evidence.
    """
    if not package_name:
        return None, "not_found"
    if not settings.brand_live_lookup_enabled:
        return None, "disabled"

    cache = _load_cache()
    cached = cache["listings"].get(package_name)
    if cached is not None and _is_fresh(cached):
        if cached.get("found"):
            return (
                PlayListing(
                    package_name=package_name,
                    title=cached["title"],
                    icon_url=cached.get("icon_url"),
                ),
                "found",
            )
        return None, "not_found"

    effective_timeout = (
        settings.brand_live_lookup_timeout_seconds if timeout is None else timeout
    )
    url = _DETAILS_URL.format(package=urllib.parse.quote(package_name, safe=""))
    body, status = _http_get(url, effective_timeout)

    if status == 404:
        cache["listings"][package_name] = {"found": False, "fetched_at": time.time()}
        _save_cache()
        return None, "not_found"
    if body is None:
        logger.warning(
            f"[brand_lookup] Play listing lookup for {package_name!r} failed "
            f"(network, status={status})"
        )
        return None, "unavailable"

    parser = _DetailsPageParser()
    try:
        parser.feed(body.decode("utf-8", errors="replace"))
    except Exception as exc:
        logger.warning(
            f"[brand_lookup] could not parse Play listing for {package_name!r}: {exc}"
        )
        return None, "unavailable"

    if not parser.title:
        return None, "unavailable"

    cache["listings"][package_name] = {
        "found": True,
        "title": parser.title,
        "icon_url": parser.icon_url,
        "fetched_at": time.time(),
    }
    _save_cache()
    return (
        PlayListing(package_name=package_name, title=parser.title, icon_url=parser.icon_url),
        "found",
    )


def search_play_by_title(
    title: str, max_results: int = 5, timeout: Optional[float] = None
) -> tuple[list[PlayListing], str]:
    """
    Searches Play for real apps sharing `title`.

    Play's own search is broad and fuzzy — a query for one brand name
    routinely surfaces a dozen loosely related apps, confirmed live
    2026-08-25 (searching "PhonePe" returned Flipkart, Truecaller, Airtel
    Thanks and more alongside the real PhonePe listing). Callers must apply
    their own strict title-matching (see labels_plausibly_match) rather
    than treating "appeared in results" as a match by itself.

    Returns (results, status) where status is "disabled" / "ok" /
    "unavailable" — same meaning as fetch_play_listing's status, except
    there is no "not_found": an empty result list with status "ok" means
    the search ran and genuinely found nothing.
    """
    if not title or not title.strip():
        return [], "not_found"
    if not settings.brand_live_lookup_enabled:
        return [], "disabled"

    cache_key = title.strip().lower()
    cache = _load_cache()
    cached = cache["searches"].get(cache_key)
    if cached is not None and _is_fresh(cached):
        return [PlayListing(**r) for r in cached["results"][:max_results]], "ok"

    effective_timeout = (
        settings.brand_live_lookup_timeout_seconds if timeout is None else timeout
    )
    url = _SEARCH_URL.format(query=urllib.parse.quote(title))
    body, status = _http_get(url, effective_timeout)
    if body is None:
        logger.warning(
            f"[brand_lookup] Play search for {title!r} failed (network, status={status})"
        )
        return [], "unavailable"

    parser = _SearchResultsParser(max_results=max_results)
    try:
        parser.feed(body.decode("utf-8", errors="replace"))
    except Exception as exc:
        logger.warning(f"[brand_lookup] could not parse Play search results for {title!r}: {exc}")
        return [], "unavailable"

    cache["searches"][cache_key] = {
        "results": [
            {"package_name": r.package_name, "title": r.title, "icon_url": r.icon_url}
            for r in parser.results
        ],
        "fetched_at": time.time(),
    }
    _save_cache()
    return parser.results, "ok"


def labels_plausibly_match(label: str, listing_title: str) -> bool:
    """
    True when `label` (an APK's declared display name) plausibly refers to
    the same app as `listing_title` (a real Play listing's title).

    Play listing titles routinely carry a marketing tagline after the real
    name — "PhonePe UPI Payments, Loan App" for package com.phonepe.app,
    confirmed live 2026-08-25 — so a strict edit-distance comparison would
    misreport the genuine app as a mismatch. A normalized substring check
    absorbs the tagline.

    Deliberately EXACT/SUBSTRING ONLY — no edit-distance fallback, unlike the
    static-table checks in impersonation.py. Confirmed live 2026-08-25:
    "G-Droid" (org.gdroid.gdroid, a real F-Droid client) normalises to
    "gdroid", which is edit-distance 1 from "godroid" ("GoDroid", an
    unrelated real glider app) — the identical transformation shape as a
    genuine typosquat like "Phonpe" -> "PhonePe". Edit distance alone cannot
    tell a real typosquat apart from two unrelated apps that happen to share
    a short name, and this function's search space is every real app on
    Play, not a curated list — unlike impersonation.py's own inline
    edit-distance check in _check_label(), which stays fuzzy because it only
    ever compares against a small, hand-verified set of protected brands
    where that ambiguity is bounded and worth the recall. Live label search
    has no such bound, so it only fires on the unambiguous case.

    Imported lazily from app.analysis.impersonation (not at module level) to
    avoid a circular import: impersonation.py imports this module to run the
    live checks, and this function needs impersonation's string-normalisation
    helper to stay consistent with the static checks rather than duplicating
    the confusable-character logic.
    """
    from app.analysis.impersonation import normalize_confusables

    a = normalize_confusables(label)
    b = normalize_confusables(listing_title)
    if not a or not b:
        return False
    return a == b or a in b or b in a


def fetch_icon_phash(icon_url: Optional[str], timeout: Optional[float] = None) -> Optional[int]:
    """
    Downloads a listing's icon and perceptually hashes it, reusing
    app.analysis.impersonation.perceptual_hash rather than duplicating the
    DCT transform. Not wired into either live check yet (title comparison
    alone already covers both live finding kinds) — exposed for a future
    icon-based live check without needing a second implementation of pHash.
    """
    if not icon_url or not settings.brand_live_lookup_enabled:
        return None
    effective_timeout = (
        settings.brand_live_lookup_timeout_seconds if timeout is None else timeout
    )
    body, _status = _http_get(icon_url, effective_timeout)
    if body is None:
        return None
    from app.analysis.impersonation import perceptual_hash

    return perceptual_hash(body)
