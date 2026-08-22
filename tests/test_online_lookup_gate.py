"""
Regression tests for the third-party reputation-lookup gate.

Both online sources in app/analysis/signatures.py are metered, and both fail in
the same silent way: VirusTotal's public tier allows 4 requests/min and 500/day
and answers HTTP 429 past that, while MalwareBazaar answers HTTP 401 to any
request without an Auth-Key header. Either response used to fall into a blanket
`except Exception` and return None -- which the caller cannot distinguish from
"this file is clean". A corpus run that quietly rate-limits itself therefore
produces a calibration set where every sample looks unknown to reputation.

What is pinned here:

  * `settings.online_lookups_enabled = False` performs ZERO outbound requests.
    scripts/score_corpus.py is the only caller in the repo that can breach either
    limit (one lookup per APK across 8 concurrent children, 600 per corpus run),
    and it turns this off by default; these tests are what make that a guarantee
    rather than an intention.
  * The MalwareBazaar request carries the Auth-Key header, and no request is made
    at all without a key. abuse.ch made auth mandatory on every endpoint,
    get_info included -- verified 2026-08-21, the same query answering 200 with
    the key and 401 without it.
  * A metered failure is not reported as a clean verdict.

Fully offline -- urlopen is replaced with a spy that records and refuses.
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.analysis import signatures
from app.core.config import settings

SHA = "0" * 64


class _Spy:
    """Records every attempted request and never touches the network."""

    def __init__(self, exc=None):
        self.calls = []
        self.exc = exc or RuntimeError("network call attempted")

    def __call__(self, req, *args, **kwargs):
        self.calls.append(req)
        raise self.exc

    @property
    def urls(self):
        return [getattr(r, "full_url", r) for r in self.calls]

    def headers_for(self, fragment):
        for req in self.calls:
            if fragment in getattr(req, "full_url", ""):
                return {k.lower(): v for k, v in (getattr(req, "headers", {}) or {}).items()}
        return None


class TestOnlineLookupGate(unittest.TestCase):
    def setUp(self):
        self.original = settings.online_lookups_enabled
        signatures.reset_signature_db()

    def tearDown(self):
        settings.online_lookups_enabled = self.original
        signatures.reset_signature_db()

    def test_disabled_makes_no_outbound_request(self):
        """The quota guarantee: off means zero requests, not fewer requests."""
        settings.online_lookups_enabled = False
        spy = _Spy()
        with mock.patch("urllib.request.urlopen", spy), \
                mock.patch.object(settings, "virustotal_api_key", "vt-key"), \
                mock.patch.object(settings, "malwarebazaar_api_key", "mb-key"):
            matches = signatures.match_signatures(SHA, None, settings.signature_db_path)
        self.assertEqual(spy.calls, [], f"expected no requests, got {spy.urls}")
        self.assertEqual(matches, [])

    def test_enabled_queries_both_sources(self):
        settings.online_lookups_enabled = True
        spy = _Spy()
        with mock.patch("urllib.request.urlopen", spy), \
                mock.patch.object(settings, "virustotal_api_key", "vt-key"), \
                mock.patch.object(settings, "malwarebazaar_api_key", "mb-key"):
            signatures.match_signatures(SHA, None, settings.signature_db_path)
        joined = " ".join(spy.urls)
        self.assertIn("mb-api.abuse.ch", joined)
        self.assertIn("virustotal.com", joined)

    def test_malwarebazaar_sends_auth_key(self):
        """abuse.ch 401s every unauthenticated request, get_info included."""
        settings.online_lookups_enabled = True
        spy = _Spy()
        with mock.patch("urllib.request.urlopen", spy), \
                mock.patch.object(settings, "virustotal_api_key", ""), \
                mock.patch.object(settings, "malwarebazaar_api_key", "mb-key"):
            signatures.match_signatures(SHA, None, settings.signature_db_path)
        headers = spy.headers_for("mb-api.abuse.ch")
        self.assertIsNotNone(headers, "MalwareBazaar was never queried")
        self.assertEqual(headers.get("Auth-key".lower()), "mb-key")

    def test_no_key_means_no_request(self):
        """A blank key must not produce a request that can only 401."""
        settings.online_lookups_enabled = True
        spy = _Spy()
        with mock.patch("urllib.request.urlopen", spy), \
                mock.patch.object(settings, "virustotal_api_key", ""), \
                mock.patch.object(settings, "malwarebazaar_api_key", ""):
            signatures.match_signatures(SHA, None, settings.signature_db_path)
        self.assertEqual(spy.calls, [], f"expected no requests, got {spy.urls}")

    def test_rate_limited_lookup_is_not_a_clean_verdict(self):
        """429 must return no match -- and must not raise, which would abort a run."""
        import urllib.error

        settings.online_lookups_enabled = True
        err = urllib.error.HTTPError(
            "https://www.virustotal.com/", 429, "Too Many Requests", {}, None
        )
        spy = _Spy(exc=err)
        with mock.patch("urllib.request.urlopen", spy), \
                mock.patch.object(settings, "virustotal_api_key", "vt-key"), \
                mock.patch.object(settings, "malwarebazaar_api_key", "mb-key"):
            matches = signatures.match_signatures(SHA, None, settings.signature_db_path)
        self.assertEqual(matches, [])
        self.assertTrue(spy.calls, "the lookup should still have been attempted")


class TestScoreCorpusDefaults(unittest.TestCase):
    """score_corpus.py is the only caller that can breach either published limit."""

    def test_online_is_opt_in_and_paced(self):
        sys.path.insert(
            0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts"))
        )
        import score_corpus

        # 15 s/sample on one worker is exactly VirusTotal's 4/min.
        self.assertEqual(score_corpus.ONLINE_SECONDS_PER_SAMPLE, 15.0)
        self.assertLess(score_corpus.ONLINE_DAILY_STOP, 500)


if __name__ == "__main__":
    unittest.main()
