"""
Regression tests for the widened panel-URL C2 pattern (app/analysis/apk_static.py).

Coverage before this change was narrow: Telegram/Firebase/Discord/TOR/raw-IP plus
exactly four hardcoded panel paths (gate.php, panel/, api/bot, bot/gate). Measured
against real MalwareBazaar samples, that caught roughly 1 in 8 — most banking-
trojan/botnet C2 kits use a PHP-backed panel with a check-in/report/command
endpoint the old pattern never looked for.

The widening stays anchored to a full http(s):// URL rather than a bare keyword
match — that is the load-bearing design choice that keeps this from flooding on
ordinary app strings. A legitimate app's string pool contains the word "report" or
"admin" constantly (crash reporting SDKs, admin-panel-branded UI copy); it does not
contain a literal URL ending in "/report.php" or "/admin.php" pointing at some
attacker's domain. Every test below exercises that boundary explicitly: the same
suspicious word must NOT match without the URL wrapper, and MUST match with it.

Fully offline — no APKs, no network, pure string patterns.
"""
import unittest

from app.analysis.apk_static import extract_c2_indicators


class TestWidenedPanelPaths(unittest.TestCase):
    def _panel_hits(self, s: str) -> list[str]:
        return [i for i in extract_c2_indicators([s]) if i.startswith("panel_url:")]

    def test_new_php_checkin_scripts_are_caught(self):
        for script in (
            "admin.php", "cmd.php", "command.php", "control.php", "register.php",
            "checkin.php", "check_in.php", "beacon.php", "heartbeat.php",
            "report.php", "upload.php", "task.php", "tasks.php",
            "getcmd.php", "getcommand.php", "c2.php", "cnc.php",
        ):
            with self.subTest(script=script):
                url = f"http://evil-c2-host.com/gate/{script}"
                self.assertTrue(
                    self._panel_hits(url), f"{script} was not flagged as a panel URL"
                )

    def test_c2_and_cnc_path_segments_are_caught(self):
        for path in ("http://evil.com/c2/report", "http://evil.com/cnc/beacon"):
            with self.subTest(path=path):
                self.assertTrue(self._panel_hits(path))

    def test_versioned_bot_api_paths_are_caught(self):
        for path in (
            "https://evil.com/api/v1/bot",
            "https://evil.com/api/v2/panel",
            "https://evil.com/api/v3/report",
            "https://evil.com/api/v1/checkin",
        ):
            with self.subTest(path=path):
                self.assertTrue(self._panel_hits(path))

    def test_bot_report_task_cmd_paths_are_caught(self):
        for path in (
            "https://evil.com/bot/report",
            "https://evil.com/bot/task",
            "https://evil.com/bot/cmd",
        ):
            with self.subTest(path=path):
                self.assertTrue(self._panel_hits(path))

    def test_original_four_patterns_still_match(self):
        """The widening must be additive — nothing already caught should regress."""
        for path in (
            "http://evil.com/gate.php",
            "http://evil.com/panel/index",
            "http://evil.com/api/bot",
            "http://evil.com/bot/gate",
        ):
            with self.subTest(path=path):
                self.assertTrue(self._panel_hits(path))

    def test_the_bare_keyword_alone_does_not_match_without_a_url(self):
        """The false-positive guard this whole design depends on: a benign string
        that merely CONTAINS one of the new trigger words, with no URL, must not
        be flagged. If this test fails, the pattern has stopped being anchored to
        a URL and will flood on ordinary app strings."""
        benign_strings = [
            "Tap here to view your report",
            "Contact admin for support",
            "Upload your profile picture",
            "Send a command to the printer",
            "Register for a new account",
            "checkin at your favorite restaurant",
            "Task completed successfully",
            "Heartbeat monitor for fitness tracking",
        ]
        for s in benign_strings:
            with self.subTest(s=s):
                self.assertEqual(self._panel_hits(s), [])

    def test_a_url_to_an_unrelated_benign_path_does_not_match(self):
        """Anchoring to a URL is necessary but not sufficient — the path itself
        still has to look like a C2 endpoint, not just be a URL that happens to
        mention 'report' as a substring of an unrelated word."""
        benign_urls = [
            "https://mycompany.com/support/reportissue.html",  # 'report' but not /report.php or a matched segment
            "https://cdn.example.com/assets/logo.png",
            "https://api.mycompany.com/v1/users/profile",
        ]
        for url in benign_urls:
            with self.subTest(url=url):
                self.assertEqual(self._panel_hits(url), [])

    def test_ordinary_app_strings_produce_no_indicators_at_all(self):
        """End-to-end sanity: a plausible slice of a normal app's string pool
        should not produce ANY C2 indicator, widened panel paths included."""
        ordinary = [
            "Settings", "Please grant camera permission to continue",
            "https://play.google.com/store/apps/details?id=com.example",
            "https://firebase.google.com/docs/reference",  # not *.firebaseio.com/*.firebaseapp.com
            "Error: could not connect to the server",
            "Your report is being generated, please wait",
            "https://schema.org/Person",
        ]
        self.assertEqual(extract_c2_indicators(ordinary), [])


if __name__ == "__main__":
    unittest.main()
