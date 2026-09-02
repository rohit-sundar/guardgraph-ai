"""
Regression test for an ingest crash that scored ordinary apps as unparseable.

`ingest_apk` logged its manifest-recovery summary from inside the LAUNCHER ICON
recovery block, referencing `recovered` — a local bound only in the separate
manifest-recovery block above it. The two conditions are independent:

  * `recovered` is bound only when the manifest FAILED to parse;
  * the icon block runs whenever `icon_phash is None`, which is the ordinary
    modern case (an adaptive/XML launcher drawable has no pixels to hash).

An app that parsed fine and had an XML icon therefore raised UnboundLocalError
out of ingest_apk. That is not a contained failure: _analyze_with_fallback
catches it and falls through to _unparseable_report, so a perfectly readable app
was reported at UNPARSEABLE_RISK_SCORE (50.0, "suspicious") — the "look at this
by hand" verdict — with no indication that the cause was a bug rather than the
sample.

Measured on a 30-sample corpus draw (2026-09-02) before the fix: it fired on
11 of 15 benign apps and 2 of 15 malware, i.e. 43% of samples overall.
"""
import sys
import os
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.analysis import ingest


class IconRecoveryDoesNotCrashAParsedManifest(unittest.TestCase):
    """The crash needs a manifest that parsed AND an icon recovered from the
    container. Both are the common case, which is why this was so damaging."""

    def _ingest_with(self, *, icon_from_apk, icon_from_container):
        apk_obj = MagicMock()
        apk_obj.get_permissions.return_value = ["android.permission.INTERNET"]
        apk_obj.get_package.return_value = "com.example.ordinary"
        apk_obj.get_app_name.return_value = "Ordinary"
        apk_obj.get_activities.return_value = ["com.example.ordinary.Main"]
        apk_obj.get_services.return_value = []
        apk_obj.get_receivers.return_value = []

        analysis_obj = MagicMock()
        analysis_obj.get_methods.return_value = []

        container = MagicMock()

        with patch.object(ingest, "compute_sha256", return_value="ab" * 32), \
             patch.object(ingest, "AnalyzeAPK", return_value=(apk_obj, MagicMock(), analysis_obj)), \
             patch.object(ingest, "open_and_scan", return_value=(container, MagicMock(anomalies=[]))), \
             patch.object(ingest, "inspect_apk_payloads", return_value={}), \
             patch.object(ingest, "extract_c2_indicators", return_value=[]), \
             patch.object(ingest, "extract_der_certificates", return_value=[]), \
             patch.object(ingest, "analyze_certificate_anomalies", return_value=[]), \
             patch.object(ingest, "detect_permission_matrix", return_value=[]), \
             patch.object(ingest, "extract_intent_actions", return_value=[]), \
             patch.object(ingest, "declares_accessibility_service", return_value=False), \
             patch.object(ingest, "extract_icon_phash", return_value=icon_from_apk), \
             patch.object(ingest, "extract_icon_phash_from_container",
                          return_value=icon_from_container), \
             patch.object(ingest, "recover_manifest", return_value=None):
            return ingest.ingest_apk("/fake/ordinary.apk")

    def test_adaptive_icon_recovered_from_container_does_not_raise(self):
        """
        The exact failing combination: manifest parses (so `recovered` is never
        bound), the launcher icon is an XML drawable (so extract_icon_phash
        returns None), and the container yields one anyway.
        """
        result, *_ = self._ingest_with(icon_from_apk=None, icon_from_container=0xDEADBEEF)

        self.assertEqual(result.package_name, "com.example.ordinary")
        self.assertEqual(result.icon_phash, f"{0xDEADBEEF:016x}")
        self.assertFalse(
            result.manifest_parse_failed,
            "a manifest that parsed must not be reported as failed just because "
            "the icon needed recovering",
        )

    def test_no_icon_anywhere_is_still_fine(self):
        result, *_ = self._ingest_with(icon_from_apk=None, icon_from_container=None)
        self.assertIsNone(result.icon_phash)
        self.assertEqual(result.package_name, "com.example.ordinary")

    def test_icon_resolved_from_the_apk_skips_recovery_entirely(self):
        result, *_ = self._ingest_with(icon_from_apk=0x1234, icon_from_container=None)
        self.assertEqual(result.icon_phash, f"{0x1234:016x}")


if __name__ == "__main__":
    unittest.main()
