"""
Unit tests for Android static malware enhancements: C2 extraction,
permission matrix detection, certificate anomaly analysis, and schema consistency.
"""
import unittest
from app.analysis.apk_static import (
    extract_c2_indicators,
    detect_permission_matrix,
    analyze_certificate_anomalies,
)
from app.core.schemas import IngestionResult, AnalysisManifest, ObfuscationSignal


class TestApkEnhancements(unittest.TestCase):
    def test_c2_extraction(self):
        sample_strings = [
            "https://api.telegram.org/bot123456789:ABCdefGHIjklMNOpqrsTUVwxyz1234567/sendMessage",
            "https://my-malware-c2.firebaseio.com/data.json",
            "https://discord.com/api/webhooks/1234567890/token_string_here",
            # Public routable IP — this is what a raw_ip indicator must be.
            # Previously this fixture used 192.168.1.50, which is now excluded
            # (see test_private_and_resolver_ips_are_not_c2 below).
            "http://185.220.101.44:8080/gate.php",
            "http://v3toraddress234567abcdef234567.onion",
            "normal string here with no c2",
        ]
        indicators = extract_c2_indicators(sample_strings)

        self.assertTrue(any("telegram_bot:" in i for i in indicators))
        self.assertTrue(any("firebase:" in i for i in indicators))
        self.assertTrue(any("discord_webhook:" in i for i in indicators))
        self.assertTrue(any("onion:" in i for i in indicators))
        self.assertTrue(any("raw_ip:" in i for i in indicators))
        self.assertTrue(any("panel_url:" in i for i in indicators))

    def test_private_and_resolver_ips_are_not_c2(self):
        """
        An RFC1918 address cannot be a C2 channel: the victim's device is not on
        the operator's LAN, so it is unreachable no matter what port it carries.
        The string is usually a real dev/test backend left in the build, but
        "the string exists" does not make it attacker infrastructure, and a
        knowledge graph that says otherwise is asserting something impossible.
        Public DNS resolvers are excluded for the same reason — a DoH endpoint
        is not the C2, the host it resolves is.
        """
        indicators = extract_c2_indicators([
            "http://192.168.8.230:8000",
            "http://10.1.2.3:4444/gate.php",
            "http://172.16.5.5:1337",
            "http://169.254.1.1:9999",
            "https://1.1.1.1/dns-query?ct=application/dns-udpwireformat",
            "https://8.8.8.8/resolve",
        ])
        self.assertEqual(
            [i for i in indicators if i.startswith("raw_ip:")], [],
            f"non-routable or resolver address recorded as C2: {indicators}",
        )

    def test_public_ip_on_a_nonstandard_port_is_still_c2(self):
        """The private-range exclusion must not suppress genuine raw-IP C2."""
        indicators = extract_c2_indicators(["http://154.216.20.57:3434/api/bot"])
        self.assertTrue(any(i.startswith("raw_ip:") for i in indicators), indicators)

    def test_permission_matrix_detection(self):
        # Test Overlay Attack Pattern
        overlay_perms = [
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.PACKAGE_USAGE_STATS",
            "android.permission.INTERNET",
        ]
        flags = detect_permission_matrix(overlay_perms)
        self.assertIn("OVERLAY_ATTACK_PATTERN", flags)

        # Test SMS OTP Stealer Pattern
        stealer_perms = [
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
        ]
        flags_stealer = detect_permission_matrix(stealer_perms)
        self.assertIn("SMS_OTP_STEALER_PATTERN", flags_stealer)

        # Test Dropper Pattern
        dropper_perms = [
            "android.permission.REQUEST_INSTALL_PACKAGES",
            "android.permission.INTERNET",
        ]
        flags_dropper = detect_permission_matrix(dropper_perms)
        self.assertIn("DROPPER_STAGE2_PATTERN", flags_dropper)

    def test_schema_enrichment_fields(self):
        ingestion = IngestionResult(
            sha256="test_sha256",
            package_name="com.example.malware",
            c2_indicators=["telegram_bot:12345:token"],
            cert_anomalies=["debug_or_test_key:CN=Android Debug"],
            permission_matrix_flags=["OVERLAY_ATTACK_PATTERN"],
            secondary_dex_count=2,
            accessibility_flags=["canRetrieveWindowContent=true"],
            dropper_signals=["hidden_dex_in_assets:assets/payload.bin"],
        )
        self.assertEqual(len(ingestion.c2_indicators), 1)
        self.assertEqual(ingestion.secondary_dex_count, 2)

        manifest = AnalysisManifest(
            target_package="com.example.malware",
            sha256="test_sha256",
            cache_hit=False,
            total_nodes_parsed=100,
            graph_density=0.05,
            behavioral_subgraphs=[],
            obfuscation=ObfuscationSignal(
                string_entropy_score=5.5,
                flattening_suspected=False,
                coverage_note="no significant static coverage gaps detected",
            ),
            predicted_ttps={},
            predicted_family=None,
            family_confidence=None,
            c2_indicators=ingestion.c2_indicators,
            cert_anomalies=ingestion.cert_anomalies,
            permission_matrix_flags=ingestion.permission_matrix_flags,
            secondary_dex_count=ingestion.secondary_dex_count,
            accessibility_flags=ingestion.accessibility_flags,
            dropper_signals=ingestion.dropper_signals,
        )
        self.assertEqual(manifest.secondary_dex_count, 2)
        self.assertIn("OVERLAY_ATTACK_PATTERN", manifest.permission_matrix_flags)


if __name__ == "__main__":
    unittest.main()
