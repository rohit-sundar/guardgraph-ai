"""
Regression tests for the N5-N8 calibration pass.

Each finding below was opened by *measuring* the corpus rather than by reading code,
so each test here pins the measured behaviour, not the implementation. Figures were
re-measured on 2026-08-21 against the expanded corpus — 618 rows, 300 F-Droid benign
(220 under 12 MB plus 80 between 12 and 60 MB) and 318 MalwareBazaar malware across
21 families, with online reputation lookups disabled — and the originals from the
353-APK corpus (220/133) are kept alongside where the comparison is the point:

  N5  accessibility parsing and the ACCESSIBILITY_* matrix flags were gated on
      `<uses-permission android:name="...BIND_ACCESSIBILITY_SERVICE">`, which 6 of 133
      malware declare. The service's intent-filter action, which 75 of 133 declare, is
      the real signal. Re-measured over 318 malware the gap is wider still: 7 declare
      the permission, 191 declare the service — and 9 of 300 clean apps do too, which
      is why the declaration gates the rule rather than scoring on its own.
  N6  `ioc_component` consumed 93.4% of its cap on clean apps against 97.6% on
      malware. Two causes: `self_signed` reported as an anomaly on every APK, and a
      YARA term that paid 0.765 for matching three generic community rules.
  N7  `obfuscation_component` was *inverted* (benign 39.3% of cap, malware 32.5%).
      Three of its four inputs were dead and the fourth — `flattening_suspected` — is
      an existential over every analysed method, so it fired on 30/30 clean apps.
  N8  `classifier_confidence_component` returned `max(probability)`, ignoring both the
      per-label calibrated threshold and how many techniques corroborated. See also
      tests/test_classifier_evidence_gate.py.

Plus the verdict-band boundaries those components feed.

Fully offline — no model, no Neo4j, no Ollama, no APK fixtures.
"""
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.analysis.apk_static import (
    ACCESSIBILITY_SERVICE_ACTION,
    accessibility_matrix_flags,
    analyze_certificate_anomalies,
    declares_accessibility_service,
    detect_permission_matrix,
)
from app.analysis.forensic import ACCESSIBILITY_INTENT_ACTIONS
from app.core.schemas import ObfuscationSignal
from app.reports.scoring import (
    BAND_HIGH_CEILING,
    BAND_LOW_CEILING,
    BAND_MEDIUM_CEILING,
    BAND_SUSPICIOUS_CEILING,
    CODE_NOT_RECOVERED_WEIGHT,
    MATRIX_FLAG_SEVERITY,
    OPAQUE_REPUTATION_SCORE_FLOOR,
    OPAQUE_DEX_MAX_METHODS,
    TOTAL_METHOD_PARSE_FAILURE_WEIGHT,
    _band_for,
    classifier_confidence_component,
    compute_risk_score,
    ioc_component,
    obfuscation_component,
    opaque_reputation_floor,
)

A11Y_PERMISSION = "android.permission.BIND_ACCESSIBILITY_SERVICE"
SMS_PERMISSIONS = ["android.permission.READ_SMS", "android.permission.RECEIVE_SMS"]


def _obfuscation(**overrides) -> ObfuscationSignal:
    """An ObfuscationSignal shaped like the corpus average clean app."""
    fields = {
        "string_entropy_score": 3.18,   # corpus benign mean (was 3.28/220 apps); threshold is 7.2
        "flattening_suspected": True,   # true for 30/30 sampled clean apps
        "flattening_method_count": 9,
        "analyzed_method_count": 288,
        "flattening_method_ratio": 0.056,   # corpus benign median (was 0.031/220 apps)
        "dex_method_count": 26553,      # corpus benign median (was 25338/220 apps)
        "declared_component_count": 120,
        "method_parse_failure_rate": 0.0,
        "unresolved_reflection_targets": 0,
        "coverage_note": "test",
    }
    fields.update(overrides)
    return ObfuscationSignal(**fields)


# ─── N5: the accessibility gate reads the declaration, not the permission ────

class TestAccessibilityDeclarationGate(unittest.TestCase):

    def test_service_intent_action_declares_accessibility(self):
        self.assertTrue(
            declares_accessibility_service(
                permissions=[], intent_actions=[ACCESSIBILITY_SERVICE_ACTION]
            )
        )

    def test_uses_permission_still_declares_accessibility(self):
        """6 of 133 corpus malware did write it (7 of 318 now); must not regress."""
        self.assertTrue(
            declares_accessibility_service(
                permissions=[A11Y_PERMISSION], intent_actions=[]
            )
        )

    def test_neither_route_declared_is_false(self):
        self.assertFalse(
            declares_accessibility_service(
                permissions=["android.permission.INTERNET"],
                intent_actions=["android.intent.action.MAIN"],
            )
        )

    def test_forensic_dictionary_shares_the_action_constant(self):
        """One restated copy of the action string is one too many."""
        self.assertEqual(ACCESSIBILITY_INTENT_ACTIONS, [ACCESSIBILITY_SERVICE_ACTION])

    def test_matrix_rules_fire_off_the_service_declaration(self):
        """
        SMS_OTP_STEALER_PATTERN needs accessibility + SMS. Gated on the
        <uses-permission> it reached 6/133 malware; on the declaration, 75/133.
        Re-measured over 318 malware: 7 and 191 respectively.
        """
        with_action = detect_permission_matrix(
            SMS_PERMISSIONS, [ACCESSIBILITY_SERVICE_ACTION]
        )
        without = detect_permission_matrix(SMS_PERMISSIONS, [])
        self.assertIn("SMS_OTP_STEALER_PATTERN", with_action)
        self.assertNotIn("SMS_OTP_STEALER_PATTERN", without)

    def test_accessibility_full_control_needs_overlay_as_well(self):
        """The declaration enables the rule; it does not satisfy it on its own."""
        alone = detect_permission_matrix([], [ACCESSIBILITY_SERVICE_ACTION])
        with_overlay = detect_permission_matrix(
            ["android.permission.SYSTEM_ALERT_WINDOW"], [ACCESSIBILITY_SERVICE_ACTION]
        )
        self.assertNotIn("ACCESSIBILITY_FULL_CONTROL", alone)
        self.assertIn("ACCESSIBILITY_FULL_CONTROL", with_overlay)

    def test_intent_actions_are_optional_for_existing_callers(self):
        self.assertEqual(detect_permission_matrix(SMS_PERMISSIONS), [])

    def test_config_flags_map_onto_weighted_matrix_ids(self):
        """
        ingest_apk used to splice the *raw* config flags into
        permission_matrix_flags, where the scorer has no weight for them and fell
        back to its 0.6 default for unknowns. Only mapped IDs may reach it.
        """
        mapped = accessibility_matrix_flags([
            "accessibility_config:res/xml/service.xml",
            "canRetrieveWindowContent=true",
            "canPerformGestures=true",
            "keylogging_event_mask:typeAllMasks",
        ])
        self.assertEqual(
            sorted(mapped),
            ["ACCESSIBILITY_GESTURE_CONTROL", "ACCESSIBILITY_KEYLOGGING_MASK",
             "ACCESSIBILITY_WINDOW_CONTENT"],
        )
        for flag in mapped:
            self.assertIn(flag, MATRIX_FLAG_SEVERITY)

    def test_unremarkable_config_maps_to_no_matrix_flag(self):
        self.assertEqual(
            accessibility_matrix_flags([
                "accessibility_config:res/xml/service.xml",
                "accessibility_config_not_statically_resolved",
            ]),
            [],
        )


# ─── N6: self-signing is how Android works, and YARA breadth is not evidence ─

def _certificate(cn: str, org: str = "GuardGraph Test", issuer_cn: str | None = None,
                 not_before=None, not_after=None) -> bytes:
    """
    A parseable DER certificate. Only the fields analyze_certificate_anomalies reads
    are meaningful — it never verifies the signature — so asn1crypto alone suffices
    and the suite needs no `cryptography` dependency.
    """
    from asn1crypto import algos, core, keys, x509

    now = datetime.now(timezone.utc)
    tbs = x509.TbsCertificate({
        "version": "v3",
        "serial_number": 1,
        "signature": algos.SignedDigestAlgorithm({"algorithm": "sha256_rsa"}),
        "issuer": x509.Name.build(
            {"common_name": issuer_cn or cn, "organization_name": org}
        ),
        "validity": x509.Validity({
            "not_before": x509.Time(
                {"utc_time": not_before or now - timedelta(days=1)}
            ),
            "not_after": x509.Time(
                {"utc_time": not_after or now + timedelta(days=3650)}
            ),
        }),
        "subject": x509.Name.build(
            {"common_name": cn, "organization_name": org}
        ),
        "subject_public_key_info": keys.PublicKeyInfo({
            "algorithm": keys.PublicKeyAlgorithm(
                {"algorithm": "rsa", "parameters": core.Null()}
            ),
            "public_key": keys.RSAPublicKey(
                {"modulus": 0xDEADBEEF, "public_exponent": 65537}
            ),
        }),
    })
    return x509.Certificate({
        "tbs_certificate": tbs,
        "signature_algorithm": algos.SignedDigestAlgorithm({"algorithm": "sha256_rsa"}),
        "signature_value": b"\x00" * 32,
    }).dump()


class TestCertificateAnomalies(unittest.TestCase):

    def test_ordinary_self_signed_release_cert_is_not_an_anomaly(self):
        """
        The N6 regression. Android has no CA in its signing model, so subject ==
        issuer holds for essentially every APK; reporting it put a constant 0.15 into
        ioc_component for 27 of 30 sampled clean apps.
        """
        self.assertEqual(
            analyze_certificate_anomalies([_certificate("Example App Publisher")]), []
        )

    def test_self_signed_with_a_junk_dn_is_still_an_anomaly(self):
        anomalies = analyze_certificate_anomalies([_certificate("a", org="")])
        self.assertTrue(anomalies, "a one-character CN must still be flagged")

    def test_debug_key_is_still_an_anomaly(self):
        anomalies = analyze_certificate_anomalies([_certificate("Android Debug")])
        self.assertTrue(any(a.startswith("debug_or_test_key") for a in anomalies))

    def test_expired_certificate_is_still_an_anomaly(self):
        now = datetime.now(timezone.utc)
        anomalies = analyze_certificate_anomalies([_certificate(
            "Example App Publisher",
            not_before=now - timedelta(days=800),
            not_after=now - timedelta(days=400),
        )])
        self.assertTrue(any(a.startswith("expired") for a in anomalies))

    def test_missing_certificate_is_still_an_anomaly(self):
        self.assertIn("missing_certificate", analyze_certificate_anomalies([]))


class TestIocComponent(unittest.TestCase):

    def test_generic_yara_breadth_no_longer_saturates(self):
        """
        The measured clean-app shape: 11 community rules, max declared severity 0.85,
        nothing else. It used to score 0.765 of the 1.0 cap on that alone.
        """
        clean = ioc_component(0, yara_match_count=11, yara_max_severity=0.85)
        self.assertLess(clean, 0.35)

    def test_yara_match_count_does_not_multiply(self):
        """Rule-declared severity is metadata; matching more generic rules is not
        more evidence."""
        few = ioc_component(0, yara_match_count=3, yara_max_severity=0.85)
        many = ioc_component(0, yara_match_count=40, yara_max_severity=0.85)
        self.assertEqual(few, many)

    def test_circumstantial_evidence_alone_cannot_reach_the_cap(self):
        piled_on = ioc_component(
            matched_c2_indicators=5,
            yara_match_count=30,
            yara_max_severity=1.0,
            cert_anomaly_count=6,
            dropper_signal_count=9,
        )
        self.assertLessEqual(piled_on, 0.35 + 1e-9)

    def test_a_signature_hash_hit_still_dominates(self):
        self.assertGreaterEqual(ioc_component(0, signature_match_count=1), 0.5)

    def test_exact_extracted_iocs_still_carry_the_component(self):
        """A Telegram bot token or .onion address names *this* sample."""
        self.assertGreaterEqual(ioc_component(0, extracted_c2_count=2), 0.7)

    def test_malware_shape_outscores_clean_shape(self):
        clean = ioc_component(0, yara_match_count=11, yara_max_severity=0.85)
        malware = ioc_component(
            0, signature_match_count=1, yara_match_count=14, yara_max_severity=0.9,
            extracted_c2_count=1, cert_anomaly_count=1, secondary_dex_count=2,
            dropper_signal_count=1,
        )
        self.assertGreater(malware, clean * 3)


# ─── N7: the obfuscation component measures evasion, not app size ────────────

class TestObfuscationComponent(unittest.TestCase):

    def test_average_clean_app_scores_zero(self):
        """It used to score a constant 0.4 — 6.00 of 15 — for 216 of 220 clean apps.

        Still 0.0 for every one of the 298 clean apps scored on the expanded corpus.
        """
        self.assertEqual(obfuscation_component(_obfuscation()), 0.0)

    def test_flattening_prevalence_is_reported_but_not_scored(self):
        """
        Reading flattening as a prevalence rather than an existential does not rescue
        it: over the full corpus, benign p75 is 0.119 against malware's 0.118 (on the
        expanded corpus 0.125 against 0.112 — still no lift, and still the wrong way), and no
        threshold from 0.05 to 0.50 gives a lift outside 0.79-1.07.
        """
        rare = _obfuscation(flattening_method_ratio=1 / 300)
        widespread = _obfuscation(
            flattening_method_count=60, analyzed_method_count=200,
            flattening_method_ratio=0.30,
        )
        self.assertEqual(obfuscation_component(rare), 0.0)
        self.assertEqual(obfuscation_component(widespread), 0.0)

    def test_no_recoverable_code_is_the_strongest_signal(self):
        """
        The samples that defeated the analyser scored 0.0 here, because an empty CFG
        set has nothing that can look flattened — the component that exists to measure
        evasion read zero on exactly the apps it was meant to catch.
        """
        packed = _obfuscation(
            string_entropy_score=0.0, flattening_suspected=False,
            flattening_method_count=0, analyzed_method_count=0,
            flattening_method_ratio=0.0, dex_method_count=0,
            declared_component_count=70,
        )
        self.assertGreaterEqual(obfuscation_component(packed), 0.6)

    def test_a_dex_too_small_for_its_own_manifest_is_evasion(self):
        """
        A corpus sample declares 539 activities, 42 services and 49 receivers, and
        ships 57 methods. No Android app implements 630 components in 57 methods; the
        payload is decrypted at runtime.
        """
        stub = _obfuscation(
            analyzed_method_count=0, flattening_method_ratio=0.0,
            flattening_suspected=False, flattening_method_count=0,
            dex_method_count=57, declared_component_count=630,
        )
        self.assertGreaterEqual(obfuscation_component(stub), 0.6)

    def test_a_real_app_is_far_from_the_manifest_vs_code_floor(self):
        """The lowest ratio in the 299-app clean corpus is 56.85 methods per declared
        component, 28x above the floor."""
        real = _obfuscation(dex_method_count=25338, declared_component_count=120)
        self.assertEqual(obfuscation_component(real), 0.0)

    def test_unmeasured_method_count_is_not_treated_as_zero(self):
        """`None` is "we did not look", which must not earn an evasion penalty."""
        self.assertEqual(
            obfuscation_component(_obfuscation(dex_method_count=None)), 0.0
        )
        self.assertEqual(
            obfuscation_component(
                _obfuscation(dex_method_count=57, declared_component_count=None)
            ),
            0.0,
        )

    def test_relevance_filter_selecting_nothing_is_not_evasion(self):
        """A small clean app whose methods touch nothing in the forensic dictionary."""
        signal = _obfuscation(
            flattening_suspected=False, flattening_method_count=0,
            analyzed_method_count=0, flattening_method_ratio=0.0,
            dex_method_count=1444, declared_component_count=8,  # com.reteclock
        )
        self.assertEqual(obfuscation_component(signal), 0.0)

    def test_string_pool_entropy_no_longer_moves_the_score(self):
        """
        Mean per-string Shannon entropy cannot reach the 7.2 threshold (7.2 bits needs
        ~147 distinct characters per string; the corpus maximum is 3.47, and 3.86 on the
        expanded corpus), and it runs backwards: benign 3.28 against malware 2.78
        (3.18 against 2.68 re-measured). Tripling the corpus did not reverse it.
        """
        low = obfuscation_component(_obfuscation(string_entropy_score=0.5))
        high = obfuscation_component(_obfuscation(string_entropy_score=7.9))
        self.assertEqual(low, high)

    def test_parse_failure_rate_is_not_scored_at_all(self):
        """
        The parse-failure branch and its three constants (PARSE_FAILURE_MIN / _WEIGHT
        / _CAP) were deleted on 2026-08-21, not merely left unscored.

        `method_parse_failure_rate` measured 0.0 on all 353 samples of the original
        corpus and 0.0 on all 616 of the expanded one. A threshold, a multiplier and a
        cap governing a signal with zero observations across two corpora is surface
        area, not calibration. This test pins the removal: were the branch restored,
        a rate no corpus sample has ever produced would start moving live scores.
        """
        for rate in (0.02, 0.25, 0.9):
            self.assertEqual(
                obfuscation_component(_obfuscation(method_parse_failure_rate=rate)),
                0.0,
                f"parse-failure rate {rate} must not contribute to the score",
            )

    def test_manifest_parse_failure_is_scored_unlike_entropy_and_flattening(self):
        """
        Unlike every other input here, manifest_parse_failed doesn't need corpus
        measurement to justify a weight: a corrupted manifest has no plausible
        benign explanation, so it's scored directly (MANIFEST_CORRUPTED_WEIGHT).
        Found in practice: a MalwareBazaar/VirusTotal-confirmed sample scored
        22.47 "low" before this existed, because the same missing manifest data
        also starved permission/ttp/classifier components of their feature vector.
        """
        clean_score = obfuscation_component(_obfuscation())
        corrupted_score = obfuscation_component(_obfuscation(manifest_parse_failed=True))

        self.assertEqual(clean_score, 0.0)
        self.assertGreater(corrupted_score, clean_score)
        self.assertAlmostEqual(corrupted_score, 0.60, places=4)


# ─── N8 + bands ──────────────────────────────────────────────────────────────

class TestVerdictBands(unittest.TestCase):

    def test_boundaries_are_ordered(self):
        self.assertLess(BAND_LOW_CEILING, BAND_MEDIUM_CEILING)
        self.assertLess(BAND_MEDIUM_CEILING, BAND_SUSPICIOUS_CEILING)
        self.assertLess(BAND_SUSPICIOUS_CEILING, BAND_HIGH_CEILING)

    def test_each_band_is_reachable_and_inclusive_at_its_ceiling(self):
        self.assertEqual(_band_for(0.0), "low")
        self.assertEqual(_band_for(BAND_LOW_CEILING), "low")
        self.assertEqual(_band_for(BAND_LOW_CEILING + 0.01), "medium")
        self.assertEqual(_band_for(BAND_MEDIUM_CEILING), "medium")
        self.assertEqual(_band_for(BAND_MEDIUM_CEILING + 0.01), "suspicious")
        self.assertEqual(_band_for(BAND_SUSPICIOUS_CEILING), "suspicious")
        self.assertEqual(_band_for(BAND_SUSPICIOUS_CEILING + 0.01), "high")
        self.assertEqual(_band_for(BAND_HIGH_CEILING), "high")
        self.assertEqual(_band_for(BAND_HIGH_CEILING + 0.01), "malicious")
        self.assertEqual(_band_for(100.0), "malicious")

    def test_unparseable_score_still_reads_suspicious(self):
        """
        routes.UNPARSEABLE_RISK_SCORE exists to say "look at this by hand". If a band
        boundary ever moves past it, the fallback silently starts claiming a verdict
        about a file nothing was observed from.
        """
        from app.api.routes import UNPARSEABLE_RISK_SCORE

        self.assertEqual(_band_for(UNPARSEABLE_RISK_SCORE), "suspicious")

    def test_a_single_confident_technique_cannot_reach_the_high_band_alone(self):
        """
        `com.symeonchen.wakeupscreen` scored 62.67 / `high` with one predicted
        technique at 0.9828 and no forensic anchors: 24.57 of the 25-point classifier
        cap from a label whose calibrated boundary is 0.10.

        The 0.10 threshold is kept deliberately after the 2026-08-21 retrain moved
        T1516's calibrated boundary to 0.45. It is not a stale copy of the shipped
        model: a *lower* threshold means a larger margin for the same probability,
        so 0.10 is the harsher case this invariant has to survive. Reading the
        threshold from the model instead would weaken the test every time a retrain
        happened to raise it.
        """
        confidence = classifier_confidence_component(
            {"T1516": 0.9828}, ttp_thresholds={"T1516": 0.10}
        )
        self.assertLess(confidence * 25, BAND_SUSPICIOUS_CEILING)


if __name__ == "__main__":
    unittest.main()


# ─── Total static-parse failure: opacity is evidence, not absence of it ───────
# Before this existed, an APK that defeated the parser entirely had
# classifier_confidence (25), ttp_severity (15) and forensic_anchor (15) all read
# 0 together — 55 of 100 points structurally unreachable — while the component
# that exists to measure evasion paid the same 0.60 it pays a loader stub that at
# least shipped some code. Meanwhile reputation is capped at 5.0, so an externally
# damning verdict could not compensate. Found live: 02c08ec2…, 41/77 VirusTotal
# engines malicious, scored 29.8 `low`.

class TestTotalMethodParseFailure(unittest.TestCase):

    def _no_cfgs_normal_dex(self):
        """02c08ec2… as the corpus actually recorded it: 59 methods sitting in the
        DEX, zero CFGs recovered, and a manifest small enough that the
        methods-per-component ratio test does not fire either."""
        return _obfuscation(
            string_entropy_score=0.0, flattening_suspected=False,
            flattening_method_count=0, analyzed_method_count=0,
            flattening_method_ratio=0.0, dex_method_count=59,
            declared_component_count=8,
        )

    def test_zero_cfgs_scores_even_when_the_dex_is_not_empty(self):
        """The actual gap. This sample scored 0.0 here — the component that exists
        to measure evasion read nothing on a sample that defeated the analyser
        outright. Keyed on analyzed_method_count: a dex_method_count test misses it,
        because 59 methods are present and simply could not be parsed into graphs."""
        self.assertEqual(obfuscation_component(self._no_cfgs_normal_dex()),
                         TOTAL_METHOD_PARSE_FAILURE_WEIGHT)

    def test_nothing_recovered_at_all_saturates_the_component(self):
        """No methods necessarily means no CFGs, so that case takes both weights and
        saturates — the right answer for "we recovered literally nothing"."""
        nothing = _obfuscation(
            string_entropy_score=0.0, flattening_suspected=False,
            flattening_method_count=0, analyzed_method_count=0,
            flattening_method_ratio=0.0, dex_method_count=0,
            declared_component_count=70,
        )
        self.assertEqual(obfuscation_component(nothing), 1.0)
        self.assertGreater(
            obfuscation_component(nothing),
            obfuscation_component(self._no_cfgs_normal_dex()),
        )

    def test_an_analysed_app_is_never_charged_this_weight(self):
        """The gate is "no code was examined" — one recovered CFG is enough to be
        outside this signal entirely."""
        barely = _obfuscation(analyzed_method_count=1, dex_method_count=59,
                              declared_component_count=8)
        self.assertEqual(obfuscation_component(barely), 0.0)

    def test_relevance_filter_on_a_normal_sized_app_is_still_not_evasion(self):
        """The half that keeps this honest, and the reason the DEX-size test exists.
        com.reteclock recovers zero CFGs from 1444 methods — the pre-filter found
        nothing touching the forensic dictionary, which is not evidence of anything.
        The three clean corpus apps in this state carry 117, 184 and 1444 methods,
        all above OPAQUE_DEX_MAX_METHODS, so none of them is charged."""
        for dex_methods in (117, 184, 1444):
            signal = _obfuscation(
                flattening_suspected=False, flattening_method_count=0,
                analyzed_method_count=0, flattening_method_ratio=0.0,
                dex_method_count=dex_methods, declared_component_count=8,
            )
            self.assertEqual(obfuscation_component(signal), 0.0, dex_methods)

    def test_the_boundary_sits_in_the_measured_gap(self):
        """Malware with no recovered CFGs tops out at 61 methods on the 2026-08-25
        corpus and 87 on the 2026-08-24 one; the lowest clean app in that state is
        117 on both. The boundary must stay strictly inside that empty gap, and is
        pinned against the WIDER of the two malware maxima so a future corpus change
        cannot silently move it onto data."""
        self.assertGreater(OPAQUE_DEX_MAX_METHODS, 87)
        self.assertLess(OPAQUE_DEX_MAX_METHODS, 117)

    def test_unmeasured_dex_count_is_not_charged(self):
        """`None` means not measured, and must stay absence-of-evidence."""
        unmeasured = _obfuscation(dex_method_count=None, analyzed_method_count=0,
                                  declared_component_count=8)
        self.assertEqual(obfuscation_component(unmeasured), 0.0)

    def test_the_three_benign_corpus_rows_stay_low_even_if_charged(self):
        """Defence in depth: even if a small clean app did land in this signal, the
        weight cannot carry it out of `low` on its own — 2.12 -> 11.12, with 19
        points of headroom to the boundary."""
        benign_like = 2.12 + TOTAL_METHOD_PARSE_FAILURE_WEIGHT * 15
        self.assertEqual(_band_for(benign_like), "low")
        self.assertLess(benign_like, BAND_LOW_CEILING)


# ─── OPAQUE_REPUTATION_SCORE_FLOOR ───────────────────────────────────────────

class TestOpaqueReputationFloor(unittest.TestCase):

    def _opaque(self):
        """Shaped like 02c08ec2…: methods in the DEX, zero CFGs recovered."""
        return _obfuscation(
            string_entropy_score=0.0, flattening_suspected=False,
            flattening_method_count=0, analyzed_method_count=0,
            flattening_method_ratio=0.0, dex_method_count=59,
            declared_component_count=8,
        )

    def test_floor_lands_in_its_intended_band(self):
        """Pinned the same way the impersonation floors are: moving a band boundary
        must not silently demote this verdict. `suspicious`, deliberately not
        `high` — internal analysis contributed nothing, so the claim being made is
        "a human should look", not "this is malicious"."""
        floor = OPAQUE_REPUTATION_SCORE_FLOOR["known_malware_no_static_coverage"]
        self.assertEqual(_band_for(floor), "suspicious")

    def test_requires_both_halves_reputation_alone_is_not_enough(self):
        """A sample the analyser could read scores on its own evidence and needs no
        floor."""
        readable = _obfuscation()
        self.assertEqual(opaque_reputation_floor(True, readable), 0.0)

    def test_requires_both_halves_opacity_alone_is_not_enough(self):
        """THE false-positive guard. A benign app this parser simply fails on must
        never be raised by our own failure to read it."""
        self.assertEqual(opaque_reputation_floor(False, self._opaque()), 0.0)

    def test_fires_when_externally_flagged_and_unreadable(self):
        expected = OPAQUE_REPUTATION_SCORE_FLOOR["known_malware_no_static_coverage"]
        self.assertEqual(opaque_reputation_floor(True, self._opaque()), expected)

    def test_a_corrupt_manifest_counts_as_degraded_coverage_too(self):
        """Same situation for scoring: the feature vector the weighted components
        need was never produced."""
        corrupt = _obfuscation(manifest_parse_failed=True)
        expected = OPAQUE_REPUTATION_SCORE_FLOOR["known_malware_no_static_coverage"]
        self.assertEqual(opaque_reputation_floor(True, corrupt), expected)

    def test_end_to_end_the_live_sample_no_longer_reads_low(self):
        """The regression this whole change exists for: externally flagged AND
        unparseable used to land in `low`."""
        result = compute_risk_score(
            predicted_ttps={},
            permissions=["android.permission.INTERNET"],
            obfuscation=self._opaque(),
            entropy_threshold=7.2,
            classifier_evidence_present=False,   # nothing to classify — the real gate
            is_known_malware=True,
        )
        self.assertGreater(result.total_score, BAND_MEDIUM_CEILING)
        self.assertEqual(result.verdict_band, "suspicious")
        self.assertTrue(result.opaque_reputation_floor_applied)

    def test_floor_never_lowers_a_score_that_earned_more_on_its_own(self):
        """Floors raise, never cap — a sample that is both opaque AND independently
        damning keeps the higher arithmetic verdict, and the flag reads False so the
        report does not credit the floor for a score the evidence earned."""
        loud = compute_risk_score(
            predicted_ttps={},
            permissions=[
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
                "android.permission.READ_SMS",
                "android.permission.RECEIVE_SMS",
                "android.permission.SEND_SMS",
                "android.permission.SYSTEM_ALERT_WINDOW",
            ],
            obfuscation=self._opaque(),
            entropy_threshold=7.2,
            classifier_evidence_present=False,
            is_known_malware=True,
            matched_anchor_behaviors={"STEALTH_SMS_INTERCEPTION", "OTP_INTERCEPTION",
                                      "CREDENTIAL_HARVESTING"},
            permission_matrix_flags=["SMS_OTP_STEALER_PATTERN", "ACCESSIBILITY_FULL_CONTROL"],
            signature_match_count=3,
            matched_c2_indicators=4,
        )
        floor = OPAQUE_REPUTATION_SCORE_FLOOR["known_malware_no_static_coverage"]
        self.assertGreater(loud.weighted_score, floor)
        self.assertEqual(loud.total_score, loud.weighted_score)
        self.assertFalse(loud.opaque_reputation_floor_applied)

    def test_holdout_false_positive_stays_low(self):
        """The one never-trained clean app inside the boundary (player.efis.data.
        ant.spl, 60 methods, no CFGs, no permissions) is charged the weight and
        still cannot leave `low`. Pinned because it is the documented limit of how
        far this signal generalizes — see OPAQUE_DEX_MAX_METHODS."""
        after = 2.12 - 0.0 + TOTAL_METHOD_PARSE_FAILURE_WEIGHT * 15
        self.assertAlmostEqual(after, 11.12, places=2)
        self.assertEqual(_band_for(after), "low")

    # ── Regression: a weight that armed itself when its input stopped being a stub ──
    # UNRESOLVED_REFLECTION_WEIGHT was calibrated while the input always returned 0,
    # and was deliberately "wired so that implementing the taint pass turns it on".
    # The taint pass landed; the weight armed; nobody re-measured. It then paid
    # 1.50/15 to 88.2% of CLEAN corpus apps against 76.9% of malware — a constant
    # pointing the wrong way, the exact defect N7 removed three other inputs for.

    def test_unresolved_reflection_does_not_move_the_score(self):
        """Reported in the coverage note, never scored."""
        none_ = _obfuscation(unresolved_reflection_targets=0)
        many = _obfuscation(unresolved_reflection_targets=12)
        self.assertEqual(obfuscation_component(none_), obfuscation_component(many))
        self.assertEqual(obfuscation_component(many), 0.0)

    def test_a_normal_app_with_reflection_scores_zero_obfuscation(self):
        """The user-visible symptom: a healthy app showing '12 reflection call
        targets not statically resolved' rendered a constant 1.50/15 forever."""
        realistic = _obfuscation(dex_method_count=28241, declared_component_count=12,
                                 unresolved_reflection_targets=12, analyzed_method_count=288)
        self.assertEqual(obfuscation_component(realistic) * 15, 0.0)

    def test_the_real_signal_still_fires(self):
        """Removing the noise term must not touch CODE_NOT_RECOVERED, which is the
        only part of this component that discriminates (malware-only in the corpus)."""
        stub = _obfuscation(dex_method_count=57, declared_component_count=630,
                            unresolved_reflection_targets=12, analyzed_method_count=5)
        self.assertEqual(obfuscation_component(stub), CODE_NOT_RECOVERED_WEIGHT)
