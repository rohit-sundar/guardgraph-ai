"""
Unit tests for signature matching (local & online) and YARA rule scanning.
"""
import sys
import os
import json
import tempfile
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.analysis.signatures import match_signatures, reset_signature_db
from app.analysis.yara_engine import compile_rules, scan_bytes, reset_compiled_rules, YARA_AVAILABLE
from app.ml.features import build_feature_vector, FEATURE_NAMES
from app.reports.scoring import compute_risk_score
from app.core.schemas import ObfuscationSignal


def test_local_signature_matching():
    # Setup mock local signature database
    mock_db = {
        "hashes": {
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {
                "family": "test_trojan",
                "severity": 0.9,
                "source": "test_feed",
                "description": "Mock test trojan"
            }
        },
        "certificates": {
            "aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44ee": {
                "family": "test_signer",
                "severity": 0.8,
                "source": "test_cert_feed",
                "description": "Mock test signer"
            }
        }
    }

    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as tmp:
        json.dump(mock_db, tmp)
        tmp_name = tmp.name

    try:
        reset_signature_db()

        # Disable online keys to ensure no real API calls are made
        with patch("app.core.config.settings.virustotal_api_key", ""), \
             patch("app.core.config.settings.malwarebazaar_api_key", ""):
            
            # Test hash matching
            matches = match_signatures(
                sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                cert_thumbprint=None,
                db_path=tmp_name
            )
            assert len(matches) == 1
            assert matches[0]["family"] == "test_trojan"
            assert matches[0]["severity"] == 0.9
            assert matches[0]["source"] == "test_feed"

            # Test cert matching
            matches_cert = match_signatures(
                sha256="unknown_hash",
                cert_thumbprint="aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44ee",
                db_path=tmp_name
            )
            assert len(matches_cert) == 1
            assert matches_cert[0]["family"] == "test_signer"
            assert matches_cert[0]["severity"] == 0.8
            assert matches_cert[0]["source"] == "test_cert_feed"

            # Test no match
            matches_none = match_signatures(
                sha256="unknown_hash",
                cert_thumbprint="unknown_cert",
                db_path=tmp_name
            )
            assert len(matches_none) == 0

    finally:
        os.unlink(tmp_name)
        reset_signature_db()


@patch("urllib.request.urlopen")
def test_online_signature_matching_vt(mock_urlopen):
    # Mock VirusTotal 200 OK response
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.read.return_value = json.dumps({
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 8, "undetected": 50},
                "popular_threat_classification": {"suggested_threat_label": "trojan.anubis"}
            }
        }
    }).encode("utf-8")
    mock_response.__enter__.return_value = mock_response
    mock_urlopen.return_value = mock_response

    # Local DB is empty, should fall back to VirusTotal
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as tmp:
        json.dump({"hashes": {}, "certificates": {}}, tmp)
        tmp_name = tmp.name

    try:
        reset_signature_db()
        # Patch settings to enable VT and disable MalwareBazaar
        with patch("app.core.config.settings.virustotal_api_key", "mock_vt_key"), \
             patch("app.core.config.settings.malwarebazaar_api_key", ""):
            
            matches = match_signatures(
                sha256="c445bb2e86e7812e02de27919cd3a65a56d49f892b9ebf2b16acc66aeda9992e",
                cert_thumbprint=None,
                db_path=tmp_name
            )
            assert len(matches) == 1
            assert matches[0]["family"] == "trojan.anubis"
            assert matches[0]["source"] == "VirusTotal"
            assert matches[0]["severity"] > 0.5
    finally:
        os.unlink(tmp_name)
        reset_signature_db()


@patch("urllib.request.urlopen")
def test_online_signature_matching_mb(mock_urlopen):
    # Mock MalwareBazaar 200 OK response
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.read.return_value = json.dumps({
        "query_status": "ok",
        "data": [{
            "signature": "cerberus",
            "intelligence": {"clamav": "Unix.Malware.Cerberus"},
            "tags": ["banking", "apk"]
        }]
    }).encode("utf-8")
    mock_response.__enter__.return_value = mock_response
    mock_urlopen.return_value = mock_response

    # Local DB is empty, should fall back to MalwareBazaar
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as tmp:
        json.dump({"hashes": {}, "certificates": {}}, tmp)
        tmp_name = tmp.name

    try:
        reset_signature_db()
        # Patch settings to enable MalwareBazaar and disable VT
        with patch("app.core.config.settings.malwarebazaar_api_key", "mock_mb_key"), \
             patch("app.core.config.settings.virustotal_api_key", ""):
            
            matches = match_signatures(
                sha256="29ae866ee972f189ee1181f0e229033ac0e7a43038474fc5",
                cert_thumbprint=None,
                db_path=tmp_name
            )
            assert len(matches) == 1
            assert matches[0]["family"] == "cerberus"
            assert matches[0]["source"] == "MalwareBazaar"
    finally:
        os.unlink(tmp_name)
        reset_signature_db()


def test_yara_rule_scanning():
    if not YARA_AVAILABLE:
        print("Skipping YARA scan test: yara-python not installed.")
        return

    reset_compiled_rules()

    # Scan bytes for botId (triggers AndroidBankingTrojan_C2Patterns)
    sample_bytes = b"Some prefix text here with botId = 12345 gate.php"
    matches = scan_bytes(sample_bytes)
    assert len(matches) >= 1
    assert any(m["rule_name"] == "AndroidBankingTrojan_C2Patterns" for m in matches)
    assert any(m["severity"] == 0.8 for m in matches)

    # Scan clean bytes
    clean_bytes = b"This is a completely normal string without suspicious keywords."
    clean_matches = scan_bytes(clean_bytes)
    assert len(clean_matches) == 0


def test_feature_vector_35_features():
    # Verify that the vector length matches the expanded 35 features
    assert len(FEATURE_NAMES) == 35
    vec = build_feature_vector(
        permissions=["android.permission.READ_SMS"],
        matched_behaviors={"OTP_INTERCEPTION"},
        topological_invariants={},
        obfuscation_entropy=6.5,
        obfuscation_flattening=False,
        obfuscation_reflection_count=2,
        signature_match_count=1,
        yara_rule_match_count=2,
        yara_max_severity=0.85
    )
    assert len(vec) == 35
    # Check that signature/YARA features are at the tail of the vector
    assert vec[-3] == 1.0  # signature_match_count
    assert vec[-2] == 2.0  # yara_rule_match_count
    assert vec[-1] == 0.85 # yara_max_severity


def test_risk_scoring_with_signatures_and_yara():
    obf = ObfuscationSignal(
        string_entropy_score=5.5,
        flattening_suspected=False,
        coverage_note="no gaps"
    )

    # Base score (no sig/YARA)
    score_clean = compute_risk_score(
        predicted_ttps={},
        permissions=[],
        obfuscation=obf,
        entropy_threshold=7.2,
        matched_anchor_behaviors=set(),
        cache_hit=False,
        cached_score=None,
        matched_c2_indicators=0
    )

    # Score with a known-malware signature match
    score_sig = compute_risk_score(
        predicted_ttps={},
        permissions=[],
        obfuscation=obf,
        entropy_threshold=7.2,
        matched_anchor_behaviors=set(),
        cache_hit=False,
        cached_score=None,
        matched_c2_indicators=0,
        signature_match_count=1,
        is_known_malware=True
    )

    # Score with YARA matches
    score_yara = compute_risk_score(
        predicted_ttps={},
        permissions=[],
        obfuscation=obf,
        entropy_threshold=7.2,
        matched_anchor_behaviors=set(),
        cache_hit=False,
        cached_score=None,
        matched_c2_indicators=0,
        yara_match_count=2,
        yara_max_severity=0.9
    )

    # Known-malware signature match should raise the reputation component and ioc component
    assert score_sig.total_score > score_clean.total_score
    assert score_sig.reputation_component > score_clean.reputation_component
    assert score_sig.ioc_component > score_clean.ioc_component

    # YARA matches should raise the ioc component
    assert score_yara.total_score > score_clean.total_score
    assert score_yara.ioc_component > score_clean.ioc_component


if __name__ == "__main__":
    test_local_signature_matching()
    test_online_signature_matching_vt()
    test_online_signature_matching_mb()
    test_yara_rule_scanning()
    test_feature_vector_33_features()
    test_risk_scoring_with_signatures_and_yara()
    print("All signature/YARA tests passed successfully!")
