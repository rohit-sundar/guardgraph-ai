"""
Tests for manifest-corruption resilience: a deliberately corrupted
AndroidManifest.xml (junk bytes between AXML chunk headers — a known
anti-analysis technique) used to take down the ENTIRE analysis, because
apk.APK() parses the manifest as its first step and Androguard's own
byte-by-byte resync can fail outright. ingest_apk() now falls back to
manifest-independent DEX/CFG extraction instead of losing all coverage.
"""
import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.analysis.obfuscation import build_obfuscation_signal


def test_ingest_apk_falls_back_when_manifest_parsing_raises():
    """
    AnalyzeAPK raising (the real-world IndexError from axml._fix_name on a
    corrupted manifest) must not propagate — ingest_apk should recover via
    the manifest-independent DEX fallback and return a degraded-but-real
    IngestionResult instead of failing the whole sample.
    """
    fake_method = MagicMock()
    fake_analysis = MagicMock()
    fake_analysis.get_methods.return_value = [fake_method] * 42

    with patch("app.analysis.ingest.AnalyzeAPK", side_effect=IndexError("string index out of range")), \
         patch("app.analysis.ingest._fallback_dex_analysis", return_value=([MagicMock()], fake_analysis)), \
         patch("app.analysis.ingest.inspect_apk_payloads", return_value={
             "secondary_dex_count": 0, "yara_targets": [], "asset_strings": [],
             "payload_assets": [], "dropper_signals": [],
         }), \
         patch("app.analysis.ingest.compute_sha256", return_value="a" * 64):
        from app.analysis.ingest import ingest_apk
        result, apk_obj, dvm, analysis, yara_targets = ingest_apk("/fake/corrupted.apk")

    assert result.manifest_parse_failed is True
    assert result.permissions == []
    assert result.activities == []
    assert result.cert_thumbprint is None
    assert result.package_name is None
    # The whole point: DEX-level data survives even though the manifest didn't.
    assert result.dex_method_count == 42
    assert apk_obj is None
    assert analysis is fake_analysis


def test_ingest_apk_reraises_when_fallback_also_fails():
    """If even the raw-ZIP DEX read fails, there is truly nothing to analyze —
    must re-raise so the caller's existing unparseable-sample handling fires,
    same behavior as before this fallback existed."""
    with patch("app.analysis.ingest.AnalyzeAPK", side_effect=IndexError("boom")), \
         patch("app.analysis.ingest._fallback_dex_analysis", return_value=(None, None)), \
         patch("app.analysis.ingest.compute_sha256", return_value="b" * 64):
        from app.analysis.ingest import ingest_apk
        try:
            ingest_apk("/fake/totally_broken.apk")
            assert False, "expected an exception to propagate"
        except IndexError:
            pass


def test_manifest_parse_failure_surfaces_in_coverage_note():
    obfuscation = build_obfuscation_signal(
        all_strings=[],
        cfgs={},
        entropy_threshold=7.2,
        flattening_zscore=3.0,
        dex_method_count=42,
        declared_component_count=0,
        manifest_parse_failed=True,
    )
    assert "AndroidManifest.xml failed to parse" in obfuscation.coverage_note


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
