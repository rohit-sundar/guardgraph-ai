"""
Tests for manifest-corruption resilience: a deliberately corrupted
AndroidManifest.xml (junk bytes between AXML chunk headers — a known
anti-analysis technique) used to take down the ENTIRE analysis, because
apk.APK() parses the manifest as its first step and Androguard's own
byte-by-byte resync can fail outright. ingest_apk() now falls back to
manifest-independent DEX/CFG extraction instead of losing all coverage.
"""
import os
import struct
import sys
import zlib
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.analysis.obfuscation import build_obfuscation_signal
from app.analysis.ingest import _raw_scan_dex_from_corrupted_zip


def _build_local_header(name: bytes, method: int, gp_flags: int, comp_size: int, uncomp_size: int) -> bytes:
    return b"PK\x03\x04" + struct.pack(
        "<HHHHHIIIHH", 20, gp_flags, method, 0, 0, 0, comp_size, uncomp_size, len(name), 0
    ) + name


def _deflate_streaming_entry(name: str, payload: bytes) -> bytes:
    """A local file header + deflate data with the streaming data-descriptor flag
    set and sizes zeroed — the shape confirmed on this project's own real corpus."""
    co = zlib.compressobj(9, zlib.DEFLATED, -15)
    compressed = co.compress(payload) + co.flush()
    header = _build_local_header(name.encode(), method=8, gp_flags=0x08, comp_size=0, uncomp_size=0)
    # Trailing junk after the compressed stream simulates the data descriptor +
    # whatever comes next — the recovery must stop exactly at the deflate EOF,
    # not read into this.
    return header + compressed + b"JUNK_AFTER_STREAM_DATA_DESCRIPTOR_ETC"


def _stored_entry(name: str, payload: bytes) -> bytes:
    header = _build_local_header(name.encode(), method=0, gp_flags=0, comp_size=len(payload), uncomp_size=len(payload))
    return header + payload


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


def test_raw_scan_recovers_streaming_deflate_dex():
    """
    The shape confirmed empirically against a real sample in this project's
    corpus: classes.dex written with the streaming data-descriptor flag set
    (local header sizes zeroed). zipfile.ZipFile() refuses such archives
    outright if the central directory is also damaged; the raw scan must
    still recover the exact original bytes by relying on deflate's own
    self-terminating structure, not on the (absent) size fields.
    """
    payload = b"dex\n035\x00" + bytes(range(256)) * 20  # stand-in DEX-shaped bytes
    blob = _deflate_streaming_entry("classes.dex", payload)

    recovered = _raw_scan_dex_from_corrupted_zip(blob)

    assert recovered.get("classes.dex") == payload


def test_raw_scan_recovers_stored_non_streaming_dex():
    payload = b"dex\n035\x00" + b"stored-not-compressed" * 10
    blob = _stored_entry("classes2.dex", payload)

    recovered = _raw_scan_dex_from_corrupted_zip(blob)

    assert recovered.get("classes2.dex") == payload


def test_raw_scan_skips_non_dex_entries():
    payload = b"irrelevant asset bytes"
    blob = _stored_entry("assets/some_asset.bin", payload)

    recovered = _raw_scan_dex_from_corrupted_zip(blob)

    assert recovered == {}


def test_raw_scan_finds_dex_after_other_entries():
    """The scan must not stop at (or get confused by) an earlier, unrelated
    entry — a realistic APK has many files before classes.dex in byte order."""
    asset = _stored_entry("resources.arsc", b"fake-resource-table-bytes")
    payload = b"dex\n035\x00real dex payload bytes here"
    dex_entry = _deflate_streaming_entry("classes.dex", payload)

    recovered = _raw_scan_dex_from_corrupted_zip(asset + dex_entry)

    assert recovered.get("classes.dex") == payload
    assert "resources.arsc" not in recovered


def test_fallback_dex_analysis_uses_raw_scan_when_zipfile_itself_cannot_open():
    """
    End-to-end within _fallback_dex_analysis: a corrupted-EOCD blob that
    zipfile.ZipFile() refuses to open at all (not just an AXML failure) must
    still reach dex.DEX() construction via the raw local-header scan.
    dex.DEX itself is mocked here since building bytes that satisfy both the
    ZIP local-header format AND the full DEX format in one fixture isn't
    worth the complexity — the raw-scan extraction (the actual thing this
    test exists to check) runs for real; only the DEX *parse* is stubbed.
    """
    payload = b"dex\n035\x00" + bytes(range(256)) * 40
    blob = _deflate_streaming_entry("classes.dex", payload)
    import tempfile
    fd, path = tempfile.mkstemp(suffix=".apk")
    with os.fdopen(fd, "wb") as f:
        f.write(blob)

    try:
        import zipfile
        try:
            zipfile.ZipFile(path)
            assert False, "test fixture is invalid — zipfile opened it fine"
        except zipfile.BadZipFile:
            pass

        fake_df = MagicMock()
        with patch("app.analysis.ingest.dex.DEX", return_value=fake_df) as mock_dex_ctor, \
             patch("app.analysis.ingest.Analysis") as mock_analysis_cls:
            mock_analysis_cls.return_value = MagicMock()
            from app.analysis.ingest import _fallback_dex_analysis
            dfs, dx = _fallback_dex_analysis(path)

        assert dfs is not None
        assert dx is not None
        # The raw scan must have handed dex.DEX() the exact recovered payload.
        mock_dex_ctor.assert_called_once_with(payload)
    finally:
        os.remove(path)


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
