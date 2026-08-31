"""
Resource limits on attacker-controlled input.

/analyze is unauthenticated and its input is hostile by definition, so the two
places where a sample chooses how much memory the server spends are bounded:

  1. The upload itself — a body streamed to disk under a hard byte ceiling
     instead of `await file.read()` into memory.
  2. The raw-ZIP DEX recovery path — a deflate stream from a deliberately
     malformed archive, inflated under a cap rather than to completion.

Both are tested at the boundary: a request just inside the limit must still be
analyzed, one past it must be refused.
"""
import io
import os
import struct
import sys
import unittest
import zlib
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi.testclient import TestClient

from app.analysis.ingest import (
    MAX_RECOVERED_DEX_BYTES,
    _raw_scan_dex_from_corrupted_zip,
)
from app.api.routes import MAX_UPLOAD_BYTES
from app.main import app


def _local_header_entry(name: bytes, payload: bytes) -> bytes:
    """
    A ZIP local file header plus deflated payload, with the sizes zeroed the way
    a streaming (data-descriptor) entry writes them. No central directory — this
    is the corrupted-archive shape the raw scanner exists for.
    """
    compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
    blob = compressor.compress(payload) + compressor.flush()
    header = struct.pack(
        "<IHHHHHIIIHH",
        0x04034B50, 20, 0x08, 8, 0, 0, 0, 0, 0, len(name), 0,
    )
    return header + name + blob


def _stub_report():
    """Minimal well-formed AnalysisReport — the endpoint validates its response."""
    from app.core.coverage import unparseable_coverage
    from app.core.schemas import (
        AnalysisManifest,
        AnalysisReport,
        ObfuscationSignal,
        RiskScoreBreakdown,
    )

    return AnalysisReport(
        manifest=AnalysisManifest(
            target_package="com.example",
            sha256="aa" * 32,
            cache_hit=False,
            total_nodes_parsed=0,
            graph_density=0.0,
            behavioral_subgraphs=[],
            obfuscation=ObfuscationSignal(
                string_entropy_score=0.0,
                flattening_suspected=False,
                coverage_note="",
            ),
            predicted_ttps={},
            predicted_family=None,
            family_confidence=None,
        ),
        risk_score=RiskScoreBreakdown(total_score=0.0, verdict_band="low"),
        coverage=unparseable_coverage("stub report — nothing was analysed"),
        narrative_report="",
        limitations=[],
    )


class TestUploadSizeLimit(unittest.TestCase):
    """The upload ceiling must reject oversized bodies without analyzing them."""

    def setUp(self):
        self.client = TestClient(app)

    def test_upload_over_limit_is_refused_with_413(self):
        oversized = b"\x00" * (MAX_UPLOAD_BYTES + 1)

        with patch("app.api.routes._run_analysis") as run:
            response = self.client.post(
                "/analyze",
                files={"file": ("big.apk", io.BytesIO(oversized), "application/vnd.android.package-archive")},
            )

        self.assertEqual(response.status_code, 413)
        # Refused before any parsing: the point of the cap is not to spend the
        # work, not merely to report a different status afterwards.
        run.assert_not_called()

    def test_upload_within_limit_is_analyzed(self):
        small = b"PK\x03\x04" + b"\x00" * 64

        with patch("app.api.routes._run_analysis") as run:
            run.return_value = _stub_report()
            response = self.client.post(
                "/analyze",
                files={"file": ("small.apk", io.BytesIO(small), "application/vnd.android.package-archive")},
            )

        self.assertEqual(response.status_code, 200)
        run.assert_called_once()

    def test_non_apk_extension_still_refused_first(self):
        response = self.client.post(
            "/analyze",
            files={"file": ("payload.txt", io.BytesIO(b"x"), "text/plain")},
        )
        self.assertEqual(response.status_code, 400)


class TestRawScanDecompressionLimit(unittest.TestCase):
    """
    The raw scanner inflates a stream whose declared sizes cannot be trusted.
    A normal DEX must still be recovered; a zip bomb must not be inflated whole.
    """

    def test_recovers_a_normal_streaming_dex(self):
        payload = b"dex\n035\x00" + b"A" * 4096
        data = _local_header_entry(b"classes.dex", payload)

        recovered = _raw_scan_dex_from_corrupted_zip(data)

        self.assertIn("classes.dex", recovered)
        self.assertEqual(recovered["classes.dex"], payload)

    def test_oversized_entry_is_skipped_not_inflated(self):
        # Highly compressible, so the archive stays small while the inflated
        # output would run past the cap — the shape of a decompression bomb.
        payload = b"\x00" * (MAX_RECOVERED_DEX_BYTES + 1024)
        data = _local_header_entry(b"classes.dex", payload)
        self.assertLess(len(data), 1024 * 1024, "fixture should be small compressed")

        recovered = _raw_scan_dex_from_corrupted_zip(data)

        self.assertEqual(recovered, {})


if __name__ == "__main__":
    unittest.main()
