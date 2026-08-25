"""
Tests for scripts/export_feedback_for_training.py — the second half of the
active-learning loop (turning recorded analyst feedback into a training-
ready CSV row). No live Neo4j or APK analysis needed: list_feedback_samples
and extract_ttp_row are mocked, exercising this script's own scoping logic
(false_positive-only, unrecoverable-file handling) in isolation.
"""
import csv
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.ml.features import TTP_FEATURE_NAMES
from app.ml.labels import TTP_LABELS
from scripts import export_feedback_for_training as export_mod


class TestBuildSha256Index(unittest.TestCase):
    def test_indexes_real_apk_files_by_hash(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            apk_path = os.path.join(tmp_dir, "sample.apk")
            with open(apk_path, "wb") as f:
                f.write(b"fake apk bytes for hashing")
            from app.analysis.ingest import compute_sha256
            expected = compute_sha256(apk_path)

            index = export_mod._build_sha256_index([tmp_dir])
            self.assertEqual(index.get(expected), apk_path)

    def test_missing_directory_is_skipped_not_an_error(self):
        index = export_mod._build_sha256_index(["/no/such/directory/here"])
        self.assertEqual(index, {})


class TestMainScoping(unittest.TestCase):
    """Only 'false_positive' feedback produces a row; 'confirmed' does not."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.out_csv = os.path.join(self.tmp_dir, "ttp_dataset.csv")
        self.fake_vec = [0.0] * len(TTP_FEATURE_NAMES)

    def _run_main(self, feedback, sha_index):
        argv = ["export_feedback_for_training.py", "--out", self.out_csv]
        with patch.object(export_mod, "list_feedback_samples", return_value=feedback), \
             patch.object(export_mod, "_build_sha256_index", return_value=sha_index), \
             patch.object(export_mod, "extract_ttp_row",
                           return_value=(self.fake_vec, {"sha256": feedback[0]["sha256"] if feedback else ""})), \
             patch.object(sys, "argv", argv):
            return export_mod.main()

    def test_false_positive_with_locally_present_apk_writes_all_zero_row(self):
        sha = "aa" * 32
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            apk_path = f.name
        try:
            rc = self._run_main(
                feedback=[{"sha256": sha, "verdict": "false_positive", "package_name": "com.evil"}],
                sha_index={sha.lower(): apk_path},
            )
            self.assertEqual(rc, 0)
            with open(self.out_csv, newline="", encoding="utf-8") as fh:
                rows = list(csv.DictReader(fh))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["sha256"], sha)
            self.assertEqual(rows[0]["label_source"], "analyst_feedback")
            for technique in TTP_LABELS:
                self.assertEqual(rows[0][technique], "0")
        finally:
            os.unlink(apk_path)

    def _row_count(self) -> int:
        """IncrementalCsvWriter always writes a header on open (even with zero
        data rows) — this counts only data rows, which is what "nothing
        written" actually means for this script."""
        if not os.path.exists(self.out_csv):
            return 0
        with open(self.out_csv, newline="", encoding="utf-8") as fh:
            return len(list(csv.DictReader(fh)))

    def test_confirmed_feedback_writes_nothing(self):
        sha = "bb" * 32
        rc = self._run_main(
            feedback=[{"sha256": sha, "verdict": "confirmed", "package_name": "com.evil"}],
            sha_index={},
        )
        self.assertEqual(rc, 0)
        self.assertEqual(self._row_count(), 0)

    def test_false_positive_with_no_local_apk_writes_nothing(self):
        sha = "cc" * 32
        rc = self._run_main(
            feedback=[{"sha256": sha, "verdict": "false_positive", "package_name": "com.evil"}],
            sha_index={},  # not found locally
        )
        self.assertEqual(rc, 0)
        self.assertEqual(self._row_count(), 0)

    def test_no_feedback_at_all_is_a_clean_noop(self):
        rc = self._run_main(feedback=[], sha_index={})
        self.assertEqual(rc, 0)
        self.assertEqual(self._row_count(), 0)


if __name__ == "__main__":
    unittest.main()
