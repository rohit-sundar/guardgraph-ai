"""
Turns recorded analyst feedback (app/graph/cache.py's record_feedback, via
POST /analyses/{sha256}/feedback) into training-ready rows appended to
data/ttp_dataset.csv, ready for `python scripts/train_model.py --target ttp`.

This is the SECOND half of the active-learning loop. The first half only
logs a correction against a sha256 — it does not retrain anything, and
neither does this script; retraining stays the existing deliberate, manual
`train_model.py` step. Running this script is itself a deliberate action a
human takes when they decide it's time to fold corrections in, not
something that happens automatically after a feedback POST.

Scope, deliberately narrow (this project's own YAGNI rule, see CLAUDE.md):

  * Only "false_positive" feedback produces a row. "confirmed" feedback
    means the analyst agrees with what was already predicted — there is
    nothing to correct, so nothing is written for it (reported as
    informational only). Building a full per-technique correction UI/schema
    was out of scope for what the feedback endpoint currently collects
    (a free-form verdict string, not per-label edits).
  * A false-positive correction is written as an all-zero TTP label row
    (label_source="analyst_feedback"), the same shape stage_c_benign()
    already produces for known-clean APKs in build_ttp_dataset.py — "this
    sample's evidence should not have implied any technique" is exactly
    what an all-zero row asserts.
  * Uploaded APKs are never retained past a single request (see
    app/api/routes.py's tmp_dir cleanup) — feedback on a sample whose file
    only ever existed as a one-off upload cannot be turned back into a
    feature row. This script only finds files still present in the curated
    corpora (data/ttp_apks/, data/benign_apks/) and says so explicitly,
    rather than silently dropping or guessing, for anything it can't find.

Usage:
    python scripts/export_feedback_for_training.py
    python scripts/export_feedback_for_training.py --search-dir data/ttp_apks --search-dir data/benign_apks
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from loguru import logger  # noqa: E402

from app.analysis.ingest import compute_sha256  # noqa: E402
from app.graph.cache import list_feedback_samples  # noqa: E402
from scripts.build_ttp_dataset import (  # noqa: E402
    extract_ttp_row, _row_dict, dataset_columns, IncrementalCsvWriter,
    OUT_CSV as TTP_DATA_PATH,
)

DEFAULT_SEARCH_DIRS = ["data/ttp_apks", "data/benign_apks"]


def _build_sha256_index(search_dirs: list[str]) -> dict[str, str]:
    """
    Hashes every .apk under search_dirs once and returns sha256 -> path.
    A full corpus hash on every run rather than trusting a cached manifest:
    this script runs rarely (a deliberate human action, not a hot path), and
    correctness against what's actually on disk right now matters more here
    than shaving a linear pass over a few hundred files.
    """
    index: dict[str, str] = {}
    for base_dir in search_dirs:
        if not os.path.isdir(base_dir):
            continue
        for root, _dirs, files in os.walk(base_dir):
            for name in files:
                if not name.lower().endswith(".apk"):
                    continue
                path = os.path.join(root, name)
                try:
                    index[compute_sha256(path)] = path
                except Exception as e:
                    logger.warning(f"[feedback-export] could not hash {path}: {e}")
    return index


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--search-dir", action="append", dest="search_dirs",
        help="Directory to search for the original APK (repeatable). "
             f"Default: {DEFAULT_SEARCH_DIRS}",
    )
    parser.add_argument("--out", default=TTP_DATA_PATH, help="Dataset CSV to append to.")
    args = parser.parse_args()
    search_dirs = args.search_dirs or DEFAULT_SEARCH_DIRS

    feedback = list_feedback_samples()
    if not feedback:
        logger.info("[feedback-export] no analyst feedback recorded — nothing to do.")
        return 0

    false_positives = [f for f in feedback if f.get("verdict") == "false_positive"]
    other = [f for f in feedback if f.get("verdict") != "false_positive"]
    for f in other:
        logger.info(
            f"[feedback-export] {f['sha256'][:12]} verdict={f.get('verdict')!r} — "
            "not a correction (only 'false_positive' feedback produces a training "
            "row; see this script's module docstring), skipping."
        )

    if not false_positives:
        logger.info("[feedback-export] no 'false_positive' feedback to export.")
        return 0

    logger.info(f"[feedback-export] indexing APKs under {search_dirs} ...")
    sha_index = _build_sha256_index(search_dirs)
    logger.info(f"[feedback-export] indexed {len(sha_index)} local APK(s).")

    written, unrecoverable = 0, []
    with IncrementalCsvWriter(args.out, dataset_columns(), overwrite=False) as writer:
        for f in false_positives:
            sha256 = f["sha256"]
            if writer.is_done(sha256):
                logger.info(f"[feedback-export] {sha256[:12]} already in {args.out}, skipping.")
                continue
            apk_path = sha_index.get(sha256.lower())
            if apk_path is None:
                unrecoverable.append(sha256)
                logger.warning(
                    f"[feedback-export] {sha256[:12]} (package={f.get('package_name')}): "
                    "correction recorded, but the original APK is not present under "
                    f"{search_dirs} — cannot regenerate a feature row. Re-upload the "
                    "sample to one of those directories and rerun this script."
                )
                continue

            result = extract_ttp_row(apk_path)
            if result is None:
                unrecoverable.append(sha256)
                logger.warning(f"[feedback-export] {sha256[:12]}: re-analysis failed, skipping.")
                continue
            vec, meta = result
            # All-zero label row: "this sample's evidence should not have implied
            # any technique" — the same shape stage_c_benign() writes for known-
            # clean APKs, applied here to a sample an analyst corrected.
            row = _row_dict(vec, techniques=set(), label_source="analyst_feedback",
                             sha256=meta["sha256"], source="analyst_correction")
            writer.write(row)
            written += 1
            logger.info(f"[feedback-export] {sha256[:12]}: wrote corrected row.")

    logger.info(
        f"[feedback-export] done — {written} row(s) appended to {args.out}, "
        f"{len(unrecoverable)} unrecoverable (file not found locally)."
    )
    if written:
        logger.info(
            "[feedback-export] run `python scripts/train_model.py --target ttp` "
            "to fold these into the trained model."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
