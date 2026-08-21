"""
Download a known-clean Android corpus from F-Droid for Stage C of the TTP dataset.

Stage C needs the negative class the TTP model spent its first life without. With
zero benign rows every label's `scale_pos_weight` is degenerate and the empirical
prior for every technique is "present", so Binary Relevance correctly learns to
always fire — an all-zero 181-feature vector used to predict 11 techniques above
0.5. Clean APKs are the minimum change that lets the existing trainer produce a
valid model; they are what the zero-vector sanity gate in scripts/train_model.py
is waiting for.

    Why F-Droid. Every app in the repo is built from source by F-Droid's own
    infrastructure, and the index publishes a SHA-256 per APK, so provenance is
    auditable end to end — which matters more for a "known-clean" label than raw
    sample count does. This script verifies that hash on every download; a file
    that does not match is discarded rather than labelled benign.

    What this corpus is NOT. F-Droid apps are open-source utilities, while the
    malware corpus is largely repackaged commercial apps. A classifier separating
    those two populations may be learning "F-Droid-ness" — no ad SDKs, fewer
    third-party libraries, smaller permission sets — rather than benign-ness. The
    defensible claim is "trained against a clean open-source baseline", not
    "validated against real-world benign apps". Mixing in commercial-but-clean
    samples (APKPure top free, or AndroZoo filtered to vt_detection=0) is the
    recommended follow-up before any external presentation.

Selection is seeded, so the same --seed and --count reproduce the same corpus.
Files already on disk are skipped, making reruns cheap and interruptions harmless.

    Holdout. --holdout-count N routes the last N apps of the selection, ordered by
    package name, to --holdout-dir instead of --out-dir. It is a split of one seeded
    selection, not a second draw, so `--count 110 --holdout-count 30` always yields
    the same 80/30 partition and never downloads an app twice.

    The holdout exists to answer "are the verdict bands real, or fitted to the apps
    the model saw?", and it can only answer that if it stays out of training. It gets
    its own DIRECTORY rather than a marker file because `--benign-dir` globs *.apk
    with no exclusion mechanism: co-located, the next Stage C run would train on it
    silently, with no error, and the calibration evidence would quietly become
    circular. Nothing in code enforces the rule — this separation is the enforcement.

Usage:
    python scripts/download_benign_apks.py                      # 220 apps -> data/benign_apks/
    python scripts/download_benign_apks.py --count 300          # a larger corpus
    python scripts/download_benign_apks.py --count 110 --holdout-count 30
    python scripts/download_benign_apks.py --dry-run            # resolve + report, fetch nothing
    python scripts/download_benign_apks.py --verify-existing    # re-hash what is already on disk

Then build the negatives and retrain — note that only --out-dir is passed to Stage C:
    python scripts/build_ttp_dataset.py --stage c --benign-dir data/benign_apks
    python scripts/train_model.py --target ttp
"""
import argparse
import hashlib
import json
import os
import random
import sys
import threading
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from loguru import logger  # noqa: E402

DEFAULT_REPO_URL = "https://f-droid.org/repo"
DEFAULT_OUT_DIR = "data/benign_apks"
DEFAULT_HOLDOUT_DIR = "data/benign_holdout"
# index-v1.json is ~58 MB and ships inside a signed JAR (index-v1.jar). The plain
# .json is served alongside it and is what we read; we are not verifying the repo
# signature here, only each APK's published SHA-256.
INDEX_NAME = "index-v1.json"

# Size window. Below the floor are stub/launcher apps with almost no code, which
# produce near-empty feature vectors and teach the model nothing; above the ceiling
# analysis time per sample stops being worth the row.
DEFAULT_MIN_BYTES = 150 * 1024
DEFAULT_MAX_BYTES = 12 * 1024 * 1024


def fetch_index(repo_url: str, cache_path: str | None) -> dict:
    """
    Load the F-Droid package index, using `cache_path` if it already holds a copy.

    Caching matters more than it looks: the index is ~58 MB, and a rerun to top up
    an interrupted corpus should not re-download it.
    """
    if cache_path and os.path.exists(cache_path) and os.path.getsize(cache_path) > 0:
        logger.info(f"[benign] using cached index {cache_path}")
        with open(cache_path, "r", encoding="utf-8") as f:
            return json.load(f)

    url = f"{repo_url.rstrip('/')}/{INDEX_NAME}"
    logger.info(f"[benign] fetching index {url} (~58 MB, this takes a moment)")
    with urllib.request.urlopen(url, timeout=180) as resp:
        raw = resp.read()
    logger.info(f"[benign] index downloaded: {len(raw) / 1e6:.1f} MB")

    if cache_path:
        os.makedirs(os.path.dirname(cache_path) or ".", exist_ok=True)
        with open(cache_path, "wb") as f:
            f.write(raw)
        logger.info(f"[benign] cached index -> {cache_path}")
    return json.loads(raw.decode("utf-8"))


def select_candidates(index: dict, min_bytes: int, max_bytes: int) -> list[dict]:
    """
    Reduce the index to one downloadable entry per package, inside the size window.

    F-Droid lists a package's builds newest-first, so entry [0] is the current
    release. Entries without a published sha256 are dropped: an unverifiable file
    has no place in a corpus whose entire value is that it is known-clean.
    """
    packages = index.get("packages", {})
    candidates: list[dict] = []

    for package_name, builds in packages.items():
        if not builds:
            continue
        build = builds[0]
        size = build.get("size") or 0
        if not (min_bytes <= size <= max_bytes):
            continue
        if str(build.get("hashType", "")).lower() != "sha256" or not build.get("hash"):
            continue
        apk_name = build.get("apkName")
        if not apk_name:
            continue
        candidates.append({
            "package": package_name,
            "apk_name": apk_name,
            "sha256": build["hash"].lower(),
            "size": size,
        })

    # Sort before sampling: dict iteration order follows the index file, which
    # changes as F-Droid publishes. Sorting makes --seed actually reproducible.
    candidates.sort(key=lambda c: c["package"])
    logger.info(
        f"[benign] {len(packages)} packages in index, {len(candidates)} inside the "
        f"{min_bytes / 1024:.0f} KiB - {max_bytes / (1024 * 1024):.0f} MiB window"
    )
    return candidates


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def target_path(entry: dict, min_bytes: int, max_bytes: int) -> str:
    """
    Where this specific build belongs on disk.

    Normally `<dest_dir>/<package>.apk`. The exception is a package that appears in
    two size windows as two different *versions* For example, `com.sidhant.queens` ships a 7.9 MB
    build and an 18.1 MB one, and both are legitimate, separately-hashed members of
    their respective corpora. Naming both `<package>.apk` means the second run's skip
    check sees the first run's file, calls it done, and the second build never lands:
    the corpus silently comes up short with every command reporting success.

    The test is the on-disk file's SIZE against the current window, not its hash:

      * size inside this window  -> same selection. Skip it, even if the bytes differ
        from the index. F-Droid publishes new builds continuously, so a corpus
        downloaded weeks ago legitimately disagrees with today's index for most of
        its apps — measured, 203 of the original 220. Those were verified against the
        index current at download time and re-fetching them would silently roll the
        corpus forward under a dataset already keyed to the old hashes.
      * size outside this window -> a different selection's file. Disambiguate with
        `<package>__<sha8>.apk`, taken from this build's own published hash so the
        name is deterministic and reproduces on a fresh machine.

    Hashing to make this decision would be both slower and wrong: it cannot tell
    "stale version of my own app" from "the other window's app".
    """
    base = os.path.join(entry["dest_dir"], f"{entry['package']}.apk")
    if not os.path.exists(base) or os.path.getsize(base) == 0:
        return base
    if min_bytes <= os.path.getsize(base) <= max_bytes:
        return base
    return os.path.join(
        entry["dest_dir"], f"{entry['package']}__{entry['sha256'][:8]}.apk"
    )


def _download_one(entry: dict, repo_url: str, min_bytes: int, max_bytes: int) -> tuple[str, str]:
    """
    Fetch one APK and verify it against the index hash. Returns (package, status).

    status is one of: "ok", "skipped", "hash-mismatch", "not-an-apk", "error:<...>".

    The destination comes from `entry["dest_dir"]`, assigned once by assign_split(),
    so the skip check, the dry-run report and --verify-existing all look in the same
    place a download would write to. Deriving it separately in each of those paths is
    how a holdout app ends up re-downloaded into the training directory.

    Written to a thread-unique temp file and renamed into place, so an interrupted
    run can never leave a truncated file that the next run's skip check would
    mistake for a completed download.
    """
    package = entry["package"]
    out_path = target_path(entry, min_bytes, max_bytes)
    if os.path.exists(out_path) and os.path.getsize(out_path) > 0:
        return package, "skipped"

    url = f"{repo_url.rstrip('/')}/{entry['apk_name']}"
    tmp_path = f"{out_path}.{threading.get_ident()}.part"
    try:
        with urllib.request.urlopen(url, timeout=120) as resp, open(tmp_path, "wb") as dst:
            while chunk := resp.read(1 << 20):
                dst.write(chunk)

        digest = _sha256_file(tmp_path)
        if digest != entry["sha256"]:
            # Do not keep it. The whole point of this corpus is a verifiable
            # clean label, and a file whose bytes disagree with F-Droid's
            # published build record carries no such guarantee.
            return package, "hash-mismatch"
        if not zipfile.is_zipfile(tmp_path):
            return package, "not-an-apk"

        os.replace(tmp_path, out_path)
        return package, "ok"
    except Exception as e:
        return package, f"error:{type(e).__name__}: {e}"
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def assign_split(
    selected: list[dict], out_dir: str, holdout_dir: str, holdout_count: int
) -> tuple[list[dict], list[dict]]:
    """
    Route the last `holdout_count` apps of the selection to `holdout_dir`.

    `selected` is already sorted by package name, so the partition is a property of
    the sorted list rather than of `random.sample`'s internal ordering — which means
    it reproduces from what is on disk, not from an implementation detail of the RNG.

    Returns (train, holdout) and stamps `dest_dir` on every entry.
    """
    holdout_count = max(0, min(holdout_count, len(selected)))
    split = len(selected) - holdout_count
    train, holdout = selected[:split], selected[split:]
    for entry in train:
        entry["dest_dir"] = out_dir
    for entry in holdout:
        entry["dest_dir"] = holdout_dir
    return train, holdout


def download_corpus(
    selected: list[dict], repo_url: str, workers: int, min_bytes: int, max_bytes: int
) -> dict[str, int]:
    """Fetch every selected APK concurrently; returns a status -> count tally."""
    for directory in {e["dest_dir"] for e in selected}:
        os.makedirs(directory, exist_ok=True)
    total = len(selected)
    tally: dict[str, int] = {}
    destinations = ", ".join(sorted({e["dest_dir"] for e in selected}))
    logger.info(f"[benign] downloading {total} APKs with {workers} workers -> {destinations}")

    with ThreadPoolExecutor(max_workers=min(workers, total)) as pool:
        futures = {
            pool.submit(_download_one, e, repo_url, min_bytes, max_bytes): e
            for e in selected
        }
        for done, fut in enumerate(as_completed(futures), 1):
            package, status = fut.result()
            bucket = status.split(":", 1)[0]
            tally[bucket] = tally.get(bucket, 0) + 1
            if bucket in ("ok", "skipped"):
                logger.info(f"[benign] [{done}/{total}] {status:8} {package}")
            else:
                logger.warning(f"[benign] [{done}/{total}] {status} {package}")
    return tally


def verify_existing(selected: list[dict], min_bytes: int, max_bytes: int) -> int:
    """Re-hash on-disk APKs against the index. Returns the number of mismatches.

    Reads `entry["dest_dir"]`, so a split selection is verified across both
    directories in one pass. Note that this only ever checks apps in the CURRENT
    selection: run it with the same --count/--seed/--min-size/--max-size you
    downloaded with, or it rebuilds a different selection, matches nothing on disk
    and reports "verified 0/0" while exiting 0 — a check that cannot fail.
    """
    bad = 0
    checked = 0
    for entry in selected:
        path = target_path(entry, min_bytes, max_bytes)
        if not os.path.exists(path):
            continue
        checked += 1
        if _sha256_file(path) != entry["sha256"]:
            bad += 1
            logger.error(f"[benign] HASH MISMATCH — not verifiably clean: {path}")
    logger.info(f"[benign] verified {checked - bad}/{checked} on-disk APKs against the index")
    return bad


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Download a known-clean F-Droid APK corpus for Stage C negatives.",
    )
    ap.add_argument("--count", type=int, default=220,
                    help="How many apps to select (default 220 — roughly 1.6x the "
                         "malware row count, which balanced the classes well).")
    ap.add_argument("--out-dir", default=DEFAULT_OUT_DIR)
    ap.add_argument("--holdout-count", type=int, default=0,
                    help="Route the last N apps of the selection (ordered by package "
                         "name) to --holdout-dir instead of --out-dir. A split of one "
                         "seeded selection, so nothing is downloaded twice. The "
                         "holdout is for calibration only and must never be passed to "
                         "build_ttp_dataset.py --benign-dir.")
    ap.add_argument("--holdout-dir", default=DEFAULT_HOLDOUT_DIR,
                    help=f"Where --holdout-count apps go (default {DEFAULT_HOLDOUT_DIR}).")
    ap.add_argument("--repo-url", default=DEFAULT_REPO_URL)
    ap.add_argument("--seed", type=int, default=42,
                    help="Selection seed. Same seed + same count = same corpus.")
    ap.add_argument("--min-size", type=int, default=DEFAULT_MIN_BYTES,
                    help="Minimum APK size in bytes (default 150 KB — skips stubs).")
    ap.add_argument("--max-size", type=int, default=DEFAULT_MAX_BYTES,
                    help="Maximum APK size in bytes (default 12 MB).")
    ap.add_argument("--workers", type=int, default=8, help="Concurrent downloads.")
    ap.add_argument("--index-cache", default=None,
                    help="Path to cache index-v1.json (default: <out-dir>/_fdroid_index.json).")
    ap.add_argument("--dry-run", action="store_true",
                    help="Resolve and report the selection without downloading APKs.")
    ap.add_argument("--verify-existing", action="store_true",
                    help="Re-hash APKs already on disk against the index and exit.")
    args = ap.parse_args()

    index_cache = args.index_cache or os.path.join(args.out_dir, "_fdroid_index.json")
    index = fetch_index(args.repo_url, index_cache)
    candidates = select_candidates(index, args.min_size, args.max_size)

    if not candidates:
        logger.error("[benign] no candidates in the size window — widen --min-size/--max-size.")
        sys.exit(1)
    if args.count > len(candidates):
        logger.warning(
            f"[benign] asked for {args.count} but only {len(candidates)} candidates exist "
            "— taking all of them."
        )

    if args.holdout_count >= args.count:
        logger.error(
            f"[benign] --holdout-count {args.holdout_count} leaves nothing to train on "
            f"out of --count {args.count}."
        )
        sys.exit(1)
    if args.holdout_count and args.holdout_dir == args.out_dir:
        logger.error("[benign] --holdout-dir must differ from --out-dir; see the module docstring.")
        sys.exit(1)

    rng = random.Random(args.seed)
    selected = rng.sample(candidates, min(args.count, len(candidates)))
    selected.sort(key=lambda c: c["package"])
    total_mb = sum(e["size"] for e in selected) / 1e6
    logger.info(f"[benign] selected {len(selected)} apps (~{total_mb:.0f} MB) with seed={args.seed}")

    train, holdout = assign_split(
        selected, args.out_dir, args.holdout_dir, args.holdout_count
    )
    if holdout:
        logger.info(
            f"[benign] split: {len(train)} -> {args.out_dir}, "
            f"{len(holdout)} -> {args.holdout_dir} (calibration holdout, never trained on)"
        )

    if args.verify_existing:
        sys.exit(1 if verify_existing(selected, args.min_size, args.max_size) else 0)

    if args.dry_run:
        for label, group in (("train", train), ("holdout", holdout)):
            if not group:
                continue
            on_disk = sum(
                1 for e in group
                if os.path.exists(target_path(e, args.min_size, args.max_size))
            )
            logger.info(
                f"[benign] --dry-run [{label}]: {on_disk}/{len(group)} already in "
                f"{group[0]['dest_dir']}, {len(group) - on_disk} would be downloaded"
            )
        for entry in selected[:10]:
            logger.info(f"[benign]   {entry['package']} ({entry['size'] / 1e6:.1f} MB)")
        return

    tally = download_corpus(
        selected, args.repo_url, args.workers, args.min_size, args.max_size
    )
    for directory in sorted({e["dest_dir"] for e in selected}):
        count = len([f for f in os.listdir(directory) if f.endswith(".apk")])
        logger.info(f"[benign] {count} APKs now in {directory}")
    logger.info(f"[benign] done: {tally}")

    failed = sum(v for k, v in tally.items() if k not in ("ok", "skipped"))
    if failed:
        logger.warning(
            f"[benign] {failed} APKs did not land. Rerunning is safe and cheap — "
            "completed files are skipped."
        )
    logger.info(
        "[benign] next: python scripts/build_ttp_dataset.py --stage c "
        f"--benign-dir {args.out_dir}"
    )
    if holdout:
        logger.warning(
            f"[benign] {args.holdout_dir} is a calibration holdout — do NOT pass it to "
            "--benign-dir. Nothing in code enforces this."
        )


if __name__ == "__main__":
    main()
