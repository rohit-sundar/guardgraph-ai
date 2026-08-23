"""
Clears and re-analyzes every cached Sample node that predates record_json
persistence, so old bulk-seeded records stop showing hollow cache hits and
frozen pre-fix LLM narratives (see scripts/clear_sample.py's docstring for
why a cache hit can never self-heal without this).

Only touches samples whose original APK is still on disk under
data/benign_apks or data/ttp_apks — anything else is skipped and reported,
since there is nothing to re-upload.

    python scripts/refresh_stale_samples.py
"""
import glob
import hashlib
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import requests

from app.graph.neo4j_client import neo4j_client

APK_DIRS = ["data/benign_apks", "data/ttp_apks"]


def _sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def build_sha256_index() -> dict[str, str]:
    """
    Maps sha256 -> filepath by hashing every APK's actual content, not by
    assuming the filename is the hash. data/ttp_apks names files by hash, but
    data/benign_apks names them by package name (e.g. com.sidhant.match3.apk)
    — a filename-only lookup silently mislabels every benign sample "not found
    on disk" even when it's sitting right there. Content hashing is the only
    way that works for both directories.
    """
    index: dict[str, str] = {}
    for d in APK_DIRS:
        for path in glob.glob(os.path.join(d, "*.apk")):
            index[_sha256_of(path)] = path
    return index


def main() -> int:
    rows = neo4j_client.run(
        "MATCH (s:Sample) WHERE s.record_json IS NULL "
        "RETURN s.sha256 AS sha256, s.app_name AS app_name"
    )
    stale = [(r["sha256"], r.get("app_name") or r["sha256"]) for r in rows]
    print(f"Found {len(stale)} stale (pre-record_json) samples.")

    print("Hashing every APK on disk to find matches (filename can't be trusted — "
          "data/benign_apks names files by package, not sha256)...")
    sha256_index = build_sha256_index()
    print(f"Indexed {len(sha256_index)} APKs on disk.")

    refreshed, skipped, failed = 0, 0, 0
    for i, (sha256, app_name) in enumerate(stale, 1):
        apk_path = sha256_index.get(sha256)
        if not apk_path:
            print(f"[{i}/{len(stale)}] {app_name} ({sha256[:12]}): SKIP — APK not found on disk")
            skipped += 1
            continue

        neo4j_client.run("MATCH (s:Sample {sha256: $sha256}) DETACH DELETE s", sha256=sha256)

        start = time.time()
        try:
            with open(apk_path, "rb") as f:
                resp = requests.post(
                    "http://127.0.0.1:8000/analyze",
                    files={"file": (os.path.basename(apk_path), f, "application/vnd.android.package-archive")},
                    timeout=600,
                )
            elapsed = time.time() - start
            print(f"[{i}/{len(stale)}] {app_name} ({sha256[:12]}): HTTP {resp.status_code} in {elapsed:.1f}s")
            if resp.status_code == 200:
                refreshed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"[{i}/{len(stale)}] {app_name} ({sha256[:12]}): ERROR {e}")
            failed += 1

    print(f"\nDone. refreshed={refreshed} skipped={skipped} failed={failed} total={len(stale)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
