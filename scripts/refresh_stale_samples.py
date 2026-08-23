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
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import requests

from app.graph.neo4j_client import neo4j_client

APK_DIRS = ["data/benign_apks", "data/ttp_apks"]


def find_apk_by_sha256(sha256: str) -> str | None:
    for d in APK_DIRS:
        candidate = os.path.join(d, f"{sha256}.apk")
        if os.path.exists(candidate):
            return candidate
    return None


def main() -> int:
    rows = neo4j_client.run(
        "MATCH (s:Sample) WHERE s.record_json IS NULL "
        "RETURN s.sha256 AS sha256, s.app_name AS app_name"
    )
    stale = [(r["sha256"], r.get("app_name") or r["sha256"]) for r in rows]
    print(f"Found {len(stale)} stale (pre-record_json) samples.")

    refreshed, skipped, failed = 0, 0, 0
    for i, (sha256, app_name) in enumerate(stale, 1):
        apk_path = find_apk_by_sha256(sha256)
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
