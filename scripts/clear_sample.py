"""
Deletes ONE cached Sample node by SHA-256, so the next upload of that exact APK
goes through the full cold path again instead of replaying a stale cache hit.

Why this needs to exist alongside clear_cache.py: store_signature() only ever
runs on a cache MISS (see app/api/routes.py — `if not cache_hit: store_signature(...)`).
A cache HIT never re-persists anything, no matter how many times the same file is
re-uploaded. So the moment a schema change adds a new field to what gets cached
(as happened going from the first "hollow cache-hit" fix to the second one that
added resolved_crypto/DCL/WebView/native + grounding), every sample analysed
BEFORE that change is stuck showing the gap forever — "just re-upload it" does
nothing, because the upload keeps hitting the same incomplete record. The only
way to actually refresh one sample is to delete its Sample node first, which is
what this script does — clear_cache.py wipes every sample, which also throws
away the correlation graph (shared techniques/C2/certificates) for every OTHER
sample, so it is the wrong tool when only one record is stale.

    python scripts/clear_sample.py <sha256>
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.graph.neo4j_client import neo4j_client


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python scripts/clear_sample.py <sha256>")
        return 1

    sha256 = sys.argv[1].strip().lower()
    if len(sha256) != 64 or any(c not in "0123456789abcdef" for c in sha256):
        print(f"'{sha256}' does not look like a SHA-256 hash (64 hex chars).")
        return 1

    rows = neo4j_client.run(
        "MATCH (s:Sample {sha256: $sha256}) RETURN s.app_name AS app_name", sha256=sha256
    )
    if not rows:
        print(f"No cached Sample node for {sha256} — nothing to clear "
              "(it may already be uncached, or was never analysed here).")
        return 0

    app_name = rows[0].get("app_name") or sha256
    neo4j_client.run("MATCH (s:Sample {sha256: $sha256}) DETACH DELETE s", sha256=sha256)
    print(f"Cleared cached record for {app_name} ({sha256}).")
    print("The next upload of this exact APK will run the full cold path and "
          "re-cache it with the current data shape.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
