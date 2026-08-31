"""
Gives the existing graph the provenance the history "Clear" button now checks.

`store_signature` stamps every new Sample node with `source` ('operator' or
'corpus'), and `delete_sample(only_if_operator=True)` refuses to drop anything
that is not 'operator'. Nodes written before that property existed have no
`source`, and are treated as undeletable — safe, but it means the Clear button
does nothing for them.

This assigns provenance to those nodes from the one piece of evidence that is
actually available on disk: whether the sample's APK sits in a corpus directory.
A sha256 that matches a file in data/ttp_apks, data/benign_apks or
data/benign_holdout was bulk-loaded by the population scripts; that is where
those files come from and nothing else puts them there.

    python scripts/backfill_sample_source.py                 # dry run
    python scripts/backfill_sample_source.py --write

Anything still unmatched keeps no `source` and therefore stays undeletable. That
is deliberate: an unmatched node is one this script cannot explain, and guessing
'operator' on it would hand the Clear button exactly the samples it should be
most careful with. Mark those by hand with --mark-operator if you know better.
"""
import argparse
import glob
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from loguru import logger

from app.graph.cache import SAMPLE_SOURCE_CORPUS, SAMPLE_SOURCE_OPERATOR
from app.graph.neo4j_client import neo4j_client

logger.remove()
logger.add(sys.stderr, level="WARNING")

CORPUS_DIRS = ("data/ttp_apks", "data/benign_apks", "data/benign_holdout")


def corpus_shas(dirs: tuple[str, ...]) -> set[str]:
    """sha256s of every APK sitting in a corpus directory, by filename.

    The population scripts name their files by hash, which is what makes this
    identification exact rather than a heuristic.
    """
    out: set[str] = set()
    for d in dirs:
        for p in glob.glob(os.path.join(d, "*.apk")):
            stem = os.path.splitext(os.path.basename(p))[0].lower()
            if len(stem) == 64 and all(c in "0123456789abcdef" for c in stem):
                out.add(stem)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus-dir", action="append", default=None)
    ap.add_argument("--write", action="store_true", help="apply the changes")
    ap.add_argument("--mark-operator", action="append", default=None,
                    metavar="SHA256",
                    help="explicitly mark one sha256 as operator-analysed "
                         "(repeatable) — makes it deletable by the Clear button")
    args = ap.parse_args()

    dirs = tuple(args.corpus_dir) if args.corpus_dir else CORPUS_DIRS
    on_disk = corpus_shas(dirs)
    print(f"corpus APKs on disk: {len(on_disk)} across {', '.join(dirs)}")

    rows = neo4j_client.run(
        "MATCH (s:Sample) RETURN s.sha256 AS sha, s.source AS source, "
        "s.app_name AS name"
    )
    print(f"Sample nodes in graph: {len(rows)}")

    already = [r for r in rows if r.get("source")]
    unknown = [r for r in rows if not r.get("source")]
    to_corpus = [r for r in unknown if (r["sha"] or "").lower() in on_disk]
    unmatched = [r for r in unknown if (r["sha"] or "").lower() not in on_disk]

    explicit = {s.lower() for s in (args.mark_operator or [])}
    to_operator = [r for r in unmatched if (r["sha"] or "").lower() in explicit]
    unmatched = [r for r in unmatched if (r["sha"] or "").lower() not in explicit]

    print()
    print(f"  already stamped         {len(already)}")
    print(f"  -> source='corpus'      {len(to_corpus)}   (APK found in a corpus dir)")
    print(f"  -> source='operator'    {len(to_operator)}   (--mark-operator)")
    print(f"  left unstamped          {len(unmatched)}   (undeletable by Clear)")

    if unmatched:
        print("\n  unmatched, first 15:")
        for r in unmatched[:15]:
            print(f"    {r['sha'][:12]}  {r.get('name')}")

    if not args.write:
        print("\nDry run. Re-run with --write to apply.")
        return 0

    if to_corpus:
        neo4j_client.run(
            "UNWIND $shas AS sha MATCH (s:Sample {sha256: sha}) SET s.source = $src",
            shas=[r["sha"] for r in to_corpus], src=SAMPLE_SOURCE_CORPUS,
        )
    if to_operator:
        neo4j_client.run(
            "UNWIND $shas AS sha MATCH (s:Sample {sha256: sha}) SET s.source = $src",
            shas=[r["sha"] for r in to_operator], src=SAMPLE_SOURCE_OPERATOR,
        )
    print(f"\nStamped {len(to_corpus)} corpus and {len(to_operator)} operator node(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
