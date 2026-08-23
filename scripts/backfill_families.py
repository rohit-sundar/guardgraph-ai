"""
Replaces classifier-guessed family labels on cached Sample nodes with the
deterministic family the third-party signature lookup already recorded.

Why this exists
---------------
`store_signature(family=predicted_family or "")` wrote whatever the auxiliary
XGBoost family classifier returned. That model was fitted on the 33-column,
6-behaviour schema; when BEHAVIOR_FEATURES grew to 8 the new columns landed at
indices 12-13, so every column from 12 onward shifted by two and the model's
answers stopped meaning anything (see app/ml/classifier.py's predict docstring).
The model has since been deleted, so new analyses write no family at all — but
the labels it already wrote are still in the graph, still displayed, and still
what find_related_samples() correlates on.

Meanwhile every one of those samples carries a REAL family in its stored record:
MalwareBazaar's `signature` or VirusTotal's `suggested_threat_label`, captured at
analysis time by app/analysis/signatures.py. Those are deterministic attributions
of the sample's own hash, not predictions — strictly better than what they are
replacing, and they name real banking-trojan families (Cerberus, TrickMo, SharkBot)
instead of the classifier's six coarse buckets.

So this does not delete the family dimension of the graph; it makes it true.

    python scripts/backfill_families.py            # report only, writes nothing
    python scripts/backfill_families.py --apply    # perform the rewrite
"""
import argparse
import json
import os
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.analysis.signatures import deterministic_family  # noqa: E402
from app.graph.neo4j_client import neo4j_client  # noqa: E402


def _canonical_casing(names: list[str]) -> dict[str, str]:
    """
    Maps each casefolded family key to the spelling to actually store.

    The scanners are inconsistent about case — this corpus carries both
    "TangleBot" and "Tanglebot", which MERGE on `name` would keep as two
    separate MalwareFamily nodes for one family, splitting its samples in the
    threat landscape. The most frequently observed spelling wins; ties break
    alphabetically so a re-run is deterministic.
    """
    by_key: dict[str, Counter] = defaultdict(Counter)
    for name in names:
        by_key[name.casefold()][name] += 1
    return {
        key: min(sorted(counter), key=lambda n: (-counter[n], n))
        for key, counter in by_key.items()
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apply", action="store_true",
                    help="write the changes; without it this only reports")
    args = ap.parse_args()

    try:
        rows = neo4j_client.run("""
            MATCH (s:Sample)
            OPTIONAL MATCH (s)-[:CLASSIFIED_AS_FAMILY]->(f:MalwareFamily)
            RETURN s.sha256 AS sha256, s.app_name AS app_name,
                   s.record_json AS record_json, f.name AS current_family
        """)
    except Exception as e:
        print(f"ERROR: Neo4j unreachable ({e}). Start it with: docker compose up -d")
        return 1

    resolved: dict[str, str] = {}   # sha256 -> real family (pre-casing-merge)
    no_record = 0
    no_family = 0

    for row in rows:
        raw = row.get("record_json")
        if not raw:
            no_record += 1
            continue
        try:
            record = json.loads(raw) or {}
        except (TypeError, ValueError):
            no_record += 1
            continue
        sig_yara = record.get("signature_yara_data") or {}
        family = deterministic_family(sig_yara.get("signature_matches"))
        if family:
            resolved[row["sha256"]] = family
        else:
            no_family += 1

    canonical = _canonical_casing(list(resolved.values()))
    final = {sha: canonical[fam.casefold()] for sha, fam in resolved.items()}

    current = {r["sha256"]: r.get("current_family") for r in rows}
    changed = {s: f for s, f in final.items() if current.get(s) != f}

    # Samples with no recoverable family but a classifier label still attached.
    # Leaving those alone would quietly preserve exactly the wrong data this
    # script exists to remove — "no family" is the honest state for them.
    to_clear = [
        r["sha256"] for r in rows
        if r["sha256"] not in final and current.get(r["sha256"]) is not None
    ]

    print(f"Sample nodes                     : {len(rows)}")
    print(f"  deterministic family recovered : {len(final)}")
    print(f"  no signature family            : {no_family}")
    print(f"  no usable record_json          : {no_record}")
    print(f"  labels that will change        : {len(changed)}")
    print(f"  labels that will be cleared    : {len(to_clear)}")

    merged = {k: v for k, v in canonical.items()
              if sum(1 for f in resolved.values() if f.casefold() == k) > 0
              and len({f for f in resolved.values() if f.casefold() == k}) > 1}
    if merged:
        print("\ncase variants merged:")
        for key, keep in sorted(merged.items()):
            variants = sorted({f for f in resolved.values() if f.casefold() == key})
            print(f"  {variants} -> {keep!r}")

    print("\nreplacing:")
    for old, n in Counter(
        current.get(s) or "<none>" for s in changed
    ).most_common():
        print(f"  {n:4}  {old}")

    print("\nwith:")
    for fam, n in Counter(final[s] for s in changed).most_common():
        print(f"  {n:4}  {fam}")

    if to_clear:
        print("\nclearing (no deterministic family recoverable):")
        for old, n in Counter(current.get(s) or "<blank>" for s in to_clear).most_common():
            print(f"  {n:4}  {old}")

    if not args.apply:
        print("\nDRY RUN — nothing written. Re-run with --apply to perform it.")
        return 0

    # Detach from the old family, attach to the real one. Done per-sample rather
    # than as one UNWIND so a single bad row cannot abort the whole rewrite.
    written = 0
    for sha256, family in changed.items():
        try:
            neo4j_client.run("""
                MATCH (s:Sample {sha256: $sha256})
                OPTIONAL MATCH (s)-[r:CLASSIFIED_AS_FAMILY]->(:MalwareFamily)
                DELETE r
                WITH s
                MERGE (f:MalwareFamily {name: $family})
                MERGE (s)-[:CLASSIFIED_AS_FAMILY]->(f)
            """, sha256=sha256, family=family)
            written += 1
        except Exception as e:
            print(f"  WARN {sha256[:12]}: {e}")

    cleared = 0
    for sha256 in to_clear:
        try:
            neo4j_client.run("""
                MATCH (s:Sample {sha256: $sha256})-[r:CLASSIFIED_AS_FAMILY]->(:MalwareFamily)
                DELETE r
            """, sha256=sha256)
            cleared += 1
        except Exception as e:
            print(f"  WARN {sha256[:12]}: {e}")

    # MalwareFamily nodes left with NO relationships of any kind — the classifier
    # buckets, the blank-name node store_signature MERGEs when family is "", and
    # any case variant that lost its samples to the canonical spelling.
    #
    # The predicate is deliberately `NOT (f)--()` and not "has no samples".
    # load_ontology.py loads the whole ATT&CK software catalog as MalwareFamily
    # nodes joined to techniques by [:USES]; 118 of them legitimately have no
    # samples in this instance, and treating "no samples" as orphaned would
    # delete the ontology mapping GraphRAG grounds against. Neo4j's own
    # constraint caught that on first run — this predicate is what makes it
    # correct rather than merely survivable.
    orphans = neo4j_client.run("""
        MATCH (f:MalwareFamily) WHERE NOT (f)--()
        RETURN collect(f.name) AS names
    """)
    names = (orphans[0]["names"] if orphans else []) or []
    if names:
        neo4j_client.run("MATCH (f:MalwareFamily) WHERE NOT (f)--() DELETE f")

    print(f"\nrewrote {written} sample(s), cleared {cleared}; removed {len(names)} "
          f"orphaned MalwareFamily node(s): {sorted(n or '<blank>' for n in names)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
