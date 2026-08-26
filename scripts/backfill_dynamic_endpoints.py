"""
Promotes runtime-observed network endpoints out of record_json and into the
graph as NetworkEndpoint nodes.

Why this exists: store_signature only ever created C2Indicator nodes from the
STATIC indicator list. Everything the dynamic pass actually observed the sample
contacting was persisted inside the record_json blob and never became a node,
so it was invisible to every graph query, correlation pivot and the threat
landscape view. Measured on the corpus at the time this was written: 46
C2Indicator nodes (all static) versus 71 distinct hosts observed live, with
ZERO overlap between the two sets — static and dynamic find disjoint
infrastructure, so the observed set was the only record of where these samples
actually reach.

No re-analysis is needed. The evidence is already stored; this reads it back
out and writes the nodes store_signature now writes natively, so existing
records match new ones.

    python scripts/backfill_dynamic_endpoints.py --dry-run   # report only
    python scripts/backfill_dynamic_endpoints.py             # write

Idempotent: MERGE on host, so re-running converges rather than duplicating.
"""
import argparse
import json
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.core.config import settings
from app.graph.cache import observed_endpoints
from app.graph.neo4j_client import neo4j_client
from app.graph.ontology import ensure_constraints

WRITE = """
MATCH (s:Sample {sha256: $sha256})
UNWIND $endpoints AS ep
MERGE (ne:NetworkEndpoint {host: ep.host})
SET ne.known_benign = ep.known_benign
MERGE (s)-[r:CONTACTED]->(ne)
SET r.observed_at_runtime = true,
    r.statically_predicted = coalesce(r.statically_predicted, false) OR ep.statically_predicted,
    r.egress_blocked_during_capture = $egress_blocked
"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true", help="report what would be written")
    args = ap.parse_args()

    rows = neo4j_client.run(
        "MATCH (s:Sample) WHERE s.record_json IS NOT NULL "
        "RETURN s.sha256 AS sha, s.record_json AS rj"
    )
    print(f"samples with a record: {len(rows)}")

    plan: list[tuple[str, list[dict]]] = []
    hosts: Counter = Counter()
    benign = predicted = 0
    for r in rows:
        try:
            rec = json.loads(r["rj"] or "{}")
        except ValueError:
            print(f"  !! unreadable record_json on {r['sha'][:12]} — skipped")
            continue
        eps = observed_endpoints(rec.get("dynamic_verification"), rec.get("c2_indicators"))
        if not eps:
            continue
        plan.append((r["sha"], eps))
        for e in eps:
            hosts[e["host"]] += 1
            benign += 1 if e["known_benign"] else 0
            predicted += 1 if e["statically_predicted"] else 0

    print(f"samples with observed endpoints: {len(plan)}")
    print(f"distinct hosts: {len(hosts)}   edges: {sum(hosts.values())}")
    print(f"  flagged known-benign: {benign}   also statically predicted: {predicted}")
    print("\nmost widely contacted hosts:")
    for h, c in hosts.most_common(12):
        print(f"  {c:>4} samples  {h}")

    if args.dry_run:
        print("\n--dry-run: nothing written")
        return 0

    ensure_constraints()
    egress_blocked = bool(settings.dynamic_analysis_require_network_isolation)
    written = 0
    for sha, eps in plan:
        try:
            neo4j_client.run(WRITE, sha256=sha, endpoints=eps, egress_blocked=egress_blocked)
            written += 1
        except Exception as e:
            print(f"  !! write failed for {sha[:12]}: {str(e)[:90]}")
    print(f"\nwrote endpoints for {written}/{len(plan)} samples")

    tot = neo4j_client.run("MATCH (n:NetworkEndpoint) RETURN count(*) AS c")[0]["c"]
    edges = neo4j_client.run("MATCH ()-[r:CONTACTED]->() RETURN count(*) AS c")[0]["c"]
    print(f"graph now holds {tot} NetworkEndpoint nodes and {edges} CONTACTED edges")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
