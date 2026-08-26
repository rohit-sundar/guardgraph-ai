"""
MITRE ATT&CK Mobile ontology loader for Neo4j.

Two loaders:
  - load_full_ontology()   — loads the full Mobile technique/tactic set (from the
                             STIX-derived data/ontology/mobile_techniques.json, or
                             the baked-in catalog fallback) plus software->technique
                             `USES` edges. This is the default; it gives GraphRAG a
                             grounded description for every technique the multi-label
                             TTP classifier can predict.
  - load_starter_ontology() — legacy 5-technique demo seed, kept for a zero-network
                             smoke test.

get_technique_context() is the retrieval GraphRAG grounds its report language in
(instead of letting the LLM invent MITRE descriptions from memory) — its signature
is unchanged so nothing downstream breaks.
"""
from loguru import logger

from app.graph.neo4j_client import neo4j_client
from app.ml.labels import load_full_technique_ontology

STARTER_TECHNIQUES = [
    {"technique_id": "T1636", "name": "Protected User Data", "tactic": "Collection",
     "description": "Adversaries may access data protected by Android permissions, such as SMS messages."},
    {"technique_id": "T1624", "name": "Event Triggered Execution", "tactic": "Persistence",
     "description": "Adversaries may establish persistence using system events, such as BroadcastReceivers."},
    {"technique_id": "T1417", "name": "Input Capture", "tactic": "Collection",
     "description": "Adversaries may capture user input, e.g. via overlay attacks or accessibility abuse."},
    {"technique_id": "T1409", "name": "Stored Application Data", "tactic": "Collection",
     "description": "Adversaries may access sensitive data stored by other applications."},
    {"technique_id": "T1471", "name": "Data Encrypted for Impact", "tactic": "Impact",
     "description": "Adversaries may encrypt device data to interrupt availability."},
]

_TECHNIQUE_MERGE = """
UNWIND $techniques AS tech
MERGE (t:Technique {technique_id: tech.technique_id})
SET t.name = tech.name, t.description = tech.description
MERGE (ta:Tactic {name: tech.tactic})
MERGE (t)-[:BELONGS_TO_TACTIC]->(ta)
"""

_SOFTWARE_MERGE = """
UNWIND $software AS sw
MERGE (m:MalwareFamily {software_id: sw.software_id})
SET m.name = sw.name, m.aliases = sw.aliases
WITH m, sw
UNWIND sw.technique_ids AS tid
MATCH (t:Technique {technique_id: tid})
MERGE (m)-[:USES]->(t)
"""

# ATT&CK's own countermeasures, edged to the techniques they cover. This is what
# lets the report's "Recommended Analyst Actions" cite a real MITRE control rather
# than whatever the model produces unprompted — the same grounding the technique
# citations already have, and the reason SYSTEM_PROMPT rule 12 has to ban generic
# advice today (observed live: a shipped narrative opened its recommendations with
# "Isolate the Device", the exact phrase that rule forbids).
_MITIGATION_MERGE = """
UNWIND $mitigations AS mit
MERGE (m:Mitigation {mitigation_id: mit.mitigation_id})
SET m.name = mit.name, m.description = mit.description
WITH m, mit
UNWIND mit.technique_ids AS tid
MATCH (t:Technique {technique_id: tid})
MERGE (m)-[:MITIGATES]->(t)
"""


# Uniqueness constraints for every key this pipeline MERGEs on. Neo4j backs each
# one with an index, which is the point: `MERGE (s:Sample {sha256: ...})` runs on
# the hot path of every upload, and without an index it is a full label scan whose
# cost grows with the corpus. Measured on the live graph before this existed: 0
# constraints and 0 property indexes, only the two default LOOKUPs.
#
# The keys mirror what the code actually merges on — Tactic on `name` and
# MalwareFamily on `name`, not the `tactic_id`/`software_id` an earlier design
# document assumed, because those are the keys cache.py and _TECHNIQUE_MERGE use.
# A constraint on a key nothing merges on would index the wrong thing.
#
# `IF NOT EXISTS` makes this idempotent, and Neo4j skips nodes where the property
# is null, so a MalwareFamily created by the ontology loader (which sets both
# software_id and name) and one created by a cache write (name only) coexist.
_CONSTRAINTS = [
    ("sample_sha256", "Sample", "sha256"),
    ("certificate_thumbprint", "Certificate", "thumbprint"),
    ("technique_id", "Technique", "technique_id"),
    ("tactic_name", "Tactic", "name"),
    ("malware_family_name", "MalwareFamily", "name"),
    ("c2_indicator_value", "C2Indicator", "value"),
    ("mitigation_id", "Mitigation", "mitigation_id"),
    # Hosts observed being contacted at runtime (cache.observed_endpoints).
    # Keyed on the normalised host so two samples reaching the same
    # infrastructure converge on one node, which is what makes the endpoint
    # usable as a correlation pivot rather than a per-sample leaf.
    ("network_endpoint_host", "NetworkEndpoint", "host"),
]


def ensure_constraints() -> int:
    """
    Creates the uniqueness constraints (and their backing indexes) if absent.
    Idempotent and safe to call on every ontology load. Returns how many
    statements ran. Failures are logged, not raised: a missing index degrades
    performance, and refusing to load an ontology over it would be worse.
    """
    created = 0
    for name, label, prop in _CONSTRAINTS:
        try:
            neo4j_client.run(
                f"CREATE CONSTRAINT {name} IF NOT EXISTS "
                f"FOR (n:{label}) REQUIRE n.{prop} IS UNIQUE"
            )
            created += 1
        except Exception as e:
            logger.warning(f"[ontology] constraint {name} ({label}.{prop}) not created: {e}")
    logger.info(f"[ontology] Ensured {created}/{len(_CONSTRAINTS)} uniqueness constraints.")
    return created


def load_starter_ontology():
    """Legacy minimal seed (5 techniques). Kept for a zero-network smoke test."""
    neo4j_client.run(_TECHNIQUE_MERGE, techniques=STARTER_TECHNIQUES)


def load_full_ontology(
    techniques_path: str = "data/ontology/mobile_techniques.json",
    software_map_path: str = "data/ontology/software_technique_map.json",
    mitigations_path: str = "data/ontology/technique_mitigations.json",
):
    """
    Loads the full Mobile technique/tactic ontology plus software->technique edges.
    Falls back to the baked-in labels.py catalog for techniques when the STIX JSON
    has not been generated yet; skips software edges when that map is absent.
    """
    ensure_constraints()
    techniques = load_full_technique_ontology(techniques_path)
    # Only keep fields Neo4j needs; ensure description key present.
    tech_rows = [
        {
            "technique_id": t["technique_id"],
            "name": t.get("name", ""),
            "tactic": t.get("tactic", "") or "Unknown",
            "description": t.get("description", "") or "",
        }
        for t in techniques
    ]
    neo4j_client.run(_TECHNIQUE_MERGE, techniques=tech_rows)
    logger.info(f"[ontology] Loaded {len(tech_rows)} techniques into Neo4j.")

    software = _load_json_list(software_map_path)
    if software:
        neo4j_client.run(_SOFTWARE_MERGE, software=software)
        logger.info(f"[ontology] Loaded {len(software)} software->technique maps into Neo4j.")
    else:
        logger.warning(
            f"[ontology] No software map at {software_map_path}; skipping USES edges. "
            "Run scripts/build_ttp_label_space.py to generate it."
        )

    mitigations = _load_json_list(mitigations_path)
    if mitigations:
        neo4j_client.run(_MITIGATION_MERGE, mitigations=mitigations)
        logger.info(f"[ontology] Loaded {len(mitigations)} mitigations into Neo4j.")
    else:
        logger.warning(
            f"[ontology] No mitigations at {mitigations_path}; skipping MITIGATES edges. "
            "Run scripts/build_ttp_label_space.py to generate it — without them the "
            "report's recommended actions have no grounded control to cite."
        )


def _load_json_list(path: str) -> list[dict]:
    """A generated ontology file, or [] when it has not been generated yet. Absent
    is a normal state (the STIX build is a separate step), so callers degrade with
    a warning rather than failing the whole load."""
    import json
    import os
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def get_mitigations_for_techniques(technique_ids: list[str], limit: int = 6) -> list[dict]:
    """
    ATT&CK mitigations covering the techniques this sample was predicted to use —
    the grounded source for the report's recommended actions.

    Ordered by how many of THIS sample's techniques each mitigation covers, so the
    control that addresses the most of what was actually found comes first, and
    capped: Mobile has 13 mitigations and a sample predicting a dozen techniques
    would otherwise pull nearly all of them, which is a list, not a recommendation.

    Falls back to the generated JSON when Neo4j is unreachable, matching
    get_technique_context — a dead graph must not silently empty the section.
    Returns [] if neither source has them, and the caller keeps its existing
    behaviour rather than printing an empty heading.
    """
    if not technique_ids:
        return []
    query = """
    MATCH (m:Mitigation)-[:MITIGATES]->(t:Technique)
    WHERE t.technique_id IN $ids
    WITH m, collect(DISTINCT t.technique_id) AS covered
    RETURN m.mitigation_id AS mitigation_id, m.name AS name,
           m.description AS description, covered AS covers
    ORDER BY size(covered) DESC, m.mitigation_id
    LIMIT $limit
    """
    try:
        res = neo4j_client.run(query, ids=technique_ids, limit=limit)
        if res:
            return res
    except Exception as e:
        logger.debug(f"[ontology] mitigation query fallback ({e}); using local JSON.")

    wanted = set(technique_ids)
    rows = []
    for m in _load_json_list("data/ontology/technique_mitigations.json"):
        covers = sorted(wanted.intersection(m.get("technique_ids") or []))
        if covers:
            rows.append({
                "mitigation_id": m["mitigation_id"],
                "name": m.get("name", ""),
                "description": m.get("description", "") or "",
                "covers": covers,
            })
    rows.sort(key=lambda r: (-len(r["covers"]), r["mitigation_id"]))
    return rows[:limit]


def get_technique_context(technique_ids: list[str]) -> list[dict]:
    """
    Retrieves ontology facts for a list of technique IDs — this is what
    GraphRAG grounds its report language in, instead of letting the LLM
    invent MITRE descriptions from memory (which risks subtle inaccuracy).
    """
    query = """
    MATCH (t:Technique)-[:BELONGS_TO_TACTIC]->(ta:Tactic)
    WHERE t.technique_id IN $ids
    RETURN t.technique_id AS technique_id, t.name AS name,
           t.description AS description, ta.name AS tactic
    """
    try:
        res = neo4j_client.run(query, ids=technique_ids)
        if res:
            return res
    except Exception as e:
        logger.debug(f"[ontology] Neo4j query fallback ({e}); using local JSON ontology.")

    techniques = load_full_technique_ontology("data/ontology/mobile_techniques.json")
    t_map = {t["technique_id"]: t for t in techniques}
    results = []
    for tid in technique_ids:
        if tid in t_map:
            t = t_map[tid]
            results.append({
                "technique_id": t["technique_id"],
                "name": t.get("name", ""),
                "description": t.get("description", "") or "",
                "tactic": t.get("tactic", "") or "Unknown",
            })
    return results


def graph_health() -> dict:
    """
    Whether Neo4j is reachable and actually holds the ontology, for /health and
    for the startup check.

    Worth stating why this exists: every graph caller swallows its own connection
    error and degrades quietly — lookup_signature() falls back to a process-local
    dict, find_related_samples() and get_threat_landscape() return empty, and
    get_technique_context() (above) falls through to the local JSON. Those are the
    right behaviours individually; together they mean a dead database looks exactly
    like a clean sample with no correlations. Nothing in the running system tells
    anyone otherwise, which is how a container that had been stopped for 43 minutes
    went unnoticed. This is the one place that reports the difference.

    Reachable-but-empty is called out separately from unreachable: it is the state
    after a fresh `docker compose up` without load_ontology.py, and it silently
    ungrounds every report rather than failing anything.

    Never raises.
    """
    query = """
    MATCH (:Technique)-[:BELONGS_TO_TACTIC]->(:Tactic)
    WITH count(*) AS grounded
    OPTIONAL MATCH (s:Sample)
    RETURN grounded, count(s) AS samples
    """
    try:
        row = neo4j_client.run(query)[0]
    except Exception as e:
        return {
            "reachable": False,
            "grounded_techniques": 0,
            "cached_samples": 0,
            "detail": f"{type(e).__name__}: {e}. Start it with: docker compose up -d",
        }

    grounded, samples = row["grounded"], row["samples"]
    if grounded == 0:
        detail = ("connected, but no grounded techniques — reports will fall back to "
                  "the local JSON ontology. Run: python scripts/load_ontology.py")
    else:
        detail = f"{grounded} grounded techniques, {samples} cached samples"
    return {
        "reachable": True,
        "grounded_techniques": grounded,
        "cached_samples": samples,
        "detail": detail,
    }

