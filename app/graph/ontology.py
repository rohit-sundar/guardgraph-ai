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


def load_starter_ontology():
    """Legacy minimal seed (5 techniques). Kept for a zero-network smoke test."""
    neo4j_client.run(_TECHNIQUE_MERGE, techniques=STARTER_TECHNIQUES)


def load_full_ontology(
    techniques_path: str = "data/ontology/mobile_techniques.json",
    software_map_path: str = "data/ontology/software_technique_map.json",
):
    """
    Loads the full Mobile technique/tactic ontology plus software->technique edges.
    Falls back to the baked-in labels.py catalog for techniques when the STIX JSON
    has not been generated yet; skips software edges when that map is absent.
    """
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

    software = _load_software_map(software_map_path)
    if software:
        neo4j_client.run(_SOFTWARE_MERGE, software=software)
        logger.info(f"[ontology] Loaded {len(software)} software->technique maps into Neo4j.")
    else:
        logger.warning(
            f"[ontology] No software map at {software_map_path}; skipping USES edges. "
            "Run scripts/build_ttp_label_space.py to generate it."
        )


def _load_software_map(path: str) -> list[dict]:
    import json
    import os
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


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

