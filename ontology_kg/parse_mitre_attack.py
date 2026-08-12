"""
GuardGraph AI — Day 2: Load MITRE ATT&CK Mobile taxonomy into Neo4j
Owner: Sar

What this does:
  1. Reads the downloaded mobile-attack.json (STIX bundle)
  2. Extracts all Tactics (x-mitre-tactic objects)
  3. Extracts all Techniques (attack-pattern objects)
  4. Links each Technique to its Tactic(s) via kill_chain_phases
  5. Loads everything into Neo4j as :Tactic and :Technique nodes

Setup:
    pip install neo4j

    export NEO4J_URI="neo4j+s://<your-aura-instance>.databases.neo4j.io"
    export NEO4J_USER="neo4j"
    export NEO4J_PASSWORD="<your-password>"

Run:
    python 04_parse_mitre_attack.py /path/to/mobile-attack.json
"""

import json
import os
import sys
from dotenv import load_dotenv
from neo4j import GraphDatabase

load_dotenv()  # reads .env file in the same folder, if present

URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
USER = os.environ.get("NEO4J_USER", "neo4j")
PASSWORD = os.environ.get("NEO4J_PASSWORD", "password")


def get_external_id(stix_object, source_name="mitre-attack"):
    """STIX objects store their ATT&CK ID (e.g. T1636, TA0028) inside external_references."""
    for ref in stix_object.get("external_references", []):
        if ref.get("source_name") == source_name:
            return ref.get("external_id")
    return None


def parse_mitre_json(path: str):
    with open(path, "r", encoding="utf-8") as f:
        bundle = json.load(f)

    objects = bundle.get("objects", bundle) if isinstance(bundle, dict) else bundle

    tactics = {}       # shortname -> {tactic_id, name}
    techniques = []    # list of {technique_id, name, tactic_shortnames: [...]}

    for obj in objects:
        obj_type = obj.get("type")

        if obj_type == "x-mitre-tactic":
            tid = get_external_id(obj)
            if tid:
                tactics[obj.get("x_mitre_shortname")] = {
                    "tactic_id": tid,
                    "name": obj.get("name"),
                }

        elif obj_type == "attack-pattern":
            # skip deprecated/revoked techniques
            if obj.get("x_mitre_deprecated") or obj.get("revoked"):
                continue
            tech_id = get_external_id(obj)
            if not tech_id:
                continue
            phases = [
                kc.get("phase_name")
                for kc in obj.get("kill_chain_phases", [])
                if kc.get("kill_chain_name") == "mitre-mobile-attack"
            ]
            if phases:  # only keep techniques that are actually part of the Mobile matrix
                techniques.append({
                    "technique_id": tech_id,
                    "name": obj.get("name"),
                    "tactic_phases": phases,
                })

    print(f"Parsed {len(tactics)} tactics and {len(techniques)} mobile techniques.")
    return tactics, techniques


CYPHER_LOAD_TACTICS = """
UNWIND $tactics AS tac
MERGE (t:Tactic {tactic_id: tac.tactic_id})
  ON CREATE SET t.name = tac.name, t.shortname = tac.shortname
"""

CYPHER_LOAD_TECHNIQUES = """
UNWIND $techniques AS tech
MERGE (t:Technique {technique_id: tech.technique_id})
  ON CREATE SET t.name = tech.name
WITH t, tech
UNWIND tech.tactic_shortnames AS shortname
MATCH (ta:Tactic {shortname: shortname})
MERGE (t)-[:BELONGS_TO_TACTIC]->(ta)
"""


def load_into_neo4j(tactics: dict, techniques: list):
    driver = GraphDatabase.driver(URI, auth=(USER, PASSWORD))

    tactic_rows = [
        {"tactic_id": v["tactic_id"], "name": v["name"], "shortname": k}
        for k, v in tactics.items()
    ]
    technique_rows = [
        {"technique_id": t["technique_id"], "name": t["name"], "tactic_shortnames": t["tactic_phases"]}
        for t in techniques
    ]

    with driver.session() as session:
        session.run(CYPHER_LOAD_TACTICS, tactics=tactic_rows)
        session.run(CYPHER_LOAD_TECHNIQUES, techniques=technique_rows)

    driver.close()
    print("Loaded tactics and techniques into Neo4j.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python 04_parse_mitre_attack.py /path/to/mobile-attack.json")
        sys.exit(1)

    tactics, techniques = parse_mitre_json(sys.argv[1])
    load_into_neo4j(tactics, techniques)