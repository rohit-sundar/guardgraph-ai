"""
GuardGraph AI — Loader script
Owner: Sar

Loads the signature dictionary (02_signature_dictionary.json) into Neo4j as
Behavior / Technique / Tactic nodes and relationships.

Setup:
    pip install neo4j
    export NEO4J_URI="neo4j+s://<your-aura-instance>.databases.neo4j.io"
    export NEO4J_USER="neo4j"
    export NEO4J_PASSWORD="<your-password>"

Run:
    python 03_load_signature_dict.py
"""

import json
import os
from dotenv import load_dotenv
from neo4j import GraphDatabase

load_dotenv()  # reads .env file in the same folder, if present

URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
USER = os.environ.get("NEO4J_USER", "neo4j")
PASSWORD = os.environ.get("NEO4J_PASSWORD", "password")

CYPHER_UPSERT = """
UNWIND $indicators AS ind
MERGE (b:Behavior {behavior_id: ind.behavior_id})
  ON CREATE SET b.label = ind.behavior_label, b.category = ind.category

// signature node (API, permission, or string) — labeled generically as Indicator here,
// tag with match_type so you can split into :API / :Permission / :StringLiteral later if needed
MERGE (sig:Indicator {signature: ind.signature})
  ON CREATE SET sig.match_type = ind.match_type
MERGE (sig)-[:INDICATES_BEHAVIOR {severity_weight: ind.severity_weight}]->(b)

FOREACH (perm IN ind.related_permissions |
  MERGE (p:Permission {name: perm})
  MERGE (p)-[:APK_REQUESTS_PERMISSION]->(b)
)

FOREACH (tech IN ind.technique_ids |
  MERGE (t:Technique {technique_id: tech})
  MERGE (b)-[:BEHAVIOR_MAPS_TO_TTP]->(t)
)

FOREACH (tac IN ind.tactic_ids |
  MERGE (ta:Tactic {tactic_id: tac})
  FOREACH (tech IN ind.technique_ids |
    MERGE (t2:Technique {technique_id: tech})
    MERGE (t2)-[:BELONGS_TO_TACTIC]->(ta)
  )
)
"""


def load_signature_dictionary(json_path: str):
    with open(json_path, "r") as f:
        data = json.load(f)

    indicators = data["indicators"]
    driver = GraphDatabase.driver(URI, auth=(USER, PASSWORD))

    with driver.session() as session:
        session.run(CYPHER_UPSERT, indicators=indicators)
        print(f"Loaded {len(indicators)} indicators into Neo4j.")

    driver.close()


if __name__ == "__main__":
    load_signature_dictionary("02_signature_dictionary.json")