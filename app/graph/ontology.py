"""
Loads a STARTER set of MITRE ATT&CK Mobile techniques as ontology nodes.
This is intentionally small — enough for GraphRAG to have real facts to
retrieve for your demo samples' predicted TTPs. Expand with the full
ATT&CK Mobile STIX bundle before anything beyond a prototype; see
scripts/load_ontology.py for where to plug that in.
"""
from app.graph.neo4j_client import neo4j_client

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


def load_starter_ontology():
    query = """
    UNWIND $techniques AS tech
    MERGE (t:Technique {technique_id: tech.technique_id})
    SET t.name = tech.name, t.description = tech.description
    MERGE (ta:Tactic {name: tech.tactic})
    MERGE (t)-[:BELONGS_TO_TACTIC]->(ta)
    """
    neo4j_client.run(query, techniques=STARTER_TECHNIQUES)


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
    return neo4j_client.run(query, ids=technique_ids)
