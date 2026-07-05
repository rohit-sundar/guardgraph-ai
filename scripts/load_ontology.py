"""
Run this once after Neo4j is up to load the starter MITRE ATT&CK Mobile
ontology. Extend app/graph/ontology.py's STARTER_TECHNIQUES list (or wire
in the full ATT&CK Mobile STIX bundle) before treating this as complete —
five techniques is enough to demo GraphRAG grounding, not enough for
production coverage.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.graph.ontology import load_starter_ontology

if __name__ == "__main__":
    load_starter_ontology()
    print("Starter ontology loaded into Neo4j.")
