"""
Run this once after Neo4j is up to load the MITRE ATT&CK Mobile ontology used for
GraphRAG grounding.

By default it loads the FULL Mobile technique/tactic set (from the STIX-derived
data/ontology/mobile_techniques.json, or the baked-in labels.py catalog fallback)
plus software->technique USES edges. Generate the STIX JSON first for full
coverage:

    python scripts/build_ttp_label_space.py
    python scripts/load_ontology.py           # full ontology (default)
    python scripts/load_ontology.py --starter # legacy 5-technique demo seed
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.graph.ontology import load_full_ontology, load_starter_ontology

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Load MITRE ATT&CK Mobile ontology into Neo4j.")
    ap.add_argument("--starter", action="store_true", help="Load only the legacy 5-technique seed.")
    args = ap.parse_args()

    if args.starter:
        load_starter_ontology()
        print("Starter ontology (5 techniques) loaded into Neo4j.")
    else:
        load_full_ontology()
        print("Full ATT&CK Mobile ontology loaded into Neo4j.")
