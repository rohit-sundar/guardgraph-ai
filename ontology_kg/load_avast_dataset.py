"""
GuardGraph AI — Day 3: Load Avast-CTU malware family/hash data into Neo4j
Owner: Sar

Handles two possible layouts:
  A) A single metadata CSV with columns: sha256, classification_family/family,
     classification_type/type, date
  B) A directory of per-sample JSON reports, where each file is named
     <sha256>.json and contains family/type fields somewhere in the report

Run discovery first:
    find . -maxdepth 3 | head -50
to see which layout you actually have, then set MODE below accordingly.

Setup:
    pip install neo4j pandas

    export NEO4J_URI="neo4j+s://<your-aura-instance>.databases.neo4j.io"
    export NEO4J_USER="neo4j"
    export NEO4J_PASSWORD="<your-password>"

Run:
    python 05_load_avast_dataset.py --mode csv --path /path/to/labels.csv --limit 300
    python 05_load_avast_dataset.py --mode json_dir --path /path/to/reports_dir --limit 300
"""

import argparse
import json
import os
import glob
from dotenv import load_dotenv
from neo4j import GraphDatabase

load_dotenv()  # reads .env file in the same folder, if present

URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
USER = os.environ.get("NEO4J_USER", "neo4j")
PASSWORD = os.environ.get("NEO4J_PASSWORD", "password")

CYPHER_LOAD_SAMPLES = """
UNWIND $samples AS s
MERGE (sample:Sample {sha256: s.sha256})
  ON CREATE SET sample.first_seen = s.date
MERGE (fam:MalwareFamily {name: s.family})
  ON CREATE SET fam.malware_type = s.malware_type
MERGE (sample)-[:CLASSIFIED_AS_FAMILY]->(fam)
"""


def load_from_csv(path: str, limit: int):
    import pandas as pd
    df = pd.read_csv(path)

    # normalize column names — adjust these mappings if your actual CSV headers differ
    colmap = {}
    for col in df.columns:
        lc = col.lower()
        if "sha256" in lc:
            colmap[col] = "sha256"
        elif "family" in lc:
            colmap[col] = "family"
        elif "type" in lc:
            colmap[col] = "malware_type"
        elif "date" in lc:
            colmap[col] = "date"
    df = df.rename(columns=colmap)

    required = {"sha256", "family", "malware_type"}
    missing = required - set(df.columns)
    if missing:
        print(f"WARNING: CSV is missing expected columns {missing}.")
        print(f"Actual columns found: {list(df.columns)}")
        print("Open the CSV and check the real header names, then adjust colmap above.")
        return []

    if "date" not in df.columns:
        df["date"] = None

    df = df.head(limit)
    return df[["sha256", "family", "malware_type", "date"]].to_dict("records")


def load_from_json_dir(path: str, limit: int):
    """Fallback: scan individual report JSONs and pull out likely metadata fields."""
    samples = []
    files = glob.glob(os.path.join(path, "**", "*.json"), recursive=True)[:limit]

    for fpath in files:
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                report = json.load(f)
        except Exception as e:
            print(f"Skipping {fpath}: {e}")
            continue

        # sha256 usually derivable from filename or a nested 'target'/'info' field —
        # adjust these lookups once you've inspected one real report file
        sha256 = os.path.splitext(os.path.basename(fpath))[0]
        family = (
            report.get("classification_family")
            or report.get("family")
            or report.get("info", {}).get("family")
        )
        malware_type = (
            report.get("classification_type")
            or report.get("type")
            or report.get("info", {}).get("category")
        )
        date = report.get("date") or report.get("info", {}).get("started")

        if family:
            samples.append({
                "sha256": sha256,
                "family": family,
                "malware_type": malware_type or "unknown",
                "date": date,
            })

    if not samples:
        print("No family/type fields found in scanned JSONs.")
        print(f"Inspect one file manually, e.g.: cat {files[0] if files else '<no files found>'}")
        print("Then update the field lookups in load_from_json_dir().")

    return samples


def load_into_neo4j(samples: list):
    if not samples:
        print("Nothing to load.")
        return
    driver = GraphDatabase.driver(URI, auth=(USER, PASSWORD))
    with driver.session() as session:
        session.run(CYPHER_LOAD_SAMPLES, samples=samples)
    driver.close()
    print(f"Loaded {len(samples)} samples into Neo4j.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["csv", "json_dir"], required=True)
    parser.add_argument("--path", required=True)
    parser.add_argument("--limit", type=int, default=300, help="Keep this small for a hackathon demo seed set")
    args = parser.parse_args()

    if args.mode == "csv":
        samples = load_from_csv(args.path, args.limit)
    else:
        samples = load_from_json_dir(args.path, args.limit)

    load_into_neo4j(samples)