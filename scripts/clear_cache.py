import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.graph.neo4j_client import neo4j_client

def main():
    print("Deleting cached Sample nodes from Neo4j...")
    neo4j_client.run("MATCH (n:Sample) DETACH DELETE n")
    print("Deleted all Sample cache nodes.")

if __name__ == "__main__":
    main()
