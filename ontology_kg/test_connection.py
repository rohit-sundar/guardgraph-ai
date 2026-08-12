"""
Minimal connection test — isolates whether this is a credentials problem
or a network/firewall problem.
Usage: python test_connection.py
"""
import os
from typing import Dict, List, Optional, Tuple

from dotenv import load_dotenv

try:
    from neo4j import GraphDatabase
except ImportError:  # pragma: no cover - defensive
    GraphDatabase = None

load_dotenv()


def build_connection_attempts(env: Optional[Dict[str, str]] = None) -> List[Tuple[str, str, str]]:
    env = env or os.environ

    local_uri = "bolt://localhost:7687"
    local_user = "neo4j"
    local_password = "changeme"

    attempts = [(local_uri, local_user, local_password)]

    env_uri = (env.get("NEO4J_URI") or "").strip()
    env_user = (env.get("NEO4J_USER") or "neo4j").strip()
    env_password = (env.get("NEO4J_PASSWORD") or "changeme").strip()

    if env_uri:
        attempts.append((env_uri, env_user, env_password))

    return attempts


def try_connect(attempts: List[Tuple[str, str, str]]) -> bool:
    last_error = None

    for index, (uri, user, password) in enumerate(attempts):
        print(f"Connecting to: {uri}")
        print(f"User: {user}")

        try:
            if GraphDatabase is None:
                raise RuntimeError("neo4j package is not installed. Install it with: pip install neo4j")

            driver = GraphDatabase.driver(uri, auth=(user, password))
            driver.verify_connectivity()
            print("SUCCESS: Connected to Neo4j.")
            driver.close()
            return True
        except Exception as e:
            last_error = e
            print(f"FAILED: {type(e).__name__}: {e}")
            if index < len(attempts) - 1:
                print("Trying fallback local Neo4j credentials...")

    if last_error is not None:
        print("All connection attempts failed.")
    return False


if __name__ == "__main__":
    attempts = build_connection_attempts()
    try_connect(attempts)