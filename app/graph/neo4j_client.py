"""
Thin Neo4j driver wrapper. Deliberately not an ORM — Cypher queries are
kept explicit and colocated with their purpose (cache.py, ontology.py)
rather than hidden behind abstraction, since query correctness matters
more than DRY-ness for a graph schema this early.
"""
from neo4j import GraphDatabase

from app.core.config import settings


class Neo4jClient:
    def __init__(self):
        self._driver = None

    def connect(self):
        try:
            self._driver = GraphDatabase.driver(
                settings.neo4j_uri,
                auth=(settings.neo4j_user, settings.neo4j_password),
            )
        except Exception as e:
            # Store None so callers can check is_connected() cheaply.
            self._driver = None
            raise RuntimeError(
                f"Neo4j connection failed ({settings.neo4j_uri}): {e}. "
                "Start Neo4j with: docker compose up -d"
            ) from e

    def close(self):
        if self._driver:
            self._driver.close()

    def run(self, query: str, **params):
        if self._driver is None:
            self.connect()  # raises RuntimeError if Neo4j is unreachable
        with self._driver.session() as session:
            result = session.run(query, **params)
            return [record.data() for record in result]


neo4j_client = Neo4jClient()
