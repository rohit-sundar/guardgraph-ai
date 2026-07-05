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
        self._driver = GraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password),
        )

    def close(self):
        if self._driver:
            self._driver.close()

    def run(self, query: str, **params):
        if self._driver is None:
            self.connect()
        with self._driver.session() as session:
            result = session.run(query, **params)
            return [record.data() for record in result]


neo4j_client = Neo4jClient()
