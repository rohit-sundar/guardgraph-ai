"""
Hot-path deterministic cache: SHA-256 / certificate lookup against known
signature nodes in Neo4j. This is the "under 50ms for a cache hit" path
from the design doc — a great demo beat ("watch how fast known malware
resolves") if you pre-populate a few signature nodes for your demo samples.
"""
from app.graph.neo4j_client import neo4j_client


def lookup_signature(sha256: str) -> dict | None:
    query = """
    MATCH (s:Sample {sha256: $sha256})
    OPTIONAL MATCH (s)-[:CLASSIFIED_AS_FAMILY]->(f:MalwareFamily)
    OPTIONAL MATCH (s)-[r:MAPS_TO_TECHNIQUE]->(t:Technique)
    RETURN s.sha256 AS sha256,
           f.name AS family,
           s.risk_score AS base_score,
           s.narrative AS narrative,
           s.limitations AS limitations,
           collect(DISTINCT CASE WHEN t IS NULL THEN NULL
                   ELSE {technique_id: t.technique_id, probability: r.probability} END) AS ttps
    """
    try:
        rows = neo4j_client.run(query, sha256=sha256)
    except Exception:
        # Neo4j not reachable (e.g. Docker not up) — degrade to cold path.
        return None
    # Gate on SHA-256 presence (the Sample node), NOT on family — the family
    # classifier is often untrained in the prototype so predicted_family may
    # be None even after a successful cold-path run. Gating on family caused
    # every second request to fall back to cold path (cache never hit).
    if not rows or rows[0].get("sha256") is None:
        return None
    row = rows[0]
    # Rebuild the technique_id -> probability map (only bare IDs used to be
    # stored, so the hot path had to return predicted_ttps={} instead of the
    # real map).
    row["ttps"] = {
        t["technique_id"]: t.get("probability")
        for t in (row.get("ttps") or [])
        if t and t.get("technique_id")
    }
    return row


def store_signature(sha256: str, family: str, risk_score: float, ttps: dict[str, float], narrative: str = "", limitations: list[str] = None):
    """
    Call this after a cold-path analysis completes, so future uploads of
    the same sample (or re-uploads during a campaign) hit the fast path.

    ttps carries technique_id -> confidence so the hot path can return the
    real predicted-TTP map (previously only bare IDs were persisted).
    """
    if limitations is None:
        limitations = []

    query = """
    MERGE (s:Sample {sha256: $sha256})
    SET s.risk_score = $risk_score,
        s.narrative = $narrative,
        s.limitations = $limitations
    MERGE (f:MalwareFamily {name: $family})
    MERGE (s)-[:CLASSIFIED_AS_FAMILY]->(f)
    WITH s
    UNWIND $ttps AS ttp
    MERGE (t:Technique {technique_id: ttp.technique_id})
    MERGE (s)-[r:MAPS_TO_TECHNIQUE]->(t)
    SET r.probability = ttp.probability
    """
    try:
        neo4j_client.run(
            query,
            sha256=sha256,
            family=family,
            risk_score=risk_score,
            ttps=[{"technique_id": k, "probability": v} for k, v in ttps.items()],
            narrative=narrative,
            limitations=limitations
        )
    except Exception:
        # Neo4j not reachable — skip caching silently rather than crashing.
        pass
