"""
Hot-path deterministic cache: SHA-256 / certificate lookup against known
signature nodes in Neo4j. This is the "under 50ms for a cache hit" path
from the design doc — a great demo beat ("watch how fast known malware
resolves") if you pre-populate a few signature nodes for your demo samples.
"""
from app.graph.neo4j_client import neo4j_client


_MEMORY_CACHE: dict[str, dict] = {}


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
        if rows and rows[0].get("sha256") is not None:
            row = rows[0]
            row["ttps"] = {
                t["technique_id"]: t.get("probability")
                for t in (row.get("ttps") or [])
                if t and t.get("technique_id")
            }
            return row
    except Exception:
        pass

    # In-memory cache fallback
    return _MEMORY_CACHE.get(sha256)


def store_signature(sha256: str, family: str, risk_score: float, ttps: dict[str, float], narrative: str = "", limitations: list[str] = None, *, signature_yara_data: dict | None = None, permissions: list[str] | None = None, risk_components: dict | None = None, obfuscation_data: dict | None = None, package_name: str | None = None, c2_indicators: list[str] | None = None, cert_thumbprint: str | None = None):
    """
    Call this after a cold-path analysis completes, so future uploads of
    the same sample (or re-uploads during a campaign) hit the fast path.

    ttps carries technique_id -> confidence so the hot path can return the
    real predicted-TTP map (previously only bare IDs were persisted).
    """
    if limitations is None:
        limitations = []
    # Sample nodes carry several string properties (limitations, narrative,
    # risk_score, sha256) and Neo4j Browser's default node caption picks
    # whichever sorts first alphabetically when there's no obvious one —
    # which used to be a random line out of `limitations`. "app_name" sorts
    # before all of those, so it wins the caption without any manual Browser
    # config. Falls back to the sha256 when the manifest didn't parse.
    app_name = package_name or sha256

    # Always save to memory cache
    _MEMORY_CACHE[sha256] = {
        "sha256": sha256,
        "family": family,
        "base_score": risk_score,
        "ttps": ttps,
        "narrative": narrative,
        "limitations": limitations,
        "signature_yara_data": signature_yara_data,
        "permissions": permissions or [],
        "risk_components": risk_components or {},
        "obfuscation_data": obfuscation_data,
        "package_name": package_name,
        "c2_indicators": c2_indicators or [],
        "cert_thumbprint": cert_thumbprint,
    }

    # Three separate statements rather than one query chaining UNWIND $ttps then
    # UNWIND $c2_indicators: an UNWIND over an empty list drops every row after
    # it for the rest of that query (ttps is legitimately {} whenever the
    # classifier evidence gate withholds a verdict), which would silently skip
    # the C2 MERGE too if it came after the ttps UNWIND in the same query.
    # Isolating each write means an empty ttps or c2 list only skips its own
    # statement, not later ones.
    base_query = """
    MERGE (s:Sample {sha256: $sha256})
    SET s.risk_score = $risk_score,
        s.narrative = $narrative,
        s.limitations = $limitations,
        s.app_name = $app_name
    MERGE (f:MalwareFamily {name: $family})
    MERGE (s)-[:CLASSIFIED_AS_FAMILY]->(f)
    """
    ttps_query = """
    MATCH (s:Sample {sha256: $sha256})
    UNWIND $ttps AS ttp
    MERGE (t:Technique {technique_id: ttp.technique_id})
    MERGE (s)-[r:MAPS_TO_TECHNIQUE]->(t)
    SET r.probability = ttp.probability
    """
    # C2Indicator nodes are keyed on the already-typed indicator string itself
    # (e.g. "firebase:evil.firebaseio.com") from apk_static.extract_c2_indicators —
    # two samples sharing infrastructure MERGE onto the same node, which is what
    # find_related_samples() pivots on.
    c2_query = """
    MATCH (s:Sample {sha256: $sha256})
    UNWIND $c2_indicators AS c2
    MERGE (ci:C2Indicator {value: c2})
    MERGE (s)-[:CONTACTS]->(ci)
    """
    # Certificate reuse across nominally different packages/samples is a strong
    # actor/campaign signal — malware families routinely re-sign variants with
    # the same (often self-signed) key rather than re-generating one per build.
    cert_query = """
    MATCH (s:Sample {sha256: $sha256})
    MERGE (c:Certificate {thumbprint: $cert_thumbprint})
    MERGE (s)-[:SIGNED_WITH]->(c)
    """
    try:
        neo4j_client.run(
            base_query,
            sha256=sha256,
            family=family,
            risk_score=risk_score,
            narrative=narrative,
            limitations=limitations,
            app_name=app_name,
        )
        if ttps:
            neo4j_client.run(
                ttps_query,
                sha256=sha256,
                ttps=[{"technique_id": k, "probability": v} for k, v in ttps.items()],
            )
        if c2_indicators:
            neo4j_client.run(c2_query, sha256=sha256, c2_indicators=c2_indicators)
        if cert_thumbprint:
            neo4j_client.run(cert_query, sha256=sha256, cert_thumbprint=cert_thumbprint)
    except Exception:
        # Neo4j not reachable — skip Neo4j write silently rather than crashing.
        pass


def find_related_samples(
    technique_ids: list[str],
    c2_indicators: list[str],
    exclude_sha256: str,
    limit: int = 8,
    cert_thumbprint: str | None = None,
) -> list[dict]:
    """
    Correlates the current sample against previously cached ones via shared
    MITRE techniques, shared C2 infrastructure, and/or a reused signing
    certificate — the graph-native query a flat JSON cache can't answer
    cheaply. Works from the CURRENT analysis's signals directly (not a
    self-lookup), so it also surfaces matches on a cold-path run before this
    sample itself has been stored.

    Returns entries merged across all signals, sorted by total overlap, each:
    {sha256, app_name, family, risk_score, shared_techniques, shared_c2,
    shared_cert}. shared_cert is the reused thumbprint, or None.
    """
    if not technique_ids and not c2_indicators and not cert_thumbprint:
        return []

    by_sha: dict[str, dict] = {}

    def _merge(rows: list[dict], key: str) -> None:
        for row in rows:
            sha = row["sha256"]
            entry = by_sha.setdefault(sha, {
                "sha256": sha,
                "app_name": row.get("app_name") or sha,
                "family": row.get("family"),
                "risk_score": row.get("risk_score"),
                "shared_techniques": [],
                "shared_c2": [],
                "shared_cert": None,
            })
            entry[key] = row.get(key) or ([] if key != "shared_cert" else None)

    try:
        if technique_ids:
            tech_rows = neo4j_client.run(
                """
                UNWIND $technique_ids AS tid
                MATCH (t:Technique {technique_id: tid})<-[:MAPS_TO_TECHNIQUE]-(other:Sample)
                WHERE other.sha256 <> $exclude_sha256
                WITH other, collect(DISTINCT tid) AS shared_techniques
                OPTIONAL MATCH (other)-[:CLASSIFIED_AS_FAMILY]->(f:MalwareFamily)
                RETURN other.sha256 AS sha256, other.app_name AS app_name,
                       f.name AS family, other.risk_score AS risk_score,
                       shared_techniques
                """,
                technique_ids=technique_ids, exclude_sha256=exclude_sha256,
            )
            _merge(tech_rows, "shared_techniques")

        if c2_indicators:
            c2_rows = neo4j_client.run(
                """
                UNWIND $c2_indicators AS c2
                MATCH (ci:C2Indicator {value: c2})<-[:CONTACTS]-(other:Sample)
                WHERE other.sha256 <> $exclude_sha256
                WITH other, collect(DISTINCT c2) AS shared_c2
                OPTIONAL MATCH (other)-[:CLASSIFIED_AS_FAMILY]->(f:MalwareFamily)
                RETURN other.sha256 AS sha256, other.app_name AS app_name,
                       f.name AS family, other.risk_score AS risk_score,
                       shared_c2
                """,
                c2_indicators=c2_indicators, exclude_sha256=exclude_sha256,
            )
            _merge(c2_rows, "shared_c2")

        if cert_thumbprint:
            cert_rows = neo4j_client.run(
                """
                MATCH (c:Certificate {thumbprint: $cert_thumbprint})<-[:SIGNED_WITH]-(other:Sample)
                WHERE other.sha256 <> $exclude_sha256
                OPTIONAL MATCH (other)-[:CLASSIFIED_AS_FAMILY]->(f:MalwareFamily)
                RETURN other.sha256 AS sha256, other.app_name AS app_name,
                       f.name AS family, other.risk_score AS risk_score,
                       $cert_thumbprint AS shared_cert
                """,
                cert_thumbprint=cert_thumbprint, exclude_sha256=exclude_sha256,
            )
            _merge(cert_rows, "shared_cert")
    except Exception:
        return []

    def _weight(r: dict) -> int:
        # A reused signing certificate is much stronger evidence of common
        # authorship than one shared technique, so it outweighs the others
        # in the sort rather than counting as a single overlap point.
        return (
            len(r["shared_techniques"]) + len(r["shared_c2"])
            + (5 if r["shared_cert"] else 0)
        )

    results = list(by_sha.values())
    results.sort(key=_weight, reverse=True)
    return results[:limit]


def get_threat_landscape(limit: int = 30) -> dict:
    """
    Cytoscape-ready snapshot of the correlation graph for the "Threat
    Landscape" UI view — the whole-graph picture find_related_samples()
    only shows per-pair. Pulls the `limit` highest-risk cached Sample nodes
    and their family/technique/C2/certificate neighborhood.

    Returns {"nodes": [...], "edges": [...]} in Cytoscape's
    {data: {...}} element shape, or empty lists if Neo4j is unreachable.
    """
    try:
        rows = neo4j_client.run(
            """
            MATCH (s:Sample)
            WITH s ORDER BY coalesce(s.risk_score, 0) DESC LIMIT $limit
            OPTIONAL MATCH (s)-[:CLASSIFIED_AS_FAMILY]->(f:MalwareFamily)
            OPTIONAL MATCH (s)-[:MAPS_TO_TECHNIQUE]->(t:Technique)
            OPTIONAL MATCH (s)-[:CONTACTS]->(c2:C2Indicator)
            OPTIONAL MATCH (s)-[:SIGNED_WITH]->(cert:Certificate)
            RETURN s.sha256 AS sha256, s.app_name AS app_name,
                   s.risk_score AS risk_score, f.name AS family,
                   collect(DISTINCT {id: t.technique_id, name: t.name}) AS techniques,
                   collect(DISTINCT c2.value) AS c2,
                   cert.thumbprint AS cert
            """,
            limit=limit,
        )
    except Exception:
        return {"nodes": [], "edges": []}

    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    def _add_node(node_id: str, label: str, node_type: str) -> None:
        if node_id not in nodes:
            nodes[node_id] = {"data": {"id": node_id, "label": label, "type": node_type}}

    def _add_edge(source: str, target: str, label: str) -> None:
        edges.append({"data": {"id": f"{source}->{target}:{label}", "source": source, "target": target, "label": label}})

    for row in rows:
        sha = row["sha256"]
        sample_id = f"sample:{sha}"
        _add_node(sample_id, row.get("app_name") or sha[:12], "Sample")

        if row.get("family"):
            family_id = f"family:{row['family']}"
            _add_node(family_id, row["family"], "MalwareFamily")
            _add_edge(sample_id, family_id, "CLASSIFIED_AS_FAMILY")

        for tech in row.get("techniques") or []:
            if not tech or not tech.get("id"):
                continue
            tech_id = f"technique:{tech['id']}"
            _add_node(tech_id, tech.get("name") or tech["id"], "Technique")
            _add_edge(sample_id, tech_id, "MAPS_TO_TECHNIQUE")

        for c2 in row.get("c2") or []:
            if not c2:
                continue
            c2_id = f"c2:{c2}"
            _add_node(c2_id, c2, "C2Indicator")
            _add_edge(sample_id, c2_id, "CONTACTS")

        if row.get("cert"):
            cert_id = f"cert:{row['cert']}"
            _add_node(cert_id, row["cert"][:16] + "...", "Certificate")
            _add_edge(sample_id, cert_id, "SIGNED_WITH")

    return {"nodes": list(nodes.values()), "edges": edges}

