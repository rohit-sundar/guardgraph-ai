"""
Hot-path deterministic cache: SHA-256 / certificate lookup against known
signature nodes in Neo4j. This is the "under 50ms for a cache hit" path
from the design doc — a great demo beat ("watch how fast known malware
resolves") if you pre-populate a few signature nodes for your demo samples.
"""
import json

from loguru import logger

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
           s.record_json AS record_json,
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
            # Rehydrate the fields Neo4j cannot hold as native properties. Without
            # this the hot path returned a total score with every risk component
            # None, no permissions and no signature panel, while the cached
            # narrative in the same response described all of them — see
            # store_signature's record_json for why they are stored this way.
            row.update(_decode_record(row.pop("record_json", None), row["sha256"]))
            return row
        # Neo4j answered, and its answer is "no such sample". That is
        # AUTHORITATIVE — do not fall through to the in-memory cache below.
        # Falling through made scripts/clear_sample.py silently ineffective
        # against a running server: the Sample node was deleted, but this
        # process still held the record in _MEMORY_CACHE, so the next upload
        # kept hitting the cache and reported every static phase as "skipped —
        # known sample" while the operator watched a delete they had just run
        # do nothing. The memory cache exists to survive a Neo4j OUTAGE, which
        # is the except branch, not to outvote a successful query.
        _MEMORY_CACHE.pop(sha256, None)
        return None
    except Exception:
        # Neo4j is unreachable — this is the case the in-memory cache is for.
        return _MEMORY_CACHE.get(sha256)


# Fields that make a cached verdict re-renderable but have no sensible native Neo4j
# representation: nested dicts and lists-of-dicts, which the property graph cannot
# store (a property must be a primitive or a homogeneous array of primitives). They
# were previously kept ONLY in _MEMORY_CACHE, which dies with the process — so after
# a restart a cache hit served a score with every component blank.
_RECORD_FIELDS = (
    "risk_components",
    "obfuscation_data",
    "signature_yara_data",
    "permissions",
    "c2_indicators",
    "cert_thumbprint",
    "package_name",
    # Added after the first pass at this fix only covered score + YARA + basic
    # fields — a cache hit on a sample analysed after THAT commit but before THIS
    # one still went hollow on everything below, because these simply weren't in
    # the persisted record at all. "Cache hit" has to mean the full report comes
    # back, not "whatever subset happened to be covered when the fix was written."
    #
    # app_label/icon_phash/impersonation are deliberately NOT here: all three
    # derive from nothing but the Phase 1 ingestion that already re-runs on every
    # cache hit (to compute the sha256 for the lookup in the first place), so
    # recomputing them fresh is free — and strictly better than caching them,
    # since a fresh run picks up any update to the protected-brand reference
    # table immediately instead of replaying whatever it said at analysis time.
    # resolved_crypto/dcl/webview/native and grounding have no such shortcut —
    # the first needs the full CFG (not rebuilt on a cache hit), the second needs
    # an LLM call (which is the whole thing the cache exists to avoid) — so those
    # two must come from here.
    "resolved_crypto_configs",
    "resolved_dcl_targets",
    "resolved_webview_bridges",
    "resolved_native_bridges",
    "grounding",
    # Persisted opportunistically whenever a dynamic pass actually ran (cold
    # path, or a cache-hit request that explicitly asked for enable_dynamic)
    # — same reasoning as resolved_*/grounding above: no cheap way to
    # recompute it on a plain cache hit, since it needs the AVD.
    "dynamic_verification",
)


def _encode_record(payload: dict) -> str:
    """Serialises the non-primitive part of a cached verdict for a single property."""
    return json.dumps({k: payload.get(k) for k in _RECORD_FIELDS}, default=str)


def _decode_record(raw, sha256: str) -> dict:
    """
    Inverse of _encode_record. Returns {} for records written before this existed —
    those genuinely have no component breakdown to recover, and the caller reports
    the gap rather than substituting zeros.
    """
    if not raw:
        logger.debug(
            f"[cache] {sha256[:12]} predates record_json — component breakdown "
            "unavailable for this hot-path hit."
        )
        return {}
    try:
        decoded = json.loads(raw)
    except (TypeError, ValueError) as e:
        logger.warning(f"[cache] {sha256[:12]} has unreadable record_json: {e}")
        return {}
    return {k: v for k, v in decoded.items() if v is not None}


def store_signature(sha256: str, family: str, risk_score: float, ttps: dict[str, float], narrative: str = "", limitations: list[str] = None, *, signature_yara_data: dict | None = None, permissions: list[str] | None = None, risk_components: dict | None = None, obfuscation_data: dict | None = None, package_name: str | None = None, c2_indicators: list[str] | None = None, cert_thumbprint: str | None = None, resolved_crypto_configs: list[str] | None = None, resolved_dcl_targets: list[str] | None = None, resolved_webview_bridges: list[str] | None = None, resolved_native_bridges: list[str] | None = None, grounding: dict | None = None, dynamic_verification: dict | None = None):
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
        "resolved_crypto_configs": resolved_crypto_configs or [],
        "resolved_dcl_targets": resolved_dcl_targets or [],
        "resolved_webview_bridges": resolved_webview_bridges or [],
        "resolved_native_bridges": resolved_native_bridges or [],
        "grounding": grounding,
        # Persisted opportunistically whenever a dynamic pass actually ran
        # (cold path or a cache-hit that explicitly requested enable_dynamic)
        # — previously thrown away after every single response, so a cache
        # hit could never show dynamic findings from an earlier run. Rides
        # the same record_json blob as everything else here rather than
        # needing its own Cypher property.
        "dynamic_verification": dynamic_verification,
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
        s.app_name = $app_name,
        s.package_name = $package_name,
        s.record_json = $record_json,
        // Re-stamped on every store, not just creation, so re-analysing an
        // already-cached sample bumps it back to the top of the history list —
        // "most recently touched", not "first ever seen". Neo4j's own
        // timestamp() (epoch millis) rather than an app-side clock, so ordering
        // stays correct regardless of which machine wrote the record.
        s.analyzed_at = timestamp()
    // Only attach a family when one is actually known. This MERGE used to run
    // unconditionally, so an unknown family created a MalwareFamily node named
    // "" that every unattributed sample then hung off — a node asserting a
    // shared classification that does not exist. FOREACH is the idiomatic Cypher
    // conditional-write: the list is empty when $family is blank, so the body
    // never executes.
    FOREACH (_ IN CASE WHEN $family IS NULL OR trim($family) = '' THEN [] ELSE [1] END |
        MERGE (f:MalwareFamily {name: $family})
        MERGE (s)-[:CLASSIFIED_AS_FAMILY]->(f)
    )
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
    #
    # dynamically_confirmed distinguishes "this string appeared in the DEX"
    # (every row here) from the strictly stronger "a dynamic pass actually
    # observed the app contacting it" (network_confirmed, when a dynamic run
    # happened) — lets correlation queries ask for verified-live
    # infrastructure, not just string co-occurrence. `coalesce(..., false) OR`
    # rather than a plain overwrite: a later store_signature call without
    # fresh dynamic data (e.g. a static-only re-analysis) must never erase a
    # confirmation an earlier dynamic run already established.
    c2_query = """
    MATCH (s:Sample {sha256: $sha256})
    UNWIND $c2_indicators AS c2
    MERGE (ci:C2Indicator {value: c2})
    MERGE (s)-[r:CONTACTS]->(ci)
    SET r.dynamically_confirmed = coalesce(r.dynamically_confirmed, false) OR (c2 IN $confirmed_c2)
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
            package_name=package_name,
            record_json=_encode_record(_MEMORY_CACHE[sha256]),
        )
        if ttps:
            neo4j_client.run(
                ttps_query,
                sha256=sha256,
                ttps=[{"technique_id": k, "probability": v} for k, v in ttps.items()],
            )
        if c2_indicators:
            confirmed_c2 = (dynamic_verification or {}).get("network_confirmed") or []
            neo4j_client.run(
                c2_query, sha256=sha256, c2_indicators=c2_indicators, confirmed_c2=confirmed_c2
            )
        if cert_thumbprint:
            neo4j_client.run(cert_query, sha256=sha256, cert_thumbprint=cert_thumbprint)
    except Exception:
        # Neo4j not reachable — skip Neo4j write silently rather than crashing.
        pass


def record_feedback(sha256: str, verdict: str, note: str | None = None) -> bool:
    """
    Records an analyst's correction against an already-analysed sample — the
    first half of an active-learning loop. Does NOT retrain anything itself;
    scripts/export_feedback_for_training.py is the second half, turning
    recorded corrections into training-ready rows for samples whose original
    APK still exists in one of the curated corpora (uploaded APKs are never
    retained past a single request — see routes.py's tmp_dir cleanup — so a
    correction on an upload-only sample is recorded here but cannot always
    be turned back into a feature row; export_feedback_for_training.py says
    so explicitly rather than silently dropping it).

    `verdict` is the analyst's own label (e.g. "false_positive", "confirmed")
    — this project makes no assumption about the label vocabulary, it only
    persists what a human analyst records. Returns False (not found) rather
    than raising when no Sample node exists for sha256, since feedback can
    only correct an existing verdict, not create one out of nothing — the
    caller (the API endpoint) turns that into a 404.
    """
    found_in_memory = sha256 in _MEMORY_CACHE
    if found_in_memory:
        _MEMORY_CACHE[sha256]["analyst_verdict"] = verdict
        _MEMORY_CACHE[sha256]["analyst_note"] = note

    query = """
    MATCH (s:Sample {sha256: $sha256})
    SET s.analyst_verdict = $verdict,
        s.analyst_note = $note,
        s.analyst_feedback_at = timestamp()
    RETURN s.sha256 AS sha256
    """
    try:
        rows = neo4j_client.run(query, sha256=sha256, verdict=verdict, note=note)
        found_in_neo4j = bool(rows)
    except Exception as e:
        logger.warning(f"[cache] record_feedback: Neo4j write failed for {sha256[:12]}: {e}")
        found_in_neo4j = False

    return found_in_memory or found_in_neo4j


def list_feedback_samples() -> list[dict]:
    """
    Every Sample node an analyst has left feedback on — the read side of
    record_feedback, consumed by scripts/export_feedback_for_training.py.
    Not paginated: this project's analyst-feedback volume is expected to be
    small enough (one manual correction at a time) that a full scan is fine;
    add a LIMIT here if that stops being true.
    """
    query = """
    MATCH (s:Sample)
    WHERE s.analyst_verdict IS NOT NULL
    RETURN s.sha256 AS sha256, s.analyst_verdict AS verdict,
           s.analyst_note AS note, s.package_name AS package_name
    """
    try:
        return neo4j_client.run(query)
    except Exception as e:
        logger.warning(f"[cache] list_feedback_samples failed: {e}")
        return []


def list_recent_samples(limit: int = 30) -> list[dict]:
    """
    Summary rows for the Analysis History panel — most-recently-touched first.
    Deliberately does NOT decode record_json here: this powers a list view where
    the caller only needs sha256/name/family/score/band, and decoding every
    row's full component breakdown just to throw it away would be wasted work
    for what is meant to be a cheap listing query. Fetch the full record via
    lookup_signature(sha256) once a specific row is opened.
    """
    query = """
    MATCH (s:Sample)
    OPTIONAL MATCH (s)-[:CLASSIFIED_AS_FAMILY]->(f:MalwareFamily)
    WHERE s.risk_score IS NOT NULL
    RETURN s.sha256 AS sha256,
           s.app_name AS app_name,
           s.package_name AS package_name,
           f.name AS family,
           s.risk_score AS risk_score,
           s.analyzed_at AS analyzed_at
    // Cypher orders null as the largest value, so a bare `DESC` here put every
    // legacy record with no analyzed_at (bulk-seeded via populate.py, never
    // stamped) ahead of every genuinely recent one — a fresh analysis could
    // vanish past LIMIT behind hundreds of untimestamped rows. Sorting
    // "has a timestamp" first pushes null-timestamp rows to the back instead,
    // then DESC breaks ties among the ones that actually have a time.
    ORDER BY s.analyzed_at IS NULL, s.analyzed_at DESC
    LIMIT $limit
    """
    try:
        rows = neo4j_client.run(query, limit=limit)
    except Exception as e:
        logger.warning(f"[cache] list_recent_samples failed: {e}")
        return []
    return [r for r in rows if r.get("sha256")]


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
    shared_c2_confirmed, shared_cert}. shared_cert is the reused thumbprint,
    or None. shared_c2_confirmed is the subset of shared_c2 where a dynamic
    pass on THAT other sample actually observed it contacting the indicator
    (r.dynamically_confirmed on its own CONTACTS edge) — stronger evidence
    than merely sharing the string, since it proves the infrastructure was
    live and reachable at analysis time, not just present in the binary.
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
                "shared_c2_confirmed": [],
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
                MATCH (ci:C2Indicator {value: c2})<-[r:CONTACTS]-(other:Sample)
                WHERE other.sha256 <> $exclude_sha256
                WITH other, collect(DISTINCT c2) AS shared_c2,
                     // collect() silently drops nulls, which is what makes this
                     // work as a filter — Cypher has no SQL-style FILTER(WHERE...)
                     // clause on an aggregate.
                     collect(DISTINCT CASE WHEN coalesce(r.dynamically_confirmed, false) THEN c2 END) AS shared_c2_confirmed
                OPTIONAL MATCH (other)-[:CLASSIFIED_AS_FAMILY]->(f:MalwareFamily)
                RETURN other.sha256 AS sha256, other.app_name AS app_name,
                       f.name AS family, other.risk_score AS risk_score,
                       shared_c2, shared_c2_confirmed
                """,
                c2_indicators=c2_indicators, exclude_sha256=exclude_sha256,
            )
            _merge(c2_rows, "shared_c2")
            _merge(c2_rows, "shared_c2_confirmed")

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

