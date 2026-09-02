"""
Hot-path deterministic cache: SHA-256 / certificate lookup against known
signature nodes in Neo4j. This is the "under 50ms for a cache hit" path
from the design doc — a great demo beat ("watch how fast known malware
resolves") if you pre-populate a few signature nodes for your demo samples.
"""
import json

from loguru import logger

from app.analysis.apk_static import c2_host, is_benign_host
from app.analysis.dynamic_verification import is_harness_endpoint
from app.core.config import settings
from app.graph.neo4j_client import neo4j_client


_MEMORY_CACHE: dict[str, dict] = {}

# Above this many samples, a shared signing certificate stops being evidence of
# a common author and becomes evidence of a common build tool. Set from the
# observed distribution: plausible reuse clusters here run to 9 samples and
# below, while the two default-key clusters are 54 and 33.
MAX_SHARED_CERT_FOR_CORRELATION = 20


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
    # Phase 5.6 — the decompiled method bodies and the ATT&CK mappings drawn from
    # them. Both of the reasons above apply at once: decompilation needs the full
    # CFG, which the hot path deliberately does not rebuild, and the mapping needs
    # an LLM call, which is the cost the cache exists to avoid.
    "decompiled_methods",
    "code_technique_mappings",
    "code_mapping_checks",
    "code_mapping_note",
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



def observed_endpoints(dynamic_verification: dict | None, c2_indicators: list[str] | None) -> list[dict]:
    """
    Rows for the NetworkEndpoint write: every distinct host the sample was seen
    contacting at runtime, deduplicated and with harness traffic removed.

    Draws on both network_observed_all (raw sockets) and urls_accessed — the
    latter is where most host observations actually land, since every HTTP
    stack that resolves DNS first reports through the URL hook.

    statically_predicted marks the hosts that also appear in the static C2 set,
    which is what makes "predicted and then observed" answerable from the graph
    instead of only from a field inside record_json.
    """
    dv = dynamic_verification or {}
    if not dv.get("ran"):
        return []
    predicted = {h for h in (c2_host(c) for c in (c2_indicators or [])) if h}
    rows: dict[str, dict] = {}
    for value in list(dv.get("network_observed_all") or []) + list(dv.get("urls_accessed") or []):
        if is_harness_endpoint(value):
            continue
        host = c2_host(value)
        if not host:
            continue
        rows[host] = {
            "host": host,
            "known_benign": is_benign_host(host),
            "statically_predicted": host in predicted,
        }
    return list(rows.values())


def store_signature(sha256: str, family: str, risk_score: float, ttps: dict[str, float], narrative: str = "", limitations: list[str] = None, *, source: str = "operator", signature_yara_data: dict | None = None, permissions: list[str] | None = None, risk_components: dict | None = None, obfuscation_data: dict | None = None, package_name: str | None = None, c2_indicators: list[str] | None = None, cert_thumbprint: str | None = None, resolved_crypto_configs: list[str] | None = None, resolved_dcl_targets: list[str] | None = None, resolved_webview_bridges: list[str] | None = None, resolved_native_bridges: list[str] | None = None, grounding: dict | None = None, dynamic_verification: dict | None = None, decompiled_methods: list[dict] | None = None, code_technique_mappings: list[dict] | None = None, code_mapping_checks: dict | None = None, code_mapping_note: str = ""):
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
        # Phase 5.6. Stored as plain dicts (the caller dumps the pydantic models)
        # so the record blob stays JSON-serialisable like everything else here.
        "decompiled_methods": decompiled_methods or [],
        "code_technique_mappings": code_technique_mappings or [],
        "code_mapping_checks": code_mapping_checks,
        "code_mapping_note": code_mapping_note,
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
        s.analyzed_at = timestamp(),
        // How this sample got here. 'operator' (an upload through the UI/API)
        // or 'corpus' (a bulk load by the population scripts) — see
        // SAMPLE_SOURCE_* below and delete_sample, which will not drop a
        // corpus node.
        //
        // coalesce, so provenance is written once and never downgraded: a
        // corpus sample an operator later re-analyses stays 'corpus', because
        // the question this property answers is "may the history clear delete
        // this", and the answer for anything the knowledge base depends on is
        // no, regardless of who touched it last.
        s.source = coalesce(s.source, $source)
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
    # Endpoints the sample was actually observed contacting at runtime.
    #
    # These used to live only inside record_json, invisible to every graph
    # query: the graph held 46 C2Indicator nodes, all statically extracted,
    # while 71 distinct hosts observed live across the corpus had no node at
    # all — and static and dynamic turned out to find disjoint infrastructure
    # (zero overlap), so the observed set was the only record of where these
    # samples actually reach.
    #
    # A separate label, not C2Indicator: "the sample connected here" is an
    # observation, "this is attacker infrastructure" is an inference, and the
    # observed set legitimately includes SDK and CDN traffic. Conflating them
    # would put googleapis.com in the graph as a C2 node. known_benign carries
    # the triage judgement without overwriting the fact.
    endpoint_query = """
    MATCH (s:Sample {sha256: $sha256})
    UNWIND $endpoints AS ep
    MERGE (ne:NetworkEndpoint {host: ep.host})
    SET ne.known_benign = ep.known_benign
    MERGE (s)-[r:CONTACTED]->(ne)
    SET r.observed_at_runtime = true,
        r.statically_predicted = coalesce(r.statically_predicted, false) OR ep.statically_predicted,
        // Egress is firewalled during detonation (see
        // dynamic_analysis_require_network_isolation), so what is observed is
        // an attempt, not a completed session. Saying "contacted" without this
        // would overstate what the capture can actually support.
        r.egress_blocked_during_capture = $egress_blocked
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
            source=source,
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
        endpoints = observed_endpoints(dynamic_verification, c2_indicators)
        if endpoints:
            neo4j_client.run(
                endpoint_query,
                sha256=sha256,
                endpoints=endpoints,
                egress_blocked=bool(settings.dynamic_analysis_require_network_isolation),
            )
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


# How a Sample node got into the graph. Recorded so the Analysis History clear
# can tell an operator upload from a bulk corpus load — see
# routes.HISTORY_CLEAR_CORPUS_ALARM, which uses it as a tripwire for the
# pollution bug that once let "Clear" delete the knowledge base.
#
# Deliberately NOT a per-sample delete guard. The operator is entitled to clear
# anything they actually analysed, corpus sample included, because a cleared
# sample is one that will run the cold path on its next upload — which is the
# whole point of the button. Scale is what distinguishes an operator clearing
# their work from a polluted history wiping the corpus, and scale is a decision
# the endpoint can make and a single delete_sample call cannot.
SAMPLE_SOURCE_OPERATOR = "operator"   # uploaded through the UI or the API
SAMPLE_SOURCE_CORPUS = "corpus"       # bulk-loaded by scripts/populate_corpus.py


def delete_sample(sha256: str) -> bool:
    """Drops one cached verdict so the next upload of that APK runs the full cold
    path. Returns whether a node was actually removed.

    DETACH DELETE, so the sample's relationships go with it while the nodes on the
    other end (techniques, families, certificates, C2 indicators) survive — those
    are shared ontology and correlation vertices, and other samples still point at
    them. Also evicts the in-process copy, which would otherwise keep answering
    for a sample the graph no longer has (see lookup_signature).
    """
    _MEMORY_CACHE.pop(sha256, None)
    try:
        rows = neo4j_client.run(
            "MATCH (s:Sample {sha256: $sha256}) RETURN s.sha256 AS sha256", sha256=sha256
        )
        if not rows:
            return False
        neo4j_client.run("MATCH (s:Sample {sha256: $sha256}) DETACH DELETE s", sha256=sha256)
        return True
    except Exception as e:
        logger.warning(f"[cache] delete_sample failed for {sha256[:12]}: {e}")
        return False


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
                MATCH (c:Certificate {thumbprint: $cert_thumbprint})<-[:SIGNED_WITH]-(:Sample)
                // A signing key shared this widely is a builder default, not an
                // actor fingerprint, and correlating on it asserts a
                // relationship that does not exist. Measured on this corpus:
                // one key covers 54 samples spanning FluBot, Cerberus, SpyNote
                // and Alien, and its subject is CN=Android, O=Android,
                // android@android.com, self-signed — the AOSP test key, which
                // is public and which anyone can sign with. Android app certs
                // are self-generated with no CA above them, so a shared key
                // means a shared toolchain, never a shared author.
                WITH c, count(*) AS signed_total
                WHERE signed_total <= $max_shared_cert
                MATCH (c)<-[:SIGNED_WITH]-(other:Sample)
                WHERE other.sha256 <> $exclude_sha256
                OPTIONAL MATCH (other)-[:CLASSIFIED_AS_FAMILY]->(f:MalwareFamily)
                RETURN other.sha256 AS sha256, other.app_name AS app_name,
                       f.name AS family, other.risk_score AS risk_score,
                       $cert_thumbprint AS shared_cert
                """,
                cert_thumbprint=cert_thumbprint, exclude_sha256=exclude_sha256,
                max_shared_cert=MAX_SHARED_CERT_FOR_CORRELATION,
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




# ---------------------------------------------------------------------------
# Threat Landscape filtering
# ---------------------------------------------------------------------------
#
# The landscape view answers "what has this instance seen", but at corpus scale
# that is hundreds of samples and every family/technique/C2 node they touch — one
# hairball in which no individual question is answerable. The filters below exist
# so an analyst can ask the pivots the graph was built for: which packages belong
# to Cerberus, which packages talk to this C2 host, which share a signing key.
#
# All filtering happens in Cypher BEFORE the LIMIT. Filtering the already-limited
# top-30 client-side would mean "Cerberus" silently showed only the Cerberus
# samples that happen to be among the 30 highest-risk overall, which is a
# different and much more misleading answer than the one the analyst asked for.


def _landscape_bands() -> dict[str, tuple[float, float]]:
    """Verdict band edges, imported from the scoring module rather than restated.

    A sample whose report reads `high` must land in this filter's `high` bucket,
    and a second local copy of the numbers is how the two drift apart. Ranges are
    (exclusive lower, inclusive upper] to match _band_for's `<=` tests; the lowest
    band opens below zero so a 0.0 score falls inside it. Imported lazily to keep
    the graph layer free of a module-import dependency on the reports layer.
    """
    from app.reports.scoring import (
        BAND_LOW_CEILING, BAND_MEDIUM_CEILING,
        BAND_SUSPICIOUS_CEILING, BAND_HIGH_CEILING,
    )
    return {
        "low": (-1.0, BAND_LOW_CEILING),
        "medium": (BAND_LOW_CEILING, BAND_MEDIUM_CEILING),
        "suspicious": (BAND_MEDIUM_CEILING, BAND_SUSPICIOUS_CEILING),
        "high": (BAND_SUSPICIOUS_CEILING, BAND_HIGH_CEILING),
        "malicious": (BAND_HIGH_CEILING, 1000.0),
    }


# Shared by the element query and the count query so the two can never disagree
# about what "matched" means. Each clause is a no-op when its parameter is null,
# which is how "no filter selected" is expressed — filter groups AND with each
# other, while multiple values inside one group OR together (pick Cerberus and
# Anubis and you get both families, not their empty intersection).
#
# Pattern comprehensions rather than EXISTS{} subqueries: same result, and they
# keep working on the 4.x servers some deployments still point at.
_LANDSCAPE_FILTER = """
    ($families IS NULL OR size([(s)-[:CLASSIFIED_AS_FAMILY]->(f:MalwareFamily)
                                WHERE f.name IN $families | f]) > 0)
AND ($techniques IS NULL OR size([(s)-[:MAPS_TO_TECHNIQUE]->(t:Technique)
                                  WHERE t.technique_id IN $techniques | t]) > 0)
AND ($c2 IS NULL OR size([(s)-[:CONTACTS]->(ci:C2Indicator)
                          WHERE ci.value IN $c2 | ci]) > 0)
AND ($certificates IS NULL OR size([(s)-[:SIGNED_WITH]->(cr:Certificate)
                                    WHERE cr.thumbprint IN $certificates | cr]) > 0)
AND ($bands IS NULL OR any(b IN $bands
        WHERE coalesce(s.risk_score, 0.0) > b.lo AND coalesce(s.risk_score, 0.0) <= b.hi))
AND ($search IS NULL
     OR toLower(coalesce(s.package_name, '')) CONTAINS $search
     OR toLower(coalesce(s.app_name, '')) CONTAINS $search
     OR toLower(coalesce(s.sha256, '')) CONTAINS $search)
"""


def _landscape_params(
    families: list[str] | None,
    techniques: list[str] | None,
    c2: list[str] | None,
    certificates: list[str] | None,
    bands: list[str] | None,
    search: str | None,
) -> dict:
    """Normalises the public filter arguments into _LANDSCAPE_FILTER's parameters.

    An empty list means the same as no list — "the analyst cleared this filter",
    not "match nothing" — so both collapse to None and the clause switches off.
    An unrecognised band name is dropped rather than failing the request: the
    band vocabulary belongs to the scoring module and a stale bookmark naming a
    band that no longer exists should degrade to "no band filter", not a 500.
    """
    band_ranges = _landscape_bands()
    selected_bands = [
        {"lo": band_ranges[b][0], "hi": band_ranges[b][1]}
        for b in (bands or []) if b in band_ranges
    ]
    term = (search or "").strip().lower()
    return {
        "families": list(families) if families else None,
        "techniques": list(techniques) if techniques else None,
        "c2": list(c2) if c2 else None,
        "certificates": list(certificates) if certificates else None,
        "bands": selected_bands or None,
        "search": term or None,
    }


def get_landscape_facets() -> dict:
    """
    The filter options for the Threat Landscape view, each with the number of
    cached samples behind it — read off the graph itself rather than hardcoded,
    so a family or C2 host this instance has never seen never appears as a
    choice that returns nothing.

    Returns empty option lists (not an error) when Neo4j is unreachable, matching
    how every other reader in this module degrades.
    """
    empty = {
        "families": [], "techniques": [], "c2": [], "certificates": [],
        "bands": [], "total_samples": 0,
    }

    try:
        total = neo4j_client.run("MATCH (s:Sample) RETURN count(s) AS total")[0]["total"]

        family_rows = neo4j_client.run("""
            MATCH (s:Sample)-[:CLASSIFIED_AS_FAMILY]->(f:MalwareFamily)
            RETURN f.name AS value, count(DISTINCT s) AS count
            ORDER BY count DESC, value ASC
        """)
        technique_rows = neo4j_client.run("""
            MATCH (s:Sample)-[:MAPS_TO_TECHNIQUE]->(t:Technique)
            RETURN t.technique_id AS value, t.name AS name, count(DISTINCT s) AS count
            ORDER BY count DESC, value ASC
        """)
        c2_rows = neo4j_client.run("""
            MATCH (s:Sample)-[r:CONTACTS]->(ci:C2Indicator)
            RETURN ci.value AS value, count(DISTINCT s) AS count,
                   // A host some dynamic run actually observed traffic to is
                   // worth pivoting on ahead of one that was only a string in
                   // the DEX, so the distinction rides along to the UI.
                   sum(CASE WHEN r.dynamically_confirmed THEN 1 ELSE 0 END) > 0 AS confirmed
            ORDER BY count DESC, value ASC
        """)
        cert_rows = neo4j_client.run("""
            MATCH (s:Sample)-[:SIGNED_WITH]->(c:Certificate)
            RETURN c.thumbprint AS value, count(DISTINCT s) AS count
            ORDER BY count DESC, value ASC
        """)
        score_rows = neo4j_client.run(
            "MATCH (s:Sample) RETURN coalesce(s.risk_score, 0.0) AS score"
        )
    except Exception:
        return empty

    band_ranges = _landscape_bands()
    band_counts = {name: 0 for name in band_ranges}
    for row in score_rows:
        score = row.get("score") or 0.0
        for name, (lo, hi) in band_ranges.items():
            if lo < score <= hi:
                band_counts[name] += 1
                break

    return {
        "families": [
            {"value": r["value"], "label": r["value"], "count": r["count"]}
            for r in family_rows if r.get("value")
        ],
        "techniques": [
            # Technique nodes MERGEd by store_signature carry only an id until
            # the ontology loader has run, so the id is the label of last resort.
            {"value": r["value"], "label": r.get("name") or r["value"],
             "detail": r["value"], "count": r["count"]}
            for r in technique_rows if r.get("value")
        ],
        "c2": [
            # The stored value is the typed indicator ("firebase:evil.web.app");
            # the bare host is what an analyst recognises, so that becomes the
            # label and the full indicator stays as the detail line.
            {"value": r["value"], "label": c2_host(r["value"]) or r["value"],
             "detail": r["value"], "count": r["count"],
             "confirmed": bool(r.get("confirmed"))}
            for r in c2_rows if r.get("value")
        ],
        "certificates": [
            {"value": r["value"], "label": r["value"][:16] + "…",
             "detail": r["value"], "count": r["count"],
             # Past this many samples a shared key is a build-tool artefact, not
             # an actor fingerprint (see MAX_SHARED_CERT_FOR_CORRELATION). The
             # option stays selectable — it is still a real answer to "who else
             # signed with this" — but the UI can label it so nobody reads the
             # AOSP test key as a campaign.
             "builder_default": r["count"] > MAX_SHARED_CERT_FOR_CORRELATION}
            for r in cert_rows if r.get("value")
        ],
        "bands": [
            {"value": name, "label": name.capitalize(), "count": band_counts[name]}
            for name in band_ranges
        ],
        "total_samples": total,
    }


def get_threat_landscape(
    limit: int = 30,
    families: list[str] | None = None,
    techniques: list[str] | None = None,
    c2: list[str] | None = None,
    certificates: list[str] | None = None,
    bands: list[str] | None = None,
    search: str | None = None,
    scope: str = "matches",
) -> dict:
    """
    Cytoscape-ready snapshot of the correlation graph for the "Threat
    Landscape" UI view — the whole-graph picture find_related_samples()
    only shows per-pair. Pulls the `limit` highest-risk cached Sample nodes
    matching the active filters.

    The filter arguments select SAMPLES: filtering on family "Cerberus" returns
    the Cerberus samples, i.e. the packages that make up the family.

    `scope` decides what is drawn ALONGSIDE those samples:

      "matches"      (default) — only the family/technique/C2/certificate nodes
                     the caller explicitly filtered on. Ask for Cerberus and you
                     get the Cerberus node and its packages, not the union of
                     every technique and endpoint those packages happen to
                     touch. With no such filter selected there is nothing to
                     narrow to, so the full neighborhood is drawn.
      "neighborhood" — every node the matched samples touch, unrestricted. This
                     is the pivot view: what does this family reach.

    The distinction matters because these are different questions. "Which
    packages are Cerberus" is answered by a star; "what infrastructure does
    Cerberus share" is answered by the hairball. Drawing the hairball for the
    first question buries the answer in nodes nobody asked about.

    Returns {"nodes": [...], "edges": [...], "matched_samples": n,
    "total_samples": n, "truncated": bool}, or the same shape with empty lists
    if Neo4j is unreachable.
    """
    params = _landscape_params(families, techniques, c2, certificates, bands, search)
    empty = {
        "nodes": [], "edges": [], "matched_samples": 0,
        "total_samples": 0, "truncated": False,
    }

    # Which neighbour nodes survive, keyed by node type. A type the caller did
    # not filter on maps to an empty set and is dropped entirely — that is the
    # point: under "matches", the only non-Sample nodes on screen are the ones
    # named in the filter.
    #
    # Band and search filters have no node of their own, so selecting only those
    # leaves every allow-set empty and `restrict` false. Rendering 30 unconnected
    # dots would be technically faithful and practically useless, so that case
    # keeps the neighborhood.
    pivot_allow = {
        "MalwareFamily": set(params["families"] or []),
        "Technique": set(params["techniques"] or []),
        "C2Indicator": set(params["c2"] or []),
        "Certificate": set(params["certificates"] or []),
    }
    restrict = scope == "matches" and any(pivot_allow.values())

    def _keep(node_type: str, value: str) -> bool:
        return not restrict or value in pivot_allow[node_type]

    try:
        counts = neo4j_client.run(
            f"""
            MATCH (every:Sample)
            WITH count(every) AS total
            // OPTIONAL, so a filter matching nothing still returns the row
            // carrying `total` instead of collapsing to no rows at all — the UI
            // needs "0 of 300" to tell an over-narrow filter from an empty
            // database, and those are different problems with different fixes.
            OPTIONAL MATCH (s:Sample)
            WHERE {_LANDSCAPE_FILTER}
            RETURN total, count(s) AS matched
            """,
            **params,
        )
        rows = neo4j_client.run(
            f"""
            MATCH (s:Sample)
            WHERE {_LANDSCAPE_FILTER}
            WITH s ORDER BY coalesce(s.risk_score, 0) DESC LIMIT $limit
            OPTIONAL MATCH (s)-[:CLASSIFIED_AS_FAMILY]->(f:MalwareFamily)
            OPTIONAL MATCH (s)-[:MAPS_TO_TECHNIQUE]->(t:Technique)
            OPTIONAL MATCH (s)-[:CONTACTS]->(c2n:C2Indicator)
            OPTIONAL MATCH (s)-[:SIGNED_WITH]->(cert:Certificate)
            RETURN s.sha256 AS sha256, s.app_name AS app_name,
                   s.package_name AS package_name,
                   s.risk_score AS risk_score, f.name AS family,
                   collect(DISTINCT {{id: t.technique_id, name: t.name}}) AS techniques,
                   collect(DISTINCT c2n.value) AS c2,
                   cert.thumbprint AS cert
            """,
            limit=limit,
            **params,
        )
    except Exception:
        return empty

    total_samples = counts[0]["total"] if counts else 0
    matched_samples = counts[0]["matched"] if counts else 0

    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    def _add_node(node_id: str, label: str, node_type: str, **extra) -> None:
        if node_id not in nodes:
            nodes[node_id] = {"data": {"id": node_id, "label": label, "type": node_type, **extra}}

    def _add_edge(source: str, target: str, label: str) -> None:
        edges.append({"data": {"id": f"{source}->{target}:{label}", "source": source, "target": target, "label": label}})

    for row in rows:
        sha = row["sha256"]
        sample_id = f"sample:{sha}"
        _add_node(
            sample_id,
            row.get("app_name") or row.get("package_name") or sha[:12],
            "Sample",
            # Carried on the node so clicking a filtered sample answers "which
            # package is this" without a second round trip — reading off the
            # packages behind a family is the point of filtering by one.
            package_name=row.get("package_name") or "",
            risk_score=row.get("risk_score"),
            sha256=sha,
        )

        if row.get("family") and _keep("MalwareFamily", row["family"]):
            family_id = f"family:{row['family']}"
            _add_node(family_id, row["family"], "MalwareFamily")
            _add_edge(sample_id, family_id, "CLASSIFIED_AS_FAMILY")

        for tech in row.get("techniques") or []:
            if not tech or not tech.get("id"):
                continue
            if not _keep("Technique", tech["id"]):
                continue
            tech_id = f"technique:{tech['id']}"
            _add_node(tech_id, tech.get("name") or tech["id"], "Technique")
            _add_edge(sample_id, tech_id, "MAPS_TO_TECHNIQUE")

        for c2_value in row.get("c2") or []:
            if not c2_value or not _keep("C2Indicator", c2_value):
                continue
            c2_id = f"c2:{c2_value}"
            _add_node(c2_id, c2_value, "C2Indicator")
            _add_edge(sample_id, c2_id, "CONTACTS")

        if row.get("cert") and _keep("Certificate", row["cert"]):
            cert_id = f"cert:{row['cert']}"
            _add_node(cert_id, row["cert"][:16] + "...", "Certificate")
            _add_edge(sample_id, cert_id, "SIGNED_WITH")

    return {
        "nodes": list(nodes.values()),
        "edges": edges,
        "matched_samples": matched_samples,
        "total_samples": total_samples,
        # The graph shows the highest-risk `limit` of the matches; saying so is
        # what stops "12 sample nodes" being misread as "12 samples exist".
        "truncated": matched_samples > limit,
        # What was actually drawn, which is not always what was asked for — a
        # band-only filter requests "matches" and gets a neighborhood, and the
        # UI has to say which view is on screen rather than guess.
        "scope": "matches" if restrict else "neighborhood",
    }
