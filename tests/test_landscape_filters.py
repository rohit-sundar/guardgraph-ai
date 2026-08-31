"""
Tests for the Threat Landscape filters — GET /graph/landscape's filter
parameters, GET /graph/landscape/facets, and the query construction behind both
(app/graph/cache.py).

The bug class these defend against is not "the filter returns nothing". It is
the filter returning something *plausible but wrong*, which on a correlation
graph is indistinguishable from a real finding:

  * Filtering after the LIMIT. get_threat_landscape shows the 30 highest-risk
    samples; if a family filter were applied to that page rather than to the
    whole Sample set, "Cerberus" would mean "Cerberus among the global top 30"
    and would silently omit most of the family. The analyst has no way to see
    the difference from the screen.
  * An empty filter list read as "match nothing" rather than "no filter", which
    empties the graph the moment someone unticks their last checkbox.
  * matched vs. total collapsing to the same number, which is what makes "your
    filter is too narrow" indistinguishable from "the database is empty" — two
    problems with opposite fixes.
  * Verdict bands drifting from the scoring module's own thresholds, so a report
    reading `high` lands in the `suspicious` bucket of the filter beside it.

Neo4j is never contacted: neo4j_client.run is patched, and the assertions are
made against the Cypher parameters the module builds, which is exactly the
surface a live database would consume.
"""
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi.testclient import TestClient

from app.graph import cache as cache_module
from app.main import app


class _RecordingNeo4j:
    """Stands in for neo4j_client.run, capturing every (query, params) pair.

    Returns rows keyed off a marker in the query text so one instance can serve
    the count query, the element query and each facet aggregation from a single
    test without the tests caring about call ordering.
    """

    def __init__(self, element_rows=None, count_row=None, facet_rows=None):
        self.calls = []
        self.element_rows = element_rows or []
        self.count_row = count_row or {"total": 0, "matched": 0}
        self.facet_rows = facet_rows or {}

    def __call__(self, query, **params):
        self.calls.append((query, params))
        if "count(s) AS matched" in query:
            return [self.count_row]
        if "RETURN s.sha256 AS sha256" in query:
            return self.element_rows
        for marker, rows in self.facet_rows.items():
            if marker in query:
                return rows
        return []

    def params_for(self, marker):
        for query, params in self.calls:
            if marker in query:
                return params
        raise AssertionError(f"no query containing {marker!r} was run")


def _sample_row(sha, **overrides):
    row = {
        "sha256": sha, "app_name": "App", "package_name": "com.example.app",
        "risk_score": 80.0, "family": "Cerberus", "techniques": [], "c2": [],
        "cert": None,
    }
    row.update(overrides)
    return row


class TestFilterParameterNormalisation(unittest.TestCase):
    """app/graph/cache.py :: _landscape_params"""

    def test_empty_lists_disable_their_clause_rather_than_matching_nothing(self):
        """
        The UI sends every filter every time, so "nothing selected" arrives as
        an empty list. Passing that through to Cypher as [] would make
        `f.name IN []` false for every sample and blank the graph the instant
        someone unticks their last checkbox. None is what switches the clause
        off — see _LANDSCAPE_FILTER's `IS NULL` guards.
        """
        params = cache_module._landscape_params([], [], [], [], [], "")
        for key in ("families", "techniques", "c2", "certificates", "bands", "search"):
            self.assertIsNone(params[key], f"{key} should disable its clause when empty")

    def test_search_is_lowercased_and_trimmed_to_match_the_tolower_comparison(self):
        """The Cypher compares toLower(package_name) CONTAINS $search, so an
        untouched "  Cerberus " would match nothing at all."""
        params = cache_module._landscape_params(None, None, None, None, None, "  Com.Example  ")
        self.assertEqual(params["search"], "com.example")

    def test_unknown_band_is_dropped_not_raised(self):
        """A stale bookmark naming a band that no longer exists must degrade to
        "no band filter", not a 500 out of a KeyError."""
        params = cache_module._landscape_params(None, None, None, None, ["nonsense"], None)
        self.assertIsNone(params["bands"])

    def test_band_ranges_come_from_the_scoring_module_thresholds(self):
        """
        The filter's idea of `high` has to be the report's idea of `high`. This
        pins the ranges to _band_for's own constants rather than to numbers
        copied into the test, so recalibrating the bands moves both together.
        """
        from app.reports import scoring

        params = cache_module._landscape_params(
            None, None, None, None, ["suspicious", "malicious"], None
        )
        ranges = {(b["lo"], b["hi"]) for b in params["bands"]}
        self.assertIn(
            (scoring.BAND_MEDIUM_CEILING, scoring.BAND_SUSPICIOUS_CEILING), ranges
        )
        self.assertIn(scoring.BAND_HIGH_CEILING, {lo for lo, _ in ranges})

    def test_every_band_name_the_facets_offer_is_one_the_filter_accepts(self):
        """
        The dropdown is built from get_landscape_facets()["bands"] and its
        selections are posted straight back as ?band=. A name offered by one and
        rejected by the other is a filter that silently does nothing.
        """
        names = list(cache_module._landscape_bands())
        params = cache_module._landscape_params(None, None, None, None, names, None)
        self.assertEqual(len(params["bands"]), len(names))

    def test_bands_partition_the_score_range_with_no_gap_between_them(self):
        """
        Contiguous (lo, hi] ranges: every possible score falls in exactly one
        band. A gap would make a sample scoring on the boundary invisible to
        every risk-level filter at once.
        """
        edges = sorted(cache_module._landscape_bands().values())
        for (_, hi), (next_lo, _) in zip(edges, edges[1:]):
            self.assertEqual(hi, next_lo)
        self.assertLess(edges[0][0], 0.0, "the lowest band must include a 0.0 score")


class TestFilteringHappensBeforeTheLimit(unittest.TestCase):
    """app/graph/cache.py :: get_threat_landscape"""

    def test_filter_predicates_are_applied_in_the_element_query_itself(self):
        """
        The load-bearing property of the whole feature. If the WHERE clause did
        not sit above `WITH s ORDER BY ... LIMIT`, filtering to a family would
        return only that family's members inside the global top-30 — a subset
        that looks like a complete answer.
        """
        fake = _RecordingNeo4j(element_rows=[_sample_row("a" * 64)])
        with patch.object(cache_module.neo4j_client, "run", fake):
            cache_module.get_threat_landscape(limit=30, families=["Cerberus"])

        query, params = next(
            (q, p) for q, p in fake.calls if "RETURN s.sha256 AS sha256" in q
        )
        self.assertEqual(params["families"], ["Cerberus"])
        where_at = query.index("$families")
        limit_at = query.index("LIMIT $limit")
        self.assertLess(where_at, limit_at, "family filter must be applied before the LIMIT")

    def test_each_filter_group_binds_its_own_parameter(self):
        fake = _RecordingNeo4j(element_rows=[])
        with patch.object(cache_module.neo4j_client, "run", fake):
            cache_module.get_threat_landscape(
                families=["Cerberus"], techniques=["T1582"],
                c2=["firebase:evil.web.app"], certificates=["AABB"],
                bands=["malicious"], search="com.evil",
            )
        params = fake.params_for("RETURN s.sha256 AS sha256")
        self.assertEqual(params["techniques"], ["T1582"])
        self.assertEqual(params["c2"], ["firebase:evil.web.app"])
        self.assertEqual(params["certificates"], ["AABB"])
        self.assertEqual(params["search"], "com.evil")
        self.assertEqual(len(params["bands"]), 1)

    def test_count_query_and_element_query_share_one_filter_definition(self):
        """
        "12 of 300" is only true if both numbers were counted the same way. The
        two queries must interpolate the same _LANDSCAPE_FILTER text, not two
        hand-maintained copies that can drift.
        """
        fake = _RecordingNeo4j(element_rows=[])
        with patch.object(cache_module.neo4j_client, "run", fake):
            cache_module.get_threat_landscape(families=["Cerberus"])
        bodies = [q for q, _ in fake.calls]
        self.assertTrue(all(cache_module._LANDSCAPE_FILTER in q for q in bodies))

    def test_matched_and_total_are_reported_separately(self):
        """
        The UI's "no samples match these filters" message versus "analyze a few
        APKs first" hinges entirely on these two being distinct. Collapsing them
        sends someone to populate a database that is already full.
        """
        fake = _RecordingNeo4j(element_rows=[], count_row={"total": 300, "matched": 0})
        with patch.object(cache_module.neo4j_client, "run", fake):
            data = cache_module.get_threat_landscape(families=["Nonexistent"])
        self.assertEqual(data["total_samples"], 300)
        self.assertEqual(data["matched_samples"], 0)
        self.assertEqual(data["nodes"], [])

    def test_truncated_is_set_when_more_samples_match_than_are_drawn(self):
        fake = _RecordingNeo4j(
            element_rows=[_sample_row(f"{i:064d}") for i in range(3)],
            count_row={"total": 300, "matched": 90},
        )
        with patch.object(cache_module.neo4j_client, "run", fake):
            data = cache_module.get_threat_landscape(limit=30, families=["Cerberus"])
        self.assertTrue(data["truncated"])

    def test_unfiltered_view_draws_the_whole_neighborhood(self):
        """With nothing selected there is nothing to narrow to, so the default
        view is unchanged from before filtering existed."""
        fake = _RecordingNeo4j(element_rows=[self._rich_row()],
                               count_row={"total": 1, "matched": 1})
        with patch.object(cache_module.neo4j_client, "run", fake):
            data = cache_module.get_threat_landscape()
        types = {n["data"]["type"] for n in data["nodes"]}
        self.assertEqual(
            types, {"Sample", "MalwareFamily", "Technique", "C2Indicator", "Certificate"}
        )
        self.assertEqual(data["scope"], "neighborhood")

    def _rich_row(self, sha="b" * 64):
        return _sample_row(
            sha,
            techniques=[{"id": "T1582", "name": "SMS Control"}],
            c2=["firebase:evil.web.app"],
            cert="AABBCCDDEEFF00112233",
        )

    def test_filtering_by_family_draws_only_the_packages_and_that_family(self):
        """
        The reason scope exists. Filtering to Cerberus asks "which packages are
        Cerberus"; answering it with every technique, C2 host and signing key
        those packages happen to touch buries the 30 nodes that were asked for
        under the dozens that were not.
        """
        fake = _RecordingNeo4j(element_rows=[self._rich_row()],
                               count_row={"total": 1, "matched": 1})
        with patch.object(cache_module.neo4j_client, "run", fake):
            data = cache_module.get_threat_landscape(families=["Cerberus"])
        types = {n["data"]["type"] for n in data["nodes"]}
        self.assertEqual(types, {"Sample", "MalwareFamily"})
        self.assertEqual(data["scope"], "matches")

    def test_edges_to_dropped_nodes_are_dropped_with_them(self):
        """A dangling edge pointing at a node that was never added is what makes
        Cytoscape refuse to render the whole graph, not just that one edge."""
        fake = _RecordingNeo4j(element_rows=[self._rich_row()],
                               count_row={"total": 1, "matched": 1})
        with patch.object(cache_module.neo4j_client, "run", fake):
            data = cache_module.get_threat_landscape(families=["Cerberus"])
        node_ids = {n["data"]["id"] for n in data["nodes"]}
        for edge in data["edges"]:
            self.assertIn(edge["data"]["source"], node_ids)
            self.assertIn(edge["data"]["target"], node_ids)

    def test_only_the_filtered_dimension_survives_not_every_type(self):
        """
        Filtering by C2 must not smuggle the family and certificate back in.
        Each node type is kept only if the caller named a value for that type.
        """
        fake = _RecordingNeo4j(element_rows=[self._rich_row()],
                               count_row={"total": 1, "matched": 1})
        with patch.object(cache_module.neo4j_client, "run", fake):
            data = cache_module.get_threat_landscape(c2=["firebase:evil.web.app"])
        types = {n["data"]["type"] for n in data["nodes"]}
        self.assertEqual(types, {"Sample", "C2Indicator"})

    def test_a_value_the_filter_did_not_name_is_excluded_from_its_own_type(self):
        """
        The allow-set is checked per value, not per type. A sample matched on
        family Cerberus must not drag in a *different* family node just because
        MalwareFamily happens to be an active dimension.
        """
        fake = _RecordingNeo4j(
            element_rows=[self._rich_row(), _sample_row("d" * 64, family="Anubis")],
            count_row={"total": 2, "matched": 2},
        )
        with patch.object(cache_module.neo4j_client, "run", fake):
            data = cache_module.get_threat_landscape(families=["Cerberus"])
        families = {n["data"]["label"] for n in data["nodes"]
                    if n["data"]["type"] == "MalwareFamily"}
        self.assertEqual(families, {"Cerberus"})

    def test_two_dimensions_selected_keeps_both(self):
        fake = _RecordingNeo4j(element_rows=[self._rich_row()],
                               count_row={"total": 1, "matched": 1})
        with patch.object(cache_module.neo4j_client, "run", fake):
            data = cache_module.get_threat_landscape(
                families=["Cerberus"], techniques=["T1582"]
            )
        types = {n["data"]["type"] for n in data["nodes"]}
        self.assertEqual(types, {"Sample", "MalwareFamily", "Technique"})

    def test_band_only_filter_keeps_the_neighborhood(self):
        """
        A risk-level filter names no node, so there is nothing to narrow to.
        Honouring "matches" literally here would return unconnected dots — a
        graph view with no graph in it.
        """
        fake = _RecordingNeo4j(element_rows=[self._rich_row()],
                               count_row={"total": 1, "matched": 1})
        with patch.object(cache_module.neo4j_client, "run", fake):
            data = cache_module.get_threat_landscape(bands=["malicious"])
        self.assertEqual(data["scope"], "neighborhood")
        self.assertIn("Technique", {n["data"]["type"] for n in data["nodes"]})

    def test_neighborhood_scope_restores_the_pivot_view(self):
        """
        "What does this family reach" is still askable — it just has to be asked
        for now instead of being the unavoidable default.
        """
        fake = _RecordingNeo4j(element_rows=[self._rich_row()],
                               count_row={"total": 1, "matched": 1})
        with patch.object(cache_module.neo4j_client, "run", fake):
            data = cache_module.get_threat_landscape(
                families=["Cerberus"], scope="neighborhood"
            )
        types = {n["data"]["type"] for n in data["nodes"]}
        self.assertEqual(
            types, {"Sample", "MalwareFamily", "Technique", "C2Indicator", "Certificate"}
        )
        self.assertEqual(data["scope"], "neighborhood")

    def test_scope_never_changes_which_samples_match(self):
        """Scope is a drawing decision, not a filtering one — the sample set and
        the counts printed beside it must be identical either way."""
        for scope in ("matches", "neighborhood"):
            fake = _RecordingNeo4j(element_rows=[self._rich_row()],
                                   count_row={"total": 9, "matched": 4})
            with patch.object(cache_module.neo4j_client, "run", fake):
                data = cache_module.get_threat_landscape(
                    families=["Cerberus"], scope=scope
                )
            samples = [n for n in data["nodes"] if n["data"]["type"] == "Sample"]
            self.assertEqual(len(samples), 1, scope)
            self.assertEqual((data["matched_samples"], data["total_samples"]), (4, 9), scope)

    def test_sample_nodes_carry_the_package_name(self):
        """
        Filtering by family is a question about packages. The visible label is
        the app's display name — attacker-chosen and frequently a brand it is
        impersonating — so the package has to ride along on the node or the
        answer needs a second lookup to read.
        """
        fake = _RecordingNeo4j(
            element_rows=[_sample_row("c" * 64, package_name="com.cerberus.dropper")],
            count_row={"total": 1, "matched": 1},
        )
        with patch.object(cache_module.neo4j_client, "run", fake):
            data = cache_module.get_threat_landscape()
        sample = next(n for n in data["nodes"] if n["data"]["type"] == "Sample")
        self.assertEqual(sample["data"]["package_name"], "com.cerberus.dropper")
        self.assertEqual(sample["data"]["sha256"], "c" * 64)

    def test_unreachable_neo4j_returns_the_full_shape_not_a_partial_dict(self):
        """Callers read matched_samples/total_samples unconditionally; a
        two-key fallback would turn an outage into a TypeError in the UI."""
        with patch.object(
            cache_module.neo4j_client, "run", side_effect=RuntimeError("down")
        ):
            data = cache_module.get_threat_landscape(families=["Cerberus"])
        self.assertEqual(
            set(data),
            {"nodes", "edges", "matched_samples", "total_samples", "truncated"},
        )


class TestLandscapeFacets(unittest.TestCase):
    """app/graph/cache.py :: get_landscape_facets"""

    def _fake(self):
        return _RecordingNeo4j(facet_rows={
            "RETURN count(s) AS total": [{"total": 4}],
            "MalwareFamily)\n            RETURN f.name": [
                {"value": "Cerberus", "count": 3}, {"value": "Anubis", "count": 1},
            ],
            "Technique)\n            RETURN t.technique_id": [
                {"value": "T1582", "name": "SMS Control", "count": 2},
                {"value": "T9999", "name": None, "count": 1},
            ],
            "C2Indicator)\n            RETURN ci.value": [
                {"value": "firebase:evil.web.app", "count": 2, "confirmed": True},
            ],
            "Certificate)\n            RETURN c.thumbprint": [
                {"value": "A" * 40, "count": 54}, {"value": "B" * 40, "count": 2},
            ],
            "RETURN coalesce(s.risk_score, 0.0) AS score": [
                {"score": 0.0}, {"score": 80.0}, {"score": 80.0}, {"score": 45.0},
            ],
        })

    def test_options_are_read_from_the_graph_with_their_sample_counts(self):
        fake = self._fake()
        with patch.object(cache_module.neo4j_client, "run", fake):
            facets = cache_module.get_landscape_facets()
        self.assertEqual(facets["total_samples"], 4)
        self.assertEqual(
            [(f["value"], f["count"]) for f in facets["families"]],
            [("Cerberus", 3), ("Anubis", 1)],
        )

    def test_technique_without_an_ontology_name_falls_back_to_its_id(self):
        """store_signature MERGEs Technique nodes by id alone, so until the
        ontology loader has run t.name is null. A blank dropdown row is
        unselectable in practice."""
        fake = self._fake()
        with patch.object(cache_module.neo4j_client, "run", fake):
            facets = cache_module.get_landscape_facets()
        unnamed = next(t for t in facets["techniques"] if t["value"] == "T9999")
        self.assertEqual(unnamed["label"], "T9999")

    def test_c2_option_labels_with_the_bare_host_and_keeps_the_typed_indicator(self):
        """The stored value carries a type prefix ("firebase:"); the analyst
        recognises the host. Both are needed — the host to read, the full value
        to send back as the filter."""
        fake = self._fake()
        with patch.object(cache_module.neo4j_client, "run", fake):
            facets = cache_module.get_landscape_facets()
        c2 = facets["c2"][0]
        self.assertEqual(c2["value"], "firebase:evil.web.app")
        self.assertEqual(c2["label"], "evil.web.app")
        self.assertTrue(c2["confirmed"])

    def test_widely_shared_certificate_is_flagged_as_a_builder_default(self):
        """
        A key on 54 samples is the AOSP test key, not an actor fingerprint — the
        same threshold find_related_samples already refuses to correlate on.
        Offering it unlabelled invites reading a toolchain as a campaign.
        """
        fake = self._fake()
        with patch.object(cache_module.neo4j_client, "run", fake):
            facets = cache_module.get_landscape_facets()
        wide = next(c for c in facets["certificates"] if c["count"] == 54)
        narrow = next(c for c in facets["certificates"] if c["count"] == 2)
        self.assertTrue(wide["builder_default"])
        self.assertFalse(narrow["builder_default"])

    def test_band_counts_bucket_each_sample_exactly_once(self):
        fake = self._fake()
        with patch.object(cache_module.neo4j_client, "run", fake):
            facets = cache_module.get_landscape_facets()
        by_name = {b["value"]: b["count"] for b in facets["bands"]}
        self.assertEqual(sum(by_name.values()), 4)
        self.assertEqual(by_name["low"], 1)        # 0.0
        self.assertEqual(by_name["malicious"], 2)  # 80.0, 80.0
        self.assertEqual(by_name["suspicious"], 1)  # 45.0

    def test_unreachable_neo4j_returns_empty_options_not_an_error(self):
        """Same degradation contract as every other reader in the module — the
        filter bar renders a note, and the graph reports the outage itself."""
        with patch.object(
            cache_module.neo4j_client, "run", side_effect=RuntimeError("down")
        ):
            facets = cache_module.get_landscape_facets()
        self.assertEqual(facets["total_samples"], 0)
        self.assertEqual(facets["families"], [])


class TestLandscapeEndpoints(unittest.TestCase):
    """app/api/routes.py :: GET /graph/landscape and /graph/landscape/facets"""

    def setUp(self):
        self.client = TestClient(app)

    def test_repeated_query_parameters_reach_the_cache_layer_as_lists(self):
        """
        Repeated params rather than a comma-joined string, because the values
        include C2 indicators and certificate thumbprints — splitting those on a
        comma would corrupt the filter into one that matches nothing.
        """
        from app.api import routes as routes_module

        with patch.object(
            routes_module, "get_threat_landscape", return_value={"nodes": [], "edges": []}
        ) as spy:
            self.client.get(
                "/graph/landscape",
                params=[("family", "Cerberus"), ("family", "Anubis"), ("band", "malicious")],
            )
        kwargs = spy.call_args.kwargs
        self.assertEqual(kwargs["families"], ["Cerberus", "Anubis"])
        self.assertEqual(kwargs["bands"], ["malicious"])

    def test_unfiltered_request_still_works(self):
        """The tab's first load sends no filters at all; that path must stay
        exactly as it was before filtering existed."""
        from app.api import routes as routes_module

        with patch.object(
            routes_module, "get_threat_landscape", return_value={"nodes": [], "edges": []}
        ) as spy:
            resp = self.client.get("/graph/landscape")
        self.assertEqual(resp.status_code, 200)
        kwargs = spy.call_args.kwargs
        self.assertEqual(kwargs["families"], [])
        self.assertIsNone(kwargs["search"])

    def test_scope_is_passed_through_the_endpoint(self):
        from app.api import routes as routes_module

        with patch.object(
            routes_module, "get_threat_landscape", return_value={"nodes": [], "edges": []}
        ) as spy:
            self.client.get("/graph/landscape", params={"scope": "neighborhood"})
        self.assertEqual(spy.call_args.kwargs["scope"], "neighborhood")

    def test_endpoint_defaults_to_matches(self):
        """The tab sends no scope on its first load, and every filter click is a
        request to narrow — so the narrow view has to be the default."""
        from app.api import routes as routes_module

        with patch.object(
            routes_module, "get_threat_landscape", return_value={"nodes": [], "edges": []}
        ) as spy:
            self.client.get("/graph/landscape")
        self.assertEqual(spy.call_args.kwargs["scope"], "matches")

    def test_facets_endpoint_serves_the_filter_vocabulary(self):
        from app.api import routes as routes_module

        payload = {
            "families": [{"value": "Cerberus", "label": "Cerberus", "count": 3}],
            "techniques": [], "c2": [], "certificates": [], "bands": [],
            "total_samples": 3,
        }
        with patch.object(routes_module, "get_landscape_facets", return_value=payload):
            resp = self.client.get("/graph/landscape/facets")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["families"][0]["value"], "Cerberus")


if __name__ == "__main__":
    unittest.main()
