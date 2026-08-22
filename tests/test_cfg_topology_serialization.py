"""
Tests for CFG topology serialization (§ subgraph explorer fix).

Before this, phase 3 extracted a real 4-hop subgraph, read its topological
invariants, and discarded the graph — so the API shipped no blocks and no edges
and the frontend fabricated both. These tests pin the three properties that fix
depends on:

  1. the serialized topology is the *actual* induced subgraph, not a reshaping;
  2. node ids are method-qualified, because block offsets collide across methods;
  3. the anchor/dispatcher overlap is computed by membership, not assumed.
"""
import os
import sys
import unittest

import networkx as nx

# Add project root to sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.analysis.cfg import method_key, split_method_signature
from app.analysis.obfuscation import build_obfuscation_signal
from app.core.pipeline import (
    MAX_TOPOLOGY_NODES,
    MAX_TOPOLOGY_SUBGRAPHS,
    AnalysisPipeline,
)
from app.core.schemas import IngestionResult, ObfuscationSignal

REFLECT_API = "v2, Ljava/lang/reflect/Field;->setAccessible(Z)V"
CRYPTO_API = "v1, Ljavax/crypto/Cipher;->doFinal([B)[B"
LOADER_API = "v0, Ldalvik/system/DexClassLoader;-><init>(Ljava/lang/String;)V"

# The exact shape Androguard's str(get_method()) emits — note the "; ->" separator.
SIG_A = "Lcom/example/pay/Sender; ->send (Ljava/lang/String;)V"
SIG_B = "Lcom/example/util/Helper; ->run ()V"


def _block(g, node_id, start, api_calls=None, strings=None):
    """Adds a node shaped like one enrich_acfg() produces."""
    g.add_node(
        node_id,
        start=start,
        end=start + 4,
        opcode_frequency={},
        api_calls=list(api_calls or []),
        string_literals=list(strings or []),
    )


def _chain(api_on=None, length=6):
    """A straight-line method CFG: 0 -> 4 -> 8 -> ... Anchor API on one block."""
    g = nx.DiGraph()
    offsets = [i * 4 for i in range(length)]
    for off in offsets:
        _block(g, str(off), off)
    # The anchor always sits on block "4", so tests can assert against it directly.
    if api_on:
        g.nodes["4"]["api_calls"] = [api_on]
    for a, b in zip(offsets, offsets[1:]):
        g.add_edge(str(a), str(b))
    return g


def _star_with_tail(tail_len, anchor_offset, api=REFLECT_API, leaves=12):
    """
    A dispatcher-shaped method: a high-degree hub ("0") plus a tail hanging off it,
    with the forensic anchor placed `tail_len` blocks down that tail. Lets a test
    put the dispatcher inside or outside the anchor's 4-hop window on demand.
    """
    g = nx.DiGraph()
    _block(g, "0", 0)
    for i in range(1, leaves + 1):
        _block(g, f"L{i}", i)
        g.add_edge("0", f"L{i}")

    prev = "0"
    for i in range(1, tail_len + 1):
        node = str(100 + i)
        _block(g, node, 100 + i)
        g.add_edge(prev, node)
        prev = node

    g.nodes[str(100 + anchor_offset)]["api_calls"] = [api]
    return g


def _run_phase3(cfgs, permissions=None):
    ingestion = IngestionResult(
        sha256="0" * 64,
        package_name="com.example.app",
        permissions=list(permissions or []),
    )
    return AnalysisPipeline.run_phase3_forensic_matching(cfgs, ingestion)


class TestSplitMethodSignature(unittest.TestCase):
    def test_parses_androguard_signature(self):
        self.assertEqual(
            split_method_signature(SIG_A), ("com.example.pay.Sender", "send")
        )

    def test_strips_the_arrow_separator(self):
        """Real output is 'L...; ->name (...)'; the arrow must not reach the label."""
        for sig in (
            "Landroidx/appcompat/app/ResourcesFlusher; ->flushMarshmallows ()V",
            "Landroidx/appcompat/app/ResourcesFlusher;->flushMarshmallows()V",
        ):
            cls, method = split_method_signature(sig)
            self.assertEqual(cls, "androidx.appcompat.app.ResourcesFlusher")
            self.assertEqual(method, "flushMarshmallows")

    def test_signature_without_arrow_still_parses(self):
        cls, method = split_method_signature("Lcom/x/Y; baz ()V")
        self.assertEqual((cls, method), ("com.x.Y", "baz"))

    def test_degenerate_signature_never_raises(self):
        self.assertEqual(split_method_signature("garbage"), ("garbage", ""))
        self.assertEqual(split_method_signature(""), ("", ""))


class TestTopologySerialization(unittest.TestCase):
    def test_topology_is_the_real_induced_subgraph(self):
        g = _chain(api_on=REFLECT_API, length=6)
        _, subgraphs, _ = _run_phase3({SIG_A: g})

        self.assertEqual(len(subgraphs), 1)
        sg = subgraphs[0]
        self.assertEqual(sg.primary_behavior_flag, "DYNAMIC_REFLECTION")
        self.assertEqual(sg.class_name, "com.example.pay.Sender")
        self.assertEqual(sg.method_name, "send")
        self.assertEqual(sg.anchor_node, "4")

        topo = sg.topology
        self.assertIsNotNone(topo)

        # Every serialized edge is a real control transition of the source graph.
        real_edges = {(u, v) for u, v in g.edges()}
        for e in topo.edges:
            u = e.source.split("#")[-1]
            v = e.target.split("#")[-1]
            self.assertIn((u, v), real_edges)

        # Exactly one anchor, and it is the block that carried the evidence.
        anchors = [n for n in topo.nodes if n.is_anchor]
        self.assertEqual(len(anchors), 1)
        self.assertEqual(anchors[0].block_offset, 4)
        self.assertIn(REFLECT_API, anchors[0].api_calls)

    def test_node_ids_are_method_qualified(self):
        g = _chain(api_on=REFLECT_API)
        _, subgraphs, _ = _run_phase3({SIG_A: g})

        key = method_key(SIG_A)
        for n in subgraphs[0].topology.nodes:
            self.assertTrue(n.id.startswith(f"{key}#"), n.id)

    def test_node_ids_do_not_embed_the_full_signature(self):
        """
        The signature is ~180 chars on an obfuscated app and would be repeated once
        per block and twice per edge. It travels once, on the subgraph record.
        """
        g = _chain(api_on=REFLECT_API)
        _, subgraphs, _ = _run_phase3({SIG_A: g})

        sg = subgraphs[0]
        self.assertEqual(sg.method_signature, SIG_A)
        for n in sg.topology.nodes:
            self.assertNotIn(SIG_A, n.id)

    def test_same_offset_in_two_methods_stays_distinct(self):
        """Offset 4 exists in nearly every method; ids must not collapse."""
        cfgs = {SIG_A: _chain(api_on=REFLECT_API), SIG_B: _chain(api_on=REFLECT_API)}
        _, subgraphs, _ = _run_phase3(cfgs)

        ids = {n.id for sg in subgraphs for n in sg.topology.nodes}
        self.assertIn(f"{method_key(SIG_A)}#4", ids)
        self.assertIn(f"{method_key(SIG_B)}#4", ids)
        self.assertNotEqual(method_key(SIG_A), method_key(SIG_B))

    def test_no_dangling_edges(self):
        """Every edge endpoint resolves to a serialized node, even after the cap."""
        g = _chain(api_on=REFLECT_API, length=30)
        _, subgraphs, _ = _run_phase3({SIG_A: g})

        topo = subgraphs[0].topology
        node_ids = {n.id for n in topo.nodes}
        self.assertLessEqual(len(topo.nodes), MAX_TOPOLOGY_NODES)
        for e in topo.edges:
            self.assertIn(e.source, node_ids)
            self.assertIn(e.target, node_ids)

    def test_plain_block_label_falls_back_to_offset(self):
        g = _chain(api_on=REFLECT_API)
        _, subgraphs, _ = _run_phase3({SIG_A: g})

        by_offset = {n.block_offset: n for n in subgraphs[0].topology.nodes}
        # Block 8 carries no api_calls, so it is labelled by its offset.
        self.assertEqual(by_offset[8].label, "0x8")
        # Block 4 does, so it is named after what it calls.
        self.assertEqual(by_offset[4].label, "setAccessible")


class TestTopologyBounding(unittest.TestCase):
    def test_breadth_before_depth(self):
        """>12 subgraphs across 3 behaviors: all 3 represented, <=12 serialized."""
        cfgs = {}
        for i in range(14):
            cfgs[f"Lcom/x/R{i}; m ()V"] = _chain(api_on=REFLECT_API)
        cfgs["Lcom/x/Crypto; m ()V"] = _chain(api_on=CRYPTO_API)
        cfgs["Lcom/x/Loader; m ()V"] = _chain(api_on=LOADER_API)

        _, subgraphs, _ = _run_phase3(cfgs)
        self.assertGreater(len(subgraphs), MAX_TOPOLOGY_SUBGRAPHS)

        drawn = [sg for sg in subgraphs if sg.topology is not None]
        self.assertLessEqual(len(drawn), MAX_TOPOLOGY_SUBGRAPHS)

        flags = {sg.primary_behavior_flag for sg in drawn}
        self.assertIn("DYNAMIC_REFLECTION", flags)
        self.assertIn("CRYPTOGRAPHY_USAGE", flags)
        self.assertIn("DYNAMIC_CODE_LOADING", flags)

    def test_substantial_subgraphs_beat_single_block_methods(self):
        """
        Regression: ranking by subgraph_size_ratio gave one-block methods a perfect
        1.0 and filled the explorer with isolated dots. Rank on absolute blocks.
        """
        cfgs = {}
        # 20 trivial one-block methods, each a complete 4-hop window (ratio 1.0).
        for i in range(20):
            g = nx.DiGraph()
            _block(g, "0", 0, api_calls=[REFLECT_API])
            cfgs[f"Lcom/x/Tiny{i}; ->m ()V"] = g
        # One substantial method whose window is many blocks but a small ratio.
        cfgs[SIG_A] = _chain(api_on=REFLECT_API, length=12)

        _, subgraphs, _ = _run_phase3(cfgs)
        drawn = {sg.method_signature for sg in subgraphs if sg.topology is not None}
        self.assertIn(SIG_A, drawn)

        big = next(sg for sg in subgraphs if sg.method_signature == SIG_A)
        self.assertGreater(len(big.topology.nodes), 1)

    def test_unserialized_subgraphs_keep_topology_none(self):
        """None means 'not serialized', never 'the subgraph was empty'."""
        cfgs = {f"Lcom/x/R{i}; m ()V": _chain(api_on=REFLECT_API) for i in range(20)}
        _, subgraphs, _ = _run_phase3(cfgs)

        undrawn = [sg for sg in subgraphs if sg.topology is None]
        self.assertTrue(undrawn)
        for sg in undrawn:
            # Attribution is still present on every subgraph, drawn or not.
            self.assertTrue(sg.method_signature)
            self.assertTrue(sg.class_name)


class TestOverlappingWindowsInOneMethod(unittest.TestCase):
    """
    Several anchors in one method are overlapping 4-hop windows over the SAME CFG,
    so their block ids are identical by construction. Any consumer that draws
    subgraphs as independent components must merge them by method first — the
    explorer did not, and the later window deduped to an empty box while its anchor
    lost styling to the plain block the earlier window had already emitted.
    """

    def _two_anchor_method(self):
        g = _chain(api_on=REFLECT_API, length=6)
        g.nodes["12"]["api_calls"] = [LOADER_API]
        return g

    def test_one_method_yields_several_subgraphs(self):
        _, subgraphs, _ = _run_phase3({SIG_A: self._two_anchor_method()})

        self.assertEqual(len(subgraphs), 2)
        self.assertEqual({sg.method_signature for sg in subgraphs}, {SIG_A})
        self.assertEqual(
            {sg.primary_behavior_flag for sg in subgraphs},
            {"DYNAMIC_REFLECTION", "DYNAMIC_CODE_LOADING"},
        )

    def test_their_node_ids_collide_by_design(self):
        _, subgraphs, _ = _run_phase3({SIG_A: self._two_anchor_method()})

        a, b = ({n.id for n in sg.topology.nodes} for sg in subgraphs)
        self.assertTrue(a & b, "windows over one method must share block ids")

    def test_each_window_marks_its_own_anchor(self):
        """The merge relies on anchor identity being per-subgraph, not per-block."""
        _, subgraphs, _ = _run_phase3({SIG_A: self._two_anchor_method()})

        anchors = {
            sg.primary_behavior_flag: [
                n.block_offset for n in sg.topology.nodes if n.is_anchor
            ]
            for sg in subgraphs
        }
        self.assertEqual(anchors["DYNAMIC_REFLECTION"], [4])
        self.assertEqual(anchors["DYNAMIC_CODE_LOADING"], [12])


class TestAnchorOutlierJoin(unittest.TestCase):
    def test_dispatcher_inside_window_is_reported(self):
        # Anchor 3 blocks down the tail -> hub is 3 hops away, inside the window.
        g = _star_with_tail(tail_len=6, anchor_offset=3)
        _, subgraphs, _ = _run_phase3({SIG_A: g})

        self.assertEqual(len(subgraphs), 1)
        sg = subgraphs[0]
        self.assertIn("0", sg.contains_outlier_nodes)

        hub = [n for n in sg.topology.nodes if n.id.endswith("#0")]
        self.assertEqual(len(hub), 1)
        self.assertTrue(hub[0].is_outlier)

    def test_dispatcher_outside_window_is_not_reported(self):
        # Anchor 6 blocks down the tail -> hub is 6 hops away, outside the window.
        g = _star_with_tail(tail_len=6, anchor_offset=6)
        _, subgraphs, _ = _run_phase3({SIG_A: g})

        sg = subgraphs[0]
        self.assertEqual(sg.contains_outlier_nodes, [])
        self.assertFalse(any(n.is_outlier for n in sg.topology.nodes))


class TestOutlierAttribution(unittest.TestCase):
    def test_details_carry_the_owning_method(self):
        g = _star_with_tail(tail_len=1, anchor_offset=1)
        signal = build_obfuscation_signal(
            all_strings=[], cfgs={SIG_A: g},
            entropy_threshold=4.5, flattening_zscore=3.0,
        )

        self.assertTrue(signal.flattening_outlier_details)
        detail = signal.flattening_outlier_details[0]
        self.assertEqual(detail.method_signature, SIG_A)
        self.assertEqual(detail.class_name, "com.example.pay.Sender")
        self.assertEqual(detail.method_name, "send")
        self.assertGreater(detail.degree, 0)

    def test_colliding_offsets_produce_distinct_node_ids(self):
        cfgs = {
            SIG_A: _star_with_tail(tail_len=1, anchor_offset=1),
            SIG_B: _star_with_tail(tail_len=1, anchor_offset=1),
        }
        signal = build_obfuscation_signal(
            all_strings=[], cfgs=cfgs,
            entropy_threshold=4.5, flattening_zscore=3.0,
        )

        # The legacy field cannot tell these apart — both are the bare offset "0".
        self.assertEqual(signal.flattening_outlier_nodes, ["0", "0"])
        # The attributed one can.
        ids = {d.node_id for d in signal.flattening_outlier_details}
        self.assertEqual(ids, {f"{method_key(SIG_A)}#0", f"{method_key(SIG_B)}#0"})


class TestBackwardCompatibility(unittest.TestCase):
    def test_cached_record_without_new_field_still_constructs(self):
        """Stored obfuscation_data blobs predate flattening_outlier_details."""
        old = {
            "string_entropy_score": 4.2,
            "flattening_suspected": True,
            "flattening_outlier_nodes": ["4", "12"],
            "reflection_call_count": 3,
            "unresolved_reflection_targets": 1,
            "coverage_note": "none",
        }
        signal = ObfuscationSignal(**old)
        self.assertEqual(signal.flattening_outlier_details, [])
        self.assertEqual(signal.flattening_outlier_nodes, ["4", "12"])


if __name__ == "__main__":
    unittest.main()
