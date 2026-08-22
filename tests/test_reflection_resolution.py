"""
Tests for reflection-target resolution — the register-constant propagation
that replaces the `unresolved_reflection_targets` stub in obfuscation.py.

Reuses the fake Androguard instruction/block/method fixtures from
test_cfg_string_extraction.py (same shape, kept local here to avoid a
cross-test-file import dependency).
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import networkx as nx

from app.analysis.cfg import enrich_acfg
from app.analysis.obfuscation import count_reflection_calls


class _FakeInstruction:
    def __init__(self, name: str, output: str):
        self._name, self._output = name, output

    def get_name(self) -> str:
        return self._name

    def get_output(self) -> str:
        return self._output


class _FakeBlock:
    def __init__(self, instructions, start=0, end=1):
        self._instructions, self.start, self.end = instructions, start, end
        self.childs = []

    def get_instructions(self):
        return self._instructions


class _FakeBlocks:
    def __init__(self, blocks):
        self._blocks = blocks

    def get(self):
        return self._blocks


class _FakeMethod:
    def __init__(self, blocks_instructions: dict):
        """blocks_instructions: {node_id: [instructions]} — node_id used as block.start."""
        self._blocks = _FakeBlocks([
            _FakeBlock(instrs, start=int(node_id), end=int(node_id) + 1)
            for node_id, instrs in blocks_instructions.items()
        ])

    def get_basic_blocks(self):
        return self._blocks


def _build_graph(node_edges: dict, node_instructions: dict) -> nx.DiGraph:
    """node_edges: {node_id: [successor_ids]}. Builds + enriches the CFG."""
    g = nx.DiGraph()
    for node_id in node_instructions:
        g.add_node(node_id)
    for src, dsts in node_edges.items():
        for dst in dsts:
            g.add_edge(src, dst)
    enrich_acfg(g, _FakeMethod(node_instructions))
    return g


def test_literal_argument_resolves_in_same_block():
    g = _build_graph(
        node_edges={},
        node_instructions={
            "0": [
                _FakeInstruction("const-string", 'v0, "com.evil.Payload"'),
                _FakeInstruction("invoke-static", "v0, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;"),
            ],
        },
    )
    total, unresolved, resolved = count_reflection_calls({"Lcom/test/Fake;->m()V": g})

    assert total == 1
    assert unresolved == 0
    assert len(resolved) == 1
    assert resolved[0]["resolved_value"] == "com.evil.Payload"
    assert resolved[0]["target_api"] == "Ljava/lang/Class;->forName"


def test_unseeded_register_stays_unresolved():
    g = _build_graph(
        node_edges={},
        node_instructions={
            "0": [
                _FakeInstruction("invoke-static", "v5, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;"),
            ],
        },
    )
    total, unresolved, resolved = count_reflection_calls({"Lcom/test/Fake;->m()V": g})

    assert total == 1
    assert unresolved == 1
    assert resolved == []


def test_method_invoke_site_counts_but_never_resolves():
    """Method.invoke carries no name argument of its own — it's a count, not a target."""
    g = _build_graph(
        node_edges={},
        node_instructions={
            "0": [
                _FakeInstruction("invoke-virtual", "v0, v1, v2, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;"),
            ],
        },
    )
    total, unresolved, resolved = count_reflection_calls({"Lcom/test/Fake;->m()V": g})

    assert total == 1
    assert unresolved == 0
    assert resolved == []


def test_single_predecessor_propagates_literal_across_blocks():
    g = _build_graph(
        node_edges={"0": ["1"]},
        node_instructions={
            "0": [_FakeInstruction("const-string", 'v0, "com.evil.Loader"')],
            "1": [_FakeInstruction("invoke-static", "v0, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;")],
        },
    )
    total, unresolved, resolved = count_reflection_calls({"Lcom/test/Fake;->m()V": g})

    assert unresolved == 0
    assert len(resolved) == 1
    assert resolved[0]["resolved_value"] == "com.evil.Loader"


def test_ambiguous_join_does_not_guess():
    """Two predecessors, only one seeds v0 — the join must not inherit either one."""
    g = _build_graph(
        node_edges={"0": ["2"], "1": ["2"]},
        node_instructions={
            "0": [_FakeInstruction("const-string", 'v0, "com.evil.OnlyOnePath"')],
            "1": [],
            "2": [_FakeInstruction("invoke-static", "v0, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;")],
        },
    )
    total, unresolved, resolved = count_reflection_calls({"Lcom/test/Fake;->m()V": g})

    assert unresolved == 1
    assert resolved == []


def test_load_class_resolves_second_register_after_this():
    g = _build_graph(
        node_edges={},
        node_instructions={
            "0": [
                _FakeInstruction("const-string", 'v1, "com.evil.Dropped"'),
                _FakeInstruction("invoke-virtual", "v6, v1, Ljava/lang/ClassLoader;->loadClass(Ljava/lang/String;)Ljava/lang/Class;"),
            ],
        },
    )
    total, unresolved, resolved = count_reflection_calls({"Lcom/test/Fake;->m()V": g})

    assert unresolved == 0
    assert resolved[0]["resolved_value"] == "com.evil.Dropped"
    assert resolved[0]["target_api"] == "Ljava/lang/ClassLoader;->loadClass"


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
