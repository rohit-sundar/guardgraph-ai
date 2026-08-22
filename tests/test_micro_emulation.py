"""
Tests for Stage 2 — bounded string-decrypt "micro-emulation" folded into
static_resolution.py: Base64.decode of a literal, String's byte-array
constructor wrapping a resolved literal, and inter-procedural summarization
of local parameterless helpers whose every return path is a constant.
"""
import base64
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
        self._blocks = _FakeBlocks([
            _FakeBlock(instrs, start=int(node_id), end=int(node_id) + 1)
            for node_id, instrs in blocks_instructions.items()
        ])

    def get_basic_blocks(self):
        return self._blocks


def _build_graph(node_edges: dict, node_instructions: dict) -> nx.DiGraph:
    g = nx.DiGraph()
    for node_id in node_instructions:
        g.add_node(node_id)
    for src, dsts in node_edges.items():
        for dst in dsts:
            g.add_edge(src, dst)
    enrich_acfg(g, _FakeMethod(node_instructions))
    return g


def test_base64_decode_of_literal_resolves():
    encoded = base64.b64encode(b"payload.evil.example").decode()
    g = _build_graph(
        node_edges={},
        node_instructions={
            "0": [
                _FakeInstruction("const-string", f'v0, "{encoded}"'),
                _FakeInstruction("invoke-static", "v0, Landroid/util/Base64;->decode(Ljava/lang/String; I)[B"),
                _FakeInstruction("move-result-object", "v1"),
                _FakeInstruction("invoke-static", "v1, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;"),
            ],
        },
    )
    total, unresolved, resolved = count_reflection_calls({"Lcom/test/Fake;->m()V": g})

    assert unresolved == 0
    assert resolved[0]["resolved_value"] == "payload.evil.example"


def test_string_byte_array_constructor_wraps_resolved_literal():
    encoded = base64.b64encode(b"com.evil.Dropped").decode()
    g = _build_graph(
        node_edges={},
        node_instructions={
            "0": [
                _FakeInstruction("const-string", f'v0, "{encoded}"'),
                _FakeInstruction("invoke-static", "v0, Landroid/util/Base64;->decode(Ljava/lang/String; I)[B"),
                _FakeInstruction("move-result-object", "v1"),
                _FakeInstruction("new-instance", "v2, Ljava/lang/String;"),
                _FakeInstruction("invoke-direct", "v2, v1, Ljava/lang/String;-><init>([B)V"),
                _FakeInstruction("invoke-static", "v2, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;"),
            ],
        },
    )
    total, unresolved, resolved = count_reflection_calls({"Lcom/test/Fake;->m()V": g})

    assert unresolved == 0
    assert resolved[0]["resolved_value"] == "com.evil.Dropped"


def test_local_parameterless_helper_summarizes_to_its_constant_return():
    helper = _build_graph(
        node_edges={},
        node_instructions={
            "0": [
                _FakeInstruction("const-string", 'v0, "com.evil.FromHelper"'),
                _FakeInstruction("return-object", "v0"),
            ],
        },
    )
    caller = _build_graph(
        node_edges={},
        node_instructions={
            "0": [
                _FakeInstruction("invoke-static", "Lcom/test/Fake;->decode()Ljava/lang/String;"),
                _FakeInstruction("move-result-object", "v0"),
                _FakeInstruction("invoke-static", "v0, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;"),
            ],
        },
    )
    cfgs = {
        "Lcom/test/Fake;->decode()Ljava/lang/String; [access_flags=private static] @ 0x10": helper,
        "Lcom/test/Fake;->caller()V": caller,
    }
    total, unresolved, resolved = count_reflection_calls(cfgs)

    assert unresolved == 0
    assert any(r["resolved_value"] == "com.evil.FromHelper" for r in resolved)


def test_helper_with_divergent_returns_does_not_summarize():
    """Two return-object paths with different literals — must not guess either."""
    helper = _build_graph(
        node_edges={"0": ["1"], "2": []},
        node_instructions={
            "0": [_FakeInstruction("const-string", 'v0, "path.a"')],
            "1": [_FakeInstruction("return-object", "v0")],
        },
    )
    # Second independent return path with a different literal — same method
    # via a second disconnected node (simulating a real second branch target).
    import networkx as nx
    helper.add_node("2")
    helper.nodes["2"]["instr_stream"] = [
        ("const-string", 'v0, "path.b"'),
        ("return-object", "v0"),
    ]

    caller = _build_graph(
        node_edges={},
        node_instructions={
            "0": [
                _FakeInstruction("invoke-static", "Lcom/test/Fake;->decode()Ljava/lang/String;"),
                _FakeInstruction("move-result-object", "v0"),
                _FakeInstruction("invoke-static", "v0, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;"),
            ],
        },
    )
    cfgs = {
        "Lcom/test/Fake;->decode()Ljava/lang/String; [access_flags=private static] @ 0x10": helper,
        "Lcom/test/Fake;->caller()V": caller,
    }
    total, unresolved, resolved = count_reflection_calls(cfgs)

    assert unresolved == 1
    assert resolved == []


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
