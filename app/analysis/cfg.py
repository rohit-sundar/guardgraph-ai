"""
Control Flow Graph construction (NetworkX) + ACFG enrichment.

Design note: we build one CFG per method and keep them as separate graphs
rather than one giant whole-app graph. This matches the paper's anchor +
4-hop-neighborhood extraction strategy — you extract subgraphs around
suspicious blocks within a method's local CFG, not across the entire app.
If you later want cross-method call-graph analysis, that's a separate
graph (see: future work, not in this skeleton).
"""
import networkx as nx


def build_method_cfg(method_analysis) -> nx.DiGraph:
    """
    Builds a directed graph for a single method.
    Node = basic block (keyed by start offset).
    Edge = control transition (fallthrough, branch, exception).

    method_analysis: androguard MethodAnalysis object.
    """
    g = nx.DiGraph()

    for block in method_analysis.get_basic_blocks().get():
        node_id = f"{block.start}"
        g.add_node(node_id, start=block.start, end=block.end)

        # get_childs() is the correct Androguard 4.x API; .childs is not public.
        for child in block.get_childs():
            # child is a tuple (min_offset, max_offset, BasicBlock)
            child_block = child[2] if isinstance(child, tuple) else child
            if child_block is None:
                continue
            child_id = f"{child_block.start}"
            g.add_edge(node_id, child_id)

    return g


def enrich_acfg(g: nx.DiGraph, method_analysis) -> nx.DiGraph:
    """
    Annotates each basic block node with opcode frequency, API calls,
    string literals, and any permission-relevant constants found in that
    block's instruction stream.

    Mutates and returns the same graph for convenience.
    """
    blocks_by_start = {
        f"{b.start}": b for b in method_analysis.get_basic_blocks().get()
    }

    for node_id, block in blocks_by_start.items():
        if node_id not in g:
            continue

        opcode_freq: dict[str, int] = {}
        api_calls: list[str] = []
        string_literals: list[str] = []

        for instr in block.get_instructions():
            mnemonic = instr.get_name()
            opcode_freq[mnemonic] = opcode_freq.get(mnemonic, 0) + 1

            output = instr.get_output()
            if mnemonic.startswith("invoke"):
                api_calls.append(output.strip())
            if mnemonic == "const-string":
                # output format: "reg, 'literal'" — extract the literal
                if "'" in output:
                    literal = output.split("'", 1)[1].rsplit("'", 1)[0]
                    string_literals.append(literal)

        g.nodes[node_id]["opcode_frequency"] = opcode_freq
        g.nodes[node_id]["api_calls"] = api_calls
        g.nodes[node_id]["string_literals"] = string_literals

    return g


def build_all_method_cfgs(analysis_obj) -> dict[str, nx.DiGraph]:
    """
    Builds + enriches a CFG for every method in the app.
    Returns dict of method signature -> enriched graph.

    Note: for large APKs this can be slow. For prototype purposes this is
    fine to run synchronously; if it becomes a bottleneck on your demo
    samples, cap it to methods touching risk-relevant classes first
    (see forensic.py anchor list) rather than optimizing the whole thing.
    """
    graphs = {}
    for method_analysis in analysis_obj.get_methods():
        try:
            g = build_method_cfg(method_analysis)
            g = enrich_acfg(g, method_analysis)
            method_sig = str(method_analysis.get_method())
            graphs[method_sig] = g
        except Exception:
            # Malformed/obfuscated methods can break Androguard's block
            # parsing. Skip and continue — one broken method shouldn't
            # kill analysis of the rest of the app. Consider logging
            # skipped methods as part of the obfuscation coverage note.
            continue

    return graphs
