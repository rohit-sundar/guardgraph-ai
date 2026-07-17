"""
Control Flow Graph construction (NetworkX) + ACFG enrichment.

Design note: we build one CFG per method and keep them as separate graphs
rather than one giant whole-app graph. This matches the paper's anchor +
4-hop-neighborhood extraction strategy — you extract subgraphs around
suspicious blocks within a method's local CFG, not across the entire app.
If you later want cross-method call-graph analysis, that's a separate
graph (see: future work, not in this skeleton).

Changes vs. original:
- §9.6: build_all_method_cfgs now returns (graphs_dict, parse_failure_rate)
  so callers can surface the failure rate as a coverage signal.
- §10.3: is_method_relevant() pre-filter skips methods with no API/string
  overlap with the forensic dictionary before doing full CFG construction,
  reducing runtime on large benign apps without changing detection outcomes.
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

        # Androguard 4.1.x exposes successors via the `childs` property
        # (list of (min_offset, max_offset, BasicBlock) tuples); there is no
        # get_childs() method on DEXBasicBlock in this version.
        for child in block.childs:
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


def is_method_relevant(
    method_analysis,
    relevant_api_substrings: frozenset[str],
    relevant_string_substrings: frozenset[str],
) -> bool:
    """
    Cheap pre-filter (§10.3): check whether a method references any API or
    string that the forensic dictionary cares about, BEFORE doing full CFG
    construction (which is expensive on large APKs).

    Uses Androguard's instruction stream directly without building a graph.
    Returns True if the method should be analyzed, False if it can be skipped.

    Note: this is a relevance filter, not a match. A method passing this
    filter still needs full ACFG enrichment + anchor detection. A method
    failing this filter is guaranteed to produce zero forensic matches
    (no false negatives from skipping it).
    """
    try:
        for block in method_analysis.get_basic_blocks().get():
            for instr in block.get_instructions():
                mnemonic = instr.get_name()
                output = instr.get_output()

                if mnemonic.startswith("invoke"):
                    if any(api in output for api in relevant_api_substrings):
                        return True

                if mnemonic == "const-string" and "'" in output:
                    literal = output.split("'", 1)[1].rsplit("'", 1)[0].lower()
                    if any(s in literal for s in relevant_string_substrings):
                        return True
    except Exception:
        # If the pre-filter itself fails, include the method to be safe —
        # skipping on error risks false negatives.
        return True

    return False


def build_all_method_cfgs(
    analysis_obj,
    use_relevance_filter: bool = True,
) -> tuple[dict[str, nx.DiGraph], float]:
    """
    Builds + enriches a CFG for every relevant method in the app.

    Returns:
        (method_sig -> enriched_graph, parse_failure_rate)

    parse_failure_rate is the fraction of attempted methods that raised an
    exception during CFG construction or ACFG enrichment. A high rate is a
    meaningful coverage gap (often caused by heavy obfuscation) and is
    surfaced in the obfuscation signal — see §9.6.

    use_relevance_filter (default True): skip methods with no forensic-
    dictionary API/string overlap before full CFG construction (§10.3).
    Set to False to replicate original behavior (builds CFG for all methods).
    """
    from app.analysis.forensic import FORENSIC_DICTIONARY

    # Build cheap lookup sets for the relevance pre-filter.
    relevant_apis: frozenset[str] = frozenset(
        api
        for rules in FORENSIC_DICTIONARY.values()
        for api in rules.get("apis", [])
    )
    relevant_strings: frozenset[str] = frozenset(
        s.lower()
        for rules in FORENSIC_DICTIONARY.values()
        for s in rules.get("strings", [])
    )

    graphs: dict[str, nx.DiGraph] = {}
    attempted = 0
    failed = 0

    for method_analysis in analysis_obj.get_methods():
        # Relevance pre-filter: skip methods with no forensic-dict overlap.
        if use_relevance_filter and not is_method_relevant(
            method_analysis, relevant_apis, relevant_strings
        ):
            continue

        attempted += 1
        try:
            g = build_method_cfg(method_analysis)
            g = enrich_acfg(g, method_analysis)
            method_sig = str(method_analysis.get_method())
            graphs[method_sig] = g
        except Exception:
            # Malformed/obfuscated methods can break Androguard's block
            # parsing. Count failures for the coverage signal; continue.
            failed += 1
            continue

    parse_failure_rate = (failed / attempted) if attempted > 0 else 0.0
    return graphs, parse_failure_rate
