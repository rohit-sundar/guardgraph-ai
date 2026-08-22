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
- N1: the pre-filter vocabulary now comes from forensic.relevance_vocabulary(),
  which walks the clause structure the tightened dictionary uses.
- T1: const-string operands are parsed delimiter-agnostically. Both extraction
  sites previously tested for a single quote; Androguard 4.1.x emits double
  quotes, so the only literals that survived were ones whose *text* contained
  an apostrophe — and those were then split on it. See parse_const_string().
"""
import hashlib
import re

import networkx as nx

# Androguard renders a const-string operand as `reg, <delimiter>literal<delimiter>`.
# Which delimiter it uses is a property of the Androguard version, not of the APK:
# 4.1.x (the pinned version) emits double quotes, older builds emitted single ones.
# Capture whichever character opens the literal and match it again at the close, so
# the parse survives either — and so an apostrophe *inside* a double-quoted literal
# is treated as text rather than as a delimiter. Greedy `.*` + re.S takes the last
# matching delimiter, which keeps embedded delimiters of the other kind intact.
_CONST_STRING_RE = re.compile(r"""(['"])(.*)\1""", re.S)


def parse_const_string(output: str) -> str | None:
    """
    Extracts the literal from a const-string instruction's operand text.

    Returns None when the operand carries no delimited literal at all, which the
    callers treat as "no string here" rather than as an empty string.
    """
    match = _CONST_STRING_RE.search(output)
    return match.group(2) if match else None


def method_key(method_sig: str) -> str:
    """
    A short, stable, collision-resistant handle for a method signature.

    Block ids have to be qualified by their owning method — offset 4 exists in
    almost every method, and an unqualified id merges unrelated blocks. Embedding
    the signature itself would work but is ruinously repetitive: an obfuscated APK
    has ~180-character signatures, and each one would be repeated once per block
    plus twice per edge. The full signature travels once, on the owning record.
    """
    return hashlib.sha1(method_sig.encode("utf-8", "replace")).hexdigest()[:10]


def split_method_signature(method_sig: str) -> tuple[str, str]:
    """
    Splits a CFG map key into a display-ready (class_name, method_name).

    `build_all_method_cfgs` keys its graphs by `str(method_analysis.get_method())`,
    which Androguard renders as `Lcom/foo/Bar; ->baz (Ljava/lang/String;)V` — the
    arrow separator is present on real output but absent from some hand-written
    signatures, so both shapes are accepted. Callers want "com.foo.Bar" and "baz"
    for labelling, so do the parse in one place.

    Never raises: a signature that does not match the expected shape comes back as
    (method_sig, "") so a malformed key degrades to a worse label rather than
    breaking analysis.
    """
    if not method_sig:
        return "", ""

    class_part, sep, rest = method_sig.partition(";")
    if not sep:
        return method_sig, ""

    class_name = class_part.strip()
    if class_name.startswith("L"):
        class_name = class_name[1:]
    class_name = class_name.replace("/", ".")

    # `rest` is " ->baz (Ljava/lang/String;)V" — the method name is the first token,
    # and the descriptor that follows it is not useful for display.
    method_name = rest.strip().split("(")[0].strip()
    if method_name.startswith("->"):
        method_name = method_name[2:].strip()

    return (class_name or method_sig), method_name


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

    Also stores the raw (mnemonic, output) instruction stream per node under
    "instr_stream" — obfuscation.py's reflection-target resolver walks this
    to do register-constant propagation without re-touching Androguard.

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
        instr_stream: list[tuple[str, str]] = []

        for instr in block.get_instructions():
            mnemonic = instr.get_name()
            opcode_freq[mnemonic] = opcode_freq.get(mnemonic, 0) + 1

            output = instr.get_output().strip()
            instr_stream.append((mnemonic, output))
            if mnemonic.startswith("invoke"):
                api_calls.append(output)
            if mnemonic == "const-string" or mnemonic == "const-string/jumbo":
                literal = parse_const_string(output)
                if literal is not None:
                    string_literals.append(literal)

        g.nodes[node_id]["opcode_frequency"] = opcode_freq
        g.nodes[node_id]["api_calls"] = api_calls
        g.nodes[node_id]["string_literals"] = string_literals
        g.nodes[node_id]["instr_stream"] = instr_stream

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

                if mnemonic == "const-string":
                    # Must use the same parse as enrich_acfg: a method whose only
                    # relevance is a dictionary *string* is never selected for CFG
                    # construction otherwise, so fixing one site without the other
                    # changes nothing.
                    literal = parse_const_string(output)
                    if literal is not None:
                        literal = literal.lower()
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
    from app.analysis.forensic import relevance_vocabulary

    # Cheap lookup sets for the relevance pre-filter. Owned by forensic.py since
    # N1 made a rule's patterns live inside clauses rather than at its top level —
    # re-deriving them here would silently drift from what match_anchors reads.
    relevant_apis, relevant_strings = relevance_vocabulary()

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
