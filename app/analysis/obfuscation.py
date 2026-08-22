"""
Obfuscation signal detection — static-only, per project constraints.

Implements the two cheapest, highest-signal detectors from the priority
list: entropy scoring and flattening detection (flattening lives in
topology.py, imported here for the combined signal). Reflection constant
resolution is included since it's static and cheap. String-decrypt
micro-execution, native .so analysis, and packer fingerprinting are
explicitly NOT implemented — flag them as unanalyzed coverage per the
report's "not observed" guardrail rather than pretending to cover them.
"""
import math
import re
from collections import Counter

import networkx as nx

from app.analysis.cfg import parse_const_string
from app.analysis.topology import detect_flattening_outlier
from app.core.schemas import ObfuscationSignal

# APIs whose first (or first-after-`this`) string argument names the class/method
# being reached reflectively. `arg_index` counts registers left-to-right as they
# appear in the invoke instruction's output (index 0 = `this` for invoke-virtual).
_REFLECTION_NAME_APIS = {
    "Ljava/lang/Class;->forName": 0,
    "Ljava/lang/ClassLoader;->loadClass": 1,
    "Ljava/lang/Class;->getMethod": 1,
    "Ljava/lang/Class;->getDeclaredMethod": 1,
}
# Counted as a reflection call site but carries no resolvable name argument of
# its own — the Method object it invokes was already named upstream via one of
# the APIs above.
_REFLECTION_INVOKE_SITE = "Ljava/lang/reflect/Method;->invoke"

_CONST_STRING_MNEMONICS = frozenset({"const-string", "const-string/jumbo"})
_MOVE_MNEMONICS = frozenset({"move-object", "move-object/16", "move-object/from16"})

# An invoke instruction's output is "regA, regB, ..., Lclass;->method(args)ret" —
# the target signature always starts at the first `L...;->` and runs to the end,
# so anything before that match, comma-split, is the register list.
_INVOKE_TARGET_RE = re.compile(r"(L[\w/$]+;->[\w$<>]+\(.*)$")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def compute_string_pool_entropy(all_strings: list[str]) -> float:
    """
    Average entropy across the app's string pool. High entropy suggests
    encrypted/encoded string literals rather than natural-language or
    typical identifier strings.
    """
    if not all_strings:
        return 0.0
    entropies = [shannon_entropy(s) for s in all_strings if s]
    return sum(entropies) / len(entropies) if entropies else 0.0


def _parse_invoke_registers_and_target(output: str) -> tuple[list[str], str | None]:
    """Splits an invoke instruction's output into (argument registers, target signature)."""
    match = _INVOKE_TARGET_RE.search(output)
    if not match:
        return [], None
    target = match.group(1)
    prefix = output[: match.start()].rstrip(", ")
    registers = [r.strip() for r in prefix.split(",") if r.strip()]
    return registers, target


def _resolve_method_reflection(g: nx.DiGraph, order: list[str]) -> tuple[int, int, list[dict]]:
    """
    Per-method register-constant resolution for reflection call targets.

    Walks each basic block's instruction stream (stashed by cfg.enrich_acfg)
    tracking a `register -> literal` map, seeded from the block's single
    predecessor when unambiguous (in-degree 1, predecessor already visited
    in `order`). Multi-predecessor joins and not-yet-visited predecessors
    (loop back-edges) start with an empty map instead of guessing — matches
    ObfuscationSignal's "absence of evidence, not evidence of absence" rule.

    No bytecode execution: this is dataflow over already-decoded operands,
    not string-decrypt emulation (that's explicitly separate future work).
    """
    total = 0
    unresolved = 0
    resolved: list[dict] = []
    exit_maps: dict[str, dict[str, str]] = {}
    visited: set[str] = set()

    for node_id in order:
        preds = list(g.predecessors(node_id))
        regs: dict[str, str] = (
            dict(exit_maps.get(preds[0], {})) if len(preds) == 1 and preds[0] in visited else {}
        )

        for mnemonic, output in g.nodes[node_id].get("instr_stream", []):
            if mnemonic in _CONST_STRING_MNEMONICS:
                literal = parse_const_string(output)
                if literal is not None:
                    reg = output.split(",", 1)[0].strip()
                    regs[reg] = literal
            elif mnemonic in _MOVE_MNEMONICS:
                parts = [p.strip() for p in output.split(",")]
                if len(parts) == 2:
                    dst, src = parts
                    if src in regs:
                        regs[dst] = regs[src]
                    else:
                        regs.pop(dst, None)
            elif mnemonic == "move-result-object":
                # Result of whatever was just invoked — not a literal we tracked.
                regs.pop(output.strip(), None)
            elif mnemonic.startswith("invoke"):
                registers, target = _parse_invoke_registers_and_target(output)
                if target is None:
                    continue
                if _REFLECTION_INVOKE_SITE in target:
                    total += 1
                    continue
                for api, arg_index in _REFLECTION_NAME_APIS.items():
                    if api not in target:
                        continue
                    total += 1
                    name_reg = registers[arg_index] if len(registers) > arg_index else None
                    value = regs.get(name_reg) if name_reg else None
                    if value is not None:
                        resolved.append({
                            "node_id": node_id,
                            "target_api": api,
                            "resolved_value": value,
                        })
                    else:
                        unresolved += 1
                    break

        exit_maps[node_id] = regs
        visited.add(node_id)

    return total, unresolved, resolved


def count_reflection_calls(cfgs: dict[str, nx.DiGraph]) -> tuple[int, int, list[dict]]:
    """
    Resolves reflection call targets (Class.forName / getMethod /
    getDeclaredMethod / ClassLoader.loadClass, plus Method.invoke call sites)
    back to literal strings via bounded, per-method register-constant
    propagation over the CFGs cfg.py already built — no execution, no
    cross-method taint.

    Returns (total reflection call sites, unresolved name-bearing sites,
    resolved call records). A name-bearing call whose argument doesn't trace
    back to a literal through an unambiguous chain of assignments stays
    unresolved rather than guessed.
    """
    total = 0
    unresolved = 0
    resolved: list[dict] = []

    for method_sig, g in cfgs.items():
        if nx.is_directed_acyclic_graph(g):
            order = list(nx.topological_sort(g))
        else:
            order = list(g.nodes())
        m_total, m_unresolved, m_resolved = _resolve_method_reflection(g, order)
        total += m_total
        unresolved += m_unresolved
        for r in m_resolved:
            r["method_sig"] = method_sig
        resolved.extend(m_resolved)

    return total, unresolved, resolved


def build_obfuscation_signal(
    all_strings: list[str],
    cfgs: dict[str, nx.DiGraph],
    entropy_threshold: float,
    flattening_zscore: float,
    unanalyzed_native_libs: int = 0,
    method_parse_failure_rate: float = 0.0,
    dex_method_count: int | None = None,
    declared_component_count: int | None = None,
) -> ObfuscationSignal:
    entropy_score = compute_string_pool_entropy(all_strings)

    # N7: count how MANY methods look flattened, not just whether one does.
    # `flattening_suspected` is kept for the frozen feature vectors, but it is an
    # existential over every analysed method and therefore true on almost any app
    # of normal size — measured, 30/30 clean apps against 23/28 malware. The
    # prevalence is what scoring reads.
    flattening_suspected = False
    flattening_nodes: list[str] = []
    flattening_methods = 0
    for g in cfgs.values():
        suspected, nodes = detect_flattening_outlier(g, flattening_zscore)
        if suspected:
            flattening_suspected = True
            flattening_methods += 1
            flattening_nodes.extend(nodes)
    analyzed_methods = len(cfgs)
    flattening_ratio = (flattening_methods / analyzed_methods) if analyzed_methods else 0.0

    reflection_total, reflection_unresolved, _resolved_reflection = count_reflection_calls(cfgs)

    coverage_notes = []
    if unanalyzed_native_libs > 0:
        coverage_notes.append(f"{unanalyzed_native_libs} native (.so) libraries not analyzed")
    if reflection_unresolved > 0:
        coverage_notes.append(f"{reflection_unresolved} reflection call targets not statically resolved")
    if entropy_score >= entropy_threshold:
        coverage_notes.append("high string-pool entropy suggests encrypted/encoded literals — semantic content not recoverable statically")
    # §9.6: flag method parse failures as a coverage gap — high failure rate
    # often indicates heavy obfuscation that broke Androguard's block parser.
    if method_parse_failure_rate >= 0.10:
        pct = round(method_parse_failure_rate * 100, 1)
        coverage_notes.append(
            f"{pct}% of relevant methods failed CFG parsing — "
            "analysis coverage reduced; possible heavy obfuscation"
        )

    # N7: the code that was recovered cannot account for the app the manifest
    # describes. This is the coverage gap that matters and it used to be invisible —
    # an empty `cfgs` means no method can look flattened, so the obfuscation signal
    # read "clean" on exactly the samples that defeated the analyser.
    if dex_method_count == 0:
        coverage_notes.insert(
            0, "no methods recovered from the DEX — the app's code was not analysable "
               "(packing, encryption, or a runtime-loaded payload)"
        )
    elif dex_method_count and declared_component_count:
        if dex_method_count < 2 * declared_component_count:
            coverage_notes.insert(
                0,
                f"{dex_method_count} methods recovered against "
                f"{declared_component_count} declared components — the DEX is too "
                "small to implement its own manifest; the payload is not in it"
            )

    # Reported, not scored: measured over the corpus, the share of analysed methods
    # that look flattened is indistinguishable between clean apps and malware.
    if flattening_ratio >= 0.20:
        coverage_notes.append(
            f"control-flow flattening shape in {flattening_ratio * 100:.0f}% of "
            f"analysed methods"
        )

    coverage_note = "; ".join(coverage_notes) if coverage_notes else "no significant static coverage gaps detected"

    return ObfuscationSignal(
        string_entropy_score=entropy_score,
        flattening_suspected=flattening_suspected,
        flattening_outlier_nodes=flattening_nodes,
        reflection_call_count=reflection_total,
        unresolved_reflection_targets=reflection_unresolved,
        method_parse_failure_rate=method_parse_failure_rate,
        flattening_method_count=flattening_methods,
        analyzed_method_count=analyzed_methods,
        flattening_method_ratio=round(flattening_ratio, 4),
        dex_method_count=None if dex_method_count is None else int(dex_method_count),
        declared_component_count=(
            None if declared_component_count is None else int(declared_component_count)
        ),
        coverage_note=coverage_note,
    )
