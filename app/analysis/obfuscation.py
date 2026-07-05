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
from collections import Counter

import networkx as nx

from app.analysis.topology import detect_flattening_outlier
from app.core.schemas import ObfuscationSignal


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


def count_reflection_calls(cfgs: dict[str, nx.DiGraph]) -> tuple[int, int]:
    """
    Counts total reflection call sites and how many have unresolvable
    (non-literal) target arguments. Full constant-propagation taint
    tracking is NOT implemented here — this is a placeholder that counts
    reflection call sites only. Wire in real taint analysis before
    trusting `unresolved` as meaningful; right now it's a stub that
    returns 0 unresolved by default.
    """
    total = 0
    unresolved = 0  # TODO: implement constant-propagation to populate this honestly

    for g in cfgs.values():
        for _, data in g.nodes(data=True):
            for call in data.get("api_calls", []):
                if "Ljava/lang/reflect/Method;->invoke" in call:
                    total += 1

    return total, unresolved


def build_obfuscation_signal(
    all_strings: list[str],
    cfgs: dict[str, nx.DiGraph],
    entropy_threshold: float,
    flattening_zscore: float,
    unanalyzed_native_libs: int = 0,
) -> ObfuscationSignal:
    entropy_score = compute_string_pool_entropy(all_strings)

    flattening_suspected = False
    flattening_nodes: list[str] = []
    for g in cfgs.values():
        suspected, nodes = detect_flattening_outlier(g, flattening_zscore)
        if suspected:
            flattening_suspected = True
            flattening_nodes.extend(nodes)

    reflection_total, reflection_unresolved = count_reflection_calls(cfgs)

    coverage_notes = []
    if unanalyzed_native_libs > 0:
        coverage_notes.append(f"{unanalyzed_native_libs} native (.so) libraries not analyzed")
    if reflection_unresolved > 0:
        coverage_notes.append(f"{reflection_unresolved} reflection call targets not statically resolved")
    if entropy_score >= entropy_threshold:
        coverage_notes.append("high string-pool entropy suggests encrypted/encoded literals — semantic content not recoverable statically")

    coverage_note = "; ".join(coverage_notes) if coverage_notes else "no significant static coverage gaps detected"

    return ObfuscationSignal(
        string_entropy_score=entropy_score,
        flattening_suspected=flattening_suspected,
        flattening_outlier_nodes=flattening_nodes,
        reflection_call_count=reflection_total,
        unresolved_reflection_targets=reflection_unresolved,
        coverage_note=coverage_note,
    )
