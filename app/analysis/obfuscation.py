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

    reflection_total, reflection_unresolved = count_reflection_calls(cfgs)

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
