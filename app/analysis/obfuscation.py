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

from app.analysis.cfg import method_key, split_method_signature
from app.analysis.static_resolution import resolve_invocations
from app.analysis.topology import detect_flattening_outlier
from app.core.schemas import ObfuscationSignal, OutlierNode

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


def count_reflection_calls(cfgs: dict[str, nx.DiGraph]) -> tuple[int, int, list[dict]]:
    """
    Resolves reflection call targets (Class.forName / getMethod /
    getDeclaredMethod / ClassLoader.loadClass, plus Method.invoke call sites)
    back to literal strings via the shared register-constant resolver in
    static_resolution.py — no execution, no cross-method taint.

    Returns (total reflection call sites, unresolved name-bearing sites,
    resolved call records). A name-bearing call whose argument doesn't trace
    back to a literal through an unambiguous chain of assignments stays
    unresolved rather than guessed.
    """
    total = 0
    unresolved = 0
    resolved: list[dict] = []

    for event in resolve_invocations(cfgs):
        target = event.target_api
        if _REFLECTION_INVOKE_SITE in target:
            total += 1
            continue
        for api, arg_index in _REFLECTION_NAME_APIS.items():
            if api not in target:
                continue
            total += 1
            arg = event.arg(arg_index)
            if arg is not None and arg[0] == "literal":
                resolved.append({
                    "node_id": event.node_id,
                    "method_sig": event.method_sig,
                    "target_api": api,
                    "resolved_value": arg[1],
                })
            else:
                unresolved += 1
            break

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
    manifest_parse_failed: bool = False,
    manifest_recovery_source: str | None = None,
    container_anomalies: list[str] | None = None,
) -> ObfuscationSignal:
    entropy_score = compute_string_pool_entropy(all_strings)

    # N7: count how MANY methods look flattened, not just whether one does.
    # `flattening_suspected` is kept for the frozen feature vectors, but it is an
    # existential over every analysed method and therefore true on almost any app
    # of normal size — measured, 30/30 clean apps against 23/28 malware. The
    # prevalence is what scoring reads.
    flattening_suspected = False
    flattening_nodes: list[str] = []
    flattening_details: list[OutlierNode] = []
    flattening_methods = 0
    # Iterate .items(), not .values(): the key is the full method signature, and
    # dropping it is what left `flattening_outlier_nodes` a list of bare block
    # offsets that no consumer could attribute back to a class or method.
    for method_sig, g in cfgs.items():
        suspected, nodes = detect_flattening_outlier(g, flattening_zscore)
        if suspected:
            flattening_suspected = True
            flattening_methods += 1
            flattening_nodes.extend(nodes)

            class_name, method_name = split_method_signature(method_sig)
            key = method_key(method_sig)
            for node in nodes:
                flattening_details.append(
                    OutlierNode(
                        node_id=f"{key}#{node}",
                        method_signature=method_sig,
                        class_name=class_name,
                        method_name=method_name,
                        block_offset=int(node) if str(node).isdigit() else 0,
                        degree=g.degree[node],
                    )
                )
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

    # A deliberately corrupted manifest (junk bytes between AXML chunk headers,
    # forcing Androguard's parser into a byte-by-byte resync that can fail
    # outright) is a strong, deliberate anti-analysis signal on its own — no
    # legitimate app has a reason to malform its own manifest. Reported, not
    # scored: unlike the manifest-vs-code check below, this hasn't been
    # measured against a corpus, so it doesn't get a calibrated weight — see
    # obfuscation_component's docstring in scoring.py for why that measurement
    # comes first here.
    if manifest_parse_failed:
        if manifest_recovery_source == "tree":
            note = (
                "AndroidManifest.xml failed the standard parse (corrupted/"
                "anti-analysis) and was recovered by the tolerant AXML fallback — "
                "permissions and components below are the manifest's own, the "
                "signing certificate is still unavailable"
            )
        elif manifest_recovery_source == "string_pool":
            note = (
                "AndroidManifest.xml failed to parse (corrupted/anti-analysis); "
                "only its string pool was recoverable — permissions and intent "
                "actions below are real declarations, but component names could "
                "not be attributed to activity/service/receiver, and the signing "
                "certificate is unavailable"
            )
        else:
            note = (
                "AndroidManifest.xml failed to parse (corrupted/anti-analysis) — "
                "permissions, components, and certificate data are unavailable; "
                "DEX/CFG-level analysis still ran"
            )
        coverage_notes.insert(0, note)

    # Archive tampering is reported here because it is the reason several of the
    # other notes exist: an entry the standard reader refuses is a gap in *this*
    # analysis, and an analyst reading a thin result deserves to know the file was
    # built to produce one. Scored separately — see CONTAINER_TAMPER_SCORE_FLOOR.
    if container_anomalies:
        coverage_notes.insert(
            0,
            "the ZIP container is malformed in ways no build tool produces ("
            + "; ".join(container_anomalies[:4])
            + ") — entries were read through the Android-tolerant container reader",
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
        flattening_outlier_details=flattening_details,
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
        manifest_parse_failed=manifest_parse_failed,
        coverage_note=coverage_note,
    )
