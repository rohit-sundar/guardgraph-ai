"""
Shared static register/class resolution engine.

One register-constant + register-class propagation pass over the CFGs,
reused by every deobfuscation feature (reflection targets, crypto config,
dynamic class loading, WebView JS bridges, native library loads) instead of
re-implementing the same dataflow per feature.

Same bounded, fail-closed design throughout this codebase's obfuscation work:
a register's value is known only via a straight-line chain of const-string /
new-instance / move assignments, propagated across a CFG edge only when the
destination block has a single, already-visited predecessor. Ambiguous joins
and loop-carried values are left unresolved rather than guessed — a wrong
"resolved" value (e.g. a fabricated C2 domain) is worse than an honest
"not statically resolved," so every consumer of this module must treat a
missing resolution as absence of evidence, not evidence of absence.
"""
import base64
import re
from dataclasses import dataclass, field

import networkx as nx

from app.analysis.cfg import parse_const_string

_CONST_STRING_MNEMONICS = frozenset({"const-string", "const-string/jumbo"})
_MOVE_MNEMONICS = frozenset({"move-object", "move-object/16", "move-object/from16"})
_NEW_INSTANCE_RE = re.compile(r"^(v\d+),\s*(L[\w/$]+;)$")
# An invoke instruction's output is "regA, regB, ..., Lclass;->method(args)ret" —
# the target signature always starts at the first `L...;->` and runs to the end.
_INVOKE_TARGET_RE = re.compile(r"(L[\w/$]+;->[\w$<>]+\(.*)$")
# Strips androguard's `str(EncodedMethod)` suffix (" [access_flags=...] @ 0xOFFSET")
# so a cfgs dict key can be compared against an invoke instruction's bare target text.
_METHOD_SIG_SUFFIX_RE = re.compile(r"\s*\[access_flags=.*$")


def _strip_method_sig_suffix(method_sig: str) -> str:
    return _METHOD_SIG_SUFFIX_RE.sub("", method_sig)


def _try_known_transform(target: str, resolved_args: dict) -> tuple[str, str] | None:
    """
    Bounded string-decrypt "micro-emulation": folds a small whitelist of pure,
    deterministic library calls whose result is fully determined by an
    already-resolved literal argument. This is real decoding (base64 module),
    not guessing — if the input isn't a resolved literal, it stays unresolved.

    Intentionally narrow: Base64.decode of a literal, and String's byte-array
    constructor wrapping an already-resolved literal. XOR/custom decoders
    that live in the app's own code are handled separately by the local
    leaf-method summarization below; a *parameterized* local decoder (one
    whose decrypted output depends on a caller-supplied key/ciphertext
    argument, not just constants baked into the helper itself) is a known,
    documented gap — resolving that would require mapping caller registers
    onto callee parameter registers, which this engine deliberately does not
    guess at.
    """
    if "Landroid/util/Base64;->decode" in target:
        arg0 = resolved_args.get(0)
        if arg0 and arg0[0] == "literal":
            try:
                padded = arg0[1] + "=" * (-len(arg0[1]) % 4)
                decoded = base64.b64decode(padded)
                return ("literal", decoded.decode("utf-8", errors="replace"))
            except Exception:
                return None
    if "Ljava/lang/String;-><init>(" in target and "[B" in target:
        # this = registers[0], the byte-array (or byte-array+charset) arg = registers[1].
        arg1 = resolved_args.get(1)
        if arg1 and arg1[0] == "literal":
            return ("literal", arg1[1])
    return None


@dataclass
class ResolvedInvoke:
    method_sig: str
    node_id: str
    target_api: str
    registers: list = field(default_factory=list)
    # index into `registers` -> ("literal"|"class", value)
    resolved: dict = field(default_factory=dict)

    def arg(self, index: int):
        return self.resolved.get(index)


def parse_invoke_registers_and_target(output: str) -> tuple[list[str], str | None]:
    """Splits an invoke instruction's output into (argument registers, target signature)."""
    match = _INVOKE_TARGET_RE.search(output)
    if not match:
        return [], None
    target = match.group(1)
    prefix = output[: match.start()].rstrip(", ")
    registers = [r.strip() for r in prefix.split(",") if r.strip()]
    return registers, target


def _resolve_method(
    g: nx.DiGraph,
    order: list[str],
    method_sig: str,
    local_summaries: dict[str, str] | None = None,
) -> tuple[list[ResolvedInvoke], dict[str, dict[str, tuple[str, str]]]]:
    """
    Returns (invoke events, per-node exit register maps) — the exit maps are
    needed by _find_return_literal for the leaf-summarization pre-pass, so
    callers doing that pass don't have to re-walk every instruction twice.
    """
    local_summaries = local_summaries or {}
    events: list[ResolvedInvoke] = []
    exit_maps: dict[str, dict[str, tuple[str, str]]] = {}
    visited: set[str] = set()

    for node_id in order:
        preds = list(g.predecessors(node_id))
        regs: dict[str, tuple[str, str]] = (
            dict(exit_maps.get(preds[0], {})) if len(preds) == 1 and preds[0] in visited else {}
        )
        pending_result: tuple[str, str] | None = None

        for mnemonic, output in g.nodes[node_id].get("instr_stream", []):
            if mnemonic in _CONST_STRING_MNEMONICS:
                literal = parse_const_string(output)
                if literal is not None:
                    reg = output.split(",", 1)[0].strip()
                    regs[reg] = ("literal", literal)
                pending_result = None
            elif mnemonic == "new-instance":
                m = _NEW_INSTANCE_RE.match(output)
                if m:
                    regs[m.group(1)] = ("class", m.group(2))
                pending_result = None
            elif mnemonic in _MOVE_MNEMONICS:
                parts = [p.strip() for p in output.split(",")]
                if len(parts) == 2:
                    dst, src = parts
                    if src in regs:
                        regs[dst] = regs[src]
                    else:
                        regs.pop(dst, None)
                pending_result = None
            elif mnemonic == "move-result-object":
                dst = output.strip()
                if pending_result is not None:
                    # A known-transform or local-leaf-summary invoke just ran and
                    # this move-result-object claims its result — fold it in as a
                    # resolved literal instead of treating it as opaque.
                    regs[dst] = pending_result
                else:
                    regs.pop(dst, None)
                pending_result = None
            elif mnemonic.startswith("invoke"):
                registers, target = parse_invoke_registers_and_target(output)
                pending_result = None
                if target is None:
                    continue
                resolved = {i: regs[r] for i, r in enumerate(registers) if r in regs}
                events.append(ResolvedInvoke(method_sig, node_id, target, registers, resolved))

                transform = _try_known_transform(target, resolved)
                if transform is None and target in local_summaries:
                    transform = ("literal", local_summaries[target])
                if transform is not None:
                    if mnemonic == "invoke-direct" and "-><init>(" in target and registers:
                        # A constructor mutates `this` in place — no move-result-object follows.
                        regs[registers[0]] = transform
                    else:
                        pending_result = transform
            else:
                pending_result = None

        exit_maps[node_id] = regs
        visited.add(node_id)

    return events, exit_maps


def _find_return_literal(g: nx.DiGraph, exit_maps: dict[str, dict[str, tuple[str, str]]]) -> str | None:
    """
    A method summarizes to a constant literal only if EVERY return-object
    instruction in it resolves to the same literal — one unresolved or
    divergent return path means the method's output depends on something
    this engine can't see (an argument, a branch), so no summary is safe.
    """
    values: set[str] = set()
    saw_return = False
    for node_id, data in g.nodes(data=True):
        stream = data.get("instr_stream", [])
        if not stream:
            continue
        mnemonic, output = stream[-1]
        if mnemonic != "return-object":
            continue
        saw_return = True
        reg = output.strip()
        val = exit_maps.get(node_id, {}).get(reg)
        if val is None or val[0] != "literal":
            return None
        values.add(val[1])
    return next(iter(values)) if saw_return and len(values) == 1 else None


def resolve_invocations(cfgs: dict[str, nx.DiGraph]) -> list[ResolvedInvoke]:
    """
    Runs the shared register/class resolver once over every method's CFG,
    returning a flat list of every invoke instruction encountered with
    whatever argument registers could be traced back to a literal or a
    freshly-constructed class. Callers filter this list for the specific
    APIs they care about (reflection, crypto, class loading, WebView, ...).

    Two passes: the first resolves every method in isolation and, for any
    method whose every return path resolves to the same literal independent
    of caller-supplied input (a local `decode()`-style helper with no
    parameters it depends on), records that as a callable summary. The
    second pass re-resolves everything with those summaries available, so a
    call site that invokes such a helper sees its constant return value
    instead of an opaque `move-result-object`.
    """
    orders: dict[str, list[str]] = {}
    for method_sig, g in cfgs.items():
        orders[method_sig] = (
            list(nx.topological_sort(g)) if nx.is_directed_acyclic_graph(g) else list(g.nodes())
        )

    local_summaries: dict[str, str] = {}
    for method_sig, g in cfgs.items():
        _, exit_maps = _resolve_method(g, orders[method_sig], method_sig)
        literal = _find_return_literal(g, exit_maps)
        if literal is not None:
            local_summaries[_strip_method_sig_suffix(method_sig)] = literal

    all_events: list[ResolvedInvoke] = []
    for method_sig, g in cfgs.items():
        events, _ = _resolve_method(g, orders[method_sig], method_sig, local_summaries)
        all_events.extend(events)
    return all_events


def short_api(target_api: str) -> str:
    """Renders 'Ljava/lang/Class;->forName(...)V' as 'java.lang.Class.forName'."""
    sig = target_api.split("(", 1)[0]
    return sig.replace("L", "", 1).replace(";->", ".").replace("/", ".")
