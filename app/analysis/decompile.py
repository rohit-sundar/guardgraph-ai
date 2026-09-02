"""
Targeted method decompilation — turns the bytecode this pipeline already
analysed back into readable Java, for the methods that carry evidence.

Deliberately NOT a whole-APK decompiler. The probe sample carries 24,551
methods; cfg.py's relevance pre-filter already narrows that to a few hundred,
and Phase 3 narrows it again to the handful that actually matched a forensic
anchor. Those are the methods worth a human — or a model — reading, and
decompiling only them is what keeps this affordable: measured on that sample,
Androguard's DAD decompiler produced 8 method bodies in 0.38s total (0.00-0.34s
each), against 12.0s just to parse the APK.

No decompiler is constructed here. `AnalyzeAPK` already attaches a DecompilerDAD
to every DEX it loads, and ingest.py's manifest-failure fallback does the same
by hand (see _fallback_dex_analysis), so both ingestion paths arrive here with
`EncodedMethod.get_source()` ready to call.

This module holds no LLM call and no network access on purpose: what to read is
a static-analysis question, and keeping it separate is what lets the selection
logic be tested without standing up Ollama. The mapping pass that consumes this
lives in app/reports/code_mapping.py.
"""
from __future__ import annotations

import networkx as nx
from loguru import logger

from app.analysis.cfg import split_method_signature
from app.core.schemas import DecompiledMethod
from app.ml.features import TTP_SENSITIVE_API_VOCAB

# Per-method ceiling on the source handed downstream. A method body is prompt
# budget, and an obfuscated app has single methods running to tens of kilobytes;
# past a couple of thousand characters the extra text is repetition, not
# evidence. Truncation is recorded on the record rather than done silently, so
# a mapping drawn from a partial body can be read as such.
MAX_CHARS_PER_METHOD = 2000

# APIs the Phase 3.5 reverse-engineering modules resolve. A method calling one of
# these is worth reading even when its argument never resolved to a literal —
# arguably MORE so, since an unresolvable Cipher.getInstance or DexClassLoader
# argument is exactly the case static resolution cannot answer and a reader can.
# Kept as substrings of the Smali-form call, matching how every other API test in
# this codebase works.
# Packages that ship inside almost every Android app and are not the app's own
# code. A method here is overwhelmingly likely to be library plumbing that merely
# tripped an anchor — measured over the five Bank of India evaluation APKs
# (2026-09-01): 6 of 30 selected methods came from these, and on `com.boi.mpay`
# (the GENUINE Bank of India app) they produced all four of its mappings —
# an AndroidX location shim, a Firebase task, and a ButterKnife view binding.
# Every one a false positive on framework code.
#
# DEMOTED, NOT EXCLUDED. Two reasons, and both matter:
#   * malware hides in a squatted namespace precisely because it looks like this
#     list — impersonation.py already detects `package_namespace_squat` — so a
#     hard exclusion would blind the reader to the case worth catching most;
#   * on an app that is ALL framework code, a demoted candidate is still better
#     than an empty tab.
# They therefore sink to the back of their tier and are read only if nothing
# better fills the budget.
#
# Note what this deliberately does NOT do: rank the app's own package first.
# Sample 3 of that evaluation set declares `in.mahila5.pay.invest` and hides its
# dropper in `io.trust.verify.pass` — an unrelated package name is the norm for
# this malware, not the exception, so own-package-first would demote exactly the
# code that matters.
_THIRD_PARTY_PREFIXES = (
    "androidx.", "android.support.", "android.arch.",
    "com.google.android.gms.", "com.google.android.material.",
    "com.google.firebase.", "com.google.common.", "com.google.gson.",
    "kotlin.", "kotlinx.", "scala.", "j$.",
    "okhttp3.", "okio.", "retrofit2.", "butterknife.", "dagger.",
    "com.squareup.", "io.reactivex.", "rx.", "org.apache.", "org.json.",
    "com.bumptech.glide.", "com.facebook.", "com.airbnb.", "io.fabric.",
)

_RE_RELEVANT_APIS = (
    "Ljavax/crypto/Cipher;->getInstance",
    "Ljavax/crypto/spec/SecretKeySpec;-><init>",
    "Ldalvik/system/DexClassLoader",
    "Ldalvik/system/InMemoryDexClassLoader",
    "Ldalvik/system/PathClassLoader",
    "Landroid/webkit/WebView;->addJavascriptInterface",
    "Ljava/lang/System;->loadLibrary",
    "Ljava/lang/Runtime;->loadLibrary",
)


def _truncate(source: str) -> tuple[str, bool]:
    """Caps a body at MAX_CHARS_PER_METHOD on a line boundary.

    Cutting mid-line would hand the model a fragment it could still quote as
    `evidence`, and the validator matches evidence against exactly this text —
    so a clean line boundary keeps the quote checkable.
    """
    if len(source) <= MAX_CHARS_PER_METHOD:
        return source, False
    head = source[:MAX_CHARS_PER_METHOD]
    cut = head.rfind("\n")
    if cut > 0:
        head = head[:cut]
    return head + "\n    // ... [truncated by GuardGraph — method body continues]\n", True


def _anchor_candidates(behavioral_subgraphs: list) -> list[tuple[str, str]]:
    """
    (method_signature, selection_reason) for methods carrying a forensic anchor,
    ordered breadth-before-depth.

    One representative per distinct behavior flag first, then the rest by anchor
    count. Same reasoning as pipeline._select_topology_subgraphs: an app with
    forty DYNAMIC_REFLECTION anchors and one OTP_INTERCEPTION anchor otherwise
    spends the whole budget on reflection and never shows the model the OTP
    theft, which is the finding that matters.
    """
    counts: dict[str, int] = {}
    flags: dict[str, set[str]] = {}
    for bs in behavioral_subgraphs:
        sig = bs.method_signature
        if not sig:
            continue
        counts[sig] = counts.get(sig, 0) + 1
        flags.setdefault(sig, set()).add(bs.primary_behavior_flag)

    by_anchor_count = sorted(counts, key=lambda s: (-counts[s], s))

    ordered: list[tuple[str, str]] = []
    seen_sigs: set[str] = set()
    seen_flags: set[str] = set()

    for sig in by_anchor_count:
        new_flags = flags[sig] - seen_flags
        if new_flags:
            seen_flags.update(flags[sig])
            seen_sigs.add(sig)
            ordered.append((sig, "anchor:" + ",".join(sorted(new_flags))))

    for sig in by_anchor_count:
        if sig not in seen_sigs:
            ordered.append((sig, "anchor:" + ",".join(sorted(flags[sig]))))

    return ordered


def _method_api_calls(g: nx.DiGraph) -> list[str]:
    return [api for _, data in g.nodes(data=True) for api in data.get("api_calls", [])]


def _re_candidates(cfgs: dict[str, nx.DiGraph]) -> list[tuple[str, str]]:
    """Methods invoking an API the Phase 3.5 RE modules resolve (see _RE_RELEVANT_APIS)."""
    out: list[tuple[str, str]] = []
    for sig, g in cfgs.items():
        calls = _method_api_calls(g)
        hits = sorted({
            api.rsplit("->", 1)[-1] if "->" in api else api.rsplit("/", 1)[-1]
            for api in _RE_RELEVANT_APIS
            if any(api in call for call in calls)
        })
        if hits:
            out.append((sig, "re_api:" + ",".join(hits)))
    return out


def _density_candidates(cfgs: dict[str, nx.DiGraph]) -> list[tuple[str, str]]:
    """
    Methods ranked by how many DISTINCT sensitive APIs they touch.

    The last-resort tier, and the reason it exists: an app whose evasion defeats
    the forensic dictionary produces no anchors at all, which is precisely the
    sample where a human reading the code has most to add. Falling silent there
    would make this pass useful only where the deterministic layer had already
    succeeded.

    Distinct APIs rather than total calls, deliberately — a loop calling
    Base64.decode two hundred times is one behaviour, not two hundred.
    """
    scored: list[tuple[int, str]] = []
    for sig, g in cfgs.items():
        calls = _method_api_calls(g)
        hits = sum(
            1 for api in TTP_SENSITIVE_API_VOCAB if any(api in call for call in calls)
        )
        if hits:
            scored.append((hits, sig))
    scored.sort(key=lambda p: (-p[0], p[1]))
    return [(sig, f"api_density:{n}") for n, sig in scored]


def is_third_party(method_sig: str) -> bool:
    """True when this method belongs to a bundled library rather than the app."""
    class_name, _ = split_method_signature(method_sig)
    return class_name.startswith(_THIRD_PARTY_PREFIXES)


def _demote_third_party(
    candidates: list[tuple[str, str]]
) -> list[tuple[str, str]]:
    """
    Sinks bundled-library methods to the back of their tier, preserving the order
    within each group.

    A stable partition rather than a filter — see _THIRD_PARTY_PREFIXES for why
    these are demoted and not dropped. Ranking is only ever consulted until the
    budget fills, so on an app with enough of its own interesting code this
    removes library methods from the prompt entirely, while an app that has
    nothing else still gets them.
    """
    own = [c for c in candidates if not is_third_party(c[0])]
    library = [c for c in candidates if is_third_party(c[0])]
    return own + library


def select_methods(
    cfgs: dict[str, nx.DiGraph],
    behavioral_subgraphs: list,
    limit: int,
) -> list[tuple[str, str]]:
    """
    (method_signature, selection_reason) for the methods worth decompiling,
    best first, capped at `limit`.

    Three tiers in descending evidentiary strength — forensic anchors, then
    RE-relevant API calls, then raw sensitive-API density. Later tiers FILL
    remaining slots rather than only firing when earlier ones are empty: an app
    with two anchor methods still gets six more methods of context, and the
    selection_reason on each says which tier it came from.
    """
    ordered: list[tuple[str, str]] = []
    seen: set[str] = set()
    for tier in (
        _anchor_candidates(behavioral_subgraphs),
        _re_candidates(cfgs),
        _density_candidates(cfgs),
    ):
        for sig, reason in _demote_third_party(tier):
            if sig in seen or len(ordered) >= limit:
                continue
            seen.add(sig)
            ordered.append((sig, reason))
        if len(ordered) >= limit:
            break
    return ordered


def select_and_decompile(
    analysis_obj,
    cfgs: dict[str, nx.DiGraph],
    behavioral_subgraphs: list,
    limit: int,
) -> tuple[list[DecompiledMethod], str]:
    """
    Returns (decompiled methods, coverage note).

    Never raises. A method DAD cannot decompile is skipped and counted into the
    coverage note — a partial set of bodies is still worth reading, and losing
    the whole pass to one malformed method would be the wrong trade on samples
    that are malformed on purpose.
    """
    if analysis_obj is None or not cfgs:
        return [], "no code was recovered from this sample — nothing to decompile"

    selected = select_methods(cfgs, behavioral_subgraphs, limit)
    if not selected:
        return [], "no method carried an anchor, an RE-relevant API or any sensitive API"

    # str(m.get_method()) is the same key build_all_method_cfgs stores its graphs
    # under (cfg.py), so this maps a CFG signature straight back to the
    # MethodAnalysis that produced it. External methods have no code body.
    by_sig: dict[str, object] = {}
    try:
        for m in analysis_obj.get_methods():
            if m.is_external():
                continue
            by_sig[str(m.get_method())] = m
    except Exception as e:
        logger.warning(f"[decompile] Could not index methods for decompilation: {e}")
        return [], f"method index unavailable ({type(e).__name__}) — nothing decompiled"

    decompiled: list[DecompiledMethod] = []
    failed = 0
    missing = 0
    for sig, reason in selected:
        method_analysis = by_sig.get(sig)
        if method_analysis is None:
            missing += 1
            continue
        try:
            source = method_analysis.get_method().get_source() or ""
        except Exception as e:
            logger.debug(f"[decompile] DAD failed on {sig[:80]}: {type(e).__name__}: {e}")
            failed += 1
            continue
        if not source.strip():
            failed += 1
            continue
        body, truncated = _truncate(source)
        class_name, method_name = split_method_signature(sig)
        decompiled.append(
            DecompiledMethod(
                method_signature=sig,
                class_name=class_name,
                method_name=method_name,
                source=body,
                truncated=truncated,
                selection_reason=reason,
            )
        )

    notes = [f"{len(decompiled)} of {len(selected)} selected methods decompiled"]
    if failed:
        notes.append(f"{failed} could not be decompiled")
    if missing:
        notes.append(f"{missing} had no recoverable method body")
    logger.info(f"[decompile] {'; '.join(notes)}.")
    return decompiled, "; ".join(notes)
