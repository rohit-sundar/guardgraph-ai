"""
Human-readable "probable cause" classification for analysis-pipeline
failures. A raw Python exception ("IndexError: string index out of range")
tells an analyst nothing actionable when static analysis can't complete.
This maps known failure signatures — ones this project has actually hit or
that are well-documented Android anti-analysis techniques, not a
hypothetical exhaustive list — to a plain-English explanation, so the
fallback report says something useful instead of a stack-trace fragment.

Matches against the full traceback text (not just the exception's own repr)
because the exception CLASS is often generic (IndexError, struct.error) —
what actually identifies the failure is WHERE it happened (which parser,
which file), which only the traceback frames carry.

Deliberately conservative: an unrecognized failure gets an honest
"unrecognized" label, not a guessed cause. A wrong guess here repeats the
mistake this project avoids everywhere else in its deobfuscation work —
see static_resolution.py's "absence of evidence, not evidence of absence"
rule, applied here to failure attribution instead of register values.
"""
import traceback

# (needle to match in the lowercased traceback text, short label, explanation)
# Order matters: more specific signatures are checked before generic ones.
_SIGNATURES: list[tuple[str, str, str]] = [
    (
        "axml",
        "Malformed AndroidManifest.xml (AXML)",
        "The manifest's binary XML structure is corrupted or deliberately padded "
        "with junk bytes between chunk headers — a known technique to desync "
        "static-analysis parsers. DEX/CFG-level analysis may still be possible "
        "even though manifest-derived fields (permissions, components) are not; "
        "see manifest_parse_failed in the coverage note if this sample recovered "
        "partial coverage rather than failing outright.",
    ),
    (
        "badzipfile",
        "Corrupted or non-standard ZIP structure",
        "The APK's ZIP container doesn't parse cleanly — a malformed central "
        "directory, non-standard compression, or deliberately broken archive "
        "structure. Some packers rely on this to survive on-device while "
        "defeating desktop analysis tools that enforce strict ZIP rules.",
    ),
    (
        "struct.error",
        "Truncated or corrupted binary structure",
        "A fixed-size binary structure (a DEX header, method table, or similar) "
        "is shorter than the format requires — consistent with a truncated, "
        "hand-edited, or deliberately malformed file.",
    ),
    (
        "memoryerror",
        "Resource-exhaustion pattern",
        "The sample triggered excessive memory allocation during parsing — "
        "consistent with a deeply nested or artificially inflated structure "
        "designed to exhaust automated analysis tools (an analysis-DoS "
        "technique) rather than a normal application.",
    ),
    (
        "recursionerror",
        "Pathologically deep/nested structure",
        "Parsing recursed past Python's limit — consistent with deliberately "
        "deep nesting (XML, class hierarchies, or resource references) crafted "
        "to break recursive-descent parsers.",
    ),
    (
        "core\\dex",  # Windows path separator; matched case-insensitively below
        "DEX structure parsing failure",
        "Androguard's DEX parser failed on this file's bytecode structure — "
        "consistent with a corrupted, truncated, or deliberately malformed DEX "
        "that doesn't match the format Androguard expects.",
    ),
    (
        "core/dex",  # POSIX path separator, same bucket as above
        "DEX structure parsing failure",
        "Androguard's DEX parser failed on this file's bytecode structure — "
        "consistent with a corrupted, truncated, or deliberately malformed DEX "
        "that doesn't match the format Androguard expects.",
    ),
]


def probable_cause(exc: BaseException) -> tuple[str, str]:
    """
    Returns (short_label, explanation) for a failure, matched against the
    full traceback text. Falls back to an honest "unrecognized" label
    rather than guessing when nothing matches a known signature.
    """
    tb_text = "".join(
        traceback.format_exception(type(exc), exc, exc.__traceback__)
    ).lower()
    for needle, label, explanation in _SIGNATURES:
        if needle in tb_text:
            return label, explanation
    return (
        "Unrecognized parser failure",
        "This failure doesn't match a known evasion signature. It may be a "
        "genuinely novel anti-analysis technique, a corrupted (non-malicious) "
        "download, or an edge case this analyzer doesn't yet handle — treat "
        "the sample as unverified and triage it manually.",
    )
