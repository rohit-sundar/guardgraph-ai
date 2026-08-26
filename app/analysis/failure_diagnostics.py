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
        # Checked before the parser signatures below: when AV pulls the file
        # mid-analysis the traceback can also contain a dex/axml frame, but the
        # antivirus is the cause and the parser frame is just where it surfaced.
        "errno 22",
        "Sample removed by host antivirus (not an APK defect)",
        "Reading the staged copy failed with EINVAL on a file that exists — on "
        "Windows this is the signature of resident antivirus quarantining the "
        "sample out from under the analyzer, not of a malformed APK. The file on "
        "disk is almost certainly intact and re-analysing it will fail the same "
        "way until the staging directory is excluded from scanning: see "
        "settings.upload_staging_dir. Confirm with `Get-MpThreatDetection` — the "
        "quarantined path is listed there.",
    ),
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
        # Androguard raises a plain ValueError naming the EOCD rather than a
        # BadZipFile, so the needle below never matched it and a deliberately
        # broken central directory — a technique this project already handles
        # in ingest._raw_scan_dex_from_corrupted_zip — was reported as an
        # unrecognised, possibly novel failure.
        "end of central directory",
        "Corrupted or non-standard ZIP structure",
        "The APK's ZIP container doesn't parse cleanly — the End of Central "
        "Directory record is missing or malformed. Android's own ZIP reader is "
        "more permissive than desktop tooling, so an archive shaped like this "
        "can still install and run on a device while defeating static analysis, "
        "which is exactly why packers do it.",
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
