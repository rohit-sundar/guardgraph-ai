"""
APK ingestion: hashing, cert thumbprint, manifest/permission/component extraction,
plus Android malware static enrichments (C2 IoCs, permission matrix, cert anomalies,
secondary DEX / dropper payloads, accessibility config, exported component risks).

This is the entry point of the cold path — everything downstream depends on
Androguard successfully parsing the APK, so failures here should be loud,
not swallowed.
"""
import hashlib
import struct
import zipfile
import zlib
from pathlib import Path
from typing import Any

from androguard.core import dex
from androguard.core.analysis.analysis import Analysis
from androguard.decompiler import decompiler as _decompiler
from androguard.misc import AnalyzeAPK
from loguru import logger

from app.core.schemas import IngestionResult
from app.analysis.impersonation import extract_icon_phash
from app.analysis.apk_static import (
    accessibility_matrix_flags,
    declares_accessibility_service,
    extract_c2_indicators,
    detect_permission_matrix,
    analyze_certificate_anomalies,
    extract_der_certificates,
    inspect_apk_payloads,
    parse_accessibility_configs,
)

_ZIP_LOCAL_HEADER_SIG = b"PK\x03\x04"


def _raw_scan_dex_from_corrupted_zip(data: bytes) -> dict[str, bytes]:
    """
    Recovers classes*.dex directly from ZIP LOCAL file headers, bypassing
    the central directory / End-Of-Central-Directory record entirely.

    A corrupted or deliberately broken EOCD is a documented Android
    anti-analysis technique in its own right — Python's `zipfile` (and many
    desktop tools) refuse to open the archive at all, while the Android
    runtime's own ZIP reader is more permissive and boots the app fine. This
    walks the raw bytes for `PK\\x03\\x04` local-header signatures instead of
    trusting the central directory, so classes.dex is still recoverable even
    when zipfile.ZipFile() itself raises BadZipFile.

    Only entries using the LOCAL header's own size fields are extracted —
    an entry using a streaming "data descriptor" (general-purpose flag bit 3
    set, sizes zeroed in the local header) has its real size written AFTER
    the compressed data instead, which this deliberately does not chase:
    guessing at a boundary would risk silently truncating or corrupting the
    dex.DEX() parse rather than failing cleanly. Skipped, not guessed.
    """
    results: dict[str, bytes] = {}
    pos = 0
    while True:
        pos = data.find(_ZIP_LOCAL_HEADER_SIG, pos)
        if pos == -1:
            break
        fixed_start = pos + 4
        fixed_end = fixed_start + 26
        if fixed_end > len(data):
            break
        (
            _version_needed, _gp_flags, method, _mtime, _mdate,
            _crc32, comp_size, _uncomp_size, name_len, extra_len,
        ) = struct.unpack("<HHHHHIIIHH", data[fixed_start:fixed_end])

        name_start = fixed_end
        name_end = name_start + name_len
        data_start = name_end + extra_len
        if data_start > len(data):
            pos = fixed_start
            continue
        name = data[name_start:name_end].decode("utf-8", errors="replace")
        is_dex_candidate = name.startswith("classes") and name.endswith(".dex") and "/" not in name
        consumed = 0  # bytes of entry data actually accounted for, to advance the scan past it

        if method == 8:
            # Deflate is self-terminating — the final block carries a BFINAL bit,
            # so a compliant decompressor knows exactly where the stream ends
            # without trusting comp_size at all. This is what actually matters
            # here: real APKs commonly write DEX entries with the streaming
            # data-descriptor flag set (sizes zeroed in the local header, real
            # sizes written AFTER the data) — confirmed empirically against this
            # project's own corpus — so refusing to touch anything but a
            # trustworthy comp_size would skip the common case entirely, not
            # just the rare one. Decompressing to zlib's own EOF marker isn't
            # guessing; it's relying on the format's structure the same way
            # `zip -FF` repair tools do.
            decompressor = zlib.decompressobj(-15)
            try:
                remainder = data[data_start:]
                payload = decompressor.decompress(remainder)
                if decompressor.eof:
                    consumed = len(remainder) - len(decompressor.unused_data)
                    if is_dex_candidate:
                        results[name] = payload
            except Exception as e:
                logger.warning(f"Raw-scan recovery of {name} failed to inflate: {e}")
        elif method == 0 and comp_size > 0:
            # Stored (uncompressed) has no self-terminating marker, so this only
            # works when the local header's own size is trustworthy — i.e. not
            # a streaming entry with zeroed sizes. Rare for a DEX in practice
            # (APKs deflate their DEX for size), not worth chasing further.
            data_end = data_start + comp_size
            if data_end <= len(data):
                consumed = comp_size
                if is_dex_candidate:
                    results[name] = data[data_start:data_end]

        # Advance past this entry to keep scanning; fall back to just past the
        # signature if we couldn't determine how much data this entry consumed.
        pos = data_start + consumed if consumed > 0 else fixed_start

    return results


def _fallback_dex_analysis(filepath: str) -> tuple[list, Any] | tuple[None, None]:
    """
    Manifest-independent DEX/CFG extraction — the fallback when apk.APK()
    (which parses AndroidManifest.xml as its first step) fails.

    A corrupted-but-recoverable manifest is a documented Android
    anti-analysis technique: junk bytes inserted between AXML chunk headers
    force Androguard's parser into a byte-by-byte resync search, which can
    fail outright (raising ResParserError / IndexError deep in axml parsing)
    even though the DEX itself is perfectly intact. classes*.dex sit at the
    ZIP root and need zero manifest parsing to read, so a corrupted manifest
    doesn't have to mean zero coverage — CFG-level analysis (forensic
    anchors that don't require a manifest `declares` gate, reflection/
    crypto/DCL/WebView/native resolution) can still run against them.

    Two layers: zipfile first (fast, handles the common case), and if the
    ZIP's own central directory is ALSO corrupted (a separate, documented
    anti-analysis technique — the Android runtime's ZIP reader is more
    permissive than Python's zipfile and boots such an app fine), a raw
    local-header scan of the bytes as a second attempt before giving up.

    Mirrors androguard.misc.AnalyzeAPK's own DEX/Analysis construction
    (using_api omitted — there is no target-SDK value available without the
    manifest; Androguard defaults it internally).
    """
    dex_bytes_by_name: dict[str, bytes] = {}
    try:
        with zipfile.ZipFile(filepath) as z:
            dex_names = sorted(
                n for n in z.namelist() if n.startswith("classes") and n.endswith(".dex")
            )
            dex_bytes_by_name = {name: z.read(name) for name in dex_names}
    except Exception as e:
        logger.warning(f"zipfile could not open the APK ({e}); trying a raw local-header scan.")
        try:
            with open(filepath, "rb") as f:
                raw_file_bytes = f.read()
            dex_bytes_by_name = _raw_scan_dex_from_corrupted_zip(raw_file_bytes)
            if dex_bytes_by_name:
                logger.info(
                    f"Raw local-header scan recovered {len(dex_bytes_by_name)} DEX file(s) "
                    "from a ZIP whose central directory doesn't parse."
                )
        except Exception as e2:
            logger.warning(f"Raw local-header scan also failed: {e2}")
            return None, None

    if not dex_bytes_by_name:
        return None, None

    try:
        dx = Analysis()
        dfs = []
        for name in sorted(dex_bytes_by_name):
            df = dex.DEX(dex_bytes_by_name[name])
            dx.add(df)
            dfs.append(df)
            df.set_decompiler(_decompiler.DecompilerDAD(df, dx))
        dx.create_xref()
        return dfs, dx
    except Exception as e:
        logger.warning(f"Manifest-independent DEX fallback also failed: {e}")
        return None, None


def compute_sha256(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def extract_cert_thumbprint(apk_obj) -> str | None:
    """
    Returns SHA-256 of the signing certificate, or None if unsigned /
    extraction fails. An unsigned or malformed cert is itself a risk
    signal — don't silently treat None the same as "clean".
    """
    try:
        certs = apk_obj.get_certificates_der_v3() or apk_obj.get_certificates_der_v2()
        if not certs:
            return None
        return hashlib.sha256(certs[0]).hexdigest()
    except Exception:
        return None


def extract_intent_actions(apk_obj) -> list[str]:
    """
    Collects declared intent-filter actions across all activities, services, and
    receivers. Used by the multi-label TTP feature vector's intent vocabulary.

    Best-effort: Androguard's per-component get_intent_filters can vary in shape /
    raise on malformed manifests, so each lookup is guarded. Returns a de-duplicated
    sorted list; an empty list is a valid (not-observed) result, not an error.
    """
    actions: set[str] = set()
    component_getters = [
        ("activity", apk_obj.get_activities),
        ("service", apk_obj.get_services),
        ("receiver", apk_obj.get_receivers),
    ]
    for itemtype, getter in component_getters:
        try:
            names = getter() or []
        except Exception:
            continue
        for name in names:
            try:
                filters = apk_obj.get_intent_filters(itemtype, name) or {}
            except Exception:
                continue
            for action in filters.get("action", []) or []:
                if action:
                    actions.add(action)
    return sorted(actions)


def ingest_apk(filepath: str) -> tuple[IngestionResult, object, object, object, list]:
    """
    Runs Androguard's full analysis pass and performs advanced static APK analysis.

    Returns:
        (IngestionResult, apk_obj, dalvik_vm_format, analysis_obj, yara_targets)

    The raw objects are returned alongside the parsed schema because CFG
    construction (cfg.py) needs direct access to the DalvikVMFormat /
    Analysis objects — don't re-parse the APK a second time downstream.
    """
    sha256 = compute_sha256(filepath)

    manifest_parse_failed = False
    try:
        apk_obj, dvm, analysis = AnalyzeAPK(filepath)
    except Exception as e:
        logger.warning(
            f"AndroidManifest.xml parsing failed ({e}) — likely a deliberately "
            "corrupted manifest (junk bytes between AXML chunk headers is a known "
            "anti-analysis technique). Falling back to manifest-independent DEX/CFG "
            "extraction; permission/component/cert fields will be unavailable, not "
            "analysed."
        )
        apk_obj = None
        dvm, analysis = _fallback_dex_analysis(filepath)
        manifest_parse_failed = True
        if analysis is None:
            # Both the manifest AND a raw-ZIP DEX read failed — nothing left to
            # analyze. Re-raise so the caller's existing unparseable-sample
            # handling takes over, same as before this fallback existed.
            raise

    # 1. Inspect payloads (secondary DEX and assets) — reads the raw ZIP directly,
    #    independent of apk_obj, so this still runs even without a parsed manifest.
    payload_info = inspect_apk_payloads(filepath)
    secondary_dex_count = payload_info.get("secondary_dex_count", 0)
    yara_targets = payload_info.get("yara_targets", [])
    asset_strings = payload_info.get("asset_strings", [])

    # 2. Extract C2 from asset strings
    c2_indicators = extract_c2_indicators(asset_strings)

    payload_assets = payload_info.get("payload_assets", [])
    dropper_signals = payload_info.get("dropper_signals", [])

    # 3-4b. Everything below needs apk_obj (the parsed manifest). None of it is
    # recoverable from the fallback path — reported empty, not guessed.
    cert_anomalies: list[str] = []
    permissions: list[str] = []
    intent_actions: list[str] = []
    permission_matrix_flags: list[str] = []
    a11y_flags: list[str] = []
    package_name = None
    cert_thumbprint = None
    activities: list[str] = []
    services: list[str] = []
    receivers: list[str] = []
    app_label = None
    icon_phash = None

    if apk_obj is not None:
        der_certs = extract_der_certificates(apk_obj)
        cert_anomalies = analyze_certificate_anomalies(der_certs)

        # Detect permission matrices. The declared intent actions go in too: the
        # accessibility rules key off BIND_ACCESSIBILITY_SERVICE, which is the
        # permission the system holds over a service and so almost never appears in
        # <uses-permission> — see apk_static.ACCESSIBILITY_SERVICE_ACTION (N5).
        permissions = list(apk_obj.get_permissions())
        intent_actions = extract_intent_actions(apk_obj)
        permission_matrix_flags = detect_permission_matrix(permissions, intent_actions)

        # Accessibility service config. Gated on the *declaration* — gating on the
        # <uses-permission> left accessibility_flags empty for 69 of the 75 corpus
        # malware samples that declare an accessibility service. Only the mapped
        # ACCESSIBILITY_* IDs join permission_matrix_flags; the raw config strings
        # stay in accessibility_flags, where the report and the matrix flags read
        # them, instead of reaching the scorer as unweighted unknowns.
        if declares_accessibility_service(permissions, intent_actions):
            a11y_flags = parse_accessibility_configs(apk_obj)
            permission_matrix_flags.extend(
                f for f in accessibility_matrix_flags(a11y_flags)
                if f not in permission_matrix_flags
            )

        package_name = apk_obj.get_package()
        cert_thumbprint = extract_cert_thumbprint(apk_obj)

        # App identity for brand-impersonation checks. Both are best-effort: a
        # missing label or an adaptive (XML) launcher icon is a coverage gap the
        # impersonation module reports, never a match.
        try:
            app_label = apk_obj.get_app_name() or None
        except Exception as e:
            logger.debug(f"App label unavailable: {e}")
            app_label = None
        phash = extract_icon_phash(apk_obj)
        icon_phash = f"{phash:016x}" if phash is not None else None
        activities = list(apk_obj.get_activities())
        services = list(apk_obj.get_services())
        receivers = list(apk_obj.get_receivers())

    # 5. How much code Androguard actually recovered. Counted here rather than in
    #    cfg.py because it is a property of the sample, not of the CFG pass, and
    #    because the scorer needs it to read a zero analysed-method count correctly
    #    (N7): a stub APK with a rich manifest and no recoverable code is evasion,
    #    an app whose methods simply matched nothing in the dictionary is not.
    try:
        dex_method_count = sum(1 for _ in analysis.get_methods())
    except Exception as e:
        logger.warning(f"DEX method count unavailable: {e}")
        dex_method_count = 0

    result = IngestionResult(
        sha256=sha256,
        package_name=package_name,
        cert_thumbprint=cert_thumbprint,
        app_label=app_label,
        icon_phash=icon_phash,
        permissions=permissions,
        activities=activities,
        services=services,
        receivers=receivers,
        intent_actions=intent_actions,
        c2_indicators=c2_indicators,
        cert_anomalies=cert_anomalies,
        permission_matrix_flags=permission_matrix_flags,
        secondary_dex_count=secondary_dex_count,
        dex_method_count=dex_method_count,
        accessibility_flags=a11y_flags,
        payload_assets=payload_assets,
        dropper_signals=dropper_signals,
        manifest_parse_failed=manifest_parse_failed,
    )

    logger.info(
        f"Ingest enrichments: c2={len(result.c2_indicators)}, "
        f"cert_anomalies={len(result.cert_anomalies)}, "
        f"perm_matrix={result.permission_matrix_flags}, "
        f"secondary_dex={result.secondary_dex_count}, "
        f"dex_methods={result.dex_method_count}, "
        f"a11y={len(result.accessibility_flags)}, "
        f"dropper_signals={len(result.dropper_signals)}, "
        f"yara_targets={len(yara_targets)}, "
        f"manifest_parse_failed={manifest_parse_failed}"
    )

    return result, apk_obj, dvm, analysis, yara_targets
