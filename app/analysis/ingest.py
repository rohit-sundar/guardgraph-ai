"""
APK ingestion: hashing, cert thumbprint, manifest/permission/component extraction,
plus Android malware static enrichments (C2 IoCs, permission matrix, cert anomalies,
secondary DEX / dropper payloads, accessibility config, exported component risks).

This is the entry point of the cold path — everything downstream depends on
Androguard successfully parsing the APK, so failures here should be loud,
not swallowed.
"""
import hashlib
from pathlib import Path
from typing import Any

from androguard.misc import AnalyzeAPK
from loguru import logger

from app.core.schemas import IngestionResult
from app.analysis.apk_static import (
    extract_c2_indicators,
    detect_permission_matrix,
    analyze_certificate_anomalies,
    extract_der_certificates,
    inspect_apk_payloads,
    parse_accessibility_configs,
)


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

    apk_obj, dvm, analysis = AnalyzeAPK(filepath)

    # 1. Inspect payloads (secondary DEX and assets)
    payload_info = inspect_apk_payloads(filepath)
    secondary_dex_count = payload_info.get("secondary_dex_count", 0)
    yara_targets = payload_info.get("yara_targets", [])
    asset_strings = payload_info.get("asset_strings", [])

    # 2. Extract C2 from asset strings
    c2_indicators = extract_c2_indicators(asset_strings)

    # 3. Analyze cert anomalies
    der_certs = extract_der_certificates(apk_obj)
    cert_anomalies = analyze_certificate_anomalies(der_certs)

    # 4. Detect permission matrices
    permissions = list(apk_obj.get_permissions())
    permission_matrix_flags = detect_permission_matrix(permissions)

    # Add accessibility config flags to permission matrix flags if accessibility is used
    a11y_flags = []
    if "android.permission.BIND_ACCESSIBILITY_SERVICE" in permissions:
        a11y_flags = parse_accessibility_configs(apk_obj)
        permission_matrix_flags.extend(a11y_flags)

    payload_assets = payload_info.get("payload_assets", [])
    dropper_signals = payload_info.get("dropper_signals", [])

    result = IngestionResult(
        sha256=sha256,
        package_name=apk_obj.get_package(),
        cert_thumbprint=extract_cert_thumbprint(apk_obj),
        permissions=permissions,
        activities=list(apk_obj.get_activities()),
        services=list(apk_obj.get_services()),
        receivers=list(apk_obj.get_receivers()),
        intent_actions=extract_intent_actions(apk_obj),
        c2_indicators=c2_indicators,
        cert_anomalies=cert_anomalies,
        permission_matrix_flags=permission_matrix_flags,
        secondary_dex_count=secondary_dex_count,
        accessibility_flags=a11y_flags,
        payload_assets=payload_assets,
        dropper_signals=dropper_signals,
    )

    logger.info(
        f"Ingest enrichments: c2={len(result.c2_indicators)}, "
        f"cert_anomalies={len(result.cert_anomalies)}, "
        f"perm_matrix={result.permission_matrix_flags}, "
        f"secondary_dex={result.secondary_dex_count}, "
        f"a11y={len(result.accessibility_flags)}, "
        f"dropper_signals={len(result.dropper_signals)}, "
        f"yara_targets={len(yara_targets)}"
    )

    return result, apk_obj, dvm, analysis, yara_targets
