"""
APK ingestion: hashing, cert thumbprint, manifest/permission/component extraction.
This is the entry point of the cold path — everything downstream depends on
Androguard successfully parsing the APK, so failures here should be loud,
not swallowed.
"""
import hashlib
from pathlib import Path

from androguard.misc import AnalyzeAPK

from app.core.schemas import IngestionResult


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


def ingest_apk(filepath: str) -> tuple[IngestionResult, object, object, object]:
    """
    Runs Androguard's full analysis pass.

    Returns:
        (IngestionResult, apk_obj, dalvik_vm_format, analysis_obj)

    The raw objects are returned alongside the parsed schema because CFG
    construction (cfg.py) needs direct access to the DalvikVMFormat /
    Analysis objects — don't re-parse the APK a second time downstream.
    """
    sha256 = compute_sha256(filepath)

    apk_obj, dvm, analysis = AnalyzeAPK(filepath)

    result = IngestionResult(
        sha256=sha256,
        package_name=apk_obj.get_package(),
        cert_thumbprint=extract_cert_thumbprint(apk_obj),
        permissions=list(apk_obj.get_permissions()),
        activities=list(apk_obj.get_activities()),
        services=list(apk_obj.get_services()),
        receivers=list(apk_obj.get_receivers()),
        intent_actions=extract_intent_actions(apk_obj),
    )

    return result, apk_obj, dvm, analysis
