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
    )

    return result, apk_obj, dvm, analysis
