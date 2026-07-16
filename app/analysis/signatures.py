"""
Hash-based and certificate-based signature matching against a local
known-malware database, with online fallback to VirusTotal and MalwareBazaar
APIs for real-time triage.

This is the fast, deterministic detection layer — if an APK's SHA-256 or
signing certificate matches a known-bad entry (locally or via online threat
intelligence), the sample is flagged immediately. Results feed into the risk
score's IOC component and are surfaced in the GraphRAG report.
"""
import json
import urllib.request
import urllib.parse
from pathlib import Path
from typing import Optional

from loguru import logger
from app.core.config import settings

# ── In-memory signature database ─────────────────────────────────────────

_SIGNATURE_DB: Optional[dict] = None


def load_signature_db(db_path: str) -> dict:
    """
    Loads the known-malware signature database from a JSON file.
    Returns the parsed dict. Caches in module-level _SIGNATURE_DB so
    subsequent calls don't re-read disk.

    Degrades gracefully: if the file doesn't exist or is malformed,
    returns an empty DB structure (no matches possible, no crash).
    """
    global _SIGNATURE_DB
    if _SIGNATURE_DB is not None:
        return _SIGNATURE_DB

    path = Path(db_path)
    if not path.exists():
        logger.warning(f"Signature DB not found at {db_path} — no local hash/cert matching available")
        _SIGNATURE_DB = {"hashes": {}, "certificates": {}}
        return _SIGNATURE_DB

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        _SIGNATURE_DB = {
            "hashes": data.get("hashes", {}),
            "certificates": data.get("certificates", {}),
        }
        total = len(_SIGNATURE_DB["hashes"]) + len(_SIGNATURE_DB["certificates"])
        logger.info(f"Signature DB loaded: {len(_SIGNATURE_DB['hashes'])} hashes, {len(_SIGNATURE_DB['certificates'])} certs")
        return _SIGNATURE_DB
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        logger.error(f"Failed to parse signature DB at {db_path}: {e}")
        _SIGNATURE_DB = {"hashes": {}, "certificates": {}}
        return _SIGNATURE_DB


def reset_signature_db() -> None:
    """Clears the cached DB — useful for testing or hot-reloading rules."""
    global _SIGNATURE_DB
    _SIGNATURE_DB = None


def _lookup_virustotal(sha256: str, api_key: str) -> Optional[dict]:
    """Queries the VirusTotal API v3 for a file hash."""
    if not api_key:
        return None

    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {"x-apikey": api_key}
    req = urllib.request.Request(url, headers=headers)

    try:
        logger.info(f"Querying VirusTotal API for hash: {sha256}")
        with urllib.request.urlopen(req, timeout=5) as response:
            if response.status == 200:
                result = json.loads(response.read().decode("utf-8"))
                attributes = result.get("data", {}).get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})
                malicious_count = stats.get("malicious", 0)
                total_engines = sum(stats.values()) if stats else 0

                # Get family suggestion if available
                classification = attributes.get("popular_threat_classification", {})
                suggested_family = classification.get("suggested_threat_label")

                # If any scanner calls it malicious, flag it
                if malicious_count > 0:
                    ratio = f"{malicious_count}/{total_engines} engines"
                    report_url = f"https://www.virustotal.com/gui/file/{sha256}"
                    logger.warning(f"VirusTotal match! {ratio} flagged it. Family: {suggested_family}")
                    return {
                        "match_type": "sha256",
                        "matched_value": sha256,
                        "family": suggested_family or "unknown",
                        "severity": round(min(1.0, 0.5 + (malicious_count / 10)), 2),
                        "source": "VirusTotal",
                        "description": f"VirusTotal detection: {ratio} flagged as malicious.",
                        "report_url": report_url,
                        "detection_ratio": ratio,
                    }
    except Exception as e:
        logger.error(f"VirusTotal API query failed: {e}")

    return None


def _lookup_malwarebazaar(sha256: str, api_key: str) -> Optional[dict]:
    """Queries the MalwareBazaar API for a file hash.
    
    The get_info endpoint is fully public — no API key required.
    The api_key parameter is accepted but unused (kept for interface consistency).
    """
    url = "https://mb-api.abuse.ch/api/v1/"
    post_data = urllib.parse.urlencode({
        "query": "get_info",
        "hash": sha256
    }).encode("utf-8")

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "GuardGraph-AI-Triage",
    }

    req = urllib.request.Request(url, data=post_data, headers=headers, method="POST")

    try:
        logger.info(f"Querying MalwareBazaar API for hash: {sha256}")
        with urllib.request.urlopen(req, timeout=10) as response:
            if response.status == 200:
                result = json.loads(response.read().decode("utf-8"))
                if result.get("query_status") == "ok":
                    data_list = result.get("data", [])
                    if data_list:
                        entry = data_list[0]
                        family = entry.get("signature")
                        clamav = entry.get("intelligence", {}).get("clamav")
                        mb_sha256 = entry.get("sha256_hash", sha256)
                        tags = entry.get("tags") or []

                        report_url = f"https://bazaar.abuse.ch/sample/{mb_sha256}/"
                        logger.warning(f"MalwareBazaar match! Family: {family}")
                        return {
                            "match_type": "sha256",
                            "matched_value": sha256,
                            "family": family or clamav or "unknown",
                            "severity": 0.95,
                            "source": "MalwareBazaar",
                            "description": f"MalwareBazaar database hit. Tags: {', '.join(tags)}",
                            "report_url": report_url,
                            "detection_ratio": None,
                        }
    except Exception as e:
        logger.error(f"MalwareBazaar API query failed: {e}")

    return None


def match_signatures(
    sha256: str,
    cert_thumbprint: Optional[str],
    db_path: str,
) -> list[dict]:
    """
    Checks an APK's SHA-256 hash and signing certificate against:
    1. Local known-malware signature database.
    2. Online triage lookup (VirusTotal and MalwareBazaar APIs) if keys are provided.

    Returns a list of match dicts, each with:
        match_type: "sha256" | "certificate"
        matched_value: the hex digest that matched
        family: malware family name (or None)
        severity: 0.0-1.0
        source: attribution source
        description: human-readable description

    Empty list = no known signatures matched (proceed to full analysis).
    """
    db = load_signature_db(db_path)
    matches: list[dict] = []

    # 1. Check Local SHA-256 hash
    sha256_lower = sha256.lower()
    if sha256_lower in db["hashes"]:
        entry = db["hashes"][sha256_lower]
        matches.append({
            "match_type": "sha256",
            "matched_value": sha256_lower,
            "family": entry.get("family"),
            "severity": float(entry.get("severity", 0.9)),
            "source": entry.get("source", "local"),
            "description": entry.get("description", "Local hash signature match"),
        })
        logger.warning(f"Local SHA-256 signature match: {sha256_lower} → {entry.get('family', 'unknown')}")

    # 2. Check Local certificate thumbprint
    if cert_thumbprint:
        cert_lower = cert_thumbprint.lower()
        if cert_lower in db["certificates"]:
            entry = db["certificates"][cert_lower]
            matches.append({
                "match_type": "certificate",
                "matched_value": cert_lower,
                "family": entry.get("family"),
                "severity": float(entry.get("severity", 0.8)),
                "source": entry.get("source", "local"),
                "description": entry.get("description", "Local certificate signature match"),
            })
            logger.warning(f"Local certificate signature match: {cert_lower} → {entry.get('family', 'unknown')}")

    # 3. Online triage fallbacks (only run on hash mismatch locally so we don't spam APIs)
    if not matches:
        # Check MalwareBazaar first (free, no strict rate limit on queries, highly specific for family)
        mb_match = _lookup_malwarebazaar(sha256_lower, settings.malwarebazaar_api_key)
        if mb_match:
            matches.append(mb_match)

        # Check VirusTotal
        vt_match = _lookup_virustotal(sha256_lower, settings.virustotal_api_key)
        if vt_match:
            matches.append(vt_match)

    return matches
