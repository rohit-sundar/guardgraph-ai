"""
Android APK static malware indicators for banking trojans, droppers, and
credential stealers.

Extracts high-signal deterministic anchors that feed IngestionResult /
AnalysisManifest and risk scoring:

  - C2 IoCs (Telegram bots, Firebase, Discord webhooks, TOR, raw IP:port)
  - High-risk permission matrix patterns (overlay / OTP stealer / dropper)
  - Certificate anomalies (debug keys, self-signed junk, invalid validity)
  - Secondary DEX / hidden payload assets (dropper stage-2 material)
  - AccessibilityService config XML flags (keylogging / gesture control)
  - Exported component backdoors (receivers/services without permission)

All extractors are pure / best-effort: malformed APKs never crash the pipeline.
"""
from __future__ import annotations

import io
import ipaddress
import re
import zipfile
from datetime import datetime, timezone
from typing import Any, Optional
from xml.etree import ElementTree as ET

from loguru import logger

try:
    from asn1crypto import x509 as asn1_x509
    ASN1_AVAILABLE = True
except ImportError:
    ASN1_AVAILABLE = False
    logger.warning("asn1crypto not available — certificate anomaly analysis disabled")


# ── Magic bytes ──────────────────────────────────────────────────────────

DEX_MAGIC = b"dex\n"
ZIP_MAGIC = b"PK\x03\x04"
ELF_MAGIC = b"\x7fELF"

# Cap how much of each asset we scan for strings / magic (DoS guard).
MAX_ASSET_SCAN_BYTES = 2 * 1024 * 1024  # 2 MiB per entry
MAX_YARA_PAYLOADS = 32  # max extra uncompressed streams for YARA


# ── C2 / IoC regex patterns ──────────────────────────────────────────────

# Telegram Bot API: api.telegram.org/bot<token>/...
_RE_TELEGRAM_BOT = re.compile(
    r"(?:https?://)?api\.telegram\.org/bot([0-9]{6,}:[A-Za-z0-9_-]{20,})(?:/\S*)?",
    re.IGNORECASE,
)
# Bare bot token often appears as a string literal next to sendMessage etc.
_RE_TELEGRAM_TOKEN = re.compile(
    r"\b([0-9]{8,12}:[A-Za-z0-9_-]{30,})\b",
)

_RE_FIREBASE = re.compile(
    r"(?:https?://)?[a-z0-9][-a-z0-9]*\.firebaseio\.com(?:/\S*)?",
    re.IGNORECASE,
)
_RE_FIREBASE_APP = re.compile(
    r"(?:https?://)?[a-z0-9][-a-z0-9]*\.firebaseapp\.com(?:/\S*)?",
    re.IGNORECASE,
)
_RE_DISCORD_WEBHOOK = re.compile(
    r"(?:https?://)?(?:discord(?:app)?\.com|discord\.gg)/api/webhooks/\d+/[A-Za-z0-9_-]+",
    re.IGNORECASE,
)
_RE_ONION = re.compile(
    r"(?:https?://)?[a-z2-7]{16,56}\.onion(?::\d{1,5})?(?:/\S*)?",
    re.IGNORECASE,
)
# Raw IPv4 with optional non-default port (exclude common benign 80/443 only
# when no path? Keep all — analyst filters noise; banking malware loves :8080).
_RE_RAW_IP = re.compile(
    r"(?:https?://)?"
    r"((?:\d{1,3}\.){3}\d{1,3})"
    r"(?::(\d{2,5}))?"
    r"(?:/[^\s\"'<>]*)?",
    re.IGNORECASE,
)
# Suspicious C2 URL paths commonly used by Android banking-trojan / botnet panels.
# Widened from the original 4-pattern set (gate.php, panel/, api/bot, bot/gate) —
# still anchored to a full http(s):// URL, not a bare keyword match, which is what
# keeps this from flooding on ordinary app strings: a legitimate app essentially
# never embeds a literal URL ending in "checkin.php" or "/c2/report", whereas a
# bare keyword like "panel" or "report" appears constantly in benign UI strings.
# Grouped by what real panel kits (Cerberus/Anubis/SpyNote-derived and similar)
# consistently use for their check-in/command endpoints.
#
# Measured against 40 real F-Droid benign APKs (2026-08-23): 0/40 produced ANY
# C2 indicator, panel_url or otherwise — the URL-anchoring is what makes that
# possible despite the trigger-word list including things like "report" and
# "admin" that are extremely common substrings in ordinary app UI strings.
# Reproduce/extend with the malware side via scripts (data/ttp_apks) before
# widening the trigger-word list further.
_RE_PANEL_PATH = re.compile(
    r"https?://[^\s\"'<>]+/(?:"
    r"gate\.php|panel/|api/bot|bot/gate"                              # original set
    r"|(?:admin|cmd|command|control|register|checkin|check_in"        # PHP C2 scripts
    r"|beacon|heartbeat|report|upload|task|tasks|getcmd|getcommand"
    r"|c2|cnc)\.php"
    r"|(?:c2|cnc)/"                                                   # path segments
    r"|api/v\d+/(?:bot|panel|report|checkin)"                         # versioned bot APIs
    r"|bot/(?:report|task|cmd)"
    r")[^\s\"'<>]*",
    re.IGNORECASE,
)

# Private / non-routable ranges we still flag (malware often uses them on LAN
# test C2) but label distinctly if needed — for now all raw IPs are kept.
_PRIVATE_IP_PREFIXES = (
    "10.", "127.", "0.", "255.",
)


# Public DNS resolvers. A DoH/DoT endpoint in a string pool is not attacker
# infrastructure, but _RE_RAW_IP matches it like any other IP-in-a-URL, so
# `raw_ip:https://1.1.1.1/dns-query?...` was being recorded as a C2Indicator —
# a factual error in a graph whose whole value is that its contents are real.
# Malware genuinely does use DoH to hide C2 *resolution*, but the resolver is
# not the C2; the host it resolves is, and that is what the dynamic pass
# observes. Keyed on address because that is what the regex yields.
_PUBLIC_RESOLVERS = frozenset({
    "1.1.1.1", "1.0.0.1",            # Cloudflare
    "8.8.8.8", "8.8.4.4",            # Google
    "9.9.9.9", "149.112.112.112",    # Quad9
    "208.67.222.222", "208.67.220.220",  # OpenDNS
    "94.140.14.14", "94.140.15.15",  # AdGuard
})

# Prefixes extract_c2_indicators() stamps onto every indicator it returns.
_C2_TYPE_PREFIXES = (
    "telegram_bot:", "firebase:", "discord_webhook:", "onion:",
    "raw_ip:", "panel_url:",
)


def c2_host(indicator: str) -> str:
    """
    The bare hostname/IP an indicator refers to, for comparing a statically
    extracted indicator against an endpoint observed at runtime.

    These never had a common shape: static indicators carry a type prefix and
    often a scheme and path (`raw_ip:https://1.2.3.4:8080/gate.php`), while the
    dynamic hooks report `host:port` or a full URL. Comparing them raw — which
    is what the confirmation check used to do — cannot match even when the host
    is byte-identical, so every confirmation was a false negative by
    construction.

    A telegram_bot indicator maps to api.telegram.org rather than to its own
    token: the token is a credential, not an address, and contact with the bot
    shows up as a connection to Telegram's API host.

    Returns "" when an indicator has no host to speak of, which callers treat
    as unmatchable rather than as a wildcard.
    """
    s = (indicator or "").strip()
    if s.startswith("telegram_bot:"):
        return "api.telegram.org"
    for prefix in _C2_TYPE_PREFIXES:
        if s.startswith(prefix):
            s = s[len(prefix):]
            break
    s = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", s, flags=re.IGNORECASE)  # scheme
    s = s.rsplit("@", 1)[-1]        # userinfo
    s = re.split(r"[/?#]", s, 1)[0]  # path / query / fragment
    s = re.sub(r":\d{1,5}$", "", s)  # trailing port
    s = s.strip("[]").lower()
    return s if _looks_like_host(s) else ""


# A string pool contains plenty of things that survive prefix/scheme stripping
# without being addresses. Observed landing in the graph as hosts before this
# guard: the literal "null" (from a stringified null URL) and "file:" (a
# single-slash file: URI, which the `://` scheme pattern does not strip). A
# knowledge graph asserting that malware contacted a host named "null" is
# exactly the kind of claim that makes the rest of it untrustworthy.
_RE_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_RE_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)+$"
)


def _looks_like_host(s: str) -> bool:
    """A dotted hostname or a valid dotted-quad. Anything else is not an address."""
    if not s or len(s) > 253:
        return False
    if _RE_IPV4.match(s):
        return all(o.isdigit() and int(o) <= 255 for o in s.split("."))
    return bool(_RE_HOSTNAME.match(s))


# Infrastructure a normal app legitimately talks to. Observing a connection to
# one of these is a fact worth recording, but it is not evidence of anything —
# an SDK phoning home looks identical whether the host app is malware or not.
# Flagged rather than dropped: "the sample contacted X" stays true either way,
# and triage queries filter on the flag.
_BENIGN_HOST_SUFFIXES = (
    "googleapis.com", "gstatic.com", "google.com", "googleusercontent.com",
    "android.com", "crashlytics.com", "firebaseio.com", "firebase.com",
    "doubleclick.net", "google-analytics.com", "facebook.com", "fbcdn.net",
    "cloudflare.com", "akamaized.net", "amazonaws.com", "windowsupdate.com",
)


def is_benign_host(host: str) -> bool:
    """
    Does this host belong to well-known app infrastructure (SDKs, CDNs,
    analytics) rather than to something worth investigating?

    Suffix match on the registrable tail so subdomains resolve correctly
    (firebaseinstallations.googleapis.com -> googleapis.com). Deliberately
    conservative and short: a host missing from this list is only ever
    *unflagged*, never asserted malicious, so a false negative here costs
    nothing but triage noise — whereas wrongly flagging a real C2 as benign
    would hide it.
    """
    h = (host or "").strip().lower().rstrip(".")
    if not h:
        return False
    return any(h == suf or h.endswith("." + suf) for suf in _BENIGN_HOST_SUFFIXES)


def extract_c2_indicators(strings: list[str]) -> list[str]:
    """
    Pull high-value C2 IoCs from a string pool (DEX string table, assets, etc.).

    Returns a de-duplicated, sorted list of indicators with type prefixes so
    GraphRAG / risk scoring can cite exact channels, e.g.:
      telegram_bot:123456:AA...
      firebase:evil.firebaseio.com
      discord_webhook:https://discord.com/api/webhooks/...
      onion:abc...xyz.onion
      raw_ip:http://1.2.3.4:8080
      panel_url:https://evil.com/gate.php
    """
    found: set[str] = set()

    for raw in strings:
        if not raw or not isinstance(raw, str):
            continue
        s = raw.strip()
        if len(s) < 8 or len(s) > 2048:
            continue

        for m in _RE_TELEGRAM_BOT.finditer(s):
            found.add(f"telegram_bot:{m.group(1)}")

        # Only accept bare tokens when telegram context is nearby
        if "telegram" in s.lower() or "sendMessage" in s or "bot" in s.lower():
            for m in _RE_TELEGRAM_TOKEN.finditer(s):
                token = m.group(1)
                # Avoid double-adding tokens already captured via full URL
                if not any(token in x for x in found if x.startswith("telegram_bot:")):
                    found.add(f"telegram_bot:{token}")

        for m in _RE_FIREBASE.finditer(s):
            found.add(f"firebase:{m.group(0).rstrip('/')}")
        for m in _RE_FIREBASE_APP.finditer(s):
            found.add(f"firebase:{m.group(0).rstrip('/')}")

        for m in _RE_DISCORD_WEBHOOK.finditer(s):
            found.add(f"discord_webhook:{m.group(0)}")

        for m in _RE_ONION.finditer(s):
            found.add(f"onion:{m.group(0).rstrip('/')}")

        for m in _RE_PANEL_PATH.finditer(s):
            found.add(f"panel_url:{m.group(0).rstrip('/')}")

        for m in _RE_RAW_IP.finditer(s):
            ip = m.group(1)
            port = m.group(2)
            # Skip clearly invalid octets
            try:
                if any(int(o) > 255 for o in ip.split(".")):
                    continue
            except ValueError:
                continue
            # Skip pure localhost / link-local noise unless non-standard port
            if ip.startswith("127.") and (not port or port in ("80", "443")):
                continue
            if ip.startswith("0.") or ip.startswith("255."):
                continue
            # A public DNS resolver is not C2 — see _PUBLIC_RESOLVERS.
            if ip in _PUBLIC_RESOLVERS:
                continue
            # RFC1918 / link-local cannot be C2. A victim's device is not on the
            # operator's LAN, so an address in these ranges is unreachable as a
            # channel no matter what port it carries — recording it as attacker
            # infrastructure is a claim that cannot be true. (These strings are
            # real, usually a dev/test backend left in the build, but "the string
            # exists" does not make it C2, and the non-standard-port branch below
            # was admitting them precisely because odd ports look suspicious.)
            try:
                if ipaddress.ip_address(ip).is_private or ipaddress.ip_address(ip).is_link_local:
                    continue
            except ValueError:
                continue
            endpoint = m.group(0).rstrip("/")
            # Prefer flagging non-standard ports more aggressively; still keep all
            if port and port not in ("80", "443"):
                found.add(f"raw_ip:{endpoint}")
            elif not any(ip.startswith(p) for p in ("10.", "192.168.", "172.")):
                # Public IPv4 in URL form without standard-only filter
                if "http" in s.lower() or port:
                    found.add(f"raw_ip:{endpoint}")

    return sorted(found)


# ── Permission matrix patterns ───────────────────────────────────────────

# Canonical short names → full Android permission strings we accept.
_PERM_ALIASES: dict[str, tuple[str, ...]] = {
    "SYSTEM_ALERT_WINDOW": (
        "android.permission.SYSTEM_ALERT_WINDOW",
    ),
    "PACKAGE_USAGE_STATS": (
        "android.permission.PACKAGE_USAGE_STATS",
    ),
    "RECEIVE_BOOT_COMPLETED": (
        "android.permission.RECEIVE_BOOT_COMPLETED",
    ),
    "BIND_ACCESSIBILITY_SERVICE": (
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
    ),
    "READ_SMS": (
        "android.permission.READ_SMS",
    ),
    "RECEIVE_SMS": (
        "android.permission.RECEIVE_SMS",
    ),
    "SEND_SMS": (
        "android.permission.SEND_SMS",
    ),
    "REQUEST_INSTALL_PACKAGES": (
        "android.permission.REQUEST_INSTALL_PACKAGES",
    ),
    "INTERNET": (
        "android.permission.INTERNET",
    ),
    "QUERY_ALL_PACKAGES": (
        "android.permission.QUERY_ALL_PACKAGES",
        "android.permission.QUERY_ALL_PACKAGES",
    ),
    "BIND_DEVICE_ADMIN": (
        "android.permission.BIND_DEVICE_ADMIN",
    ),
    "READ_PHONE_STATE": (
        "android.permission.READ_PHONE_STATE",
    ),
    "WRITE_SETTINGS": (
        "android.permission.WRITE_SETTINGS",
    ),
}

# An app that acts as an accessibility service declares the *service*, not a
# <uses-permission>: BIND_ACCESSIBILITY_SERVICE is the permission the *system*
# holds over that service, so it shows up as the service's android:permission
# attribute and never in the app's own permission list. Measured over the 353-APK
# corpus, gating on <uses-permission> catches 6/133 malware; gating on the
# service's intent-filter action catches 75/133 against 7/220 benign. Every
# accessibility-dependent rule in this module reads the declaration, not the
# permission (N5). forensic.py imports this constant rather than restating it.
ACCESSIBILITY_SERVICE_ACTION = "android.accessibilityservice.AccessibilityService"


def declares_accessibility_service(
    permissions: list[str] | None = None,
    intent_actions: list[str] | None = None,
) -> bool:
    """
    True when the app declares an accessibility service, by either route: the
    intent-filter action on the service (the real-world form) or the legacy
    <uses-permission> (kept because a handful of samples do write it).
    """
    if ACCESSIBILITY_SERVICE_ACTION in set(intent_actions or ()):
        return True
    return "android.permission.BIND_ACCESSIBILITY_SERVICE" in set(permissions or ())


# (flag_id, required_any_of_groups) — each group is OR within, AND across groups
_PERMISSION_MATRIX: list[tuple[str, list[list[str]]]] = [
    (
        "OVERLAY_ATTACK_PATTERN",
        # SYSTEM_ALERT_WINDOW + (PACKAGE_USAGE_STATS | QUERY_ALL_PACKAGES) + often BOOT
        [
            ["SYSTEM_ALERT_WINDOW"],
            ["PACKAGE_USAGE_STATS", "QUERY_ALL_PACKAGES"],
        ],
    ),
    (
        "OVERLAY_BOOT_PERSISTENCE",
        [
            ["SYSTEM_ALERT_WINDOW"],
            ["RECEIVE_BOOT_COMPLETED"],
        ],
    ),
    (
        "SMS_OTP_STEALER_PATTERN",
        [
            ["BIND_ACCESSIBILITY_SERVICE"],
            ["READ_SMS", "RECEIVE_SMS"],
        ],
    ),
    (
        "SMS_OTP_SENDER_PATTERN",
        [
            ["READ_SMS", "RECEIVE_SMS"],
            ["SEND_SMS"],
        ],
    ),
    (
        "DROPPER_STAGE2_PATTERN",
        [
            ["REQUEST_INSTALL_PACKAGES"],
            ["INTERNET"],
        ],
    ),
    (
        "DEVICE_ADMIN_PERSISTENCE",
        [
            ["BIND_DEVICE_ADMIN"],
        ],
    ),
    (
        "BANKING_TARGET_ENUMERATION",
        [
            ["QUERY_ALL_PACKAGES", "PACKAGE_USAGE_STATS"],
            ["INTERNET"],
        ],
    ),
    (
        "ACCESSIBILITY_FULL_CONTROL",
        [
            ["BIND_ACCESSIBILITY_SERVICE"],
            ["SYSTEM_ALERT_WINDOW"],
        ],
    ),
]


def _normalize_permissions(permissions: list[str]) -> set[str]:
    """Map full permission strings to short alias keys we use in matrix rules."""
    perms = set(permissions or [])
    short: set[str] = set()
    for alias, fulls in _PERM_ALIASES.items():
        for full in fulls:
            if full in perms:
                short.add(alias)
                break
        # Also accept already-short or suffix matches
        for p in perms:
            if p.endswith("." + alias) or p == alias:
                short.add(alias)
    return short


def detect_permission_matrix(
    permissions: list[str],
    intent_actions: list[str] | None = None,
) -> list[str]:
    """
    Detect high-risk multi-permission combinations used by banking malware.

    Returns flag IDs such as OVERLAY_ATTACK_PATTERN, SMS_OTP_STEALER_PATTERN.

    `intent_actions` carries the app's declared intent-filter actions. Three rules
    here (SMS_OTP_STEALER_PATTERN, ACCESSIBILITY_FULL_CONTROL, and the a11y config
    flags derived alongside them) key off BIND_ACCESSIBILITY_SERVICE, which almost
    never appears as a <uses-permission> — see ACCESSIBILITY_SERVICE_ACTION. Without
    the actions those rules fire on 6/133 malware instead of 75/133 (N5). The
    argument is optional so existing permission-only callers keep working, but the
    pipeline always passes it.
    """
    short = _normalize_permissions(permissions)
    if declares_accessibility_service(permissions, intent_actions):
        short.add("BIND_ACCESSIBILITY_SERVICE")
    flags: list[str] = []
    for flag_id, groups in _PERMISSION_MATRIX:
        if all(any(p in short for p in group) for group in groups):
            flags.append(flag_id)
    return flags


# ── Certificate anomaly analysis ─────────────────────────────────────────

_DEBUG_CN_MARKERS = (
    "android debug",
    "androiddebugkey",
    "cn=test",
    "ou=test",
    "o=test",
    "cn=android",
    "debug key",
)
_GENERIC_JUNK_CN = re.compile(r"^(test|android|debug|1|a|none|unknown|user|dev)$", re.I)


def _name_to_str(name) -> str:
    """Render an asn1crypto Name as a readable DN string."""
    try:
        # human_friendly gives "Common Name: Foo, Organization: Bar"
        return name.human_friendly
    except Exception:
        try:
            return str(name.native)
        except Exception:
            return str(name)


def _name_cn(name) -> Optional[str]:
    try:
        native = name.native
        if isinstance(native, dict):
            return native.get("common_name") or native.get("organization_name")
        if isinstance(native, (list, tuple)):
            for part in native:
                if isinstance(part, dict) and "common_name" in part:
                    return part["common_name"]
    except Exception:
        pass
    return None


def analyze_certificate_anomalies(der_certs: list[bytes]) -> list[str]:
    """
    Flag signing-certificate anomalies common in Android malware.

    Returns human-readable anomaly strings, e.g.:
      debug_or_test_key:CN=Android Debug
      self_signed_junk_dn:CN=a
      generic_subject:CN=test
      expired
      not_yet_valid
      missing_certificate

    Plain `self_signed` is deliberately NOT an anomaly (N6). Android app signing
    *is* self-signing — there is no CA in the model — so subject == issuer holds for
    essentially every APK ever published. Reporting it put a constant on 27/30
    clean apps and 22/28 malware in the sampled corpus, i.e. a floor under
    ioc_component that carried no information. What remains flagged is a
    self-signed certificate whose distinguished name is *also* junk (a one-character
    CN, a near-empty DN), which is a real dropper tell.
    """
    if not der_certs:
        return ["missing_certificate"]

    if not ASN1_AVAILABLE:
        return []

    anomalies: list[str] = []
    now = datetime.now(timezone.utc)

    for der in der_certs[:3]:  # inspect first few signers
        try:
            cert = asn1_x509.Certificate.load(der)
            subject = cert.subject
            issuer = cert.issuer
            subject_str = _name_to_str(subject)
            issuer_str = _name_to_str(issuer)
            cn = _name_cn(subject) or ""
            subject_lower = subject_str.lower()

            # Debug / test keys
            if any(m in subject_lower for m in _DEBUG_CN_MARKERS):
                anomalies.append(f"debug_or_test_key:{subject_str[:120]}")
            elif cn and _GENERIC_JUNK_CN.match(str(cn).strip()):
                anomalies.append(f"generic_subject:CN={cn}")

            # Self-signed is the norm on Android, so only a self-signed cert whose
            # DN is *also* junk counts as an anomaly (N6).
            try:
                self_signed = subject.dump() == issuer.dump()
            except Exception:
                self_signed = subject_str == issuer_str
            if self_signed and (
                len(subject_str) < 20
                or re.search(r"\bCN\s*[:=]\s*[01a]\b", subject_str, re.I)
            ):
                anomalies.append(f"self_signed_junk_dn:{subject_str[:80]}")

            # Validity window
            try:
                nb = cert["tbs_certificate"]["validity"]["not_before"].native
                na = cert["tbs_certificate"]["validity"]["not_after"].native
                if hasattr(nb, "tzinfo") and nb.tzinfo is None:
                    nb = nb.replace(tzinfo=timezone.utc)
                if hasattr(na, "tzinfo") and na.tzinfo is None:
                    na = na.replace(tzinfo=timezone.utc)
                # asn1crypto may return date instead of datetime
                if not isinstance(nb, datetime):
                    nb = datetime(nb.year, nb.month, nb.day, tzinfo=timezone.utc)
                if not isinstance(na, datetime):
                    na = datetime(na.year, na.month, na.day, tzinfo=timezone.utc)
                if now > na:
                    anomalies.append(f"expired:{na.date().isoformat()}")
                if now < nb:
                    anomalies.append(f"not_yet_valid:{nb.date().isoformat()}")
            except Exception as e:
                logger.debug(f"Cert validity parse failed: {e}")

        except Exception as e:
            logger.debug(f"Certificate parse failed: {e}")
            anomalies.append("unparseable_certificate")

    # De-dupe while preserving order
    seen: set[str] = set()
    ordered: list[str] = []
    for a in anomalies:
        if a not in seen:
            seen.add(a)
            ordered.append(a)
    return ordered


def extract_der_certificates(apk_obj) -> list[bytes]:
    """
    DER certificates for an APK, across all three signature schemes.

    v3/v2 expose no-argument list getters. v1 (the legacy JAR signature, still
    the only scheme on a large share of real malware) does NOT: androguard's
    get_certificate_der() takes the signature filename and must be called once
    per entry in get_signature_names().

    That difference is why this used to return nothing for every v1-only APK.
    get_certificate_der was listed alongside the v2/v3 getters and invoked with
    no arguments, which raises TypeError — swallowed whole by a bare
    `except Exception: continue`, so a third of the corpus silently had no
    certificate, no SIGNED_WITH edge, and no cert-anomaly analysis, with
    nothing anywhere reporting a failure.
    """
    certs: list[bytes] = []

    def _collect(result) -> None:
        if isinstance(result, (bytes, bytearray)):
            certs.append(bytes(result))
        elif isinstance(result, (list, tuple)):
            certs.extend(bytes(c) for c in result if isinstance(c, (bytes, bytearray)))

    for getter in ("get_certificates_der_v3", "get_certificates_der_v2"):
        fn = getattr(apk_obj, getter, None)
        if not fn:
            continue
        try:
            _collect(fn())
        except Exception as e:
            logger.debug(f"[cert] {getter} failed: {e}")
        if certs:
            return certs

    # v1 / JAR signing — one certificate per META-INF/*.(RSA|DSA|EC) entry.
    try:
        for name in apk_obj.get_signature_names() or []:
            try:
                _collect(apk_obj.get_certificate_der(name))
            except Exception as e:
                logger.debug(f"[cert] v1 cert {name} failed: {e}")
    except Exception as e:
        logger.debug(f"[cert] enumerating v1 signature names failed: {e}")
    return certs


# ── Secondary DEX / asset payload inspection ─────────────────────────────

_BANKING_OVERLAY_HINTS = re.compile(
    r"(chase|wellsfargo|wells.?fargo|paypal|bankofamerica|citibank|hsbc|"
    r"barclays|revolut|cashapp|venmo|binance|coinbase|kraken|metamask|"
    r"login|signin|overlay|inject|phish)",
    re.IGNORECASE,
)

_SUSPICIOUS_ASSET_EXTS = {
    ".dex", ".jar", ".apk", ".zip", ".so", ".bin", ".dat", ".enc",
    ".db", ".json", ".html", ".htm", ".js",
}


def _looks_like_dex(data: bytes) -> bool:
    return len(data) >= 8 and data[:4] == DEX_MAGIC


def _looks_like_zip(data: bytes) -> bool:
    return len(data) >= 4 and data[:4] == ZIP_MAGIC


def _looks_like_elf(data: bytes) -> bool:
    return len(data) >= 4 and data[:4] == ELF_MAGIC


def inspect_apk_payloads(filepath: str) -> dict[str, Any]:
    """
    Walk the APK ZIP and flag secondary DEX files + suspicious assets.

    Returns:
      {
        "secondary_dex_count": int,          # classes2.dex ... + hidden DEX assets
        "payload_assets": list[str],         # path|reason descriptors
        "dropper_signals": list[str],        # high-level dropper flags
        "yara_targets": list[tuple[str, bytes]],  # (label, uncompressed bytes)
        "asset_strings": list[str],          # strings harvested for C2 regex
      }
    """
    secondary_dex = 0
    payload_assets: list[str] = []
    dropper_signals: list[str] = []
    yara_targets: list[tuple[str, bytes]] = []
    asset_strings: list[str] = []

    try:
        with zipfile.ZipFile(filepath, "r") as zf:
            names = zf.namelist()

            for name in names:
                lower = name.lower().replace("\\", "/")
                base = lower.rsplit("/", 1)[-1]

                # Multi-DEX at archive root (classes2.dex, classes3.dex, ...)
                if re.fullmatch(r"classes\d+\.dex", base) and base != "classes.dex":
                    secondary_dex += 1
                    payload_assets.append(f"{name}|secondary_dex")
                    try:
                        data = zf.read(name)
                        yara_targets.append((f"dex:{name}", data))
                    except Exception:
                        pass
                    continue

                # Primary classes.dex always a YARA target (uncompressed)
                if base == "classes.dex":
                    try:
                        data = zf.read(name)
                        yara_targets.append((f"dex:{name}", data))
                    except Exception:
                        pass
                    continue

                # Focus on assets/ and res/raw/
                in_assets = lower.startswith("assets/") or "/assets/" in lower
                in_raw = "res/raw/" in lower or lower.startswith("res/raw/")
                if not (in_assets or in_raw):
                    # Still check accessibility configs under res/xml/
                    continue

                # Size guard
                try:
                    info = zf.getinfo(name)
                    if info.file_size > MAX_ASSET_SCAN_BYTES:
                        # Still note oversized encrypted-looking blobs
                        if any(lower.endswith(ext) for ext in (".dex", ".jar", ".apk", ".bin", ".dat", ".enc", ".so")):
                            payload_assets.append(f"{name}|oversized_blob:{info.file_size}")
                            dropper_signals.append(f"oversized_asset:{name}")
                        continue
                    data = zf.read(name)
                except Exception:
                    continue

                if not data:
                    continue

                # Magic-byte detection (hidden DEX / ZIP / ELF regardless of extension)
                if _looks_like_dex(data):
                    secondary_dex += 1
                    payload_assets.append(f"{name}|hidden_dex_magic")
                    dropper_signals.append(f"hidden_dex_in_assets:{name}")
                    yara_targets.append((f"asset_dex:{name}", data))
                elif _looks_like_zip(data) and not lower.endswith((".apk", ".jar", ".zip")):
                    payload_assets.append(f"{name}|hidden_zip_magic")
                    dropper_signals.append(f"disguised_zip_payload:{name}")
                    yara_targets.append((f"asset_zip:{name}", data[:MAX_ASSET_SCAN_BYTES]))
                elif _looks_like_elf(data) and not lower.endswith(".so"):
                    payload_assets.append(f"{name}|disguised_elf")
                    dropper_signals.append(f"disguised_native_lib:{name}")
                elif any(lower.endswith(ext) for ext in (".dex", ".jar", ".apk")):
                    payload_assets.append(f"{name}|packed_code_asset")
                    dropper_signals.append(f"code_asset:{name}")
                    yara_targets.append((f"asset:{name}", data))

                # Banking overlay HTML templates
                if lower.endswith((".html", ".htm")) and _BANKING_OVERLAY_HINTS.search(base + name):
                    payload_assets.append(f"{name}|banking_overlay_html")
                    dropper_signals.append(f"overlay_template:{name}")
                    # Pull printable strings from HTML for C2 / form action URLs
                    try:
                        text = data.decode("utf-8", errors="ignore")
                        asset_strings.extend(_harvest_printable_strings(text))
                    except Exception:
                        pass

                # Harvest strings from small text-like assets for C2 extraction
                if lower.endswith((".json", ".js", ".txt", ".xml", ".cfg", ".conf", ".properties")):
                    try:
                        text = data.decode("utf-8", errors="ignore")
                        asset_strings.extend(_harvest_printable_strings(text))
                    except Exception:
                        pass

                # Encrypted-looking high-entropy small blobs with suspicious names
                if any(lower.endswith(ext) for ext in (".dat", ".bin", ".enc", ".db")):
                    if not _looks_like_dex(data) and not _looks_like_zip(data):
                        payload_assets.append(f"{name}|opaque_blob")

    except zipfile.BadZipFile:
        logger.warning(f"APK is not a valid ZIP: {filepath}")
        dropper_signals.append("invalid_apk_zip")
    except Exception as e:
        logger.warning(f"Payload inspection failed for {filepath}: {e}")

    # Cap YARA targets to avoid scanning huge multi-asset packs
    if len(yara_targets) > MAX_YARA_PAYLOADS:
        yara_targets = yara_targets[:MAX_YARA_PAYLOADS]

    return {
        "secondary_dex_count": secondary_dex,
        "payload_assets": payload_assets[:100],
        "dropper_signals": sorted(set(dropper_signals))[:50],
        "yara_targets": yara_targets,
        "asset_strings": asset_strings[:500],
    }


def _harvest_printable_strings(text: str, min_len: int = 8) -> list[str]:
    """Pull URL-ish / token-ish substrings from text assets."""
    out: list[str] = []
    # Split on quotes and whitespace to approximate a string pool
    for part in re.split(r"[\s\"'<>]+", text):
        if len(part) >= min_len and (
            "http" in part.lower()
            or "telegram" in part.lower()
            or "firebase" in part.lower()
            or "discord" in part.lower()
            or ".onion" in part.lower()
            or re.search(r"\d+\.\d+\.\d+\.\d+", part)
        ):
            out.append(part[:512])
    return out


# ── Accessibility service config XML ─────────────────────────────────────

_A11Y_TRUE_FLAGS = (
    "canRetrieveWindowContent",
    "canPerformGestures",
    "canRequestTouchExplorationMode",
    "canRequestEnhancedWebAccessibility",
    "canRequestFilterKeyEvents",
    "canTakeScreenshot",
)


def parse_accessibility_configs(apk_obj) -> list[str]:
    """
    Parse the app's accessibility-service config XML resources for keylogging /
    full-control flags. Callers gate this on declares_accessibility_service(),
    which reads the service declaration rather than a <uses-permission> (N5).

    Returns flags like:
      canRetrieveWindowContent=true
      accessibilityEventTypes=typeAllMasks
      canPerformGestures=true
      accessibility_config_missing
    """
    flags: list[str] = []

    # Collect candidate XML paths from the APK file list
    try:
        files = list(apk_obj.get_files() or [])
    except Exception:
        files = []

    config_paths = [
        f for f in files
        if "accessibility" in f.lower() and f.lower().endswith(".xml")
    ]
    # Also common generic names under res/xml/
    for f in files:
        fl = f.lower().replace("\\", "/")
        if fl.startswith("res/xml/") and fl.endswith(".xml"):
            if f not in config_paths:
                config_paths.append(f)

    parsed_any = False
    for path in config_paths:
        try:
            data = apk_obj.get_file(path)
            if not data:
                continue
            # Androguard may return already-decoded XML or binary AXML
            if isinstance(data, bytes):
                # Try plain XML first; binary AXML needs androguard helper
                text = None
                try:
                    text = data.decode("utf-8")
                    if text.lstrip().startswith("<"):
                        pass
                    else:
                        text = None
                except Exception:
                    text = None
                if text is None:
                    text = _axml_to_string(apk_obj, path, data)
                if not text:
                    continue
            else:
                text = str(data)

            if "accessibility" not in text.lower() and "AccessibilityService" not in text:
                # Skip unrelated res/xml files
                if "accessibility" not in path.lower():
                    continue

            parsed_any = True
            flags.extend(_parse_a11y_xml_text(text, path))
        except Exception as e:
            logger.debug(f"Accessibility config parse failed for {path}: {e}")

    # Fallback: scan AndroidManifest for accessibility-service meta-data resource
    if not parsed_any:
        try:
            # String-scan raw manifest if available
            raw = None
            try:
                raw = apk_obj.get_android_manifest_axml()
            except Exception:
                pass
            if raw is not None:
                try:
                    xml_str = raw.get_xml() if hasattr(raw, "get_xml") else str(raw)
                    if isinstance(xml_str, bytes):
                        xml_str = xml_str.decode("utf-8", errors="ignore")
                    if "BIND_ACCESSIBILITY_SERVICE" in xml_str or "accessibility" in xml_str.lower():
                        flags.append("accessibility_declared_in_manifest")
                        if "canRetrieveWindowContent" in xml_str:
                            flags.append("canRetrieveWindowContent=true")
                except Exception:
                    pass
        except Exception:
            pass

    if not flags:
        # Caller only invokes this for an app that declares an accessibility
        # service — a missing config is itself a mild signal (it may be built
        # at runtime via setServiceInfo).
        flags.append("accessibility_config_not_statically_resolved")

    # De-dupe
    seen: set[str] = set()
    out: list[str] = []
    for f in flags:
        if f not in seen:
            seen.add(f)
            out.append(f)
    return out


def _axml_to_string(apk_obj, path: str, data: bytes) -> Optional[str]:
    """Best-effort binary AXML → string via androguard helpers."""
    try:
        from androguard.core.axml import AXMLPrinter
        printer = AXMLPrinter(data)
        buff = printer.get_xml()
        if isinstance(buff, bytes):
            return buff.decode("utf-8", errors="ignore")
        return str(buff)
    except Exception:
        # Last resort: latin-1 dump and regex for attribute names
        try:
            raw = data.decode("latin-1", errors="ignore")
            if any(k in raw for k in _A11Y_TRUE_FLAGS) or "accessibilityEventTypes" in raw:
                return raw
        except Exception:
            pass
    return None


def _parse_a11y_xml_text(text: str, path: str) -> list[str]:
    flags: list[str] = []
    flags.append(f"accessibility_config:{path}")

    # Attribute presence via regex (AXML dumps / plain XML both work)
    for attr in _A11Y_TRUE_FLAGS:
        if re.search(rf'{attr}\s*=\s*["\']?true["\']?', text, re.I):
            flags.append(f"{attr}=true")

    # Event types — typeAllMasks / typeViewClicked are keylogging signals
    m = re.search(
        r'accessibilityEventTypes\s*=\s*["\']([^"\']+)["\']',
        text,
        re.I,
    )
    if m:
        event_types = m.group(1)
        flags.append(f"accessibilityEventTypes={event_types}")
        if "typeAllMasks" in event_types or "typeAllMask" in event_types:
            flags.append("keylogging_event_mask:typeAllMasks")
        if "typeViewClicked" in event_types or "typeViewTextChanged" in event_types:
            flags.append("keylogging_event_mask:view_input_events")

    m = re.search(
        r'accessibilityFeedbackType\s*=\s*["\']([^"\']+)["\']',
        text,
        re.I,
    )
    if m:
        flags.append(f"accessibilityFeedbackType={m.group(1)}")

    # Also try ElementTree when well-formed
    try:
        # Strip default namespaces for easier parsing
        cleaned = re.sub(r'\sxmlns(?::\w+)?="[^"]*"', "", text)
        root = ET.fromstring(cleaned)
        for elem in root.iter():
            attrib = {k.split("}")[-1]: v for k, v in elem.attrib.items()}
            for attr in _A11Y_TRUE_FLAGS:
                if attrib.get(attr, "").lower() == "true":
                    flag = f"{attr}=true"
                    if flag not in flags:
                        flags.append(flag)
            if "accessibilityEventTypes" in attrib:
                et = attrib["accessibilityEventTypes"]
                flag = f"accessibilityEventTypes={et}"
                if flag not in flags:
                    flags.append(flag)
    except ET.ParseError:
        pass

    return flags


def accessibility_matrix_flags(accessibility_flags: list[str]) -> list[str]:
    """
    Map parsed accessibility-config flags onto the ACCESSIBILITY_* permission-matrix
    flag IDs that MATRIX_FLAG_SEVERITY (scoring.py) actually weights.

    Both ingest_apk and enrich_apk_static go through this. ingest_apk previously
    spliced the *raw* config flags into permission_matrix_flags, so entries like
    `accessibility_config:res/xml/service.xml` reached the scorer, which has no
    weight for them and fell back to its 0.6 default for unknown flags (N5).
    """
    flags: list[str] = []
    if any("canRetrieveWindowContent=true" in f for f in accessibility_flags):
        flags.append("ACCESSIBILITY_WINDOW_CONTENT")
    if any("canPerformGestures=true" in f for f in accessibility_flags):
        flags.append("ACCESSIBILITY_GESTURE_CONTROL")
    if any("keylogging_event_mask" in f for f in accessibility_flags):
        flags.append("ACCESSIBILITY_KEYLOGGING_MASK")
    return flags


# ── Exported component backdoors ─────────────────────────────────────────

def detect_exported_risks(apk_obj) -> list[str]:
    """
    Flag components with android:exported=true (or legacy implicit export via
    intent-filters) that do not require a permission — common backdoor /
    SMS-intercept entry points for banking trojans.
    """
    risks: list[str] = []

    for itemtype, getter in (
        ("service", getattr(apk_obj, "get_services", lambda: [])),
        ("receiver", getattr(apk_obj, "get_receivers", lambda: [])),
        ("activity", getattr(apk_obj, "get_activities", lambda: [])),
    ):
        try:
            names = getter() or []
        except Exception:
            continue

        for name in names:
            try:
                exported = _is_exported(apk_obj, itemtype, name)
                if not exported:
                    continue
                perm = _component_permission(apk_obj, itemtype, name)
                if perm:
                    continue  # protected by permission — lower risk

                # Intent actions for context
                actions: list[str] = []
                try:
                    filters = apk_obj.get_intent_filters(itemtype, name) or {}
                    actions = list(filters.get("action", []) or [])
                except Exception:
                    pass

                action_hint = ""
                sensitive = [
                    a for a in actions
                    if any(
                        k in a.upper()
                        for k in (
                            "SMS", "BOOT", "PACKAGE", "USER_PRESENT",
                            "CONNECTIVITY", "PHONE", "ADMIN", "ACCESSIBILITY",
                        )
                    )
                ]
                if sensitive:
                    action_hint = f"|actions={','.join(sensitive[:5])}"

                risks.append(f"exported_{itemtype}_no_perm:{name}{action_hint}")
            except Exception:
                continue

    return risks[:50]


def _is_exported(apk_obj, itemtype: str, name: str) -> bool:
    """
    Determine if a component is exported. Prefer explicit android:exported;
    fall back to presence of intent-filters (pre-Android-12 implicit export).
    """
    # Androguard helpers vary by version
    for method_name in (f"get_{itemtype}_exported", "is_exported"):
        fn = getattr(apk_obj, method_name, None)
        if fn is None:
            continue
        try:
            if method_name == "is_exported":
                val = fn(itemtype, name)
            else:
                val = fn(name)
            if val is not None:
                return bool(val)
        except Exception:
            continue

    # Intent-filter presence ⇒ historically exported
    try:
        filters = apk_obj.get_intent_filters(itemtype, name) or {}
        if filters.get("action") or filters.get("action"):
            return True
        if any(filters.values()):
            return True
    except Exception:
        pass

    # Parse from AXML element attributes if available
    try:
        # get_attribute_value style
        fn = getattr(apk_obj, "get_attribute_value", None)
        if fn:
            # Different androguard signatures — try common ones
            for args in (
                (itemtype, name, "exported"),
                (name, "exported"),
            ):
                try:
                    val = fn(*args)
                    if val is not None:
                        return str(val).lower() == "true"
                except TypeError:
                    continue
                except Exception:
                    break
    except Exception:
        pass

    return False


def _component_permission(apk_obj, itemtype: str, name: str) -> Optional[str]:
    try:
        fn = getattr(apk_obj, "get_attribute_value", None)
        if not fn:
            return None
        for args in (
            (itemtype, name, "permission"),
            (name, "permission"),
        ):
            try:
                val = fn(*args)
                if val:
                    return str(val)
            except TypeError:
                continue
            except Exception:
                break
    except Exception:
        pass
    return None


# ── Dynamic code loading string signals ──────────────────────────────────

_DYNLOAD_PATTERNS = (
    "DexClassLoader",
    "PathClassLoader",
    "InMemoryDexClassLoader",
    "openDexFile",
    "dalvik.system.DexClassLoader",
    "Runtime.loadLibrary",
    "System.loadLibrary",
    "System.load(",
)


def detect_dynamic_loading_signals(strings: list[str]) -> list[str]:
    """Flag dynamic code-loading APIs observed in the string pool."""
    hits: set[str] = set()
    joined_lower_parts = [s for s in strings if s]
    for s in joined_lower_parts:
        for pat in _DYNLOAD_PATTERNS:
            if pat in s:
                hits.add(f"dynload:{pat}")
    return sorted(hits)


# ── Orchestrator used by ingest.py ───────────────────────────────────────

def enrich_apk_static(
    filepath: str,
    apk_obj,
    permissions: list[str],
    extra_strings: Optional[list[str]] = None,
    intent_actions: Optional[list[str]] = None,
) -> dict[str, Any]:
    """
    Run all static malware enrichments for an APK.

    Returns a dict ready to splat into IngestionResult fields, plus
    `yara_targets` for Phase 1.5 uncompressed scanning (not part of schema).
    """
    # Certificate anomalies
    der_certs = extract_der_certificates(apk_obj)
    cert_anomalies = analyze_certificate_anomalies(der_certs)

    # Permission matrix
    permission_matrix_flags = detect_permission_matrix(permissions, intent_actions)

    # Payload / multi-DEX inspection
    payloads = inspect_apk_payloads(filepath)

    # Accessibility config — gated on the service declaration, not the permission (N5).
    accessibility_flags: list[str] = []
    if declares_accessibility_service(permissions, intent_actions):
        accessibility_flags = parse_accessibility_configs(apk_obj)
        permission_matrix_flags = permission_matrix_flags + [
            f for f in accessibility_matrix_flags(accessibility_flags)
            if f not in permission_matrix_flags
        ]

    # Exported component risks
    exported_risks = detect_exported_risks(apk_obj)

    # String pool for C2: asset strings + optional DEX strings from caller
    string_pool: list[str] = list(payloads.get("asset_strings") or [])
    if extra_strings:
        string_pool.extend(extra_strings)

    # Also pull Androguard string list if cheaply available on analysis later;
    # at ingest time we only have apk_obj — harvest from assets is enough for
    # early IoCs; pipeline can re-run extract_c2_indicators on CFG strings.

    c2_indicators = extract_c2_indicators(string_pool)

    # Dynamic loading signals from asset/string pool
    dynload = detect_dynamic_loading_signals(string_pool)
    dropper_signals = list(payloads.get("dropper_signals") or [])
    dropper_signals.extend(dynload)

    # Combine dropper pattern with hidden payloads
    if (
        "DROPPER_STAGE2_PATTERN" in permission_matrix_flags
        and payloads.get("secondary_dex_count", 0) > 0
    ):
        dropper_signals.append("dropper_with_hidden_dex_payload")

    if exported_risks:
        dropper_signals.append(f"exported_unprotected_components:{len(exported_risks)}")

    return {
        "c2_indicators": c2_indicators,
        "cert_anomalies": cert_anomalies,
        "permission_matrix_flags": sorted(set(permission_matrix_flags)),
        "secondary_dex_count": int(payloads.get("secondary_dex_count") or 0),
        "accessibility_flags": accessibility_flags,
        "exported_risks": exported_risks,
        "payload_assets": payloads.get("payload_assets") or [],
        "dropper_signals": sorted(set(dropper_signals)),
        "yara_targets": payloads.get("yara_targets") or [],
    }
