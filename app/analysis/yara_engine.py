"""
YARA rule engine for Android APK/DEX scanning.

Provides built-in YARA rules targeting Android banking malware patterns
plus loading of custom rules from data/yara_rules/. Scans the raw APK
binary for byte-level pattern matches that complement the higher-level
CFG/forensic-dictionary analysis.

Why YARA alongside CFG analysis:
- YARA catches string-level and byte-level indicators (C2 domains, bot
  commands, packer stubs) that CFG analysis doesn't look for.
- CFG analysis catches structural/behavioral patterns (control-flow
  flattening, API call chains) that YARA can't express.
- Together they provide defense-in-depth: a sample that evades one
  detection layer is likely caught by the other.

Dependency: yara-python (pip install yara-python)
Falls back gracefully if yara-python is not installed — logs a warning
and returns empty matches rather than crashing the pipeline.
"""
import re
from pathlib import Path
from typing import Optional

from loguru import logger

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    logger.warning("yara-python not installed — YARA scanning disabled. Install with: pip install yara-python")


# ── Built-in YARA rules (embedded as source strings) ────────────────────

BUILTIN_RULES_SOURCE = r"""
rule AndroidBankingTrojan_C2Patterns {
    meta:
        description = "Detects common C2 communication patterns in Android banking trojans"
        severity = "0.8"
        category = "c2_communication"
        author = "GuardGraph AI"

    strings:
        $bot_cmd1 = "botId" ascii wide nocase
        $bot_cmd2 = "bot_id" ascii wide nocase
        $bot_cmd3 = "sendSMS" ascii wide nocase
        $bot_cmd4 = "grabSMS" ascii wide nocase
        $bot_cmd5 = "getContacts" ascii wide nocase
        $bot_cmd6 = "startKeylog" ascii wide nocase
        $bot_cmd7 = "startVNC" ascii wide nocase
        $bot_cmd8 = "injectList" ascii wide nocase
        $bot_cmd9 = "getAccounts" ascii wide nocase
        $bot_cmd10 = "push_notification" ascii wide nocase

        $panel1 = "/gate.php" ascii wide nocase
        $panel2 = "/api/bot" ascii wide nocase
        $panel3 = "/panel/" ascii wide nocase

    condition:
        any of ($bot_cmd*) or any of ($panel*)
}

rule AndroidBankingTrojan_SMSInterception {
    meta:
        description = "Detects SMS interception code patterns used by banking trojans"
        severity = "0.9"
        category = "sms_interception"
        author = "GuardGraph AI"

    strings:
        $sms1 = "android.provider.Telephony.SMS_RECEIVED" ascii wide
        $sms2 = "pdus" ascii wide
        $sms3 = "getMessageBody" ascii wide
        $sms4 = "getOriginatingAddress" ascii wide
        $sms5 = "abortBroadcast" ascii wide
        $sms6 = "SMS_DELIVER" ascii wide
        $sms7 = "SmsMessage" ascii wide

        $otp1 = "otp" ascii wide nocase
        $otp2 = "verification" ascii wide nocase
        $otp3 = "confirm" ascii wide nocase
        $otp4 = "one.time" ascii wide nocase
        $otp5 = "2fa" ascii wide nocase
        $otp6 = "mtan" ascii wide nocase

    condition:
        2 of ($sms*) and 1 of ($otp*)
}

rule AndroidBankingTrojan_AccessibilityAbuse {
    meta:
        description = "Detects accessibility service abuse for credential overlay/keylogging"
        severity = "0.85"
        category = "accessibility_abuse"
        author = "GuardGraph AI"

    strings:
        $acc1 = "AccessibilityService" ascii wide
        $acc2 = "onAccessibilityEvent" ascii wide
        $acc3 = "AccessibilityNodeInfo" ascii wide
        $acc4 = "performAction" ascii wide
        $acc5 = "findAccessibilityNodeInfosByViewId" ascii wide
        $acc6 = "findAccessibilityNodeInfosByText" ascii wide

        $overlay1 = "TYPE_APPLICATION_OVERLAY" ascii wide
        $overlay2 = "SYSTEM_ALERT_WINDOW" ascii wide
        $overlay3 = "WindowManager$LayoutParams" ascii wide

        $action1 = "ACTION_CLICK" ascii wide
        $action2 = "ACTION_SET_TEXT" ascii wide
        $action3 = "getText" ascii wide

    condition:
        2 of ($acc*) and (1 of ($overlay*) or 2 of ($action*))
}

rule AndroidBankingTrojan_OverlayAttack {
    meta:
        description = "Detects WebView-based overlay/phishing injection targeting banking apps"
        severity = "0.85"
        category = "overlay_attack"
        author = "GuardGraph AI"

    strings:
        $webview1 = "WebView" ascii wide
        $webview2 = "loadUrl" ascii wide
        $webview3 = "setJavaScriptEnabled" ascii wide
        $webview4 = "addJavascriptInterface" ascii wide
        $webview5 = "evaluateJavascript" ascii wide

        $inject1 = "inject" ascii wide nocase
        $inject2 = "phish" ascii wide nocase
        $inject3 = "overlay" ascii wide nocase
        $inject4 = "document.getElementById" ascii wide
        $inject5 = ".value" ascii wide

        $target1 = "bank" ascii wide nocase
        $target2 = "login" ascii wide nocase
        $target3 = "password" ascii wide nocase
        $target4 = "credential" ascii wide nocase
        $target5 = "signin" ascii wide nocase

    condition:
        2 of ($webview*) and 1 of ($inject*) and 1 of ($target*)
}

rule AndroidPacker_KnownStubs {
    meta:
        description = "Detects known commercial packer/protector stubs (Jiagu, Bangcle, DexProtector)"
        severity = "0.6"
        category = "packer_detection"
        author = "GuardGraph AI"

    strings:
        // Qihoo 360 Jiagu
        $jiagu1 = "libjiagu" ascii wide
        $jiagu2 = "com.qihoo.util" ascii wide
        $jiagu3 = "com.stub.StubApp" ascii wide

        // Bangcle (SecNeo)
        $bangcle1 = "libsecexe" ascii wide
        $bangcle2 = "libsecmain" ascii wide
        $bangcle3 = "com.secneo.apkwrapper" ascii wide

        // DexProtector
        $dexprot1 = "DexProtector" ascii wide
        $dexprot2 = "libaurorabridge" ascii wide

        // Tencent Legu
        $legu1 = "libshella" ascii wide
        $legu2 = "com.tencent.StubShell" ascii wide

        // Baidu
        $baidu1 = "libbaiduprotect" ascii wide
        $baidu2 = "com.baidu.protect" ascii wide

        // iJiami
        $ijiami1 = "libexec" ascii wide
        $ijiami2 = "ijiami" ascii wide

        // APKProtect — a distinct open packer, not the same product as Jiagu
        // above (Qihoo 360's own packer IS Jiagu; a separately-named "Qihoo360"
        // family was deliberately not added here, since inventing markers for
        // it beyond the Jiagu strings already covered would be an unverified
        // guess — this project's own signature data (protected_brands.json)
        // requires real-artifact provenance, not guessed strings).
        $apkprot1 = "libAPKProtect" ascii wide
        $apkprot2 = "APKProtect.dat" ascii wide
        $apkprot3 = "com.apkprotect" ascii wide

    condition:
        any of them
}

rule AndroidMalware_SuspiciousDEX {
    meta:
        description = "Detects suspicious DEX file characteristics — manipulation or embedded payloads"
        severity = "0.7"
        category = "dex_manipulation"
        author = "GuardGraph AI"

    strings:
        $dex_magic = "dex\n" ascii
        $dex_035 = "dex\n035" ascii
        $dex_037 = "dex\n037" ascii
        $dex_038 = "dex\n038" ascii

        // DexClassLoader usage (dynamic code loading)
        $dynload1 = "DexClassLoader" ascii wide
        $dynload2 = "PathClassLoader" ascii wide
        $dynload3 = "InMemoryDexClassLoader" ascii wide
        $dynload4 = "openDexFile" ascii wide

        // Reflection heavy usage
        $reflect1 = "java/lang/reflect" ascii wide
        $reflect2 = "getDeclaredMethod" ascii wide
        $reflect3 = "setAccessible" ascii wide

    condition:
        (any of ($dex_*) at 0 and filesize > 5MB) or
        2 of ($dynload*) or
        (all of ($reflect*))
}

rule AndroidMalware_EncodedPayload {
    meta:
        description = "Detects Base64-encoded or encrypted payload indicators"
        severity = "0.65"
        category = "encoded_payload"
        author = "GuardGraph AI"

    strings:
        $b64_1 = "Base64" ascii wide
        $b64_2 = "decode" ascii wide
        $b64_3 = "android.util.Base64" ascii wide

        $crypto1 = "javax/crypto/Cipher" ascii wide
        $crypto2 = "AES" ascii wide
        $crypto3 = "DES" ascii wide
        $crypto4 = "SecretKeySpec" ascii wide
        $crypto5 = "IvParameterSpec" ascii wide

        $assets1 = "getAssets" ascii wide
        $assets2 = ".dat" ascii wide nocase
        $assets3 = ".bin" ascii wide nocase
        $assets4 = ".enc" ascii wide nocase

    condition:
        (2 of ($b64_*) and 2 of ($crypto*)) or
        (1 of ($crypto*) and 2 of ($assets*))
}

rule AndroidMalware_AntiAnalysis {
    meta:
        description = "Detects anti-emulator, anti-debug, and anti-analysis techniques"
        severity = "0.5"
        category = "anti_analysis"
        author = "GuardGraph AI"

    strings:
        // Emulator detection
        $emu1 = "goldfish" ascii wide nocase
        $emu2 = "ranchu" ascii wide nocase
        $emu3 = "generic" ascii wide nocase
        $emu4 = "sdk_gphone" ascii wide nocase
        $emu5 = "google_sdk" ascii wide nocase
        $emu6 = "Emulator" ascii wide nocase
        $emu7 = "Android SDK built for" ascii wide
        $emu8 = "Genymotion" ascii wide nocase
        $emu9 = "BlueStacks" ascii wide nocase

        // Debug detection
        $dbg1 = "isDebuggerConnected" ascii wide
        $dbg2 = "android.os.Debug" ascii wide
        $dbg3 = "FLAG_DEBUGGABLE" ascii wide

        // Root detection
        $root1 = "/system/app/Superuser.apk" ascii wide
        $root2 = "/system/xbin/su" ascii wide
        $root3 = "com.noshufou.android.su" ascii wide
        $root4 = "eu.chainfire.supersu" ascii wide

        // Frida detection
        $frida1 = "frida" ascii wide nocase
        $frida2 = "27042" ascii wide
        $frida3 = "libfrida" ascii wide

    condition:
        3 of ($emu*) or 2 of ($dbg*) or 2 of ($root*) or 1 of ($frida*)
}
"""


# ── Packer family identification ─────────────────────────────────────────

# AndroidPacker_KnownStubs's own matched_strings (e.g. "$jiagu1") name which
# specific commercial packer fired, but scan_file()/scan_bytes() only surface
# the generic rule name/description. Mapping identifier prefix -> readable
# family name turns "AndroidPacker_KnownStubs matched" into "Jiagu (Qihoo
# 360)" in the manifest/report — same underlying detection, more useful text.
_PACKER_FAMILY_BY_PREFIX = {
    "jiagu": "Jiagu (Qihoo 360)",
    "bangcle": "Bangcle / SecNeo",
    "dexprot": "DexProtector",
    "legu": "Tencent Legu",
    "baidu": "Baidu Protect",
    "ijiami": "iJiami",
    "apkprot": "APKProtect",
}


def identify_packer_families(matched_strings: list[str]) -> list[str]:
    """
    Given AndroidPacker_KnownStubs's matched_strings (identifiers like
    "$jiagu1", "$bangcle2"), returns the distinct packer family names they
    correspond to, in the order first seen. Empty if none recognized (e.g.
    called on a different rule's matches, or an empty list).
    """
    families: list[str] = []
    for identifier in matched_strings:
        prefix = identifier.lstrip("$").rstrip("0123456789")
        family = _PACKER_FAMILY_BY_PREFIX.get(prefix)
        if family and family not in families:
            families.append(family)
    return families


# ── Module-level compiled rules cache ────────────────────────────────────

# Derived, not hardcoded, so the startup log can't drift from the source above.
BUILTIN_RULE_COUNT = len(re.findall(r"^rule\s+\w+", BUILTIN_RULES_SOURCE, re.MULTILINE))

_COMPILED_RULES: Optional["yara.Rules"] = None


def compile_rules(rules_dir: str = "") -> Optional["yara.Rules"]:
    """
    Compiles built-in YARA rules + any .yar/.yara files in rules_dir.
    Returns compiled yara.Rules object, or None if yara-python is
    unavailable.

    Caches the compiled rules — call reset_compiled_rules() to force
    recompilation (e.g. after adding new .yar files).
    """
    global _COMPILED_RULES
    if not YARA_AVAILABLE:
        return None
    if _COMPILED_RULES is not None:
        return _COMPILED_RULES

    # Always include the built-in rules
    sources = {"builtin": BUILTIN_RULES_SOURCE}
    valid_external_count = 0
    invalid_external_count = 0

    # Load external .yar/.yara files from rules_dir.
    # Both extensions matter: download_yara_rules.py preserves the upstream
    # filename, and Yara-Rules/rules ships a mix of .yar and .yara — globbing
    # only "*.yar" silently drops the .yara subset from the compiled ruleset.
    if rules_dir:
        rules_path = Path(rules_dir)
        if rules_path.is_dir():
            rule_files = sorted(
                p for p in rules_path.glob("*")
                if p.suffix.lower() in (".yar", ".yara")
            )
            for yar_file in rule_files:
                try:
                    rule_text = yar_file.read_text(encoding="utf-8")
                    # Try compiling this single file first to check for syntax/import errors
                    yara.compile(source=rule_text)
                    # Namespace on full filename, not stem — foo.yar and foo.yara
                    # would otherwise collide and one would be dropped.
                    sources[yar_file.name] = rule_text
                    valid_external_count += 1
                except Exception as e:
                    # Ignore invalid files to prevent one broken community rule from disabling the entire engine
                    invalid_external_count += 1
                    logger.warning(f"Skipping YARA file {yar_file.name} due to compilation error: {e}")

    try:
        _COMPILED_RULES = yara.compile(sources=sources)
        logger.info(
            f"YARA rules compiled: {BUILTIN_RULE_COUNT} built-in, "
            f"{valid_external_count} external file(s) loaded. "
            f"({invalid_external_count} broken external(s) skipped)"
        )
        if rules_dir and valid_external_count == 0:
            logger.warning(
                f"No community YARA rules loaded from '{rules_dir}' — running on the "
                f"{BUILTIN_RULE_COUNT} built-in rules only. "
                f"Populate it with: python scripts/download_yara_rules.py"
            )
        return _COMPILED_RULES
    except yara.SyntaxError as e:
        # Fallback to just built-in rules if the merge fails unexpectedly
        logger.error(f"Merged YARA compilation failed: {e}. Falling back to built-in rules only.")
        try:
            _COMPILED_RULES = yara.compile(source=BUILTIN_RULES_SOURCE)
            return _COMPILED_RULES
        except Exception:
            return None



def reset_compiled_rules() -> None:
    """Clears the compiled rules cache — forces recompilation on next scan."""
    global _COMPILED_RULES
    _COMPILED_RULES = None


def scan_file(filepath: str, rules_dir: str = "") -> list[dict]:
    """
    Scans a file (APK or DEX) against compiled YARA rules.

    Returns a list of match dicts, each with:
        rule_name: str — the YARA rule identifier
        tags: list[str] — rule tags
        severity: float — 0.0-1.0 from rule meta
        description: str — from rule meta
        category: str — from rule meta
        matched_strings: list[str] — which string identifiers triggered

    Empty list = no YARA rules matched (not suspicious at this layer).
    Returns empty list if yara-python is not available.
    """
    if not YARA_AVAILABLE:
        return []

    rules = compile_rules(rules_dir)
    if rules is None:
        return []

    try:
        raw_matches = rules.match(filepath)
    except yara.Error as e:
        logger.error(f"YARA scan failed on {filepath}: {e}")
        return []

    matches: list[dict] = []
    for m in raw_matches:
        meta = m.meta if hasattr(m, "meta") else {}

        # Extract matched string identifiers for reporting
        matched_strings = []
        if hasattr(m, "strings"):
            for string_match in m.strings:
                # yara-python 4.x: StringMatch objects with .identifier
                if hasattr(string_match, "identifier"):
                    matched_strings.append(string_match.identifier)
                # yara-python 3.x fallback: tuples of (offset, identifier, data)
                elif isinstance(string_match, tuple) and len(string_match) >= 2:
                    matched_strings.append(str(string_match[1]))

        matches.append({
            "rule_name": m.rule,
            "tags": list(m.tags) if hasattr(m, "tags") else [],
            "severity": float(meta.get("severity", 0.5)),
            "description": str(meta.get("description", "")),
            "category": str(meta.get("category", "unknown")),
            "matched_strings": list(set(matched_strings))[:20],  # dedupe, cap at 20
            "scan_target": "apk",
        })

    if matches:
        logger.warning(f"YARA scan matched {len(matches)} rule(s): {[m['rule_name'] for m in matches]}")

    return matches


def scan_bytes(data: bytes, rules_dir: str = "", scan_target: str = "bytes") -> list[dict]:
    """
    Scans raw bytes (e.g. extracted DEX content) against compiled YARA rules.
    Same return format as scan_file(), plus scan_target label.
    """
    if not YARA_AVAILABLE:
        return []

    rules = compile_rules(rules_dir)
    if rules is None:
        return []

    try:
        raw_matches = rules.match(data=data)
    except yara.Error as e:
        logger.error(f"YARA byte scan failed ({scan_target}): {e}")
        return []

    matches: list[dict] = []
    for m in raw_matches:
        meta = m.meta if hasattr(m, "meta") else {}
        matched_strings = []
        if hasattr(m, "strings"):
            for string_match in m.strings:
                if hasattr(string_match, "identifier"):
                    matched_strings.append(string_match.identifier)
                elif isinstance(string_match, tuple) and len(string_match) >= 2:
                    matched_strings.append(str(string_match[1]))

        matches.append({
            "rule_name": m.rule,
            "tags": list(m.tags) if hasattr(m, "tags") else [],
            "severity": float(meta.get("severity", 0.5)),
            "description": str(meta.get("description", "")),
            "category": str(meta.get("category", "unknown")),
            "matched_strings": list(set(matched_strings))[:20],
            "scan_target": scan_target,
        })

    return matches


def scan_apk_with_payloads(
    filepath: str,
    payload_targets: list[tuple[str, bytes]] | None = None,
    rules_dir: str = "",
) -> tuple[list[dict], list[str]]:
    """
    Defense-in-depth YARA scan that covers:

      1. The outer .apk ZIP container on disk (packed bytes)
      2. Uncompressed inner streams (classes*.dex, hidden asset DEX/ZIP payloads)

    ZIP compression can hide ASCII/hex strings from rules that match over the
    raw .apk file; scanning uncompressed DEX/asset bytes closes that gap.

    Returns (deduped_matches, scan_target_labels).
    Matches for the same rule_name are merged (union of matched_strings,
    max severity, combined scan_target labels).
    """
    all_matches: list[dict] = []
    targets_scanned: list[str] = []

    # 1) Outer APK file
    file_matches = scan_file(filepath, rules_dir=rules_dir)
    for m in file_matches:
        m.setdefault("scan_target", "apk")
    all_matches.extend(file_matches)
    targets_scanned.append("apk")

    # 2) Uncompressed payloads (DEX / disguised assets)
    for label, data in (payload_targets or []):
        if not data:
            continue
        targets_scanned.append(label)
        try:
            byte_matches = scan_bytes(data, rules_dir=rules_dir, scan_target=label)
            all_matches.extend(byte_matches)
        except Exception as e:
            logger.warning(f"YARA payload scan failed for {label}: {e}")

    merged = _dedupe_yara_matches(all_matches)
    if merged:
        logger.warning(
            f"YARA scan matched {len(merged)} rule(s) across {len(targets_scanned)} target(s): "
            f"{[m['rule_name'] for m in merged]}"
        )
    return merged, targets_scanned


def _dedupe_yara_matches(matches: list[dict]) -> list[dict]:
    """Merge matches that share the same rule_name across scan targets."""
    by_rule: dict[str, dict] = {}
    for m in matches:
        name = m.get("rule_name", "")
        if name not in by_rule:
            by_rule[name] = {
                "rule_name": name,
                "tags": list(m.get("tags") or []),
                "severity": float(m.get("severity", 0.5)),
                "description": str(m.get("description", "")),
                "category": str(m.get("category", "unknown")),
                "matched_strings": list(m.get("matched_strings") or []),
                "scan_target": str(m.get("scan_target", "apk")),
            }
            continue

        existing = by_rule[name]
        existing["severity"] = max(existing["severity"], float(m.get("severity", 0.0)))
        # Union tags / strings
        existing["tags"] = list(set(existing["tags"]) | set(m.get("tags") or []))
        existing["matched_strings"] = list(
            set(existing["matched_strings"]) | set(m.get("matched_strings") or [])
        )[:20]
        # Record all targets that hit this rule
        targets = {t.strip() for t in existing["scan_target"].split("|") if t.strip()}
        targets.add(str(m.get("scan_target", "")))
        existing["scan_target"] = "|".join(sorted(t for t in targets if t))

    merged = list(by_rule.values())
    for match in merged:
        if match["rule_name"] != "AndroidPacker_KnownStubs":
            continue
        families = identify_packer_families(match["matched_strings"])
        if families:
            match["description"] = f'{match["description"]} — matched: {", ".join(families)}'
    return merged
