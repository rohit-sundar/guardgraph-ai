"""
Scoped dynamic verification — Phase 8, opt-in only.

Deliberately narrow, on purpose: this does NOT run a general sandbox and does
NOT produce its own independent behavioral report. It installs the APK on an
already-running AVD, attaches Frida for a bounded window, and hooks exactly
the handful of APIs that have a direct static counterpart already computed
earlier in this pipeline — network connections (vs. ingestion.c2_indicators),
SMS API invocation (vs. the SMS_OTP_STEALER_PATTERN forensic anchor),
DexClassLoader class loads actually executed (vs. resolved_dcl_targets from
dcl_tracing.py), accessibility service binding (vs. accessibility_flags), and
Cipher invocation (vs. resolved_crypto_configs). Every dynamic finding is
reported as confirming or not confirming a specific static prediction, never
as a free-standing new claim — this is what lets GraphRAG say "static
analysis predicted X; dynamic execution confirmed it" instead of bolting a
second, disconnected report onto the narrative.

A booted AVD is no longer a precondition a human has to satisfy: when nothing
is attached, _ensure_device_booted starts the AVD named by AVD_NAME (or the
only installed one) and waits for sys.boot_completed before going further, so
`enable_dynamic=true` is all a request needs. It is NOT shut down afterwards —
subsequent runs reuse it and skip the boot entirely. Set
DYNAMIC_ANALYSIS_AUTO_BOOT=false for the old fail-fast behaviour.
frida-server itself IS self-healed (see _ensure_frida_server_running):
confirmed live, repeatedly, across this feature's own testing that
frida-server on the AVD dies between runs on its own, so every dynamic pass
verifies it's running and restarts it if not, rather than depending on a
human noticing. What is still a one-time manual step: pushing the
frida-server binary to the device at all — see
app/analysis/frida_scripts/README.md (go/no-go gate run 2026-08-23:
WHPX-accelerated AVD, Frida 17.15.5 client/server, Android 11 x86_64).

Fails closed like every other RE-deep-dive module in this pipeline
(dcl_tracing.py, native_bridge.py, crypto_recovery.py): never raises, and any
failure produces `{"ran": False, ...}` with a coverage_note explaining what
happened. `ran: False` must not be read as "no dynamic evidence" — that is
what an all-empty `ran: True` result means; `ran: False` means the pass
itself did not complete.

CONTAINMENT — read before running an untrusted APK through this:
An AVD's default networking gives the guest real internet egress AND a route
to the HOST's own loopback via the 10.0.2.2 alias, so an unconstrained guest
could reach this machine's other listening services (this API, Neo4j,
Ollama) or a real C2. `_egress_appears_blocked()` below MEASURES (does not
just assume) whether the guest currently has a real path out, and
`run_dynamic_verification` refuses to install the APK at all if it doesn't
look blocked — this is a probe-and-gate, not a kill switch this code can
throw, because the documented emulator console command for that
(`adb emu network disable`) does not exist on the build validated here (see
`_egress_appears_blocked`'s docstring). The durable, admin-enforced fix is a
host firewall rule blocking the emulator process's outbound traffic — this
session had no admin rights to apply it, so it is a manual one-time step; see
app/analysis/frida_scripts/README.md for the exact command. Until that rule
is in place, treat the probe-and-gate here as the only line of defense, not
a guaranteed one.
"""
import os
import re
import shutil
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

from loguru import logger

from app.analysis.apk_static import c2_host
from app.core.config import settings

_AGENT_SCRIPT_PATH = Path(__file__).parent / "frida_scripts" / "_agent.js"


class _DynamicVerificationError(Exception):
    """
    Internal only. Every adb/frida step raises this on failure so
    run_dynamic_verification has exactly one catch site and every failure
    mode (device offline, install rejected, package never launched, Frida
    couldn't attach) produces the same shaped `ran: False` outcome rather
    than a different partial state per failure site.
    """


def is_harness_endpoint(value: str) -> bool:
    """
    Is this endpoint the analysis harness talking to itself rather than the
    sample contacting anything?

    The AVD's own adbd listens on :5555 and is reachable from inside the
    emulator, so the network hooks record it like any other connection. It was
    landing in network_observed_all and being read as attacker infrastructure —
    exactly the kind of unfounded claim this graph cannot afford. 10.0.2.x is
    qemu's user-mode network (the emulator itself, the host alias, its DNS).
    """
    v = (value or "").lower()
    return (
        ":5555" in v
        or "10.0.2." in v
        or v.startswith("0.0.0.0")
        or "127.0.0.1" in v
        or "localhost" in v
    )


def _is_frida_error(exc: BaseException) -> bool:
    """
    Is this exception frida's (the target went away), or ours (a fault in our
    own capture code)?

    Not `isinstance(exc, frida.Error)`: frida 17 dropped that base class, and
    its fourteen error types now inherit Exception directly. Referencing it
    raised AttributeError from inside the capture window's exception handler,
    which aborted an otherwise-healthy run and reported ran=False — observed
    live as "unexpected error: module 'frida' has no attribute 'Error'". The
    line that crashed existed precisely to avoid misreporting a capture-code
    fault as the sample self-terminating, so its own failure cost exactly what
    it was written to protect.

    Matching the module's actual error classes keeps that original intent
    without naming a base that no longer exists. An empty tuple (frida
    unimportable, or renamed classes in some future version) makes this False,
    which is the safe answer: "our bug", not a forensic claim about the
    malware that was never observed.
    """
    try:
        import frida
    except ImportError:
        return False
    classes = tuple(
        obj
        for name, obj in vars(frida).items()
        if isinstance(obj, type) and issubclass(obj, Exception) and name.endswith("Error")
    )
    return isinstance(exc, classes)


@dataclass
class DynamicVerificationOutcome:
    ran: bool = False
    duration_s: float = 0.0
    # Static C2 indicators (ingestion.c2_indicators) the dynamic pass actually
    # observed a connection to / did not observe a connection to. Absence from
    # network_confirmed is not refutation — see run_dynamic_verification's
    # docstring on coverage_note explaining common false-negative causes
    # (sandbox detection, a C2 check gated behind a timer longer than the
    # capture window, no network egress inside the AVD).
    network_confirmed: list[str] = field(default_factory=list)
    network_predicted_not_seen: list[str] = field(default_factory=list)
    # Every host:port the app actually attempted to connect to during the
    # capture window, independent of whether it matched a static prediction.
    # The confirm/refute fields above only ever cover what the static pass
    # already predicted — a real connection to an address nothing predicted
    # used to be silently dropped instead of shown, which threw away genuine
    # observed evidence whenever it didn't happen to line up with a static
    # finding. This is that evidence, unfiltered.
    network_observed_all: list[str] = field(default_factory=list)
    sms_api_invoked: bool = False
    dcl_payload_executed: bool = False
    dcl_classes_loaded: list[str] = field(default_factory=list)
    accessibility_bound: bool = False
    crypto_invoked: bool = False
    # native_bridge.py statically resolves System.loadLibrary("x") call sites
    # to their .so and JNI symbols but can never confirm the call actually
    # ran. This hooks the exact same API dynamically — a non-empty list here
    # means the app genuinely loaded that native library at runtime, the same
    # "predicted vs confirmed" treatment dcl_payload_executed already gets.
    native_libraries_loaded: list[str] = field(default_factory=list)
    native_library_confirmed: bool = False
    # IoC-oriented findings — not diffed against any static prediction (there
    # usually isn't one), reported standalone the way any dynamic-analysis
    # sandbox would: full URLs actually requested, files the app wrote to its
    # own sandbox (a dropper's payload lands here, not somewhere pre-declared
    # statically), and shell commands executed via Runtime.exec.
    urls_accessed: list[str] = field(default_factory=list)
    files_written: list[str] = field(default_factory=list)
    commands_executed: list[str] = field(default_factory=list)
    # The hooks that back sms_api_invoked/accessibility_bound/crypto_invoked
    # send a real value (destination number, service class name, cipher
    # algorithm) — these three booleans used to be all that survived, the
    # value itself thrown away every time. A premium-rate SMS destination or
    # a weak cipher (DES/ECB) is a real, specific IoC, not just a yes/no.
    sms_destinations: list[str] = field(default_factory=list)
    accessibility_services: list[str] = field(default_factory=list)
    crypto_algorithms: list[str] = field(default_factory=list)
    # Cheap substitute for real parameterized string-decryption (see
    # hooks.js's hookCrypto): the actual doFinal() return value, captured
    # live and truncated (CRYPTO_OUTPUT_PREVIEW_CAP in hooks.js), plus
    # Cipher.init's encrypt/decrypt mode. Reported as independent
    # observations, not correlated per-Cipher-instance — see hookCrypto's
    # comment on why that correlation isn't attempted. Each entry:
    # {"algorithm": ..., "preview": ...} or {"algorithm": ..., "mode": ...}.
    crypto_outputs: list[dict] = field(default_factory=list)
    crypto_modes_observed: list[str] = field(default_factory=list)
    # Incoming-SMS interception — the actual OTP-theft path this project is
    # aimed at (sms_api_invoked above only ever covered the app SENDING a
    # message). Non-empty means the app parsed an incoming SMS's sender
    # during the capture window, which on an AVD with no real SIM/carrier is
    # only reachable via `adb shell` simulating an incoming SMS — see
    # run_dynamic_verification's docstring for how that's driven.
    sms_intercepted: list[str] = field(default_factory=list)
    # Overlay-attack detection — a WindowManager.addView call with a
    # SYSTEM/OVERLAY-class window type (>=2000), the mechanism behind a fake
    # login screen drawn over the real banking app. Mechanically verified
    # (installs cleanly, correct API for this AVD image); NOT yet confirmed
    # firing against a real overlay attack in this codebase's own testing —
    # said so explicitly rather than overclaiming a hook that hasn't been
    # seen to fire.
    overlay_detected: bool = False
    overlay_window_types: list[str] = field(default_factory=list)
    # Contacts/call-log/SMS-history reads via ContentResolver.query, and
    # clipboard reads (crypto-clipper malware swaps a copied wallet address).
    sensitive_content_queries: list[str] = field(default_factory=list)
    clipboard_read: bool = False
    # Full event timeline, {t (ms since agent load), kind, value}, sorted —
    # every event carries `t` now; this is that ordering surfaced rather
    # than only unordered per-kind sets, so a report can eventually say
    # "contacted C2 3.2s after launch" instead of just "at some point".
    timeline: list[dict] = field(default_factory=list)
    # /static/screenshots/{sha256}_final.png — a live capture of the app's
    # foreground UI at the end of the window, or None if capture failed or
    # sha256 wasn't provided (e.g. a caller testing this module standalone).
    # Kept mainly for before/after comparison against screenshot_reaction_url —
    # by the end of the window a quiet sample has often idled back to its home
    # screen, so this alone is frequently just a blank screen.
    screenshot_url: str | None = None
    # /static/screenshots/{sha256}_reaction.png — captured a few seconds after
    # the SMS/tap stimuli fire (see _run_capture_window_with_stimuli), while
    # the app is most likely actually reacting. This is the primary useful
    # capture; screenshot_url is the secondary end-of-window one.
    screenshot_reaction_url: str | None = None
    # Screenshots taken the instant a crucial event fired (overlay drawn, SMS
    # intercepted, accessibility bound, DCL payload class loaded, SMS sent,
    # OS command executed) — see _CRUCIAL_SCREENSHOT_KINDS. Each entry:
    # {"kind": <event kind that triggered it>, "url": ..., "t": <ms since
    # agent load>}. Complements the fixed reaction/final shots with ones tied
    # to a specific observed cause, one per kind, capped at
    # _MAX_EVENT_SCREENSHOTS total.
    event_screenshots: list[dict] = field(default_factory=list)
    # Last ~50 logcat lines captured the moment the target process crashed
    # mid-capture (see _collect_events' crashed branch). Substantiates the
    # "possible anti-analysis self-termination" inference with the actual
    # exception/reason instead of leaving it as a guess from the Frida
    # session merely disconnecting — empty unless a crash actually happened.
    crash_logcat_tail: list[str] = field(default_factory=list)
    # Count of every raw agent event by kind (network, sms_send, dcl_class_load,
    # accessibility_bound, crypto_invoked, url_accessed, file_written,
    # command_executed, hook_installed, hook_error, target_crashed) — lets the
    # report say something concrete ("5 hooks installed cleanly, 0 network
    # attempts, 3 classes dynamically loaded") even on a run where nothing
    # matched a static prediction, rather than reading as blank just because
    # nothing happened to line up.
    event_summary: dict = field(default_factory=dict)
    coverage_note: str = "dynamic analysis did not run"

    def to_dict(self) -> dict:
        return {
            "ran": self.ran,
            "duration_s": round(self.duration_s, 2),
            "network_confirmed": self.network_confirmed,
            "network_observed_all": self.network_observed_all,
            "urls_accessed": self.urls_accessed,
            "files_written": self.files_written,
            "commands_executed": self.commands_executed,
            "event_summary": self.event_summary,
            "network_predicted_not_seen": self.network_predicted_not_seen,
            "sms_api_invoked": self.sms_api_invoked,
            "dcl_payload_executed": self.dcl_payload_executed,
            "dcl_classes_loaded": self.dcl_classes_loaded,
            "accessibility_bound": self.accessibility_bound,
            "crypto_invoked": self.crypto_invoked,
            "native_libraries_loaded": self.native_libraries_loaded,
            "native_library_confirmed": self.native_library_confirmed,
            "sms_destinations": self.sms_destinations,
            "accessibility_services": self.accessibility_services,
            "crypto_algorithms": self.crypto_algorithms,
            "crypto_outputs": self.crypto_outputs,
            "crypto_modes_observed": self.crypto_modes_observed,
            "sms_intercepted": self.sms_intercepted,
            "overlay_detected": self.overlay_detected,
            "overlay_window_types": self.overlay_window_types,
            "sensitive_content_queries": self.sensitive_content_queries,
            "clipboard_read": self.clipboard_read,
            "timeline": self.timeline,
            "screenshot_url": self.screenshot_url,
            "screenshot_reaction_url": self.screenshot_reaction_url,
            "event_screenshots": self.event_screenshots,
            "crash_logcat_tail": self.crash_logcat_tail,
            "coverage_note": self.coverage_note,
        }


def _adb_env() -> dict:
    env = os.environ.copy()
    if settings.adb_server_port:
        env["ANDROID_ADB_SERVER_PORT"] = str(settings.adb_server_port)
    return env


def _adb(args: list[str], timeout: int = 30) -> str:
    cmd = [settings.adb_path]
    if settings.adb_device_serial:
        cmd += ["-s", settings.adb_device_serial]
    cmd += args
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, env=_adb_env(),
            # Explicit, because `text=True` alone decodes with the LOCALE codec —
            # cp1252 on a default Windows install. adb emits UTF-8, and device
            # output routinely carries non-Latin text (an app's own UI strings via
            # `uiautomator dump`, localized package labels, logcat). A byte that
            # cp1252 leaves undefined (0x81, 0x8d, 0x8f, 0x90, 0x9d) killed
            # subprocess's reader thread with UnicodeDecodeError, which does NOT
            # propagate here — it leaves result.stdout as None, so this returned
            # None and the caller failed later with an unrelated-looking
            # "expected string or bytes-like object". Observed live: a sample whose
            # UI text is non-Latin aborted the whole Phase 8 capture window this
            # way, and the failure was then reported to the analyst as the sample
            # "self-terminating" (anti-analysis) rather than as our own decode bug.
            # errors="replace" so a single odd byte degrades one character instead
            # of losing the entire stream again.
            encoding="utf-8", errors="replace",
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        raise _DynamicVerificationError(f"adb {' '.join(args)} failed: {e}") from e
    if result.returncode != 0:
        raise _DynamicVerificationError(
            f"adb {' '.join(args)} exit {result.returncode}: {result.stderr.strip()}"
        )
    return result.stdout


_UNSIGNED_INSTALL_MARKERS = (
    "INSTALL_PARSE_FAILED_NO_CERTIFICATES",
    "INSTALL_PARSE_FAILED_UNEXPECTED_EXCEPTION",  # some corrupt-signature cases surface here instead
    "INSTALL_FAILED_INVALID_APK",
)


def _ensure_resign_keystore() -> str:
    """
    Generates the throwaway debug keystore once and reuses it — regenerating
    per-sample would change nothing about install success and just costs
    time. This key asserts nothing about any sample's real identity; it
    exists only so `pm install` has *a* valid signature to accept.
    """
    ks_path = settings.dynamic_resign_keystore_path
    if os.path.exists(ks_path):
        return ks_path
    os.makedirs(os.path.dirname(ks_path) or ".", exist_ok=True)
    keytool = settings.java_keytool_path
    try:
        subprocess.run(
            [
                keytool, "-genkeypair", "-v",
                "-keystore", ks_path, "-storepass", "guardgraph", "-keypass", "guardgraph",
                "-alias", "guardgraph-dynamic-resign", "-keyalg", "RSA", "-keysize", "2048",
                "-validity", "10000",
                "-dname", "CN=GuardGraph Dynamic Verification, OU=Sandbox, O=GuardGraph, C=US",
            ],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30, check=True,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as e:
        raise _DynamicVerificationError(f"could not generate re-sign keystore: {e}") from e
    return ks_path


def _resign_apk(apk_path: str) -> str:
    """
    Re-signs a COPY of the APK with the throwaway debug key, so a sample
    with a missing/corrupt signature (common from malware-feed downloads —
    Android's package manager refuses to install ANYTHING unsigned) can
    still be installed for dynamic verification. The DEX/manifest/behavior
    are untouched — only the signing block is replaced — and the original
    uploaded file used for hashing/static analysis is never modified, only
    a temp copy passed to `pm install`.

    Raises _DynamicVerificationError (never silently) if apksigner isn't
    configured (settings.android_build_tools_dir empty) or the sample's zip
    structure is too corrupt for apksigner itself to process — some malware
    samples are broken beyond even this fallback, and that is reported, not
    hidden.
    """
    if not settings.android_build_tools_dir:
        raise _DynamicVerificationError(
            "re-sign fallback unavailable — android_build_tools_dir not configured"
        )
    apksigner = os.path.join(settings.android_build_tools_dir, "apksigner.bat")
    if not os.path.exists(apksigner):
        apksigner = os.path.join(settings.android_build_tools_dir, "apksigner")
    ks_path = _ensure_resign_keystore()

    fd, resigned_path = tempfile.mkstemp(suffix=".apk")
    os.close(fd)
    shutil.copyfile(apk_path, resigned_path)

    try:
        result = subprocess.run(
            [
                apksigner, "sign",
                "--ks", ks_path, "--ks-pass", "pass:guardgraph", "--key-pass", "pass:guardgraph",
                resigned_path,
            ],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        os.unlink(resigned_path)
        raise _DynamicVerificationError(f"apksigner failed to run: {e}") from e
    if result.returncode != 0:
        os.unlink(resigned_path)
        raise _DynamicVerificationError(
            f"apksigner could not re-sign this sample: {result.stderr.strip()}"
        )
    return resigned_path


_SIGNATURE_MISMATCH_MARKERS = (
    "INSTALL_FAILED_UPDATE_INCOMPATIBLE",
    "signatures do not match",
)


def _install(apk_path: str, package_name: str) -> str:
    """
    Returns the path actually installed — the original, unless a
    missing/corrupt signature forced the re-sign fallback, in which case
    it's a temp copy the caller is responsible for cleaning up.

    -g grants runtime permissions at install time — SMS/accessibility hooks
    need the app to actually be ABLE to call the APIs being watched;
    otherwise every run reads as "not observed" for the wrong reason (a
    permission dialog no automated pass here answers), not because the app
    doesn't try.

    Two independent retry paths, confirmed live against real failures rather
    than assumed:
      1. Missing/corrupt signature (_UNSIGNED_INSTALL_MARKERS) -> re-sign
         with the throwaway debug key, retry once.
      2. Whatever gets installed (original OR re-signed) collides with a
         DIFFERENTLY-signed package of the same name already on the device
         (_SIGNATURE_MISMATCH_MARKERS) -> uninstall the stale package,
         retry once more. `_teardown` uninstalls after every normal run, so
         this state should be rare — but a crashed prior pass (killed
         process, disconnected AVD) skips teardown, and re-signing a sample
         guarantees a different key than whatever was there before, so this
         path WILL be hit the moment that happens. Confirmed by a live
         collision during this feature's own testing, not hypothetical.
    """
    def _attempt(path: str) -> None:
        _adb(["install", "-r", "-g", path], timeout=120)

    def _attempt_with_uninstall_retry(path: str) -> None:
        try:
            _attempt(path)
        except _DynamicVerificationError as e:
            if not any(marker in str(e) for marker in _SIGNATURE_MISMATCH_MARKERS):
                raise
            logger.warning(f"[Phase 8] stale conflicting install detected, uninstalling first: {e}")
            try:
                _adb(["uninstall", package_name], timeout=30)
            except _DynamicVerificationError as e2:
                logger.warning(f"[Phase 8] uninstall-before-retry failed (continuing anyway): {e2}")
            _attempt(path)

    try:
        _attempt_with_uninstall_retry(apk_path)
        return apk_path
    except _DynamicVerificationError as e:
        if not any(marker in str(e) for marker in _UNSIGNED_INSTALL_MARKERS):
            raise
        logger.warning(f"[Phase 8] install failed on signature grounds, retrying re-signed: {e}")
        resigned_path = _resign_apk(apk_path)
        _attempt_with_uninstall_retry(resigned_path)
        return resigned_path


def _grant_overlay_permission(package_name: str) -> None:
    """
    SYSTEM_ALERT_WINDOW is an AppOps special permission, not a normal runtime
    one — `adb install -g` does NOT grant it, only permissions the manifest
    declares under the standard runtime-permission model. Without this, an
    overlay-attack sample could never be observed regardless of the
    detection hook's correctness: the addView call would either throw
    immediately or never be reached, since real Android requires a user to
    interactively flip this on in Settings. Best-effort/non-fatal — a sample
    that doesn't need this permission is completely unaffected.
    """
    try:
        _adb(["shell", "appops", "set", package_name, "SYSTEM_ALERT_WINDOW", "allow"], timeout=15)
    except _DynamicVerificationError as e:
        logger.warning(f"[Phase 8] could not grant SYSTEM_ALERT_WINDOW (non-fatal): {e}")


def _egress_appears_blocked() -> bool:
    """
    Containment check, NOT containment itself — read carefully before trusting
    this.

    The obvious approach ("adb emu network disable", the emulator console's
    documented runtime network kill switch) does NOT exist on the emulator
    build validated here: `adb emu network disable` returns "KO: bad
    sub-command" (confirmed live, 2026-08-23 — this build only implements
    `network status/speed/delay/capture`, not enable/disable, despite that
    being documented for the console in general). There is also no reliable
    boot-time "kill all networking" flag — `-net-tap`/`-net-socket` change
    HOW the guest reaches the network, not whether it can.

    So instead of claiming a kill switch this code cannot actually operate,
    this function MEASURES the current state with a real TCP connect attempt
    from inside the guest to a public IP that always answers on 443 if any
    route exists. This is advisory, not a guarantee: a network that opens up
    between this probe and the app's own connection attempt a few seconds
    later would not be caught. The durable fix is host-side and is NOT
    something this code can do without admin rights this environment does not
    have — see REQUIRED_HOST_FIREWALL_SETUP in this module's docstring / the
    frida_scripts/README.md for the one-time `netsh` rule to run yourself.

    Returns True if egress looks blocked (the safe state to proceed in),
    False if a real connection succeeded (network reaches the internet).
    Any probe failure (adb error, no device) is treated as False — i.e. NOT
    provably safe — matching this module's fail-closed convention: an
    unverifiable state must never be read as "verified safe".
    """
    try:
        out = _adb(
            ["shell", "sh", "-c", "echo | toybox nc -w 3 8.8.8.8 443 >/dev/null 2>&1; echo $?"],
            timeout=15,
        )
        return out.strip() != "0"
    except _DynamicVerificationError as e:
        logger.warning(f"[Phase 8] egress probe itself failed — treating as NOT verified safe: {e}")
        return False


def _launch(package_name: str) -> None:
    _adb(
        ["shell", "monkey", "-p", package_name, "-c", "android.intent.category.LAUNCHER", "1"],
        timeout=30,
    )


def _broadcast_declared_actions(package_name: str, intent_actions: list[str] | None) -> int:
    """
    Fallback activation path for apps with no launcher activity — confirmed
    live: a real corpus sample has no exported activity at all (`monkey`
    exits 252, "no activities found") and used to make this entire pass
    report ran=False, even though the sample may be very much alive as a
    pure background/receiver-only component (SMS interceptors and
    boot-persistence droppers commonly have zero UI).

    Fires each of the app's OWN declared intent-filter actions
    (ingestion.intent_actions, already extracted statically) as a system
    broadcast, letting Android's normal intent-filter resolution deliver it
    to whichever manifest receiver actually registered for that exact
    action — deliberately NOT a hardcoded guess list, since a receiver's
    onReceive commonly branches on intent.getAction() and silently no-ops
    for anything else; using the sample's own declared actions is the only
    way to actually match what it's listening for.

    Restricted to "android."/"com.google." prefixed actions: those are the
    well-known system broadcasts (BOOT_COMPLETED, SMS_RECEIVED,
    PACKAGE_ADDED, USER_PRESENT, ...) deliverable with no extras. An app's
    own custom-namespaced action almost always expects specific extras this
    generic broadcast can't supply, so sending it would be a no-op at best.

    Best-effort per action — one broadcast failing (e.g. a protected system
    action `adb shell` isn't allowed to send) must not abort the rest.
    Returns how many broadcasts were actually accepted, for logging only.
    """
    sent = 0
    for action in intent_actions or []:
        if not action or not action.startswith(("android.", "com.google.")):
            continue
        try:
            # -p scopes delivery to this package only — without it the
            # broadcast goes to every app on the AVD listening for that
            # action, which is unnecessary noise (and, on a shared AVD,
            # could exercise components that have nothing to do with the
            # sample under test).
            # --include-stopped-packages is required, not optional: `pm install`
            # leaves an app in the STOPPED state until something starts it, and
            # the framework drops broadcasts to stopped packages by default.
            # Without this flag the intent is accepted (result=0) and delivered
            # to nothing, which looks identical to "the app ignored it".
            _adb(["shell", "am", "broadcast", "--include-stopped-packages",
                  "-p", package_name, "-a", action], timeout=10)
            sent += 1
        except _DynamicVerificationError as e:
            logger.warning(f"[Phase 8] fallback broadcast {action} failed (non-fatal): {e}")
    return sent


def _start_declared_components(
    package_name: str, activities: list[str] | None, services: list[str] | None
) -> str | None:
    """
    Activation tier between `monkey` and broadcast fallback: start the app's
    own declared components explicitly, by component name.

    `monkey -c android.intent.category.LAUNCHER` can only start an activity
    that declares the LAUNCHER category. Malware routinely declares activities
    WITHOUT it — hiding the launcher icon is itself a common evasion — and for
    those `monkey` exits 252 ("no activities found") even though the activity
    exists and starts perfectly well via `am start -n <pkg>/<component>`.
    Confirmed live on a corpus sample: two declared activities, no launcher
    category, monkey failed, explicit start produced a live process.

    Tries activities first (an Activity brings the process up in the
    foreground, which is what the UI-driven hooks and screenshots want), then
    services. Returns a short description of what worked, or None if nothing
    did; each failure is non-fatal so the caller can still fall through to
    broadcasts.
    """
    for component in list(activities or []):
        try:
            _adb(["shell", "am", "start", "-n", f"{package_name}/{component}"], timeout=15)
            if _find_pid(package_name, retries=3, delay=1.0):
                return f"activity {component}"
        except _DynamicVerificationError as e:
            logger.debug(f"[Phase 8] explicit activity start {component} failed: {e}")
    for component in list(services or []):
        try:
            _adb(["shell", "am", "start-service", "-n", f"{package_name}/{component}"], timeout=15)
            if _find_pid(package_name, retries=3, delay=1.0):
                return f"service {component}"
        except _DynamicVerificationError as e:
            logger.debug(f"[Phase 8] explicit service start {component} failed: {e}")
    return None


def _find_pid(package_name: str, retries: int = 10, delay: float = 1.0) -> int:
    """
    `pidof` exits 1 (not 0) when the process isn't up yet — that is the
    expected, retryable state in the first second or so after `am start`,
    not a failure. _adb() raises on any nonzero exit, so each attempt is
    wrapped here rather than letting the first miss blow up the whole retry
    loop (confirmed live: without this, the loop only ever "succeeded" when
    the process happened to already be running on the very first check).
    """
    for _ in range(retries):
        try:
            out = _adb(["shell", "pidof", package_name], timeout=10).strip()
        except _DynamicVerificationError:
            out = ""
        if out:
            # A multi-process app can report several space-separated pids;
            # the first is the main process the launcher intent above started.
            return int(out.split()[0])
        time.sleep(delay)
    raise _DynamicVerificationError(
        f"{package_name} did not appear in the process list after launch"
    )


def _teardown(package_name: str) -> None:
    """
    Best-effort cleanup. Every demo run may chain several APKs back to back,
    so the AVD must come back clean regardless of how the run above failed —
    failures here are logged, not raised, since a torn-down state is already
    the best available outcome at this point.
    """
    try:
        _adb(["shell", "am", "force-stop", package_name], timeout=15)
    except _DynamicVerificationError as e:
        logger.warning(f"[Phase 8] force-stop failed (non-fatal): {e}")
    try:
        _adb(["uninstall", package_name], timeout=30)
    except _DynamicVerificationError as e:
        logger.warning(f"[Phase 8] uninstall failed (non-fatal): {e}")


def _device_is_online() -> bool:
    """True when `adb devices` lists at least one device in state `device`.
    States like `offline`/`unauthorized`/`booting` are deliberately NOT counted
    — a half-attached emulator accepts a connection but fails every real
    command, which is exactly the confusing half-broken state this gate is
    meant to keep the pipeline out of."""
    try:
        out = _adb(["devices"], timeout=15)
    except _DynamicVerificationError:
        return False
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            return True
    return False


def _list_avds() -> list[str]:
    try:
        result = subprocess.run(
            [settings.emulator_path, "-list-avds"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30, env=_adb_env(),
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        raise _DynamicVerificationError(
            f"could not run '{settings.emulator_path} -list-avds' ({e}) — set EMULATOR_PATH "
            "in .env to the full path of the SDK's emulator binary."
        ) from e
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def _resolve_avd_name() -> str:
    """AVD_NAME from .env wins. Otherwise auto-select, but only when the choice
    is unambiguous — see settings.avd_name for why guessing between several
    AVDs is unsafe rather than merely arbitrary."""
    if settings.avd_name:
        return settings.avd_name
    avds = _list_avds()
    if not avds:
        raise _DynamicVerificationError(
            "no AVD is attached and none is installed to boot — create one (API 30+, "
            "'google_apis', x86_64) via Android Studio's Device Manager or avdmanager; "
            "see app/analysis/frida_scripts/README.md."
        )
    if len(avds) > 1:
        raise _DynamicVerificationError(
            f"no AVD is attached and several are installed ({', '.join(avds)}) — set "
            "AVD_NAME in .env to the one to boot. Pick the 'google_apis' image, not "
            "'google_apis_playstore': the Play-signed image blocks Frida from injecting."
        )
    return avds[0]


def _ensure_device_booted() -> None:
    """
    Boots the AVD when nothing is attached, so a request only has to ask for
    dynamic analysis rather than a human also having to remember to start an
    emulator first. No-op (and costs one `adb devices` call) when a device is
    already up, which is the common case once the first run of the day has
    booted it — this deliberately does NOT shut the AVD down afterwards, so
    subsequent runs stay fast.

    Two concurrent jobs can both find no device and both try to boot: the
    second emulator process fails on its own (an AVD can't boot twice) and is
    harmless, because the wait loop below only cares that SOME device reaches
    `device` state, which the first boot delivers.
    """
    if _device_is_online():
        return
    if not settings.dynamic_analysis_auto_boot:
        raise _DynamicVerificationError(
            "no AVD attached and auto-boot is disabled (DYNAMIC_ANALYSIS_AUTO_BOOT=false) "
            "— boot one manually, or re-enable auto-boot."
        )

    avd = _resolve_avd_name()
    logger.info(f"[Phase 8] No device attached — booting AVD '{avd}' (this can take a minute).")
    try:
        # Fire-and-forget, like _ensure_frida_server_running: the emulator runs
        # for the lifetime of the server, not of this request, so this must not
        # wait on it. Its stdout/stderr go nowhere on purpose — a booted AVD is
        # verified below by polling adb, which is the signal that actually
        # matters, not whatever the emulator logs on the way up.
        subprocess.Popen(
            [settings.emulator_path, "-avd", avd, "-no-snapshot",
             "-gpu", settings.emulator_gpu_mode, "-no-boot-anim"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
            env=_adb_env(),
        )
    except OSError as e:
        raise _DynamicVerificationError(
            f"could not launch the emulator ({e}) — set EMULATOR_PATH in .env to the full "
            "path of the SDK's emulator binary."
        ) from e

    # `adb wait-for-device` is deliberately not used: it blocks forever when no
    # emulator ever appears (a bad AVD name, a failed launch), turning a clean
    # failure into a hung request. Polling bounds that.
    deadline = time.time() + settings.avd_boot_timeout_seconds
    while time.time() < deadline:
        # sys.boot_completed only flips to 1 once the framework is actually up.
        # `adb devices` reporting `device` comes minutes earlier on a cold boot,
        # and installing against that half-booted window fails in confusing ways.
        if _device_is_online():
            try:
                if _adb(["shell", "getprop", "sys.boot_completed"], timeout=15).strip() == "1":
                    logger.info(f"[Phase 8] AVD '{avd}' booted and ready.")
                    return
            except _DynamicVerificationError:
                pass
        time.sleep(3)
    raise _DynamicVerificationError(
        f"AVD '{avd}' did not finish booting within {settings.avd_boot_timeout_seconds}s "
        "(AVD_BOOT_TIMEOUT_SECONDS). Try booting it by hand to see what it reports — a "
        "hang here is usually GPU-related (try EMULATOR_GPU_MODE=swiftshader_indirect)."
    )


def _ensure_frida_server_running() -> None:
    """
    Self-healing, not a one-time precondition check. frida-server on the AVD
    has proven flaky across this feature's own live testing — confirmed dying
    between analysis runs multiple times ("unable to connect to remote
    frida-server: closed") — so every dynamic pass verifies and, if needed,
    restarts it and re-establishes the port forward, instead of requiring a
    human to notice a dead server and run two manual adb commands each time.

    Does NOT push the frida-server binary — that is a one-time manual setup
    step (see app/analysis/frida_scripts/README.md). A missing binary here
    is a real setup gap this function surfaces, not something to silently
    work around.
    """
    try:
        pid = _adb(["shell", "pidof", "frida-server"], timeout=10).strip()
    except _DynamicVerificationError:
        pid = ""

    if not pid:
        logger.warning("[Phase 8] frida-server not running on device — restarting it")
        # subprocess.run (via _adb) BLOCKS until the child exits — but `adb
        # shell "cmd &"` does not reliably detach and return on its own even
        # though the device-side command backgrounds itself (confirmed live:
        # this hung the full 15s timeout every time under subprocess.run,
        # despite the equivalent manual `adb shell "... &" &`, backgrounded a
        # SECOND time at the host shell level, returning instantly). Fire-and
        # forget with Popen instead of waiting on a call that isn't going to
        # return promptly.
        cmd = [settings.adb_path]
        if settings.adb_device_serial:
            cmd += ["-s", settings.adb_device_serial]
        cmd += ["shell", f"su 0 {settings.frida_server_device_path}"]
        try:
            subprocess.Popen(
                cmd, env=_adb_env(),
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
            )
        except OSError as e:
            raise _DynamicVerificationError(
                f"frida-server is not running and could not be started (is it actually "
                f"pushed to {settings.frida_server_device_path}? one-time setup step — "
                f"see app/analysis/frida_scripts/README.md): {e}"
            ) from e
        time.sleep(2)  # give the binary a moment to bind before the forward/attach below

    # Re-forward unconditionally, even if frida-server was already running: a
    # `pidof` hit doesn't guarantee the forward survived (confirmed live — an
    # adb server restart drops forwards without touching the device-side
    # process). `adb forward` is idempotent, so redoing it costs nothing.
    try:
        _adb(
            ["forward", f"tcp:{settings.frida_local_port}", f"tcp:{settings.frida_local_port}"],
            timeout=10,
        )
    except _DynamicVerificationError as e:
        raise _DynamicVerificationError(f"could not establish adb port forward for frida: {e}") from e


# Common dialog-dismiss button labels, uppercased for a case-insensitive
# match against uiautomator's reported text. Deliberately generic — not
# targeting any specific app's UI, just the handful of words every Android
# system/permission dialog's affirmative button uses.
_DISMISS_BUTTON_TEXTS = frozenset({
    "OK", "GOT IT", "CONTINUE", "ACCEPT", "DISMISS", "CLOSE", "YES",
    "I AGREE", "AGREE", "ALLOW", "WHILE USING THE APP",
})
_BOUNDS_RE = re.compile(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]")


def _dismiss_blocking_dialog() -> bool:
    """
    Best-effort, one attempt. Android's own OS-level dialogs — an old-
    targetSdkVersion "this app was built for an older version of Android"
    compatibility warning, a runtime permission prompt — can block a
    sample's own code from ever running at all for the entire capture
    window. Confirmed live: a real corpus sample sat on exactly that
    compatibility dialog for the WHOLE window, so every single hook read
    not-observed for the wrong reason — the app never got to run, not that
    it behaved benignly. The stimulus taps in
    _run_capture_window_with_stimuli are fixed-coordinate and don't hit an
    arbitrary dialog's button, so this is a separate, targeted step: dump
    the current UI hierarchy via `uiautomator`, find a clickable node whose
    text matches a common dismiss label, and tap its center.

    Returns whether something was actually dismissed, purely so the caller
    can decide whether to retry (dismissing one dialog can reveal another).
    """
    try:
        _adb(["shell", "uiautomator", "dump", "/sdcard/guardgraph_ui.xml"], timeout=10)
        xml_text = _adb(["shell", "cat", "/sdcard/guardgraph_ui.xml"], timeout=10)
    except _DynamicVerificationError:
        return False
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return False
    for node in root.iter("node"):
        text = (node.get("text") or "").strip().upper()
        if node.get("clickable") == "true" and text in _DISMISS_BUTTON_TEXTS:
            m = _BOUNDS_RE.match(node.get("bounds") or "")
            if not m:
                continue
            x1, y1, x2, y2 = (int(v) for v in m.groups())
            cx, cy = (x1 + x2) // 2, (y1 + y2) // 2
            try:
                _adb(["shell", "input", "tap", str(cx), str(cy)], timeout=10)
                return True
            except _DynamicVerificationError:
                return False
    return False


def _dismiss_blocking_dialogs(max_attempts: int = 3) -> None:
    """Repeats _dismiss_blocking_dialog up to max_attempts times — dismissing
    one dialog (e.g. the compatibility warning) can reveal a second one
    (e.g. a permission prompt) right behind it. Stops as soon as an attempt
    finds nothing to dismiss, since further attempts would just re-dump an
    unchanged screen."""
    for _ in range(max_attempts):
        if not _dismiss_blocking_dialog():
            return
        time.sleep(0.5)


def _run_capture_window_with_stimuli(timeout_s: int, sha256: str | None) -> str | None:
    """
    A passive `time.sleep(timeout_s)` was the entire capture window until
    this — a sample that gates its real behavior behind ANY interaction
    (a real incoming SMS to intercept, a tap indicating "this looks like a
    used device") would sit idle for the whole window and read as "not
    observed" for the wrong reason. Injects two categories of stimulus
    partway through, both best-effort (a failed injection must not cost the
    rest of the capture window):

    - A simulated inbound SMS via the emulator console (`adb emu sms send`)
      — an AVD has no real carrier, so hookSmsRead in hooks.js can never
      fire without this. The fake OTP text is deliberately generic/obvious
      (not disguised as this being a real user's real bank), consistent
      with this being a detonation aid, not a deception.
    - A couple of synthetic taps (`adb shell input tap`), the same "does
      this look like a live device" signal a real user provides just by
      existing, which some malware waits for before activating.

    Bounded to a fixed split of the window rather than being configurable —
    this is a fixed-purpose detonation aid, not a general fuzzer.

    Also takes the "reaction" screenshot a few seconds after the stimuli,
    not at the arbitrary end of the whole window — a fixed end-of-window
    capture is the worst possible moment: by then a quiet sample has often
    idled back to its home screen, showing nothing useful. Returns that
    screenshot's URL (or None) so the caller can attach it to the outcome.
    """
    # Dismiss any OS-level dialog blocking the app before it ever gets to
    # run its own code (see _dismiss_blocking_dialog's docstring) — done
    # FIRST, before the settle sleep, since a compatibility warning shows up
    # immediately on launch and would otherwise burn the entire window.
    _dismiss_blocking_dialogs()

    settle = min(8, max(1, timeout_s // 4))
    time.sleep(settle)

    try:
        # +91 98765 43210 is India's conventional placeholder mobile number —
        # the same role US "555" numbers play — used ubiquitously in Indian
        # docs/tutorials/examples, so it reads as obviously synthetic rather
        # than a real subscriber number. Deliberately NOT a real bank's
        # DLT-registered sender ID (e.g. "VM-SBIINB"): making the injected
        # stimulus look like an authentic bank text would blur "we triggered
        # this ourselves" into "this looks like a real SMS", which is a
        # deception this project's screenshots must not risk — see the OTP
        # text below, generic for the same reason.
        _adb(["emu", "sms", "send", "+919876543210", "Your OTP code is 482913. Do not share it."], timeout=10)
    except _DynamicVerificationError as e:
        logger.warning(f"[Phase 8] simulated SMS injection failed (non-fatal): {e}")

    try:
        # Coordinates are deliberately generic screen-center-ish points, not
        # targeted at any specific UI element — the point is "a touch event
        # occurred", not interacting with particular app content.
        _adb(["shell", "input", "tap", "540", "1000"], timeout=10)
        time.sleep(0.5)
        _adb(["shell", "input", "tap", "540", "1400"], timeout=10)
    except _DynamicVerificationError as e:
        logger.warning(f"[Phase 8] synthetic tap injection failed (non-fatal): {e}")

    # A permission prompt can appear as a direct result of the stimuli above
    # (e.g. a first SMS-related API call triggering a runtime permission
    # dialog) — one more dismissal pass before the reaction screenshot.
    _dismiss_blocking_dialogs()

    # A few seconds for the app to actually respond (render an overlay,
    # process the SMS, react to the taps) before capturing.
    time.sleep(3)
    reaction_screenshot_url = _capture_screenshot(sha256, tag="reaction")

    elapsed = settle + 3
    remaining = max(0, timeout_s - elapsed)
    # A flat time.sleep(remaining) here used to leave a dialog that appeared
    # AFTER both dismissal passes above sitting untouched for the rest of the
    # window — confirmed live: a runtime "let app always run in background?"
    # permission dialog appeared only after the tap stimuli opened a settings
    # screen, past the last dismissal check, and then blocked every
    # subsequent screenshot (reaction and final looked identical) for the
    # remainder of a real corpus sample's run. Broken into ~5s chunks with a
    # dismissal check between each instead, so a late-appearing dialog still
    # gets cleared well within the window rather than at the very end.
    _DIALOG_CHECK_INTERVAL = 5
    while remaining > 0:
        chunk = min(_DIALOG_CHECK_INTERVAL, remaining)
        time.sleep(chunk)
        remaining -= chunk
        if remaining > 0:
            _dismiss_blocking_dialogs()

    return reaction_screenshot_url


# Event kinds worth an immediate screenshot the moment they fire, rather than
# waiting for the fixed reaction/final captures — these are the ones most
# likely to coincide with an actual visible UI change or a genuinely critical
# single-shot moment: an overlay is drawn on screen, an incoming SMS is read
# (often right as a banking trojan reacts to it), a service binds
# accessibility (sometimes preceded by a permission prompt completing), a
# dynamically-loaded class actually executes (the payload itself firing), the
# app sends an SMS of its own (exfiltration / premium-number abuse), or it
# shells out to run an OS command (Runtime.exec — rare and significant on its
# own). Deliberately excludes high-frequency kinds (network, url_accessed,
# crypto_invoked, file_written, sensitive_content_query, clipboard_read) —
# those can fire dozens of times per second and rarely correlate with a
# visible UI change, so triggering on them would mostly capture screenshot
# noise while adding real latency to every message callback.
_CRUCIAL_SCREENSHOT_KINDS = {
    "sms_intercepted", "overlay_window", "accessibility_bound", "dcl_class_load",
    "sms_send", "command_executed",
}
# One shot per kind (first occurrence only) and a hard cap on the total —
# each capture is a blocking adb screencap+pull (see _capture_screenshot),
# so this bounds how much latency event-triggered capture can add to the
# capture window even if every crucial kind fires immediately. Kept equal to
# len(_CRUCIAL_SCREENSHOT_KINDS): the per-kind dedup already prevents repeat
# captures of the same kind, so this cap should never cut a kind off early —
# it only guards against the set growing later without this being raised too.
_MAX_EVENT_SCREENSHOTS = len(_CRUCIAL_SCREENSHOT_KINDS)


def _collect_events(pid: int, timeout_s: int, sha256: str | None = None) -> tuple[list[dict], str | None]:
    import frida  # imported lazily — frida is only needed on the opt-in dynamic path

    # frida's own device discovery talks to adb through its bundled host-server
    # logic, which reads this same env var — setting it only inside _adb_env()
    # (used for our own subprocess calls) left frida still probing the default
    # port 5037, which is unusable here (Hyper-V reserves it; see adb_server_port's
    # docstring in config.py). Confirmed via live attach failure ("device not
    # found") until this was set process-wide before any frida.* call.
    if settings.adb_server_port:
        os.environ["ANDROID_ADB_SERVER_PORT"] = str(settings.adb_server_port)

    _ensure_frida_server_running()

    if not _AGENT_SCRIPT_PATH.exists():
        raise _DynamicVerificationError(
            f"compiled agent not found at {_AGENT_SCRIPT_PATH} — run `npm install "
            "&& npm run build` in app/analysis/frida_scripts/ (see its README)"
        )
    src = _AGENT_SCRIPT_PATH.read_text(encoding="utf-8")

    try:
        dev = (
            frida.get_device(settings.frida_device_id, timeout=10)
            if settings.frida_device_id
            else frida.get_usb_device(timeout=10)
        )
        session = dev.attach(pid)
    except Exception as e:
        raise _DynamicVerificationError(f"frida could not attach to pid {pid}: {e}") from e

    events: list[dict] = []
    _event_screenshot_kinds_seen: set[str] = set()

    def on_message(message, data):
        if message.get("type") == "send":
            payload = message.get("payload")
            if isinstance(payload, dict):
                events.append(payload)
                kind = payload.get("kind")
                if (
                    kind in _CRUCIAL_SCREENSHOT_KINDS
                    and kind not in _event_screenshot_kinds_seen
                    and len(_event_screenshot_kinds_seen) < _MAX_EVENT_SCREENSHOTS
                ):
                    _event_screenshot_kinds_seen.add(kind)
                    url = _capture_screenshot(sha256, tag=f"event_{kind}")
                    if url:
                        events.append({
                            "kind": "event_screenshot",
                            "value": kind,
                            "url": url,
                            "t": payload.get("t"),
                        })
        elif message.get("type") == "error":
            logger.warning(f"[Phase 8] agent script error: {message.get('description')}")

    crashed = False
    target_died = False
    reaction_screenshot_url: str | None = None
    try:
        script = session.create_script(src)
        script.on("message", on_message)
        script.load()
        reaction_screenshot_url = _run_capture_window_with_stimuli(timeout_s, sha256)
    except Exception as e:
        # The target process can legitimately die between attach() succeeding
        # and the capture window completing — some malware actively detects a
        # rooted/emulated/instrumented environment and self-terminates rather
        # than run, which is itself a real anti-analysis signal. Confirmed
        # live: a real corpus sample produced exactly this ("the connection
        # is closed") mid-capture. Whatever events fired before the crash are
        # still real observed evidence — discarding them because the process
        # later died would throw away exactly the kind of partial coverage
        # this project reports elsewhere (native-symbol/reflection coverage
        # notes) rather than hides. A synthetic event carries the crash fact
        # through to _diff_against_predictions' coverage_note instead of
        # raising, which would drop everything captured so far as ran=False.
        crashed = True
        # Only a frida.Error means the TARGET actually went away. Any other
        # exception here is a fault in our own capture code, and reporting that
        # as "the sample self-terminated" states a forensic conclusion about the
        # malware that was never observed. Confirmed live: a UnicodeDecodeError
        # in _adb (see its encoding= comment) aborted the window on a perfectly
        # healthy process, and the report told the analyst the sample had
        # detected instrumentation and killed itself. Partial events are kept
        # either way — what changes is only what this claims happened.
        target_died = _is_frida_error(e)
        logger.warning(
            f"[Phase 8] capture window ended early for pid {pid} "
            f"({'target exited' if target_died else 'INTERNAL ERROR in capture code'}): {e!r}"
        )
    if crashed:
        events.append({
            "kind": "target_crashed" if target_died else "capture_aborted",
            "value": (
                (
                    f"process exited/crashed mid-capture — possible anti-analysis "
                    f"self-termination, {len(events)} event(s) captured before this point"
                )
                if target_died
                else (
                    f"capture window aborted by an internal error in the analysis "
                    f"harness, not by anything the sample did — "
                    f"{len(events)} event(s) captured before this point are still valid, "
                    f"but coverage is incomplete for a reason unrelated to this APK"
                )
            ),
        })
        crash_logcat = _capture_logcat_tail()
        if crash_logcat:
            events.append({"kind": "crash_logcat", "value": "\n".join(crash_logcat)})
    try:
        session.detach()
    except Exception:
        pass  # process may have already exited during the window — events collected so far still count

    return events, reaction_screenshot_url


def _diff_against_predictions(events: list[dict], static_predictions: dict) -> DynamicVerificationOutcome:
    outcome = DynamicVerificationOutcome(ran=True)

    # Both event kinds carry a contacted endpoint. Only `network` was read
    # here before, which discarded url_accessed entirely — corpus-wide that is
    # ~6x more host observations thrown away than kept, since every HTTP stack
    # that resolves DNS first reports through the URL hook rather than the raw
    # socket one.
    seen_network = {
        e["value"] for e in events
        if e.get("kind") in ("network", "url_accessed") and e.get("value")
    }
    predicted_c2 = set(static_predictions.get("c2_indicators") or [])

    # Compare on normalised hosts, not raw strings. The previous substring test
    # ("telegram_bot:<token>" in "1.2.3.4:443", or the reverse) could not match
    # a static indicator against an observed endpoint even when the host was
    # identical: the static side carries a type prefix, a scheme and often a
    # path, the dynamic side is host:port. Every confirmation was a false
    # negative by construction. See apk_static.c2_host.
    seen_hosts = {
        h for h in (c2_host(v) for v in seen_network if not is_harness_endpoint(v)) if h
    }
    confirmed = {
        predicted for predicted in predicted_c2
        if (h := c2_host(predicted)) and h in seen_hosts
    }
    outcome.network_confirmed = sorted(confirmed)
    outcome.network_predicted_not_seen = sorted(predicted_c2 - confirmed)
    # Harness traffic is not sample behaviour: the AVD's own adbd (10.0.2.x /
    # 0.0.0.0 / 127.0.0.1 on :5555) is reachable from inside the emulator and
    # was being recorded as attacker infrastructure the app contacted.
    outcome.network_observed_all = sorted(
        v for v in seen_network if not is_harness_endpoint(v)
    )

    outcome.sms_api_invoked = any(e.get("kind") == "sms_send" for e in events)
    outcome.sms_destinations = sorted({e["value"] for e in events if e.get("kind") == "sms_send" and e.get("value")})

    loaded_classes = sorted({e["value"] for e in events if e.get("kind") == "dcl_class_load" and e.get("value")})
    outcome.dcl_classes_loaded = loaded_classes
    predicted_dcl = set(static_predictions.get("dcl_targets") or [])
    outcome.dcl_payload_executed = bool(loaded_classes) and (
        not predicted_dcl
        or any(any(p in c or c in p for c in loaded_classes) for p in predicted_dcl)
    )

    outcome.accessibility_bound = any(e.get("kind") == "accessibility_bound" for e in events)
    outcome.accessibility_services = sorted({e["value"] for e in events if e.get("kind") == "accessibility_bound" and e.get("value")})
    outcome.crypto_invoked = any(e.get("kind") == "crypto_invoked" for e in events)
    outcome.crypto_algorithms = sorted({e["value"] for e in events if e.get("kind") == "crypto_invoked" and e.get("value")})
    outcome.crypto_outputs = [
        {"algorithm": e.get("algorithm", ""), "preview": e.get("value", "")}
        for e in events if e.get("kind") == "crypto_output"
    ]
    outcome.crypto_modes_observed = sorted({e["value"] for e in events if e.get("kind") == "crypto_mode" and e.get("value")})

    loaded_libs = sorted({e["value"] for e in events if e.get("kind") == "native_library_loaded" and e.get("value")})
    outcome.native_libraries_loaded = loaded_libs
    predicted_native = set(static_predictions.get("native_targets") or [])
    # Same substring-containment approach as dcl_payload_executed above: the
    # predicted side is native_bridge.py's describe() string (e.g.
    # 'System.loadLibrary("foo") -> libfoo.so ...'), which always contains
    # the bare library name our hook reports, just wrapped in extra text.
    outcome.native_library_confirmed = bool(loaded_libs) and (
        not predicted_native
        or any(any(p in lib or lib in p for lib in loaded_libs) for p in predicted_native)
    )

    outcome.urls_accessed = sorted({e["value"] for e in events if e.get("kind") == "url_accessed" and e.get("value")})
    outcome.files_written = sorted({e["value"] for e in events if e.get("kind") == "file_written" and e.get("value")})
    outcome.commands_executed = sorted({e["value"] for e in events if e.get("kind") == "command_executed" and e.get("value")})

    outcome.sms_intercepted = sorted({e["value"] for e in events if e.get("kind") == "sms_intercepted" and e.get("value")})

    overlay_events = [e for e in events if e.get("kind") == "overlay_window"]
    outcome.overlay_detected = bool(overlay_events)
    outcome.overlay_window_types = sorted({e["value"] for e in overlay_events if e.get("value")})

    outcome.sensitive_content_queries = sorted({
        e["value"] for e in events if e.get("kind") == "sensitive_content_query" and e.get("value")
    })
    outcome.clipboard_read = any(e.get("kind") == "clipboard_read" for e in events)

    # Screenshots taken the moment a crucial event fired (see
    # _CRUCIAL_SCREENSHOT_KINDS) — "value" carries which event kind triggered
    # the capture, "url" the resulting screenshot. Complements the fixed
    # reaction/final screenshots with ones tied to an actual observed cause.
    outcome.event_screenshots = [
        {"kind": e.get("value"), "url": e.get("url"), "t": e.get("t", 0)}
        for e in events if e.get("kind") == "event_screenshot" and e.get("url")
    ]

    crash_logcat_events = [e["value"] for e in events if e.get("kind") == "crash_logcat" and e.get("value")]
    outcome.crash_logcat_tail = crash_logcat_events[0].splitlines() if crash_logcat_events else []

    # Full timeline — every event already carries `t` (ms since agent load)
    # from hooks.js; surface it sorted rather than only the deduplicated
    # per-kind sets above, which lose ordering entirely. crash_logcat is
    # excluded: it's a multi-line log dump, not a compact timeline row — it
    # has its own dedicated field (crash_logcat_tail) instead.
    outcome.timeline = sorted(
        (
            {"t": e.get("t", 0), "kind": e.get("kind"), "value": e.get("value")}
            for e in events if e.get("kind") not in ("hook_installed", "ready", "crash_logcat")
        ),
        key=lambda e: e["t"],
    )

    hook_errors = [e["value"] for e in events if e.get("kind") == "hook_error"]
    # Both kinds must reach the coverage note — they describe the same coverage
    # gap and differ only in cause (the sample vs. our own harness).
    crash_events = [
        e["value"] for e in events
        if e.get("kind") in ("target_crashed", "capture_aborted")
    ]

    summary: dict[str, int] = {}
    for e in events:
        kind = e.get("kind")
        if kind:
            summary[kind] = summary.get(kind, 0) + 1
    outcome.event_summary = summary

    coverage_parts = [f"{len(events)} events observed over the run window"]
    if hook_errors:
        coverage_parts.append(f"{len(hook_errors)} hook(s) failed to install: {'; '.join(hook_errors)}")
    if crash_events:
        coverage_parts.append(crash_events[0])
    outcome.coverage_note = "; ".join(coverage_parts)
    return outcome


_SCREENSHOT_DIR = Path(__file__).parent.parent / "static" / "screenshots"


def _capture_screenshot(sha256: str | None, tag: str = "final") -> str | None:
    """
    One `adb shell screencap`. `tag` distinguishes multiple captures for the
    same sample within one run (see _run_capture_window_with_stimuli) — a
    screenshot taken at a fixed, arbitrary end-of-window moment is the worst
    time to take it: by then a quiet sample has often idled back to a blank
    home screen, showing nothing useful. "reaction" is taken shortly after
    the SMS/tap stimuli fire, while the app is most likely actually doing
    something; "final" is the end-of-window shot kept for a before/after
    comparison, not as the primary capture.

    Best-effort: any failure returns None rather than raising, since a
    missing screenshot is a minor coverage gap, not a reason to fail the
    whole pass. Saved under app/static/ (already mounted by main.py) so the
    frontend can reference it directly as a URL without a new serving route.
    """
    if not sha256:
        return None
    try:
        _SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)
        device_path = "/sdcard/guardgraph_capture.png"
        _adb(["shell", "screencap", "-p", device_path], timeout=15)
        local_path = _SCREENSHOT_DIR / f"{sha256}_{tag}.png"
        cmd = [settings.adb_path]
        if settings.adb_device_serial:
            cmd += ["-s", settings.adb_device_serial]
        cmd += ["pull", device_path, str(local_path)]
        result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=20, env=_adb_env())
        if result.returncode != 0 or not local_path.exists():
            logger.warning(f"[Phase 8] screenshot pull ({tag}) failed: {result.stderr.strip()}")
            return None
        return f"/static/screenshots/{sha256}_{tag}.png"
    except Exception as e:
        logger.warning(f"[Phase 8] screenshot capture ({tag}) failed (non-fatal): {e}")
        return None


def _clear_logcat() -> None:
    """
    Best-effort. Called once at the start of each run so a later
    _capture_logcat_tail() call is scoped to THIS sample's own output, not
    leftover history from whatever ran on the AVD before it.
    """
    try:
        _adb(["logcat", "-c"], timeout=10)
    except _DynamicVerificationError as e:
        logger.warning(f"[Phase 8] logcat clear failed (non-fatal): {e}")


def _capture_logcat_tail(lines: int = 50) -> list[str]:
    """
    Best-effort, called only when the target process crashes mid-capture (see
    _collect_events) — substantiates the "possible anti-analysis
    self-termination" inference in coverage_note with the actual
    exception/reason instead of leaving it as a guess purely from the Frida
    session disconnecting. A crash that turns out to be an unrelated app bug
    rather than anti-analysis evasion is exactly the kind of thing this
    should let an analyst catch instead of trusting the inference blindly.
    """
    try:
        out = _adb(["logcat", "-d", "-t", str(lines)], timeout=15)
        return [line for line in out.splitlines() if line.strip()]
    except Exception as e:
        logger.warning(f"[Phase 8] logcat capture failed (non-fatal): {e}")
        return []


def run_dynamic_verification(
    apk_path: str,
    package_name: str | None,
    static_predictions: dict,
    timeout_s: int | None = None,
    sha256: str | None = None,
) -> dict:
    """
    static_predictions: {"c2_indicators": [...], "dcl_targets": [...],
    "native_targets": [...], "intent_actions": [...]} — pass
    ingestion.c2_indicators, the resolved DCL target paths (see
    dcl_tracing.py), the resolved native-bridge describe() strings (see
    native_bridge.py) and ingestion.intent_actions, all already computed by
    the earlier static phases. This function does not re-derive predictions;
    it only diffs against what it's given (native_targets, dcl_targets) or
    uses it to activate a headless sample (intent_actions — see
    _broadcast_declared_actions).

    Never raises — see module docstring for the fail-closed contract. Also
    see the module docstring's CONTAINMENT section: this refuses to install
    the APK at all unless the AVD's egress currently measures as blocked —
    see settings.dynamic_analysis_require_network_isolation to understand
    (not to casually disable) that gate.
    """
    if not package_name:
        return DynamicVerificationOutcome(
            ran=False, coverage_note="no package name resolved — cannot install/launch"
        ).to_dict()

    timeout_s = timeout_s or settings.dynamic_analysis_timeout_seconds
    start = time.time()
    installed = False
    installed_path = apk_path
    try:
        # First, before anything that talks to a device — including the egress
        # probe below, which needs one to measure and fails closed without it.
        _ensure_device_booted()
        if settings.dynamic_analysis_require_network_isolation and not _egress_appears_blocked():
            raise _DynamicVerificationError(
                "AVD egress does not measure as blocked (a real TCP connection to a public "
                "IP succeeded) — refusing to install an untrusted APK on a network-reachable "
                "device. Apply the host firewall rule in app/analysis/frida_scripts/README.md, "
                "or set DYNAMIC_ANALYSIS_REQUIRE_NETWORK_ISOLATION=false only if you have "
                "verified isolation some other way."
            )
        installed_path = _install(apk_path, package_name)
        installed = True
        _clear_logcat()
        _grant_overlay_permission(package_name)
        launch_fallback_used = False
        try:
            _launch(package_name)
        except _DynamicVerificationError as e:
            # No launcher activity is common for pure background/receiver-only
            # malware (see _broadcast_declared_actions' docstring) — fall back
            # to activating it via its own declared broadcast actions instead
            # of letting this abort the whole pass with ran=False.
            launch_fallback_used = True
            # Ladder, cheapest and most faithful first: an explicit component
            # start is far closer to a normal launch than a synthetic broadcast,
            # so it is tried before falling back to one.
            started_via = _start_declared_components(
                package_name,
                static_predictions.get("activities"),
                static_predictions.get("services"),
            )
            if started_via:
                logger.warning(
                    f"[Phase 8] launcher start failed ({e}); started explicitly via {started_via}"
                )
            else:
                logger.warning(
                    f"[Phase 8] launcher start failed ({e}) and no declared component "
                    "started; falling back to declared-action broadcasts"
                )
                _broadcast_declared_actions(package_name, static_predictions.get("intent_actions"))
        pid = _find_pid(package_name)
        events, reaction_screenshot_url = _collect_events(pid, timeout_s, sha256)
        outcome = _diff_against_predictions(events, static_predictions)
        outcome.duration_s = time.time() - start
        outcome.screenshot_reaction_url = reaction_screenshot_url
        outcome.screenshot_url = _capture_screenshot(sha256, tag="final")
        if launch_fallback_used:
            outcome.coverage_note = (
                f"app declares no launcher activity (a common way to hide the icon) — "
                f"activated via {started_via} instead of a launcher start; "
                if started_via else
                "app has no launcher activity and no declared component would start — "
                "activated via its own declared broadcast-receiver actions instead; "
            ) + (
                "findings below still reflect this sample's real runtime behavior. "
            ) + outcome.coverage_note
        if installed_path != apk_path:
            # Analyst-facing honesty: the DEX/manifest/behavior observed below
            # came from THIS sample, but its own signature was missing/corrupt
            # (already flagged separately by cert_anomalies) and had to be
            # replaced with a throwaway debug key to get past `pm install`'s
            # hard signature requirement — see _resign_apk.
            outcome.coverage_note = (
                "installed after re-signing with a throwaway debug key (original signature "
                "missing/invalid — see cert_anomalies); dynamic findings below reflect this "
                "sample's own DEX/behavior, not the replaced signing block. "
            ) + outcome.coverage_note
        return outcome.to_dict()
    except _DynamicVerificationError as e:
        logger.warning(f"[Phase 8] verification pass aborted: {e}")
        return DynamicVerificationOutcome(
            ran=False, duration_s=time.time() - start, coverage_note=str(e)
        ).to_dict()
    except Exception as e:  # last-resort guard — a dynamic pass must never crash the pipeline
        logger.error(f"[Phase 8] unexpected failure: {e}")
        return DynamicVerificationOutcome(
            ran=False, duration_s=time.time() - start, coverage_note=f"unexpected error: {e}"
        ).to_dict()
    finally:
        if installed:
            _teardown(package_name)
        if installed_path != apk_path and os.path.exists(installed_path):
            try:
                os.unlink(installed_path)
            except OSError as e:
                logger.warning(f"[Phase 8] could not clean up re-signed temp copy: {e}")
