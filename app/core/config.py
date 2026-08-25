"""
Central config. Loads from .env. Nothing here should be hardcoded secrets.

LLM backend: Ollama running locally (http://localhost:11434).
To use a different model, set OLLAMA_MODEL in .env.

FAMILY_TO_TTPS is a deliberate bridge: the v1 classifier outputs malware-family
labels, but ttp_severity_component expects MITRE technique IDs. Without this
mapping that scoring component is silently dead (always returns DEFAULT). This is
an honest proxy until per-technique binary classifiers are trained — see §9.2.
"""
import os

from pydantic_settings import BaseSettings, SettingsConfigDict


def _default_build_tools_dir() -> str:
    """
    Best-effort locate the newest installed build-tools directory (holds
    apksigner/zipalign, needed to re-sign a malware sample whose own
    signature is missing/corrupt before it can be installed on the AVD —
    Android's package manager refuses to install anything unsigned, and
    plenty of real-world malware samples arrive that way).
    """
    sdk_root = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    if not sdk_root:
        return ""
    build_tools_root = os.path.join(sdk_root, "build-tools")
    if not os.path.isdir(build_tools_root):
        return ""
    versions = sorted(os.listdir(build_tools_root))
    return os.path.join(build_tools_root, versions[-1]) if versions else ""


def _default_keytool_path() -> str:
    """
    `keytool` is NOT reliably on PATH even when `java` is: on this dev
    machine PATH only carries a slim javapath shim (java.exe/javaw.exe), not
    the full JDK bin directory — confirmed live (`keytool: command not
    found` despite `java -version` working fine). JAVA_HOME, when set,
    points at the real JDK bin/ which does carry it.
    """
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        candidate = os.path.join(java_home, "bin", "keytool.exe")
        if os.path.exists(candidate):
            return candidate
        candidate = os.path.join(java_home, "bin", "keytool")
        if os.path.exists(candidate):
            return candidate
    return "keytool"


def _default_adb_path() -> str:
    """
    Best-effort locate adb.exe under ANDROID_HOME/ANDROID_SDK_ROOT, since it is
    not reliably on PATH (confirmed on the dev machine: the PATH entry pointed
    one directory short of the real binary). Falls back to the bare command
    name, which still works if adb genuinely is on PATH.
    """
    sdk_root = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    if sdk_root:
        candidate = os.path.join(sdk_root, "platform-tools", "adb.exe")
        if os.path.exists(candidate):
            return candidate
        candidate = os.path.join(sdk_root, "platform-tools", "adb")
        if os.path.exists(candidate):
            return candidate
    return "adb"


def _default_emulator_path() -> str:
    """
    Best-effort locate the AVD launcher under ANDROID_HOME/ANDROID_SDK_ROOT,
    mirroring _default_adb_path. `emulator` is even less reliably on PATH than
    adb — the SDK ships it in its own `emulator/` directory rather than
    `platform-tools/`, and it must be invoked from there (it resolves its
    qemu binaries and system images relative to its own location).
    """
    sdk_root = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    if sdk_root:
        for name in ("emulator.exe", "emulator"):
            candidate = os.path.join(sdk_root, "emulator", name)
            if os.path.exists(candidate):
                return candidate
    return "emulator"


class Settings(BaseSettings):
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "changeme"

    # Local LLM via Ollama (OpenAI-compatible endpoint)
    ollama_base_url: str = "http://localhost:11434/v1"
    ollama_model: str = "qwen2.5:7b-instruct-q4_K_M"

    model_path: str = "data/models/guardgraph_xgb_v1.json"
    samples_dir: str = "data/samples"

    # Signature detection & YARA scanning
    signature_db_path: str = "data/signatures/known_hashes.json"
    yara_rules_dir: str = "data/yara_rules"
    virustotal_api_key: str = ""
    malwarebazaar_api_key: str = ""

    # Master switch for the two third-party reputation lookups in
    # app/analysis/signatures.py. Both public tiers are metered — VirusTotal
    # allows 4 requests/min and 500/day, and MalwareBazaar now rejects every
    # unauthenticated request with HTTP 401. Nothing on the /analyze path can
    # breach either limit: _run_analysis() is synchronous inside async def, so
    # requests serialise at one analysis per 60-200 s, and lookup_signature()
    # answers repeat uploads from Neo4j before Phase 1.5 ever runs.
    # scripts/score_corpus.py is the only caller that can, which is why it
    # turns this OFF by default and paces itself behind --online.
    online_lookups_enabled: bool = True

    entropy_high_threshold: float = 7.2
    flattening_degree_outlier_zscore: float = 3.0

    # ── Dynamic verification (Phase 8) ──────────────────────────────────────
    # Off by default — this must never block a normal /analyze request, since
    # it needs a booted AVD (see app/analysis/frida_scripts/README.md's
    # go/no-go setup notes) and takes tens of seconds. Opt-in per request via
    # /analyze's `enable_dynamic` query param, gated additionally on this
    # master switch so a misconfigured deployment can't accidentally expose
    # emulator-dependent behavior on a request path with no AVD behind it.
    dynamic_analysis_enabled: bool = False
    dynamic_analysis_timeout_seconds: int = 30
    # Refuse to install an APK unless a live probe measures the AVD's egress as
    # blocked (see dynamic_verification._egress_appears_blocked). True by
    # default — this is a safety gate, not a convenience switch; only set
    # false if you have verified isolation some other way (e.g. a host
    # firewall rule already scopes the emulator process, or you deliberately
    # want to observe traffic against a controlled honeypot).
    dynamic_analysis_require_network_isolation: bool = True
    # adb's default port 5037 is unusable on a machine where Hyper-V has
    # reserved it in a dynamic port-exclusion range (confirmed via `netsh int
    # ipv4 show excludedportrange protocol=tcp` on the dev machine — 5037 fell
    # inside 4939-5038). Override per-machine in .env if 5039 collides there
    # too; `emulator/dynamic_verification.py` sets ANDROID_ADB_SERVER_PORT
    # from this for every adb invocation rather than trusting the default.
    adb_server_port: int = 5039
    adb_path: str = _default_adb_path()
    # ── AVD auto-boot ───────────────────────────────────────────────────────
    # A booted AVD used to be a hard precondition a human had to satisfy by
    # hand before every dynamic run. With this on, Phase 8 boots the AVD
    # itself when no device is attached, so `enable_dynamic=true` is all a
    # request needs. Set false to keep the old behaviour (fail fast with a
    # coverage note instead of spending a minute booting) — e.g. on CI, or
    # where the AVD is managed by something else.
    dynamic_analysis_auto_boot: bool = True
    # Which AVD to boot. Empty = auto-select, but ONLY when exactly one AVD
    # exists; with several installed, Phase 8 refuses and names them rather
    # than guessing. Guessing is genuinely unsafe here: a `google_apis_
    # playstore` image looks identical in `-list-avds` but is Play-signed and
    # silently blocks Frida from injecting, which would surface as a confusing
    # "could not attach" much later. Name the `google_apis` one explicitly.
    avd_name: str = ""
    emulator_path: str = _default_emulator_path()
    # swiftshader_indirect (software rendering) is the safe default: hardware
    # GPU passthrough is the usual cause of an emulator that hangs or dies on
    # boot, and nothing in this pipeline needs GPU speed — the screenshots are
    # flat 2D UI. Set "host" for a faster boot on a machine with a known-good GPU.
    emulator_gpu_mode: str = "swiftshader_indirect"
    # Cold-booting an AVD is slow and varies hugely by machine (~20s on the dev
    # machine's WHPX-accelerated x86_64 image, several minutes on an unaccelerated
    # or ARM-translated one). Generous by default so a slow first boot reports a
    # real result rather than a spurious timeout.
    avd_boot_timeout_seconds: int = 300
    # None = whichever single USB/emulator device Frida finds (frida.get_usb_device).
    # Set explicitly (e.g. "emulator-5554") once more than one AVD/device could
    # be attached, so a stray second instance can't silently steal the target.
    adb_device_serial: str = ""
    frida_device_id: str = ""
    # frida-server has proven flaky in this feature's own live testing —
    # confirmed dying between runs multiple times — so dynamic_verification.py
    # self-heals it (checks + restarts + re-forwards) rather than requiring a
    # human to notice and run manual adb commands every time. This is where
    # it must already be PUSHED (one-time manual setup, see
    # app/analysis/frida_scripts/README.md) — self-healing only covers it not
    # currently running, not it never having been installed on the device.
    frida_server_device_path: str = "/data/local/tmp/frida-server"
    frida_local_port: int = 27042
    # apksigner/zipalign dir, for re-signing a sample whose own signature is
    # missing/corrupt (common in malware-feed downloads) before install — see
    # dynamic_verification._resign_apk. Empty string disables the fallback
    # entirely; install then just fails closed as before on such a sample.
    android_build_tools_dir: str = _default_build_tools_dir()
    # Where the throwaway debug keystore used ONLY for that re-sign step is
    # cached (generated once, reused after). This key has no relationship to
    # the sample's real identity — it exists purely so Android's package
    # manager has *a* valid signature to install against; nothing about
    # provenance or authorship is asserted by it.
    dynamic_resign_keystore_path: str = "data/dynamic/debug_resign.jks"
    java_keytool_path: str = _default_keytool_path()

    # Hard ceiling on the Phase 7 (GraphRAG) prompt, in approximate tokens.
    # Set against the OBSERVED 16,386 tokens Ollama actually evaluated for
    # qwen2.5:7b-instruct before truncating — not the nominal 32,768 context,
    # which is never what the model receives in practice.
    graphrag_prompt_token_budget: int = 15000

    # Fixed decode seed for the GraphRAG LLM call. temperature=0 alone does not
    # guarantee reproducible output — batch scheduling and KV-cache reuse can
    # still perturb the decode between identical calls. Ollama honours `seed`,
    # so pin it rather than relying on greedy decoding alone.
    graphrag_seed: int = 42

    # Penalizes tokens already used in the completion so far, applied to logits
    # BEFORE the greedy argmax pick — still fully deterministic given the same
    # seed and history, unlike temperature/top_p which reintroduce sampling.
    # Ollama's default (1.1) was not enough to stop a live-observed degenerate
    # loop: qwen2.5:7b-instruct-q4_K_M repeated "API Coverage Component Weighted
    # Score: 1234567890" for most of a 2000-token completion budget rather than
    # writing the report (2026-08-23). Raised until that stops recurring.
    graphrag_repeat_penalty: float = 1.3

    # How long Ollama should keep the model resident after a request. Measured:
    # the FIRST large prefill after a model load decodes differently from every
    # later one, so an idle unload (Ollama's default is 5m) silently makes the
    # next analysis the odd one out. Hold the model resident across a normal
    # working session instead. Only the native /api/chat endpoint honours this —
    # the OpenAI-compatible /v1 endpoint accepts and ignores it.
    graphrag_keep_alive: str = "30m"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()

# MUST match the label order your XGBoost model was trained on.
# Update this the moment training finishes tonight — index order matters,
# XGBoost has no idea what index 3 "means", it just returns index 3.
MODEL_LABEL_MAP = [
    "banker",
    "trojan",
    "password_stealer",
    "coinminer",
    "rat",
    "keylogger",
]

# MITRE ATT&CK Mobile TTP severity weights used in risk scoring.
# Per-technique overrides (checked first). Tune against real analyst judgment.
TTP_SEVERITY_WEIGHTS = {
    "T1636": 0.9,   # Protected User Data (SMS)
    "T1624": 0.8,   # Event Triggered Execution
    "T1417": 0.85,  # Input Capture
    "T1409": 0.6,   # Stored Application Data
    "T1471": 0.95,  # Data Encrypted for Impact
    "DEFAULT": 0.5,
}

# Tactic-derived severity fallback so EVERY predicted Mobile technique gets a
# principled severity (not DEFAULT) — used by ttp_severity_component when a
# technique is not in TTP_SEVERITY_WEIGHTS. Keyed by ATT&CK Mobile tactic display
# name (see app/ml/labels.TECHNIQUE_TACTIC). Higher = more fraud/impact relevant.
TACTIC_SEVERITY = {
    "Impact": 0.95,
    "Credential Access": 0.90,
    "Collection": 0.85,
    "Exfiltration": 0.85,
    "Privilege Escalation": 0.70,
    "Command and Control": 0.70,
    "Persistence": 0.65,
    "Initial Access": 0.60,
    "Defense Evasion": 0.60,
    "Execution": 0.55,
    "Discovery": 0.40,
    "Lateral Movement": 0.55,
}

# LEGACY / hot-path only. The cold path now predicts techniques DIRECTLY via the
# multi-label TTPClassifier (app/ml/classifier.py) instead of this family→TTP proxy.
# Kept for the hot path and as a fallback for the untrained-family case; do not use
# it to derive cold-path predicted_ttps anymore (§9.2 superseded by the TTP model).
FAMILY_TO_TTPS: dict[str, list[str]] = {
    "banker":           ["T1636", "T1417", "T1624"],  # SMS harvest, input capture, persistence
    "trojan":           ["T1624", "T1409"],            # persistence, stored data
    "password_stealer": ["T1417", "T1409"],            # input capture, stored data
    "coinminer":        ["T1624"],                     # persistence (autostart)
    "rat":              ["T1417", "T1636", "T1624"],  # input capture, SMS, persistence
    "keylogger":        ["T1417"],                     # input capture
}
