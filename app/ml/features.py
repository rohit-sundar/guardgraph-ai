"""
SINGLE SOURCE OF TRUTH for feature vector schema.

Your overnight training script and this inference module MUST produce
vectors in this exact order. XGBoost has no concept of column names at
inference time (unless you pass a DataFrame with matching column names
consistently) — a silent order mismatch produces confident, wrong
predictions with no error. If you change this file, retrain.

Import FEATURE_NAMES from here in your training script too, don't
redefine it there.
"""

# Permission flags — extend this list to match whatever permission set
# your CICMalDroid2020 preprocessing settled on. Keep alphabetical for sanity.
PERMISSION_FEATURES = [
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
]

# Behavior flags from the forensic dictionary — one binary feature per
# behavior category (was this behavior observed anywhere in the app).
#
# This list must cover FORENSIC_DICTIONARY in full. DYNAMIC_CODE_LOADING and
# ACCESSIBILITY_ABUSE were matched by Phase 3 and weighted in BEHAVIOR_SEVERITY
# (0.70 and 0.90) but reached neither feature vector, so the second-highest
# behavior weight in the table — and the single most characteristic
# banking-trojan signal — could be scored and reported yet never influence a
# prediction. Adding them moves FEATURE_NAMES 33 -> 35 and TTP_FEATURE_NAMES
# 179 -> 181; both are frozen contracts, so any change here requires a full
# dataset rebuild and retrain, not just a retrain.
BEHAVIOR_FEATURES = [
    "STEALTH_SMS_INTERCEPTION",
    "OTP_INTERCEPTION",
    "DYNAMIC_REFLECTION",
    "CRYPTOGRAPHY_USAGE",
    "CREDENTIAL_HARVESTING",
    "C2_BEHAVIOR",
    "DYNAMIC_CODE_LOADING",
    "ACCESSIBILITY_ABUSE",
]

# Topological stats — must match keys produced by topology.py exactly.
TOPOLOGY_FEATURES = [
    f"{metric}_{stat}"
    for metric in ["degree_centrality", "closeness_centrality", "clustering_coefficient"]
    for stat in ["mean", "std", "median", "min", "max"]
]

# Obfuscation signal features
OBFUSCATION_FEATURES = [
    "string_entropy_score",
    "flattening_suspected",
    "reflection_call_count",
]

# Signature detection & YARA scanning features.
# Added for Phase 1.5 integration — these capture detection-layer signals
# that the ML model can learn from alongside structural/behavioral features.
SIGNATURE_YARA_FEATURES = [
    "signature_match_count",    # number of hash/cert signature hits
    "yara_rule_match_count",    # number of YARA rules triggered
    "yara_max_severity",        # highest severity across YARA matches (0.0-1.0)
]

FEATURE_NAMES = (
    PERMISSION_FEATURES + BEHAVIOR_FEATURES + TOPOLOGY_FEATURES
    + OBFUSCATION_FEATURES + SIGNATURE_YARA_FEATURES
)


def build_feature_vector(
    permissions: list[str],
    matched_behaviors: set[str],
    topological_invariants: dict[str, float],
    obfuscation_entropy: float,
    obfuscation_flattening: bool,
    obfuscation_reflection_count: int,
    signature_match_count: int = 0,
    yara_rule_match_count: int = 0,
    yara_max_severity: float = 0.0,
) -> list[float]:
    """
    Builds a feature vector in FEATURE_NAMES order. Returns a plain list —
    caller wraps in np.array()/DataFrame as needed for the model.
    """
    vec = []

    for perm in PERMISSION_FEATURES:
        vec.append(1.0 if perm in permissions else 0.0)

    for behavior in BEHAVIOR_FEATURES:
        vec.append(1.0 if behavior in matched_behaviors else 0.0)

    for feat_name in TOPOLOGY_FEATURES:
        vec.append(float(topological_invariants.get(feat_name, 0.0)))

    vec.append(float(obfuscation_entropy))
    vec.append(1.0 if obfuscation_flattening else 0.0)
    vec.append(float(obfuscation_reflection_count))

    # Signature & YARA features
    vec.append(float(signature_match_count))
    vec.append(float(yara_rule_match_count))
    vec.append(float(yara_max_severity))

    assert len(vec) == len(FEATURE_NAMES), (
        f"Feature vector length {len(vec)} != FEATURE_NAMES length {len(FEATURE_NAMES)}. "
        "Schema drift — fix before running inference."
    )

    return vec


# ══════════════════════════════════════════════════════════════════════════
# MULTI-LABEL TTP MODEL FEATURE SCHEMA (additive — see app/ml/labels.py)
#
# This is a SEPARATE, larger feature vector used ONLY by the multi-label MITRE
# ATT&CK Mobile TTP classifier (TTPClassifier in classifier.py). It fuses:
#   • DroidTTP-style broad manifest binary presence vocab (permissions / intents /
#     sensitive APIs / component counts), and
#   • GUARD graph-invariant topology aggregated across ALL anchor subgraphs.
#
# The 33-feature `FEATURE_NAMES` / `build_feature_vector` above and the family
# model are NOT affected — this block is purely additive. `TTP_FEATURE_NAMES` is
# its own frozen contract; changing it requires retraining the TTP model.
# ══════════════════════════════════════════════════════════════════════════

# Broad permission vocabulary (DroidTTP-style binary presence). Curated toward
# banking-fraud / spyware capability. Full "android.permission.*" strings.
TTP_PERMISSION_VOCAB = [
    "android.permission.INTERNET",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.ACCESS_WIFI_STATE",
    "android.permission.CHANGE_WIFI_STATE",
    "android.permission.CHANGE_NETWORK_STATE",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.WRITE_SMS",
    "android.permission.RECEIVE_MMS",
    "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.BROADCAST_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.GET_ACCOUNTS",
    "android.permission.MANAGE_ACCOUNTS",
    "android.permission.AUTHENTICATE_ACCOUNTS",
    "android.permission.USE_CREDENTIALS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.CALL_PHONE",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.ANSWER_PHONE_CALLS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAPTURE_AUDIO_OUTPUT",
    "android.permission.MODIFY_AUDIO_SETTINGS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
    "android.permission.BIND_VPN_SERVICE",
    "android.permission.BIND_INPUT_METHOD",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.REQUEST_DELETE_PACKAGES",
    "android.permission.INSTALL_PACKAGES",
    "android.permission.DELETE_PACKAGES",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.GET_TASKS",
    "android.permission.REORDER_TASKS",
    "android.permission.KILL_BACKGROUND_PROCESSES",
    "android.permission.RESTART_PACKAGES",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.WAKE_LOCK",
    "android.permission.FOREGROUND_SERVICE",
    "android.permission.DISABLE_KEYGUARD",
    "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    "android.permission.WRITE_SETTINGS",
    "android.permission.WRITE_SECURE_SETTINGS",
    "android.permission.CHANGE_CONFIGURATION",
    "android.permission.BLUETOOTH",
    "android.permission.BLUETOOTH_ADMIN",
    "android.permission.NFC",
    "android.permission.VIBRATE",
    "android.permission.FLASHLIGHT",
    "android.permission.EXPAND_STATUS_BAR",
    "android.permission.STATUS_BAR",
    "android.permission.READ_LOGS",
    "android.permission.DUMP",
    "android.permission.MOUNT_UNMOUNT_FILESYSTEMS",
    "android.permission.BROADCAST_STICKY",
    "android.permission.CLEAR_APP_CACHE",
    "android.permission.USE_FINGERPRINT",
    "android.permission.USE_BIOMETRIC",
    "android.permission.SET_WALLPAPER",
    "android.permission.INSTALL_SHORTCUT",
    "android.permission.UNINSTALL_SHORTCUT",
    "android.permission.PACKAGE_USAGE_STATS",
    "android.permission.MASTER_CLEAR",
    "android.permission.REBOOT",
    "android.permission.WRITE_APN_SETTINGS",
    "android.permission.CONTROL_LOCATION_UPDATES",
    "android.permission.ACCESS_LOCATION_EXTRA_COMMANDS",
    "android.permission.SEND_RESPOND_VIA_MESSAGE",
    "android.permission.RECEIVE_USER_PRESENT",
    "android.permission.INTERACT_ACROSS_USERS",
    "android.permission.READ_PRIVILEGED_PHONE_STATE",
    "android.permission.MANAGE_OWN_CALLS",
    "android.permission.READ_HISTORY_BOOKMARKS",
    "android.permission.WRITE_HISTORY_BOOKMARKS",
    "android.permission.SUBSCRIBED_FEEDS_READ",
]

# Common intent-filter actions abused by malware (binary presence over the app's
# declared intent actions). Full action strings.
TTP_INTENT_VOCAB = [
    "android.intent.action.BOOT_COMPLETED",
    "android.intent.action.QUICKBOOT_POWERON",
    "android.provider.Telephony.SMS_RECEIVED",
    "android.provider.Telephony.SMS_DELIVER",
    "android.provider.Telephony.WAP_PUSH_RECEIVED",
    "android.provider.Telephony.SECRET_CODE",
    "android.intent.action.PHONE_STATE",
    "android.intent.action.NEW_OUTGOING_CALL",
    "android.intent.action.USER_PRESENT",
    "android.intent.action.SCREEN_ON",
    "android.intent.action.SCREEN_OFF",
    "android.intent.action.PACKAGE_ADDED",
    "android.intent.action.PACKAGE_REMOVED",
    "android.intent.action.PACKAGE_REPLACED",
    "android.intent.action.MY_PACKAGE_REPLACED",
    "android.net.conn.CONNECTIVITY_CHANGE",
    "android.intent.action.BATTERY_CHANGED",
    "android.intent.action.BATTERY_LOW",
    "android.intent.action.ACTION_POWER_CONNECTED",
    "android.intent.action.ACTION_POWER_DISCONNECTED",
    "android.app.action.DEVICE_ADMIN_ENABLED",
    "android.intent.action.MEDIA_MOUNTED",
    "android.intent.action.LOCALE_CHANGED",
    "android.intent.action.DREAMING_STARTED",
    "android.intent.action.INPUT_METHOD_CHANGED",
]

# Sensitive API-call substrings (Smali-form). Binary presence, matched against the
# set of API calls observed anywhere in the app's CFGs.
TTP_SENSITIVE_API_VOCAB = [
    "SmsManager;->sendTextMessage",
    "SmsManager;->sendMultipartTextMessage",
    "SmsManager;->getDefault",
    "TelephonyManager;->getDeviceId",
    "TelephonyManager;->getSubscriberId",
    "TelephonyManager;->getSimSerialNumber",
    "TelephonyManager;->getLine1Number",
    "TelephonyManager;->getNetworkOperator",
    "TelephonyManager;->listen",
    "Ljava/lang/reflect/Method;->invoke",
    "Ljava/lang/Class;->forName",
    "Ljava/lang/reflect/Constructor;->newInstance",
    "Ldalvik/system/DexClassLoader",
    "Ldalvik/system/PathClassLoader",
    "Ldalvik/system/BaseDexClassLoader",
    "Ljavax/crypto/Cipher;->doFinal",
    "Ljavax/crypto/Cipher;->getInstance",
    "Ljavax/crypto/spec/SecretKeySpec",
    "Ljava/security/MessageDigest;->digest",
    "Landroid/util/Base64;->decode",
    "Landroid/util/Base64;->encode",
    "Ljava/net/HttpURLConnection;->connect",
    "Ljava/net/URL;->openConnection",
    "Ljava/net/Socket;-><init>",
    "Landroid/webkit/WebView;->loadUrl",
    "Landroid/webkit/WebView;->addJavascriptInterface",
    "Landroid/view/accessibility/AccessibilityNodeInfo",
    "Landroid/app/admin/DevicePolicyManager;->lockNow",
    "Landroid/app/admin/DevicePolicyManager;->resetPassword",
    "Ljava/lang/Runtime;->exec",
    "Landroid/content/pm/PackageManager;->getInstalledPackages",
    "Landroid/provider/Settings$Secure;->getString",
]

# Component-count features (cheap structural signal; malware often over-declares
# receivers/services). Kept as raw (capped) counts — trees handle scale fine.
TTP_COMPONENT_FEATURES = [
    "num_activities",
    "num_services",
    "num_receivers",
]

# Full TTP feature contract. Reuses the family model's BEHAVIOR / TOPOLOGY /
# OBFUSCATION / SIGNATURE_YARA blocks (identical semantics) so the two schemas
# stay consistent where they overlap.
TTP_FEATURE_NAMES = (
    TTP_PERMISSION_VOCAB
    + TTP_INTENT_VOCAB
    + TTP_SENSITIVE_API_VOCAB
    + TTP_COMPONENT_FEATURES
    + BEHAVIOR_FEATURES
    + TOPOLOGY_FEATURES
    + OBFUSCATION_FEATURES
    + SIGNATURE_YARA_FEATURES
)

_COMPONENT_COUNT_CAP = 50.0  # cap component counts so a pathological app can't dominate


def build_ttp_feature_vector(
    permissions: list[str],
    intent_actions: list[str] | None = None,
    api_calls=None,
    num_activities: int = 0,
    num_services: int = 0,
    num_receivers: int = 0,
    matched_behaviors: set[str] | None = None,
    topological_invariants: dict[str, float] | None = None,
    obfuscation_entropy: float = 0.0,
    obfuscation_flattening: bool = False,
    obfuscation_reflection_count: int = 0,
    signature_match_count: int = 0,
    yara_rule_match_count: int = 0,
    yara_max_severity: float = 0.0,
) -> list[float]:
    """
    Builds the multi-label TTP feature vector in TTP_FEATURE_NAMES order.

    `api_calls` is any iterable of API-call strings observed across the app's CFGs
    (used for sensitive-API presence). `topological_invariants` should be the
    GUARD stats AGGREGATED across all anchor subgraphs
    (topology.aggregate_subgraph_invariants), not a single subgraph.

    Both the dataset builder and inference MUST call this same function so training
    and inference feature columns line up exactly.
    """
    intent_actions = intent_actions or []
    matched_behaviors = matched_behaviors or set()
    topological_invariants = topological_invariants or {}
    perm_set = set(permissions)
    intent_set = set(intent_actions)
    api_list = list(api_calls) if api_calls is not None else []

    vec: list[float] = []

    for perm in TTP_PERMISSION_VOCAB:
        vec.append(1.0 if perm in perm_set else 0.0)

    for action in TTP_INTENT_VOCAB:
        vec.append(1.0 if action in intent_set else 0.0)

    for api_sub in TTP_SENSITIVE_API_VOCAB:
        vec.append(1.0 if any(api_sub in call for call in api_list) else 0.0)

    vec.append(min(float(num_activities), _COMPONENT_COUNT_CAP))
    vec.append(min(float(num_services), _COMPONENT_COUNT_CAP))
    vec.append(min(float(num_receivers), _COMPONENT_COUNT_CAP))

    for behavior in BEHAVIOR_FEATURES:
        vec.append(1.0 if behavior in matched_behaviors else 0.0)

    for feat_name in TOPOLOGY_FEATURES:
        vec.append(float(topological_invariants.get(feat_name, 0.0)))

    vec.append(float(obfuscation_entropy))
    vec.append(1.0 if obfuscation_flattening else 0.0)
    vec.append(float(obfuscation_reflection_count))

    vec.append(float(signature_match_count))
    vec.append(float(yara_rule_match_count))
    vec.append(float(yara_max_severity))

    assert len(vec) == len(TTP_FEATURE_NAMES), (
        f"TTP feature vector length {len(vec)} != TTP_FEATURE_NAMES length "
        f"{len(TTP_FEATURE_NAMES)}. Schema drift — fix before running inference."
    )

    return vec
