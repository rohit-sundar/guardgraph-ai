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
BEHAVIOR_FEATURES = [
    "STEALTH_SMS_INTERCEPTION",
    "OTP_INTERCEPTION",
    "DYNAMIC_REFLECTION",
    "CRYPTOGRAPHY_USAGE",
    "CREDENTIAL_HARVESTING",
    "C2_BEHAVIOR",
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
