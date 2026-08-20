"""
Forensic dictionary + anchor detection + 4-hop subgraph extraction.

This is a STARTER dictionary, not exhaustive. Extend FORENSIC_DICTIONARY
as you validate against real samples in your demo set — the paper's list
is a reasonable v1 but banking-fraud-specific indicators will grow as you
test.

N1: every rule used to be a flat OR over `apis` + `strings`, and the `permissions`
key was declared but never read. Any single bare substring anywhere in the app was
therefore enough to fire a behavior, and measured against the 220-app F-Droid corpus
that made the dictionary an anti-classifier: benign apps fired 3.91 behaviors on
average against malware's 3.73. ACCESSIBILITY_ABUSE hit 207/220 clean apps because
AndroidX references AccessibilityNodeInfo in every app that bundles it; "otp"
matched "hotpink" and "notPlaced"; "password" matched Compose's "isPassword=false"
semantics string. forensic_anchor_component is 15% of the deterministic score and
cannot learn its way out of a bad rule, so precision matters more here than recall.

Two mechanisms replace the flat OR:

  * a manifest **gate** (`declares`) — a behavior the app never declared the
    capability for cannot fire. Measured on the corpus, declaring an accessibility
    service splits 7/220 benign from 75/133 malware, and an SMS permission splits
    5/220 from 81/133. This is the change that does most of the work.
  * **clauses** — a rule is a list of alternatives, and every populated key within
    one alternative must hit *in the same method*. That is how "a WebView call near
    a credential string" is expressed without also firing on either alone.
"""
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

import networkx as nx

from app.analysis.apk_static import ACCESSIBILITY_SERVICE_ACTION

# ── shared vocabularies ───────────────────────────────────────────────────────
# Named so the gates read as capability declarations rather than magic lists.

SMS_PERMISSIONS = [
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_MMS",
    "android.permission.RECEIVE_WAP_PUSH",
]

SMS_INTENT_ACTIONS = [
    "android.provider.Telephony.SMS_RECEIVED",
    "android.provider.Telephony.SMS_DELIVER",
]

# An accessibility trojan declares the *service*, not a <uses-permission>: the
# permission is what the system holds over the service, so it appears as the
# service's android:permission attribute. Gating on <uses-permission> alone
# catches 6/133 malware; gating on the service's intent-filter action catches 75.
# The action string is owned by apk_static, which reads the manifest — the same
# declaration now also gates accessibility config parsing and the ACCESSIBILITY_*
# permission-matrix flags (N5), and one restated copy would be one too many.
ACCESSIBILITY_INTENT_ACTIONS = [ACCESSIBILITY_SERVICE_ACTION]

# Endpoints specific enough to stand as C2 evidence on their own. Bare http(s)://
# and Ljava/net/HttpURLConnection;->connect are deliberately absent — "this app
# makes an HTTP request" is a capability, not an anchor. Exact IoCs are extracted
# separately by apk_static.extract_c2_indicators and scored via ioc_component.
C2_ENDPOINT_STRINGS = [
    "api.telegram.org/bot",
    "firebaseio.com",
    "firebaseapp.com",
    "discord.com/api/webhooks",
    "discordapp.com/api/webhooks",
    ".onion",
    "gate.php",
    "/panel/",
]

# Shapes of data worth exfiltrating. Only ever used *with* a network API in the
# same method — none of them is specific enough to stand alone.
EXFIL_HINT_STRINGS = [
    "bot_token", "chat_id", "gate.php", "/panel/", "screencap", "keylog",
    "phish", "grabber", "cvv", "card_number", "seed phrase", "mnemonic",
    "imei", "sim_serial", "device_info", "exfil",
]

NETWORK_APIS = [
    "Ljava/net/HttpURLConnection;->connect",
    "Ljava/net/URL;->openConnection",
]

# Delimited forms only. Bare "otp" matched hotpink / notPlaced / adSlotPath in
# 25 of 30 clean apps sampled, which is what put OTP_INTERCEPTION on 156/220.
OTP_STRINGS = [
    "otp_code", "otpcode", "otp code", "otp_id", "otpid", "smsotp", "otp sms",
    "sendotp", "getotp", "enter otp", "one time password", "one-time password",
    "onetimepassword", "verification code", "verificationcode", "sms code",
    "2fa code",
]

SMS_READ_APIS = [
    "Landroid/telephony/SmsMessage;->getMessageBody",
    "Landroid/telephony/SmsMessage;->createFromPdu",
]

LOADER_APIS = [
    "Ldalvik/system/DexClassLoader",
    "Ldalvik/system/InMemoryDexClassLoader",
    "Ldalvik/system/PathClassLoader",
]

LOADER_STRINGS = [
    "dexclassloader", "pathclassloader", "inmemorydexclassloader",
    "opendexfile", "dalvik.system.dexclassloader",
]


# ── the dictionary ────────────────────────────────────────────────────────────
#
# Rule shape:
#   "declares":  optional manifest gate, any-of. The app must declare at least one
#                listed permission or intent action or the behavior cannot fire.
#   "clauses":   any-of. Within one clause every populated key must hit in the SAME
#                method — that is what makes a clause corroborating evidence rather
#                than a second OR branch.
#   "permissions" under "declares" is the old inert key, now actually consumed.

FORENSIC_DICTIONARY: dict[str, dict[str, Any]] = {
    "STEALTH_SMS_INTERCEPTION": {
        "declares": {"permissions": SMS_PERMISSIONS, "intent_actions": SMS_INTENT_ACTIONS},
        "clauses": [
            {"apis": [
                "Landroid/telephony/SmsManager;->sendTextMessage",
                "Landroid/telephony/SmsMessage;->createFromPdu",
                "Landroid/telephony/SmsMessage;->getMessageBody",
                "Landroid/telephony/gsm/SmsMessage",
            ]},
        ],
    },
    "OTP_INTERCEPTION": {
        "declares": {"permissions": SMS_PERMISSIONS, "intent_actions": SMS_INTENT_ACTIONS},
        "clauses": [
            {"strings": OTP_STRINGS},
            # Reading SMS bodies next to any credential-ish word is the same
            # behavior spelled without the word "OTP".
            {"apis": SMS_READ_APIS,
             "strings": ["otp", "code", "verify", "bank", "login", "password"]},
        ],
    },
    "DYNAMIC_REFLECTION": {
        # Method;->invoke alone fired on 45/45 clean apps — Gson, Retrofit and
        # Kotlin's own runtime all reflect. What separates evasion from plumbing is
        # breaking visibility, or reflecting into code that was loaded at runtime.
        # This remains the weakest anchor in the table (1.7x lift); it is kept
        # because dropping it would change the frozen 35/181 feature contracts.
        "clauses": [
            {"apis": ["Ljava/lang/reflect/Method;->setAccessible",
                      "Ljava/lang/reflect/Field;->setAccessible"]},
            {"apis": ["Ljava/lang/reflect/Method;->invoke"], "strings": LOADER_STRINGS},
        ],
    },
    "CRYPTOGRAPHY_USAGE": {
        "clauses": [{"apis": ["Ljavax/crypto/Cipher;->doFinal"]}],
    },
    "CREDENTIAL_HARVESTING": {
        "clauses": [
            # A WebView reachable from credential strings — the overlay/phishing
            # pattern. loadUrl alone was 7/45 benign; requiring the string in the
            # same method takes the pair to 1/45 while keeping 16/41 malware.
            {"apis": ["Landroid/webkit/WebView;->loadUrl",
                      "Landroid/webkit/WebView;->addJavascriptInterface",
                      "Landroid/webkit/WebView;->evaluateJavascript"],
             "strings": ["login", "password", "bank", "card_number", "cvv",
                         "phish", "grabber", "inject"]},
            # Strings with no benign reading at all — no API needed.
            {"strings": ["keylog", "phish", "grabber", "cvv", "card_number",
                         "seed phrase", "mnemonic"]},
        ],
    },
    "C2_BEHAVIOR": {
        "clauses": [
            {"strings": C2_ENDPOINT_STRINGS},
            {"apis": NETWORK_APIS, "strings": EXFIL_HINT_STRINGS},
        ],
    },
    "DYNAMIC_CODE_LOADING": {
        "clauses": [
            {"apis": LOADER_APIS},
            {"strings": LOADER_STRINGS},
        ],
    },
    "ACCESSIBILITY_ABUSE": {
        "declares": {
            "permissions": ["android.permission.BIND_ACCESSIBILITY_SERVICE"],
            "intent_actions": ACCESSIBILITY_INTENT_ACTIONS,
        },
        "clauses": [
            {"apis": ["Landroid/accessibilityservice/AccessibilityService",
                      "Landroid/view/accessibility/AccessibilityNodeInfo",
                      "AccessibilityEvent;->getText"]},
            {"strings": ["onaccessibilityevent", "canretrievewindowcontent",
                         "typeallmasks", "performglobalaction", "dispatchgesture"]},
        ],
    },
}


@dataclass(frozen=True)
class ManifestContext:
    """
    The manifest-level capability declarations the gates read.

    Passed explicitly rather than defaulted so a new call site cannot silently
    disable every gated rule: match_anchors takes it as a required argument.
    """

    permissions: frozenset[str] = frozenset()
    intent_actions: frozenset[str] = frozenset()

    @classmethod
    def from_ingestion(cls, ingestion: Any) -> "ManifestContext":
        return cls(
            permissions=frozenset(getattr(ingestion, "permissions", ()) or ()),
            intent_actions=frozenset(getattr(ingestion, "intent_actions", ()) or ()),
        )

    @classmethod
    def empty(cls) -> "ManifestContext":
        """An app that declared nothing — no gated behavior can fire."""
        return cls()

    def declares(self, gate: Mapping[str, Iterable[str]]) -> bool:
        return bool(
            self.permissions.intersection(gate.get("permissions", ()))
            or self.intent_actions.intersection(gate.get("intent_actions", ()))
        )


def relevance_vocabulary() -> tuple[frozenset[str], frozenset[str]]:
    """
    (api substrings, lowercased string substrings) mentioned anywhere in the
    dictionary — the superset cfg.is_method_relevant pre-filters on.

    A method matching none of these cannot satisfy any clause, so skipping it is
    free of false negatives. Being a superset is the whole contract: it may admit
    methods that go on to match nothing.
    """
    apis: set[str] = set()
    strings: set[str] = set()
    for rules in FORENSIC_DICTIONARY.values():
        for clause in rules["clauses"]:
            apis.update(clause.get("apis", ()))
            strings.update(s.lower() for s in clause.get("strings", ()))
    return frozenset(apis), frozenset(strings)


def _clause_hits(
    clause: Mapping[str, Iterable[str]],
    api_calls: Iterable[str],
    string_literals: Iterable[str],
) -> tuple[bool, set[str], set[str]]:
    """
    Evaluate one clause against one method's evidence.

    Returns (satisfied, matched_api_patterns, matched_string_patterns). Every
    populated key must contribute at least one hit — an absent key is not a
    constraint, so {"apis": [...]} means "this API, no string required".
    """
    api_patterns = list(clause.get("apis", ()))
    string_patterns = list(clause.get("strings", ()))

    matched_apis = {p for p in api_patterns if any(p in call for call in api_calls)}
    lowered = [lit.lower() for lit in string_literals]
    matched_strings = {
        p for p in string_patterns if any(p.lower() in lit for lit in lowered)
    }

    satisfied = (not api_patterns or bool(matched_apis)) and (
        not string_patterns or bool(matched_strings)
    )
    return satisfied, matched_apis, matched_strings


def match_anchors(g: nx.DiGraph, manifest: ManifestContext) -> dict[str, list[str]]:
    """
    Scans one method's ACFG against the forensic dictionary.
    Returns dict of behavior_flag -> list of matching node_ids (anchors).

    `manifest` carries the app-level declarations the `declares` gates read; pass
    ManifestContext.empty() only when the manifest genuinely could not be parsed,
    since that suppresses every gated behavior.

    Clause evaluation is per *method* (this whole graph), not per node: the API call
    and the string literal that corroborate each other are routinely in different
    basic blocks of the same method. Anchors are then the nodes that actually carry
    the evidence, so the 4-hop subgraph is still extracted around real hits.
    """
    node_api_calls = {n: d.get("api_calls", []) for n, d in g.nodes(data=True)}
    node_strings = {n: d.get("string_literals", []) for n, d in g.nodes(data=True)}
    method_apis = [c for calls in node_api_calls.values() for c in calls]
    method_strings = [s for lits in node_strings.values() for s in lits]

    matches: dict[str, list[str]] = {}

    for behavior, rules in FORENSIC_DICTIONARY.items():
        gate = rules.get("declares")
        if gate and not manifest.declares(gate):
            continue

        anchors: list[str] = []
        for clause in rules["clauses"]:
            satisfied, hit_apis, hit_strings = _clause_hits(
                clause, method_apis, method_strings
            )
            if not satisfied:
                continue
            # Attribute the hit to every node holding part of the evidence, so the
            # 4-hop subgraph is still extracted around a real instruction.
            for node_id in g.nodes:
                carries = any(
                    p in call for p in hit_apis for call in node_api_calls[node_id]
                ) or any(
                    p.lower() in lit.lower()
                    for p in hit_strings
                    for lit in node_strings[node_id]
                )
                if carries and node_id not in anchors:
                    anchors.append(node_id)

        if anchors:
            matches[behavior] = anchors

    return matches


def extract_anchor_subgraph(g: nx.DiGraph, anchor_node: str, hops: int = 4) -> nx.DiGraph:
    """
    Extracts the induced subgraph of all nodes within `hops` forward or
    backward of the anchor node. Matches the paper's "exactly four hops"
    spec.
    """
    if anchor_node not in g:
        return nx.DiGraph()

    undirected = g.to_undirected()
    nearby = nx.single_source_shortest_path_length(undirected, anchor_node, cutoff=hops)
    node_set = set(nearby.keys())

    return g.subgraph(node_set).copy()
