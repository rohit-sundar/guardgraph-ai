"""
Forensic dictionary + anchor detection + 4-hop subgraph extraction.

This is a STARTER dictionary, not exhaustive. Extend FORENSIC_DICTIONARY
as you validate against real samples in your demo set — the paper's list
is a reasonable v1 but banking-fraud-specific indicators will grow as you
test.
"""
import networkx as nx

FORENSIC_DICTIONARY = {
    "STEALTH_SMS_INTERCEPTION": {
        "apis": ["Landroid/telephony/SmsManager;->sendTextMessage"],
        "permissions": ["android.permission.READ_SMS", "android.permission.RECEIVE_SMS"],
    },
    "OTP_INTERCEPTION": {
        "apis": [],
        "permissions": ["android.permission.READ_SMS", "android.permission.RECEIVE_SMS"],
        "strings": ["otp", "one time password", "verification code"],
    },
    "DYNAMIC_REFLECTION": {
        "apis": ["Ljava/lang/reflect/Method;->invoke"],
        "permissions": [],
    },
    "CRYPTOGRAPHY_USAGE": {
        "apis": ["Ljavax/crypto/Cipher;->doFinal"],
        "permissions": [],
    },
    "CREDENTIAL_HARVESTING": {
        "apis": [
            "Landroid/webkit/WebView;->loadUrl",
            "Landroid/view/accessibility/AccessibilityService",
        ],
        "permissions": ["android.permission.BIND_ACCESSIBILITY_SERVICE"],
        "strings": ["login", "password", "bank"],
    },
    "C2_BEHAVIOR": {
        "apis": ["Ljava/net/HttpURLConnection;->connect"],
        "permissions": [],
        "strings": ["http://", "https://"],  # refine: flag non-standard TLDs / raw IPs specifically
    },
}


def match_anchors(g: nx.DiGraph) -> dict[str, list[str]]:
    """
    Scans every node's ACFG metadata against the forensic dictionary.
    Returns dict of behavior_flag -> list of matching node_ids (anchors).
    """
    matches: dict[str, list[str]] = {}

    for node_id, data in g.nodes(data=True):
        api_calls = data.get("api_calls", [])
        string_literals = data.get("string_literals", [])

        for behavior, rules in FORENSIC_DICTIONARY.items():
            hit = False

            for api_pattern in rules.get("apis", []):
                if any(api_pattern in call for call in api_calls):
                    hit = True

            for s in rules.get("strings", []):
                if any(s.lower() in lit.lower() for lit in string_literals):
                    hit = True

            if hit:
                matches.setdefault(behavior, []).append(node_id)

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
