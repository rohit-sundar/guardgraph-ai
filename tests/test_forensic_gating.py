"""
Regression tests for N1 — the forensic dictionary over-matching clean apps.

Before this change every rule was a flat OR over `apis` + `strings`, and the
`permissions` key was never read. One bare substring anywhere in the app fired a
behavior, so measured against the 220-app F-Droid benign corpus the dictionary ran
backwards: clean apps fired 3.91 behaviors on average, malware 3.73. The specific
accidents these tests pin down were all observed in that corpus:

  * "otp" matched `hotpink`, `notPlaced`, `adSlotPath` — 25 of 30 sampled clean apps
  * "password" matched Compose's `isPassword=false` semantics string — 45/45
  * `Landroid/view/accessibility/AccessibilityNodeInfo` matched every app that
    bundles AndroidX — 45/45, which is why ACCESSIBILITY_ABUSE hit 207/220 benign

`forensic_anchor_component` is 15% of the deterministic score and has no ability to
learn its way out of a bad rule, so the fix is structural: a manifest gate plus
clause-level corroboration.
"""
import os
import sys

import networkx as nx

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.analysis.forensic import (
    FORENSIC_DICTIONARY,
    ManifestContext,
    match_anchors,
    relevance_vocabulary,
)

A11Y_ACTION = "android.accessibilityservice.AccessibilityService"
A11Y_API = "Landroid/view/accessibility/AccessibilityNodeInfo;->getText()"


def _method(*blocks: tuple[list[str], list[str]]) -> nx.DiGraph:
    """
    A method CFG from (api_calls, string_literals) per basic block, wired as a
    straight line. Multiple blocks exist so tests can place corroborating evidence
    in *different* blocks of the same method.
    """
    g = nx.DiGraph()
    for i, (apis, strings) in enumerate(blocks):
        g.add_node(str(i), api_calls=list(apis), string_literals=list(strings))
        if i:
            g.add_edge(str(i - 1), str(i))
    return g


# ── the manifest gate ────────────────────────────────────────────────────────

def test_accessibility_apis_alone_do_not_fire_on_an_undeclared_app():
    """
    The 207/220 case. AndroidX references AccessibilityNodeInfo in every app that
    bundles it, so the API is evidence of a dependency, not of a capability.
    """
    g = _method(([A11Y_API], []))
    assert "ACCESSIBILITY_ABUSE" not in match_anchors(g, ManifestContext.empty())


def test_accessibility_fires_once_the_service_is_declared():
    """
    Same evidence, app declares the service. On the corpus this gate separates
    7/220 benign from 75/133 malware — it keeps the malware recall intact.
    """
    g = _method(([A11Y_API], []))
    declared = ManifestContext(intent_actions=frozenset({A11Y_ACTION}))
    assert "ACCESSIBILITY_ABUSE" in match_anchors(g, declared)


def test_uses_permission_also_opens_the_accessibility_gate():
    """Either half of the gate is enough — a rule's gate is any-of."""
    g = _method(([A11Y_API], []))
    declared = ManifestContext(
        permissions=frozenset({"android.permission.BIND_ACCESSIBILITY_SERVICE"})
    )
    assert "ACCESSIBILITY_ABUSE" in match_anchors(g, declared)


def test_sms_behaviors_need_an_sms_declaration():
    g = _method((["Landroid/telephony/SmsManager;->sendTextMessage(...)"], []))
    assert "STEALTH_SMS_INTERCEPTION" not in match_anchors(g, ManifestContext.empty())

    declared = ManifestContext(permissions=frozenset({"android.permission.SEND_SMS"}))
    assert "STEALTH_SMS_INTERCEPTION" in match_anchors(g, declared)


def test_ungated_behaviors_still_fire_without_a_manifest():
    """Only rules carrying a `declares` key are gated; the rest are unaffected."""
    g = _method(([], ["dalvik.system.DexClassLoader"]))
    assert "DYNAMIC_CODE_LOADING" in match_anchors(g, ManifestContext.empty())


# ── the specific substring accidents ─────────────────────────────────────────

def test_otp_does_not_match_hotpink():
    """
    `hotpink`, `notPlaced` and `adSlotPath` all contain "otp". With the SMS gate
    open, only a delimited OTP form may fire.
    """
    declared = ManifestContext(permissions=frozenset({"android.permission.READ_SMS"}))
    noise = _method(([], ["hotpink", "isNotPlaced", "adSlotPath", "dotplus"]))
    assert "OTP_INTERCEPTION" not in match_anchors(noise, declared)

    real = _method(([], ["Enter OTP code"]))
    assert "OTP_INTERCEPTION" in match_anchors(real, declared)


def test_compose_semantics_string_does_not_fire_credential_harvesting():
    """
    ", isPassword=false, offsetMapping=" is a Compose TextField toString fragment
    present in every app using Compose. A credential word needs a WebView in the
    same method before it counts.
    """
    g = _method(([], [", isPassword=false, offsetMapping="]))
    assert "CREDENTIAL_HARVESTING" not in match_anchors(g, ManifestContext.empty())


def test_reflection_needs_more_than_a_bare_invoke():
    """`Method;->invoke` fired on 45/45 sampled clean apps — Gson and Retrofit reflect."""
    g = _method((["Ljava/lang/reflect/Method;->invoke(...)"], []))
    assert "DYNAMIC_REFLECTION" not in match_anchors(g, ManifestContext.empty())

    breaks_visibility = _method((["Ljava/lang/reflect/Field;->setAccessible(...)"], []))
    assert "DYNAMIC_REFLECTION" in match_anchors(breaks_visibility, ManifestContext.empty())


def test_bare_http_connect_is_not_c2_evidence():
    """A network call is a capability. C2 needs an endpoint or an exfil shape."""
    g = _method((["Ljava/net/HttpURLConnection;->connect()"], []))
    assert "C2_BEHAVIOR" not in match_anchors(g, ManifestContext.empty())

    endpoint = _method(([], ["https://api.telegram.org/bot123/sendMessage"]))
    assert "C2_BEHAVIOR" in match_anchors(endpoint, ManifestContext.empty())


# ── clause semantics ─────────────────────────────────────────────────────────

def test_clause_requires_every_populated_key():
    """A WebView alone, or a credential string alone, is not credential harvesting."""
    empty = ManifestContext.empty()
    api_only = _method((["Landroid/webkit/WebView;->loadUrl(...)"], []))
    assert "CREDENTIAL_HARVESTING" not in match_anchors(api_only, empty)

    string_only = _method(([], ["please enter your bank login"]))
    assert "CREDENTIAL_HARVESTING" not in match_anchors(string_only, empty)


def test_clause_evidence_may_span_basic_blocks_of_one_method():
    """
    Corroboration is per method, not per basic block: the `loadUrl` call and the
    string it loads are routinely in different blocks. Matching per node would make
    the api+string clauses nearly unsatisfiable.
    """
    g = _method(
        ([], ["https://example.test/bank/login"]),
        (["Landroid/webkit/WebView;->loadUrl(...)"], []),
    )
    assert "CREDENTIAL_HARVESTING" in match_anchors(g, ManifestContext.empty())


def test_anchors_point_at_the_nodes_carrying_the_evidence():
    """
    The anchor node ids feed extract_anchor_subgraph, so they have to be the blocks
    that actually hold the hit — not every node in the method.
    """
    g = _method(
        ([], ["nothing interesting here"]),
        ([], ["dalvik.system.DexClassLoader"]),
        ([], ["also nothing"]),
    )
    assert match_anchors(g, ManifestContext.empty())["DYNAMIC_CODE_LOADING"] == ["1"]


# ── the pre-filter contract ──────────────────────────────────────────────────

def test_relevance_vocabulary_covers_every_clause_pattern():
    """
    cfg.is_method_relevant() skips methods matching none of this vocabulary, so a
    pattern missing from it becomes an unreachable rule — a silent false negative
    rather than a test failure. Assert the superset property directly.
    """
    apis, strings = relevance_vocabulary()
    for behavior, rules in FORENSIC_DICTIONARY.items():
        for clause in rules["clauses"]:
            for pattern in clause.get("apis", ()):
                assert pattern in apis, f"{behavior}: api {pattern!r} missing"
            for pattern in clause.get("strings", ()):
                assert pattern.lower() in strings, f"{behavior}: string {pattern!r} missing"


def test_every_rule_declares_at_least_one_clause():
    for behavior, rules in FORENSIC_DICTIONARY.items():
        assert rules.get("clauses"), f"{behavior} has no clauses and can never fire"
        for clause in rules["clauses"]:
            assert clause.get("apis") or clause.get("strings"), (
                f"{behavior} has an empty clause, which would fire on every method"
            )


def test_gated_rules_name_a_reachable_declaration():
    for behavior, rules in FORENSIC_DICTIONARY.items():
        gate = rules.get("declares")
        if gate is None:
            continue
        assert gate.get("permissions") or gate.get("intent_actions"), (
            f"{behavior} has an empty gate, which suppresses it permanently"
        )
