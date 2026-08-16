"""
Regression tests for T1 — const-string literal extraction.

`cfg.py` parsed const-string operands assuming Androguard wraps literals in
SINGLE quotes. Androguard 4.1.2 — the pinned version — wraps them in DOUBLE
quotes, so the only literals that survived the test were ones whose *text*
contained an apostrophe, and those were then split on that apostrophe:

    "t set content description via JB-MR2 API\\""
    "t fetch getDisplayList method; dimming won"

Every extracted string was a mangled fragment of an English error message.
Consequences, all of which these tests exist to prevent recurring:

  * `compute_string_pool_entropy` received [] or garbage, so
    obfuscation_component — 15% of the risk score — was effectively dead.
  * OTP_INTERCEPTION (apis=0, strings=3) and DYNAMIC_CODE_LOADING
    (apis=0, strings=5) are string-only forensic rules and could never fire on
    their own evidence. OTP interception is the project's central claim.
  * merge_c2_from_strings ran its C2 regexes over an empty list, so DEX-derived
    IoCs were never found.

Both parse sites had to change together: is_method_relevant() gates which
methods reach enrich_acfg at all, so fixing only the enrichment site leaves the
pre-filter blind to string-only relevance and the matched-behavior set unchanged.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.analysis.cfg import parse_const_string, enrich_acfg, is_method_relevant


# ── the parser itself ────────────────────────────────────────────────────────

def test_double_quoted_literal_is_extracted():
    """Androguard 4.1.x format — the case that was broken in production."""
    assert parse_const_string('v4, "sendTextMessage"') == "sendTextMessage"
    assert parse_const_string('v2, "*"') == "*"
    assert parse_const_string('v4, " "') == " "


def test_single_quoted_literal_still_works():
    """Older Androguard builds emit single quotes; the fix must not swap one bug for another."""
    assert parse_const_string("v2, 'getDeviceId'") == "getDeviceId"


def test_apostrophe_inside_a_double_quoted_literal_is_text_not_a_delimiter():
    """
    The exact corruption seen in the wild: splitting on an embedded apostrophe
    returned "t fetch getDisplayList method; dimming won" instead of the string.
    """
    assert parse_const_string('v1, "can\'t fetch getDisplayList method"') == "can't fetch getDisplayList method"


def test_empty_literal_is_an_empty_string_not_none():
    """'' is a real literal. None means 'no literal here' and must stay distinct."""
    assert parse_const_string('v3, ""') == ""


def test_operand_without_a_literal_returns_none():
    assert parse_const_string("v0, 5") is None
    assert parse_const_string("") is None


# ── both call sites ──────────────────────────────────────────────────────────

class _FakeInstruction:
    def __init__(self, name: str, output: str):
        self._name, self._output = name, output

    def get_name(self) -> str:
        return self._name

    def get_output(self) -> str:
        return self._output


class _FakeBlock:
    def __init__(self, instructions, start=0, end=1):
        self._instructions, self.start, self.end = instructions, start, end
        self.childs = []

    def get_instructions(self):
        return self._instructions


class _FakeBlocks:
    def __init__(self, blocks):
        self._blocks = blocks

    def get(self):
        return self._blocks


class _FakeMethod:
    def __init__(self, instructions):
        self._blocks = _FakeBlocks([_FakeBlock(instructions)])

    def get_basic_blocks(self):
        return self._blocks

    def get_method(self):
        return "Lcom/test/Fake;->method()V"


def test_enrich_acfg_collects_double_quoted_strings():
    import networkx as nx

    method = _FakeMethod([
        _FakeInstruction("const-string", 'v0, "android/telephony/SmsManager"'),
        _FakeInstruction("const-string", 'v1, "otp"'),
        _FakeInstruction("invoke-virtual", "v2, Landroid/telephony/SmsManager;->sendTextMessage"),
    ])
    g = nx.DiGraph()
    g.add_node("0")
    enrich_acfg(g, method)

    assert g.nodes["0"]["string_literals"] == ["android/telephony/SmsManager", "otp"]
    assert len(g.nodes["0"]["api_calls"]) == 1


def test_is_method_relevant_selects_on_string_only_evidence():
    """
    A method whose sole relevance is a dictionary *string* must be selected for
    CFG construction. While this site was broken, string-only forensic rules
    could not fire even after the enrichment site was fixed.
    """
    method = _FakeMethod([_FakeInstruction("const-string", 'v0, "verification code"')])

    assert is_method_relevant(method, frozenset(), frozenset({"verification code"})) is True
    assert is_method_relevant(method, frozenset(), frozenset({"unrelated string"})) is False


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
