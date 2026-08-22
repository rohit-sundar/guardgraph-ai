"""
Regression tests for N9 — the two scoring components that returned a MEAN.

`ttp_severity_component` and `forensic_anchor_component` both averaged the severities
of what the analysis found, which made each component fall as the evidence grew. The
whole 196-test suite passed both before and after the fix, because nothing pinned the
one property that was actually broken: **more proven evidence must never lower a
component**. That invariant is what these tests pin.

They deliberately assert monotonicity and direction, not exact values. The saturation
constants are calibration (re-derive with `python scripts/measure_saturation.py`) and
are expected to move; the invariant is not.

Measured shape of the bug, over data/ttp_dataset.csv (220 benign / 144 malware):

  ttp_severity (mean)     benign max 0.941 > malware max 0.810 — the single
                          highest-scoring sample in the corpus was CLEAN, because
                          one severe technique averages to its own severity while
                          eight average to the middle of the scale.
  forensic_anchor (mean)  benign p95 0.800 vs malware p50 0.767 — separation of
                          -0.033. The component discriminated backwards.

Fully offline — no model, no Neo4j, no Ollama, no APK fixtures.
"""
import itertools

import pytest

from app.reports.scoring import (
    BEHAVIOR_SEVERITY,
    forensic_anchor_component,
    ttp_severity_component,
)

# Ordered most- to least-severe so a prefix of length n is the n most severe anchors.
ANCHORS_BY_SEVERITY = [
    b for b, _ in sorted(BEHAVIOR_SEVERITY.items(), key=lambda kv: -kv[1])
]

# Five real Discovery techniques — the corroborating evidence that used to *cost*
# a sample points when it appeared alongside a high-severity technique.
DISCOVERY = ["T1418", "T1422", "T1424", "T1426", "T1430"]
IMPACT = "T1471"  # Data Encrypted for Impact, severity 0.95


# ── ttp_severity_component ────────────────────────────────────────────────────

def test_ttp_severity_never_falls_when_a_technique_is_added():
    """The invariant. Adding a predicted technique cannot lower the component."""
    predicted = {IMPACT: 0.9}
    previous = ttp_severity_component(predicted)
    for technique in DISCOVERY:
        predicted[technique] = 0.9
        current = ttp_severity_component(predicted)
        assert current >= previous, (
            f"adding {technique} lowered the component {previous:.4f} -> {current:.4f}"
        )
        previous = current


def test_ttp_severity_rises_with_corroborating_techniques():
    """
    The exact regression that opened N9: one severe technique used to score 0.855 and
    the same technique plus five corroborating ones scored 0.510.
    """
    alone = ttp_severity_component({IMPACT: 0.9})
    corroborated = ttp_severity_component({IMPACT: 0.9, **{t: 0.9 for t in DISCOVERY}})
    assert corroborated > alone


def test_ttp_severity_rises_with_probability():
    """Monotone in confidence as well as in breadth."""
    values = [ttp_severity_component({IMPACT: p}) for p in (0.1, 0.3, 0.5, 0.7, 0.9)]
    assert values == sorted(values)


def test_ttp_severity_weighs_severe_techniques_above_trivial_ones():
    """A single Impact technique must outscore a single Discovery one at equal confidence."""
    assert ttp_severity_component({IMPACT: 0.9}) > ttp_severity_component({"T1418": 0.9})


def test_ttp_severity_stays_in_range_under_absurd_input():
    assert ttp_severity_component({}) == 0.0
    saturated = ttp_severity_component({f"T{1400 + i}": 1.0 for i in range(60)})
    assert 0.0 <= saturated <= 1.0


# ── forensic_anchor_component ─────────────────────────────────────────────────

def test_anchor_component_never_falls_when_a_behavior_is_added():
    """The invariant, walking severe-first so each addition is strictly weaker."""
    previous = 0.0
    for n in range(1, len(ANCHORS_BY_SEVERITY) + 1):
        current = forensic_anchor_component(set(ANCHORS_BY_SEVERITY[:n]))
        assert current >= previous, (
            f"adding {ANCHORS_BY_SEVERITY[n - 1]} lowered the component "
            f"{previous:.4f} -> {current:.4f}"
        )
        previous = current


def test_anchor_component_monotone_over_every_subset_pair():
    """
    Exhaustive over all 256 subsets of the eight anchors: a superset can never score
    below a subset. The mean violated this in both directions depending on which
    behaviors were added.
    """
    scores = {}
    for r in range(len(ANCHORS_BY_SEVERITY) + 1):
        for combo in itertools.combinations(ANCHORS_BY_SEVERITY, r):
            scores[frozenset(combo)] = forensic_anchor_component(set(combo))

    for subset, sub_score in scores.items():
        for behavior in ANCHORS_BY_SEVERITY:
            if behavior in subset:
                continue
            superset = subset | {behavior}
            assert scores[superset] >= sub_score, (
                f"{sorted(superset)} scored below {sorted(subset)}"
            )


def test_malware_shaped_anchor_set_outscores_benign_shaped_one():
    """
    The direction failure N9 found in the corpus. Clean apps match a median of one
    anchor; the mean of one anchor is that anchor's own severity, so a benign app
    matching DYNAMIC_REFLECTION (0.6) scored 0.600 while malware matching
    CRYPTOGRAPHY_USAGE + DYNAMIC_REFLECTION + C2_BEHAVIOR averaged 0.583.
    """
    benign_shaped = forensic_anchor_component({"DYNAMIC_REFLECTION"})
    malware_shaped = forensic_anchor_component(
        {"CRYPTOGRAPHY_USAGE", "DYNAMIC_REFLECTION", "C2_BEHAVIOR"}
    )
    assert malware_shaped > benign_shaped


def test_adding_a_weak_anchor_does_not_dilute_a_severe_one():
    """
    The narrower form of the same bug: proving an extra low-severity behavior on top
    of the strongest anchor there is must not reduce the score.
    """
    severe_only = forensic_anchor_component({"STEALTH_SMS_INTERCEPTION"})
    plus_weak = forensic_anchor_component(
        {"STEALTH_SMS_INTERCEPTION", "CRYPTOGRAPHY_USAGE"}
    )
    assert plus_weak >= severe_only


def test_anchor_component_stays_in_range():
    assert forensic_anchor_component(set()) == 0.0
    assert 0.0 <= forensic_anchor_component(set(ANCHORS_BY_SEVERITY)) <= 1.0


@pytest.mark.parametrize("unknown", ["NOT_A_REAL_BEHAVIOR", ""])
def test_unknown_behavior_uses_the_default_weight_without_crashing(unknown):
    """Anchors added to the forensic dictionary but not to BEHAVIOR_SEVERITY."""
    assert forensic_anchor_component({unknown}) > 0.0
