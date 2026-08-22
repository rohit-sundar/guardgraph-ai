"""
Re-derives TTP_SEVERITY_SATURATION_MASS and ANCHOR_SATURATION_MASS (scoring.py, N9)
against the assembled TTP dataset.

Both constants replaced a MEAN over per-item severities. The mean made each component
non-monotonic in evidence — every additional corroborating technique or behavior pulled
the average toward the middle of the severity scale — and on the corpus it left
forensic_anchor_component discriminating backwards. This script prints the tables those
two constants were chosen from, so a change to the analysis stages, the severity
weights, or the corpus can be answered with a measurement instead of an argument.

Unlike scripts/score_corpus.py this needs no APKs: the TTP feature vectors and the
eight forensic-anchor presence flags are already columns in data/ttp_dataset.csv, so a
run is seconds rather than hours. It therefore measures the two components in isolation
and says nothing about total scores or verdict bands — re-derive those with
score_corpus.py after changing either constant.

    python scripts/measure_saturation.py
"""
import math
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pandas as pd  # noqa: E402

from app.core.pipeline import TTP_PREDICT_THRESHOLD  # noqa: E402
from app.ml.classifier import ttp_classifier  # noqa: E402
from app.ml.features import TTP_FEATURE_NAMES  # noqa: E402
from app.reports.scoring import (  # noqa: E402
    ANCHOR_SATURATION_MASS,
    BEHAVIOR_SEVERITY,
    TTP_SEVERITY_SATURATION_MASS,
    _technique_severity,
)

DATASET = "data/ttp_dataset.csv"
CANDIDATE_K = (1.0, 1.5, 2.0, 2.5, 3.0, 3.5, 4.0, 4.5, 5.0)


def _squash(mass: float, k: float) -> float:
    return 1.0 - math.exp(-mass / k)


def _describe(frame: pd.DataFrame, column: str, label: str) -> None:
    g = frame[column]
    print(
        f"  {label:<16} p50 {g.median():.3f}  p75 {g.quantile(.75):.3f}  "
        f"p95 {g.quantile(.95):.3f}  max {g.max():.3f}"
    )


def _candidate_table(rows: pd.DataFrame, chosen: float) -> None:
    """
    Separation is malware p50 minus benign p95: the gap between where malware
    typically lands and where all but the noisiest 5% of clean apps top out. It is
    the number to maximise; its SIGN is the number to check first.
    """
    print(f"  {'K':<7} {'benign p50':<11} {'benign p95':<11} {'benign max':<11} "
          f"{'malw p25':<10} {'malw p50':<10} {'separation'}")
    for k in CANDIDATE_K:
        benign = rows[rows.benign].mass.map(lambda m: _squash(m, k))
        malware = rows[~rows.benign].mass.map(lambda m: _squash(m, k))
        mark = "  <- in use" if abs(k - chosen) < 1e-9 else ""
        print(
            f"  {k:<7.1f} {benign.median():<11.3f} {benign.quantile(.95):<11.3f} "
            f"{benign.max():<11.3f} {malware.quantile(.25):<10.3f} "
            f"{malware.median():<10.3f} {malware.median() - benign.quantile(.95):+.3f}{mark}"
        )

    mal_p50 = rows[~rows.benign].mass.median()
    old_p50 = rows[~rows.benign].old.median()
    if mal_p50 > 0 and 0.0 < old_p50 < 1.0:
        neutral = -mal_p50 / math.log(1.0 - old_p50)
        print(f"\n  K that leaves the malware median where the mean put it: {neutral:.3f}")


def measure_ttp(df: pd.DataFrame) -> pd.DataFrame:
    """Severity-weighted technique mass, using the trained bundle's own thresholds."""
    ttp_classifier.load()
    model = ttp_classifier._bundle["model"]
    thresholds = ttp_classifier.thresholds()
    proba = model.predict_proba_matrix(df[TTP_FEATURE_NAMES].to_numpy(dtype=float))

    rows = []
    for i, source in enumerate(df["label_source"]):
        predicted = {
            label: float(proba[i, j])
            for j, label in enumerate(model.labels)
            if proba[i, j] >= thresholds.get(label, TTP_PREDICT_THRESHOLD)
        }
        mass = sum(p * _technique_severity(t) for t, p in predicted.items())
        rows.append({
            "benign": source == "benign",
            "n": len(predicted),
            "mass": mass,
            # The superseded mean, kept so the table can show what changed.
            "old": min(1.0, mass / len(predicted)) if predicted else 0.0,
        })
    return pd.DataFrame(rows)


def measure_anchors(df: pd.DataFrame) -> pd.DataFrame:
    """
    Forensic-anchor mass. The eight anchor behaviors are already binary presence
    columns in the dataset (they are TTP features too), so no APK is re-analysed.
    """
    behaviors = [b for b in BEHAVIOR_SEVERITY if b in df.columns]
    missing = sorted(set(BEHAVIOR_SEVERITY) - set(behaviors))
    if missing:
        print(f"  WARNING: not columns in {DATASET}, excluded from this run: {missing}")

    rows = []
    for _, row in df.iterrows():
        matched = [b for b in behaviors if float(row[b]) > 0]
        weights = [BEHAVIOR_SEVERITY[b] for b in matched]
        rows.append({
            "benign": row["label_source"] == "benign",
            "n": len(matched),
            "mass": sum(weights),
            "old": min(1.0, (sum(weights) / len(weights)) + min(0.2, 0.05 * (len(weights) - 1)))
            if weights else 0.0,
        })
    return pd.DataFrame(rows)


def _report(title: str, rows: pd.DataFrame, chosen: float) -> None:
    print(f"\n{'=' * 78}\n{title}\n{'=' * 78}")
    for is_benign, group in rows.groupby("benign"):
        print(f"\n{'BENIGN' if is_benign else 'MALWARE'}  n={len(group)}")
        print(f"  {'items matched':<16} p50 {group.n.median():.1f}  "
              f"p75 {group.n.quantile(.75):.1f}  max {int(group.n.max())}")
        _describe(group, "mass", "severity mass")
        _describe(group, "old", "OLD (mean)")
    print("\nsaturating candidates:")
    _candidate_table(rows, chosen)


def main() -> int:
    if not os.path.exists(DATASET):
        print(f"{DATASET} not found — build it with scripts/build_ttp_dataset.py first.")
        return 1

    df = pd.read_csv(DATASET)
    print(f"{DATASET}: {len(df)} rows "
          f"({int((df.label_source == 'benign').sum())} benign / "
          f"{int((df.label_source != 'benign').sum())} malware)")

    _report("ttp_severity_component", measure_ttp(df), TTP_SEVERITY_SATURATION_MASS)
    _report("forensic_anchor_component", measure_anchors(df), ANCHOR_SATURATION_MASS)

    print("\nNote: these are the two components in isolation. Total scores and the "
          "verdict\nbands move with them - re-run scripts/score_corpus.py before "
          "trusting a band.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
