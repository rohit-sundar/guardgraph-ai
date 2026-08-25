"""
Score a whole corpus through pipeline phases 1-6 and print the tables the risk
score's calibration constants were chosen from.

This is the tool behind the N5-N8 work and behind `scoring._band_for`'s thresholds.
Every constant in `app/reports/scoring.py`'s calibration block was picked by reading
this script's output on 220 F-Droid benign APKs and 133 MalwareBazaar samples — rerun
it after any change to an analysis stage and confirm the numbers still hold, rather
than trusting that a rule "looks" more precise.

Phase 7 (GraphRAG) is deliberately excluded: it is ~94% of wall clock and cannot
change the score. Phase 1.5 is included, because YARA and signature hits feed
ioc_component.

Each APK is scored in a **child process** running this same file with `--score-one`.
Androguard can abort the interpreter outright on a malformed DEX, and a corpus run
that dies at sample 200 of 365 is worthless; isolation costs an interpreter start per
sample and buys a result for every sample that survives.

Online reputation lookups are OFF here by default. This script is the only
caller in the repo that can breach VirusTotal's public quota (4 requests/min,
500/day): one lookup per APK across 8 concurrent children is 600 requests and
120% of a day's allowance for a single corpus run. Calibrating with lookups off
is also the conservative choice -- VirusTotal only ever returns a verdict when
malicious > 0, so reputation can raise malware scores and never benign ones.
Pass --online to opt in; it pins one worker and paces at 4/min.

Usage:
    python scripts/score_corpus.py                        # whole corpus, 8 workers
    python scripts/score_corpus.py --sample 30            # 30 per class, quick look
    python scripts/score_corpus.py --workers 4 --out out.json
    python scripts/score_corpus.py --bands 30,40,60,75    # try candidate boundaries
    python scripts/score_corpus.py --resume               # skip APKs already in --out
    python scripts/score_corpus.py --sample 6 --online    # metered, 1 worker, 15s/APK
"""
import argparse
import glob
import json
import os
import random
import statistics
import subprocess
import sys
import time
import warnings
from concurrent.futures import ThreadPoolExecutor

warnings.filterwarnings("ignore")

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

# --online pacing. One worker at 15 s/sample is exactly VirusTotal's 4/min, with
# no shared state to coordinate; the daily stop is 450 rather than 500 so an
# interactive /analyze during the run still has headroom.
ONLINE_SECONDS_PER_SAMPLE = 15.0
ONLINE_DAILY_STOP = 450

# Set by --use-signature-db and forwarded to the children. Off by default: see score_one.
_USE_SIGNATURE_DB = False

DEFAULT_BENIGN_DIR = "data/benign_apks"
DEFAULT_MALWARE_DIR = "data/ttp_apks"
DEFAULT_OUT = "data/corpus_scores.json"

COMPONENTS = [
    ("classifier", "classifier_confidence_component", 25.0),
    ("permission", "permission_api_component", 20.0),
    ("ttp_sev", "ttp_severity_component", 15.0),
    ("anchor", "forensic_anchor_component", 15.0),
    ("obfuscation", "obfuscation_component", 15.0),
    ("reputation", "reputation_component", 5.0),
    ("ioc", "ioc_component", 5.0),
]


# ── one APK, in a child process ──────────────────────────────────────────────

def score_one(apk_path: str) -> dict:
    """Phases 1-6 on a single APK. Returns the score plus the scorer's raw inputs."""
    from loguru import logger

    logger.remove()  # the parent prints progress; per-phase logs would drown it

    # The local hash/cert DB is neutralised for calibration, for the same reason online
    # lookups are: data/signatures/known_hashes.json now holds the SHA-256 of every APK
    # in this corpus, so leaving it enabled means each malware sample matches itself —
    # is_known_malware True, reputation_component 0.95 against the 0.3 unknown prior,
    # plus a signature term in ioc_component. That is +5 to +8 points on every malware
    # sample and exactly 0 on every benign one, injected into the run that decides where
    # the verdict bands go: they would separate beautifully because the score would be
    # reading the answer key. scoring.py's boundary block documents "signature_matches 0
    # for every sample" as a precondition, and this is what keeps that true.
    # --use-signature-db opts back in, for measuring the hot path rather than calibrating.
    from app.core.config import settings
    if not os.environ.get("GUARDGRAPH_SCORE_WITH_SIGDB"):
        settings.signature_db_path = os.path.join(PROJECT_ROOT, "_no_signature_db.json")

    from app.core.pipeline import AnalysisPipeline, has_deterministic_evidence

    ingestion, _apk, _dvm, analysis_obj, yara_targets = (
        AnalysisPipeline.run_phase1_ingestion(apk_path)
    )
    sig_yara = AnalysisPipeline.run_phase1b_signature_yara(
        apk_path, ingestion, yara_targets=yara_targets
    )
    cfgs, parse_failure_rate = AnalysisPipeline.run_phase2_graph_construction(analysis_obj)
    all_matches, subgraphs, all_strings = (
        AnalysisPipeline.run_phase3_forensic_matching(cfgs, ingestion)
    )
    ingestion = AnalysisPipeline.merge_c2_from_strings(ingestion, all_strings)
    obfuscation, fvec, ttpvec, _density, total_nodes = (
        AnalysisPipeline.run_phase4_feature_engineering(
            ingestion, cfgs, all_matches, subgraphs, all_strings,
            parse_failure_rate, sig_yara=sig_yara,
        )
    )
    evidence = has_deterministic_evidence(len(cfgs), set(all_matches), ttpvec)
    predicted_ttps, family, _fconf = AnalysisPipeline.run_phase5_ml_classification(
        ttpvec, fvec, evidence_present=evidence
    )
    risk = AnalysisPipeline.run_phase6_risk_scoring(
        predicted_ttps, ingestion.permissions, obfuscation, all_matches,
        cache_hit=False, cached_score=None, sig_yara=sig_yara,
        ingestion=ingestion, classifier_evidence_present=evidence,
    )

    return {
        "apk": os.path.basename(apk_path),
        "package": ingestion.package_name,
        "total": risk.total_score,
        "band": risk.verdict_band,
        "zero_day": risk.zero_day_indicator,
        "evidence": evidence,
        "behaviors": sorted(all_matches),
        "predicted_ttps": predicted_ttps,
        "predicted_family": family,
        "components": {
            short: getattr(risk, attr) for short, attr, _cap in COMPONENTS
        },
        # Raw scorer inputs. Keeping them means a candidate re-weighting can be
        # evaluated offline against a corpus run instead of costing another hour.
        "inputs": {
            "analyzed_methods": len(cfgs),
            "dex_methods": ingestion.dex_method_count,
            "total_nodes": total_nodes,
            "parse_failure_rate": round(parse_failure_rate, 4),
            "flattening_method_ratio": obfuscation.flattening_method_ratio,
            "string_entropy_score": round(obfuscation.string_entropy_score, 4),
            "reflection_call_count": obfuscation.reflection_call_count,
            "permissions": len(ingestion.permissions),
            "matrix_flags": list(ingestion.permission_matrix_flags or []),
            "accessibility_flags": list(ingestion.accessibility_flags or []),
            "cert_anomalies": list(ingestion.cert_anomalies or []),
            "extracted_c2": len(ingestion.c2_indicators or []),
            "secondary_dex": int(ingestion.secondary_dex_count or 0),
            "dropper_signals": len(ingestion.dropper_signals or []),
            "signature_matches": len(sig_yara.signature_matches),
            "yara_matches": len(sig_yara.yara_matches),
            "yara_max_severity": max(
                [m.severity for m in sig_yara.yara_matches], default=0.0
            ),
        },
    }


# ── fan-out ──────────────────────────────────────────────────────────────────

def _run_child(label: str, path: str, index: int, total: int, started: float) -> dict:
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    if _USE_SIGNATURE_DB:
        env["GUARDGRAPH_SCORE_WITH_SIGDB"] = "1"
    try:
        proc = subprocess.run(
            [sys.executable, os.path.abspath(__file__), "--score-one", path],
            capture_output=True, text=True, timeout=1800, env=env,
            encoding="utf-8", errors="replace",
        )
        record = json.loads(proc.stdout.strip().splitlines()[-1])
    except Exception as exc:  # a crashed child is a data point, not a failure
        record = {"apk": os.path.basename(path), "error": repr(exc)[:200]}
    record["label"] = label
    print(
        f"  [{index}/{total}] {record['apk'][:26]:<28} {label:<8} "
        f"{record.get('total', record.get('error', '?'))} {record.get('band', '')} "
        f"({int(time.time() - started)}s)",
        flush=True,
    )
    return record


def score_corpus(
    targets: list[tuple[str, str]], workers: int, online: bool = False
) -> list[dict]:
    started = time.time()
    counter = {"n": 0}

    def one(item):
        label, path = item
        counter["n"] += 1
        return _run_child(label, path, counter["n"], len(targets), started)

    if not online:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            return list(pool.map(one, targets))

    # Serial and paced. Each child performs at most one VirusTotal lookup, so
    # counting samples counts lookups; stop at the daily budget rather than
    # collecting a run's worth of HTTP 429s that read as "clean".
    records: list[dict] = []
    for position, item in enumerate(targets):
        if len(records) >= ONLINE_DAILY_STOP:
            print(f"\n  stopping at the {ONLINE_DAILY_STOP}-lookup daily budget "
                  f"({len(targets) - len(records)} APKs not scored)", flush=True)
            break
        sample_started = time.time()
        records.append(one(item))
        if position < len(targets) - 1:
            time.sleep(max(0.0, ONLINE_SECONDS_PER_SAMPLE - (time.time() - sample_started)))
    print(f"\nonline lookups performed this run: {len(records)} "
          f"(VirusTotal public tier allows 500/day)", flush=True)
    return records


# ── reporting ────────────────────────────────────────────────────────────────

def _quantile(sorted_values: list[float], p: float) -> float:
    if not sorted_values:
        return 0.0
    i = (len(sorted_values) - 1) * p
    lo = int(i)
    hi = min(lo + 1, len(sorted_values) - 1)
    return sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * (i - lo)


def _band_of(total: float, bands: tuple[float, float, float, float]) -> str:
    low, medium, suspicious, high = bands
    if total <= low:
        return "low"
    if total <= medium:
        return "medium"
    if total <= suspicious:
        return "suspicious"
    if total <= high:
        return "high"
    return "malicious"


def report(records: list[dict], bands: tuple[float, float, float, float]) -> None:
    ok = [r for r in records if "error" not in r]
    failed = [r for r in records if "error" in r]
    groups = {
        "benign": [r for r in ok if r["label"] == "benign"],
        "malware": [r for r in ok if r["label"] == "malware"],
    }

    print(f"\n{'=' * 78}\nSCORED {len(ok)} APKs ({len(failed)} unparseable)\n{'=' * 78}")

    print("\n── total_score distribution " + "─" * 50)
    print(f"{'':<9}{'n':>5}{'min':>8}{'p05':>8}{'p25':>8}{'median':>9}"
          f"{'p75':>8}{'p95':>8}{'max':>8}")
    for name, group in groups.items():
        values = sorted(r["total"] for r in group)
        if not values:
            continue
        cells = "".join(
            f"{_quantile(values, p):>8.2f}" for p in (0.0, 0.05, 0.25)
        )
        print(f"{name:<9}{len(values):>5}{cells}{_quantile(values, 0.5):>9.2f}"
              f"{_quantile(values, 0.75):>8.2f}{_quantile(values, 0.95):>8.2f}"
              f"{values[-1]:>8.2f}")

    print(f"\n── verdict bands at {bands} " + "─" * 40)
    print(f"{'band':<14}{'benign':>10}{'malware':>10}")
    for band in ("low", "medium", "suspicious", "high", "malicious"):
        counts = [
            sum(1 for r in group if _band_of(r["total"], bands) == band)
            for group in groups.values()
        ]
        print(f"{band:<14}{counts[0]:>10}{counts[1]:>10}")

    print("\n── components: mean, and share of the component's cap " + "─" * 24)
    print(f"{'component':<14}{'benign':>10}{'malware':>10}{'ben %cap':>10}{'mal %cap':>10}")
    for short, _attr, cap in COMPONENTS:
        means = []
        for group in groups.values():
            values = [r["components"][short] or 0.0 for r in group]
            means.append(statistics.mean(values) if values else 0.0)
        print(f"{short:<14}{means[0]:>10.2f}{means[1]:>10.2f}"
              f"{100 * means[0] / cap:>9.1f}%{100 * means[1] / cap:>9.1f}%")

    benign = sorted(r["total"] for r in groups["benign"])
    malware = sorted(r["total"] for r in groups["malware"])
    if benign and malware:
        print("\n── threshold sweep: >= t called malicious " + "─" * 36)
        print(f"{'t':>6}{'TPR':>8}{'FPR':>8}{'Youden':>9}{'precision':>11}{'F1':>8}")
        best = None
        for step in range(10, 191):
            t = step / 2
            tp = sum(1 for v in malware if v >= t)
            fp = sum(1 for v in benign if v >= t)
            tpr, fpr = tp / len(malware), fp / len(benign)
            precision = tp / (tp + fp) if tp + fp else 0.0
            f1 = 2 * precision * tpr / (precision + tpr) if precision + tpr else 0.0
            if best is None or tpr - fpr > best[3]:
                best = (t, tpr, fpr, tpr - fpr, precision, f1)
            if step % 10 == 0:
                print(f"{t:>6.1f}{tpr:>8.3f}{fpr:>8.3f}{tpr - fpr:>9.3f}"
                      f"{precision:>11.3f}{f1:>8.3f}")
        print(f"\nbest Youden J at t={best[0]:.1f}: TPR={best[1]:.3f} FPR={best[2]:.3f} "
              f"precision={best[4]:.3f} F1={best[5]:.3f}")

        print("\n── the separating region " + "─" * 52)
        print("benign top 10 :", [f"{v:.1f}" for v in benign[-10:]])
        print("malware low 10:", [f"{v:.1f}" for v in malware[:10]])

    misfiled = [
        r for r in groups["benign"]
        if _band_of(r["total"], bands) in ("high", "malicious")
    ]
    if misfiled:
        print(f"\n── clean apps at 'high' or above ({len(misfiled)}) " + "─" * 34)
        for r in sorted(misfiled, key=lambda r: -r["total"]):
            drivers = ", ".join(
                f"{short}={r['components'][short]:.1f}"
                for short, _a, _c in COMPONENTS
                if (r["components"][short] or 0.0) > 0
            )
            print(f"  {(r['package'] or r['apk'])[:44]:<46} {r['total']:>6.2f}  {drivers}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--score-one", help=argparse.SUPPRESS)
    parser.add_argument("--benign-dir", default=DEFAULT_BENIGN_DIR)
    parser.add_argument("--malware-dir", default=DEFAULT_MALWARE_DIR)
    parser.add_argument("--sample", type=int, default=0,
                        help="APKs per class; 0 (default) scores the whole corpus")
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--out", default=DEFAULT_OUT)
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument("--bands", default=None,
                        help="comma-separated low,medium,suspicious,high ceilings to "
                             "report against; defaults to the shipped thresholds")
    parser.add_argument("--from-json", default=None,
                        help="re-report an earlier run instead of re-scoring")
    parser.add_argument("--resume", action="store_true",
                        help="load --out if it exists, skip APKs already scored, and "
                             "merge before writing. Also lets several --benign-dir "
                             "runs accumulate into one file.")
    parser.add_argument("--use-signature-db", action="store_true",
                        help="let the local hash/cert DB match during scoring. OFF by "
                             "default: the DB holds this corpus's own hashes, so enabling "
                             "it while re-deriving verdict bands feeds the answer key into "
                             "the calibration. Use only for hot-path measurement.")
    parser.add_argument("--online", action="store_true",
                        help="enable VirusTotal/MalwareBazaar lookups. Forces "
                             "--workers 1 and paces at 4/min, so expect ~15s per APK "
                             "and a hard stop at the daily budget.")
    args = parser.parse_args()

    global _USE_SIGNATURE_DB
    _USE_SIGNATURE_DB = args.use_signature_db
    if _USE_SIGNATURE_DB:
        print("WARNING: --use-signature-db is ON. The local DB holds this corpus's own "
              "hashes, so these scores must NOT be used to re-derive the verdict bands.")

    # Children inherit this through _run_child's env copy. Default off: see the
    # module docstring for the quota arithmetic.
    os.environ["ONLINE_LOOKUPS_ENABLED"] = "true" if args.online else "false"
    if args.online and args.workers != 1:
        print(f"--online pins --workers 1 (was {args.workers}) to hold 4/min")
        args.workers = 1

    # A redirected stdout on Windows defaults to cp1252, and the report's rules and
    # arrows are not in it — a 50-minute run must not die at the print statement.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

    # Before anything else, including in the child: settings.yara_rules_dir,
    # signature_db_path and the model paths are all repo-relative, and a child that
    # inherits some other cwd silently scores with no YARA rules and no signature DB.
    os.chdir(PROJECT_ROOT)

    if args.score_one:
        sys.stdout.reconfigure(encoding="utf-8")
        try:
            print(json.dumps(score_one(args.score_one), ensure_ascii=True, default=str))
        except Exception as exc:
            print(json.dumps({
                "apk": os.path.basename(args.score_one), "error": repr(exc)[:300],
            }))
        return

    if args.bands:
        bands = tuple(float(x) for x in args.bands.split(","))
        if len(bands) != 4:
            parser.error("--bands takes exactly four ceilings, e.g. 30,40,60,75")
    else:
        from app.reports.scoring import (
            BAND_LOW_CEILING, BAND_MEDIUM_CEILING, BAND_SUSPICIOUS_CEILING,
            BAND_HIGH_CEILING,
        )
        bands = (
            BAND_LOW_CEILING, BAND_MEDIUM_CEILING, BAND_SUSPICIOUS_CEILING,
            BAND_HIGH_CEILING,
        )

    if args.from_json:
        with open(args.from_json, encoding="utf-8") as fh:
            report(json.load(fh), bands)
        return

    random.seed(args.seed)
    benign = sorted(glob.glob(os.path.join(args.benign_dir, "*.apk")))
    malware = sorted(glob.glob(os.path.join(args.malware_dir, "*.apk")))
    if not benign and not malware:
        parser.error(f"no APKs under {args.benign_dir} or {args.malware_dir}")

    def pick(paths):
        if args.sample and args.sample < len(paths):
            return random.sample(paths, args.sample)
        return paths

    targets = ([("benign", p) for p in pick(benign)]
               + [("malware", p) for p in pick(malware)])

    # --resume: previously scored APKs are keyed by basename, which is what a
    # record carries. A crash at 95% of a two-hour run used to cost the run.
    existing: list[dict] = []
    if args.resume and os.path.exists(args.out):
        with open(args.out, encoding="utf-8") as fh:
            existing = json.load(fh)
        done = {r["apk"] for r in existing if "error" not in r}
        before = len(targets)
        targets = [t for t in targets if os.path.basename(t[1]) not in done]
        print(f"--resume: {len(done)} already in {args.out}, "
              f"skipping {before - len(targets)} of {before}")

    print(f"Scoring {len(targets)} APKs on {args.workers} workers "
          f"({sum(1 for lbl, _ in targets if lbl == 'benign')} benign / "
          f"{sum(1 for lbl, _ in targets if lbl == 'malware')} malware)"
          f"{' -- ONLINE, paced at 4/min' if args.online else ''}")

    records = score_corpus(targets, args.workers, online=args.online)

    # Merge new over old so a re-run of a failed APK replaces its error record.
    merged = {r["apk"]: r for r in existing}
    merged.update({r["apk"]: r for r in records})
    records = list(merged.values())

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(records, fh, ensure_ascii=True, indent=1)
    print(f"\nwrote {args.out} ({len(records)} records)")

    report(records, bands)


if __name__ == "__main__":
    main()
