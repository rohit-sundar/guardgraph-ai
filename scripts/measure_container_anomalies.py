"""
Measures `apk_container.scan_container`'s anomaly codes across the local corpus.

Every deterministic signal in this system has to clear the same bar before it is
allowed near the scorer: what rate does it fire at on clean apps? A structural
check that looks damning and fires on 4% of benign apps is a false-positive
generator, and the band comments in scoring.py exist because that lesson was
learned the expensive way.

    python scripts/measure_container_anomalies.py
    python scripts/measure_container_anomalies.py --benign-dir data/benign_apks \
        --malware-dir data/ttp_apks --extra-dir evaluation

Reports, per anomaly family, the count and rate on each corpus, so the decision
about which codes are worth scoring is made from numbers rather than from how
alarming the code name sounds.
"""
import argparse
import glob
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from loguru import logger

from app.analysis.apk_container import open_and_scan

logger.remove()
logger.add(sys.stderr, level="ERROR")


def _family(code: str) -> str:
    """`zip_fake_encryption:85/89` -> `zip_fake_encryption`."""
    return code.split(":", 1)[0]


def scan_dir(path: str, label: str, limit: int | None = None) -> tuple[Counter, int, list]:
    apks = sorted(glob.glob(os.path.join(path, "*.apk")))
    if limit:
        apks = apks[:limit]
    counts: Counter = Counter()
    rows = []
    for i, apk in enumerate(apks, 1):
        _container, scan = open_and_scan(apk)
        families = {_family(c) for c in scan.anomalies}
        for fam in families:
            counts[fam] += 1
        if families:
            rows.append((os.path.basename(apk), sorted(scan.anomalies)))
        if i % 50 == 0:
            print(f"  [{label}] {i}/{len(apks)}", flush=True)
    return counts, len(apks), rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--benign-dir", action="append", default=None)
    ap.add_argument("--malware-dir", action="append", default=None)
    ap.add_argument("--extra-dir", action="append", default=None)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--show-benign-hits", action="store_true",
                    help="List every clean app that tripped a code — the list "
                         "that decides whether a code is scoreable.")
    args = ap.parse_args()

    benign_dirs = args.benign_dir or ["data/benign_apks", "data/benign_holdout"]
    malware_dirs = args.malware_dir or ["data/ttp_apks"]

    groups: list[tuple[str, list[str]]] = [
        ("benign", benign_dirs),
        ("malware", malware_dirs),
    ]
    if args.extra_dir:
        groups.append(("extra", args.extra_dir))

    results: dict[str, tuple[Counter, int, list]] = {}
    for label, dirs in groups:
        total_counts: Counter = Counter()
        total_n = 0
        total_rows: list = []
        for d in dirs:
            if not os.path.isdir(d):
                print(f"skipping missing dir {d}")
                continue
            print(f"scanning {d} ({label}) ...", flush=True)
            counts, n, rows = scan_dir(d, label, args.limit)
            total_counts.update(counts)
            total_n += n
            total_rows.extend(rows)
        results[label] = (total_counts, total_n, total_rows)

    families = sorted({f for c, _n, _r in results.values() for f in c})
    width = max((len(f) for f in families), default=20)

    print()
    print("anomaly family".ljust(width), end="")
    for label, _ in groups:
        print(f"{label:>22}", end="")
    print()
    print("-" * (width + 22 * len(groups)))

    for fam in families:
        print(fam.ljust(width), end="")
        for label, _ in groups:
            counts, n, _rows = results[label]
            hits = counts[fam]
            rate = (hits / n * 100) if n else 0.0
            print(f"{hits:>8}/{n:<6} {rate:>5.1f}%", end="")
        print()

    print()
    for label, _ in groups:
        _counts, n, rows = results[label]
        print(f"{label}: {len(rows)}/{n} samples tripped at least one code")

    if args.show_benign_hits:
        print("\nclean apps that tripped a code:")
        for name, codes in results["benign"][2]:
            print(f"  {name}  {codes}")

    if results.get("extra"):
        print("\nextra dir detail:")
        for name, codes in results["extra"][2]:
            print(f"  {name}  {codes}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
