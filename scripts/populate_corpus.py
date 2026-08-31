"""
Rebuilds the Neo4j knowledge corpus by re-analysing every APK on disk.

Why this exists alongside refresh_stale_samples.py: that script only targets
records predating record_json persistence. This one re-analyses the corpus
wholesale, which is what a change to the analysis pipeline itself requires — a
cached verdict can never self-heal (see scripts/clear_sample.py), so a pipeline
fix reaches old samples only by deleting each record and running it again.

Each sample's Sample node is deleted immediately before its upload rather than
wiping the graph up front. A big-bang wipe leaves the graph empty for the whole
run, and an interrupted run leaves it permanently gutted; deleting per sample
means the corpus only ever loses the one record currently being rebuilt, and an
interrupted run leaves everything it has not reached yet intact.

    python scripts/populate_corpus.py --limit 30       # checkpoint batch
    python scripts/populate_corpus.py --resume         # everything not yet done

The holdout set (data/benign_holdout) is deliberately NOT included: it is the
only independent check the score calibration has, and analysing it here would
fold it into the corpus it is supposed to be held out from.
"""
import argparse
import glob
import hashlib
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import requests

from app.graph.neo4j_client import neo4j_client

CORPUS_DIRS = ["data/ttp_apks", "data/benign_apks"]
PROGRESS_PATH = "data/populate_progress.json"


def sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def persisted(sha: str) -> bool:
    """
    Did this sample actually land in the graph? The only evidence that counts —
    the run's whole purpose is the Neo4j record, so the graph, not the HTTP
    status, decides whether a sample is done. Errors count as not-persisted so
    an unreachable Neo4j never gets recorded as progress.
    """
    try:
        rows = neo4j_client.run(
            "MATCH (s:Sample {sha256: $sha}) RETURN count(s) AS c", sha=sha
        )
        return bool(rows and rows[0].get("c"))
    except Exception:
        return False


def load_progress() -> dict:
    try:
        with open(PROGRESS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {"done": []}
    except (FileNotFoundError, ValueError, OSError):
        return {"done": []}


def save_progress(progress: dict) -> None:
    """Written after every sample, not at the end: a run measured in hours will
    be interrupted, and a progress file that only lands on clean exit is no
    progress file at all."""
    os.makedirs(os.path.dirname(PROGRESS_PATH), exist_ok=True)
    tmp = PROGRESS_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(progress, f)
    os.replace(tmp, PROGRESS_PATH)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0, help="stop after N samples (0 = all)")
    ap.add_argument("--resume", action="store_true", help="skip samples already done")
    ap.add_argument("--no-dynamic", action="store_true", help="static only")
    ap.add_argument("--api", default="http://127.0.0.1:8000")
    ap.add_argument("--dirs", nargs="*", default=CORPUS_DIRS)
    args = ap.parse_args()

    paths = []
    for d in args.dirs:
        paths.extend(sorted(glob.glob(os.path.join(d, "*.apk"))))
    print(f"Corpus on disk: {len(paths)} APKs across {len(args.dirs)} dir(s)")

    progress = load_progress()
    done = set(progress.get("done", []))
    if args.resume:
        print(f"Resuming — {len(done)} already done")

    queue = []
    for p in paths:
        sha = sha256_of(p)
        if args.resume and sha in done:
            continue
        queue.append((sha, p))
    if args.limit:
        queue = queue[: args.limit]
    print(f"Queued: {len(queue)}\n")

    ok = failed = dyn_ran = 0
    started = time.time()
    for i, (sha, path) in enumerate(queue, 1):
        name = os.path.basename(path)
        # Delete first: an upload of an already-cached sample is a cache hit,
        # which returns the stale verdict and re-analyses nothing.
        try:
            neo4j_client.run("MATCH (s:Sample {sha256: $sha}) DETACH DELETE s", sha=sha)
        except Exception as e:
            print(f"[{i}/{len(queue)}] {name[:34]:<34} DELETE FAILED: {e}")
            failed += 1
            continue

        # record_history=false marks these as corpus rather than operator
        # analyses — see the /analyze docstring. It keeps them out of the
        # Analysis History panel AND stamps the Sample node so the panel's
        # "Clear" cannot delete the knowledge base this script just built.
        params = {"skip_report": "true", "record_history": "false"}
        if not args.no_dynamic:
            params["enable_dynamic"] = "true"

        t0 = time.time()
        try:
            with open(path, "rb") as f:
                resp = requests.post(
                    f"{args.api}/analyze",
                    files={"file": (name, f, "application/vnd.android.package-archive")},
                    params=params,
                    timeout=1800,
                )
            dt = time.time() - t0
            if resp.status_code == 200:
                body = resp.json()
                manifest = body.get("manifest") or {}
                dv = manifest.get("dynamic_verification") or {}
                ran = bool(dv.get("ran"))
                score = (body.get("risk_score") or {}).get("total_score")
                band = (body.get("risk_score") or {}).get("verdict_band")

                # HTTP 200 does NOT mean the sample was persisted. When static
                # analysis aborts, /analyze still answers 200 — with the
                # mid-band unparseable verdict — and deliberately does not
                # cache it (see routes._unparseable_report: a parse failure is
                # a property of the analyzer, not a verdict worth replaying).
                # Trusting the status code alone recorded those shas as done,
                # so a later --resume skipped them forever and the corpus lost
                # them silently while the run reported failed=0. Observed live:
                # host antivirus quarantined the staged APK mid-analysis, and
                # 3 of 30 samples vanished exactly this way.
                if not persisted(sha):
                    note = (manifest.get("obfuscation") or {}).get("coverage_note") or ""
                    print(f"[{i}/{len(queue)}] {name[:34]:<34} {dt:6.1f}s  "
                          f"NOT PERSISTED (score {score}) — {note[:90]}")
                    failed += 1
                    continue

                dyn_ran += 1 if ran else 0
                print(f"[{i}/{len(queue)}] {name[:34]:<34} {dt:6.1f}s  "
                      f"{str(score):>6} {band:<10} dyn={'Y' if ran else 'n'}")
                ok += 1
                done.add(sha)
                progress["done"] = sorted(done)
                save_progress(progress)
            else:
                print(f"[{i}/{len(queue)}] {name[:34]:<34} HTTP {resp.status_code}")
                failed += 1
        except Exception as e:
            print(f"[{i}/{len(queue)}] {name[:34]:<34} ERROR {type(e).__name__}: {str(e)[:60]}")
            failed += 1

        if i % 10 == 0 or i == len(queue):
            avg = (time.time() - started) / i
            print(f"    -- {i}/{len(queue)} | ok={ok} failed={failed} dynamic={dyn_ran} "
                  f"| avg {avg:.1f}s/sample | elapsed {(time.time()-started)/60:.1f} min")

    total = time.time() - started
    print(f"\nDone. ok={ok} failed={failed} dynamic_ran={dyn_ran} "
          f"in {total/60:.1f} min ({total/max(1,len(queue)):.1f}s/sample)")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
