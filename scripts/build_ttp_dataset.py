"""
Build the multi-label MITRE ATT&CK Mobile TTP training dataset (staged / hybrid).

DroidTTP's own dataset is not public and CICMalDroid2020 carries no TTP labels, so
we assemble labels ourselves:

  Stage A (real, bounded)  — for each software in data/ontology/software_technique_map.json,
      pull Android sample hashes from MalwareBazaar (by signature/tag), download the APKs,
      extract features, and label each row with that software's ATT&CK techniques
      (label_source="stix_ref").
  Stage B (weak bootstrap) — for local CICMalDroid2020 banking/SMS APKs, derive weak TTP
      labels from forensic-dictionary behaviors via BEHAVIOR_TO_TTPS (label_source="weak").

Feature extraction reuses the SAME analysis functions the cold path uses and calls
`build_ttp_feature_vector`, so training columns line up exactly with inference. Keep
`extract_ttp_row` in sync with the pipeline's Phase-4 TTP vector construction.

    * First check whether DroidTTP has since released its dataset — prefer it if so. *

Usage:
    python scripts/build_ttp_dataset.py --stage a --max-per-family 15
    python scripts/build_ttp_dataset.py --stage b --cic-dir data/cicmaldroid_apks
    python scripts/build_ttp_dataset.py --stage all
    python scripts/build_ttp_dataset.py --stage a --download-workers 16   # faster network
"""
import argparse
import io
import json
import os
import sys
import threading
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
import pyzipper  # noqa: E402  — MalwareBazaar samples are WinZip-AES encrypted; stdlib zipfile can't decrypt those

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pandas as pd  # noqa: E402
from loguru import logger  # noqa: E402

from app.analysis.ingest import ingest_apk  # noqa: E402
from app.analysis.cfg import build_all_method_cfgs  # noqa: E402
from app.analysis.forensic import match_anchors, extract_anchor_subgraph  # noqa: E402
from app.analysis.topology import (  # noqa: E402
    compute_topological_invariants,
    aggregate_subgraph_invariants,
)
from app.analysis.obfuscation import build_obfuscation_signal  # noqa: E402
from app.ml.features import build_ttp_feature_vector, TTP_FEATURE_NAMES  # noqa: E402
from app.ml.labels import TTP_LABELS  # noqa: E402
from app.core.config import settings  # noqa: E402

SOFTWARE_MAP_PATH = "data/ontology/software_technique_map.json"
OUT_CSV = "data/ttp_dataset.csv"
MB_API = "https://mb-api.abuse.ch/api/v1/"
# Written by the download phase, read by the analysis phase: carries each sample's
# family + ATT&CK techniques so analysis never has to re-query MalwareBazaar.
MANIFEST_NAME = "_manifest.json"

# Weak-label heuristic: forensic-dictionary behavior -> likely ATT&CK Mobile techniques.
# Rule-derived on purpose (label_source="weak") — used only to bootstrap coverage.
BEHAVIOR_TO_TTPS: dict[str, list[str]] = {
    "STEALTH_SMS_INTERCEPTION": ["T1636", "T1582"],
    "OTP_INTERCEPTION":         ["T1636", "T1582", "T1638"],
    "CREDENTIAL_HARVESTING":    ["T1417", "T1516", "T1635"],
    "C2_BEHAVIOR":              ["T1437", "T1521", "T1646"],
    "DYNAMIC_REFLECTION":       ["T1406", "T1633"],
    "CRYPTOGRAPHY_USAGE":       ["T1471", "T1521"],
}


def extract_ttp_row(apk_path: str) -> tuple[list[float], dict] | None:
    """
    Runs the cold-path static analysis on one APK and returns
    (ttp_feature_vector, meta). meta carries matched behaviors + sha256 for labeling.
    Returns None if the APK cannot be parsed. Keep in sync with pipeline Phase 4.
    """
    try:
        ingestion, apk_obj, dvm, analysis_obj = ingest_apk(apk_path)
    except Exception as e:
        logger.error(f"[dataset] ingest failed for {apk_path}: {e}")
        return None

    try:
        cfgs, parse_failure_rate = build_all_method_cfgs(analysis_obj)
    except Exception as e:
        logger.error(f"[dataset] CFG build failed for {apk_path}: {e}")
        return None

    all_matches: dict[str, list[str]] = {}
    subgraph_invariants: list[dict] = []
    all_strings: list[str] = []
    all_apis: set[str] = set()

    for g in cfgs.values():
        for _, data in g.nodes(data=True):
            all_strings.extend(data.get("string_literals", []))
            all_apis.update(data.get("api_calls", []))
        matches = match_anchors(g)
        for behavior, anchor_nodes in matches.items():
            all_matches.setdefault(behavior, []).extend(anchor_nodes)
            for anchor in anchor_nodes:
                sub = extract_anchor_subgraph(g, anchor, hops=4)
                subgraph_invariants.append(compute_topological_invariants(sub))

    agg_invariants = aggregate_subgraph_invariants(subgraph_invariants)

    obfuscation = build_obfuscation_signal(
        all_strings=all_strings,
        cfgs=cfgs,
        entropy_threshold=settings.entropy_high_threshold,
        flattening_zscore=settings.flattening_degree_outlier_zscore,
        method_parse_failure_rate=parse_failure_rate,
    )

    vec = build_ttp_feature_vector(
        permissions=ingestion.permissions,
        intent_actions=ingestion.intent_actions,
        api_calls=all_apis,
        num_activities=len(ingestion.activities),
        num_services=len(ingestion.services),
        num_receivers=len(ingestion.receivers),
        matched_behaviors=set(all_matches.keys()),
        topological_invariants=agg_invariants,
        obfuscation_entropy=obfuscation.string_entropy_score,
        obfuscation_flattening=obfuscation.flattening_suspected,
        obfuscation_reflection_count=obfuscation.reflection_call_count,
        # Signature/YARA left zero-filled in the training set (detection-layer signals
        # that boost inference-time scoring; zero-fill is safe — they only add signal).
        signature_match_count=0,
        yara_rule_match_count=0,
        yara_max_severity=0.0,
    )
    meta = {
        "sha256": ingestion.sha256,
        "matched_behaviors": sorted(all_matches.keys()),
    }
    return vec, meta


def _row_dict(vec: list[float], techniques: set[str], label_source: str,
              sha256: str, source: str) -> dict:
    row = dict(zip(TTP_FEATURE_NAMES, vec))
    for tid in TTP_LABELS:
        row[tid] = 1 if tid in techniques else 0
    row["label_source"] = label_source
    row["sha256"] = sha256
    row["source_family"] = source
    return row


# ── Stage A: real APKs from MalwareBazaar, labeled by ATT&CK software->technique ──

def _mb_hashes_for_signature(
    signature: str, limit: int, auth_key: str
) -> tuple[list[str], bool]:
    """
    Return (APK sha256 hashes tagged with `signature`, query_ok).

    query_ok distinguishes "MalwareBazaar has no APKs for this name" from "the query
    errored" (502, timeout). Without that split a transient 502 looks identical to an
    empty family, and the caller would mark the family done and never retry it.
    """
    headers = {"Auth-Key": auth_key} if auth_key else {}
    data = urllib.parse.urlencode(
        {"query": "get_siginfo", "signature": signature, "limit": str(limit)}
    ).encode()
    try:
        req = urllib.request.Request(MB_API, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        logger.warning(f"[dataset] MalwareBazaar get_siginfo failed for '{signature}': {e}")
        return [], False
    status = payload.get("query_status")
    if status != "ok":
        # no_results means the name is genuinely unknown — a real answer, not a failure.
        return [], status == "no_results"
    return [
        item["sha256_hash"]
        for item in payload.get("data", [])
        if str(item.get("file_type", "")).lower() == "apk"
    ], True


def _mb_download_apk(sha256: str, dest_dir: str, auth_key: str) -> str | None:
    """Download + unzip one MalwareBazaar sample (zip password 'infected')."""
    os.makedirs(dest_dir, exist_ok=True)
    out_path = os.path.join(dest_dir, f"{sha256}.apk")
    if os.path.exists(out_path):
        return out_path
    headers = {"Auth-Key": auth_key} if auth_key else {}
    data = urllib.parse.urlencode({"query": "get_file", "sha256_hash": sha256}).encode()
    try:
        req = urllib.request.Request(MB_API, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=60) as resp:
            body = resp.read()
        # A successful get_file returns the sample as a zip archive (magic "PK").
        # Any error (bad hash, auth, rate limit) comes back as a small JSON body,
        # so gate on the actual bytes rather than the Content-Type header — abuse.ch
        # does not reliably set application/zip on the download response.
        if not body.startswith(b"PK"):
            logger.warning(f"[dataset] MB download rejected for {sha256}: {body[:200]!r}")
            return None
        # MalwareBazaar archives use WinZip AES-256 encryption (compression method 99),
        # which the stdlib zipfile cannot decrypt — pyzipper.AESZipFile handles both
        # AES and legacy ZipCrypto members.
        #
        # Unpack to a thread-unique temp file and rename into place: the rename is
        # atomic, so an interrupted run can never leave a truncated .apk that the
        # os.path.exists() resume check above would later mistake for a good sample.
        tmp_path = f"{out_path}.{threading.get_ident()}.part"
        try:
            with pyzipper.AESZipFile(io.BytesIO(body)) as zf:
                zf.setpassword(b"infected")
                inner = zf.namelist()[0]
                with zf.open(inner) as src, open(tmp_path, "wb") as dst:
                    dst.write(src.read())
            os.replace(tmp_path, out_path)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        return out_path
    except Exception as e:
        logger.warning(f"[dataset] MB download failed for {sha256}: {e}")
        return None


def _download_many(
    hashes: list[str], dest_dir: str, auth_key: str, workers: int
) -> list[tuple[str, str]]:
    """
    Fetch several samples concurrently and return [(sha256, apk_path)] for the ones
    that succeeded, in the original `hashes` order so dataset rows stay deterministic.

    Downloads are network-bound, so threads help; feature extraction stays serial in
    the caller because Androguard is CPU-bound and not thread-safe.
    """
    if not hashes:
        return []
    paths: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=min(workers, len(hashes))) as pool:
        futures = {
            pool.submit(_mb_download_apk, h, dest_dir, auth_key): h for h in hashes
        }
        for fut in as_completed(futures):
            h = futures[fut]
            try:
                apk_path = fut.result()
            except Exception as e:  # _mb_download_apk swallows its own errors; belt and braces
                logger.warning(f"[dataset] MB download worker failed for {h}: {e}")
                continue
            if apk_path:
                paths[h] = apk_path
    logger.info(f"[dataset] downloaded {len(paths)}/{len(hashes)} samples ({workers} workers)")
    return [(h, paths[h]) for h in hashes if h in paths]


def _manifest_path(apk_dir: str, override: str | None = None) -> str:
    return override or os.path.join(apk_dir, MANIFEST_NAME)


def _read_manifest(path: str) -> dict:
    """
    Load the manifest document: {"samples": {sha256: {...}}, "families": {name: {...}}}.

    "families" records which software entries have already been resolved against
    MalwareBazaar, so a rerun re-queries only the ones that errored.
    """
    if not os.path.exists(path):
        return {"samples": {}, "families": {}}
    try:
        with open(path, "r", encoding="utf-8") as f:
            doc = json.load(f)
        return {
            "samples": doc.get("samples", {}),
            "families": doc.get("families", {}),
        }
    except Exception as e:
        logger.error(f"[dataset] could not read manifest {path}: {e}")
        return {"samples": {}, "families": {}}


def _missing_samples(targets: dict[str, dict], apk_dir: str) -> list[str]:
    """Manifest entries with no APK on disk — i.e. what a rerun still needs to fetch."""
    return [
        h for h in targets
        if not os.path.exists(os.path.join(apk_dir, f"{h}.apk"))
    ]


def _resolve_stage_a_targets(
    software_map: list[dict],
    max_per_family: int,
    auth_key: str,
    done_families: dict[str, dict] | None = None,
) -> tuple[dict[str, dict], dict[str, dict]]:
    """
    Ask MalwareBazaar which samples represent each ATT&CK software entry.

    Returns (targets, family_status):
      targets       {sha256: {"family": ..., "techniques": [...]}}. A sample tagged
                    under two families keeps the first that claimed it, so labels
                    stay single-valued.
      family_status {name: {"resolved": bool, "count": int}} — resolved=False when a
                    query errored, which is what makes the next run retry just that
                    family instead of sweeping all of them again.

    Families already marked resolved in `done_families` are skipped entirely; the
    sweep is the slow, flaky part of the download phase and is not worth repeating.
    """
    done_families = done_families or {}
    label_set = set(TTP_LABELS)
    targets: dict[str, dict] = {}
    family_status: dict[str, dict] = {}
    skipped = 0

    for sw in software_map:
        name = sw["name"]
        techniques = sorted({t for t in sw["technique_ids"] if t in label_set})
        if not techniques:
            continue
        if done_families.get(name, {}).get("resolved"):
            skipped += 1
            continue

        hashes: list[str] = []
        query_ok = True
        for sig in [name, *sw.get("aliases", [])]:
            found, ok = _mb_hashes_for_signature(sig, max_per_family, auth_key)
            hashes.extend(found)
            query_ok = query_ok and ok
            if len(hashes) >= max_per_family:
                break
            time.sleep(1)  # be polite to the API

        wanted = list(dict.fromkeys(hashes))[:max_per_family]
        for h in wanted:
            targets.setdefault(h, {"family": name, "techniques": techniques})
        # Only call a family done when every query behind it actually answered.
        family_status[name] = {"resolved": query_ok, "count": len(wanted)}
        if wanted:
            logger.info(f"[dataset] {name}: {len(wanted)} candidate samples")
        elif not query_ok:
            logger.warning(f"[dataset] {name}: unresolved (API error) — will retry on rerun")

    if skipped:
        logger.info(f"[dataset] skipped {skipped} already-resolved families")
    return targets, family_status


# ── Stage A phase 1: download only (network-bound, low memory, fully resumable) ──

def stage_a_download(
    max_per_family: int,
    apk_dir: str,
    download_workers: int,
    manifest_path: str,
    force_resolve: bool = False,
) -> dict[str, dict]:
    """
    Resolve every family's sample hashes, fetch the APKs, and persist the manifest.

    Kept deliberately free of Androguard: analysis is the memory-hungry part that can
    take the whole process down, so all downloads finish and land on disk first.

    Reruns are incremental — already-resolved families are not re-queried and existing
    APKs are not re-fetched. Pass force_resolve=True to sweep every family again.
    """
    if not os.path.exists(SOFTWARE_MAP_PATH):
        logger.error(f"[dataset] {SOFTWARE_MAP_PATH} missing — run scripts/build_ttp_label_space.py first.")
        return {}
    with open(SOFTWARE_MAP_PATH, "r", encoding="utf-8") as f:
        software_map = json.load(f)

    auth_key = settings.malwarebazaar_api_key

    # Merge into whatever a previous run already established. Overwriting the manifest
    # would drop samples whose family happens to error this time, even though their
    # APKs are on disk — and stage_a_analyze only ever looks at the manifest.
    prior = {} if force_resolve else _read_manifest(manifest_path)
    targets: dict[str, dict] = dict(prior.get("samples", {}))
    families: dict[str, dict] = dict(prior.get("families", {}))

    new_targets, new_status = _resolve_stage_a_targets(
        software_map, max_per_family, auth_key, done_families=families
    )
    targets.update(new_targets)
    families.update(new_status)

    if not targets:
        logger.error("[dataset] no candidate samples resolved from MalwareBazaar.")
        return {}

    os.makedirs(apk_dir, exist_ok=True)
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump({"samples": targets, "families": families}, f, indent=2)
    unresolved = [n for n, s in families.items() if not s.get("resolved")]
    logger.info(
        f"[dataset] manifest: {len(targets)} samples ({len(new_targets)} new), "
        f"{len(families) - len(unresolved)}/{len(families)} families resolved -> {manifest_path}"
    )

    # Only fetch what is not already on disk; _mb_download_apk also re-checks.
    pending = _missing_samples(targets, apk_dir)
    logger.info(f"[dataset] {len(targets) - len(pending)} already downloaded, {len(pending)} to fetch")
    _download_many(pending, apk_dir, auth_key, download_workers)

    missing = _missing_samples(targets, apk_dir)
    have = len(targets) - len(missing)
    logger.info(f"[dataset] download phase: {have}/{len(targets)} samples on disk")
    if unresolved:
        logger.warning(
            f"[dataset] {len(unresolved)} families still unresolved, rerun to retry just these: {unresolved}"
        )
    if missing:
        logger.warning(
            f"[dataset] {len(missing)} samples still missing — rerun the download phase "
            f"to retry them (existing files are skipped): {[h[:12] for h in missing[:10]]}"
        )
    return targets


# ── Stage A phase 2: analysis only (CPU/memory-bound, reads what phase 1 fetched) ──

def stage_a_analyze(apk_dir: str, manifest_path: str) -> list[dict]:
    """Extract features for every downloaded sample named in the manifest."""
    targets = _read_manifest(manifest_path).get("samples", {})
    if not targets:
        logger.error(f"[dataset] no manifest at {manifest_path} — run --phase download first.")
        return []

    rows: list[dict] = []
    for sha256, info in targets.items():
        apk_path = os.path.join(apk_dir, f"{sha256}.apk")
        if not os.path.exists(apk_path):
            continue  # never downloaded; the download phase reports these
        try:
            extracted = extract_ttp_row(apk_path)
        except Exception as e:
            # Anchor matching, topology and feature building sit outside the guards
            # inside extract_ttp_row and can raise on malformed or packed APKs.
            # One bad sample must not destroy a multi-hour run.
            logger.exception(f"[dataset] analysis failed for {sha256[:12]}: {e}")
            continue
        if extracted is None:
            continue
        vec, meta = extracted
        techniques = set(info["techniques"])
        rows.append(_row_dict(vec, techniques, "stix_ref", meta["sha256"], info["family"]))
        logger.info(
            f"[dataset] stage A row {len(rows)}: {info['family']} "
            f"{meta['sha256'][:12]} techniques={sorted(techniques)}"
        )
    return rows


# ── Stage B: weak-labeled CICMalDroid2020 / local APKs ──

def stage_b(cic_dir: str) -> list[dict]:
    if not cic_dir or not os.path.isdir(cic_dir):
        logger.warning(f"[dataset] CIC dir '{cic_dir}' not found — skipping stage B.")
        return []
    label_set = set(TTP_LABELS)
    rows: list[dict] = []
    apks = [os.path.join(cic_dir, f) for f in os.listdir(cic_dir) if f.endswith(".apk")]
    for apk_path in apks:
        try:
            extracted = extract_ttp_row(apk_path)
        except Exception as e:
            logger.exception(f"[dataset] analysis failed for {os.path.basename(apk_path)}: {e}")
            continue
        if extracted is None:
            continue
        vec, meta = extracted
        techniques: set[str] = set()
        for behavior in meta["matched_behaviors"]:
            techniques.update(BEHAVIOR_TO_TTPS.get(behavior, []))
        techniques &= label_set
        if not techniques:
            continue  # no weak signal -> not a useful positive row
        rows.append(_row_dict(vec, techniques, "weak", meta["sha256"], "cicmaldroid"))
        logger.info(f"[dataset] stage B row: {meta['sha256'][:12]} weak techniques={sorted(techniques)}")
    return rows


def main():
    ap = argparse.ArgumentParser(description="Build the multi-label TTP training dataset.")
    ap.add_argument("--stage", choices=["a", "b", "all"], default="all")
    ap.add_argument("--max-per-family", type=int, default=15)
    ap.add_argument("--apk-dir", default="data/ttp_apks")
    ap.add_argument("--cic-dir", default="data/cicmaldroid_apks")
    ap.add_argument("--out", default=OUT_CSV)
    ap.add_argument(
        "--download-workers", type=int, default=8,
        help="Concurrent MalwareBazaar downloads (default 8). Lower it if abuse.ch rate-limits you.",
    )
    ap.add_argument(
        "--phase", choices=["download", "analyze", "both"], default="both",
        help="Stage A only. 'download' fetches APKs and writes the manifest; 'analyze' "
             "runs Androguard over what was fetched. Split them so an analysis crash "
             "never costs you the downloads.",
    )
    ap.add_argument(
        "--manifest", default=None,
        help=f"Manifest path (default: <apk-dir>/{MANIFEST_NAME}).",
    )
    ap.add_argument(
        "--force-resolve", action="store_true",
        help="Re-query MalwareBazaar for every family, ignoring the manifest's "
             "already-resolved markers (default: retry only families that errored).",
    )
    args = ap.parse_args()

    logger.info(
        "[dataset] NOTE: check whether DroidTTP has released a public dataset before "
        "reconstructing — prefer it if available."
    )

    manifest_path = _manifest_path(args.apk_dir, args.manifest)

    if args.stage in ("a", "all") and args.phase in ("download", "both"):
        stage_a_download(
            args.max_per_family, args.apk_dir, args.download_workers, manifest_path,
            force_resolve=args.force_resolve,
        )

    if args.phase == "download":
        logger.info("[dataset] download phase complete — rerun with --phase analyze.")
        return

    rows: list[dict] = []
    if args.stage in ("a", "all"):
        rows += stage_a_analyze(args.apk_dir, manifest_path)
    if args.stage in ("b", "all"):
        rows += stage_b(args.cic_dir)

    if not rows:
        logger.error("[dataset] No rows produced. Nothing written.")
        return

    columns = TTP_FEATURE_NAMES + TTP_LABELS + ["label_source", "sha256", "source_family"]
    df = pd.DataFrame(rows, columns=columns)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    df.to_csv(args.out, index=False)
    pos_per_label = {t: int(df[t].sum()) for t in TTP_LABELS if df[t].sum() > 0}
    logger.info(f"[dataset] Wrote {len(df)} rows x {len(columns)} cols -> {args.out}")
    logger.info(f"[dataset] Labels with >=1 positive: {len(pos_per_label)} -> {pos_per_label}")


if __name__ == "__main__":
    main()
