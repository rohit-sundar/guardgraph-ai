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
  Stage C (benign negatives) — for local clean APKs, emit all-zero label rows
      (label_source="benign"). Stages A and B produce positives only, which is what
      taught the model label priors instead of evidence: an all-zeros feature vector
      still predicted 9 techniques at >= 0.5. A classifier that has never been shown a
      clean app has never been asked to say "no". Source 150-300 from F-Droid, APKPure
      top charts, or AndroZoo's vt_detection=0 slice.

Feature extraction reuses the SAME analysis functions the cold path uses and calls
`build_ttp_feature_vector`, so training columns line up exactly with inference. Keep
`extract_ttp_row` in sync with the pipeline's Phase-4 TTP vector construction.

    * First check whether DroidTTP has since released its dataset — prefer it if so. *

Usage:
    python scripts/build_ttp_dataset.py --stage a --max-per-family 15
    python scripts/build_ttp_dataset.py --stage b --cic-dir data/cicmaldroid_apks
    python scripts/build_ttp_dataset.py --stage c --benign-dir data/benign_apks
    python scripts/build_ttp_dataset.py --stage all
    python scripts/build_ttp_dataset.py --stage a --download-workers 16   # faster network
"""
import argparse
import csv
import datetime
import io
import functools
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

from app.analysis.ingest import ingest_apk, compute_sha256  # noqa: E402
from app.analysis.cfg import build_all_method_cfgs  # noqa: E402
from app.analysis.forensic import (  # noqa: E402
    ManifestContext,
    match_anchors,
    extract_anchor_subgraph,
)
from app.analysis.topology import (  # noqa: E402
    compute_topological_invariants,
    aggregate_subgraph_invariants,
)
from app.analysis.obfuscation import build_obfuscation_signal  # noqa: E402
from app.ml.features import build_ttp_feature_vector, TTP_FEATURE_NAMES  # noqa: E402
from app.ml.labels import TTP_LABELS  # noqa: E402
from app.core.config import settings  # noqa: E402

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SOFTWARE_MAP_PATH = "data/ontology/software_technique_map.json"
DERIVED_MAP_PATH = "data/ontology/derived_family_map.json"
OUT_CSV = "data/ttp_dataset.csv"
MB_API = "https://mb-api.abuse.ch/api/v1/"
# Written by the download phase, read by the analysis phase: carries each sample's
# family + ATT&CK techniques so analysis never has to re-query MalwareBazaar.
MANIFEST_NAME = "_manifest.json"
LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")


def _setup_logging(phase: str) -> str:
    """
    Tee the run to a timestamped file in logs/ alongside the console.

    A crash during analysis (a large CFG can OOM the process) takes the terminal
    with it, so the on-screen progress is gone. The file sink is what survives, and
    together with the manifest it tells you exactly which samples still need work on
    resume. enqueue=False keeps loguru flushing each record, so a hard crash loses
    at most the line in flight rather than a buffer's worth of history.
    """
    os.makedirs(LOGS_DIR, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = os.path.join(LOGS_DIR, f"build_ttp_dataset_{phase}_{ts}.log")
    # Loguru's default stderr sink is DEBUG, and androguard logs every DEX map_item
    # it parses through the same logger. Over a multi-hour corpus run that is not
    # noise you scroll past — measured on this corpus, stderr grew 140 MB/min and
    # projected to ~7 GB for one stage, on a disk with 25 GB free. (The repo already
    # carries a 17 GB overnight_stage_c.log from exactly this.) Replace the default
    # sink with an INFO one; the file sink below was already INFO, so nothing that
    # was ever worth keeping is lost.
    logger.remove()
    logger.add(sys.stderr, level="INFO")
    logger.add(log_path, level="INFO", enqueue=False, backtrace=True, diagnose=False)
    logger.info(f"[dataset] logging this run to {log_path}")
    return log_path

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
        ingestion, apk_obj, dvm, analysis_obj, _yara_targets = ingest_apk(apk_path)
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
    # Same manifest gate the cold path applies (N1) — training rows must be built
    # from the rules inference will actually run, or the behavior columns lie.
    manifest = ManifestContext.from_ingestion(ingestion)

    for g in cfgs.values():
        for _, data in g.nodes(data=True):
            all_strings.extend(data.get("string_literals", []))
            all_apis.update(data.get("api_calls", []))
        matches = match_anchors(g, manifest)
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
        dex_method_count=ingestion.dex_method_count,
        declared_component_count=(
            len(ingestion.activities) + len(ingestion.services)
            + len(ingestion.receivers)
        ),
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
    total = len(hashes)
    paths: dict[str, str] = {}
    logger.info(f"[dataset] fetching {total} samples with {workers} workers")
    with ThreadPoolExecutor(max_workers=min(workers, total)) as pool:
        futures = {
            pool.submit(_mb_download_apk, h, dest_dir, auth_key): h for h in hashes
        }
        # as_completed is drained on this thread, so the counter needs no lock.
        for done, fut in enumerate(as_completed(futures), 1):
            h = futures[fut]
            try:
                apk_path = fut.result()
            except Exception as e:  # _mb_download_apk swallows its own errors; belt and braces
                logger.warning(f"[dataset] MB download worker failed for {h}: {e}")
                apk_path = None
            if apk_path:
                paths[h] = apk_path
                logger.info(f"[dataset] [{done}/{total}] ok   {h[:12]} ({len(paths)} on disk)")
            else:
                logger.warning(f"[dataset] [{done}/{total}] fail {h[:12]}")
    logger.info(f"[dataset] downloaded {len(paths)}/{total} samples ({workers} workers)")
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


# ATT&CK software names carry qualifiers that MalwareBazaar signatures do not:
# the ontology says "SpyNote RAT", "S.O.V.A.", "Pegasus for Android"; the bazaar
# tags samples "SpyNote", "SOVA", "Pegasus". The `aliases` field does not rescue
# this -- in data/ontology/software_technique_map.json it is almost always just
# [name]. Measured 2026-08-21: querying names and aliases alone reaches 15
# families and 142 APKs, while adding these variants reaches 23 families and 523
# APKs. That gap is the real content of the manifest's "96 families returned zero
# Android samples", which is a name-matching artefact, not the bazaar's answer.
_SIGNATURE_SUFFIXES = (
    " RAT", " Trojan", " Banker", " Bot", " Malware", " Spyware", " Stealer",
)


def _signature_variants(name: str, aliases: list[str]) -> list[str]:
    """MalwareBazaar signature strings worth trying, most specific first.

    Order matters: the caller stops as soon as it has enough hashes, so the
    unmodified name must come first and the lossiest variant (first word) last.
    """
    out: list[str] = []
    for base in [name, *aliases]:
        candidates = [base]
        for suffix in _SIGNATURE_SUFFIXES:
            if base.endswith(suffix):
                candidates.append(base[: -len(suffix)].strip())
        if any(ch in base for ch in ". -"):
            candidates.append(base.replace(".", "").replace(" ", "").replace("-", ""))
        if " " in base:
            candidates.append(base.split()[0])
        for candidate in candidates:
            if candidate and candidate not in out:
                out.append(candidate)
    return out




@functools.lru_cache(maxsize=1)
def _derived_family_names() -> frozenset:
    """Names whose ATT&CK techniques were inherited rather than STIX-sourced."""
    if not os.path.exists(DERIVED_MAP_PATH):
        return frozenset()
    with open(DERIVED_MAP_PATH, "r", encoding="utf-8") as f:
        return frozenset(d["name"] for d in json.load(f).get("families", []))


def _expand_with_derived_families(software_map: list[dict]) -> tuple[list[dict], set[str]]:
    """
    Adds modern Android bankers that MalwareBazaar carries but ATT&CK has no
    software entry for, each inheriting its parent entry's technique_ids.

    Why this exists: MalwareBazaar is exhausted for MITRE-named families (measured
    2026-08-25 - every one returned fewer samples than asked for except Cerberus),
    so the only route to a larger, MORE DIVERSE malware corpus is families ATT&CK
    has not catalogued. Hydra, Coper, Alien, ERMAC, Hook, Octo and Vultur are ~427
    available samples of current banking trojans, which is precisely the threat
    this project targets.

    The inheritance is by documented code lineage, not loose analogy - Alien/ERMAC/
    Hook are Cerberus forks, Octo/Coper are Exobot descendants - and every entry
    carries its own `basis` and `confidence` in the JSON. Rows built from these are
    stamped label_source='lineage_ref' rather than 'stix_ref', so the training set
    can always be split back into MITRE-sourced and lineage-inferred labels. That
    distinction is the whole reason this is acceptable: the provenance claim stays
    honest because it is recorded per row, not asserted globally.

    A derived family whose parent is missing from software_map is skipped with a
    warning rather than silently dropped - it would otherwise download samples that
    can never be labelled.
    """
    if not os.path.exists(DERIVED_MAP_PATH):
        return software_map, set()
    with open(DERIVED_MAP_PATH, "r", encoding="utf-8") as f:
        spec = json.load(f)
    by_name = {e["name"]: e for e in software_map}
    added, names = [], set()
    for d in spec.get("families", []):
        parent = by_name.get(d["parent"])
        if not parent:
            logger.warning(
                f"[dataset] derived family {d['name']}: parent '{d['parent']}' not in "
                "software_map - skipping, it could never be labelled."
            )
            continue
        added.append({
            "software_id": f"DERIVED-{d['name']}",
            "name": d["name"],
            "aliases": [],
            "technique_ids": list(parent["technique_ids"]),
        })
        names.add(d["name"])
    if added:
        logger.info(
            f"[dataset] +{len(added)} lineage-derived families "
            f"({', '.join(sorted(names))}) inheriting their parent's techniques."
        )
    return software_map + added, names


def _resolve_stage_a_targets(
    software_map: list[dict],
    max_per_family: int,
    auth_key: str,
    done_families: dict[str, dict] | None = None,
    per_family_caps: dict[str, int] | None = None,
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
    The exception: a family whose done_families count is already below its
    per_family_caps target is retried anyway (only that name, at its own cap) —
    this is what lets a top-up run raise an existing family's count without
    --force-resolve re-sweeping all of software_map.

    per_family_caps overrides max_per_family for named entries (see
    scripts/family_targets.py, which computes this from per-class sample
    targets). Unlisted names keep the flat max_per_family default —
    passing None here is exactly today's behavior.
    """
    done_families = done_families or {}
    per_family_caps = per_family_caps or {}
    label_set = set(TTP_LABELS)
    targets: dict[str, dict] = {}
    family_status: dict[str, dict] = {}
    skipped = 0

    for sw in software_map:
        name = sw["name"]
        techniques = sorted({t for t in sw["technique_ids"] if t in label_set})
        if not techniques:
            continue
        effective_cap = per_family_caps.get(name, max_per_family)
        prior = done_families.get(name, {})
        if prior.get("resolved") and prior.get("count", 0) >= effective_cap:
            skipped += 1
            continue

        hashes: list[str] = []
        query_ok = True
        matched_sig = name
        for sig in _signature_variants(name, sw.get("aliases", [])):
            found, ok = _mb_hashes_for_signature(sig, effective_cap, auth_key)
            if found and not hashes:
                matched_sig = sig
            hashes.extend(found)
            query_ok = query_ok and ok
            if len(hashes) >= effective_cap:
                break
            time.sleep(1)  # be polite to the API

        wanted = list(dict.fromkeys(hashes))[:effective_cap]
        for h in wanted:
            targets.setdefault(h, {"family": name, "techniques": techniques})
        # Only call a family done when every query behind it actually answered.
        family_status[name] = {
            "resolved": query_ok, "count": len(wanted), "signature": matched_sig,
        }
        if wanted:
            logger.info(
                f"[dataset] {name}: {len(wanted)} candidate samples"
                + (f" (as '{matched_sig}')" if matched_sig != name else "")
            )
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
    per_family_caps: dict[str, int] | None = None,
) -> dict[str, dict]:
    """
    Resolve every family's sample hashes, fetch the APKs, and persist the manifest.

    Kept deliberately free of Androguard: analysis is the memory-hungry part that can
    take the whole process down, so all downloads finish and land on disk first.

    Reruns are incremental — already-resolved families are not re-queried and existing
    APKs are not re-fetched. Pass force_resolve=True to sweep every family again.

    per_family_caps (see --max-per-family-map) overrides max_per_family per named
    entry — see _resolve_stage_a_targets for how a family under its cap is retried
    without needing force_resolve.
    """
    if not os.path.exists(SOFTWARE_MAP_PATH):
        logger.error(f"[dataset] {SOFTWARE_MAP_PATH} missing — run scripts/build_ttp_label_space.py first.")
        return {}
    with open(SOFTWARE_MAP_PATH, "r", encoding="utf-8") as f:
        software_map = json.load(f)
    software_map, _derived_names = _expand_with_derived_families(software_map)

    auth_key = settings.malwarebazaar_api_key

    # Merge into whatever a previous run already established. Overwriting the manifest
    # would drop samples whose family happens to error this time, even though their
    # APKs are on disk — and stage_a_analyze only ever looks at the manifest.
    prior = {} if force_resolve else _read_manifest(manifest_path)
    targets: dict[str, dict] = dict(prior.get("samples", {}))
    families: dict[str, dict] = dict(prior.get("families", {}))

    new_targets, new_status = _resolve_stage_a_targets(
        software_map, max_per_family, auth_key, done_families=families,
        per_family_caps=per_family_caps,
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


# ── Incremental CSV output ──

def dataset_columns() -> list[str]:
    return TTP_FEATURE_NAMES + TTP_LABELS + ["label_source", "sha256", "source_family"]


class IncrementalCsvWriter:
    """
    Append rows to the dataset CSV as each APK finishes, instead of once at the end.

    Analysis runs for hours and a single OOM used to discard every completed row.
    Writing per-sample means a crash costs you one APK. The file also doubles as the
    resume log: `completed` holds the sha256s already present, so a rerun skips them.

    Reopening an existing CSV whose header does not match the current feature set is
    refused — TTP_FEATURE_NAMES has changed before, and blindly appending would
    silently misalign every column in the older rows.
    """

    def __init__(self, path: str, columns: list[str], overwrite: bool = False):
        self.path = path
        self.columns = columns
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)

        resumable = os.path.exists(path) and os.path.getsize(path) > 0
        if resumable and overwrite:
            os.remove(path)
            resumable = False
            logger.warning(f"[dataset] --overwrite: discarded existing {path}")

        self.completed: set[str] = set()
        if resumable:
            self._check_header()
            self.completed = self._read_completed()
            logger.info(f"[dataset] resuming {path}: {len(self.completed)} rows already written")

        self._fh = open(path, "a", newline="", encoding="utf-8")
        self._writer = csv.DictWriter(self._fh, fieldnames=columns)
        if not resumable:
            self._writer.writeheader()
            self._fh.flush()
        self.written = 0

    def _check_header(self) -> None:
        with open(self.path, newline="", encoding="utf-8") as f:
            header = next(csv.reader(f), [])
        if header != self.columns:
            raise SystemExit(
                f"[dataset] {self.path} has {len(header)} columns but this build produces "
                f"{len(self.columns)}. Appending would corrupt the dataset — rerun with "
                f"--overwrite, or point --out at a new file."
            )

    def _read_completed(self) -> set[str]:
        try:
            with open(self.path, newline="", encoding="utf-8") as f:
                return {
                    r["sha256"].lower()
                    for r in csv.DictReader(f)
                    if r.get("sha256")
                }
        except Exception as e:
            logger.error(f"[dataset] could not read completed rows from {self.path}: {e}")
            return set()

    def is_done(self, sha256: str) -> bool:
        return sha256.lower() in self.completed

    def write(self, row: dict) -> None:
        self._writer.writerow(row)
        # flush() hands the bytes to the OS, which is what survives the process being
        # OOM-killed. fsync would only add protection against power loss, at a cost
        # paid on every row.
        self._fh.flush()
        self.completed.add(str(row["sha256"]).lower())
        self.written += 1

    def close(self) -> None:
        self._fh.close()

    def __enter__(self) -> "IncrementalCsvWriter":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


# ── Stage A phase 2: analysis only (CPU/memory-bound, reads what phase 1 fetched) ──

def stage_a_analyze(apk_dir: str, manifest_path: str, writer: IncrementalCsvWriter) -> int:
    """
    Extract features for every downloaded sample named in the manifest, writing each
    row to `writer` as it completes. Returns the number of rows written.
    """
    targets = _read_manifest(manifest_path).get("samples", {})
    if not targets:
        logger.error(f"[dataset] no manifest at {manifest_path} — run --phase download first.")
        return 0

    on_disk = [(h, i) for h, i in targets.items()
               if os.path.exists(os.path.join(apk_dir, f"{h}.apk"))]
    pending = [(h, i) for h, i in on_disk if not writer.is_done(h)]
    total = len(pending)
    logger.info(
        f"[dataset] stage A: {len(on_disk)}/{len(targets)} samples downloaded, "
        f"{len(on_disk) - total} already in CSV, {total} to analyse"
    )

    written = 0
    for idx, (sha256, info) in enumerate(pending, 1):
        apk_path = os.path.join(apk_dir, f"{sha256}.apk")
        # Log BEFORE analysis: if a heavy CFG OOM-kills the process, this line is the
        # last thing in the file and names the sample that did it.
        logger.info(f"[dataset] [{idx}/{total}] analysing {sha256[:12]} ({info['family']})")
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
        # Provenance is per row, not global: a family whose techniques were inherited
        # by documented lineage (see _expand_with_derived_families) is NOT a STIX
        # reference and must never claim to be one. Stamping it here is what lets the
        # dataset be split back into MITRE-sourced and lineage-inferred labels.
        source = "lineage_ref" if info["family"] in _derived_family_names() else "stix_ref"
        writer.write(_row_dict(vec, techniques, source, meta["sha256"], info["family"]))
        written += 1
        logger.info(
            f"[dataset] [{idx}/{total}] row written: {info['family']} "
            f"{meta['sha256'][:12]} techniques={sorted(techniques)}"
        )
    return written


# ── Stage B: weak-labeled CICMalDroid2020 / local APKs ──

def stage_b(cic_dir: str, writer: IncrementalCsvWriter) -> int:
    """Weak-label local APKs, writing each row as it completes. Returns rows written."""
    if not cic_dir or not os.path.isdir(cic_dir):
        logger.warning(f"[dataset] CIC dir '{cic_dir}' not found — skipping stage B.")
        return 0
    label_set = set(TTP_LABELS)
    apks = [os.path.join(cic_dir, f) for f in os.listdir(cic_dir) if f.endswith(".apk")]
    total = len(apks)
    logger.info(f"[dataset] stage B: {total} local APKs to consider")

    written = 0
    for idx, apk_path in enumerate(apks, 1):
        name = os.path.basename(apk_path)
        # These files are not named by hash, so hash first to honour the resume set —
        # a file read is trivial next to a full CFG build.
        try:
            if writer.is_done(compute_sha256(apk_path)):
                continue
        except Exception as e:
            logger.warning(f"[dataset] could not hash {name}: {e}")
            continue
        logger.info(f"[dataset] [{idx}/{total}] analysing {name}")
        try:
            extracted = extract_ttp_row(apk_path)
        except Exception as e:
            logger.exception(f"[dataset] analysis failed for {name}: {e}")
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
        writer.write(_row_dict(vec, techniques, "weak", meta["sha256"], "cicmaldroid"))
        written += 1
        logger.info(f"[dataset] stage B row: {meta['sha256'][:12]} weak techniques={sorted(techniques)}")
    return written


# ── Stage C: benign negatives (all-zero label rows) ──

def stage_c_benign(benign_dir: str, writer: IncrementalCsvWriter) -> int:
    """
    Emit an all-zero label row per clean APK. Returns rows written.

    Deliberately unlike stage B, which drops rows that produce no techniques: here a
    row with no positive labels IS the signal. These are the negatives the model needs
    to learn that an absence of evidence means "no technique", not "the usual ones".

    Nothing here verifies the APKs are actually clean — that is on whoever fills the
    directory. Mislabelled malware in this set teaches the model the exact opposite of
    the intended lesson, so prefer a source with a verdict attached (AndroZoo
    vt_detection=0) over "it looked fine on the store page".
    """
    if not benign_dir or not os.path.isdir(benign_dir):
        logger.warning(f"[dataset] benign dir '{benign_dir}' not found — skipping stage C.")
        return 0
    apks = [os.path.join(benign_dir, f) for f in os.listdir(benign_dir) if f.endswith(".apk")]
    total = len(apks)
    logger.info(f"[dataset] stage C: {total} benign APKs to consider")

    written = 0
    for idx, apk_path in enumerate(apks, 1):
        name = os.path.basename(apk_path)
        try:
            if writer.is_done(compute_sha256(apk_path)):
                continue
        except Exception as e:
            logger.warning(f"[dataset] could not hash {name}: {e}")
            continue
        logger.info(f"[dataset] [{idx}/{total}] analysing benign {name}")
        try:
            extracted = extract_ttp_row(apk_path)
        except Exception as e:
            logger.exception(f"[dataset] analysis failed for {name}: {e}")
            continue
        if extracted is None:
            continue
        vec, meta = extracted
        writer.write(_row_dict(vec, set(), "benign", meta["sha256"], "benign"))
        written += 1
        logger.info(f"[dataset] stage C row: {meta['sha256'][:12]} (all labels 0)")
    return written


def main():
    ap = argparse.ArgumentParser(description="Build the multi-label TTP training dataset.")
    ap.add_argument("--stage", choices=["a", "b", "c", "all"], default="all")
    ap.add_argument("--max-per-family", type=int, default=15)
    ap.add_argument("--apk-dir", default="data/ttp_apks")
    ap.add_argument("--cic-dir", default="data/cicmaldroid_apks")
    ap.add_argument(
        "--benign-dir", default="data/benign_apks",
        help="Directory of known-clean APKs for stage C. Each becomes an all-zero "
             "label row — the negative class the model currently has none of.",
    )
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
    ap.add_argument(
        "--max-per-family-map", default=None,
        help="Path to a JSON {family_name: cap} file overriding --max-per-family "
             "for named entries (default: None, every family uses the flat "
             "--max-per-family value — today's behavior, unchanged). See "
             "scripts/family_targets.py, which computes this file from per-class "
             "sample targets against data/ontology/software_technique_map.json.",
    )
    ap.add_argument(
        "--overwrite", action="store_true",
        help="Discard an existing --out CSV and rebuild it from scratch (default: "
             "append, skipping samples already present).",
    )
    args = ap.parse_args()

    _setup_logging(args.phase)
    logger.info(
        "[dataset] NOTE: check whether DroidTTP has released a public dataset before "
        "reconstructing — prefer it if available."
    )

    manifest_path = _manifest_path(args.apk_dir, args.manifest)

    per_family_caps = None
    if args.max_per_family_map:
        with open(args.max_per_family_map, "r", encoding="utf-8") as f:
            per_family_caps = json.load(f)
        logger.info(f"[dataset] loaded per-family caps for {len(per_family_caps)} names from {args.max_per_family_map}")

    if args.stage in ("a", "all") and args.phase in ("download", "both"):
        stage_a_download(
            args.max_per_family, args.apk_dir, args.download_workers, manifest_path,
            force_resolve=args.force_resolve, per_family_caps=per_family_caps,
        )

    if args.phase == "download":
        logger.info("[dataset] download phase complete — rerun with --phase analyze.")
        return

    columns = dataset_columns()
    written = 0
    with IncrementalCsvWriter(args.out, columns, overwrite=args.overwrite) as writer:
        if args.stage in ("a", "all"):
            written += stage_a_analyze(args.apk_dir, manifest_path, writer)
        if args.stage in ("b", "all"):
            written += stage_b(args.cic_dir, writer)
        if args.stage in ("c", "all"):
            written += stage_c_benign(args.benign_dir, writer)

    if not os.path.exists(args.out) or os.path.getsize(args.out) == 0:
        logger.error("[dataset] No rows produced. Nothing written.")
        return

    # Summarise from the file, not from this run's rows: on a resumed run most of the
    # dataset was written by earlier invocations and never passed through memory here.
    df = pd.read_csv(args.out)
    if df.empty:
        logger.error("[dataset] No rows produced. Nothing written.")
        return
    pos_per_label = {t: int(df[t].sum()) for t in TTP_LABELS if t in df and df[t].sum() > 0}
    logger.info(
        f"[dataset] Wrote {written} new rows this run; {len(df)} rows x "
        f"{len(df.columns)} cols total -> {args.out}"
    )
    logger.info(f"[dataset] Labels with >=1 positive: {len(pos_per_label)} -> {pos_per_label}")

    label_cols = [t for t in TTP_LABELS if t in df.columns]
    n_benign = int((df[label_cols].sum(axis=1) == 0).sum())
    if n_benign:
        logger.info(f"[dataset] Benign (all-zero label) rows: {n_benign}/{len(df)} ({n_benign / len(df):.1%})")
    else:
        logger.warning(
            "[dataset] No benign rows — every sample in this dataset is malware, so the "
            "trained model can only learn label priors. Add clean APKs with "
            "--stage c --benign-dir <dir> before training."
        )


if __name__ == "__main__":
    main()
