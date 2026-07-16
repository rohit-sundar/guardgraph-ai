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
"""
import argparse
import io
import json
import os
import sys
import time
import urllib.parse
import urllib.request
import zipfile

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

def _mb_hashes_for_signature(signature: str, limit: int, auth_key: str) -> list[str]:
    """Return APK sha256 hashes tagged with `signature` on MalwareBazaar."""
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
        return []
    if payload.get("query_status") != "ok":
        return []
    return [
        item["sha256_hash"]
        for item in payload.get("data", [])
        if str(item.get("file_type", "")).lower() == "apk"
    ]


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
            content_type = resp.headers.get("content-type", "")
            body = resp.read()
        if content_type.startswith("application/json"):
            logger.warning(f"[dataset] MB download rejected for {sha256}: {body[:200]!r}")
            return None
        with zipfile.ZipFile(io.BytesIO(body)) as zf:
            inner = zf.namelist()[0]
            with zf.open(inner, pwd=b"infected") as src, open(out_path, "wb") as dst:
                dst.write(src.read())
        return out_path
    except Exception as e:
        logger.warning(f"[dataset] MB download failed for {sha256}: {e}")
        return None


def stage_a(max_per_family: int, apk_dir: str) -> list[dict]:
    if not os.path.exists(SOFTWARE_MAP_PATH):
        logger.error(f"[dataset] {SOFTWARE_MAP_PATH} missing — run scripts/build_ttp_label_space.py first.")
        return []
    with open(SOFTWARE_MAP_PATH, "r", encoding="utf-8") as f:
        software_map = json.load(f)

    auth_key = settings.malwarebazaar_api_key
    label_set = set(TTP_LABELS)
    rows: list[dict] = []

    for sw in software_map:
        techniques = {t for t in sw["technique_ids"] if t in label_set}
        if not techniques:
            continue
        candidates = [sw["name"], *sw.get("aliases", [])]
        hashes: list[str] = []
        for sig in candidates:
            hashes.extend(_mb_hashes_for_signature(sig, max_per_family, auth_key))
            if len(hashes) >= max_per_family:
                break
            time.sleep(1)  # be polite to the API
        for h in list(dict.fromkeys(hashes))[:max_per_family]:
            apk_path = _mb_download_apk(h, apk_dir, auth_key)
            if not apk_path:
                continue
            extracted = extract_ttp_row(apk_path)
            if extracted is None:
                continue
            vec, meta = extracted
            rows.append(_row_dict(vec, techniques, "stix_ref", meta["sha256"], sw["name"]))
            logger.info(f"[dataset] stage A row: {sw['name']} {meta['sha256'][:12]} techniques={sorted(techniques)}")
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
        extracted = extract_ttp_row(apk_path)
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
    args = ap.parse_args()

    logger.info(
        "[dataset] NOTE: check whether DroidTTP has released a public dataset before "
        "reconstructing — prefer it if available."
    )

    rows: list[dict] = []
    if args.stage in ("a", "all"):
        rows += stage_a(args.max_per_family, args.apk_dir)
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
