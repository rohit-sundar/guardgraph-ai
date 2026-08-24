"""
Builds data/signatures/known_hashes.json from the malware corpus on disk.

Why this exists
---------------
Pillar 1 of the design is "deterministic threat identification using SHA-256 hashes
and certificate information", but the shipped database held nine placeholder hashes
(`a1b2c3d4…`), three placeholder certificates, and the SHA-256 of the **empty file**
— zero real entries, while 344 confirmed malware APKs sat in data/ttp_apks/. Every
deterministic hit in every corpus run therefore came from the live VirusTotal lookup,
which means the offline path was never exercised and the demo carried a third-party
rate limit it did not need.

This regenerates the file from data/ttp_apks/_manifest.json (sha256 -> family, written
by build_ttp_dataset.py at download time) plus the certificates read off the APKs.

Two exclusions, both load-bearing
---------------------------------
1. **The empty-file entry is removed, not de-rated.** Severity is never consulted when
   deciding known-malware status — pipeline.py does
   `is_known = any(m.match_type == "sha256" ...)`, match *type* only — so a 0-byte
   upload matching `e3b0c44298…` sets is_known_malware=True and jumps
   reputation_component from the 0.3 unknown prior to 0.95 no matter what severity
   says. The entry has to go.

2. **A certificate used by more than one family is never written.** Measured over the
   corpus, four thumbprints are shared across unrelated families — one signs 62 samples
   across nine of them — and reading their subject DNs identifies all four as the
   Android debug key (`CN=Android Debug`) or the AOSP test key
   (`CN=Android, android@android.com`). Those keys identify nobody. Shipping them would
   mean any debug-signed APK is reported as known malware; F-Droid builds are properly
   signed so the corpus shows no false positive today, but a bank's own internal test
   build usually is debug-signed, which is exactly the population that must not trip it.

   Certificates seen on only ONE sample are also skipped: the sample's own hash already
   covers it, and a single observation cannot distinguish an actor's key from a builder's.
   What ships is the intersection — unique to one family AND reused across >= 2 samples.

Usage:
    python scripts/build_signature_db.py                 # dry run, prints the diff
    python scripts/build_signature_db.py --apply         # writes the file
    python scripts/build_signature_db.py --verify        # check the file matches the corpus
"""
import argparse
import hashlib
import json
import os
import sys
import warnings
from collections import defaultdict

warnings.filterwarnings("ignore")
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

MANIFEST = "data/ttp_apks/_manifest.json"
APK_DIR = "data/ttp_apks"
DB_PATH = "data/signatures/known_hashes.json"

# A hash match on a confirmed corpus sample is maximal confidence in *identification*.
# One value for every entry rather than a per-family guess: the corpus carries no
# per-family severity data, and inventing a spread would be exactly the fabricated
# precision this script exists to remove.
SIGNATURE_SEVERITY = 0.95
CERT_SEVERITY = 0.85
MIN_CERT_SAMPLES = 2

# Subject common names that identify a build tool rather than an actor. Checked in
# addition to the multi-family rule, so a debug key that happens to appear under one
# family in a future corpus is still refused.
BUILD_TOOL_CNS = {"android debug", "android"}


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def collect(verify_hashes: bool):
    """Returns (hashes, certificates, notes) built from the corpus."""
    from loguru import logger
    logger.remove()
    from androguard.core.apk import APK
    from app.analysis.ingest import extract_cert_thumbprint
    from app.analysis.apk_static import extract_der_certificates
    from app.analysis.signatures import normalize_family_name

    manifest = json.load(open(MANIFEST, encoding="utf-8"))["samples"]
    notes = {"mismatched_hashes": [], "unparseable": 0}

    hashes = {}
    cert_families = defaultdict(set)
    cert_counts = defaultdict(int)
    cert_cn = {}

    for i, (sha, entry) in enumerate(sorted(manifest.items()), 1):
        path = os.path.join(APK_DIR, f"{sha}.apk")
        if not os.path.exists(path):
            continue

        if verify_hashes and sha256_file(path).lower() != sha.lower():
            notes["mismatched_hashes"].append(sha)
            continue

        raw_family = entry.get("family")
        # Store the normalised name: deterministic_family() normalises whatever is here
        # before it reaches the graph, so storing the raw form would mean the DB and the
        # graph disagree (e.g. "S.O.V.A." vs "S.O.V.A").
        family = normalize_family_name(raw_family) or raw_family
        hashes[sha.lower()] = {
            "family": family,
            "severity": SIGNATURE_SEVERITY,
            "source": "MalwareBazaar",
            "description": f"{family} — confirmed sample in the GuardGraph malware corpus",
        }

        try:
            apk = APK(path)
            thumb = (extract_cert_thumbprint(apk) or "").lower()
        except Exception:
            notes["unparseable"] += 1
            continue
        if not thumb:
            continue
        cert_families[thumb].add(family)
        cert_counts[thumb] += 1
        if thumb not in cert_cn:
            try:
                from asn1crypto import x509 as ax
                der = extract_der_certificates(apk)
                subject = ax.Certificate.load(der[0]).subject.native if der else {}
                cert_cn[thumb] = str(subject.get("common_name", "")).strip().lower()
            except Exception:
                cert_cn[thumb] = ""

        if i % 100 == 0:
            print(f"  read {i}/{len(manifest)}", flush=True)

    certificates = {}
    skipped = {"multi_family": 0, "build_tool_cn": 0, "single_sample": 0}
    for thumb, families in cert_families.items():
        if len(families) > 1:
            skipped["multi_family"] += 1
            continue
        if cert_cn.get(thumb, "") in BUILD_TOOL_CNS:
            skipped["build_tool_cn"] += 1
            continue
        if cert_counts[thumb] < MIN_CERT_SAMPLES:
            skipped["single_sample"] += 1
            continue
        family = next(iter(families))
        certificates[thumb] = {
            "family": family,
            "severity": CERT_SEVERITY,
            "source": "GuardGraph corpus",
            "description": (
                f"Signing certificate reused across {cert_counts[thumb]} {family} "
                "samples in the corpus"
            ),
        }
    notes["skipped_certs"] = skipped
    return hashes, certificates, notes


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apply", action="store_true", help="write the file (default: dry run)")
    ap.add_argument("--verify", action="store_true",
                    help="check the shipped DB still matches the corpus, then exit")
    ap.add_argument("--no-hash-check", action="store_true",
                    help="trust the manifest keys instead of re-hashing every APK")
    args = ap.parse_args()

    os.chdir(PROJECT_ROOT)
    if not os.path.exists(MANIFEST):
        print(f"ERROR: {MANIFEST} not found — nothing to build from.")
        return 1

    print(f"Reading {MANIFEST} and {APK_DIR}/ ...")
    hashes, certificates, notes = collect(verify_hashes=not args.no_hash_check)

    existing = {}
    if os.path.exists(DB_PATH):
        existing = json.load(open(DB_PATH, encoding="utf-8"))
    old_h = existing.get("hashes", {})
    old_c = existing.get("certificates", {})

    print(f"\n  hashes       {len(old_h):>4} -> {len(hashes):>4}")
    print(f"  certificates {len(old_c):>4} -> {len(certificates):>4}")
    print(f"  unparseable APKs (hash still recorded): {notes['unparseable']}")
    print(f"  hash mismatches vs manifest: {len(notes['mismatched_hashes'])}")
    s = notes["skipped_certs"]
    print(f"  certs skipped: {s['multi_family']} multi-family, "
          f"{s['build_tool_cn']} build-tool CN, {s['single_sample']} single-sample")

    dropped = [h for h in old_h if h not in hashes]
    if dropped:
        print(f"\n  dropping {len(dropped)} existing hash entries (placeholders/empty-file):")
        for h in dropped:
            print(f"    {h[:20]}…  {old_h[h].get('family')}")

    if args.verify:
        ok = set(old_h) == set(hashes) and set(old_c) == set(certificates)
        print("\nVERIFY:", "matches the corpus" if ok else "OUT OF DATE — re-run with --apply")
        return 0 if ok else 1

    if not args.apply:
        print("\nDry run. Re-run with --apply to write.")
        return 0

    payload = {
        "_comment": (
            "GuardGraph AI — known-malware signature database. GENERATED by "
            "scripts/build_signature_db.py from data/ttp_apks/_manifest.json; do not hand-edit. "
            "Certificates shared across families, signed with a build-tool key, or seen on a "
            "single sample are deliberately excluded — see the script docstring."
        ),
        "hashes": dict(sorted(hashes.items())),
        "certificates": dict(sorted(certificates.items())),
    }
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with open(DB_PATH, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    print(f"\nWrote {DB_PATH}: {len(hashes)} hashes, {len(certificates)} certificates.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
