"""
Re-derives a protected brand's identity from an APK you have verified is genuine.

`data/reference/protected_brands.json` is the table every impersonation check
compares against, and a stale entry fails in both directions at once. Measured on
2026-08-27 against the Bank of India evaluation set, where the table listed
`com.boi.ua.android` / `com.boi.erupee.prod` and one icon hash while the app the
bank actually ships is `com.boi.mpay`:

    genuine BOI Mobile icon   9e399ee3991ae105   hamming 26 to the stored hash
    clone sample 2            7226d9b6265989a7   hamming 40
    clone sample 3            d9a6099ba64949b7   hamming 34
    clone sample 4            736319c3260959f7   hamming 42   (threshold is 8)

So the real app was reported for impersonating its own brand, while three clones
carrying BOI artwork matched nothing. Hand-editing the JSON fixes one row and
leaves the next stale entry to be found the same way; this reads the facts out of
a known-good APK so the fix is repeatable.

    python scripts/refresh_brand_reference.py --brand "Bank of India" \\
        --apk evaluation/5_Boi_Mobile.apk

    python scripts/refresh_brand_reference.py --brand "Bank of India" \\
        --apk evaluation/5_Boi_Mobile.apk --write

Prints the diff by default and touches nothing; `--write` applies it. The APK is
an assertion by the operator that this build is genuine — the script cannot
verify that and does not pretend to, which is why nothing is written without the
flag.
"""
import argparse
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from loguru import logger

from app.analysis.apk_container import ApkContainer
from app.analysis.apk_static import extract_der_certificates
from app.analysis.impersonation import (
    REFERENCE_PATH,
    extract_icon_phash,
    extract_icon_phash_from_container,
)

logger.remove()
logger.add(sys.stderr, level="WARNING")


def read_apk_identity(apk_path: str) -> dict:
    """Package, label, signing certificate and launcher icon hash."""
    from androguard.core.apk import APK

    out: dict = {"apk": os.path.basename(apk_path)}
    apk_obj = None
    try:
        apk_obj = APK(apk_path)
    except Exception as e:
        print(f"  ! manifest parse failed ({e}) — falling back to the container")

    if apk_obj is not None:
        out["package"] = apk_obj.get_package() or None
        try:
            out["label"] = apk_obj.get_app_name() or None
        except Exception:
            out["label"] = None
        certs = extract_der_certificates(apk_obj)
        out["cert_sha256"] = [hashlib.sha256(c).hexdigest() for c in certs]
        phash = extract_icon_phash(apk_obj)
        out["icon_phash"] = f"{phash:016x}" if phash is not None else None
    else:
        out["package"] = out["label"] = None
        out["cert_sha256"] = []
        out["icon_phash"] = None

    if not out.get("icon_phash"):
        container = ApkContainer(apk_path)
        phash = extract_icon_phash_from_container(container)
        out["icon_phash"] = f"{phash:016x}" if phash is not None else None

    return out


def merge(entry: dict, identity: dict) -> tuple[dict, list[str]]:
    """
    Additive merge. Existing packages, labels, certificates and icon hashes are
    never dropped — a brand's older apps are still that brand's apps, and
    removing one would make its clones invisible, which is the failure this
    script exists to fix rather than to relocate.
    """
    changes: list[str] = []
    updated = json.loads(json.dumps(entry))  # deep copy

    pkg = identity.get("package")
    if pkg and pkg not in updated.get("packages", []):
        updated.setdefault("packages", []).append(pkg)
        changes.append(f"+ package {pkg}")

    label = identity.get("label")
    if label and label not in updated.get("labels", []):
        updated.setdefault("labels", []).append(label)
        changes.append(f"+ label {label!r}")

    # Migrate a scalar icon_phash to the list shape on first touch.
    hashes = updated.get("icon_phashes")
    if hashes is None:
        legacy = updated.pop("icon_phash", None)
        hashes = [legacy] if legacy else []
        updated["icon_phashes"] = hashes
        if legacy:
            changes.append(f"~ icon_phash -> icon_phashes [{legacy}]")

    icon = identity.get("icon_phash")
    if icon and icon not in hashes:
        hashes.append(icon)
        changes.append(f"+ icon_phash {icon}")

    for cert in identity.get("cert_sha256", []):
        if cert not in [c.lower() for c in updated.get("cert_sha256", [])]:
            updated.setdefault("cert_sha256", []).append(cert)
            changes.append(f"+ cert {cert[:16]}…")

    if changes and not updated.get("verified"):
        updated["verified"] = True
        changes.append("~ verified -> true")

    return updated, changes


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--brand", required=True, help='exact brand name in the table')
    ap.add_argument("--apk", required=True, action="append",
                    help="a genuine APK for this brand; repeatable")
    ap.add_argument("--reference", default=REFERENCE_PATH)
    ap.add_argument("--write", action="store_true", help="apply the changes")
    args = ap.parse_args()

    with open(args.reference, encoding="utf-8") as fh:
        table = json.load(fh)

    entries = table.get("brands", [])
    idx = next(
        (i for i, e in enumerate(entries) if e.get("brand") == args.brand), None
    )
    if idx is None:
        print(f"No brand named {args.brand!r} in {args.reference}.")
        print("Known brands:", ", ".join(sorted(e.get("brand", "?") for e in entries)))
        return 1

    entry = entries[idx]
    print(f"{args.brand} — current entry:")
    print(json.dumps(entry, indent=2, ensure_ascii=False))

    all_changes: list[str] = []
    for apk in args.apk:
        if not os.path.exists(apk):
            print(f"  ! {apk} not found — skipped")
            continue
        print(f"\nreading {apk} ...")
        identity = read_apk_identity(apk)
        print(f"  package    {identity.get('package')}")
        print(f"  label      {identity.get('label')!r}")
        print(f"  icon       {identity.get('icon_phash')}")
        print(f"  certs      {[c[:16] + '…' for c in identity.get('cert_sha256', [])]}")
        entry, changes = merge(entry, identity)
        all_changes.extend(changes)

    if not all_changes:
        print("\nNothing to change — the table already covers this build.")
        return 0

    print("\nchanges:")
    for c in all_changes:
        print(f"  {c}")

    if not args.write:
        print("\nDry run. Re-run with --write to apply.")
        return 0

    entries[idx] = entry
    table["brands"] = entries
    with open(args.reference, "w", encoding="utf-8") as fh:
        json.dump(table, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    print(f"\nWrote {args.reference}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
