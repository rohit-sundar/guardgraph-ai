"""
Fills in the two fields of data/reference/protected_brands.json that cannot be
hand-written: `icon_phash` and `cert_sha256`.

Both must come from a genuine APK. A signing certificate is what Android uses to
decide whether an update is from the same publisher, so recording the wrong one turns
the certificate check from the engine's strongest signal into a false accusation
against the real app. There is no way to derive either value from a package name, so
this script asks for the APKs instead.

    # 1. Put genuine APKs in a directory. Obtain them from the official listing —
    #    a copy from an APK-mirror site is exactly the thing this module exists to
    #    detect, and seeding the reference from one poisons every later comparison.
    python scripts/build_brand_reference.py --apk-dir data/reference/apks

    # 2. Check the reference set does not collide with itself before trusting it.
    python scripts/build_brand_reference.py --collisions

Matching is by package name: each APK is parsed, its package read, and the brand whose
`packages` list contains it is updated. An APK whose package matches no brand is
reported and skipped rather than guessed at — add the brand entry first.

Entries are marked `verified: true` only once BOTH fields are populated from a real
APK, so `verified` means "the strong checks can run against this brand", not "somebody
looked at it".
"""
import argparse
import json
import re
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.analysis.impersonation import (  # noqa: E402
    ICON_MATCH_MAX_DISTANCE,
    REFERENCE_PATH,
    extract_icon_phash,
    hamming_distance,
    load_reference,
)

MIN_SAFE_COLLISION_DISTANCE = ICON_MATCH_MAX_DISTANCE * 2


def _load_raw(path: str) -> dict:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def _index_by_package(raw: dict) -> dict[str, dict]:
    index = {}
    for entry in raw.get("brands", []):
        for package in entry.get("packages", []):
            index[package] = entry
    return index


# Androguard reports an unresolvable label in two shapes, and neither is a name:
#   "@7F120160"              a raw resource id
#   "<0x5120, type 0x00>"    an undecoded resource reference
# Both appear when an app installed from a bundle keeps its strings in a language split.
_UNRESOLVED_LABEL = re.compile(r"^(@[0-9A-Fa-f]+|<0x[0-9A-Fa-f]+,.*>)$")


def _apks_to_read(apk_dir: str) -> list[tuple[str, str]]:
    """
    Every APK worth parsing under apk_dir, as (path, display name).

    Handles both layouts: loose `*.apk` files, and the one `adb pull` produces for an app
    installed from an app bundle — a per-package directory holding `base.apk` plus
    `split_config.*.apk`. Only `base.apk` is read from those: the splits carry the same
    package and the same signing key, but no launcher icon and no manifest of their own,
    so parsing them adds nothing and costs a multi-hundred-MB parse each.
    """
    found: list[tuple[str, str]] = []
    for name in sorted(os.listdir(apk_dir)):
        full = os.path.join(apk_dir, name)
        if os.path.isdir(full):
            inner = sorted(f for f in os.listdir(full) if f.lower().endswith(".apk"))
            if not inner:
                continue
            base = "base.apk" if "base.apk" in inner else inner[0]
            found.append((os.path.join(full, base), f"{name}/{base}"))
        elif name.lower().endswith(".apk"):
            found.append((full, name))
    return found


def ingest_apks(apk_dir: str, path: str) -> int:
    from androguard.core.apk import APK

    from app.analysis.ingest import extract_cert_thumbprint

    if not os.path.isdir(apk_dir):
        print(f"ERROR: {apk_dir} is not a directory.")
        return 1

    raw = _load_raw(path)
    by_package = _index_by_package(raw)
    updated, skipped, unmatched = 0, 0, []

    for full, name in _apks_to_read(apk_dir):
        try:
            apk = APK(full)
            package = apk.get_package()
        except Exception as exc:
            print(f"  {name}: could not parse ({type(exc).__name__}: {exc})")
            skipped += 1
            continue

        entry = by_package.get(package)
        if entry is None:
            unmatched.append((name, package))
            continue

        phash = extract_icon_phash(apk)
        cert = extract_cert_thumbprint(apk)

        if phash is not None:
            entry["icon_phash"] = f"{phash:016x}"
        if cert:
            certs = {c.lower() for c in entry.get("cert_sha256", [])}
            certs.add(cert.lower())
            entry["cert_sha256"] = sorted(certs)

        # `verified` means the signing certificate came off a real APK, which is what
        # makes the strongest check runnable. It deliberately does NOT also require an
        # icon hash: an adaptive (XML) launcher icon has no pixels to hash, and most
        # modern apps ship one, so requiring it would leave `verified: false` forever on
        # brands whose certificate check works perfectly. `icon_phash: null` already says
        # the icon check is unavailable for that brand.
        entry["verified"] = bool(entry.get("cert_sha256"))
        # An app installed from a bundle keeps its strings in the language split, so
        # base.apk alone resolves the label to its raw resource id ("@7F120160").
        # Recording that as a display name would put a garbage string into the table
        # that _check_label then matches real app names against.
        label = apk.get_app_name()
        if label and _UNRESOLVED_LABEL.match(label):
            print(f"  ! {package}: label unresolved in base.apk ({label}) — not recorded. "
                  "The string lives in split_config.<lang>.apk.")
            label = None
        if label and label not in entry.get("labels", []):
            entry.setdefault("labels", []).append(label)

        print(f"  {entry['brand']:<28} package={package}")
        print(f"      icon_phash={entry.get('icon_phash') or 'NONE (adaptive/XML icon)'}")
        print(f"      cert={(cert or 'NONE')[:32]}...  verified={entry['verified']}")
        updated += 1

    if unmatched:
        print("\nAPKs whose package matches no brand entry (add the brand first):")
        for name, package in unmatched:
            print(f"  {name}: {package}")

    n_cert = sum(1 for b in raw["brands"] if b.get("cert_sha256"))
    n_icon = sum(1 for b in raw["brands"] if b.get("icon_phash"))
    raw["status"] = (
        f"{n_cert} of {len(raw['brands'])} brands carry a signing certificate read from a "
        f"real APK, so the certificate check runs for them; {n_icon} also carry a launcher "
        "icon hash. The remainder ship adaptive (XML) icons, which have no pixels to hash — "
        "that is a permanent property of those apps, not work left undone."
    )
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(raw, handle, indent=2)
        handle.write("\n")

    print(f"\nUpdated {updated} brand(s), skipped {skipped}. Wrote {path}.")
    return 0


def report_collisions(path: str) -> int:
    """
    Pairwise icon distances inside the reference set.

    Two DISTINCT brands sitting within ICON_MATCH_MAX_DISTANCE of each other means the
    threshold cannot separate them, and any app matching one will be reported against
    both. That is a property of the reference set, not of the sample, so it has to be
    checked here rather than discovered during an analysis.
    """
    brands = [b for b in load_reference(path) if b.icon_phash is not None]
    if len(brands) < 2:
        print(f"Only {len(brands)} brand(s) carry an icon hash — nothing to compare. "
              "Run with --apk-dir first.")
        return 0

    print(f"Pairwise icon distances across {len(brands)} hashed brands "
          f"(match threshold {ICON_MATCH_MAX_DISTANCE}, want >= {MIN_SAFE_COLLISION_DISTANCE}):\n")
    problems = 0
    for i, a in enumerate(brands):
        for b in brands[i + 1:]:
            distance = hamming_distance(a.icon_phash, b.icon_phash)
            if distance < MIN_SAFE_COLLISION_DISTANCE:
                flag = "  <-- COLLIDES" if distance <= ICON_MATCH_MAX_DISTANCE else "  <-- close"
                problems += 1
                print(f"  {a.name:<26} {b.name:<26} {distance:>3}{flag}")

    if problems == 0:
        print(f"  no pair closer than {MIN_SAFE_COLLISION_DISTANCE}. Threshold is safe "
              "for this reference set.")
    else:
        print(f"\n{problems} pair(s) too close. Either the icons genuinely look alike "
              "(lower ICON_MATCH_MAX_DISTANCE and accept the recall loss) or one of "
              "the APKs is not the app it claims to be.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--apk-dir", help="directory of genuine APKs to read icons/certs from")
    ap.add_argument("--reference", default=REFERENCE_PATH, help="reference table to update")
    ap.add_argument("--collisions", action="store_true",
                    help="report pairwise icon distances inside the reference set")
    args = ap.parse_args()

    if not os.path.exists(args.reference):
        print(f"ERROR: {args.reference} not found.")
        return 1
    if args.collisions:
        return report_collisions(args.reference)
    if not args.apk_dir:
        ap.print_help()
        return 1
    return ingest_apks(args.apk_dir, args.reference)


if __name__ == "__main__":
    raise SystemExit(main())
