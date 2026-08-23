"""
Computes per-family MalwareBazaar download caps from coarse-class sample targets.

`scripts/build_ttp_dataset.py --stage a` downloads by ATT&CK Mobile *software*
name (Anubis, Cerberus, Triada, ...), not by the coarse 6-class taxonomy
(banker/rat/keylogger/password_stealer/trojan/coinminer) the auxiliary family
classifier predicts (app/core/config.py MODEL_LABEL_MAP). No mapping between
the two existed in the repo. This script is that mapping, plus the arithmetic
to turn "we want ~200 banker samples" into "download this many more of each
real banker-type family name."

CLASS_TO_FAMILIES below is a best-effort categorization built by reading every
name in data/ontology/software_technique_map.json (126 entries as of writing)
against public threat-intel characterizations, excluding iOS-only entries
(Pegasus for iOS, XLoader for iOS, WireLurker, XcodeGhost, YiSpecter,
ZergHelper, INSOMNIA, TriangleDB — GuardGraph analyzes Android APKs only).
Some buckets (keylogger, password_stealer) have very few strong matches in this
catalog — most of MITRE's non-banker Android "software" entries are
APT/targeted-surveillance tools, and data/ttp_apks/_manifest.json already shows
most of those resolve to 0 samples on MalwareBazaar. Expect banker and trojan to
reach target easily; expect rat, keylogger and password_stealer to fall short —
this script reports the real shortfall it computed, not a promise it can close.

Usage:
    python scripts/family_targets.py
    python scripts/build_ttp_dataset.py --stage a --phase download \
        --max-per-family-map data/family_caps.json --download-workers 3
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from build_ttp_dataset import _manifest_path, _read_manifest  # noqa: E402

CLASS_TARGETS = {
    "banker": 200,
    "rat": 70,
    "keylogger": 50,
    "password_stealer": 50,
    "trojan": 50,
}

CLASS_TO_FAMILIES: dict[str, list[str]] = {
    "banker": [
        "Anubis", "Cerberus", "FluBot", "Ginp", "Gustuff", "Escobar", "EventBot",
        "Exobot", "Riltok", "Rotexy", "MazarBOT", "S.O.V.A.", "SharkBot",
        "TrickMo", "BRATA", "GodFather", "Crocodilus", "Asacub", "TangleBot",
        "Drinik", "Chameleon", "Fakecalls", "Red Alert 2.0",
    ],
    "rat": [
        "AndroRAT", "DroidJack", "SpyNote RAT", "X-Agent for Android", "HilalRAT",
        "RatMilad", "Monokle", "RCSAndroid", "Pegasus for Android", "FinFisher",
        "DCHSpy", "eSurv", "ViceLeaker", "GoldenEagle", "SilkBean", "WolfRAT",
        "VajraSpy", "CarbonSteal", "BOULDSPY", "HenBox", "Desert Scorpion",
        "FrozenCell", "GolfSpy", "SpyC23", "SpyDealer", "Skygofree",
        "Stealth Mango", "BusyGasper", "AhRat", "Sunbird", "Circles",
    ],
    "keylogger": [
        # Thin bucket on purpose — see module docstring. Most Android spyware in
        # this catalog performs keylogging as one behavior among several rather
        # than being keylogger-primary; these are the closest fits.
        "FlexiSpy", "Mandrake", "GPlayed", "CherryBlos", "DEFENSOR ID",
    ],
    "password_stealer": [
        # Also thin — see module docstring.
        "XLoader for Android", "Gooligan", "FakeSpy", "TianySpy", "RedDrop",
    ],
    "trojan": [
        "Triada", "Trojan-SMS.AndroidOS.Agent.ao", "Trojan-SMS.AndroidOS.FakeInst.a",
        "Trojan-SMS.AndroidOS.OpFake.a", "Agent Smith", "Bread", "Charger",
        "Dvmap", "NotCompatible", "RuMMS", "SimBad", "HummingBad", "HummingWhale",
        "OldBoot", "AbstractEmu", "DressCode", "DualToy", "PJApps",
        "Corona Updates", "Tangelo", "ANDROIDOS_ANSERVER.A", "CHEMISTGAMES",
        "TERRACOTTA", "Twitoor", "Tiktok Pro", "Xbot", "OBAD", "Zen",
        "Golden Cup", "SameCoin", "Concipit1248", "Binary Validator", "Allwinner",
        "Adups", "DoubleAgent", "Dendroid", "ShiftyBug", "FjordPhantom",
        "FlyTrap", "BrainTest",
    ],
}


def compute_family_caps(
    class_targets: dict[str, int],
    class_to_families: dict[str, list[str]],
    current_counts: dict[str, int],
) -> dict[str, int]:
    """
    For each class, split its remaining shortfall (target minus what's already
    resolved, summed across its constituent family names) evenly across those
    names, added on top of what each already has. A name already over its even
    share keeps its current count rather than being capped down — this only
    ever raises caps, never shrinks an existing download.
    """
    caps: dict[str, int] = {}
    for cls, target in class_targets.items():
        names = class_to_families.get(cls, [])
        if not names:
            continue
        have = sum(current_counts.get(n, 0) for n in names)
        shortfall = max(0, target - have)
        share = -(-shortfall // len(names))  # ceil division
        for n in names:
            caps[n] = current_counts.get(n, 0) + share
    return caps


def main():
    manifest_path = _manifest_path("data/ttp_apks")
    manifest = _read_manifest(manifest_path)
    current_counts = {
        name: info.get("count", 0) for name, info in manifest.get("families", {}).items()
    }

    caps = compute_family_caps(CLASS_TARGETS, CLASS_TO_FAMILIES, current_counts)

    out_path = "data/family_caps.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(caps, f, indent=2, sort_keys=True)

    print(f"Wrote {len(caps)} per-family caps to {out_path}\n")
    for cls, target in CLASS_TARGETS.items():
        names = CLASS_TO_FAMILIES.get(cls, [])
        have = sum(current_counts.get(n, 0) for n in names)
        will_request = sum(caps.get(n, 0) for n in names)
        print(
            f"  {cls:<17} target {target:>4}  |  have {have:>4}  |  "
            f"requesting up to {will_request:>4} across {len(names)} names"
        )
    print(
        "\n'requesting up to' is a ceiling, not a promise - MalwareBazaar may "
        "return fewer than asked for a given name. Re-run this script after "
        "the download phase completes to see the real shortfall against target."
    )


if __name__ == "__main__":
    main()
