"""
Build the MITRE ATT&CK Mobile TTP label space + ontology from the official STIX bundle.

Syncs the ATT&CK Mobile matrix from the public STIX data and emits a canonical
technique/tactic label space plus a software->technique map, used to build the
multi-label TTP training labels and the Neo4j ontology for GraphRAG grounding.

What it does (pure metadata, one network fetch):
  1. Downloads mobile-attack.json from mitre-attack/attack-stix-data.
  2. Parses techniques (attack-pattern), tactics (x-mitre-tactic), software
     (malware/tool), and `uses` relationships (software -> technique).
  3. Emits:
       data/ontology/mobile_techniques.json      technique_id, name, tactic, description, is_subtechnique
       data/ontology/software_technique_map.json  software_id, name, aliases, technique_ids
  4. Prints a suggested (sorted) TTP_LABELS set and reports how it overlaps with
     the frozen catalog in app/ml/labels.py — so a maintainer can consciously
     re-freeze the label contract before retraining (never auto-rewritten here).

Usage:
    python scripts/build_ttp_label_space.py
    python scripts/build_ttp_label_space.py --url <alternate mobile-attack.json url>
"""
import argparse
import json
import os
import sys
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.ml.labels import TTP_LABELS  # noqa: E402

DEFAULT_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/mobile-attack/mobile-attack.json"
)
OUT_DIR = "data/ontology"
TECHNIQUES_OUT = os.path.join(OUT_DIR, "mobile_techniques.json")
SOFTWARE_MAP_OUT = os.path.join(OUT_DIR, "software_technique_map.json")


def _attack_id(obj: dict) -> str | None:
    """Return the ATT&CK external_id (T####, TA####, S####) for a STIX object."""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return None


def _is_live(obj: dict) -> bool:
    """Skip deprecated/revoked objects."""
    return not obj.get("x_mitre_deprecated", False) and not obj.get("revoked", False)


def build(url: str) -> None:
    print(f"[build_ttp_label_space] Fetching ATT&CK Mobile STIX from:\n  {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "guardgraph-ttp/1.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        bundle = json.loads(resp.read().decode("utf-8"))
    objects = bundle.get("objects", [])
    print(f"[build_ttp_label_space] Parsed {len(objects)} STIX objects.")

    # tactic shortname (kill-chain phase_name) -> display name
    tactic_shortname_to_name: dict[str, str] = {}
    for obj in objects:
        if obj.get("type") == "x-mitre-tactic" and _is_live(obj):
            shortname = obj.get("x_mitre_shortname")
            if shortname:
                tactic_shortname_to_name[shortname] = obj.get("name", shortname)

    # techniques
    techniques: list[dict] = []
    stixid_to_techid: dict[str, str] = {}
    for obj in objects:
        if obj.get("type") != "attack-pattern" or not _is_live(obj):
            continue
        tech_id = _attack_id(obj)
        if not tech_id:
            continue
        stixid_to_techid[obj["id"]] = tech_id
        phases = obj.get("kill_chain_phases", [])
        tactic = ""
        if phases:
            shortname = phases[0].get("phase_name", "")
            tactic = tactic_shortname_to_name.get(shortname, shortname.replace("-", " ").title())
        techniques.append(
            {
                "technique_id": tech_id,
                "name": obj.get("name", ""),
                "tactic": tactic,
                "description": (obj.get("description", "") or "").strip(),
                "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique", False)),
            }
        )
    techniques.sort(key=lambda t: t["technique_id"])

    # software (malware + tool)
    software: dict[str, dict] = {}  # stix_id -> {software_id, name, aliases}
    for obj in objects:
        if obj.get("type") in ("malware", "tool") and _is_live(obj):
            software[obj["id"]] = {
                "software_id": _attack_id(obj) or "",
                "name": obj.get("name", ""),
                "aliases": obj.get("x_mitre_aliases", []) or [],
            }

    # `uses` relationships: software -> technique
    software_to_techs: dict[str, set[str]] = {}
    for obj in objects:
        if obj.get("type") != "relationship" or obj.get("relationship_type") != "uses":
            continue
        src = obj.get("source_ref", "")
        tgt = obj.get("target_ref", "")
        if src in software and tgt in stixid_to_techid:
            software_to_techs.setdefault(src, set()).add(stixid_to_techid[tgt])

    software_map = []
    for stix_id, meta in software.items():
        techs = sorted(software_to_techs.get(stix_id, set()))
        if not techs:
            continue
        software_map.append(
            {
                "software_id": meta["software_id"],
                "name": meta["name"],
                "aliases": meta["aliases"],
                "technique_ids": techs,
            }
        )
    software_map.sort(key=lambda s: s["software_id"])

    os.makedirs(OUT_DIR, exist_ok=True)
    with open(TECHNIQUES_OUT, "w", encoding="utf-8") as f:
        json.dump(techniques, f, indent=2)
    with open(SOFTWARE_MAP_OUT, "w", encoding="utf-8") as f:
        json.dump(software_map, f, indent=2)

    print(f"[build_ttp_label_space] Wrote {len(techniques)} techniques -> {TECHNIQUES_OUT}")
    print(f"[build_ttp_label_space] Wrote {len(software_map)} software->technique maps -> {SOFTWARE_MAP_OUT}")

    # Coverage report vs the frozen classifier contract (never auto-rewritten).
    live_parents = {t["technique_id"] for t in techniques if not t["is_subtechnique"]}
    frozen = set(TTP_LABELS)
    missing = sorted(frozen - live_parents)   # in our label set but not live (deprecated?)
    uncovered = sorted(live_parents - frozen)  # live techniques our label set omits
    print("\n[label-space coverage vs app/ml/labels.py TTP_LABELS]")
    print(f"  frozen labels: {len(frozen)} | live Mobile parent techniques: {len(live_parents)}")
    if missing:
        print(f"  ⚠ frozen labels NOT found live (review — may be deprecated/renamed): {missing}")
    if uncovered:
        print(f"  ℹ live techniques not in TTP_LABELS ({len(uncovered)}): {uncovered}")
    print(
        "\nTo re-freeze the contract: review the two lists above, edit _TECHNIQUE_CATALOG "
        "in app/ml/labels.py deliberately, then RETRAIN. This script never edits it for you."
    )


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Build ATT&CK Mobile TTP label space + ontology from STIX.")
    ap.add_argument("--url", default=DEFAULT_STIX_URL, help="mobile-attack.json URL")
    args = ap.parse_args()
    build(args.url)
