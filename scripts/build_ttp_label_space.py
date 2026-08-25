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
import re
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
MITIGATIONS_OUT = os.path.join(OUT_DIR, "technique_mitigations.json")


def _attack_id(obj: dict) -> str | None:
    """Return the ATT&CK external_id (T####, TA####, S####) for a STIX object."""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return None


def _is_live(obj: dict) -> bool:
    """Skip deprecated/revoked objects."""
    return not obj.get("x_mitre_deprecated", False) and not obj.get("revoked", False)


# ATT&CK models "this technique should NOT be mitigated" as a mitigation of its own.
# It is a real ATT&CK concept but the opposite of an analyst action, and a report
# telling a bank's security team to "apply Do Not Mitigate" is nonsense. Dropped at
# generation so it can never reach the prompt.
MITIGATIONS_EXCLUDED = {"M1059"}

# Mitigation descriptions are catalogue prose written for the whole matrix, and one
# (M1013) runs to 2,665 characters. The report needs enough to say what the control
# means, not the full entry — and the prompt has a hard token budget that a handful
# of these would eat into for no added decision value.
MITIGATION_DESC_MAX = 600
_CITATION_RE = re.compile(r"\s*\(Citation:[^)]*\)")


def _clean_description(desc: str) -> str:
    """Strips ATT&CK's inline "(Citation: ...)" markers and caps length at a
    sentence boundary. The markers are footnote plumbing that means nothing in a
    triage report and would otherwise be quoted back by the model verbatim."""
    desc = _CITATION_RE.sub("", desc).strip()
    if len(desc) <= MITIGATION_DESC_MAX:
        return desc
    cut = desc[:MITIGATION_DESC_MAX]
    stop = cut.rfind(". ")
    return (cut[: stop + 1] if stop > 200 else cut.rstrip()) + " […]"


def build(url: str, stix_file: str | None = None) -> None:
    # A pinned local bundle beats a download when one is already vendored: it keeps
    # the generated ontology reproducible against a known ATT&CK version instead of
    # silently moving the day MITRE publishes, and it works with no network.
    if stix_file:
        print(f"[build_ttp_label_space] Reading local ATT&CK Mobile STIX:\n  {stix_file}")
        with open(stix_file, "r", encoding="utf-8") as fh:
            bundle = json.load(fh)
    else:
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

    # Mitigations. ATT&CK ships one `course-of-action` per mitigation plus a
    # `mitigates` relationship to every technique it covers. These are what let the
    # report's "Recommended Analyst Actions" cite a grounded MITRE control instead
    # of whatever the model invents — the same grounding technique citations already
    # get. A small set for Mobile (13) but densely linked (167 edges).
    mitigations: dict[str, dict] = {}
    for obj in objects:
        if obj.get("type") != "course-of-action" or not _is_live(obj):
            continue
        mid = _attack_id(obj)
        if mid and mid not in MITIGATIONS_EXCLUDED:
            mitigations[obj["id"]] = {
                "mitigation_id": mid,
                "name": obj.get("name", ""),
                "description": _clean_description(obj.get("description", "") or ""),
                "technique_ids": set(),
            }
    for obj in objects:
        if obj.get("type") != "relationship" or obj.get("relationship_type") != "mitigates":
            continue
        src, tgt = obj.get("source_ref", ""), obj.get("target_ref", "")
        if src in mitigations and tgt in stixid_to_techid:
            mitigations[src]["technique_ids"].add(stixid_to_techid[tgt])

    # A mitigation covering no live technique is dropped rather than written empty —
    # it would only add a node nothing can traverse to.
    mitigation_rows = [
        {**m, "technique_ids": sorted(m["technique_ids"])}
        for m in mitigations.values()
        if m["technique_ids"]
    ]
    mitigation_rows.sort(key=lambda m: m["mitigation_id"])

    os.makedirs(OUT_DIR, exist_ok=True)
    with open(MITIGATIONS_OUT, "w", encoding="utf-8") as f:
        json.dump(mitigation_rows, f, indent=2)
    with open(TECHNIQUES_OUT, "w", encoding="utf-8") as f:
        json.dump(techniques, f, indent=2)
    with open(SOFTWARE_MAP_OUT, "w", encoding="utf-8") as f:
        json.dump(software_map, f, indent=2)

    print(f"[build_ttp_label_space] Wrote {len(techniques)} techniques -> {TECHNIQUES_OUT}")
    print(f"[build_ttp_label_space] Wrote {len(software_map)} software->technique maps -> {SOFTWARE_MAP_OUT}")
    print(f"[build_ttp_label_space] Wrote {len(mitigation_rows)} mitigations -> {MITIGATIONS_OUT}")

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
    ap.add_argument("--stix-file", default=None,
                    help="Read a local mobile-attack.json instead of downloading "
                         "(e.g. ontology_kg/mobile-attack-19.1.json) — reproducible, and offline.")
    args = ap.parse_args()
    build(args.url, args.stix_file)
