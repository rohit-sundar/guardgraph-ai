"""
Quick diagnostic: run this to see what's actually inside your mobile-attack json.
Usage: python debug_mitre_json.py mobile-attack-19.1.json
"""
import json
import sys
from collections import Counter

with open(sys.argv[1], "r", encoding="utf-8") as f:
    bundle = json.load(f)

print("Top-level type:", type(bundle))
if isinstance(bundle, dict):
    print("Top-level keys:", list(bundle.keys()))
    objects = bundle.get("objects", [])
else:
    objects = bundle

print("Total objects:", len(objects))

type_counts = Counter(obj.get("type") for obj in objects)
print("\nObject type counts:")
for t, c in type_counts.most_common(20):
    print(f"  {t}: {c}")

# Show one attack-pattern's raw external_references so we see the real source_name
for obj in objects:
    if obj.get("type") == "attack-pattern":
        print("\nSample attack-pattern external_references:")
        print(json.dumps(obj.get("external_references", []), indent=2)[:800])
        print("\nSample attack-pattern kill_chain_phases:")
        print(json.dumps(obj.get("kill_chain_phases", []), indent=2))
        break

# Show one tactic's raw structure
for obj in objects:
    if obj.get("type") == "x-mitre-tactic":
        print("\nSample x-mitre-tactic:")
        print(json.dumps(obj, indent=2)[:800])
        break