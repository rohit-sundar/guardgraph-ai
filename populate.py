import glob, os, requests

APK_DIR = "data/ttp_apks"   # point this at tonight's 100 APKs
apks = glob.glob(os.path.join(APK_DIR, "*.apk"))
print(f"Found {len(apks)} APKs")

for i, path in enumerate(apks, 1):
    name = os.path.basename(path)
    try:
        with open(path, "rb") as f:
            resp = requests.post(
                "http://127.0.0.1:8000/analyze",
                files={"file": (name, f, "application/vnd.android.package-archive")},

                # Bulk population doesn't need per-APK prose, and the Ollama call
                # is the ~60-200s/request cost that made this loop impractical at
                # volume. Neo4j still gets the full sha256/family/TTPs/risk_score
                # write — skip_report only bypasses the narrative generation.
                params={"skip_report": "true"},
                timeout=600,
            )
        print(f"[{i}/{len(apks)}] {name}: {resp.status_code}")
    except Exception as e:
        print(f"[{i}/{len(apks)}] {name}: ERROR {e}")