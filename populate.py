import glob, os, requests

APK_DIRS = ["data/benign_apks", "data/ttp_apks"]
apks = []
for d in APK_DIRS:
    apks.extend(glob.glob(os.path.join(d, "*.apk")))

print(f"Found {len(apks)} APKs across {APK_DIRS}")

for i, path in enumerate(apks, 1):
    name = os.path.basename(path)
    try:
        with open(path, "rb") as f:
            resp = requests.post(
                "http://127.0.0.1:8000/analyze",
                files={"file": (name, f, "application/vnd.android.package-archive")},
                timeout=600,
            )
        print(f"[{i}/{len(apks)}] {name}: {resp.status_code}")
    except Exception as e:
        print(f"[{i}/{len(apks)}] {name}: ERROR {e}")
