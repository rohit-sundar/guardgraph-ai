"""
GuardGraph AI — Test Ingestion/Upload Script

Sends the specified malware sample APK to the running FastAPI server's /analyze endpoint
and pretty-prints the JSON report.
"""
import json
import urllib.request
import urllib.parse
import sys
from pathlib import Path

APK_PATH = r"C:\Users\Admin\Downloads\guardgraph-ai\test_malware_samples\f651876e9185c206d770229b0cb312b7ae620225e0e6768709b93d4258bbbced.apk"
API_URL = "http://localhost:8000/analyze"


def upload_apk(apk_path: str, url: str):
    path = Path(apk_path)
    if not path.exists():
        print(f"Error: APK file not found at {apk_path}")
        return

    print(f"Uploading and analyzing: {path.name}...")
    
    # Construct multipart/form-data payload manually to avoid extra dependencies
    boundary = "----GuardGraphBoundary" + "1234567890"
    
    # Read the APK file bytes
    with open(path, "rb") as f:
        file_bytes = f.read()
        
    # Build multipart body
    body_parts = [
        f"--{boundary}".encode("utf-8"),
        f'Content-Disposition: form-data; name="file"; filename="{path.name}"'.encode("utf-8"),
        b"Content-Type: application/vnd.android.package-archive",
        b"",
        file_bytes,
        f"--{boundary}--".encode("utf-8"),
        b""
    ]
    
    body = b"\r\n".join(body_parts)
    
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
    req.add_header("Content-Length", str(len(body)))
    
    try:
        with urllib.request.urlopen(req, timeout=120) as response:
            if response.status == 200:
                result = json.loads(response.read().decode("utf-8"))
                print("\n=== Analysis Report ===")
                print(json.dumps(result, indent=2))
            else:
                print(f"Failed with HTTP status: {response.status}")
    except Exception as e:
        print(f"Error connecting to server or parsing response: {e}")


if __name__ == "__main__":
    apk_to_send = sys.argv[1] if len(sys.argv) > 1 else APK_PATH
    upload_apk(apk_to_send, API_URL)
