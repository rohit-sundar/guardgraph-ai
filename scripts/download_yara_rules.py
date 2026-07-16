"""
GuardGraph AI — Community YARA Rule Downloader

This script downloads community YARA rules (e.g. from Yara-Rules/rules on GitHub),
filters out rules that require the non-standard and deprecated 'androguard' YARA module,
and saves the pure-YARA/standard rules to `data/yara_rules/` for the scan engine to load.
"""
import io
import os
import re
import zipfile
import urllib.request
from pathlib import Path
from loguru import logger

# Default repository to download rules from (YARA-Rules community repo)
RULES_ZIP_URL = "https://github.com/Yara-Rules/rules/archive/refs/heads/master.zip"
TARGET_DIR = Path("data/yara_rules")


def download_and_extract_rules(url: str = RULES_ZIP_URL, target_dir: Path = TARGET_DIR):
    """
    Downloads the YARA rules ZIP, filters out non-standard modules,
    and writes them into the target directory.
    """
    target_dir.mkdir(parents=True, exist_ok=True)

    logger.info(f"Downloading YARA rules from: {url}")
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "GuardGraph-AI-YARA-Downloader"}
        )
        with urllib.request.urlopen(req, timeout=30) as response:
            zip_data = response.read()
    except Exception as e:
        logger.error(f"Failed to download YARA rules: {e}")
        return

    logger.info("Extracting and filtering rules...")
    skipped_androguard = 0
    copied_rules = 0

    # Read zip in memory
    with zipfile.ZipFile(io.BytesIO(zip_data)) as archive:
        for file_info in archive.infolist():
            if file_info.filename.endswith((".yar", ".yara")):
                try:
                    content = archive.read(file_info).decode("utf-8", errors="ignore")
                except Exception as e:
                    logger.warning(f"Could not read {file_info.filename}: {e}")
                    continue

                # Check if the rule imports non-standard/deprecated YARA modules like 'androguard'
                # We also check for 'cuckoo' just in case, but 'androguard' is the main one for mobile.
                if re.search(r'import\s+"androguard"', content) or re.search(r'import\s+"cuckoo"', content):
                    skipped_androguard += 1
                    continue

                # Generate clean destination filename
                orig_path = Path(file_info.filename)
                # Keep category prefix (e.g. mobile_malware, exploit, etc.)
                category = orig_path.parent.name
                dest_filename = f"community_{category}_{orig_path.name}"
                dest_path = target_dir / dest_filename

                try:
                    dest_path.write_text(content, encoding="utf-8")
                    copied_rules += 1
                except Exception as e:
                    logger.warning(f"Failed to write rule {dest_filename}: {e}")

    logger.info(
        f"YARA rules download & filter completed!\n"
        f"  - Downloaded and saved: {copied_rules} rules\n"
        f"  - Skipped (due to 'androguard' module import): {skipped_androguard} rules\n"
        f"  - Rules directory: {target_dir.resolve()}"
    )


if __name__ == "__main__":
    download_and_extract_rules()
