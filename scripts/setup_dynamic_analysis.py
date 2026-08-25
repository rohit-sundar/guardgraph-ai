"""
One-time (and re-runnable) setup checker/fixer for the opt-in dynamic-analysis
feature (Android emulator + Frida — see app/analysis/dynamic_verification.py
and app/analysis/frida_scripts/README.md). Written so a teammate — or an AI
assistant acting on a teammate's behalf — can get this working WITHOUT
guessing paths, without a Frida client/server version mismatch, and without
skipping the network-containment step.

What this script CAN safely automate on its own:
  - Detect the Android SDK, adb, and any running AVD.
  - Detect the installed `frida` Python client's exact version and download
    the MATCHING frida-server build for the connected device's real ABI
    (the #1 real-world source of "frida could not attach" failures), push it,
    and start it.
  - Build the compiled Frida agent (`npm install && npm run build`).
  - Check (never silently apply) whether the required Windows Firewall
    containment rules exist.
  - Check whether `.env` has DYNAMIC_ANALYSIS_ENABLED set.

What it deliberately does NOT do:
  - Install Android Studio / the SDK itself, or create an AVD from scratch —
    those are large, one-time, human-supervised downloads (multi-GB) that
    should not run unattended inside an AI agent's tool loop.
  - Apply the firewall rules itself — those require Administrator and are a
    security-relevant action a human should run and see, not something a
    script should silently do on someone's machine.

Usage:
    python scripts/setup_dynamic_analysis.py            # check + fix what's safe
    python scripts/setup_dynamic_analysis.py --check-only

Exit code 0 = ready to set DYNAMIC_ANALYSIS_ENABLED=true and go; nonzero =
read the printed summary, one or more steps still need a human.
"""
from __future__ import annotations

import argparse
import lzma
import os
import platform
import re
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FRIDA_SCRIPTS_DIR = REPO_ROOT / "app" / "analysis" / "frida_scripts"
ENV_FILE = REPO_ROOT / ".env"

# Mirrors app/core/config.py's dynamic-verification defaults — kept in sync
# by hand since this script must run before the app's own settings import
# chain is guaranteed to work (e.g. before .env even has a Neo4j password).
DEFAULT_ADB_SERVER_PORT = 5039
FRIDA_SERVER_DEVICE_PATH = "/data/local/tmp/frida-server"

# adb's `ro.product.cpu.abi` values -> Frida's release-asset arch names.
ABI_TO_FRIDA_ARCH = {
    "x86_64": "x86_64",
    "x86": "x86",
    "arm64-v8a": "arm64",
    "armeabi-v7a": "arm",
}


class Result:
    def __init__(self):
        self.checks: list[tuple[str, str, str]] = []  # (name, status, detail)

    def add(self, name: str, status: str, detail: str = ""):
        # status: "OK", "FIXED", "WARN", "FAIL"
        self.checks.append((name, status, detail))
        icon = {"OK": "[OK]", "FIXED": "[FIXED]", "WARN": "[WARN]", "FAIL": "[FAIL]"}[status]
        print(f"{icon} {name}" + (f" — {detail}" if detail else ""))

    def ok(self) -> bool:
        return all(s in ("OK", "FIXED", "WARN") for _, s, _ in self.checks)


def run(cmd: list[str], timeout: int = 30, env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)


def find_android_sdk() -> Path | None:
    for var in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        val = os.environ.get(var)
        if val and Path(val).exists():
            return Path(val)
    # Common default locations, since PATH entries for the SDK are commonly
    # one directory short of the real thing (confirmed on the dev machine).
    candidates = [
        Path.home() / "AppData/Local/Android/Sdk",   # Windows
        Path.home() / "Library/Android/sdk",          # macOS
        Path.home() / "Android/Sdk",                  # Linux
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


def find_adb(sdk_root: Path | None) -> Path | None:
    exe = "adb.exe" if platform.system() == "Windows" else "adb"
    if sdk_root:
        # Handles both the modern platform-tools/ layout and the
        # platform-tools-latest-windows/platform-tools/ double-nesting that
        # tripped this project up before (see app/core/config.py's
        # _default_adb_path docstring).
        for candidate in sdk_root.glob(f"**/platform-tools*/{exe}"):
            if candidate.is_file():
                return candidate
    found = shutil.which("adb")
    return Path(found) if found else None


def adb_env() -> dict:
    env = os.environ.copy()
    env["ANDROID_ADB_SERVER_PORT"] = str(env.get("ADB_SERVER_PORT", DEFAULT_ADB_SERVER_PORT))
    return env


def get_connected_device(adb: Path) -> str | None:
    try:
        out = run([str(adb), "devices"], env=adb_env()).stdout
    except Exception:
        return None
    for line in out.strip().splitlines()[1:]:
        parts = line.split()
        if len(parts) == 2 and parts[1] == "device":
            return parts[0]
    return None


def get_frida_client_version() -> str | None:
    try:
        import frida  # type: ignore
        return frida.__version__
    except ImportError:
        return None


def get_device_abi(adb: Path, serial: str) -> str | None:
    try:
        out = run([str(adb), "-s", serial, "shell", "getprop", "ro.product.cpu.abi"], env=adb_env()).stdout
        return out.strip() or None
    except Exception:
        return None


def frida_server_running(adb: Path, serial: str) -> bool:
    try:
        out = run([str(adb), "-s", serial, "shell", "pidof", "frida-server"], env=adb_env())
        return bool(out.stdout.strip())
    except Exception:
        return False


def download_and_install_frida_server(adb: Path, serial: str, frida_version: str, arch: str, result: Result) -> bool:
    asset = f"frida-server-{frida_version}-android-{arch}.xz"
    url = f"https://github.com/frida/frida/releases/download/{frida_version}/{asset}"
    dest_xz = REPO_ROOT / "bin" / asset
    dest_bin = dest_xz.with_suffix("")  # strip .xz
    dest_xz.parent.mkdir(parents=True, exist_ok=True)

    try:
        if not dest_bin.exists():
            print(f"    downloading {url} ...")
            urllib.request.urlretrieve(url, dest_xz)
            with lzma.open(dest_xz, "rb") as f_in, open(dest_bin, "wb") as f_out:
                f_out.write(f_in.read())
        run([str(adb), "-s", serial, "push", str(dest_bin), FRIDA_SERVER_DEVICE_PATH], timeout=60, env=adb_env())
        run([str(adb), "-s", serial, "shell", "chmod", "+x", FRIDA_SERVER_DEVICE_PATH], env=adb_env())
        # Fire-and-forget, matching dynamic_verification.py's own
        # _ensure_frida_server_running — `adb shell "cmd &"` under
        # subprocess.run() hangs even though the device backgrounds the
        # command correctly (confirmed live), so this must NOT wait for exit.
        #
        # `su 0` is required, not cosmetic, and must stay identical to
        # _ensure_frida_server_running's invocation: a plain `adb shell`
        # starts frida-server as uid 2000 (shell), which cannot ptrace into
        # another app's process. That server binds its port and answers
        # `pidof` perfectly well, so this script reported a green
        # "frida-server running" while every actual attach failed with
        # "unable to access process with pid N" — confirmed live on a fresh
        # API 33 google_apis AVD. A false green here is worse than a failure,
        # because the runtime's own self-heal then sees a live pid and
        # declines to restart it as root.
        subprocess.Popen(
            [str(adb), "-s", serial, "shell", f"su 0 {FRIDA_SERVER_DEVICE_PATH}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=adb_env(),
        )
        import time
        time.sleep(2)
        if frida_server_running(adb, serial):
            result.add("frida-server running on device", "FIXED", f"v{frida_version} ({arch})")
            return True
        result.add("frida-server running on device", "FAIL",
                    "pushed and started, but pidof still finds nothing — check `adb shell` manually")
        return False
    except Exception as e:
        result.add("frida-server install", "FAIL", f"{e} — see manual steps in frida_scripts/README.md")
        return False


def build_frida_agent(result: Result):
    hooks_js = FRIDA_SCRIPTS_DIR / "hooks.js"
    agent_js = FRIDA_SCRIPTS_DIR / "_agent.js"
    if not hooks_js.exists():
        result.add("Frida agent build", "FAIL", f"{hooks_js} not found — is app/analysis/frida_scripts/ present?")
        return
    # Freshness is checked BEFORE npm is required, because npm is a build-time
    # dependency needed only when a rebuild is actually warranted — demanding it
    # to validate an already-committed artifact blocks setup for no reason.
    # `>=`, not `>`: git stamps every file it checks out with the same mtime, so
    # a fresh clone or merge lands _agent.js and hooks.js on an identical
    # timestamp. Strict `>` reads that tie as "stale" and sends anyone without
    # Node down a rebuild path they don't need (confirmed live on a merge).
    if agent_js.exists() and agent_js.stat().st_mtime >= hooks_js.stat().st_mtime:
        result.add("Frida agent build", "OK", "_agent.js already up to date")
        return
    npm = shutil.which("npm")
    if not npm:
        result.add("Frida agent build", "FAIL",
                    "npm not found on PATH — hooks.js is newer than the compiled _agent.js, so this "
                    "genuinely needs a rebuild: install Node.js (nodejs.org), then re-run this script")
        return
    try:
        node_modules = FRIDA_SCRIPTS_DIR / "node_modules"
        if not node_modules.exists():
            print("    npm install ...")
            run(["npm", "install"], timeout=180, env=os.environ.copy())  # cwd set below via cwd kwarg
        print("    npm run build ...")
        r = subprocess.run(["npm", "run", "build"], cwd=str(FRIDA_SCRIPTS_DIR),
                            capture_output=True, text=True, timeout=120)
        if r.returncode == 0 and agent_js.exists():
            result.add("Frida agent build", "FIXED", "_agent.js compiled from hooks.js")
        else:
            result.add("Frida agent build", "FAIL", r.stderr.strip()[-400:])
    except Exception as e:
        result.add("Frida agent build", "FAIL", str(e))


def check_firewall_rules(result: Result):
    if platform.system() != "Windows":
        result.add("Network containment (firewall)", "WARN",
                    "this script's automated check is Windows-only — on macOS/Linux, block the emulator "
                    "process's outbound egress with your platform's firewall (pfctl/iptables) by hand; "
                    "see app/analysis/frida_scripts/README.md for what to block and why")
        return
    try:
        proc = run(["powershell", "-NoProfile", "-Command",
                    "Get-NetFirewallRule -DisplayName 'Block Android Emulator Egress*' "
                    "| Select-Object -ExpandProperty DisplayName"], timeout=15)
        # Get-NetFirewallRule itself requires elevation just to READ rules on
        # this machine (confirmed live: "Access is denied" from a non-admin
        # PowerShell) — that failure means "couldn't check", not "rules don't
        # exist". Conflating the two would tell someone to re-apply rules
        # that are actually already there, which is confusing, not harmful,
        # but still wrong — so these are reported as distinct outcomes.
        if proc.returncode != 0 or "access is denied" in (proc.stderr or "").lower():
            result.add("Network containment (firewall)", "WARN",
                        "could not check — reading firewall rules itself needs Administrator on this "
                        "machine. Re-run this script from an elevated PowerShell/terminal to actually "
                        "verify, or check by hand: Get-NetFirewallRule -DisplayName "
                        "'Block Android Emulator Egress*' from an Administrator prompt. If you've never "
                        "run the two `New-NetFirewallRule` commands in "
                        "app/analysis/frida_scripts/README.md, do that first (also Administrator).")
            return
        names = set(line.strip() for line in proc.stdout.splitlines() if line.strip())
        have_qemu = any("qemu" in n.lower() for n in names)
        have_netsimd = any("netsimd" in n.lower() for n in names)
        if have_qemu and have_netsimd:
            result.add("Network containment (firewall)", "OK", "both rules present")
        else:
            missing = []
            if not have_qemu:
                missing.append("qemu-system-x86_64.exe")
            if not have_netsimd:
                missing.append("netsimd.exe")
            result.add("Network containment (firewall)", "WARN",
                        f"missing rule(s) for: {', '.join(missing)} — run the two `New-NetFirewallRule` "
                        f"commands in app/analysis/frida_scripts/README.md AS ADMINISTRATOR before "
                        f"enabling dynamic analysis for real. dynamic_verification.py will still refuse "
                        f"to install an APK if it measures egress as reachable, but that's a live "
                        f"per-run probe, not a substitute for this.")
    except Exception as e:
        result.add("Network containment (firewall)", "WARN", f"could not query firewall rules: {e}")


def check_env_flag(result: Result):
    if not ENV_FILE.exists():
        result.add(".env DYNAMIC_ANALYSIS_ENABLED", "WARN",
                    f"{ENV_FILE} does not exist yet — copy .env.example to .env first")
        return
    text = ENV_FILE.read_text(encoding="utf-8", errors="replace")
    m = re.search(r"^DYNAMIC_ANALYSIS_ENABLED=(\S+)", text, re.MULTILINE)
    if m and m.group(1).lower() == "true":
        result.add(".env DYNAMIC_ANALYSIS_ENABLED", "OK", "already true")
    else:
        result.add(".env DYNAMIC_ANALYSIS_ENABLED", "WARN",
                    "not set to true — the feature is a no-op regardless of any per-request flag until "
                    "this is set. Not changed automatically (it's a real behavior switch); "
                    "set it yourself in .env when you're ready, after the firewall rules are applied.")


def main():
    # Windows consoles commonly default to a legacy codepage (cp1252/cp437)
    # that can't render the em-dashes this script's messages use, silently
    # mangling them into "?" or garbage bytes — confirmed live. Force UTF-8
    # if the runtime supports it (Python 3.7+); harmless no-op elsewhere.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check-only", action="store_true",
                         help="report status without downloading/installing/building anything")
    args = parser.parse_args()

    result = Result()
    print("GuardGraph AI — dynamic-analysis setup check\n" + "=" * 60)

    sdk_root = find_android_sdk()
    if sdk_root:
        result.add("Android SDK", "OK", str(sdk_root))
    else:
        result.add("Android SDK", "FAIL",
                    "not found via ANDROID_HOME/ANDROID_SDK_ROOT or common default paths — install "
                    "Android Studio (https://developer.android.com/studio), or set ANDROID_HOME yourself")
        _print_summary(result)
        sys.exit(1)

    adb = find_adb(sdk_root)
    if adb:
        result.add("adb", "OK", str(adb))
    else:
        result.add("adb", "FAIL", f"no adb(.exe) found under {sdk_root} — install the 'Android SDK "
                    "Platform-Tools' package via Android Studio's SDK Manager")
        _print_summary(result)
        sys.exit(1)

    serial = get_connected_device(adb)
    if serial:
        result.add("AVD / device connected", "OK", serial)
    else:
        result.add("AVD / device connected", "FAIL",
                    "`adb devices` shows nothing — boot an AVD first. List existing ones with "
                    f"`{sdk_root / 'emulator' / ('emulator.exe' if platform.system() == 'Windows' else 'emulator')} "
                    "-list-avds`, or create one via Android Studio's Device Manager: API 30, "
                    "'google_apis' (NOT 'google_apis_playstore' — that image is read-only, Frida can't "
                    "inject), x86_64. Boot with `emulator -avd <name> -no-snapshot "
                    "-gpu swiftshader_indirect` if hardware GPU passthrough is unreliable on this machine.")
        _print_summary(result)
        sys.exit(1)

    frida_version = get_frida_client_version()
    if frida_version:
        result.add("frida Python client", "OK", f"v{frida_version}")
    else:
        result.add("frida Python client", "FAIL",
                    "not installed — `pip install -r requirements.txt` should have covered this; "
                    "if not, `pip install frida frida-tools`")
        _print_summary(result)
        sys.exit(1)

    abi = get_device_abi(adb, serial)
    frida_arch = ABI_TO_FRIDA_ARCH.get(abi or "")
    if not frida_arch:
        result.add("Device ABI", "FAIL", f"unrecognized ABI {abi!r} — expected one of {list(ABI_TO_FRIDA_ARCH)}")
        _print_summary(result)
        sys.exit(1)
    result.add("Device ABI", "OK", f"{abi} -> frida arch '{frida_arch}'")

    if frida_server_running(adb, serial):
        result.add("frida-server running on device", "OK")
    elif args.check_only:
        result.add("frida-server running on device", "WARN", "not running (--check-only, not installing)")
    else:
        print("  frida-server not running — downloading the matching build and installing it...")
        download_and_install_frida_server(adb, serial, frida_version, frida_arch, result)

    if args.check_only:
        agent_js = FRIDA_SCRIPTS_DIR / "_agent.js"
        if agent_js.exists():
            result.add("Frida agent build", "OK" if agent_js.stat().st_mtime >=
                        (FRIDA_SCRIPTS_DIR / "hooks.js").stat().st_mtime else "WARN",
                        "" if agent_js.exists() else "not built")
        else:
            result.add("Frida agent build", "WARN", "_agent.js missing (--check-only, not building)")
    else:
        build_frida_agent(result)

    check_firewall_rules(result)
    check_env_flag(result)

    _print_summary(result)
    sys.exit(0 if result.ok() else 1)


def _print_summary(result: Result):
    print("\n" + "=" * 60)
    fails = [n for n, s, _ in result.checks if s == "FAIL"]
    warns = [n for n, s, _ in result.checks if s == "WARN"]
    if not fails and not warns:
        print("All checks passed. Set DYNAMIC_ANALYSIS_ENABLED=true in .env (if not already) and go —")
        print("test with: curl -X POST \"http://localhost:8000/analyze?enable_dynamic=true\" "
              "-F \"file=@data/ttp_apks/<some_sample>.apk\"")
    else:
        if fails:
            print(f"BLOCKED on: {', '.join(fails)} — see [FAIL] lines above for exact next steps.")
        if warns:
            print(f"Needs your attention (not auto-fixed on purpose): {', '.join(warns)}")
        print("\nFull setup + troubleshooting guide: app/analysis/frida_scripts/README.md")


if __name__ == "__main__":
    main()
