# Dynamic-verification Frida agent

`hooks.js` is the source. `_agent.js` (committed, gitignored from this dir's
`node_modules/`) is the bundled output `dynamic_verification.py` actually loads
at runtime — Node/npm are a **build-time** dependency only, not a runtime one.

Frida 16+ stopped injecting `Java`/`ObjC` as ambient globals; the Java bridge
must be bundled into the agent via `frida-compile`. Confirmed working on this
machine 2026-08-23 (Frida 17.15.5 client/server, Node v24, npm 11).

Rebuild after editing `hooks.js`:
```
npm install
npm run build
```

## Containment — run this before ever enabling dynamic analysis for real

An AVD's default networking gives the guest real internet egress AND a route
to the **host's own loopback** via the `10.0.2.2` alias — an unconstrained
guest could reach this machine's other listening services (this API, Neo4j,
Ollama) or a real C2, not a sandboxed facsimile of the internet.

There is no reliable in-emulator kill switch on the build validated here:
`adb emu network disable` (the documented emulator-console command) returns
`KO: bad sub-command` — confirmed live, 2026-08-23. `dynamic_verification.py`
therefore probes real egress before every run and refuses to install the APK
if it looks reachable (`dynamic_analysis_require_network_isolation`, on by
default) — but that is a measurement, not a guarantee, and it cannot be
enforced from inside a Claude session without admin rights.

**Run this once, as Administrator**, to make isolation real instead of
probabilistic. The network-capable process turned out to be **two separate
executables, not one** — confirmed via `Get-Process`: `qemu-system-x86_64.exe`
(the emulator's CPU/device emulation, not `emulator.exe` itself) AND
`netsimd.exe` (a separate network-simulation daemon this emulator build
spawns) — traffic kept flowing through the second one even with the first
blocked, found live while validating containment. **Both rules are required**:

```powershell
New-NetFirewallRule -DisplayName "Block Android Emulator Egress (qemu)" `
  -Direction Outbound -Action Block `
  -Program "C:\Users\Admin\AppData\Local\Android\Sdk\emulator\qemu\windows-x86_64\qemu-system-x86_64.exe"

New-NetFirewallRule -DisplayName "Block Android Emulator Egress (netsimd)" `
  -Direction Outbound -Action Block `
  -Program "C:\Users\Admin\AppData\Local\Android\Sdk\emulator\netsimd.exe"
```

If `netsimd.exe` isn't at that path on your machine, find it with
`Get-Process netsimd | Select-Object Path` while the emulator is running and
use that path instead.

adb/Frida traffic between this machine and the AVD is unaffected — that
connection is host-initiated (adb connects into the guest, not the reverse),
and these rules only block the guest's own outbound egress.

**Verify both rules are actually in effect before trusting them**: with the
AVD running, `_egress_appears_blocked()` (in `dynamic_verification.py`) does
this same check every time via `toybox nc`, and `run_dynamic_verification`
refuses to install an APK if it measures as reachable — but you can also
check by hand from inside the guest shell (`adb shell`) that a real outbound
connection (e.g. `nc -w2 8.8.8.8 53`) times out rather than succeeding.

This does not blind the network-confirmation hook: `hookNetwork` in
`hooks.js` fires on the `java.net.InetSocketAddress(host, port)`
**constructor**, which every socket path (raw `Socket`, OkHttp,
`HttpURLConnection`) calls before any packet leaves the device — the confirm
signal is captured at the API call, not by observing real traffic. What it
does cost: a sample that gates its whole payload behind a successful
connectivity check first will read `not observed` for everything downstream
of that check. That is a real, reported coverage limitation, not a bug.

---

## Setting this up on a teammate's machine (one-time)

Everything below is currently **local, uncommitted work on Tarun's machine**
(see `TEAM_CONTEXT.md` Session 14) — if you've pulled `main`/this branch and
`app/analysis/dynamic_verification.py` doesn't exist yet, ask for it to be
pushed first. Once the code is there, here's how to make it actually run:

**1. Android SDK + an AVD.** Android Studio's SDK (`platform-tools` +
`emulator`) is enough; you don't need `cmdline-tools`/`sdkmanager` if you
already have a system image. Create one API 30 `google_apis` (NOT
`google_apis_playstore` — that image is read-only/non-rootable, Frida can't
inject) x86_64 AVD, then boot it once with software rendering first to
confirm it boots at all on your hardware before trying anything else:
```
emulator -avd <your_avd_name> -no-snapshot -gpu swiftshader_indirect
```

**2. `adb` reachable.** Check `adb devices` lists your AVD. If port 5037 is
unusable (Hyper-V reserves it as a dynamic exclusion range on some Windows
setups — check with `netsh int ipv4 show excludedportrange protocol=tcp`),
set `ADB_SERVER_PORT` / this project's `adb_server_port` setting (default
`5039`) to an open port instead, and make sure `.env`'s `ADB_PATH` points at
your real `adb.exe`/`adb` (see `_default_adb_path()` in `app/core/config.py`
— it searches `ANDROID_HOME`/`ANDROID_SDK_ROOT`, but confirm it actually
found the right binary since PATH entries for the SDK are commonly one
directory short of the real thing).

**3. `frida-server` on the device**, matching your **frida Python client's
major version** and the AVD's ABI (x86_64 for the image above):
```
adb push frida-server /data/local/tmp/frida-server
adb shell chmod +x /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &     # dynamic_verification.py self-heals if this dies later
```
`pip install frida` gives you the matching client; download the server build
from Frida's GitHub releases for the exact same version number.

**4. Build the compiled agent** (Node + npm needed at build time only):
```
cd app/analysis/frida_scripts
npm install
npm run build          # regenerates _agent.js from hooks.js
```

**5. Apply the containment firewall rules above** (both of them —
`qemu-system-x86_64.exe` AND `netsimd.exe`) before ever setting
`enable_dynamic=true` against anything you don't already trust.

**6. Turn it on.** In `.env`, set `DYNAMIC_ANALYSIS_ENABLED=true` (off by
default — the whole feature is a no-op without this, regardless of any
per-request flag). Everything else in `app/core/config.py`'s dynamic-analysis
block has a working default (30s capture window, network-isolation
requirement, etc.) — only change those if you know why.

## How to actually see a dynamic-analysis result

`/analyze` (or `/analyze/start` + `/analyze/stream/{job_id}` for the web UI's
live progress bar) both accept `?enable_dynamic=true` as a query parameter —
it's OFF unless you pass it explicitly, on every single request, even with
`DYNAMIC_ANALYSIS_ENABLED=true` in `.env`:

```bash
curl -X POST "http://localhost:8000/analyze?enable_dynamic=true" \
  -F "file=@data/ttp_apks/<some_sample>.apk"
```

or through the web UI (`http://localhost:8000/`): upload as normal, but check
the "Enable dynamic analysis" toggle before hitting analyze (it adds
`?enable_dynamic=true` to the same `/analyze/start` call under the hood).
Expect it to take **tens of seconds to ~1 minute** (install, launch, a
30-second capture window, teardown) — this is why it's opt-in and never on
the default path.

Once it's run, the result shows up:
- **In the web UI**: a new "🧪 Dynamic Verification" tab appears on the
  report (hidden entirely if dynamic analysis didn't run for this request) —
  per-signal CONFIRMED/REFUTED/not-observed rows, the event timeline, up to 3
  screenshots, and (if the process crashed mid-capture) a logcat panel.
- **Via the API directly**: `dynamic_verification` on the returned
  `AnalysisManifest` — `ran`, `network_confirmed`,
  `screenshot_reaction_url`/`screenshot_url`/`event_screenshots`,
  `native_library_confirmed`, `crash_logcat_tail`, etc. Full field list in
  `app/core/schemas.py`'s `DynamicVerificationResult`.
- **In Neo4j** (`http://localhost:7474`): a confirmed C2 contact sets
  `dynamically_confirmed = true` on that sample's `CONTACTS` relationship to
  the `C2Indicator` node — query it directly:
  ```cypher
  MATCH (s:Sample)-[r:CONTACTS]->(ci:C2Indicator)
  RETURN s.app_name, ci.value, r.dynamically_confirmed
  ```
  `null` on that property means the sample hasn't been (re-)analyzed since
  this feature existed, not "checked and found nothing" — see
  `TEAM_CONTEXT.md` Session 14 for the full explanation and a real bug this
  distinction surfaced.

## Troubleshooting

- **"no launcher activity" / `monkey` exits 252**: expected for pure
  background/receiver-only malware — `dynamic_verification.py` now falls
  back to broadcasting the app's own declared intent-filter actions instead
  of failing outright (see Session 14). If it still fails, that sample
  genuinely has no externally-triggerable entry point.
- **`frida could not attach`**: check `adb shell pidof frida-server` — if
  empty, it died; `_ensure_frida_server_running()` restarts it automatically
  on the *next* run, but won't retroactively fix the one that just failed.
- **AVD egress refuses to measure as blocked**: re-check both firewall
  rules are applied to the exact binary paths on *your* machine (they differ
  per Android SDK install location) — `Get-Process qemu-system-x86_64,
  netsimd | Select-Object Path` while the emulator is running gives the real
  paths to use.
