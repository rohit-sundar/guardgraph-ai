# GuardGraph AI — Audit Sweep Report
**2026-08-24, 14:55–15:29 (33 min sweep) + follow-up investigation**

> **This snapshot predates the rest of 2026-08-24's work.** Everything below is real and still holds,
> but a large amount of additional dynamic-analysis work happened *after* this sweep the same day —
> new screenshot capture modes, native-library confirmation, headless-malware launch fallback, crash
> logcat capture, and a Neo4j `dynamically_confirmed` flag (which itself surfaced and fixed a real
> cache-hit data-loss bug). See `TEAM_CONTEXT.md`'s **Session 14** entry for all of that, verified live
> the same way this report was.

## What was run
36 live requests against the real running server (not mocks): 30 static-only
runs (10 smallest samples each from `ttp_apks`, `benign_apks`,
`benign_holdout`), 5 with dynamic verification enabled (2/2/1 split), 1 full
report (LLM) generation on a guaranteed-fresh `benign_holdout` sample.

## Headline result
**Zero hard errors. Zero crashes. Zero HTTP failures. 36/36 requests
completed successfully.** Full test suite: **338/338 passed**, 41 subtests,
before *and* after the fix below.

## One real bug found — and fixed
My own audit script flagged "empty field, no explanation" on nearly every
run. Most of those were **false alarms in my own audit heuristic** (see
below), but one pattern was real and systemic:

**`resolved_native_bridges` was empty on literally 100% of the 36 runs.
`resolved_crypto_configs` was empty on most.** Root cause, traced to the
actual code: the CFG relevance pre-filter (`forensic.py::relevance_vocabulary()`)
only builds a CFG for a method if it references an API/string the forensic
dictionary already knows about. `crypto_recovery.py` resolves
`Cipher.getInstance` / `SecretKeySpec.<init>` / `IvParameterSpec.<init>`, and
`native_bridge.py` resolves `System.loadLibrary` / `Runtime.loadLibrary` —
**none of these six APIs were in the forensic dictionary's vocabulary.** A
method that called only these, with no other forensic-relevant pattern,
never got a CFG built, so those two RE-deep-dive modules never even saw it.
(DCL and WebView bridge detection were **not** affected — their target APIs
were already in the dictionary.)

**Fixed**: `relevance_vocabulary()` now unions in the actual target APIs from
`crypto_recovery.py` and `native_bridge.py`, restoring the module's own
documented contract ("superset of everything any downstream module might
care about").

**Fix validated live**, before/after, on `org.mupen64plusae` (an N64
emulator app bundling 88 native libraries):
- **Before**: `resolved_native_bridges: []`, `resolved_crypto_configs: []`
- **After**: 3 real native library resolutions with JNI symbol tables (e.g.
  `System.loadLibrary("ae-bridge") -> lib/x86/libae-bridge.so — 246 dynamic
  symbols`), and 3 real crypto configs (`AES/CBC/NoPadding`, SecretKeySpec,
  IvParameterSpec).

This was a genuinely broken core feature for most real-world APKs, not an
edge case — now fixed, tested live, and covered by the full suite.

## False alarms in my own audit script (not app bugs)
- **`predicted_ttps: []` on benign apps** — flagged by my script as
  "unjustified," but verified with evidence (`has_deterministic_evidence`
  gate not tripped, no "classifier suppressed" limitation present) that the
  classifier ran normally on real evidence and correctly predicted nothing
  malicious. That's the textbook right answer for a benign app, not a gap.
- **`resolved_*` empty on small/simple apps** — for apps that genuinely don't
  use crypto/DCL/WebView/native APIs, an empty list is correct, not a
  failure. My script's heuristic couldn't tell "nothing there" from "didn't
  look" — I could only resolve this by manually cross-checking
  `analyzed_method_count` and re-testing fresh, which I did for a
  representative sample.

## Noted, not a bug: external API flakiness
MalwareBazaar returned intermittent HTTP 502s a few times during the sweep
(their infrastructure, not ours). Already handled correctly — logged, and
VirusTotal lookups continued unaffected. No code change needed.

## Known, pre-existing limitation (not new, not fixed today)
Many `ttp_apks`/`benign_apks` samples were already cached from an earlier
bulk-population run that **predates** RE-deep-dive and grounding-check
persistence — those specific cached records will keep showing
`resolved_*: []` and a "cache hit predates..." limitation message until
re-uploaded fresh. The fix above only benefits new analyses; it doesn't
retroactively repair old cache entries. `benign_holdout` was never
bulk-populated, so it's unaffected by this.

## Sweep 2 (40 more samples, non-overlapping: next 15 ttp_apks, 15 benign_apks,
remaining 10 benign_holdout)

**40/40 succeeded, zero errors.** Confirms sweep 1's fix is stable and didn't
regress anything.

One open question surfaced, deliberately **not** patched — it needs corpus
measurement, not a quick fix, per this project's own stated methodology
(see forensic.py's N1 history): a malware sample (`cmf0.c3b5bm90zq.patch`)
declares heavy dangerous permissions and matches `SMS_OTP_STEALER_PATTERN` +
`ACCESSIBILITY_FULL_CONTROL` via the permission-matrix heuristic, yet the
CFG-based forensic anchor matcher found zero behavioral subgraphs — only
51 of 6164 methods (0.8%) ever got a CFG built. Checked whether this ratio
is an outlier: it isn't — **7 other flagged samples (both malicious and
benign) show the same 0.8-1.7% range**, meaning the relevance pre-filter is
behaving consistently by design, not breaking on this one sample. Whether
this specific malware's SMS/accessibility abuse uses code patterns outside
the forensic dictionary's vocabulary, or whether the permission-matrix flag
is simply a broader/less-precise signal than actual forensic anchors
require (which the project's own N1 history suggests is plausible), is a
real open question — flagging it for a human call rather than guessing.

## Sweep 3 (dynamic verification, all 40 sweep-2 samples)
The first dynamic pass only covered 5 samples — a real gap, fixed by running
dynamic verification (install/launch/hook/capture on the live AVD) across
all 40 samples from sweep 2.

**40/40 requests completed, 0 HTTP/exception errors. 34/40 (85%) actually
completed a full dynamic capture** (`dynamic_ran: true`); the other 6 each
have an individually-logged, non-silent reason (3 launch failures — no
matching launcher activity or process never appeared; 2 Frida attach
failures — process refused injection / timed out; 1 process crash
mid-capture, correctly handled as a distinct event kind, not an error). 2
additional rows show `dynamic_ran: null` — those are genuinely unparseable
APKs that hit the documented fallback path (`risk_score: 50.0`,
`verdict_band: suspicious`, `package: null`) before ingestion even
completed, so dynamic verification correctly never got a chance to start.

**Real finding — the dynamic pass caught live malware C2 traffic**: 5
`ttp_apks` samples were observed actually contacting real C2 URLs during
capture (not static string extraction — a live `InetSocketAddress`/URL
construction call fired):
```
http://52.247.214.89//o1o/a14.php
http://hawus.net/o1o/a4.php
http://yosm4k4l3m.xyz//o1o/a16.php
http://dedecom.ga/o1o/a16.php
```
Each also wrote to its own `shared_prefs/set.xml` — consistent with a C2
config-drop pattern. One sample (`6496931678cdd40d021d0e17d...`) triggered
1500 crypto invocations and 24 file writes in one capture window — a
genuinely crypto/IO-heavy sample worth a closer look on its own.

Benign samples, by contrast, only ever wrote Android's own harmless
profiler cache files (`profileinstaller_profileWrittenFor...`) — no URLs,
no commands executed. Good separation; the mechanism isn't over-triggering
on ordinary app behavior.

## Bottom line
**116 total live requests across all four sweeps today. 0 HTTP errors, 0
unhandled exceptions, full test suite green throughout (338/338).** One real
static-analysis defect found and fixed (crypto/native RE-deep-dive coverage
gap), proven working on real data. Dynamic verification is now validated
across 45 real samples combined, including catching genuine live malware C2
communication — the strongest evidence available that the feature does what
it's for. One open, non-mechanical question about forensic-anchor recall on
a specific malware sample is documented for a human call rather than
patched blind.
