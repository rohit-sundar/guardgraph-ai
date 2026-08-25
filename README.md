# GuardGraph AI — Prototype Skeleton

Android malware risk-scoring engine. CFG/ACFG graph features + XGBoost
multi-label classification + Neo4j knowledge graph + local-LLM GraphRAG
report generation (Ollama) on the static/default path, plus an **opt-in
dynamic-analysis pass** (Android emulator + Frida) that confirms/refutes
specific static predictions at runtime — see step 7 of the quickstart below,
`app/analysis/frida_scripts/README.md` for the containment rules, and
`TEAM_CONTEXT.md`'s Session 14 for the full design writeup.

The dynamic pass is **opt-in per request** and off by default: nothing on the
normal `/analyze` path touches an emulator unless you ask for it.

## Status
This is a **skeleton**, not a finished product. Every module has a working
interface and honest stubs where real logic goes. Nothing here fakes success —
unimplemented paths raise `NotImplementedError` or return explicit
`"not_implemented"` markers so you never mistake a stub for a working feature.

## Structure
```
guardgraph-ai/
├── app/
│   ├── api/            FastAPI routes
│   ├── core/           config, schemas, shared utils
│   ├── analysis/       Androguard ingestion, CFG/ACFG, forensic dictionary, obfuscation
│   ├── ml/             feature vectorization, XGBoost inference
│   ├── graph/          Neo4j client, cache lookup, ontology loader
│   └── reports/        risk scoring, GraphRAG report generation
├── data/
│   ├── samples/        put test APKs here (gitignored)
│   ├── benign_apks/    known-clean Stage C corpus, 299 apps (gitignored, ~3.0 GB)
│   ├── benign_holdout/ 30 clean apps held out of training, for calibration only (~0.8 GB).
│   │                   Kept in its own directory on purpose — see the quickstart.
│   └── models/         put trained model.json here
├── scripts/
│   ├── train_model.py            CICMalDroid2020 training script skeleton
│   ├── build_ttp_dataset.py      assembles the multi-label TTP dataset (stages A/B/C)
│   ├── download_benign_apks.py   fetches the F-Droid known-clean corpus for stage C
│   ├── download_yara_rules.py    fetches the community YARA rule corpus
│   └── load_ontology.py          loads MITRE ATT&CK Mobile / CAPEC into Neo4j
├── tests/
├── docker-compose.yml   Neo4j only — API runs locally for prototype
├── requirements.txt
└── .env.example
```

## Quickstart

First-time setup, in order. Assumes **Docker**, **Python 3.12**, and
[**Ollama**](https://ollama.com) are installed. Report generation runs fully
offline via Ollama.

> **Ollama is not part of this repo.** Download it yourself from
> [ollama.com](https://ollama.com) (or drop a portable build under `bin/ollama/`,
> which is gitignored) — GraphRAG report generation needs it, but everything else
> (upload, static analysis, forensic anchors, signature/YARA, risk scoring) works
> without it. Do not commit Ollama binaries/models to this repo — they run
> hundreds of MB to multiple GB and belong nowhere near git history.

```bash
# 1. Create + activate a virtualenv and install dependencies
python -m venv .venv
source .venv/bin/activate                 # Windows (PowerShell): .venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

```bash
# 2. Configure environment — the defaults in .env.example work as-is
cp .env.example .env                       # Windows (PowerShell): copy .env.example .env
```

```bash
# 3. Start the local LLM used for report generation.
#    Run these in their OWN terminal — `ollama serve` stays running in the foreground.
ollama pull qwen2.5:7b-instruct-q4_K_M
ollama serve                               # skip if Ollama already runs as a background service
```

```bash
# 4. Start Neo4j (knowledge graph: hot-path cache + report grounding)
docker compose up -d
```

```bash
# 5. Download the community YARA rules (run once, or to refresh)
python scripts/download_yara_rules.py
```

```bash
# 6. Run the API (leave running; --reload for development)
uvicorn app.main:app --reload --port 8000
```

```bash
# 7. Dynamic analysis (Android emulator + Frida). 
python scripts/setup_dynamic_analysis.py
```

The script is the whole setup: it finds your SDK and adb, downloads the
frida-server build matching your installed `frida` client and the AVD's ABI,
pushes and starts it, builds the Frida agent bundle, and checks the firewall
containment rules. It exits non-zero and tells you the exact next step if
anything is missing. Re-run it any time dynamic analysis misbehaves.

Two things it cannot do for you:

- **Create the AVD.** You need one API 30+ **`google_apis`** x86_64 image
  (Android Studio → Device Manager). Not `google_apis_playstore` — that image is
  Play-signed and silently blocks Frida from injecting, which shows up much later
  as a confusing `could not attach to pid N`.
- **Apply the host firewall rules** (needs Administrator). The pipeline probes
  the AVD's egress before every install and **refuses to install an APK** if a
  real outbound connection succeeds. Commands are in
  `app/analysis/frida_scripts/README.md`.

Then set `DYNAMIC_ANALYSIS_ENABLED=true` in `.env`. The AVD itself is booted
automatically when no device is attached, so you do not need to start the
emulator by hand. Per-machine settings — all optional, all documented in
`.env.example`:

| variable | what it's for |
|---|---|
| `AVD_NAME` | Which AVD to boot. Required **only** if you have more than one — with several installed the pipeline refuses to guess and names them. |
| `DYNAMIC_ANALYSIS_AUTO_BOOT` | `true` (default) boots the AVD on demand. `false` fails fast instead. |
| `EMULATOR_PATH` / `ADB_PATH` | Auto-detected from `ANDROID_HOME`; set only if detection fails. |
| `ADB_SERVER_PORT` | Defaults to `5039`. adb's own default 5037 collides with Hyper-V's reserved port range on some Windows machines. |
| `EMULATOR_GPU_MODE` | `swiftshader_indirect` (software) by default — hardware GPU passthrough is the usual cause of an emulator that hangs on boot. |
| `AVD_BOOT_TIMEOUT_SECONDS` | Cold-boot budget, default 300. |

Trigger it per request with `?enable_dynamic=true`, or tick **"🧪 Also run
dynamic verification"** in the UI (the checkbox appears after you pick a file,
above the analyse button — it is off by default):

```bash
curl -X POST "http://localhost:8000/analyze?enable_dynamic=true" \
  -F "file=@data/ttp_apks/<sample>.apk"
```

Results render in the **🧪 Dynamic Verification** tab. `ran: false` there means
the pass did not complete (no AVD, install failure, app crashed on launch) — it
never means "no malicious behaviour found", and the coverage note says which.
Note that an x86_64 AVD cannot install ARM-only APKs, and API 30+ refuses APKs
whose `resources.arsc` is compressed; both are reported honestly rather than
scored as clean.

Then upload an APK. A sample ships with the repository:
```bash
curl -X POST http://localhost:8000/analyze -F "file=@guardgraph_test/guardgraph_test.apk"
```
The first analysis of a given file takes roughly two to three minutes, almost all of it
Phase 7's local LLM call — append `?skip_report=true` to get the verdict, score and full
manifest without the narrative. Upload the same file again and it returns from the Neo4j
cache instead of re-analysing.

## What's real vs stubbed right now

| Module | State |
|---|---|
| FastAPI upload + hashing | Working |
| Real-time pipeline progress (SSE) | Working. `POST /analyze/start` returns a `job_id` immediately; `GET /analyze/stream/{job_id}` relays each of the ten backend phases' actual start/done/skipped boundaries as they happen, ending in one `complete` event carrying the full report — this is what the UI's progress bar is driven by. A dropped connection (network hiccup, tab backgrounded) does not lose the job: reconnecting to the same `job_id` resumes relaying from wherever the analysis currently is, and the terminal event is recoverable even after a disconnect. `POST /analyze` remains a plain synchronous request/response with no progress — used by curl, this quickstart, and `scripts/test_upload.py` |
| Androguard ingestion | Working (needs `androguard` installed) |
| CFG construction (NetworkX) | Working |
| ACFG enrichment | Working |
| Forensic dictionary / anchor detection | Working. Each rule is gated on a manifest declaration and its patterns are grouped into clauses that must corroborate each other within one method. |
| 4-hop subgraph extraction | Working |
| Topological feature mining | Working (degree/closeness/clustering; eigenvector/Katz stubbed — slow on large graphs, add if needed) |
| Obfuscation / anti-analysis scoring | Working, recalibrated. String-pool entropy and control-flow flattening are still measured and reported, but neither is scored: measured over the 633-APK corpus, entropy cannot reach its threshold and runs backwards (mean benign 3.18 vs malware 2.71; it peaks at 3.86 against a 7.2 threshold), and flattening prevalence has no lift (benign p75 0.126 vs malware 0.112). Rebuilding the corpus twice reversed neither — those figures are within 0.03 of what the 618-row and 353-row corpora gave, which is the most stable measurement in the project. The component now scores the one thing that held up: a DEX too small to implement its own manifest. The CFG parse-failure branch was **deleted**, not left unscored: it measured 0.0 on all 353 samples of the first corpus, all 616 of the second, and all 633 of this one. |
| Signature + YARA scanning (hash/cert DB, VirusTotal, MalwareBazaar, YARA rules) | Working; online triage (VT/MalwareBazaar) needs API keys in `.env`, otherwise local hash/cert + YARA run offline. 8 built-in rules always load; the ~500 community rule *files* require quickstart step 5 — without it the engine runs built-in-only and says so in the startup log |
| Brand / app-identity impersonation detection | Working (`app/analysis/impersonation.py`). Separate from every other row here — it answers "is this app pretending to be a different, legitimate app?" rather than "how malicious does the code look?". **Five** checks against a reference table of protected brands: signing-certificate mismatch on an exact package match (definitive — Android identifies publishers by key), launcher-icon reuse (64-bit DCT perceptual hash, survives rescale/recompress), package-name typosquatting, **package-namespace squatting** (a package that is a protected package *plus* a suffix — `org.telegram.messenger.wgstjg` — which typosquatting cannot catch, since appending 6 characters is far outside the edit-distance bound), and display-name impersonation, all after Unicode-confusable normalization. A match raises a **floor** under the verdict rather than adding to the weighted score, since a cloned banking app can carry a deliberately unremarkable payload — see `IMPERSONATION_SCORE_FLOOR` in `app/reports/scoring.py`. Ships with `data/reference/protected_brands.json` **populated from genuine APKs**: 66 brands — Indian banks/UPI/government apps plus the global social, commerce and streaming apps commonly used as fraud lures, every package name verified against a live Play listing. **15 of them carry a real signing certificate** read off a Play-installed APK, so the strongest check runs for those; the rest are package/label entries. The certified set includes **Bank of India** (`com.boi.ua.android`, `com.boi.erupee.prod`), Telegram, WhatsApp, PhonePe, Paytm, GPay, BHIM and the major Indian banks. Each app was installed from **Google Play onto an emulator with Play services** and pulled with `adb`, so the recorded signing key is the one Android actually verifies on device — not an APK-mirror copy, which re-signs and would invert the check. 6 also carry a launcher-icon hash (the rest ship adaptive XML icons, which have no pixels to hash — a permanent property of those apps, not work left undone). Regenerate with `python scripts/build_brand_reference.py --apk-dir <dir>`, then `--collisions`. Measured over the malware corpus, the name-based checks produce **22 findings across 344 samples with 0 false positives on 329 clean apps**. With the certificates now recorded, the **5 exact-package clones** on disk — trojans wearing Telegram's and Google Fit's exact package names — fire `certificate_mismatch` and go **35.62 `medium` → 72.01 `malicious` on identity evidence alone**, with no payload analysis involved. All 16 genuine brand APKs produce **zero** findings. Populate them for real with `python scripts/build_brand_reference.py --apk-dir <dir-of-genuine-APKs>` (get the APKs from official listings, not a mirror), then `--collisions` to confirm the icon threshold doesn't confuse two of your own brands. |
| **Dynamic verification (opt-in, Android emulator + Frida)** | Working (`app/analysis/dynamic_verification.py`, `app/analysis/frida_scripts/`). Off by default on every request (`enable_dynamic` query param AND `settings.dynamic_analysis_enabled`, both must be true) — installs the sample on a network-isolated AVD, launches it (falling back to broadcasting its own declared intent-filter actions for headless/receiver-only malware with no launcher activity), and hooks 13 APIs for a bounded capture window to confirm/refute specific static predictions already made elsewhere in the pipeline: C2 contact, DCL payload execution, native library loads, SMS interception, overlay-attack windows, accessibility binding, crypto invocation, plus standalone IoCs (URLs/files/commands) and up to 3 screenshots per run (reaction / event-triggered / end-of-window). A confirmed C2 contact is also written to Neo4j as `dynamically_confirmed=true` on that sample's `CONTACTS` relationship, letting cross-sample correlation distinguish "shares this C2 string" from the stronger "was caught actually calling it". See `app/analysis/frida_scripts/README.md` for full setup (AVD, frida-server, containment firewall rules) and `TEAM_CONTEXT.md`'s Session 14 for the design writeup and every failure mode found live. |
| Family XGBoost inference (auxiliary) | **Not shipped, deliberately.** `data/models/guardgraph_xgb_v1.json` was removed rather than retrained, for two independent reasons. (1) It was trained on the 33-feature schema and `BEHAVIOR_FEATURES` later grew in the *middle*, so a length-based compatibility slice kept the vector the right size while shifting every column from index 12 onward — a silent misalignment producing confident, wrong families. `app/ml/classifier.py` now compares the booster's stored `feature_names` against `FEATURE_NAMES` and refuses to predict on a mismatch, naming the first column that diverges. (2) Its training data, `data/cicmaldroid_features.csv`, is synthetic — exactly 250 rows per family, all 15 topology columns identically zero, `string_entropy_score` up to 7.79 where the real pipeline's measured maximum is 3.47 — so `predicted_family` was never trustworthy regardless of the alignment. **Do not retrain from that CSV.** With no artifact present, `predicted_family` comes from a deterministic hash/certificate match when there is one and is otherwise blank; the primary cold path predicts techniques directly and does not depend on it. |
| Multi-label MITRE ATT&CK TTP classifier (primary, cold path) | Trained — `data/models/guardgraph_ttp_br_v1.joblib` is committed. Trained on **633 rows — 299 benign / 334 malware across 21 families**, 34 of 57 techniques carrying enough positives to train (the other 23 are listed in `dropped_labels` and are never predicted; see the limitation note below the table). **The stratified-split metrics this repo used to quote were measuring family memorisation, not technique inference** — every malware row's label comes from its family's ATT&CK software entry, so a split that stratifies on labels puts identical label vectors on both sides of the train/test boundary by construction. `ttp_metrics.json` therefore also carries `family_held_out`, a `GroupKFold` evaluation with whole families held out of each fold. Both numbers, side by side: **stratified micro-F1 0.87** against **family-held-out micro-F1 0.29, Jaccard 0.087**. Note the direction — nearly doubling the corpus (364 → 633 rows) *raised* the stratified figure and *lowered* the held-out one. More data does not buy generalization to a family the model has never seen, which is precisely why the risk score puts 60% of its weight on deterministic evidence. Quote the held-out number, not the leaky one. Re-derive both with `python scripts/train_model.py --target ttp`, which prints them side by side. |
| Neo4j cache lookup (hot path) | Working, needs Neo4j running + ontology loaded. The full cached record (risk components, obfuscation signal, permissions, signature/YARA data) now persists to Neo4j as a JSON property on the `Sample` node, not only to an in-process dict — a cache hit after a server restart used to silently return a total score with every component blank while the cached narrative still described them. **The lookup runs before the APK is parsed, not after** — it is keyed on the SHA-256 of the raw bytes, which needs no parsing, but it used to sit behind a full Androguard pass, so a sample answered from cache still paid the entire cost of analysing it. A hit now parses the manifest only (no DEX cross-reference build): measured end to end at **0.75 s**, from 6.6 s of Phase 1 ingestion down to 0.24 s on the same 3.9 MB sample. The manifest parse is kept rather than answering from the stored record alone because the impersonation check re-runs on every hit — so an updated brand table applies to already-cached samples without re-analysis — and it needs the app label, launcher-icon hash and signing certificate, none of which are cached. |
| Reverse-engineering deep dive (reflection, crypto config, dynamic code loading, WebView JS bridges, native/JNI bridges) | Working. Shared register-constant propagation engine (`app/analysis/static_resolution.py`) resolves reflection targets, `Cipher.getInstance`/`SecretKeySpec` chains, `DexClassLoader` targets, `addJavascriptInterface` bridges, and `System.loadLibrary` symbol correlation — all static, fails closed on ambiguous dataflow rather than guessing. Surfaced in the "🔬 Reverse Engineering" report tab |
| Manifest-corruption / anti-analysis resilience | Working. AXML chunk-header corruption and ZIP EOCD/local-header corruption both fall back to manifest-independent DEX/CFG recovery instead of aborting the whole analysis; unrecognized parser failures get a probable-cause explanation (`app/analysis/failure_diagnostics.py`) instead of a raw traceback, and the GraphRAG narrative always runs (never a hardcoded empty placeholder) even on total parse failure |
| Neo4j graph correlation (beyond the cache) | Working. `ttp_context` grounds the "MITRE ATT&CK Mapping" tab in real ontology facts (name/tactic/description), `find_related_samples` correlates the current sample against previously-cached ones via shared MITRE techniques / shared C2 infrastructure / a reused signing certificate ("Correlated Samples" tab), and `get_threat_landscape` + `/graph/landscape` render the whole correlation graph live inside the app via Cytoscape ("Threat Landscape" tab) — no separate Neo4j Desktop window needed for a demo |
| Risk scoring formula | Working. **Seven weighted components, which is a deliberate departure from the paper's six** — GuardGraph adds a `forensic_anchor` term (0.15) because the paper scores no equivalent, and matched API/permission anchors are the evidence that survives when the model meets an unfamiliar family; the remaining weights were rebalanced to accommodate it rather than copied. Two of the paper's inputs are also measured and *not* scored, for reasons given in the obfuscation row above. The component internals were calibrated against a **633-APK corpus — 299 benign / 334 malware across 21 families**, with a further 30 clean apps held out of training entirely and used to validate the boundaries rather than set them. **This is reproducible from what is on disk**: `data/benign_apks` + `data/ttp_apks` are the same 643 APKs the calibration ran over (10 malware are permanently unparseable, which is why 633 is scored, not 643), so `python scripts/score_corpus.py` re-derives every number in this table and in `app/reports/scoring.py`'s comment block. Earlier revisions of this README carried a caveat that the checked-out corpus was smaller than the calibration one and the figures could not be reproduced — that is no longer true, and the run takes about 100 minutes on four cores. One boundary moved in the 2026-08-24 re-derivation: the `high` ceiling went 70 → 72, because the highest-scoring clean app rose to 71.54 and would otherwise have read `malicious`. Calibrated with reputation **disabled**, which is the conservative direction — and that is measured, not asserted: turning it on moves malware **+4.75 to +5.75** points and clean apps **exactly 0.00**, because a clean app matches neither the local signature DB nor VirusTotal, which only returns a verdict when `malicious > 0`. **The demo runs with reputation on.** Since the local hash DB is checked first and the online branch runs only when it finds nothing, a known sample resolves offline in milliseconds and never spends VirusTotal quota; the third-party lookup is reserved for genuinely unknown APKs, which is where it earns its latency. So the shipped bands sit *below* where a live run places malware, and no boundary was drawn in a regime kinder to malware than the one you will see. `ttp_severity_component` and `forensic_anchor_component` sum evidence into a saturating mass rather than averaging it (`python scripts/measure_saturation.py` reproduces the derivation) — the averaged form used to make the score *fall* as more corroborating evidence was found. |
| Verdict bands (`low` / `medium` / `suspicious` / `high` / `malicious`) | Calibrated at **30 / 40 / 60 / 72**, each boundary set by its own criterion rather than by cutting 0–100 into equal parts (see `app/reports/scoring.py`). `medium` sits in the gap between where clean apps typically top out above `low` and where malware density resumes — it exists to stop labelling that clean-app tail `suspicious`, which is a labeling fix, not a new detection boundary. `high`'s ceiling is placed above the highest score observed on a known-clean app during calibration, rather than just below the malware first quartile — this trades some malware-`malicious` recall for precision, so more malware reads `high` instead of `malicious`, but nothing is downgraded past `high`: the total share of malware reaching `high`-or-above is unchanged. Apps whose legitimate functionality genuinely overlaps a banking trojan's capability surface (e.g. automation or accessibility tools that use SMS/overlay/accessibility APIs) can still land in `high` — that is capability overlap, not a scoring defect, and no boundary fully separates it. Re-derive all four boundaries against your own corpus with `python scripts/score_corpus.py` before trusting them in a different deployment. |
| Zero-day risk indicator | Working — strong deterministic/structural evidence + low model confidence + cache miss raises `zero_day_indicator` |
| GraphRAG report generation (local LLM via Ollama) | Working — calls Ollama (`qwen2.5:7b-instruct-q4_K_M`), no cloud key needed. **Grounding is enforced, not requested.** A 7B model does drift under a strict grounding prompt, so the narrative is checked after generation rather than trusted: three independent post-generation checks verify that every MITRE technique cited was actually predicted, that no permission named was absent from the manifest, and that no hash or identifier was invented; fabricated sample-identity lines are stripped and the real header is stamped deterministically. The result is a first-class `grounding` field on the API response, rendered in the UI as a per-check pass/fail panel — and a `null` grounding renders as "checks did not run", never as a green badge. Prompt-injection hardening is in place for the analyzed sample's own strings, which are untrusted input written by the malware author. |
| Auth, queues, multi-user | Not built — out of scope for prototype |

### Known limitation: 23 of 57 techniques are never predicted
The multi-label model trains a technique only when the corpus carries enough positive
examples of it. 34 of the 57 ATT&CK Mobile techniques clear that bar; the remaining 23
are listed in `dropped_labels` in `data/models/ttp_metrics.json` and **the model can
never output them**, at any confidence. This is a property of the corpus, not a
threshold that can be tuned — the labels are derived from each family's ATT&CK software
entry, so a technique no carrier family in MalwareBazaar attests to has no positives to
learn from, and adding more samples of the same families will not create any.

The one that matters for banking fraud is **T1636 (Protected User Data — SMS)**, which
carries the second-highest per-technique severity override in the scorer (0.9, behind
T1471 at 0.95 — which *is* trained). SMS/OTP theft is not missed as a result: it is
carried deterministically by the `STEALTH_SMS_INTERCEPTION` forensic anchor and the
`SMS_OTP_STEALER_PATTERN` permission matrix flag — both weighted 1.0, and both matching
on observed APIs and manifest declarations rather than on an inferred label, so they
report it at higher confidence than the model would. That split —
model for breadth, deterministic evidence for the findings a bank acts on — is the same
reason 60% of the risk score's weight sits outside the model.

### Brand reference: populating it from genuine APKs

`data/reference/protected_brands.json` ships populated. To rebuild it, or to add a brand, put
genuine APKs in `data/reference/apks/` (gitignored) and run:

```bash
python scripts/build_brand_reference.py --apk-dir data/reference/apks
python scripts/build_brand_reference.py --collisions   # icon hashes must not collide
```

**Where the APKs come from is not a detail.** Install each app from the **official Google Play
listing** — onto a device, or an emulator image that has Play services — and pull it with
`adb pull`. A copy from an APK-mirror site is exactly the artefact this module exists to
detect: mirrors re-sign, so seeding the reference from one records the *wrong* key. That does
not merely fail to detect, it **inverts** the check — the genuine app reports as impersonating
itself and the clone reports as authentic. The current table was built by installing from Play
onto a Pixel emulator (API 37.1) and pulling the result.

`adb pull` on an app installed from a bundle gives a directory of `base.apk` +
`split_config.*.apk`. Put that directory under `data/reference/apks/` as-is; the script
recurses one level and reads only `base.apk`. It also refuses to record a label that came back
as an unresolved resource id (`@7F124DF6`, `<0x5120, type 0x00>`) — a bundle keeps its strings
in the language split, so `base.apk` alone cannot always resolve the app name, and writing that
raw id in as a display name would have the label check matching real app names against garbage.

**Two rules that will bite if ignored**, both recorded in the file's own `warning` field:

1. **A wrong package name creates a false positive on the real app** — it reads as a typosquat
   of a package that does not exist. Three entries in this table were wrong before it was built
   from real APKs, and two of them flagged the genuine app: Play ships HDFC as
   `com.hdfcbank.android.now`, Kotak as `com.kotak811mobilebankingapp.instantsavingsupiscanandpayrecharge`,
   and Amazon India as `in.amazon.mShop.android.shopping` — note `in.`, not `com.`.
2. **Once a brand carries any certificate, every package listed under it is checked against
   that list.** So a package whose own key was never recorded makes the genuine app on it read
   as a clone. Verified: a two-package brand with one recorded key flags the genuine sibling as
   `certificate_mismatch`. Either record a key per package, or drop the packages you could not
   verify — `org.telegram.messenger.web` and `.beta` were dropped for this reason, since
   neither is distributed through Play.

`verified: true` means a signing certificate was read off a real APK, which is what makes the
strongest check runnable. It deliberately does **not** also require an icon hash: most modern
apps ship an adaptive (XML) launcher icon, which has no pixels to hash, so requiring it would
pin `verified: false` on brands whose certificate check works perfectly. `icon_phash: null`
already says the icon check is unavailable for that brand.

### Vendored frontend libraries

`app/static/vendor/` holds three scripts and two font files that were CDN `<script>`/`<link>`
tags until they were pulled local. Cytoscape draws the Threat Landscape tab and the CFG
explorer, so a captive portal or a throttled venue network would silently remove the graph
half of the product; the other two scripts are the markdown renderer and the sanitizer
standing between the LLM narrative and the DOM. They are checked in deliberately —
**do not put the CDN URLs back.**

| File | Version | Refresh from |
|---|---|---|
| `marked.min.js` | 15.0.12 | `https://cdn.jsdelivr.net/npm/marked@15.0.12/marked.min.js` |
| `purify.min.js` | 3.1.6 | `https://cdn.jsdelivr.net/npm/dompurify@3.1.6/dist/purify.min.js` |
| `cytoscape.min.js` | 3.28.1 | `https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.28.1/cytoscape.min.js` |
| `fonts/outfit-latin-variable.woff2` | v15, latin subset | Google Fonts CSS2 API: `family=Outfit:wght@300..800` |
| `fonts/jetbrains-mono-latin-variable.woff2` | v24, latin subset | Google Fonts CSS2 API: `family=JetBrains+Mono:wght@400..600` |

Each URL above is pinned; the `marked` tag this replaced was unpinned (`npm/marked/`) and
resolved to 15.0.12 at the time of vendoring — re-fetching an unpinned "latest" is a change,
not a restore. The two fonts are variable fonts, so one file each covers the whole weight
range used (`--font-sans` / `--font-mono` in `styles.css`, declared via `@font-face` at the
top of that file); both still carry system fallbacks, so even a corrupted/missing font file
costs typography, not function. Non-Latin glyphs are out of scope — this is a Latin-only
subset, matching the UI's English-only copy.

## Scalability — what it costs, and what actually scales

Single process, synchronous analysis inside `async def`, an in-process job dict, no queue,
no auth, no rate limit on `/analyze`. That is deliberate for a prototype and
[`routes.py`](app/api/routes.py) says so in its module docstring — *"Do not 'optimize' this
before it's needed."* The numbers below are the honest answer to what that costs, all
measured on this repository rather than estimated.

| Stage | Cost | How it scales |
|---|---|---|
| **Phases 1–6** (ingest → CFG → anchors → topology → classify → score) | **6.4 samples/min sustained, ~384/hour** | **Linearly in workers** — CPU-bound, no shared state. *Unless online reputation is on; see below.* |
| **Phase 7** (GraphRAG narrative, local Ollama) | **~156 s** of a ~165 s cold run — **~94% of wall clock** | Serial per sample, and **already optional** |
| **Hot path** (SHA-256 → Neo4j lookup → manifest-only parse) | **0.75 s** | Bounded by Neo4j, the one shared component |
| Upload | 150 MB cap, streamed to disk | Not buffered in memory |

The phases 1–6 figure is measured end to end over the full 643-APK calibration corpus —
7.37 GB, mean APK 11.7 MB, **100.5 minutes wall clock** — on a 4-physical-core laptop, with `scripts/score_corpus.py` running 8 workers and
**a fresh child process per APK** — process isolation costs an interpreter start per sample
and is kept because Androguard can abort the interpreter outright on a malformed DEX. A
long-lived worker pool would do better; this number is a floor, not a ceiling.

Phase 7 is the one phase whose cost is **independent of APK size** — it generates a
~2000-token narrative whether the sample is 2 MB or 60 MB, so it dominates most on the
small samples where analysis itself is cheapest. That is what makes switching it off such a
clean lever, and why halving `max_tokens` is the only code change that would move it.

**The important structural point: the 94% bottleneck is already switched off for bulk work.**
`POST /analyze?skip_report=true` bypasses Phase 7 entirely
([routes.py:323](app/api/routes.py#L323)), so bulk triage runs at phases-1–6 speed and
narrative generation happens on demand, per escalated sample — which is the right shape
anyway, since an analyst reads a narrative for the handful of samples that clear `high`, not
for the 300 that read `low`. Bulk-populating the corpus is exactly this: `populate.py` sets
`skip_report=true` and the cache then answers repeat uploads in 0.75 s.

**The CPU-bound claim holds only with `ONLINE_LOOKUPS_ENABLED=false`.** With it on — which is
how a live demo runs — Phase 1.5 makes one VirusTotal call per uncached sample, and the public
quota is **4 requests/min and 500/day**. That, not the CPU, becomes the ceiling — and it is the
*daily* cap that bites, not the per-minute one: 4/min is close to the ~5/min measured above, but
500/day against a local capacity of ~9,200 samples/day means third-party reputation can cover
about **5%** of what the analyzer can actually chew through. A single 643-sample corpus run
alone would need 129% of a day's allowance. This is why `scripts/score_corpus.py` disables online lookups by
default and pins itself to one worker paced at 15 s/sample when `--online` is passed. For bulk
work the local hash/cert DB and YARA run offline and carry the deterministic signal; the
third-party lookup is a per-sample enrichment for interactive analysis, not a batch dependency.

**What genuinely blocks a second process today** — stated because "add workers" is not free
here: `_JOBS` is an in-process dict guarded by a thread lock
([routes.py:380](app/api/routes.py#L380)), so the SSE progress stream is process-affine. A
client must reconnect to the *same* process that started its job. Running N API workers
therefore needs either sticky routing or a shared job store; everything else in the request
path is already stateless. Neo4j is the only durable shared component, and it is the only
one that would need to be sized rather than replicated.

## Wiring in your trained model
Drop your model file at `data/models/guardgraph_xgb_v1.json` and set
`MODEL_LABEL_MAP` in `app/core/config.py` to match your training label order.
The feature vector schema is documented in `app/ml/features.py` — your
training script's feature order MUST match this exactly. Train on a **named**
DataFrame whose columns are `FEATURE_NAMES`: the booster then stores those names,
and `app/ml/classifier.py` compares them against the live schema at load and
refuses to predict on a mismatch rather than producing a confidently wrong family.
Train on a bare array and the booster carries no names, which is also refused —
an unnamed model cannot be checked, and this project has already shipped one
silent column shift (see the Family XGBoost row above).

## Multi-label MITRE ATT&CK Mobile TTP classifier (cold path)

The cold path predicts ATT&CK Mobile techniques directly as a multi-label problem
(Binary Relevance — one XGBoost per technique), combining GUARD-style graph-invariant
topology with DroidTTP-style manifest/API presence features. Deterministic forensic-anchor
and obfuscation signals set a score floor and raise `zero_day_indicator` on first-seen
samples the model doesn't recognise.

Column order is load-bearing — an appended feature and an *inserted* one are
indistinguishable by vector length, and only the latter corrupts every column after
it. Freeze these before training:
- `app/ml/labels.py` → `TTP_LABELS` (technique output order)
- `app/ml/features.py` → `TTP_FEATURE_NAMES` / `build_ttp_feature_vector` (181 features)

**Ontology grounding** — run once. Required for grounded reports, even without a trained model.
```bash
python scripts/build_ttp_label_space.py    # ATT&CK Mobile label space + ontology from STIX
python scripts/load_ontology.py            # into Neo4j; --starter for an offline 5-technique seed
```

**Training** — optional. The dataset is assembled in three stages: **A** pulls real APKs
from MalwareBazaar (needs `MALWAREBAZAAR_API_KEY`; downloads live malware), **B**
weak-labels local CICMalDroid samples, and **C** adds known-clean APKs as the negative
class. Run Stage A's two phases separately — analysis is memory-hungry and can crash the
process, which you don't want to cost you the downloads.

```bash
# 1. Download malware — network-bound and resumable. Writes data/ttp_apks/_manifest.json.
#    --download-workers 3, not 8: at 8, abuse.ch drops ~18% of transfers mid-body
#    (IncompleteRead / "Remote end closed connection"). Reruns retry only what is missing.
python scripts/build_ttp_dataset.py --stage a --phase download --max-per-family 40 --download-workers 3
```

```bash
# 2a. Benign corpus, small window (<=12 MB) — ~1 GB, a couple of minutes.
python scripts/download_benign_apks.py

# 2b. Benign corpus, large window (12-60 MB) — ~3 GB, into the SAME directory, and
#     --holdout-count carves out the calibration holdout in the same pass.
#
python scripts/download_benign_apks.py --count 110 --seed 42 --holdout-count 30 \
  --min-size 12582913 --max-size 62914560 \
  --out-dir data/benign_apks --index-cache data/benign_apks/_fdroid_index.json

#     Verify against F-Droid's published hashes — checks both directories in one
#     pass. 
python scripts/download_benign_apks.py --verify-existing --count 110 --seed 42 --holdout-count 30 \
  --min-size 12582913 --max-size 62914560 \
  --out-dir data/benign_apks --index-cache data/benign_apks/_fdroid_index.json
```

```bash
# 3. Analyse malware — CPU/memory-bound, takes hours. Writes to data/ttp_dataset.csv.
python scripts/build_ttp_dataset.py --stage a --phase analyze
```

```bash
# 4. Analyse the benign corpus — appends all-zero-label rows to the same CSV.
python scripts/build_ttp_dataset.py --stage c --benign-dir data/benign_apks
```

```bash
# 5. Train Binary Relevance; benchmarks Classifier Chains / Label Powerset.
python scripts/train_model.py --target ttp
#    -> data/models/guardgraph_ttp_br_v1.joblib + data/models/ttp_metrics.json
```

Reruns of the download phase are incremental. On "families still unresolved" (transient
abuse.ch 502s), just rerun — only those families are retried; `--force-resolve` re-sweeps all.

The analyse phase is incremental too: rows are appended as each APK finishes, so a crash
costs one sample rather than the whole pass, and a rerun skips what is already in the CSV.
`--overwrite` rebuilds from scratch — needed if the CSV predates a `TTP_FEATURE_NAMES`
change, since appending mismatched columns is refused rather than silently misaligned.
Both phases tee their output to `logs/build_ttp_dataset_<phase>_<timestamp>.log`, which is
what survives if the terminal dies with the process.