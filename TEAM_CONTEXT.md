# GuardGraph AI — Team Context & Change Log
> Feed this file to your LLM as project context before asking it to work on GuardGraph AI.  
> It contains the full picture: architecture, every file's purpose, what's real vs stubbed, and a dated change log.

---

## Change Log

### Session 11 — 2026-08-20 (pm) | Author: Rohit — Recalibrate risk score components and verdict bands against the 353-APK corpus

> **Overview:** `scripts/score_corpus.py` [NEW] measures every score component against 220 F-Droid
> benign apps + 133 MalwareBazaar malware samples, and the numbers showed three of seven components
> were dead weight or actively backwards. This is a breaking recalibration (`fix(scoring)!`), not a
> tuning pass — component *definitions* changed, not just thresholds. Weights themselves (0.25/0.20/
> 0.15/0.15/0.15/0.05/0.05) are unchanged; what changed is what feeds each one.

**Files changed:** `app/analysis/apk_static.py`, `app/analysis/forensic.py`, `app/analysis/ingest.py`, `app/analysis/obfuscation.py`, `app/core/pipeline.py`, `app/core/schemas.py`, `app/reports/scoring.py`, `scripts/build_ttp_dataset.py`, `.gitignore`, `README.md`
**Files added:** `scripts/score_corpus.py` [NEW], `tests/test_score_calibration.py` [NEW]

- **`classifier_confidence_component`** — was `max(predicted_ttps.values())`. Now a threshold-normalized
  evidence mass: each predicted technique's probability is rescaled to its margin past its own
  per-technique decision boundary (boundaries range 0.10–0.90 by label prevalence, from
  `ttp_metrics.json`), margins are summed across all predicted techniques, and the sum is squashed
  through `1 - e^(-mass / 2.5)`. A single confident label no longer carries the full component —
  breadth across corroborating techniques does. Malware predicts a median of 8 techniques; clean apps
  mostly predict 0–2.
- **`obfuscation_component`** — rewritten. Measured over the corpus, the four original inputs were
  each dead: string-pool entropy never reaches the 7.2 threshold and runs backwards (benign 3.28 vs
  malware 2.78 mean); `flattening_suspected` fired on 30/30 sampled clean apps; unresolved-reflection
  is a permanent stub at 0; parse-failure rate was 0.0 across all 353 samples. The component read a
  near-constant 6.00/15 for both populations. Replaced with **manifest-vs-code mismatch**
  (`MIN_METHODS_PER_DECLARED_COMPONENT = 2.0` — a DEX with fewer methods than its manifest's declared
  components could possibly implement is a loader stub; 12 corpus malware fail this, 0 of 220 clean
  apps come within 28x of the floor) plus CFG parse-failure rate. Entropy and flattening are still
  measured and reported in the coverage note — just no longer scored.
- **`ioc_component`** — split evidence into *sample-identifying* (hash/cert signature hits, exact
  extracted C2 IoCs, secondary DEX payloads — can reach the cap alone) vs. *circumstantial* (generic
  YARA severity, cert anomalies, dropper signals, forensic C2 strings — jointly capped at 0.35). The
  old flat tiering let three YARA hits at severity 0.85 pay 0.765 of the cap, and clean apps matched a
  mean of 10.8 community rules at that severity — YARA rule-author severity is metadata, not
  specificity, so breadth no longer multiplies.
- **Accessibility detection** (`apk_static.py`, `forensic.py`) now gates on the declared
  accessibility-service **intent-filter action**, not the `BIND_ACCESSIBILITY_SERVICE`
  `<uses-permission>` — apps essentially never declare that permission (it's what the *system* holds
  over the service). This is what [[Session 10]]'s forensic gating rests on.
- **Certificate analysis** no longer flags self-signing as an anomaly — Android app signing is
  self-signing by design; that was a 100%-false-positive rule.
- **Verdict bands are now named constants** derived from measured score distributions, not an even
  0/30/60/80/100 cut: `BAND_LOW_CEILING = 30.0` (clean corpus p95), `BAND_SUSPICIOUS_CEILING = 60.0`
  (above the highest score any of the 220 clean apps reached — `high` is a band the clean corpus never
  enters), `BAND_HIGH_CEILING = 65.0` (below the malware first-quartile in two separate corpus runs,
  chosen to be insensitive to day-to-day VirusTotal/MalwareBazaar answer variance). Was 80.0 for the
  `high`/`malicious` boundary, where only 12 of 133 malware ever reached `malicious`.
- **Measured result:** 212 of 220 clean apps read `low`, none reaches `high`; 106 of 133 malware read
  `high` or `malicious`. Reproduce with `python scripts/score_corpus.py` after any analysis-stage change
  — every constant in `scoring.py`'s calibration block was picked from that script's tables, not intuition.
- **Tests:** `tests/test_score_calibration.py` [NEW] pins the calibration constants and band boundaries.

---

### Session 10 — 2026-08-20 (am) | Author: Rohit — Gate forensic rules on manifest declarations

> **Symptom:** `FORENSIC_DICTIONARY` ORed `apis` + `strings` per rule and never read the declared
> `permissions` key, so **one bare substring anywhere in the app** was enough to fire a behavior.
> `ACCESSIBILITY_ABUSE` hit 207/220 clean F-Droid apps because AndroidX references
> `AccessibilityNodeInfo` in any app that bundles it; `"otp"` matched `"hotpink"` and `"notPlaced"`;
> a bare `"password"` matched Jetpack Compose's `isPassword=false` semantics string. Measured on the
> 220-benign / 133-malware corpus, clean apps fired **3.91** behaviors on average against malware's
> **4.01** — the dictionary ran backwards. `forensic_anchor_component` is 15% of the deterministic
> score and cannot learn its way out of a bad rule, so precision matters more here than recall.

**Files changed:** `app/analysis/cfg.py`, `app/analysis/forensic.py` (rewritten), `app/api/routes.py`, `app/core/pipeline.py`, `scripts/build_ttp_dataset.py`, `README.md`
**Files added:** `tests/test_forensic_gating.py` [NEW]

- **Manifest `declares` gate** — a rule can require the app to have declared a specific capability
  (permission, or an intent-filter action) before it is even eligible to fire. Measured on the corpus:
  gating `SMS_*` behaviors on an SMS permission splits 5/220 clean from 81/133 malware; gating
  accessibility abuse on the service's intent-filter action (not the `<uses-permission>`, which real
  trojans almost never declare) splits 7/220 from 75/133. This one change does most of the precision
  recovery.
- **`clauses`** — each rule is now a list of alternatives, and every populated key (`apis`, `strings`,
  `permissions`) within one alternative must match **inside the same method** before it counts. This is
  how "a WebView call near a credential string, in the same method" is expressed without either half
  firing alone — the old flat OR treated them as independent evidence.
- **Rewritten string vocabularies** — OTP/credential substrings are now delimited forms only
  (`"otp_code"`, `"one time password"`, `"verification code"`, …) instead of bare `"otp"` / `"password"`,
  which is what let `hotpink`/`notPlaced`/`isPassword=false` match in the first place.
- **C2 endpoint strings tightened** to things specific enough to stand alone as an anchor
  (`api.telegram.org/bot`, `firebaseio.com`, `.onion`, `gate.php`, `/panel/`) — bare `http://` /
  `HttpURLConnection;->connect` were removed; "this app makes an HTTP request" is a capability, not
  evidence. Exact C2 IoCs are extracted separately by `apk_static.extract_c2_indicators` and scored via
  `ioc_component`, not `forensic_anchor_component`.
- **Tests:** `tests/test_forensic_gating.py` [NEW] — 209 lines covering the gate/clause logic and the
  specific false-positive substrings this fix removes.

---

### Session 9 — 2026-08-18 | Author: Tarun — Web UI + basic implementation

> **Overview:** Added a static single-page web UI served directly by FastAPI, so `/analyze` has a
> human-facing frontend instead of curl/Swagger-only access. No new backend endpoints — the UI calls
> the existing `/analyze` route.

**Files changed:** `app/api/routes.py`, `app/core/schemas.py`, `app/graph/cache.py`, `app/graph/ontology.py`, `app/main.py`, `.gitignore`
**Files added:** `app/static/index.html` [NEW], `app/static/app.js` [NEW, 595 lines], `app/static/styles.css` [NEW, 937 lines]

- **`app/main.py`** [MOD]: mounts `app/static/` at `/static` and serves `index.html` at `/` when the
  directory exists — the API is a no-op change for anyone hitting `/analyze` directly.
- **`app/static/`** [NEW]: upload form + risk-score/verdict-band display + narrative report rendering
  (via `marked.js`) + a Cytoscape.js graph view for behavioral subgraphs. Static assets only — no
  build step, no framework, loaded via CDN `<script>` tags (`marked`, `cytoscape`) plus Google Fonts.
- **`.gitignore`** [MOD]: `bin/ollama/` added — a portable Ollama build some contributors keep locally
  for GPU-accelerated report generation is **not part of this repo**; see the README note under
  Quickstart. It was committed once by accident (hundreds of MB of CUDA DLLs) and immediately reset
  out before ever reaching the remote — purged from local `.git` via `git gc --prune=now` after
  expiring the reflog. Never add binaries under `bin/` to git.
- **`app/graph/cache.py`, `app/graph/ontology.py`** [MOD]: minor fixes surfaced while wiring the UI
  end-to-end against a live Neo4j instance — not independently itemized here; see the diff.

---

### Session 8 — 2026-07-27 | Author: Rohit — Make the TTP dataset builder actually produce a dataset (AES extraction, parallel downloads, crash-resumable phases)

> **Overview:** `scripts/build_ttp_dataset.py` silently produced zero Stage A rows — every MalwareBazaar download was discarded before Androguard ever saw it. Fixed the download path, then made the whole builder survivable: downloads and analysis are now separate resumable phases, progress is logged to disk, and dataset rows are written as they are produced instead of once at the end.

**Files changed:** `scripts/build_ttp_dataset.py` [MOD], `requirements.txt` [MOD], `.gitignore` [MOD], `README.md` [MOD], `logs/.gitkeep` [NEW]

- **Download was broken two ways** — Stage A had never yielded a sample:
  - The success check rejected any response with a JSON `Content-Type`, which fired on **valid** zip downloads (abuse.ch does not reliably set `application/zip`). Now gated on the `PK` zip magic bytes; genuine errors still arrive as small JSON bodies and fail the check.
  - MalwareBazaar archives use **WinZip AES-256** (compression method 99), which stdlib `zipfile` cannot decrypt — extraction would have raised even past the first bug. Now uses `pyzipper.AESZipFile` (password `infected`), added as the one new dependency.
- **Parallel downloads** — `_download_many()` fetches a family's samples through a `ThreadPoolExecutor` and returns them in the original hash order so row order stays deterministic. Feature extraction is deliberately left serial: Androguard is CPU-bound and not thread-safe. Measured 15.3s → 7.4s on 4 live samples at 8 workers. `--download-workers` (default 8).
- **Atomic writes** — samples unpack to a thread-unique `.part` file then `os.replace()` into position. Required for concurrency, but it also fixes a latent bug: an interrupted run previously left a **truncated `.apk`** that the `os.path.exists()` resume check would reuse forever as a good sample.
- **Stage A split into two phases** (`--phase download|analyze|both`) — an OOM or Androguard crash during feature extraction used to kill the run and discard every downloaded APK's work:
  - `stage_a_download()` resolves hashes, fetches APKs, persists the manifest. Touches no Androguard.
  - `stage_a_analyze()` reads the manifest and extracts features from whatever landed on disk.
  - `data/ttp_apks/_manifest.json` carries `sha256 → {family, techniques}`; those labels previously lived only in a loop variable and could not survive the phase boundary.
- **Resolve sweep is now resumable** — `_mb_hashes_for_signature()` returns `(hashes, query_ok)`. A 502 and a genuinely empty family both returned `[]`, so transient failures were indistinguishable from real answers and were never retried. Per-family resolution status is recorded in the manifest, already-resolved families are skipped on rerun, and the manifest is **merged** rather than overwritten (overwriting dropped samples whose family errored on a later run, even with their APKs on disk).
- **Crash-survivable logging** — every run tees to `logs/build_ttp_dataset_<phase>_<timestamp>.log` (`enqueue=False`, so each record is flushed and survives a hard kill). Downloads log `[n/total] ok|fail <sha>`; analysis logs `[n/total] analysing <sha>` **before** each extraction, so an OOM leaves the offending sample as the last line in the file.
- **Incremental CSV** — `IncrementalCsvWriter` appends and flushes each row as its APK completes, so a crash costs one sample instead of the whole pass. The CSV doubles as the resume log: already-present `sha256`s are skipped before analysis (Stage B hashes each file first to do the same). Appending to a CSV whose header does not match the current 239 columns is **refused** — `TTP_FEATURE_NAMES` has changed before and appending would silently misalign every older row; `--overwrite` rebuilds from scratch. Final label stats are read back from the file, since a resumed run never holds most of the dataset in memory.
- **Per-sample exception guards** — `extract_ttp_row` calls in both stages are wrapped. Anchor matching, topology, and feature building sit outside that function's internal guards and can raise on malformed or packed APKs; one bad sample must not destroy a multi-hour run.
- **`.gitignore`**: `logs/*` with a tracked `logs/.gitkeep`. `data/ttp_apks/` (live malware **and** the regenerable manifest) stays fully ignored.
- **Verified:** AES download+extract against live MalwareBazaar (2.3 MB valid APK); serial-vs-parallel timing; manifest roundtrip and missing-sample reporting; only-failed-families re-queried on rerun (simulated 502); rows survive `os._exit(137)` with no cleanup; resume detects prior rows case-insensitively and appends no duplicate header; stale-header append raises; end-to-end `--phase analyze` on a real APK produces a correctly labelled row and a rerun adds no duplicates.

---

### Session 7 — 2026-07-22 | Author: Tarun — Android Malware Static Enrichments (C2 IoCs, Permission Matrices, Cert Anomalies, Secondary DEX Payloads, Uncompressed YARA Scanning)

> **Overview:** Comprehensive static malware analysis expansion targeting Android banking trojans, droppers, credential stealers, and evasion techniques. Extracted C2 channels, permission matrix patterns, certificate anomalies, secondary DEX payloads, and accessibility configuration flags directly into the analysis manifest and risk scoring engine.

**Files changed:** `app/analysis/apk_static.py` [NEW], `app/analysis/ingest.py` [MOD], `app/analysis/yara_engine.py` [MOD], `app/core/schemas.py` [MOD], `app/reports/scoring.py` [MOD], `tests/test_apk_enhancements.py` [NEW]

- **`app/analysis/apk_static.py`** [NEW]: Comprehensive Android static malware analyzer for banking trojans, droppers, and OTP stealers:
  - **C2 Threat Intel Extractor**: Pulls Telegram bot tokens/APIs (`telegram_bot:`), Firebase endpoints (`firebase:`), Discord webhooks (`discord_webhook:`), TOR `.onion` URLs (strictly validated against Tor base32 character encoding `[a-z2-7]`), raw IP:port endpoints (`raw_ip:`), and C2 panel gate URLs (`panel_url:`).
  - **Permission Matrix Risk Rules**: Detects multi-permission behavioral attack patterns:
    - `OVERLAY_ATTACK_PATTERN` (`SYSTEM_ALERT_WINDOW` + `PACKAGE_USAGE_STATS` / `QUERY_ALL_PACKAGES`)
    - `SMS_OTP_STEALER_PATTERN` (`BIND_ACCESSIBILITY_SERVICE` + `READ_SMS` / `RECEIVE_SMS`)
    - `DROPPER_STAGE2_PATTERN` (`REQUEST_INSTALL_PACKAGES` + `INTERNET`)
    - `DEVICE_ADMIN_PERSISTENCE` (`BIND_DEVICE_ADMIN`)
    - `BANKING_TARGET_ENUMERATION` (`QUERY_ALL_PACKAGES` + `INTERNET`)
  - **Certificate Anomaly Parser**: Analyzes X.509 certificates for debug keys (`CN=Android Debug`), generic/test subjects (`CN=test`), self-signed junk fields, and expired/future validity dates.
  - **Secondary DEX & Asset Payload Inspection**: Walks APK ZIP entries to count secondary DEX files (`classes2.dex`, `classes3.dex`) and assets with hidden `dex\n` / `PK\x03\x04` magic bytes, HTML banking overlay templates, and disguised native libraries.
  - **Accessibility Config XML Parser**: Parses XML accessibility resources for `canRetrieveWindowContent="true"`, `canPerformGestures="true"`, and event listening masks.
- **`app/analysis/ingest.py`** [MOD]: Integrated static enrichments into Phase 1 ingestion (`ingest_apk`), returning populated static anchor fields and uncompressed payload targets for Phase 1.5 YARA scanning.
- **`app/analysis/yara_engine.py`** [MOD]: Enhanced `scan_apk_with_payloads` to scan uncompressed DEX and asset byte streams in addition to the outer `.apk` ZIP file, eliminating ZIP compression evasion.
- **`app/core/schemas.py`** [MOD, additive]: Extended `IngestionResult` and `AnalysisManifest` with `c2_indicators`, `cert_anomalies`, `permission_matrix_flags`, `secondary_dex_count`, `accessibility_flags`, `exported_risks`, `payload_assets`, and `dropper_signals`.
- **`app/reports/scoring.py`** [MOD]: Integrated matrix flags, C2 counts, cert anomalies, secondary DEX counts, and dropper signals into `permission_api_component`, `reputation_component`, and `ioc_component`.
- **`tests/test_apk_enhancements.py`** [NEW]: Unit test suite covering C2 extraction, permission matrices, cert anomalies, Tor base32 validation, and schema validation. Full test suite passing (8/8 green).

---

### Session 6 — 2026-07-17 | Author: Rohit — Fix CFG construction crash on Androguard 4.1.2 (cold path was fully dead)

> **Symptom:** `/analyze` returned HTTP 200 but every sample came back with `total_nodes_parsed: 0`,
> `method_parse_failure_rate: 1.0`, `predicted_family: None`, and empty subgraphs — reported (wrongly)
> as *"100% of relevant methods failed CFG parsing — possible heavy obfuscation."* The whole cold-path
> graph pipeline was silently producing nothing.

**Commit — `fix(cfg): use DEXBasicBlock.childs property instead of nonexistent get_childs() on Androguard 4.1.2`**
- **`app/analysis/cfg.py`** [MOD]: `build_method_cfg()` called `block.get_childs()`, which does **not
  exist** on `DEXBasicBlock` in the pinned `androguard==4.1.2`. Every relevant method threw
  `AttributeError`, was caught by the broad `except` in `build_all_method_cfgs`, and counted as a parse
  failure — so 100% "failure" was a masked API mismatch, not obfuscation. Switched to the `childs`
  **property** (list of `(min_offset, max_offset, BasicBlock)` tuples); the existing tuple-unpacking
  logic already handled that shape, so this is a one-line fix + corrected comment.
- **Root cause note:** the old comment claimed `get_childs()` was "the correct Androguard 4.x API" — it
  is not for 4.1.x. The broad exception swallow in `build_all_method_cfgs` is what turned a hard API
  error into a plausible-looking (but false) obfuscation signal. Left the swallow in place (it is the
  intended obfuscation-resilience behavior) now that the underlying call is correct.
- **Verified end-to-end on `data/samples/test.apk`:** `total_nodes_parsed` 0 → **924**,
  `method_parse_failure_rate` 1.0 → **0.0**, **123** behavioral subgraphs, flattening + 124 reflection
  calls detected, risk score 26.97/low → **44.23/suspicious** with `zero_day_indicator: True`, and a
  genuine 3964-char Ollama narrative (previously the error stub, also from a `.env` `OLLAMA_BASE_URL`
  missing `/v1` — corrected locally in `.env`, not tracked). Full test suite **13/13 green**.
- **Still stubbed by design (unchanged, not regressions):** `predicted_family: None` (no trained family
  model → cold-path `store_signature` cache write never fires) and `predicted_ttps: []` (no trained TTP
  model). Neo4j ontology (262 nodes: 124 Technique / 12 Tactic / 126 MalwareFamily) is loaded via the
  `scripts/` and is independent of this fix.

---

### Session 5 — 2026-07-16 | Author: Rohit — Multi-label MITRE ATT&CK TTP classifier + zero-day cold-path risk engine

> Replacing the family→TTP proxy (`FAMILY_TO_TTPS`) with a **genuine multi-label MITRE ATT&CK Mobile
> TTP classifier** (Binary Relevance XGBoost) and turning the cold path into an explicit **zero-day
> risk engine**. Fuses the **GUARD** paper's graph-invariant topology with **DroidTTP's** multi-label
> TTP mapping, grounded by a pre-populated ATT&CK Mobile ontology so GraphRAG stays evidence-bounded.
> Decisions (locked with the team): Binary Relevance default + benchmark CC/LP; hybrid staged dataset;
> expanded feature schema added **additively** in `features.py` (33-vector invariant preserved).

**Commit 1 — `feat(ontology): build MITRE ATT&CK Mobile TTP label space and full ontology from STIX`**
- **`app/ml/labels.py`** [NEW]: canonical multi-label output contract. `TTP_LABELS` = 57 curated,
  real, current Mobile ATT&CK parent techniques (banking-fraud-weighted, 11 tactics), plus
  `TECHNIQUE_TACTIC` / `TECHNIQUE_NAME` maps. This is to the TTP model what `FEATURE_NAMES` is to the
  feature vector — **freeze-before-train invariant** documented. `load_full_technique_ontology()`
  reads the STIX-derived JSON when present, else falls back to the baked-in catalog.
- **`scripts/build_ttp_label_space.py`** [NEW]: fetches `mobile-attack.json` from
  `mitre-attack/attack-stix-data`, parses techniques/tactics/software/`uses` relationships, and emits
  `data/ontology/mobile_techniques.json` + `data/ontology/software_technique_map.json`. Prints a
  coverage report vs. the frozen `TTP_LABELS` (never auto-rewrites the contract).
- **`app/graph/ontology.py`** [MOD]: added `load_full_ontology()` — loads the full technique/tactic
  set + `MalwareFamily-[:USES]->Technique` edges so GraphRAG has a grounded description for **every**
  predictable TTP. `load_starter_ontology()` kept as a zero-network seed; `get_technique_context()`
  signature unchanged.
- **`scripts/load_ontology.py`** [MOD]: defaults to the full ontology; `--starter` for the legacy seed.
- **Verified:** `app/ml/labels.py` imports cleanly (57 labels, sorted, consistent maps). STIX
  fetch + Neo4j load require network/DB — not exercised in this environment.

**Commit 2 — `feat(ml): add expanded GUARD+DroidTTP feature schema for multi-label TTP model`**
- **`app/ml/features.py`** [MOD, additive]: added `TTP_FEATURE_NAMES` (**179 features**) and
  `build_ttp_feature_vector(...)` — DroidTTP-style binary presence vocab (92 permissions + 25 intent
  actions + 32 sensitive-API substrings + 3 component counts) **+** the family model's 6 behavior
  flags + 15 GUARD topology stats + 3 obfuscation + 3 signature/YARA blocks (reused for consistency).
  The existing `FEATURE_NAMES` (33) and `build_feature_vector` are **not modified** — 33-vector
  invariant preserved.
- **`app/analysis/topology.py`** [MOD]: added `aggregate_subgraph_invariants(list_of_dicts)` →
  per-key mean across **all** anchor subgraphs (fixes the `behavioral_subgraphs[0]`-only bug where
  only the first suspicious region reached the model). Length stays 15; empty→all-zero, never raises.
- **Verified:** `build_ttp_feature_vector` emits exactly 179 values (empty + populated); no duplicate
  feature names; component-count cap (50) works; aggregation mean correct; legacy 33-vector unchanged.

**Commit 3 — `feat(data): add staged multi-label TTP dataset builder (STIX refs + weak-label bootstrap)`**
- **`scripts/build_ttp_dataset.py`** [NEW]: hybrid dataset builder. **Stage A** — for each software in
  `software_technique_map.json`, pull Android sample hashes from MalwareBazaar (`get_siginfo`),
  download+unzip APKs (`get_file`, pwd `infected`), extract features, label with that software's ATT&CK
  techniques (`label_source="stix_ref"`). **Stage B** — weak-label local CICMalDroid2020 APKs from
  forensic-dictionary behaviors via `BEHAVIOR_TO_TTPS` (`label_source="weak"`). Emits
  `data/ttp_dataset.csv` = 179 feature cols + 57 technique cols + 3 meta. Reuses the exact cold-path
  analysis functions and calls `build_ttp_feature_vector`, so training/inference columns match.
- **`app/core/schemas.py`** [MOD, additive]: `IngestionResult.intent_actions: list[str] = []`
  (feeds the TTP intent vocab; legacy family model does not read it).
- **`app/analysis/ingest.py`** [MOD]: added `extract_intent_actions(apk_obj)` (best-effort, guarded)
  and populate `IngestionResult.intent_actions` in `ingest_apk`.
- HTTP uses stdlib `urllib` (matches `signatures.py`) — **no new dependency**.
- **Verified:** both scripts import cleanly; `_row_dict` produces the exact 239-column contract;
  `IngestionResult.intent_actions` defaults to `[]`. Network stages (MalwareBazaar + APK download)
  require an API key + connectivity — not exercised in this environment.

**Commit 4 — `feat(ml): implement Binary-Relevance XGBoost multi-label TTP classifier with LP/CC benchmark`**
- **`app/ml/classifier.py`** [MOD, additive]: added `BinaryRelevanceXGB` (one XGBoost per technique,
  per-label `scale_pos_weight`, constant fallback for degenerate columns) + `TTPClassifier` +
  `ttp_classifier` singleton. `predict()` returns `{technique_id: prob}` over **all 57** `TTP_LABELS`
  (untrained labels → 0.0). Same loud-stub contract (`FileNotFoundError` until trained). The family
  `MalwareClassifier`/`classifier` singleton is unchanged.
- **`scripts/train_model.py`** [MOD, extend]: added `--target ttp` path (family training stays the
  default). Trains **BR** (shipped, saved to `data/models/guardgraph_ttp_br_v1.joblib`) and
  **benchmarks Classifier Chains + Label Powerset**, reporting DroidTTP-style metrics (micro/macro
  F1, sample Jaccard, Hamming loss) to `data/models/ttp_metrics.json`. Multi-label stratified split
  via `iterative-stratification` when installed, else a graceful random-split fallback.
- **Verified end-to-end on synthetic signal data (320 rows, 9 labels):** BR trains + saves; benchmarks
  run — BR micro-F1 **0.90** > CC 0.89 > LP 0.78 (LP worst, consistent with the zero-day rationale);
  `TTPClassifier.load()+predict()` returns probs over all 57 labels; SMS-driver vector → T1636/T1582
  top (>0.5); benign vector max 0.03; untrained labels → 0.0. *(Real APK-derived data pending; the
  synthetic model is a wiring check only.)*

**Commit 5 — `feat(cold-path): wire multi-label TTP classifier into zero-day risk scoring engine`**
- **`app/core/pipeline.py`** [MOD]: Phase 4 now builds BOTH the legacy family 33-vector (unchanged)
  and the **179-feature TTP vector** (GUARD topology aggregated across ALL anchor subgraphs; API
  presence over all CFG calls) — returns a 5-tuple. Phase 5 calls `ttp_classifier.predict()` for
  `predicted_ttps` **directly** (thresholded at `TTP_PREDICT_THRESHOLD=0.5`, probs retained); the
  family model is now an **auxiliary** label only. The `FAMILY_TO_TTPS` proxy is no longer used on
  the cold path.
- **`app/api/routes.py`** [MOD]: unpack the Phase-4 5-tuple; pass both vectors to Phase 5.
- **`app/reports/scoring.py`** [MOD]: `ttp_severity_component` now covers the **full** Mobile space
  via `_technique_severity` (per-technique override → tactic-derived → DEFAULT). Added the
  **zero-day indicator**: strong deterministic (forensic anchor) and/or structural (obfuscation)
  evidence + low model confidence + not a cache hit ⇒ `zero_day_indicator=True`. Formula weights
  unchanged — the model-free components already provide the score floor.
- **`app/core/config.py`** [MOD]: added `TACTIC_SEVERITY` (per-tactic base severity); marked
  `FAMILY_TO_TTPS` legacy/hot-path-only.
- **`app/core/schemas.py`** [MOD, additive]: `RiskScoreBreakdown.zero_day_indicator: bool = False`.
- **Verified (no APK needed):** Phase 4 returns 5 values with a 179-len TTP vec; Phase 5 emits direct
  TTPs (T1636/T1582) with the synthetic model and `None` family (graceful); tactic severity correct
  (T1642 Impact→0.95, T1418 Discovery→0.4); zero-day indicator True on anchors/obfuscation-high +
  empty model, False when model confident, on cache hit, and on benign.

**Commit 6 — `test(ml): add multi-label TTP tests and update project docs`**
- **`app/reports/graphrag.py`** [MOD]: added guardrail rule 7 — when `zero_day_indicator` is true,
  the report prominently flags a POSSIBLE NOVEL / ZERO-DAY VARIANT and states the verdict rests on
  model-free evidence. Already retrieves `get_technique_context()` for the directly-predicted TTPs, so
  with the full ontology (Commit 1) every predicted technique is grounded (no ungrounded MITRE text).
- **`tests/test_features.py`** [MOD]: added `test_ttp_feature_vector_length` (179-vector invariant +
  no-duplicate-columns + count-cap check), alongside the existing 33-vector test.
- **`tests/test_pipeline_phases.py`** [MOD]: fixed Phase-4 test for the 5-tuple return (asserts 179-len
  TTP vec); added `test_phase5_ttp_classification_contract` (keys ⊆ `TTP_LABELS`, probs in [0,1],
  robust to model presence) and `test_phase6_zero_day_indicator`.
- **`requirements.txt`** [MOD]: pinned `loguru` (was used unpinned) and added
  `iterative-stratification` (multi-label stratified split; trainer falls back to random split if absent).
- **`.gitignore`** [MOD]: ignore `data/ttp_apks/` (downloaded real malware — never commit).
  `data/models/*` and `data/*.csv` already cover the model + dataset.
- **`README.md` / `GUARDGRAPH_PROJECT_CONTEXT.md`** [MOD]: documented the multi-label TTP workflow,
  zero-day engine, and the new commands.
- **Verified — FULL SUITE GREEN:** `tests/test_features.py` (33 + 179 invariants),
  `tests/test_pipeline_phases.py` (5 tests: phases exist, Phase-4 5-tuple, Phase-5 TTP contract,
  Phase-6 risk + zero-day), `tests/test_signatures_yara.py` (regression) all pass. No regressions.

**Feature vector schema: NEW parallel TTP contract (179) added; legacy family vector (33) UNCHANGED.**

---

### Session 4 — 2026-07-16 | Author: Tarun

**Files changed:** `app/analysis/signatures.py` [NEW], `app/analysis/yara_engine.py` [NEW], `app/core/config.py`, `app/core/schemas.py`, `app/core/pipeline.py`, `app/api/routes.py`, `app/ml/features.py`, `app/reports/scoring.py`, `requirements.txt`  
**Files added:** `scripts/download_yara_rules.py`, `scripts/test_upload.py`, `data/signatures/known_hashes.json`, `data/yara_rules/` (518 rules), `tests/test_signatures_yara.py`

| # | Change | File(s) Changed | Status |
|---|---|---|---|
| Phase 1.5 | New pipeline phase inserted between ingestion and CFG: hash+cert local signature lookup → VirusTotal API triage → MalwareBazaar API triage → YARA rule scanning | `pipeline.py`, `routes.py`, `signatures.py`, `yara_engine.py` | ✅ Done |
| Signature DB | Local JSON signature database `data/signatures/known_hashes.json` seeded with known banking trojan SHA-256 hashes (Anubis, Cerberus, TeaBot, FluBot, Sharkbot, Octo, Hydra) and certificate thumbprints | `known_hashes.json` | ✅ Done |
| VirusTotal triage | `_lookup_virustotal()` queries VT API v3 on cache miss. Returns family name, `detection_ratio` (e.g. `"23/74 engines"`), severity scaled by engine count, and a direct clickable `report_url` to `virustotal.com/gui/file/<sha256>` | `signatures.py` | ✅ Done |
| MalwareBazaar triage | `_lookup_malwarebazaar()` queries the abuse.ch public hash-lookup endpoint (no auth needed for `get_info`). Returns family/ClamAV tag, severity 0.95, and `report_url` to `bazaar.abuse.ch/sample/<sha256>` | `signatures.py` | ✅ Done |
| YARA engine | `app/analysis/yara_engine.py` compiles 8 built-in banking-trojan rules (SMS interception, C2 command patterns, accessibility abuse, overlay attacks, DEX manipulation, encoded payload, packer stubs, obfuscated class names) + all valid external `.yar` files from `data/yara_rules/`. Validates each community rule individually — broken rules are skipped with a warning instead of crashing the entire engine | `yara_engine.py` | ✅ Done |
| Community rules | `scripts/download_yara_rules.py` downloads the `Yara-Rules/rules` GitHub repo as a ZIP, filters out rules using `import "androguard"` or `import "cuckoo"` (non-standard modules), and saves 518 clean rules. 455 successfully compile at runtime; 19 have relative include errors and are safely skipped | `download_yara_rules.py`, `data/yara_rules/` | ✅ Done |
| Schema | Added `SignatureMatch`, `YaraMatch`, `SignatureYaraResult` Pydantic models. `SignatureMatch` includes `report_url` (clickable link) and `detection_ratio` (e.g. `"23/74 engines"`). `AnalysisManifest` now has `signature_yara: SignatureYaraResult` field | `schemas.py` | ✅ Done |
| Feature vector | Extended from **30 → 33 features** by adding `signature_match_count`, `yara_rule_match_count`, `yara_max_severity`. **Model must be retrained** to use these — existing model still works (XGBoost only checks count, not names; zero-fill is safe for v1 interim) | `features.py` | ✅ Done |
| Risk scoring | `reputation_component` now jumps to high-risk (score 8+) on any known-malware signature hit. `ioc_component` now scales with combined YARA match count and max severity | `scoring.py` | ✅ Done |
| Tests | Added `tests/test_signatures_yara.py` covering local hash/cert match, mocked VirusTotal, mocked MalwareBazaar, and YARA scan. Updated `tests/test_features.py` and `tests/test_pipeline_phases.py` for 33-feature vector | `tests/` | ✅ Done |
| API keys | VT and MalwareBazaar keys added to `.env` and registered in `config.py` as `virustotal_api_key` / `malwarebazaar_api_key`. MalwareBazaar hash lookup is public — key stored but not used for hash queries (only needed for file submission/download) | `.env`, `config.py` | ✅ Done |

**Live test result (2026-07-16):** `f651876e...bbbced.apk` correctly identified as `trojan.ag1587137/abrisk` by VirusTotal (23/74 engines), with 5 YARA rules matched: `android_meterpreter`, `contains_base64`, `possible_includes_base64_packed_functions`, `domain`, `IP`. Clickable VT report URL returned in API response.

**Feature vector schema: CHANGED (30 → 33) — retrain model when ready, but current model still runs safely with zero-filled new columns.**

---

### Session 3 — 2026-07-06 | Author: Ajay

**Files changed:** `app/graph/cache.py`, `app/api/routes.py`, `.gitignore`  
**Files added:** `scripts/test_rag_pipeline.py`

| # | Change | File(s) Changed | Status |
|---|---|---|---|
| Hot Path | LLM narrative + limitations now cached in Neo4j `(s:Sample)` node during cold path; hot path serves cached text directly — **`generate_report()` is no longer called on cache hits** | `cache.py`, `routes.py` | ✅ Done |
| RAG Harness | Standalone test script that injects mock `AnalysisManifest` + `RiskScoreBreakdown` into `generate_report()`, bypassing Androguard + ML. Mocks Neo4j ontology call. Successfully tested against local Ollama (`qwen2.5:7b-instruct-q4_K_M`) | `scripts/test_rag_pipeline.py` | ✅ Done |
| Obsidian | Added `.obsidian/`, `AI_ENGINEER_TASKS.md`, `*.tasks.md`, `.venv/` to `.gitignore` so personal task tracking and vault settings stay local | `.gitignore` | ✅ Done |

**Key architectural change:** The hot path now achieves the design doc's `<50ms` target by serving pre-computed LLM narratives from Neo4j, eliminating the 5–10s Ollama call on cache hits.

**RAG hallucination spot-check (initial):** The `qwen2.5:7b-instruct` model correctly grounded its report on the mock manifest data and cited confidence values. Minor drift observed in "Recommended Analyst Actions" section — model gave generic IT advice instead of APK-specific analyst actions. Prompt tuning needed.

---

### Session 2 — 2026-07-06 | Author: Ajay

**Files changed:** `app/core/config.py`, `app/core/schemas.py`, `app/analysis/cfg.py`,  
`app/analysis/obfuscation.py`, `app/reports/scoring.py`, `app/api/routes.py`, `app/graph/neo4j_client.py`

| # | Defect / Issue | File(s) Changed | Status |
|---|---|---|---|
| §9.1 | Hot path did not short-circuit — full CFG pipeline ran even on cache hits | `routes.py` | ✅ Fixed |
| §9.2 | Family-name keys fed into TTP severity lookup (always returned DEFAULT — 20% of score was dead) | `config.py`, `routes.py` | ✅ Fixed |
| §9.3 | Forensic anchor matches (proven API presence) had zero weight in risk score | `scoring.py`, `schemas.py`, `routes.py` | ✅ Fixed |
| §9.4 | Graph density was a meaningless cross-method sum | `routes.py` | ✅ Fixed |
| §9.5 | Coverage gaps (native, reflection, parse failures) did not raise the score | `scoring.py`, `obfuscation.py` | ✅ Fixed |
| §9.6 | CFG parse failures silently swallowed; Neo4j connect had no error handling | `cfg.py`, `neo4j_client.py`, `obfuscation.py` | ✅ Fixed |
| §9.7 | 4-hop constant unvalidated — no instrumentation to check over/under-capture | `schemas.py`, `routes.py` | ✅ Instrumented |
| §10.3 | CFG built for every method before anchor detection — expensive on large APKs | `cfg.py` | ✅ Fixed |

**Feature vector schema: UNCHANGED — no retraining needed.**

---

### Session 1 — 2026-07-06 | Author: Ajay

Initial prototype skeleton scaffolded and delivered. All files listed in the directory structure were created. See §3 for full build status.

---

## 1. What This Project Is

**GuardGraph AI** — static-analysis-only Android malware detection and risk-scoring engine for banking fraud threats (banking trojans, OTP interception, credential harvesting, SMS abuse).

**Core idea:** APK → Control Flow Graphs (CFGs) + Attributed CFGs (ACFGs) → graph-invariant topological features (centrality, clustering) around suspicious code regions → features survive obfuscation → classify behavior → risk score → analyst report.

**Why static-only:** Dynamic analysis (sandboxing/emulation) ruled out as too slow for banking fraud campaigns. Static graph-invariant features survive identifier renaming, junk-code insertion, and control-flow flattening.

**Key product decision:** The system explicitly reports what it *could not* analyze (native code, encrypted strings, unresolved reflection) rather than silently guessing. This is a compliance selling point, not an engineering shortcut.

**LLM backend:** Local Ollama (OpenAI-compatible at `http://localhost:11434/v1`). No cloud API keys needed. Default model: `qwen2.5:7b-instruct-q4_K_M`.

---

## 2. Directory Structure

```
guardgraph-ai/
├── app/
│   ├── main.py                   FastAPI entrypoint, /health endpoint
│   ├── api/routes.py             /analyze endpoint — full pipeline orchestrator
│   ├── core/
│   │   ├── config.py             Settings, MODEL_LABEL_MAP, TTP_SEVERITY_WEIGHTS, FAMILY_TO_TTPS, API keys
│   │   └── schemas.py            Pydantic contracts (IngestionResult, SignatureMatch, YaraMatch, AnalysisManifest, etc.)
│   ├── analysis/
│   │   ├── ingest.py             SHA-256, cert thumbprint, Androguard ingestion, static enrichments
│   │   ├── apk_static.py         [NEW S7] C2 regex extractor, permission matrices, cert anomalies, secondary DEX payloads, a11y config XML
│   │   ├── signatures.py         [NEW S4] Local hash/cert DB + VT + MalwareBazaar online triage
│   │   ├── yara_engine.py        [NEW S4] YARA compiler + scanner (outer APK + uncompressed DEX/asset byte streams)
│   │   ├── cfg.py                CFG + ACFG enrichment (NetworkX) + relevance pre-filter
│   │   ├── forensic.py           Forensic dictionary, anchor detection, 4-hop subgraph extraction
│   │   ├── topology.py           Centrality/clustering stats, flattening outlier detection
│   │   └── obfuscation.py        Entropy scoring, reflection counting, coverage notes
│   ├── ml/
│   │   ├── labels.py             [NEW S5] *** SINGLE SOURCE OF TRUTH for TTP output order (57 Mobile techniques) ***
│   │   ├── features.py           *** feature schemas: FEATURE_NAMES (33, family) + TTP_FEATURE_NAMES (179, S5) ***
│   │   └── classifier.py         MalwareClassifier (family) + [S5] BinaryRelevanceXGB / TTPClassifier (multi-label TTP)
│   ├── graph/
│   │   ├── neo4j_client.py       Thin driver wrapper (graceful connect failure)
│   │   ├── cache.py              Hot-path signature lookup/store
│   │   └── ontology.py           MITRE ATT&CK Mobile starter ontology loader
│   ├── static/                   [NEW S9] Web UI served by FastAPI at `/` — upload form, verdict display,
│   │   ├── index.html            narrative rendering (marked.js), behavioral-subgraph graph view
│   │   ├── app.js                (Cytoscape.js). No build step — CDN script tags. Static only, not tracked
│   │   └── styles.css            in this doc file-by-file below (see Session 9 change log entry).
│   └── reports/
│       ├── scoring.py            [S11] Risk score formula (7-component, 0-100), calibration constants,
│       │                         named verdict-band constants — see §5
│       └── graphrag.py           Ollama-based report generation (anti-hallucination system prompt)
├── scripts/
│   ├── train_model.py            family training + [S5] --target ttp (BR + CC/LP benchmark)
│   ├── build_ttp_label_space.py  [NEW S5] ATT&CK Mobile STIX → label space + ontology JSON
│   ├── build_ttp_dataset.py      [S5, S8] staged multi-label TTP dataset (MalwareBazaar + weak-label);
│   │                             [S8] two resumable phases (--phase download|analyze), manifest, incremental CSV
│   ├── load_ontology.py          Neo4j ontology seed ([S5] full Mobile ontology by default)
│   ├── download_yara_rules.py    [NEW S4] Downloads + filters Yara-Rules/rules community repo
│   ├── score_corpus.py           [NEW S11] Measures every scoring component against the 353-APK corpus
│   │                             (220 F-Droid benign + 133 MalwareBazaar malware) — source of every
│   │                             calibration constant and verdict-band boundary in scoring.py
│   └── test_upload.py            [NEW S4] Local test script to POST an APK and pretty-print the report
├── tests/
│   ├── test_features.py          Feature vector length invariant test (MUST always pass — currently 33)
│   ├── test_pipeline_phases.py   Phase contract and integration tests
│   ├── test_signatures_yara.py   [NEW S4] Signature matching + YARA scan unit tests
│   ├── test_apk_enhancements.py  [NEW S7] Static malware enrichments unit tests
│   ├── test_forensic_gating.py   [NEW S10] Manifest-gate + same-method-clause forensic rule tests
│   └── test_score_calibration.py [NEW S11] Pins calibration constants + verdict band boundaries
├── data/
│   ├── samples/                  (gitignored) APK files for testing
│   ├── models/                   (gitignored) trained XGBoost model goes here
│   ├── ttp_apks/                 (gitignored) [S8] Stage A downloads + _manifest.json — live malware, never commit
│   ├── signatures/
│   │   └── known_hashes.json     [NEW S4] Local hash+cert signature database (Anubis, Cerberus, TeaBot, etc.)
│   └── yara_rules/               [NEW S4] 518 community YARA rules (455 compile successfully)
├── logs/                         [NEW S8] (contents gitignored) per-run build_ttp_dataset logs; .gitkeep tracked
├── docker-compose.yml            Neo4j only
├── requirements.txt
├── .env.example                  Copy to .env and fill in
└── README.md
```

---

## 3. Current Build Status

### What Is Real (Fully Implemented)

| Component | File | Notes |
|---|---|---|
| APK ingestion (SHA-256, cert, manifest) | `ingest.py` | Androguard AnalyzeAPK |
| CFG/ACFG construction | `cfg.py` | Per-method, NetworkX DiGraph |
| Relevance pre-filter | `cfg.py` | `is_method_relevant()` — skips methods with no forensic-dict overlap |
| Parse failure tracking | `cfg.py` | Returns `(graphs, failure_rate)` tuple |
| Forensic dictionary + anchor detection | `forensic.py` | 6 behavior categories. **[S10] Each rule now gates on a manifest declaration (permission or intent-filter action) and groups patterns into clauses that must corroborate within one method** — the old flat OR read backwards on the corpus (clean apps fired more behaviors than malware) |
| 4-hop subgraph extraction | `forensic.py` | `extract_anchor_subgraph()` |
| Topological feature mining | `topology.py` | Degree, closeness, clustering centrality |
| Flattening outlier detection | `topology.py` | Z-score on degree distribution. **[S11] Measured but not scored** — no lift over the corpus (benign/malware p75 nearly identical) |
| Shannon entropy scoring | `obfuscation.py` | Over full string pool. **[S11] Measured but not scored** — corpus mean runs backwards (benign > malware) and never reaches the threshold |
| **[S9] Web UI** | `app/static/` | Upload form + verdict display + narrative rendering + Cytoscape.js subgraph view. Served by FastAPI at `/`, no build step |
| **[S11] Corpus scoring/calibration tool** | `score_corpus.py` | Measures all 7 components + verdict bands against 220 benign + 133 malware; source of every constant in `scoring.py`'s calibration block |
| Reflection call counting | `obfuscation.py` | Call sites counted; resolution is stubbed |
| Coverage note generation | `obfuscation.py` | Includes parse failure rate >= 10% |
| **[S4] Local signature matching** | `signatures.py` | SHA-256 + cert thumbprint against `data/signatures/known_hashes.json` |
| **[S4] VirusTotal online triage** | `signatures.py` | VT API v3; returns family, `detection_ratio`, clickable `report_url` |
| **[S4] MalwareBazaar online triage** | `signatures.py` | Public hash-lookup; returns family, `report_url` |
| **[S4] YARA scanning** | `yara_engine.py` | 8 built-in rules + 455 community rules; outer APK + uncompressed inner DEX/asset streams |
| **[S7] Static Malware Enrichments** | `apk_static.py` | C2 IoCs (Telegram, Firebase, raw IP, TOR), permission matrices, cert anomalies, secondary DEX payloads |
| **[S8] TTP dataset builder** | `build_ttp_dataset.py` | Stage A downloads (AES-decrypted, parallel) and analysis are separate resumable phases; manifest + incremental CSV survive a crash |
| Risk scoring — all 7 components | `scoring.py` | See formula below |
| Neo4j hot-path cache lookup | `cache.py` | Degrades gracefully on DB outage |
| MITRE ontology retrieval | `ontology.py` | Used by GraphRAG for grounded context |
| GraphRAG report generation | `graphrag.py` | Ollama, strict anti-hallucination prompt |
| Full pipeline orchestration | `routes.py` | Hot-path truly short-circuits; cold-path complete |

### What Is Stubbed (Intentionally — Fails Loudly)

| Component | File | Current Behavior |
|---|---|---|
| XGBoost classifier | `classifier.py` | `FileNotFoundError` until model trained; pipeline proceeds with empty predictions |
| Reflection constant-propagation | `obfuscation.py` | Call sites counted; `unresolved` always returns 0 |
| Native (.so) analysis | — | Not implemented; flagged in coverage_note |
| String-decrypt micro-execution | — | Not implemented; entropy signal used as proxy |
| Packer fingerprinting | — | Not implemented |

### Explicitly Out of Scope for Prototype

Celery/Redis, Postgres, S3, Kubernetes, Terraform, auth, job queues, multi-user support,
full MALOnt/UCO ontology, SHAP explainability, adversarial robustness testing,
eigenvector/Katz centrality.

---

## 4. Pipeline: Two Execution Paths

### Hot Path (cache hit — target <50 ms)

```
upload → SHA-256 → Neo4j lookup → cache HIT
  → compute_risk_score (from cached data, no CFG work at all)
  → generate_report (Ollama)
  → AnalysisReport
```

### Cold Path (unknown sample)

```
upload → SHA-256 → Neo4j lookup → cache MISS
  → Androguard AnalyzeAPK
  → [Phase 1.5 NEW S4] match_signatures(sha256, cert_thumbprint)
      → local DB lookup (data/signatures/known_hashes.json)
      → VirusTotal API v3 (if no local match + VT key set)
      → MalwareBazaar API (public endpoint, always queried)
      → yara_scan_file(filepath, rules_dir="data/yara_rules")
          → compile_rules(): 8 built-in + 455 community rules (19 broken skipped)
          → rules.match(filepath) → [YaraMatch, ...]
  → build_all_method_cfgs(use_relevance_filter=True)
      → is_method_relevant() pre-filter [CHEAP]
      → build_method_cfg + enrich_acfg [EXPENSIVE, only for relevant methods]
      → returns (cfgs: dict, parse_failure_rate: float)
  → for each CFG: match_anchors → extract_anchor_subgraph(hops=4) → compute_topological_invariants
  → build_obfuscation_signal(entropy + flattening + reflection + parse_failure_rate)
  → build_feature_vector → classifier.predict [raises FileNotFoundError if untrained]
  → FAMILY_TO_TTPS bridge → predicted_ttps (MITRE T-numbers with 0.85 confidence discount)
  → compute_risk_score(7 components, matched_anchor_behaviors=set of behavior names)
  → generate_report(manifest + risk_score → Ollama → narrative text)
  → store_signature(Neo4j) [future hits take hot path]
  → AnalysisReport
```

---

## 5. Risk Scoring Formula (Current — Session 11, recalibrated against the 353-APK corpus)

```
Risk Score (0–100) =
    0.25 × classifier_confidence       threshold-normalized evidence mass across ALL predicted
                                        techniques (not max probability) — Session 11
  + 0.20 × permission_api_risk         weighted dangerous permissions + permission matrix flags
  + 0.15 × ttp_severity                MITRE T-number severities (direct multi-label TTP model, Session 5)
  + 0.15 × forensic_anchor             manifest-gated + same-method-clause anchor matches — Session 10
  + 0.15 × obfuscation / coverage      manifest-vs-code mismatch + CFG parse failure rate — Session 11
                                        (string entropy & flattening measured/reported, NOT scored — both
                                        measured dead/inverted over the corpus)
  + 0.05 × reputation                  Neo4j cache prior score
  + 0.05 × ioc                         sample-identifying evidence (uncapped-ish) + circumstantial
                                        evidence (jointly capped at 0.35) — Session 11
```

**Verdict bands (Session 11, named constants in `scoring.py`, derived from measured score distributions —
reproduce with `python scripts/score_corpus.py`):**
`BAND_LOW_CEILING = 30.0` | `BAND_SUSPICIOUS_CEILING = 60.0` | `BAND_HIGH_CEILING = 65.0`

```
0–30    Low          (clean corpus p95 = 26.73; 212/220 clean apps land here)
31–60   Suspicious   (highest score any of the 220 clean apps reached is 53.33 — `high` is a
                       band the clean corpus never enters)
61–65   High         (below the malware first-quartile in two corpus runs — chosen to tolerate
                       day-to-day VirusTotal/MalwareBazaar answer variance)
66–100  Malicious    (106/133 corpus malware read High or Malicious; was 80.0 before Session 11,
                       where only 12/133 malware ever reached Malicious)
```

### Forensic Anchor Behavior Severity Weights (BEHAVIOR_SEVERITY in scoring.py)

| Behavior Flag | Severity |
|---|---|
| STEALTH_SMS_INTERCEPTION | 1.00 |
| OTP_INTERCEPTION | 0.95 |
| CREDENTIAL_HARVESTING | 0.90 |
| C2_BEHAVIOR | 0.70 |
| DYNAMIC_REFLECTION | 0.60 |
| CRYPTOGRAPHY_USAGE | 0.40 |

---

## 6. Critical Invariants

### Feature Vector Schema (NEVER CHANGE WITHOUT RETRAINING)

`app/ml/features.py` → `FEATURE_NAMES` → **33 features** in this order (updated Session 4):

```
[6 permission flags]      android.permission.BIND_ACCESSIBILITY_SERVICE, READ_SMS,
                          RECEIVE_SMS, SEND_SMS, SYSTEM_ALERT_WINDOW, REQUEST_INSTALL_PACKAGES
[6 behavior flags]        STEALTH_SMS_INTERCEPTION, OTP_INTERCEPTION, DYNAMIC_REFLECTION,
                          CRYPTOGRAPHY_USAGE, CREDENTIAL_HARVESTING, C2_BEHAVIOR
[15 topology stats]       degree_centrality × {mean,std,median,min,max}
                          closeness_centrality × {mean,std,median,min,max}
                          clustering_coefficient × {mean,std,median,min,max}
[3 obfuscation features]  string_entropy_score, flattening_suspected, reflection_call_count
[3 signature/YARA — NEW S4] signature_match_count, yara_rule_match_count, yara_max_severity
```

> ⚠️ **Retraining note (Session 4):** The current XGBoost model was trained on 30 features. The 3 new columns are zero-filled at inference time — predictions remain valid but do not yet benefit from signature/YARA signal. Retrain once a labelled dataset is available that includes these new features.

XGBoost has no concept of column names at inference time — a column-order mismatch produces confident, wrong predictions with no error raised.

#### Multi-label TTP contracts (Session 5 — NEVER CHANGE WITHOUT RETRAINING THE TTP MODEL)

Two additional frozen contracts, additive alongside the 33-vector:

- `app/ml/labels.py` → `TTP_LABELS` → **57 MITRE ATT&CK Mobile techniques** (the classifier's output
  column order — freeze before training). `TECHNIQUE_TACTIC` / `TECHNIQUE_NAME` maps included.
- `app/ml/features.py` → `TTP_FEATURE_NAMES` / `build_ttp_feature_vector` → **179 features**
  (92 perms + 25 intents + 32 sensitive APIs + 3 component counts + 6 behaviors + 15 topology +
  3 obfuscation + 3 signature/YARA). Same silent-mismatch hazard as the 33-vector.

The legacy 33-vector `FEATURE_NAMES` and the family `MalwareClassifier` are unchanged.

### GraphRAG Guardrails (Never Relax)

1. Only state findings present in the JSON manifest, risk score, or MITRE ontology context
2. Say "not observed" — never invent evidence
3. Separate deterministic findings from model predictions
4. Always include confidence values with predicted TTPs
5. End with "Recommended Analyst Actions" in priority order

---

## 7. File-by-File: Current State After Session 2

### `app/core/config.py`

Key exports:
- `settings` — reads NEO4J_URI, OLLAMA_BASE_URL, OLLAMA_MODEL, etc. from `.env`
- `MODEL_LABEL_MAP = ["banker","trojan","password_stealer","coinminer","rat","keylogger"]`
- `TTP_SEVERITY_WEIGHTS = {"T1636": 0.9, "T1624": 0.8, "T1417": 0.85, "T1409": 0.6, "T1471": 0.95, "DEFAULT": 0.5}`
- `FAMILY_TO_TTPS` — NEW in Session 2: `{"banker": ["T1636","T1417","T1624"], "trojan": ["T1624","T1409"], ...}` (all 6 families mapped)

---

### `app/core/schemas.py`

```
IngestionResult:      sha256, package_name, cert_thumbprint, permissions,
                      activities, services, receivers

BehavioralSubgraph:   subgraph_id, primary_behavior_flag, matched_apis,
                      topological_invariants,
                      subgraph_size_ratio [NEW] — subgraph_nodes / method_nodes (0.0–1.0)

ObfuscationSignal:    string_entropy_score, flattening_suspected, flattening_outlier_nodes,
                      reflection_call_count, unresolved_reflection_targets,
                      method_parse_failure_rate [NEW] — 0.0–1.0 (§9.6),
                      coverage_note

AnalysisManifest:     target_package, sha256, cache_hit, total_nodes_parsed,
                      graph_density [corrected: mean per-method density],
                      behavioral_subgraphs, obfuscation, predicted_ttps,
                      predicted_family, family_confidence

RiskScoreBreakdown:   classifier_confidence_component, permission_api_component,
                      ttp_severity_component,
                      forensic_anchor_component [NEW],
                      obfuscation_component, reputation_component, ioc_component,
                      total_score, verdict_band

AnalysisReport:       manifest, risk_score, narrative_report, limitations
```

---

### `app/analysis/cfg.py` — CHANGED SESSION 2

```python
is_method_relevant(method_analysis, relevant_api_substrings, relevant_string_substrings) -> bool
    # Cheap pre-filter using instruction stream scan. False = safe to skip.

build_method_cfg(method_analysis) -> nx.DiGraph
    # node=basic_block(start_offset), edge=control_transition

enrich_acfg(g, method_analysis) -> nx.DiGraph
    # Adds opcode_frequency, api_calls, string_literals to each node

build_all_method_cfgs(analysis_obj, use_relevance_filter=True) -> tuple[dict, float]
    # Returns (method_sig→graph, parse_failure_rate)
    # BREAKING CHANGE from Session 1: must unpack as: cfgs, failure_rate = build_all_method_cfgs(...)
```

---

### `app/analysis/forensic.py` — NO CHANGES

```python
FORENSIC_DICTIONARY = {
    "STEALTH_SMS_INTERCEPTION": {apis, permissions},
    "OTP_INTERCEPTION":         {permissions, strings: ["otp","one time password","verification code"]},
    "DYNAMIC_REFLECTION":       {apis: ["Ljava/lang/reflect/Method;->invoke"]},
    "CRYPTOGRAPHY_USAGE":       {apis: ["Ljavax/crypto/Cipher;->doFinal"]},
    "CREDENTIAL_HARVESTING":    {apis, permissions, strings: ["login","password","bank"]},
    "C2_BEHAVIOR":              {apis, strings: ["http://","https://"]},
}

match_anchors(g) -> dict[str, list[str]]           # behavior→[anchor_node_ids]
extract_anchor_subgraph(g, anchor, hops=4) -> nx.DiGraph  # BFS ≤4 hops undirected
```

---

### `app/analysis/topology.py` — NO CHANGES

```python
compute_topological_invariants(g) -> dict[str, float]
    # 15 features: {degree,closeness,clustering} × {mean,std,median,min,max}
    # Returns all-zeros on empty graph; never raises.
    # NOTE: Eigenvector/Katz centrality intentionally excluded (unstable on disconnected subgraphs)

detect_flattening_outlier(g, zscore_threshold=3.0) -> tuple[bool, list[str]]
    # Dispatcher-node detection via Z-score on degree distribution
    # Returns (False, []) on graphs with <5 nodes or zero std
```

---

### `app/analysis/obfuscation.py` — CHANGED SESSION 2

```python
shannon_entropy(s) -> float
compute_string_pool_entropy(all_strings) -> float
count_reflection_calls(cfgs) -> tuple[int, int]   # (total, unresolved=0 STUB)

build_obfuscation_signal(
    all_strings, cfgs, entropy_threshold, flattening_zscore,
    unanalyzed_native_libs=0,
    method_parse_failure_rate=0.0   # NEW param
) -> ObfuscationSignal
    # Adds parse failure info to coverage_note when rate >= 10%
    # Populates ObfuscationSignal.method_parse_failure_rate
```

---

### `app/ml/features.py` — NO CHANGES (do not change without retraining)

```python
FEATURE_NAMES = PERMISSION_FEATURES + BEHAVIOR_FEATURES + TOPOLOGY_FEATURES + OBFUSCATION_FEATURES
# Total: 30 features

build_feature_vector(permissions, matched_behaviors, topological_invariants,
                     obfuscation_entropy, obfuscation_flattening, obfuscation_reflection_count)
    -> list[float]  # always len==30, asserts this
```

---

### `app/ml/classifier.py` — NO CHANGES

```python
classifier = MalwareClassifier()  # module-level singleton

classifier.predict(feature_vector: list[float]) -> dict[str, float]
    # Returns {family_label: probability} for all MODEL_LABEL_MAP labels
    # Raises FileNotFoundError if data/models/guardgraph_xgb_v1.json not found
    # routes.py catches this and proceeds with empty predictions
```

---

### `app/graph/neo4j_client.py` — CHANGED SESSION 2

```python
neo4j_client.connect()
    # Now wrapped in try/except — raises RuntimeError("Start Neo4j with: docker compose up -d")
    # instead of raw driver exception

neo4j_client.run(query, **params) -> list[dict]
    # cache.py wraps all calls in try/except, so DB outage degrades to cold path
```

---

### `app/graph/cache.py` — CHANGED SESSION 3

```python
lookup_signature(sha256) -> dict | None
    # Now also returns: narrative, limitations alongside sha256, family, base_score, ttps
    # None on miss or any DB error

store_signature(sha256, family, risk_score, ttps, narrative="", limitations=None)
    # NEW params: narrative (str) and limitations (list[str])
    # Stores LLM-generated text in Neo4j so hot path can serve it directly
    # Silent pass on DB error
```

---

### `app/graph/ontology.py` — NO CHANGES

Holds 5 starter MITRE techniques: T1636, T1624, T1417, T1409, T1471.
`get_technique_context(technique_ids)` retrieves them from Neo4j for GraphRAG grounding.

---

### `app/reports/scoring.py` — CHANGED SESSION 2

```python
BEHAVIOR_SEVERITY = {behavior_flag: float}   # NEW — per-behavior severity weights

forensic_anchor_component(matched_anchor_behaviors: set[str]) -> float   # NEW
    # Mean severity of matched behaviors + breadth bonus (max 0.2)

obfuscation_component(obfuscation, entropy_threshold) -> float
    # Extended: now adds up to +0.3 for method_parse_failure_rate >= 10%

compute_risk_score(
    predicted_ttps, permissions, obfuscation, entropy_threshold,
    matched_anchor_behaviors=None,   # NEW param
    cache_hit=False, cached_score=None, matched_c2_indicators=0
) -> RiskScoreBreakdown
    # 7-component formula; component values in RiskScoreBreakdown are weight-scaled
    # (e.g. forensic_anchor_component max = 15, not 1.0)
```

---

### `app/reports/graphrag.py` — NO CHANGES

```python
SYSTEM_PROMPT   # 6-rule anti-hallucination guardrail (do not relax)

generate_report(manifest, risk_score) -> tuple[str, list[str]]
    # Connects to Ollama at settings.ollama_base_url (default localhost:11434/v1)
    # Raises RuntimeError on connection failure (caught in routes.py)
    # Returns (narrative_text, limitations_list)
    # Requires: ollama serve + ollama pull qwen2.5:7b-instruct-q4_K_M
```

---

### `app/api/routes.py` — CHANGED SESSION 2 + SESSION 3

```python
@router.post("/analyze") -> AnalysisReport

# HOT PATH (cache hit) — NO LLM CALL (Session 3 fix):
#   ingest_apk → sha256 → lookup_signature → HIT
#   → compute_risk_score(empty signal, cached score)
#   → narrative = cached["narrative"]          ← served from Neo4j, not Ollama
#   → limitations = cached["limitations"]
#   → return AnalysisReport (target: <50ms)

# COLD PATH (cache miss):
#   ingest_apk
#   → cfgs, failure_rate = build_all_method_cfgs(analysis_obj)
#   → for each (method_sig, g): match_anchors + extract_anchor_subgraph + topological_invariants
#       → BehavioralSubgraph(..., subgraph_size_ratio=sub_nodes/method_nodes)
#   → build_obfuscation_signal(..., method_parse_failure_rate=failure_rate)
#   → build_feature_vector → classifier.predict (or FileNotFoundError → empty)
#   → predicted_ttps = {t: family_conf * 0.85 for t in FAMILY_TO_TTPS[predicted_family]}
#   → graph_density = mean(per_method_density)  [corrected §9.4]
#   → compute_risk_score(..., matched_anchor_behaviors=set(all_matches.keys()))
#   → generate_report → store_signature(narrative=narrative, limitations=limitations) → return
```

---

## 8. Setup & Running

```bash
# 1. Copy env
cp .env.example .env

# 2. Start Neo4j
docker compose up -d

# 3. Seed ontology (run once)
python scripts/load_ontology.py

# 4. Pull Ollama model (run once)
ollama pull qwen2.5:7b-instruct-q4_K_M
ollama serve          # if not already running as a service

# 5. Install dependencies
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 6. Smoke test
python tests/test_features.py        # must print "OK: feature vector length 33 matches FEATURE_NAMES"
python tests/test_signatures_yara.py # must print "All signature/YARA tests passed successfully!"

# 7. Download community YARA rules (run once, or to refresh)
python scripts/download_yara_rules.py
# Downloads 518 rules, filters out androguard/cuckoo imports, saves to data/yara_rules/
# 455 rules load successfully at runtime; 19 with relative include errors are auto-skipped

# 8. Run API
uvicorn app.main:app --reload
# Swagger UI: http://localhost:8000/docs
# Health:     http://localhost:8000/health

# 9. Test with a real APK (S4 convenience script)
python scripts/test_upload.py
# Edit APK_PATH in the script to point to your sample
# Or: python scripts/test_upload.py /path/to/sample.apk
```

### Training (when CICMalDroid2020 is preprocessed)

```bash
# Preprocess dataset into: data/cicmaldroid_features.csv
# Columns must match FEATURE_NAMES (30 cols) + "family" label column
# Topology columns can be zero-filled for v1 training run

python scripts/train_model.py
# Model saved to: data/models/guardgraph_xgb_v1.json
# CRITICAL: update MODEL_LABEL_MAP in app/core/config.py to match
#           training label order EXACTLY after training completes
```

---

## 9. Team Role Split

| Role | Owner | Status |
|---|---|---|
| FastAPI + Androguard + CFG/ACFG pipeline | A | ✅ Complete |
| Forensic dictionary, obfuscation signals, entropy scoring | B | ✅ Complete |
| XGBoost training on CICMalDroid2020, risk scoring | C | 🔲 Model not yet trained (feature vector now 33 cols — retrain needed) |
| Neo4j schema + ontology, GraphRAG + report, frontend | D | ✅ Backend complete; frontend TBD |

---

## 10. Remaining Work (Priority Order)

1. **Confirm CICMalDroid2020 label structure** — single-label (multiclass) or multi-label per sample? Determines whether `multi:softprob` is correct or needs one-vs-rest binary classifiers.
2. **Train v1 model** — permission/API/manifest features only; zero-fill topology columns. Drop at `data/models/guardgraph_xgb_v1.json`. Update `MODEL_LABEL_MAP` to match label order exactly.
3. **Run `scripts/load_ontology.py`** — once Neo4j is up.
4. **Curate demo APK set** — 2–3 clean + 2–3 known banking trojans from CICMalDroid2020 + 1 packed/obfuscated. Validate full pipeline before any demo.
5. **Tune thresholds** — `ENTROPY_HIGH_THRESHOLD` (default 7.2) and `FLATTENING_DEGREE_OUTLIER_ZSCORE` (default 3.0) against real APK output.
6. **Manual hallucination spot-check** — Verify 3–5 GraphRAG reports against source manifest. Local 7B models drift more than larger models under strict system prompts.
7. **Validate 4-hop constant** — Inspect `subgraph_size_ratio` in `BehavioralSubgraph` across demo APKs. ~1.0 = hops too wide; very low = hops too narrow.
8. **Frontend** — Streamlit recommended for speed. React/Next.js only if stakeholder-facing polish required.

---

## 11. Critical "Do Not Do" List

- ❌ Do NOT silently change `FEATURE_NAMES` in `features.py` without retraining
- ❌ Do NOT add Celery/Redis, Postgres, S3, K8s, Terraform, or auth — explicitly out of scope
- ❌ Do NOT implement eigenvector/Katz centrality — deliberately excluded (unstable on disconnected subgraphs)
- ❌ Do NOT implement native `.so` analysis, packer fingerprinting, or string-decrypt micro-execution — out of scope for prototype
- ❌ Do NOT let GraphRAG use any information not in the JSON manifest / Neo4j ontology context
- ❌ Do NOT swap Label Powerset back in for the classifier (class-imbalance issue)
- ❌ Do NOT cite GUARD paper (Windows PE32) accuracy/latency numbers as evidence for GuardGraph AI Android performance
- ❌ Do NOT treat the hot-path as "done" without confirming `build_all_method_cfgs` is truly not called on a cache hit — verified as of Session 2

---

*Document generated: 2026-07-06 | Updated: 2026-08-21 | Maintained by: AI Assistant (Claude Code) on behalf of the GuardGraph AI team*
