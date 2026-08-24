# GuardGraph AI — Prototype Skeleton

Android malware risk-scoring engine. CFG/ACFG graph features + XGBoost
multi-label classification + Neo4j knowledge graph + local-LLM GraphRAG
report generation (Ollama) on the static/default path, plus an **opt-in
dynamic-analysis pass** (Android emulator + Frida) added 2026-08-24 that
confirms/refutes specific static predictions at runtime — see
`app/analysis/frida_scripts/README.md` for setup and
`TEAM_CONTEXT.md`'s Session 14 for the full design writeup. The dynamic
pass is currently **local, uncommitted work** — check `git status` /
`git log` before assuming it's on whatever branch you've checked out.

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
│   ├── benign_apks/    known-clean Stage C corpus, 300 apps (gitignored, ~3.1 GB)
│   ├── benign_holdout/ 30 clean apps held out of training, for calibration only (~0.7 GB).
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

Then upload an APK — your sample lives at `data/samples/test.apk`:
```bash
curl -X POST http://localhost:8000/analyze -F "file=@data/samples/test.apk"
```

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
| Obfuscation / anti-analysis scoring | Working, recalibrated. String-pool entropy and control-flow flattening are still measured and reported, but neither is scored: measured over a 618-APK corpus (see note below — this is larger than the corpus currently checked out in `data/`), entropy cannot reach its threshold and runs backwards (benign 3.18 vs malware 2.68), and flattening prevalence has no lift (benign p75 0.125 vs malware 0.112). Tripling the corpus reversed neither. The component now scores the one thing that held up: a DEX too small to implement its own manifest — 37 of 318 malware, and no clean app within 28x. The CFG parse-failure branch was **deleted**, not left unscored: it measured 0.0 on all 353 samples of the old corpus and all 616 of this one. |
| Signature + YARA scanning (hash/cert DB, VirusTotal, MalwareBazaar, YARA rules) | Working; online triage (VT/MalwareBazaar) needs API keys in `.env`, otherwise local hash/cert + YARA run offline. 8 built-in rules always load; the ~500 community rule *files* require quickstart step 5 — without it the engine runs built-in-only and says so in the startup log |
| Brand / app-identity impersonation detection | Working (`app/analysis/impersonation.py`). Separate from every other row here — it answers "is this app pretending to be a different, legitimate app?" rather than "how malicious does the code look?". Four checks against a reference table of protected brands: signing-certificate mismatch on an exact package match (definitive — Android identifies publishers by key), launcher-icon reuse (64-bit DCT perceptual hash, survives rescale/recompress), package-name typosquatting, and display-name impersonation, all after Unicode-confusable normalization. A match raises a **floor** under the verdict rather than adding to the weighted score, since a cloned banking app can carry a deliberately unremarkable payload — see `IMPERSONATION_SCORE_FLOOR` in `app/reports/scoring.py`. Ships with `data/reference/protected_brands.json` as a **seed**: 65 brands as of 2026-08-24 (Indian banks/UPI/government apps, global social/commerce/streaming/gaming apps commonly used as fraud lures — every package name verified against a live Play Store listing, never guessed), package names and labels only, `verified: false` on every entry, so the two strongest checks (cert, icon) can't fire yet. Populate them for real with `python scripts/build_brand_reference.py --apk-dir <dir-of-genuine-APKs>` (get the APKs from official listings, not a mirror), then `--collisions` to confirm the icon threshold doesn't confuse two of your own brands. |
| **Dynamic verification (opt-in, Android emulator + Frida)** | Working, **local/uncommitted as of 2026-08-24** (`app/analysis/dynamic_verification.py`, `app/analysis/frida_scripts/`). Off by default on every request (`enable_dynamic` query param AND `settings.dynamic_analysis_enabled`, both must be true) — installs the sample on a network-isolated AVD, launches it (falling back to broadcasting its own declared intent-filter actions for headless/receiver-only malware with no launcher activity), and hooks 13 APIs for a bounded capture window to confirm/refute specific static predictions already made elsewhere in the pipeline: C2 contact, DCL payload execution, native library loads, SMS interception, overlay-attack windows, accessibility binding, crypto invocation, plus standalone IoCs (URLs/files/commands) and up to 3 screenshots per run (reaction / event-triggered / end-of-window). A confirmed C2 contact is also written to Neo4j as `dynamically_confirmed=true` on that sample's `CONTACTS` relationship, letting cross-sample correlation distinguish "shares this C2 string" from the stronger "was caught actually calling it". See `app/analysis/frida_scripts/README.md` for full setup (AVD, frida-server, containment firewall rules) and `TEAM_CONTEXT.md`'s Session 14 for the design writeup and every failure mode found live. |
| Family XGBoost inference (auxiliary) | Trained — `data/models/guardgraph_xgb_v1.json` is committed and loads by default, so `classifier_confidence` (auxiliary path) is live. Re-train with `train_model.py` if you change `app/ml/features.py`'s feature order. |
| Multi-label MITRE ATT&CK TTP classifier (primary, cold path) | Trained — `data/models/guardgraph_ttp_br_v1.joblib` is committed. **The stratified-split metrics this repo used to quote (`binary_relevance`: micro-F1 0.81) were measuring family memorisation, not technique inference** — every malware row's label comes from its family's ATT&CK software entry, so a split that stratifies on labels puts identical label vectors on both sides of the train/test boundary by construction. `ttp_metrics.json` now also carries `family_held_out`, a `GroupKFold` evaluation with whole families held out of each fold: **micro-F1 0.35** (down from 0.81), **Jaccard 0.079**. That's the number that means something about a family this model has never seen — quote it, not the leaky one. Re-derive both with `python scripts/train_model.py --target ttp`, which prints them side by side. |
| Neo4j cache lookup (hot path) | Working, needs Neo4j running + ontology loaded. The full cached record (risk components, obfuscation signal, permissions, signature/YARA data) now persists to Neo4j as a JSON property on the `Sample` node, not only to an in-process dict — a cache hit after a server restart used to silently return a total score with every component blank while the cached narrative still described them. |
| Reverse-engineering deep dive (reflection, crypto config, dynamic code loading, WebView JS bridges, native/JNI bridges) | Working. Shared register-constant propagation engine (`app/analysis/static_resolution.py`) resolves reflection targets, `Cipher.getInstance`/`SecretKeySpec` chains, `DexClassLoader` targets, `addJavascriptInterface` bridges, and `System.loadLibrary` symbol correlation — all static, fails closed on ambiguous dataflow rather than guessing. Surfaced in the "🔬 Reverse Engineering" report tab |
| Manifest-corruption / anti-analysis resilience | Working. AXML chunk-header corruption and ZIP EOCD/local-header corruption both fall back to manifest-independent DEX/CFG recovery instead of aborting the whole analysis; unrecognized parser failures get a probable-cause explanation (`app/analysis/failure_diagnostics.py`) instead of a raw traceback, and the GraphRAG narrative always runs (never a hardcoded empty placeholder) even on total parse failure |
| Neo4j graph correlation (beyond the cache) | Working. `ttp_context` grounds the "MITRE ATT&CK Mapping" tab in real ontology facts (name/tactic/description), `find_related_samples` correlates the current sample against previously-cached ones via shared MITRE techniques / shared C2 infrastructure / a reused signing certificate ("Correlated Samples" tab), and `get_threat_landscape` + `/graph/landscape` render the whole correlation graph live inside the app via Cytoscape ("Threat Landscape" tab) — no separate Neo4j Desktop window needed for a demo |
| Risk scoring formula | Working; weights match the paper's spec and the component internals were calibrated against a 618-APK corpus — 300 benign / 318 malware, with a further 30 clean apps held out of training entirely (`python scripts/score_corpus.py`). **The `data/` corpus currently checked into this repo is smaller than that** (`data/benign_apks` + `data/ttp_apks` together are ~367 APKs, matching the 364-row TTP training set, not the 618-row scoring-calibration one) — the calibration numbers quoted throughout this table and in `app/reports/scoring.py`'s comments are real measurements from when the larger corpus existed, not something you can currently reproduce byte-for-byte from what's on disk. Rebuild the larger corpus per the quickstart (`download_benign_apks.py` with the large-window flags + `build_ttp_dataset.py --stage a`) and re-run `score_corpus.py` before trusting these boundaries in a new deployment. Calibrated with online reputation **disabled**, which is the conservative direction: VirusTotal only returns a verdict when `malicious > 0`, so enabling it can raise malware scores and never benign ones. `ttp_severity_component` and `forensic_anchor_component` sum evidence into a saturating mass rather than averaging it (`python scripts/measure_saturation.py` reproduces the derivation) — the averaged form used to make the score *fall* as more corroborating evidence was found. |
| Verdict bands (`low` / `medium` / `suspicious` / `high` / `malicious`) | Calibrated at **30 / 40 / 60 / 70**, each boundary set by its own criterion rather than by cutting 0–100 into equal parts (see `app/reports/scoring.py`). `medium` sits in the gap between where clean apps typically top out above `low` and where malware density resumes — it exists to stop labelling that clean-app tail `suspicious`, which is a labeling fix, not a new detection boundary. `high`'s ceiling is placed above the highest score observed on a known-clean app during calibration, rather than just below the malware first quartile — this trades some malware-`malicious` recall for precision, so more malware reads `high` instead of `malicious`, but nothing is downgraded past `high`: the total share of malware reaching `high`-or-above is unchanged. Apps whose legitimate functionality genuinely overlaps a banking trojan's capability surface (e.g. automation or accessibility tools that use SMS/overlay/accessibility APIs) can still land in `high` — that is capability overlap, not a scoring defect, and no boundary fully separates it. Re-derive all four boundaries against your own corpus with `python scripts/score_corpus.py` before trusting them in a different deployment. |
| Zero-day risk indicator | Working — strong deterministic/structural evidence + low model confidence + cache miss raises `zero_day_indicator` |
| GraphRAG report generation (local LLM via Ollama) | Working — calls Ollama (`qwen2.5:7b-instruct-q4_K_M`), no cloud key needed. **Caveat:** the local 7B model drifts under the strict grounding prompt (can invent subgraphs/figures) — prompt hardening / output validation still pending |
| Auth, queues, multi-user | Not built — out of scope for prototype |

## Wiring in your trained model
Drop your model file at `data/models/guardgraph_xgb_v1.json` and set
`MODEL_LABEL_MAP` in `app/core/config.py` to match your training label order.
The feature vector schema is documented in `app/ml/features.py` — your
training script's feature order MUST match this exactly or predictions will
be silently wrong (XGBoost doesn't validate column meaning, only column count).

## Multi-label MITRE ATT&CK Mobile TTP classifier (cold path)

The cold path predicts ATT&CK Mobile techniques directly as a multi-label problem
(Binary Relevance — one XGBoost per technique), combining GUARD-style graph-invariant
topology with DroidTTP-style manifest/API presence features. Deterministic forensic-anchor
and obfuscation signals set a score floor and raise `zero_day_indicator` on first-seen
samples the model doesn't recognise.

Column order is load-bearing (XGBoost validates count, not meaning) — freeze these before
training:
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