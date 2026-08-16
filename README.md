# GuardGraph AI — Prototype Skeleton

Static-analysis-only Android malware risk-scoring engine. CFG/ACFG graph
features + XGBoost multi-label classification + Neo4j knowledge graph +
local-LLM GraphRAG report generation (Ollama).

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
│   └── models/         put trained model.json here
├── scripts/
│   ├── train_model.py       CICMalDroid2020 training script skeleton
│   └── load_ontology.py     loads MITRE ATT&CK Mobile / CAPEC into Neo4j
├── tests/
├── docker-compose.yml   Neo4j only — API runs locally for prototype
├── requirements.txt
└── .env.example
```

## Quickstart

First-time setup, in order. Assumes **Docker**, **Python 3.12**, and
[**Ollama**](https://ollama.com) are installed. Report generation runs fully
offline via Ollama.

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
| Androguard ingestion | Working (needs `androguard` installed) |
| CFG construction (NetworkX) | Working |
| ACFG enrichment | Working |
| Forensic dictionary / anchor detection | Working, but the dictionary is a starter set — currently over-matches common libraries (AndroidX/Glide/Lottie reflection + HTTP read as anchors), so expect false positives until it's tuned/allowlisted |
| 4-hop subgraph extraction | Working |
| Topological feature mining | Working (degree/closeness/clustering; eigenvector/Katz stubbed — slow on large graphs, add if needed) |
| Entropy-based obfuscation scoring | Working |
| Signature + YARA scanning (hash/cert DB, VirusTotal, MalwareBazaar, YARA rules) | Working; online triage (VT/MalwareBazaar) needs API keys in `.env`, otherwise local hash/cert + YARA run offline. 8 built-in rules always load; the ~500 community rule *files* require quickstart step 5 — without it the engine runs built-in-only and says so in the startup log |
| Family XGBoost inference (auxiliary) | Stub — needs `data/models/guardgraph_xgb_v1.json`. Not loaded by default, so `classifier_confidence` contributes 0 to the score until trained |
| Multi-label MITRE ATT&CK TTP classifier (primary, cold path) | Working code; needs `data/models/guardgraph_ttp_br_v1.joblib` from `train_model.py --target ttp`. Degrades gracefully (empty TTPs) until trained — until then `ttp_severity` contributes 0 |
| Neo4j cache lookup (hot path) | Working, needs Neo4j running + ontology loaded. Cold-path caching only writes a `Sample` node when the family model predicts a family, so with the model untrained nothing is cached back |
| Risk scoring formula | Working, weights match the paper's spec. With both XGBoost models untrained the verdict rests entirely on the deterministic static signals (permissions, forensic anchors, obfuscation, signature/YARA, IOCs) + the zero-day floor |
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
- `app/ml/features.py` → `TTP_FEATURE_NAMES` / `build_ttp_feature_vector` (179 features)

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
# 1. Download malware — network-bound, resumable, parallelizable. Writes data/ttp_apks/_manifest.json.
python scripts/build_ttp_dataset.py --stage a --phase download --max-per-family 15 --download-workers 8
```

```bash
# 2. Download the benign corpus from F-Droid — ~1 GB, a couple of minutes.
python scripts/download_benign_apks.py
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
abuse.ch 502s), just rerun — only those families are retried; `--force-resolve` re-sweeps all. `--stage all` runs everything back-to-back including Stage B.

The analyse phase is incremental too: rows are appended as each APK finishes, so a crash
costs one sample rather than the whole pass, and a rerun skips what is already in the CSV.
`--overwrite` rebuilds from scratch — needed if the CSV predates a `TTP_FEATURE_NAMES`
change, since appending mismatched columns is refused rather than silently misaligned.
Both phases tee their output to `logs/build_ttp_dataset_<phase>_<timestamp>.log`, which is
what survives if the terminal dies with the process.