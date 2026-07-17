# GuardGraph AI — Prototype Skeleton

Static-analysis-only Android malware risk-scoring engine. CFG/ACFG graph
features + XGBoost multi-label classification + Neo4j knowledge graph +
Claude-based GraphRAG report generation.

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

# 2. Configure environment — the defaults in .env.example work as-is
cp .env.example .env                       # Windows (PowerShell): copy .env.example .env

# 3. Start the local LLM used for report generation.
#    Run these in their OWN terminal — `ollama serve` stays running in the foreground.
ollama pull qwen2.5:7b-instruct-q4_K_M
ollama serve                               # skip if Ollama already runs as a background service

# 4. Start Neo4j (knowledge graph: hot-path cache + report grounding)
docker compose up -d

# 5. Load the MITRE ATT&CK Mobile ontology into Neo4j (one network fetch, run once).
#    Grounds the GraphRAG report in real technique/tactic facts.
python scripts/build_ttp_label_space.py    # fetch + build the ATT&CK Mobile label space
python scripts/load_ontology.py            # load it into Neo4j (use --starter for an offline 5-technique seed)

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
| Forensic dictionary / anchor detection | Working, dictionary is a starter set — extend it |
| 4-hop subgraph extraction | Working |
| Topological feature mining | Working (degree/closeness/clustering; eigenvector/Katz stubbed — slow on large graphs, add if needed) |
| Entropy-based obfuscation scoring | Working |
| Family XGBoost inference (auxiliary) | Stub — needs `data/models/guardgraph_xgb_v1.json` |
| Multi-label MITRE ATT&CK TTP classifier (primary, cold path) | Working code; needs `data/models/guardgraph_ttp_br_v1.joblib` from `train_model.py --target ttp`. Degrades gracefully (empty TTPs) until trained |
| Neo4j cache lookup (hot path) | Working, needs Neo4j running + ontology loaded |
| Risk scoring formula | Working, weights match the paper's spec |
| GraphRAG report generation (Claude) | Working, calls Anthropic API — needs API key |
| Auth, queues, multi-user | Not built — out of scope for prototype |

## Wiring in your trained model
Drop your model file at `data/models/guardgraph_xgb_v1.json` and set
`MODEL_LABEL_MAP` in `app/core/config.py` to match your training label order.
The feature vector schema is documented in `app/ml/features.py` — your
training script's feature order MUST match this exactly or predictions will
be silently wrong (XGBoost doesn't validate column meaning, only column count).

## Multi-label MITRE ATT&CK Mobile TTP classifier (cold path)

The cold path predicts MITRE ATT&CK **Mobile techniques directly** as a multi-label
problem (Binary Relevance = one XGBoost per technique), replacing the old
family→TTP proxy. It fuses the GUARD paper's graph-invariant topology (aggregated
across all anchor subgraphs) with DroidTTP-style manifest/API presence features, and
turns the cold path into a **zero-day risk engine**: deterministic forensic-anchor and
structural obfuscation signals set a score floor and raise `zero_day_indicator` when the
model is unfamiliar with a first-seen sample.

Single sources of truth:
- `app/ml/labels.py` → `TTP_LABELS` (technique output order — freeze before training).
- `app/ml/features.py` → `TTP_FEATURE_NAMES` / `build_ttp_feature_vector` (179 features).

```bash
# 1. Build the ATT&CK Mobile label space + ontology from STIX (one network fetch)
python scripts/build_ttp_label_space.py

# 2. Load the full Mobile ontology into Neo4j (GraphRAG grounding)
python scripts/load_ontology.py

# 3. Build the multi-label TTP dataset (real APKs via MalwareBazaar + weak-label bootstrap)
python scripts/build_ttp_dataset.py --stage all --max-per-family 15

# 4. Train Binary Relevance (shipped) and benchmark Classifier Chains / Label Powerset
python scripts/train_model.py --target ttp
#    -> data/models/guardgraph_ttp_br_v1.joblib  +  data/models/ttp_metrics.json
```

The multi-label model is built from the GUARD (graph-invariant topology) and DroidTTP
(multi-label ATT&CK Mobile mapping) methods.
