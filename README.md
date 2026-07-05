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

```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# start Neo4j
docker compose up -d

cp .env.example .env   # fill in NEO4J + ANTHROPIC_API_KEY

# run API
uvicorn app.main:app --reload --port 8000
```

Upload an APK:
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
| XGBoost inference | Stub — needs `data/models/guardgraph_xgb_v1.json` from your overnight training run |
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
