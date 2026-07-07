# GuardGraph AI — Team Context & Change Log
> Feed this file to your LLM as project context before asking it to work on GuardGraph AI.  
> It contains the full picture: architecture, every file's purpose, what's real vs stubbed, and a dated change log.

---

## Change Log

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
│   │   ├── config.py             Settings, MODEL_LABEL_MAP, TTP_SEVERITY_WEIGHTS, FAMILY_TO_TTPS
│   │   └── schemas.py            Pydantic contracts (IngestionResult, AnalysisManifest, etc.)
│   ├── analysis/
│   │   ├── ingest.py             SHA-256, cert thumbprint, Androguard ingestion
│   │   ├── cfg.py                CFG + ACFG enrichment (NetworkX) + relevance pre-filter
│   │   ├── forensic.py           Forensic dictionary, anchor detection, 4-hop subgraph extraction
│   │   ├── topology.py           Centrality/clustering stats, flattening outlier detection
│   │   └── obfuscation.py        Entropy scoring, reflection counting, coverage notes
│   ├── ml/
│   │   ├── features.py           *** SINGLE SOURCE OF TRUTH for feature vector schema ***
│   │   └── classifier.py         XGBoost load/predict wrapper
│   ├── graph/
│   │   ├── neo4j_client.py       Thin driver wrapper (graceful connect failure)
│   │   ├── cache.py              Hot-path signature lookup/store
│   │   └── ontology.py           MITRE ATT&CK Mobile starter ontology loader
│   └── reports/
│       ├── scoring.py            Risk score formula (7-component, 0-100)
│       └── graphrag.py           Ollama-based report generation (anti-hallucination system prompt)
├── scripts/
│   ├── train_model.py            CICMalDroid2020 training script skeleton
│   └── load_ontology.py          One-time Neo4j ontology seed
├── tests/
│   └── test_features.py          Feature vector length invariant test (MUST always pass)
├── data/
│   ├── samples/                  (gitignored) APK files for testing
│   └── models/                   (gitignored) trained XGBoost model goes here
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
| Forensic dictionary + anchor detection | `forensic.py` | 6 behavior categories |
| 4-hop subgraph extraction | `forensic.py` | `extract_anchor_subgraph()` |
| Topological feature mining | `topology.py` | Degree, closeness, clustering centrality |
| Flattening outlier detection | `topology.py` | Z-score on degree distribution |
| Shannon entropy scoring | `obfuscation.py` | Over full string pool |
| Reflection call counting | `obfuscation.py` | Call sites counted; resolution is stubbed |
| Coverage note generation | `obfuscation.py` | Includes parse failure rate >= 10% |
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

## 5. Risk Scoring Formula (Current — Session 2)

```
Risk Score (0–100) =
    0.25 × classifier_confidence       max family probability
  + 0.20 × permission_api_risk         weighted dangerous permissions
  + 0.15 × ttp_severity                MITRE T-number severities (via FAMILY_TO_TTPS bridge)
  + 0.15 × forensic_anchor             NEW — deterministic API matches, behavior-severity weighted
  + 0.15 × obfuscation / coverage      entropy + flattening + parse failure rate
  + 0.05 × reputation                  Neo4j cache prior score
  + 0.05 × ioc                         C2 indicator count
```

**Verdict bands:** 0–30 Low | 31–60 Suspicious | 61–80 High | 81–100 Malicious

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

`app/ml/features.py` → `FEATURE_NAMES` → **30 features** in this order:

```
[6 permission flags]      android.permission.BIND_ACCESSIBILITY_SERVICE, READ_SMS,
                          RECEIVE_SMS, SEND_SMS, SYSTEM_ALERT_WINDOW, REQUEST_INSTALL_PACKAGES
[6 behavior flags]        STEALTH_SMS_INTERCEPTION, OTP_INTERCEPTION, DYNAMIC_REFLECTION,
                          CRYPTOGRAPHY_USAGE, CREDENTIAL_HARVESTING, C2_BEHAVIOR
[15 topology stats]       degree_centrality × {mean,std,median,min,max}
                          closeness_centrality × {mean,std,median,min,max}
                          clustering_coefficient × {mean,std,median,min,max}
[3 obfuscation features]  string_entropy_score, flattening_suspected, reflection_call_count
```

XGBoost has no concept of column names at inference time — a column-order mismatch produces confident, wrong predictions with no error raised.

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
python tests/test_features.py     # must print "OK: feature vector length 30 matches FEATURE_NAMES"

# 7. Run API
uvicorn app.main:app --reload
# Swagger UI: http://localhost:8000/docs
# Health:     http://localhost:8000/health
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
| XGBoost training on CICMalDroid2020, risk scoring | C | 🔲 Model not yet trained |
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

*Document generated: 2026-07-06 | Updated: 2026-07-07 | Maintained by: AI Assistant (Antigravity) on behalf of the GuardGraph AI team*
