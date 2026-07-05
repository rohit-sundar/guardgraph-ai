# GuardGraph AI — Full Project Context

> This document is written for an AI coding assistant picking up this project.
> It contains the idea, architecture, decisions already made (and why), current
> build status, what's real vs stubbed, and what to do next. Read this before
> touching any code.

---

## 1. What this project is

**GuardGraph AI** is a static-analysis-only Android malware detection and
risk-scoring engine, purpose-built for **banking fraud threats** (banking
trojans, OTP interception, credential harvesting, SMS abuse).

Core idea: instead of signature matching or heavy dynamic analysis (sandboxing,
emulation), it analyzes an APK's **Control Flow Graphs (CFGs)** and
**Attributed CFGs (ACFGs)**, extracts graph-invariant topological features
(centrality, clustering) around suspicious code regions, and uses those
features — which survive code obfuscation like renaming, junk-code insertion,
and control-flow flattening — to classify behavior and score risk.

A Neo4j knowledge graph stores malware intelligence (MITRE ATT&CK Mobile /
CAPEC mappings, known signatures, malware families) and a GraphRAG layer
(Claude API) generates analyst-readable, evidence-grounded reports — never
hallucinating findings not present in the extracted data.

### Why this approach (explicit design decision)
- Dynamic analysis (sandboxing/emulation) was ruled out as too heavy/slow for
  the target use case (banks need fast per-APK verdicts during active fraud
  campaigns).
- Static graph-invariant features were chosen specifically because they
  survive common obfuscation techniques that defeat naive string/API-name
  matching.
- The system explicitly reports **what it could not analyze** (native code,
  encrypted strings, unresolved reflection) rather than silently guessing —
  this is a deliberate credibility/product decision for a banking compliance
  audience, not just an engineering shortcut.

---

## 2. Original idea source

The project originated from an academic/business proposal document
("GuardGraph AI: Malware Analysis Engine") which specified:

- **Problem**: fraudulent APKs steal banking credentials, intercept OTPs,
  abuse permissions, and evade signature-based detection.
- **System components**: API Gateway (FastAPI), Ingestion & Identity (hash +
  cert), Signature Graph Store (Neo4j), Static Reverse Engineering Engine
  (Androguard), CFG Builder (NetworkX), ACFG Enricher, Forensic-dictionary
  ("FoI") Matcher, Subgraph Extractor (exactly 4 hops), Topological Feature
  Miner, Multi-Label Classifier (MITRE ATT&CK Mobile), Graph-RAG Engine,
  Report Generator.
- **Two execution paths**:
  - **Hot path** (cache hit on known hash/cert): Neo4j lookup, <50ms target.
  - **Cold path** (unknown/first-seen sample): full static pipeline,
    ~150ms target for constrained samples (this target is optimistic and
    should not be treated as a hard SLA for the prototype).
- **Risk scoring formula** (weighted, 0–100):
  ```
  Risk Score =
      0.30 * classifier_probability
    + 0.20 * permission_api_risk
    + 0.20 * ttp_severity
    + 0.15 * graph_obfuscation_score
    + 0.10 * reputation_score
    + 0.05 * ioc_score
  ```
  Verdict bands: 0–30 Low, 31–60 Suspicious, 61–80 High, 81–100 Malicious.
- **Datasets/ontologies referenced**: Avast-CTU CAPEv2 (⚠️ later identified as
  wrong — it's Windows/PE sandbox data, not applicable to Android/Dalvik),
  MALOnt, Malware-Ontology-Graph, Unified Cyber Ontology (UCO), Unified
  Cybersecurity Ontology, MITRE ATT&CK Mobile, CAPEC.
- **Neo4j schema**: Node labels include Sample, Hash, Certificate, Package,
  Permission, API, StringLiteral, BasicBlock, Subgraph, Behavior, Tactic,
  Technique, CAPECPattern, MalwareFamily, OntologyConcept, Report, Mitigation.
  Relationships include HAS_HASH, SIGNED_BY, DECLARES_PERMISSION, CALLS_API,
  MATCHES_BEHAVIOR, MAPS_TO_TECHNIQUE, CLASSIFIED_AS_FAMILY, etc.
- **Report guardrails** (critical, carried through the whole build): GenAI
  layer must never invent evidence — only summarize JSON manifest facts,
  Neo4j retrieval results, and MITRE/CAPEC context. If evidence is missing,
  it must say "not observed" rather than guess. Deterministic findings must
  be separated from model predictions. Confidence values must accompany all
  predicted TTPs.

---

## 3. Key corrections made to the original plan during scoping

1. **Dataset swap**: Avast-CTU CAPEv2 is Windows PE/Cuckoo sandbox data —
   wrong feature space entirely for Android Dalvik bytecode. Replaced with
   **CICMalDroid2020** (also considered: Drebin, AndroZoo) as the Android-native
   training set.
2. **Classifier structure**: the paper implied Label Powerset multi-label
   classification. This explodes combinatorially as the MITRE Mobile label
   set grows and starves rare classes of training examples. Switched to
   **binary-relevance-per-technique / one-vs-rest**, or plain multiclass if
   CICMalDroid2020 labels turn out to be single-family-per-sample (needs
   confirming against the actual dataset — check this before training).
3. **Obfuscation handling** — this was the open question that shaped a lot of
   the architecture. Full breakdown below (Section 4).
4. **Scope cut for prototype vs full product**: the full product plan (K8s,
   Terraform, Celery/Redis queues, multi-user auth, Postgres+S3) was
   descoped. Current build target is a **prototype**: synchronous FastAPI,
   local filesystem storage, SQLite/no persistence layer for jobs, no auth,
   Docker Compose for Neo4j only. The goal of the prototype is to prove the
   architecture and reasoning are real, not to be production-hardened.

---

## 4. Obfuscation strategy (important — this shaped the whole analysis layer)

The central technical challenge identified: how do you detect malware
behavior under obfuscation using **static analysis only** (no dynamic
execution allowed by project constraint)?

Per-technique handling, in priority order for implementation:

| Obfuscation technique | Static handling | Status in prototype |
|---|---|---|
| Identifier/method renaming | Already handled — features are opcode/API/graph-structure based, not name-based | ✅ Implemented (inherent) |
| Control-flow flattening | Detect via centrality outlier: one dispatcher node with abnormally high degree vs. otherwise flat distribution | ✅ Implemented (`detect_flattening_outlier`) |
| Junk/dead code insertion | Anchor-based 4-hop extraction limits blast radius — don't need to filter junk explicitly | ✅ Implemented (inherent, via anchor extraction) |
| String encryption | Biggest real gap. Ideal: statically identify + isolate the decrypt routine and micro-execute it with constant inputs (sandboxed, not full dynamic analysis). Fallback: treat high string-pool entropy as a risk signal itself | ⚠️ Entropy scoring implemented; micro-execution of decrypt routines **not implemented** |
| Reflection-hidden API calls | Constant-propagation/taint tracking on `Class.forName`/`getMethod` string args to resolve real targets statically | ⚠️ Call-site counting implemented; actual constant-propagation resolution **not implemented** (stubbed, returns 0 unresolved by default — see `count_reflection_calls` in `obfuscation.py`) |
| Native code (.so) offloading | Static disassembly via headless Ghidra/radare2 to pull imported/JNI symbols — no emulation | ❌ Not implemented — flagged as "unanalyzed surface" in coverage notes |
| Dynamic code loading (`DexClassLoader`) | Presence of dynamic-loading code itself is a strong static signal even if payload is unseen; if payload is bundled as plaintext asset, recursively run through same pipeline | ❌ Not implemented |
| Commercial packers (Jiagu, Bangcle, etc.) | Fingerprint library of known packer stubs (class names, manifest markers) — closed-set, cheap | ❌ Not implemented |
| Universal fallback: entropy scoring | Shannon entropy over string pools — catches encryption/encoding generally without semantic decoding | ✅ Implemented (`shannon_entropy`, `compute_string_pool_entropy`) |

**Product framing decision**: GuardGraph AI will not defeat every obfuscation
technique statically — the strategy is to **detect obfuscation itself as a
first-class signal** and have the report explicitly state analysis coverage
("X% of control flow resolved; native/encrypted regions flagged as
unanalyzed high-risk surface") rather than silently degrading. This is
consistent with the "say not observed" guardrail and is a selling point for
banking compliance audiences, not a weakness to hide.

---

## 5. Team & timeline context

Team of 4. Original ask was a 2-week **full product** plan; this was later
descoped to a 2-week **prototype** plan (current active target).

### Prototype role split
- **A**: FastAPI + Androguard + CFG/ACFG pipeline
- **B**: Forensic dictionary, anchor detection, obfuscation signal (entropy scoring prioritized as cheapest/highest-signal)
- **C**: Offline XGBoost training on CICMalDroid2020, risk scoring formula, feature vector pipeline
- **D**: Neo4j schema + ontology load, Graph-RAG prompt, report generation, frontend

### Prototype week-by-week (as planned)
**Week 1**: get an ugly but real end-to-end chain working — upload → hash →
Androguard → CFG/ACFG → JSON manifest. Day 5 is an integration checkpoint;
expect this to be where things break.

**Week 2**: add obfuscation detectors (entropy + flattening only for v1),
finalize risk score formula (can simplify to 3-4 factors if some components
aren't ready), Graph-RAG prompt + hallucination testing, minimal frontend
(Streamlit is faster than React if the demo doesn't need to look
"product-polished"; use React/Next.js only if stakeholder-facing polish
matters). **Curate a fixed demo set of 3-6 known-good APK samples in advance**
— don't demo on unseen samples live. Day 14 is buffer, schedule no new work
into it.

### Explicitly cut from the prototype (do not build unless asked)
- Native (.so) code analysis
- String-decrypt micro-execution
- Commercial packer fingerprint library
- Kubernetes/Terraform deploy
- Full MALOnt/UCO ontology integration (MITRE/CAPEC only for now)
- Auth, job queues (Celery/Redis), multi-user support, Postgres/S3

---

## 6. Tech stack (prototype-scoped)

| Layer | Choice | Notes |
|---|---|---|
| API | FastAPI + Uvicorn | Synchronous for prototype — no queue needed at this scale |
| Static analysis | Androguard | Dalvik/APK parsing |
| Graph construction | NetworkX | In-memory CFG per method |
| Graph DB | Neo4j Community | Docker Compose, local |
| ML | XGBoost | Binary-relevance/multiclass, NOT Label Powerset |
| LLM/RAG | Claude API (`claude-sonnet-4-6`) direct calls | No MCP/orchestration framework needed for v1 |
| Dataset | CICMalDroid2020 | Android-native; Drebin/AndroZoo as alternatives |
| Storage | Local filesystem for APKs | No S3/Postgres for prototype |
| Frontend | Streamlit or Next.js | Streamlit faster to build; use React only if demo needs product-polish |
| Deploy | Docker Compose (Neo4j only) | No cloud needed for prototype |

---

## 7. Current build status (as of last handoff)

A full prototype skeleton has been scaffolded and delivered as a zip
(`guardgraph-ai-prototype.zip`). Directory structure:

```
guardgraph-ai/
├── app/
│   ├── main.py                  FastAPI entrypoint
│   ├── api/routes.py            /analyze endpoint — orchestrates full pipeline
│   ├── core/
│   │   ├── config.py            Settings, MODEL_LABEL_MAP, TTP_SEVERITY_WEIGHTS
│   │   └── schemas.py           Pydantic contracts (IngestionResult, AnalysisManifest, etc.)
│   ├── analysis/
│   │   ├── ingest.py            SHA-256, cert thumbprint, Androguard ingestion
│   │   ├── cfg.py               CFG construction + ACFG enrichment (NetworkX)
│   │   ├── forensic.py          Forensic dictionary, anchor detection, 4-hop subgraph extraction
│   │   ├── topology.py          Centrality/clustering stats, flattening outlier detection
│   │   └── obfuscation.py       Entropy scoring, reflection call counting, coverage notes
│   ├── ml/
│   │   ├── features.py          SINGLE SOURCE OF TRUTH for feature vector schema
│   │   └── classifier.py        XGBoost load/predict wrapper
│   ├── graph/
│   │   ├── neo4j_client.py      Thin driver wrapper
│   │   ├── cache.py             Hot-path signature lookup/store
│   │   └── ontology.py          MITRE ATT&CK Mobile starter ontology loader
│   └── reports/
│       ├── scoring.py           Risk score formula (matches paper's weights exactly)
│       └── graphrag.py          Claude-based report generation with anti-hallucination system prompt
├── scripts/
│   ├── train_model.py           CICMalDroid2020 training script skeleton
│   └── load_ontology.py         One-time Neo4j ontology seed
├── tests/
│   └── test_features.py         Feature vector length invariant test
├── data/{samples,models}/       Gitignored, for local APKs and trained model
├── docker-compose.yml           Neo4j only
├── requirements.txt
├── .env.example
└── README.md
```

### What's real (implemented, not mocked)
- Full ingestion → CFG → ACFG → anchor detection → 4-hop subgraph extraction → topological feature mining → obfuscation scoring → risk scoring → Neo4j hot-path cache → GraphRAG report generation chain.
- Risk scoring formula matches the paper's weights exactly.
- GraphRAG prompt enforces all five guardrails from the original design doc (grounded-only, "not observed" for gaps, separate deterministic vs. predicted, confidence values required, prioritized actions).

### What's stubbed (on purpose, fails loudly rather than faking success)
- **XGBoost classifier**: raises `FileNotFoundError` until a trained model is dropped at `data/models/guardgraph_xgb_v1.json`. Pipeline degrades gracefully — proceeds without predictions, report correctly says "not observed" for classifier findings.
- **Reflection constant-propagation**: call sites are counted but target resolution is not implemented — `unresolved_reflection_targets` always reports conservatively via a placeholder.
- **Eigenvector/Katz centrality**: intentionally excluded from `topology.py` — expensive/unstable on disconnected subgraphs. Only degree, closeness, and clustering are computed. Add the other two only if specifically needed and tested against real subgraph shapes.
- **Native (.so) analysis, packer fingerprinting, string-decrypt micro-execution**: not implemented at all, per the explicit obfuscation-coverage priority order (Section 4).

### Critical invariant to protect
`app/ml/features.py` — `FEATURE_NAMES` — is the single source of truth for
feature vector column order. `scripts/train_model.py` imports it; inference
in `app/api/routes.py` (via `build_feature_vector`) must produce vectors in
the exact same order. **XGBoost has no concept of column names at inference
time** — a silent mismatch here produces confident, wrong predictions with
no error raised. If this file changes, the model must be retrained. There is
a smoke test (`tests/test_features.py`) that checks vector *length* matches,
but does not and cannot check semantic column-order correctness — that's a
process discipline issue, not something automatable here.

---

## 8. Immediate next steps (in priority order)

1. **Confirm CICMalDroid2020 label structure** before training — is it
   single-label (multiclass) or genuinely multi-label per sample? This
   determines whether `train_model.py`'s `multi:softprob` objective is
   correct or needs to change to per-technique binary classifiers.
2. **Train v1 model** on permission/API/manifest features only (zero-fill
   topology columns) — don't block the first training run on running the
   CFG pipeline across the whole dataset; that's a separate, slower job.
   Retrain once topological features are available dataset-wide.
3. **Drop the trained model** at `data/models/guardgraph_xgb_v1.json` and
   confirm `MODEL_LABEL_MAP` in `app/core/config.py` matches training label
   order exactly.
4. **Run `scripts/load_ontology.py`** once Neo4j is up via `docker compose up -d`.
5. **Curate the demo APK set** (3-6 samples: 2-3 clean, 2-3 known banking
   trojans from CICMalDroid2020, 1 packed/obfuscated) and validate the full
   pipeline against them before tuning thresholds.
6. **Tune `ENTROPY_HIGH_THRESHOLD`** and `FLATTENING_DEGREE_OUTLIER_ZSCORE`
   in `.env` against real output on the demo set — the starter values are
   reasonable guesses, not validated.
7. **Test GraphRAG output for hallucination manually** against 3-5 real
   reports before trusting it in front of anyone — there is no automated
   groundedness check in the current build.
8. **Build the frontend** (Streamlit recommended for speed unless the demo
   is stakeholder/investor-facing and needs polish, in which case Next.js).

---

## 9. Local LLM option for GraphRAG (if swapping out Claude API)

If the Claude API is swapped for a local LLM in `app/reports/graphrag.py`
(e.g. for cost, offline demo requirements, or data-residency reasons), the
following was evaluated:

### Hardware constraint: 8GB VRAM (as of this note)
At 8GB, 12B-class models (including Gemma 4 12B, which is a real model —
released March 2026, 16GB VRAM minimum, MoE-adjacent, nears Gemma 4 26B
benchmarks) do not fit without quality-damaging quantization. Options that
actually fit at 8GB:

| Model | Fit at 8GB | Notes |
|---|---|---|
| **Gemma 4 E4B** (effective 4B, edge variant) | Q4_K_M fits comfortably | Same Gemma 4 family; native system-prompt support carries over — useful for strict guardrail prompts |
| **Qwen 2.5/3 7B-Instruct** | Q4 fits, tight | Better structured-output/JSON reliability than similarly-sized Gemma per community feedback — relevant since the pipeline needs clean, parseable manifests |
| **Phi-4-mini** | Fits easily | Strong instruction-following for its size, tends to "stay on script" — matters for the no-hallucination requirement |
| Gemma 4 12B / Qwen 7B at full precision | ❌ Does not fit at 8GB | Don't force it — OOM crashes mid-demo are worse than a smaller model |

### Recommendation
**Qwen 2.5 7B-Instruct, Q4_K_M GGUF, served via Ollama.** Rationale: the
GraphRAG step is a constrained extraction/formatting task (JSON manifest +
ontology facts → structured report citing only given evidence), not
open-ended generation. Qwen's instruct variants tend to be more literal/
obedient to system-prompt constraints than Gemma at comparable size, which
matches the "never invent evidence" guardrail better than a model optimized
for more creative/exploratory output.

Gemma 4 E4B is the fallback if Qwen's report *prose quality* proves weaker
in practice — A/B test both against the curated demo set (Section 5) before
committing; "best" here means "best at obeying the guardrail prompt," not a
benchmark leaderboard position.

### AirLLM — explicitly NOT a fit for this component
AirLLM streams model layers from disk to run models far larger than
available VRAM (e.g. a 70B model on 8GB). This is viable for offline batch
jobs but not for the `/analyze` endpoint's per-APK report generation, which
needs to complete in a reasonable time during a live demo — AirLLM's
disk-streaming throughput is seconds-per-token, not interactive.

### Integration path
Ollama exposes an OpenAI-compatible API at `http://localhost:11434/v1`.
Swapping `app/reports/graphrag.py`'s `anthropic.Anthropic()` client for an
OpenAI-compatible client pointed at that endpoint is a small diff, not a
rewrite — the same `SYSTEM_PROMPT` guardrail text can be reused as-is.

```bash
ollama pull qwen2.5:7b-instruct-q4_K_M
```

### Known tradeoff to accept
Local 7B-class models will hallucinate more than Claude did under the same
strict system prompt. Manual groundedness spot-checking (already flagged as
a gap in Section 8, step 7) becomes more important, not less, if this swap
is made — a smaller model is more prone to "helpfully" filling gaps despite
explicit instructions not to.

---

## 10. Things an AI assistant should NOT do without being asked

- Do not add Celery/Redis, Postgres, S3, K8s, Terraform, or auth — these are
  explicitly out of scope for the prototype phase.
- Do not silently change the feature vector schema in `features.py` without
  flagging that the model needs retraining.
- Do not implement eigenvector/Katz centrality, native `.so` analysis,
  packer fingerprinting, or string-decrypt micro-execution unless
  specifically requested — these were deliberately descoped, not forgotten.
- Do not let the GraphRAG report generator use any information not present
  in the JSON manifest / Neo4j ontology context passed into the prompt —
  this is a hard product requirement (banking compliance credibility), not
  a nice-to-have.
- Do not swap Label Powerset back in for the classifier without discussing
  the class-imbalance tradeoff first.
