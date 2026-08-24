# GuardGraph AI — Full Project Context

> This document is written for an AI coding assistant picking up this project.
> It contains the idea, architecture, decisions already made (and why), current
> build status, what's real vs stubbed, and what to do next. Read this before
> touching any code.

> **This file predates 2026-08-22 and its "static-analysis-only" framing below (Sections 1 and 4) is
> now WRONG.** Read **`TEAM_CONTEXT.md`'s "Session 14"** entry first — as of 2026-08-24 this project
> also runs a scoped, opt-in Android-emulator + Frida **dynamic** verification pass
> (`app/analysis/dynamic_verification.py`) alongside the static pipeline, specifically to confirm/refute
> static predictions (C2 contact, DCL payload execution, native library loads) at runtime. That work is
> currently **uncommitted on this machine** — check `git status` before assuming it exists wherever
> you're reading this from. Sessions 12-13 (RE deep dive, manifest/ZIP resilience, Neo4j graph
> correlation, GraphRAG anti-fabrication, several small committed fixes) are also not covered here —
> read Session 12/13/14 in `TEAM_CONTEXT.md`'s Change Log in that order. Session 12 importantly records
> what was *tried and found not to work* (e.g. the local LLM does not reliably follow structural output
> instructions, confirmed across repeated live tests — don't re-attempt a rigid section-header contract
> without reading why it was reverted).

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

### Why this approach (explicit design decision — since revised, see banner above)
- Dynamic analysis (sandboxing/emulation) was ruled out as too heavy/slow for
  the target use case (banks need fast per-APK verdicts during active fraud
  campaigns). **Revised in Session 14 (2026-08-24, `TEAM_CONTEXT.md`)**: a
  scoped, strictly opt-in dynamic pass was added on top of this static
  engine, not instead of it — the default/cold path is still exactly this
  static-only design; dynamic analysis only ever runs when a caller
  explicitly asks for it via `enable_dynamic`, and every dynamic hook exists
  to confirm/refute a specific prediction this static engine already made,
  never as an independent verdict source.
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
| String encryption | Biggest real gap. Ideal: statically identify + isolate the decrypt routine and micro-execute it with constant inputs (sandboxed, not full dynamic analysis). Fallback: treat high string-pool entropy as a risk signal itself | ⚠️ Bounded micro-emulation implemented in `static_resolution._try_known_transform` (Base64.decode / String(byte[]) folding over already-resolved literals, plus local leaf-decoder summarization). A *parameterized* local decoder — one whose output depends on a caller-supplied key — remains a documented gap. Entropy is still measured but no longer scored (measured dead; see scoring.py) |
| Reflection-hidden API calls | Constant-propagation/taint tracking on `Class.forName`/`getMethod` string args to resolve real targets statically | ✅ Implemented — `app/analysis/static_resolution.py` propagates register constants within a method; `count_reflection_calls` in `obfuscation.py` returns resolved targets and counts only genuinely unresolved sites |
| Native code (.so) offloading | Static disassembly via headless Ghidra/radare2 to pull imported/JNI symbols — no emulation | ⚠️ Partial — `app/analysis/native_bridge.py` resolves `System.loadLibrary` targets, locates the `.so` (including disguised placement under `assets/`), and reads its ELF dynamic symbol table via pyelftools to correlate with `native`-flagged DEX methods. No disassembly: which native method belongs to which library needs `RegisterNatives` inside the `.so`, still out of scope |
| Dynamic code loading (`DexClassLoader`) | Presence of dynamic-loading code itself is a strong static signal even if payload is unseen; if payload is bundled as plaintext asset, recursively run through same pipeline | ✅ Implemented — `app/analysis/dcl_tracing.py` resolves the dexPath argument of `DexClassLoader` / `InMemoryDexClassLoader` / `PathClassLoader` and cross-references it against the flagged payload-asset inventory. The payload is not itself re-run through the pipeline |
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
│   │   ├── config.py            Settings, MODEL_LABEL_MAP, TTP_SEVERITY_WEIGHTS, VT/MB API keys
│   │   └── schemas.py           Pydantic contracts (IngestionResult, SignatureMatch, YaraMatch, AnalysisManifest, etc.)
│   ├── analysis/
│   │   ├── ingest.py            SHA-256, cert thumbprint, Androguard ingestion
│   │   ├── signatures.py        [S4] Local hash/cert DB + VirusTotal + MalwareBazaar online triage
│   │   ├── yara_engine.py       [S4] YARA compiler/scanner — 8 built-in rules + 455 community rules
│   │   ├── cfg.py               CFG construction + ACFG enrichment (NetworkX)
│   │   ├── forensic.py          Forensic dictionary, anchor detection, 4-hop subgraph extraction
│   │   ├── topology.py          Centrality/clustering stats, flattening outlier detection
│   │   └── obfuscation.py       Entropy scoring, reflection call counting, coverage notes
│   ├── ml/
│   │   ├── features.py          SINGLE SOURCE OF TRUTH for feature vector schema (33 features as of S4)
│   │   └── classifier.py        XGBoost load/predict wrapper
│   ├── graph/
│   │   ├── neo4j_client.py      Thin driver wrapper
│   │   ├── cache.py             Hot-path signature lookup/store
│   │   └── ontology.py          MITRE ATT&CK Mobile starter ontology loader
│   ├── static/                  [S9] Web UI (index.html, app.js, styles.css) served by FastAPI at `/`
│   └── reports/
│       ├── scoring.py           [S11] Risk score formula — weights match the paper (0.25/0.20/0.15/
│       │                        0.15/0.15/0.05/0.05), component internals recalibrated against a
│       │                        353-APK measured corpus
│       └── graphrag.py          Local-LLM (Ollama) report generation with anti-hallucination system prompt
├── scripts/
│   ├── train_model.py           CICMalDroid2020 training script skeleton
│   ├── load_ontology.py         One-time Neo4j ontology seed
│   ├── download_yara_rules.py   [S4] Downloads + filters Yara-Rules/rules community GitHub repo
│   ├── score_corpus.py          [S11] Measures all scoring components against the 353-APK corpus
│   └── test_upload.py           [S4] Local script to POST an APK and pretty-print analysis report
├── tests/
│   ├── test_features.py         Feature vector length invariant test (currently 33)
│   ├── test_pipeline_phases.py  Pipeline phase contract tests
│   ├── test_signatures_yara.py  [S4] Signature matching + YARA scan unit tests
│   ├── test_forensic_gating.py  [S10] Manifest-gate + clause forensic rule tests
│   └── test_score_calibration.py [S11] Pins calibration constants + verdict band boundaries
├── data/{samples,models}/       Gitignored, for local APKs and trained model
├── data/signatures/
│   └── known_hashes.json        [S4] Local signature DB (Anubis, Cerberus, TeaBot, FluBot, etc.)
├── data/yara_rules/             [S4] 518 community YARA rules (455 compile; 19 auto-skipped)
├── docker-compose.yml           Neo4j only
├── requirements.txt
├── .env.example
└── README.md
```

### What's real (implemented, not mocked)
- Full ingestion → CFG → ACFG → anchor detection → 4-hop subgraph extraction → topological feature mining → obfuscation scoring → risk scoring → Neo4j hot-path cache → GraphRAG report generation chain.
- **[S4] Signature detection + online triage**: local hash/cert DB lookup → VirusTotal API v3 (detection ratio + clickable report URL) → MalwareBazaar public API. Inserted as Phase 1.5 before CFG construction.
- **[S4] YARA scanning**: 8 built-in banking-trojan rules + 455 community rules from Yara-Rules/rules GitHub repo, compiled with per-rule validation (broken rules auto-skipped, not crash).
- **[S9] Web UI**: static single-page frontend at `app/static/` (upload form, verdict display, narrative rendering, Cytoscape.js subgraph view), served by FastAPI at `/`. No build step.
- **[S10] Forensic dictionary is manifest-gated**: each rule now requires a declared permission or intent-filter action before it can fire, plus same-method corroborating clauses. The original flat-OR dictionary ran backwards on a 353-APK corpus (clean apps fired *more* behaviors than malware); see TEAM_CONTEXT.md Session 10.
- **[S11] Risk scoring is recalibrated against a 353-APK corpus** (220 F-Droid benign + 133 MalwareBazaar malware) via `scripts/score_corpus.py` — component *weights* (0.25/0.20/0.15/0.15/0.15/0.05/0.05) are unchanged from the paper, but three of seven components' internal definitions changed (classifier confidence, obfuscation, IoC) after measurement showed they were dead or inverted; verdict band boundaries are now named constants at 30/60/65, not an even 0/30/60/80/100 cut. See TEAM_CONTEXT.md Session 11 for the full measurement writeup.
- GraphRAG prompt enforces all five guardrails from the original design doc (grounded-only, "not observed" for gaps, separate deterministic vs. predicted, confidence values required, prioritized actions).

### What's stubbed (on purpose, fails loudly rather than faking success)
- **Multi-label TTP classifier (primary, cold path — Session 5)**: `app/ml/classifier.py`
  `TTPClassifier` predicts MITRE ATT&CK Mobile techniques *directly* (Binary Relevance XGBoost over
  `app/ml/labels.TTP_LABELS`), replacing the `FAMILY_TO_TTPS` proxy. Raises `FileNotFoundError` until
  a model is dropped at `data/models/guardgraph_ttp_br_v1.joblib` (train via
  `scripts/train_model.py --target ttp`); pipeline degrades gracefully to empty predictions. The cold
  path is now an explicit **zero-day engine** — deterministic + structural components floor the score
  and set `RiskScoreBreakdown.zero_day_indicator`. See TEAM_CONTEXT.md Session 5 for full detail.
- **Family XGBoost classifier (now auxiliary)**: raises `FileNotFoundError` until a trained model is dropped at `data/models/guardgraph_xgb_v1.json`. Pipeline degrades gracefully — proceeds without predictions, report correctly says "not observed" for classifier findings.
- **Reflection constant-propagation**: implemented (`app/analysis/static_resolution.py`). `unresolved_reflection_targets` now counts name-bearing call sites whose argument did not trace back to a literal, rather than a placeholder.
- **Eigenvector/Katz centrality**: intentionally excluded from `topology.py` — expensive/unstable on disconnected subgraphs. Only degree, closeness, and clustering are computed. Add the other two only if specifically needed and tested against real subgraph shapes.
- **Packer fingerprinting**: not implemented at all, per the explicit obfuscation-coverage priority order (Section 4). Native (.so) analysis and string-decrypt micro-execution have since been built to the bounded scope described in that section's table — read it before assuming either is absent.

### Critical invariant to protect
`app/ml/features.py` — `FEATURE_NAMES` — is the single source of truth for
feature vector column order. As of Session 4 this is **33 features** (30 original + 3 signature/YARA columns added). `scripts/train_model.py` imports it; inference
in `app/api/routes.py` (via `build_feature_vector`) must produce vectors in
the exact same order. **XGBoost has no concept of column names at inference
time** — a silent mismatch here produces confident, wrong predictions with
no error raised. If this file changes, the model must be retrained. There are
smoke tests (`tests/test_features.py`, `tests/test_pipeline_phases.py`) that check vector *length* matches,
but do not and cannot check semantic column-order correctness — that's a
process discipline issue, not something automatable here.

> ⚠️ **Note for team member C (XGBoost training):** The feature vector grew from 30 → 33 in Session 4. The current deployed model zero-fills the 3 new columns, so predictions remain valid but don't yet benefit from signature/YARA signal. When retraining, ensure `signature_match_count`, `yara_rule_match_count`, and `yara_max_severity` are included in the training CSV in the correct column positions.

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

---

## 11. Refactoring Changes Log (Modular Phases & Local LLM Integration)

### Swap to Local LLM (July 10, 2026)
- Replaced Anthropic Claude API calls in `app/reports/graphrag.py` with an OpenAI-compatible client pointed at local Ollama (`http://localhost:11434/v1`).
- Configured local model default to `qwen2.5:7b-instruct-q4_K_M` via `OLLAMA_MODEL` environment settings in `.env` and `app/core/config.py`.
- Replaced `anthropic` library dependency with `openai` package in `requirements.txt`.

### Modular Processing Phases Refactor (July 10, 2026)
- Created `app/core/pipeline.py` implementing `AnalysisPipeline` to modularize static analysis execution into seven sequential, clean phases.
- Refactored `app/api/routes.py` to route execution through `AnalysisPipeline`.
- Configured loguru filters in `app/main.py` to silence Androguard's verbose debug output, displaying only clean GuardGraph phase timings.
- Created `tests/test_pipeline_phases.py` to verify phase compliance and contracts.

### Signature Detection + YARA + Online Triage Integration (July 16, 2026) | Author: Rohit
- **Phase 1.5 added** to `AnalysisPipeline` in `app/core/pipeline.py`: runs between ingestion (Phase 1) and CFG construction (Phase 2).
- **`app/analysis/signatures.py`** [NEW]: local JSON hash/cert signature DB lookup (`data/signatures/known_hashes.json`), followed by VirusTotal API v3 triage (`_lookup_virustotal`) and MalwareBazaar public hash-lookup triage (`_lookup_malwarebazaar`). Both online functions return `report_url` (clickable link) and `detection_ratio` (e.g. `"23/74 engines"`).
- **`app/analysis/yara_engine.py`** [NEW]: compiles 8 built-in banking-trojan YARA rules + all valid `.yar` files from `data/yara_rules/`. Each rule file is validated individually — broken files are skipped with a warning, not a crash. At runtime: 1 built-in + 455 community rules loaded (19 community rules auto-skipped for relative include/ELF module errors).
- **`scripts/download_yara_rules.py`** [NEW]: downloads `Yara-Rules/rules` GitHub repo as ZIP, filters out `import "androguard"` and `import "cuckoo"` rules (non-standard YARA modules), saves 518 clean rules to `data/yara_rules/`. Run this once to populate rules, or re-run to refresh.
- **`data/signatures/known_hashes.json`** [NEW]: local signature database seeded with SHA-256 hashes and certificate thumbprints for Anubis, Cerberus, TeaBot, FluBot, Sharkbot, Octo, Hydra.
- **`app/core/schemas.py`** updated: added `SignatureMatch` (with `report_url`, `detection_ratio`), `YaraMatch`, `SignatureYaraResult` Pydantic models. `AnalysisManifest.signature_yara` field added.
- **`app/ml/features.py`** updated: feature vector extended **30 → 33** with `signature_match_count`, `yara_rule_match_count`, `yara_max_severity`. Model must be retrained; interim zero-fill is safe.
- **`app/reports/scoring.py`** updated: `reputation_component` boosted on signature hit; `ioc_component` now scales with YARA match count and max severity.
- **`tests/test_signatures_yara.py`** [NEW]: unit tests for local matching, mocked VT/MB, YARA scan. All tests pass.
- **Live verified** against `f651876e...bbbced.apk`: VT returned `trojan.ag1587137/abrisk` (23/74 engines), 5 YARA rules matched.

### Android Malware Static Enrichments Integration (July 22, 2026) | Author: Rohit
- **`app/analysis/apk_static.py`** [NEW]: Comprehensive Android static malware analyzer for banking trojans, droppers, and OTP stealers. Extracts C2 IoCs via regex for Telegram bots (`telegram_bot:`), Firebase (`firebase:`), Discord webhooks, TOR `.onion` URLs (strictly validated against Tor base32 character encoding `[a-z2-7]`), raw IP:port, and C2 panel gate URLs; evaluates high-risk permission matrices (`OVERLAY_ATTACK_PATTERN`, `SMS_OTP_STEALER_PATTERN`, `DROPPER_STAGE2_PATTERN`, `DEVICE_ADMIN_PERSISTENCE`, `BANKING_TARGET_ENUMERATION`); parses X.509 certificate anomalies (debug keys `CN=Android Debug`, generic test subjects, self-signed junk, expired/future validity); walks ZIP assets for secondary DEX payloads (`classes2.dex`, `classes3.dex`, hidden DEX/ZIP magic bytes), HTML banking overlay templates, and disguised native libraries; parses accessibility service config XML for `canRetrieveWindowContent` and keylogging masks.
- **`app/analysis/ingest.py`** [MOD]: Integrated static enrichments into Phase 1 ingestion (`ingest_apk`), returning static anchor fields and uncompressed payload targets for Phase 1.5 YARA scanning.
- **`app/analysis/yara_engine.py`** [MOD]: Enhanced `scan_apk_with_payloads` to scan uncompressed DEX and asset byte streams in addition to the outer `.apk` ZIP file, eliminating ZIP compression evasion.
- **`app/core/schemas.py`** updated: Extended `IngestionResult` and `AnalysisManifest` with `c2_indicators`, `cert_anomalies`, `permission_matrix_flags`, `secondary_dex_count`, `accessibility_flags`, `exported_risks`, `payload_assets`, and `dropper_signals`.
- **`app/reports/scoring.py`** updated: Integrated static anchors into `permission_api_component`, `reputation_component`, and `ioc_component`.
- **`tests/test_apk_enhancements.py`** [NEW]: Unit test suite covering C2 extraction, permission matrices, cert anomalies, Tor base32 validation, and schema validation. Full test suite passing (8/8 green).

### Web UI (August 18, 2026) | Author: Tarun
- **`app/static/`** [NEW]: static single-page frontend (`index.html`, `app.js`, `styles.css`) — upload form, verdict/risk-score display, narrative report rendering via `marked.js`, and a Cytoscape.js graph view of behavioral subgraphs. No build step, CDN script tags only.
- **`app/main.py`** [MOD]: mounts `app/static/` at `/static` and serves `index.html` at `/` when present. No change to any existing API route.
- A portable local Ollama build (`bin/ollama/`) was committed once by accident during this session (hundreds of MB of CUDA DLLs) and reset out again before ever reaching the remote. `.gitignore` now excludes `bin/ollama/` explicitly; **never add binaries under `bin/` to git** — download Ollama separately per the README.

### Forensic Rule Gating (August 20, 2026, am) | Author: Rohit
- **`app/analysis/forensic.py`** [REWRITTEN]: `FORENSIC_DICTIONARY` rules used to OR `apis` + `strings` and never read `permissions` — one bare substring anywhere in the app fired a behavior (`"otp"` matched `"hotpink"`; AndroidX's `AccessibilityNodeInfo` reference fired `ACCESSIBILITY_ABUSE` on 207/220 clean F-Droid apps). Measured on a 353-APK corpus (220 benign / 133 malware), the dictionary ran backwards: clean apps fired 3.91 behaviors on average vs. malware's 4.01. Fixed with a manifest `declares` gate (permission or intent-filter action required before a rule is even eligible) plus `clauses` requiring corroborating patterns to hit **in the same method**.
- **`tests/test_forensic_gating.py`** [NEW]: 209 lines covering the gate/clause logic and the specific substrings that used to false-positive.
- Full detail: see TEAM_CONTEXT.md Session 10.

### Risk Score Recalibration (August 20, 2026, pm) | Author: Rohit
- **`scripts/score_corpus.py`** [NEW]: measures every risk-score component against the same 353-APK corpus (220 F-Droid benign + 133 MalwareBazaar malware). Three of seven components were found dead or actively inverted by measurement, not intuition.
- **`app/reports/scoring.py`** [REWRITTEN internals, weights unchanged]: `classifier_confidence_component` changed from `max(predicted_ttps.values())` to a threshold-normalized evidence mass summed across all predicted techniques. `obfuscation_component` dropped string-entropy and flattening-prevalence scoring (both measured dead/backwards) in favor of manifest-vs-code method-count mismatch + CFG parse-failure rate. `ioc_component` now separates sample-identifying evidence (can reach the cap alone) from circumstantial evidence (jointly capped at 0.35), since generic YARA rule severity used to let breadth alone saturate the component.
- **Verdict bands** are now named constants (`BAND_LOW_CEILING=30.0`, `BAND_SUSPICIOUS_CEILING=60.0`, `BAND_HIGH_CEILING=65.0`) each derived from its own criterion against the measured corpus, replacing the original even 0/30/60/80/100 split. Result: 212/220 clean apps read `low`, none reaches `high`; 106/133 malware read `high` or `malicious`.
- **`tests/test_score_calibration.py`** [NEW]: pins the calibration constants and band boundaries.
- Full detail, including the per-component measurement tables: see TEAM_CONTEXT.md Session 11.
