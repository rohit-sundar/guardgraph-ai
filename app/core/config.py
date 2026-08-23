"""
Central config. Loads from .env. Nothing here should be hardcoded secrets.

LLM backend: Ollama running locally (http://localhost:11434).
To use a different model, set OLLAMA_MODEL in .env.

FAMILY_TO_TTPS is a deliberate bridge: the v1 classifier outputs malware-family
labels, but ttp_severity_component expects MITRE technique IDs. Without this
mapping that scoring component is silently dead (always returns DEFAULT). This is
an honest proxy until per-technique binary classifiers are trained — see §9.2.
"""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "changeme"

    # Local LLM via Ollama (OpenAI-compatible endpoint)
    ollama_base_url: str = "http://localhost:11434/v1"
    ollama_model: str = "qwen2.5:7b-instruct-q4_K_M"

    model_path: str = "data/models/guardgraph_xgb_v1.json"
    samples_dir: str = "data/samples"

    # Signature detection & YARA scanning
    signature_db_path: str = "data/signatures/known_hashes.json"
    yara_rules_dir: str = "data/yara_rules"
    virustotal_api_key: str = ""
    malwarebazaar_api_key: str = ""

    # Master switch for the two third-party reputation lookups in
    # app/analysis/signatures.py. Both public tiers are metered — VirusTotal
    # allows 4 requests/min and 500/day, and MalwareBazaar now rejects every
    # unauthenticated request with HTTP 401. Nothing on the /analyze path can
    # breach either limit: _run_analysis() is synchronous inside async def, so
    # requests serialise at one analysis per 60-200 s, and lookup_signature()
    # answers repeat uploads from Neo4j before Phase 1.5 ever runs.
    # scripts/score_corpus.py is the only caller that can, which is why it
    # turns this OFF by default and paces itself behind --online.
    online_lookups_enabled: bool = True

    entropy_high_threshold: float = 7.2
    flattening_degree_outlier_zscore: float = 3.0

    # Hard ceiling on the Phase 7 (GraphRAG) prompt, in approximate tokens.
    # Set against the OBSERVED 16,386 tokens Ollama actually evaluated for
    # qwen2.5:7b-instruct before truncating — not the nominal 32,768 context,
    # which is never what the model receives in practice.
    graphrag_prompt_token_budget: int = 15000

    # Fixed decode seed for the GraphRAG LLM call. temperature=0 alone does not
    # guarantee reproducible output — batch scheduling and KV-cache reuse can
    # still perturb the decode between identical calls. Ollama honours `seed`,
    # so pin it rather than relying on greedy decoding alone.
    graphrag_seed: int = 42

    # Penalizes tokens already used in the completion so far, applied to logits
    # BEFORE the greedy argmax pick — still fully deterministic given the same
    # seed and history, unlike temperature/top_p which reintroduce sampling.
    # Ollama's default (1.1) was not enough to stop a live-observed degenerate
    # loop: qwen2.5:7b-instruct-q4_K_M repeated "API Coverage Component Weighted
    # Score: 1234567890" for most of a 2000-token completion budget rather than
    # writing the report (2026-08-23). Raised until that stops recurring.
    graphrag_repeat_penalty: float = 1.3

    # How long Ollama should keep the model resident after a request. Measured:
    # the FIRST large prefill after a model load decodes differently from every
    # later one, so an idle unload (Ollama's default is 5m) silently makes the
    # next analysis the odd one out. Hold the model resident across a normal
    # working session instead. Only the native /api/chat endpoint honours this —
    # the OpenAI-compatible /v1 endpoint accepts and ignores it.
    graphrag_keep_alive: str = "30m"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()

# MUST match the label order your XGBoost model was trained on.
# Update this the moment training finishes tonight — index order matters,
# XGBoost has no idea what index 3 "means", it just returns index 3.
MODEL_LABEL_MAP = [
    "banker",
    "trojan",
    "password_stealer",
    "coinminer",
    "rat",
    "keylogger",
]

# MITRE ATT&CK Mobile TTP severity weights used in risk scoring.
# Per-technique overrides (checked first). Tune against real analyst judgment.
TTP_SEVERITY_WEIGHTS = {
    "T1636": 0.9,   # Protected User Data (SMS)
    "T1624": 0.8,   # Event Triggered Execution
    "T1417": 0.85,  # Input Capture
    "T1409": 0.6,   # Stored Application Data
    "T1471": 0.95,  # Data Encrypted for Impact
    "DEFAULT": 0.5,
}

# Tactic-derived severity fallback so EVERY predicted Mobile technique gets a
# principled severity (not DEFAULT) — used by ttp_severity_component when a
# technique is not in TTP_SEVERITY_WEIGHTS. Keyed by ATT&CK Mobile tactic display
# name (see app/ml/labels.TECHNIQUE_TACTIC). Higher = more fraud/impact relevant.
TACTIC_SEVERITY = {
    "Impact": 0.95,
    "Credential Access": 0.90,
    "Collection": 0.85,
    "Exfiltration": 0.85,
    "Privilege Escalation": 0.70,
    "Command and Control": 0.70,
    "Persistence": 0.65,
    "Initial Access": 0.60,
    "Defense Evasion": 0.60,
    "Execution": 0.55,
    "Discovery": 0.40,
    "Lateral Movement": 0.55,
}

# LEGACY / hot-path only. The cold path now predicts techniques DIRECTLY via the
# multi-label TTPClassifier (app/ml/classifier.py) instead of this family→TTP proxy.
# Kept for the hot path and as a fallback for the untrained-family case; do not use
# it to derive cold-path predicted_ttps anymore (§9.2 superseded by the TTP model).
FAMILY_TO_TTPS: dict[str, list[str]] = {
    "banker":           ["T1636", "T1417", "T1624"],  # SMS harvest, input capture, persistence
    "trojan":           ["T1624", "T1409"],            # persistence, stored data
    "password_stealer": ["T1417", "T1409"],            # input capture, stored data
    "coinminer":        ["T1624"],                     # persistence (autostart)
    "rat":              ["T1417", "T1636", "T1624"],  # input capture, SMS, persistence
    "keylogger":        ["T1417"],                     # input capture
}
