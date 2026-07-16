"""
Central config. Loads from .env. Nothing here should be hardcoded secrets.

LLM backend: Ollama running locally (http://localhost:11434).
To use a different model, set OLLAMA_MODEL in .env.

FAMILY_TO_TTPS is a deliberate bridge: the v1 classifier outputs malware-family
labels, but ttp_severity_component expects MITRE technique IDs. Without this
mapping that scoring component is silently dead (always returns DEFAULT). This is
an honest proxy until per-technique binary classifiers are trained — see §9.2.
"""
from pydantic_settings import BaseSettings


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

    entropy_high_threshold: float = 7.2
    flattening_degree_outlier_zscore: float = 3.0

    class Config:
        env_file = ".env"


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
# Starter values — tune against real analyst judgment before trusting these.
TTP_SEVERITY_WEIGHTS = {
    "T1636": 0.9,   # Protected User Data (SMS)
    "T1624": 0.8,   # Event Triggered Execution
    "T1417": 0.85,  # Input Capture
    "T1409": 0.6,   # Stored Application Data
    "T1471": 0.95,  # Data Encrypted for Impact
    "DEFAULT": 0.5,
}

# Bridges family classifier output → likely MITRE technique IDs (§9.2 fix).
# Confidence from the family classifier is propagated to each mapped technique
# at a per-technique discount (the family→technique mapping is imprecise).
# Expand as per-technique classifiers replace this proxy.
FAMILY_TO_TTPS: dict[str, list[str]] = {
    "banker":           ["T1636", "T1417", "T1624"],  # SMS harvest, input capture, persistence
    "trojan":           ["T1624", "T1409"],            # persistence, stored data
    "password_stealer": ["T1417", "T1409"],            # input capture, stored data
    "coinminer":        ["T1624"],                     # persistence (autostart)
    "rat":              ["T1417", "T1636", "T1624"],  # input capture, SMS, persistence
    "keylogger":        ["T1417"],                     # input capture
}
