"""
Central config. Loads from .env. Nothing here should be hardcoded secrets.

LLM backend: Ollama running locally (http://localhost:11434).
To use a different model, set OLLAMA_MODEL in .env.
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
