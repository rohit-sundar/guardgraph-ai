import sys
from loguru import logger

# Suppress verbose debug logs from Androguard (level.no < 30 is below WARNING).
# Also silences the "dummy data are found between elements" AXML resync
# warning specifically — it's expected, harmless noise on a padded/corrupted
# manifest (see ingest.py's manifest-independent DEX fallback, which handles
# this case), and it can fire hundreds/thousands of times on a single sample
# since Androguard logs one line per resync byte it steps over.
_NOISY_ANDROGUARD_MESSAGES = ("dummy data are found between elements",)


def _log_filter(record: dict) -> bool:
    if "androguard" not in record["name"]:
        return True
    if record["level"].no < 30:
        return False
    return not any(m in record["message"] for m in _NOISY_ANDROGUARD_MESSAGES)


logger.remove()
logger.add(sys.stderr, filter=_log_filter, level="DEBUG")

import os
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from app.api.routes import router

app = FastAPI(
    title="GuardGraph AI",
    description="Static-analysis Android malware risk-scoring engine (prototype)",
    version="0.1.0-prototype",
)

app.include_router(router)

static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.get("/", response_class=FileResponse)
    def read_index():
        return FileResponse(os.path.join(static_dir, "index.html"))


@app.get("/health")
def health():
    return {"status": "ok"}

