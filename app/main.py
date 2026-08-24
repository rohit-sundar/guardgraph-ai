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
# Also to a file — the terminal running uvicorn is the only place these lines
# otherwise exist, which made a live Phase 8 (dynamic verification) result
# unrecoverable after the fact when debugging a specific request. Rotated so
# a long-running dev server doesn't grow this unbounded.
logger.add("logs/guardgraph.log", filter=_log_filter, level="DEBUG", rotation="20 MB", retention=3)

import os
import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from app.api.routes import router

@asynccontextmanager
async def lifespan(_: FastAPI):
    """
    Pay the Ollama model load at boot rather than on somebody's first upload.

    Measured: a cold /analyze took over 15 minutes with the load on the request
    path, against 2m33s once the model was resident.

    Started on a background thread rather than awaited, so the server answers
    immediately — a 4.7 GB load can take minutes, and blocking startup on it would
    move the wait from the first request to the process not coming up at all.
    Failure is logged and ignored; the analysis path already handles a cold or
    absent Ollama.
    """
    from app.reports.graphrag import preload_model

    threading.Thread(target=preload_model, name="ollama-preload", daemon=True).start()
    yield


app = FastAPI(
    title="GuardGraph AI",
    description="Static-analysis Android malware risk-scoring engine (prototype)",
    version="0.1.0-prototype",
    lifespan=lifespan,
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

