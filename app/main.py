import sys
from loguru import logger

# Suppress verbose debug logs from Androguard (level.no < 30 is below WARNING)
logger.remove()
logger.add(
    sys.stderr,
    filter=lambda record: "androguard" not in record["name"] or record["level"].no >= 30,
    level="DEBUG",
)

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

