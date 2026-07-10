import sys
from loguru import logger

# Suppress verbose debug logs from Androguard (level.no < 30 is below WARNING)
logger.remove()
logger.add(
    sys.stderr,
    filter=lambda record: "androguard" not in record["name"] or record["level"].no >= 30,
    level="DEBUG",
)

from fastapi import FastAPI
from app.api.routes import router

app = FastAPI(
    title="GuardGraph AI",
    description="Static-analysis Android malware risk-scoring engine (prototype)",
    version="0.1.0-prototype",
)

app.include_router(router)


@app.get("/health")
def health():
    return {"status": "ok"}
