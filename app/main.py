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
