"""
SentraGuard Lite - FastAPI Service
-----------------------------------
Exactly 2 endpoints as per spec:
  POST /analyze
  GET  /policy

No health endpoint added on purpose (spec says avoid extra APIs).
"""
import logging
from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.schemas import AnalyzeRequest, AnalyzeResponse, PolicyResponse
from app.core.scoring import analyze_request, BLOCK_THRESHOLD, TRANSFORM_THRESHOLD

# Logging: only safe metadata, never raw prompt/response content (per handbook).
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sentraguard")

app = FastAPI(title="SentraGuard Lite", version="1.0")

POLICY = {
    "version": "1",
    "detectors": ["prompt_injection", "pii", "rag_injection"],
    "thresholds": {"block_score": BLOCK_THRESHOLD, "transform_score": TRANSFORM_THRESHOLD},
}


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    # Clear, structured error messages for invalid payloads (per handbook)
    return JSONResponse(
        status_code=422,
        content={"error": "validation_error", "details": exc.errors()},
    )


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze(payload: AnalyzeRequest):
    context_docs = [doc.model_dump() for doc in payload.context_docs]
    result = analyze_request(payload.prompt, context_docs)

    # Safe logging only: request_id, counts, tags, timestamp (no raw content)
    request_id = payload.metadata.request_id if payload.metadata else None
    logger.info(
        "analyze_call request_id=%s risk_tags=%s decision=%s",
        request_id, result["risk_tags"], result["decision"],
    )

    return result


@app.get("/policy", response_model=PolicyResponse)
async def policy():
    return POLICY


@app.get("/", include_in_schema=False)
async def root():
    return RedirectResponse(url="/docs")
