"""
/analyze router
===============
FastAPI router for the phishing detection endpoint.
"""

from __future__ import annotations

import json
from fastapi import APIRouter, HTTPException, status
from fastapi.responses import StreamingResponse

from app.logging import logger
from app.schemas.analyze import AnalyzeRequest, AnalyzeResponse
from app.services.analysis_service import AnalysisService
from app.services.llm_adapter import LLMConfigurationError

router = APIRouter(prefix="/analyze", tags=["analysis"])

# Service is instantiated once at import time (singleton pattern)
_analysis_service: AnalysisService | None = None


def get_analysis_service() -> AnalysisService:
    global _analysis_service
    if _analysis_service is None:
        _analysis_service = AnalysisService()
    return _analysis_service


@router.post(
    "",
    response_model=AnalyzeResponse,
    summary="Analyze a URL for phishing",
    description=(
        "Runs the full adaptive two-stage phishing detection pipeline: "
        "ML classifier → Fast Evidence → Stage 1 LLM → optional Playwright "
        "screenshot → Stage 2 LLM → citizen safety guidance."
    ),
)
async def analyze_url(request: AnalyzeRequest):
    url = str(request.url)
    logger.info(f"[Router /analyze] Received request for URL: {url}")

    service = get_analysis_service()

    async def event_generator():
        try:
            async for event in service.analyze_stream(url=url, bypass_cache=request.bypass_cache):
                yield json.dumps(event) + "\n"
        except LLMConfigurationError as exc:
            yield json.dumps({"event": "error", "message": f"LLM Configuration Error: {str(exc)}"}) + "\n"
        except Exception as exc:
            logger.exception(f"[Router /analyze] Error in stream: {exc}")
            yield json.dumps({"event": "error", "message": f"Analysis failed: {type(exc).__name__}: {str(exc)}"}) + "\n"

    return StreamingResponse(event_generator(), media_type="application/x-ndjson")


@router.get(
    "/health",
    summary="Health check for the analysis service",
)
async def analyze_health() -> dict:
    """Returns service status and DB record count."""
    from app.services.phishing_database import phishing_db
    from app.models.machine_learning import phishing_model

    return {
        "status": "ok",
        "ml_model_loaded": phishing_model.is_loaded,
        "confirmed_phishing_db_records": phishing_db.count(),
    }
