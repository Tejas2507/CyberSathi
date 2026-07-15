"""
CyberSathi — FastAPI Application Entry Point
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import API_V1_STR, PROJECT_NAME
from app.logging import logger
from app.models.machine_learning import phishing_model
from app.settings import settings


# ---------------------------------------------------------------------------
# Ensure artifact directories exist
# ---------------------------------------------------------------------------
for _d in ["artifacts/screenshots", "artifacts/rendered_html", "artifacts/html"]:
    Path(_d).mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Lifespan: load ML model on startup
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load heavy resources before serving requests."""
    logger.info(f"[Startup] Loading URLDetector ML model...")
    try:
        await asyncio.to_thread(phishing_model.load_model)
        logger.info("[Startup] ML model loaded successfully.")
    except Exception as exc:
        logger.error(f"[Startup] Failed to load ML model: {exc}")
    yield
    logger.info("[Shutdown] CyberSathi shutting down.")


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title=PROJECT_NAME,
    description=(
        "AI-powered phishing detection backend using adaptive evidence collection "
        "and Gemini LLM reasoning."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url=f"{API_V1_STR}/docs",
    redoc_url=f"{API_V1_STR}/redoc",
    openapi_url=f"{API_V1_STR}/openapi.json",
)

# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------

cors_origins = settings.BACKEND_CORS_ORIGINS
if isinstance(cors_origins, str):
    cors_origins = [o.strip() for o in cors_origins.split(",")]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------

from app.routers.analyze import router as analyze_router  # noqa: E402

app.include_router(analyze_router, prefix=API_V1_STR)


# ---------------------------------------------------------------------------
# Root health check
# ---------------------------------------------------------------------------

@app.get("/", tags=["health"])
async def root():
    return {"project": PROJECT_NAME, "version": "1.0.0", "status": "running"}


@app.get("/health", tags=["health"])
async def health():
    return {
        "status": "ok",
        "ml_model_loaded": phishing_model.is_loaded,
    }
