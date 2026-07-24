"""
app/main.py

FastAPI application entry point for RootTrace backend.

Registers all routers and configures the application.
Run with:
    uvicorn app.main:app --reload
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.vulnerability import router as vulnerability_router
from app.utils.logger import get_logger

logger = get_logger(__name__)

app = FastAPI(
    title="RootTrace — Vulnerability Intelligence Engine",
    description=(
        "Phase 1: Mock package loading → OSV vulnerability scanning → "
        "Risk scoring → Structured JSON response."
    ),
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── CORS (allow all origins in development) ───────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(vulnerability_router)


@app.get("/", tags=["Root"])
def root() -> dict:
    """Root health check — confirms the API is running."""
    return {
        "project": "RootTrace",
        "module": "Vulnerability Intelligence Engine",
        "phase": 1,
        "status": "running",
        "docs": "/docs",
    }


logger.info("RootTrace | Vulnerability Intelligence Engine starting up — Phase 1")
