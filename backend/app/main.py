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
from app.api.dependency import router as dependency_router
from app.api.findings import router as findings_router
from app.api.ai_analysis import router as ai_analysis_router
from app.utils.logger import get_logger

logger = get_logger(__name__)

app = FastAPI(
    title="RootTrace — Supply Chain Security Platform",
    description=(
        "RootTrace Backend Services:\n"
        "- Dependency Analysis Engine: Manifest Parsing, Graph Construction & Metadata\n"
        "- Vulnerability Intelligence Engine: OSV Scanning & Risk Scoring"
    ),
    version="0.2.0",
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
app.include_router(dependency_router)
app.include_router(findings_router)
app.include_router(ai_analysis_router)


@app.get("/", tags=["Root"])
def root() -> dict:
    """Root health check — confirms the API is running."""
    return {
        "project": "RootTrace",
        "modules": [
            "Dependency Analysis Engine",
            "Vulnerability Intelligence Engine",
        ],
        "status": "running",
        "docs": "/docs",
    }


logger.info("RootTrace | Vulnerability Intelligence Engine starting up — Phase 1")
