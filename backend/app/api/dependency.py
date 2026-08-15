"""
api/dependency.py

FastAPI router for the Dependency Analysis Engine.

Endpoints:
    POST /api/v1/dependencies/analyze  — Analyze a repository and return the dependency graph & metadata.
    GET  /api/v1/dependencies/health   — Health check for this router.

This file is thin by design.
All business logic lives in services/dependency/engine.py.
"""

from fastapi import APIRouter, HTTPException, status
from app.services.dependency.engine import DependencyAnalysisEngine
from app.schemas.dependency_request import DependencyAnalysisRequest
from app.schemas.dependency_response import DependencyAnalysisResponse
from app.utils.logger import get_logger

logger = get_logger(__name__)

router = APIRouter(
    prefix="/api/v1/dependencies",
    tags=["Dependencies"],
)

# Engine instance shared across requests (stateless, safe to reuse)
_engine = DependencyAnalysisEngine()


@router.post(
    "/analyze",
    response_model=DependencyAnalysisResponse,
    summary="Analyze Repository Dependencies",
    description=(
        "Scans a repository directory, discovers manifest files (package.json, "
        "requirements.txt, pom.xml, go.mod, Dockerfile), parses dependencies, "
        "builds a dependency graph, and produces a normalized package inventory."
    ),
)
def analyze_dependencies(request: DependencyAnalysisRequest) -> DependencyAnalysisResponse:
    """
    POST /api/v1/dependencies/analyze

    Analyzes dependencies in the specified repository path.
    """
    logger.info("API | POST /api/v1/dependencies/analyze — repo: %s", request.repository_path)

    try:
        result = _engine.analyze(
            repository_path=request.repository_path,
            scan_id=request.scan_id,
            repository_id=request.repository_id,
        )
    except Exception as exc:
        logger.exception("API | Unhandled dependency engine error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Dependency analysis failed: {str(exc)}",
        )

    logger.info(
        "API | Analysis complete — status=%s, %d total dependencies, %d manifests parsed.",
        result.status,
        result.total_dependencies,
        result.manifests_parsed,
    )
    return DependencyAnalysisResponse(**result.model_dump())


@router.get(
    "/health",
    summary="Health Check",
    description="Returns health status for the Dependency Analysis Engine router.",
)
def health_check() -> dict:
    """
    GET /api/v1/dependencies/health
    """
    return {
        "status": "ok",
        "module": "Dependency Analysis Engine",
        "version": "1.0.0",
        "phase": 1,
    }
