"""
api/ai_analysis.py

FastAPI router for the AI Security Analysis input.
"""

from fastapi import APIRouter, HTTPException, status, Query
from app.services.ai.ai_input_provider import SecurityAnalysisInputProvider
from app.schemas.ai_analysis_schema import (
    AIAnalysisInputOut,
    AIAnalysisSummaryOut,
    AIAnalysisContextOut,
)
from app.api.findings import _finding_to_out
from app.utils.logger import get_logger

logger = get_logger(__name__)

router = APIRouter(
    prefix="/api/v1/ai-analysis",
    tags=["AI Analysis"],
)

_provider = SecurityAnalysisInputProvider()

@router.get(
    "/input",
    response_model=AIAnalysisInputOut,
    summary="Get AI Security Analysis Input",
    description="Returns prioritized and context-limited vulnerability findings for AI processing.",
)
def get_ai_analysis_input(max_findings: int = Query(50, ge=1, le=200)) -> AIAnalysisInputOut:
    """
    GET /api/v1/ai-analysis/input
    
    Provides the canonical AI input structure.
    """
    logger.info("API | GET /api/v1/ai-analysis/input — requested with max_findings=%d", max_findings)
    try:
        result = _provider.get_analysis_input(max_findings=max_findings)
    except Exception as exc:
        logger.exception("API | Unhandled AI input provider error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"AI input generation failed: {str(exc)}",
        )
    
    findings_out = [_finding_to_out(f) for f in result.findings]
    
    return AIAnalysisInputOut(
        contract_version=result.contract_version,
        scan_id=result.scan_id,
        summary=AIAnalysisSummaryOut(**result.summary.model_dump()),
        findings=findings_out,
        context=AIAnalysisContextOut(**result.context.model_dump()),
    )
