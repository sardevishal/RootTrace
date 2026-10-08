"""
api/ai_analysis.py

FastAPI router for the AI Security Analysis input.
"""

from fastapi import APIRouter, HTTPException, status, Query
from app.services.ai.ai_input_provider import SecurityAnalysisInputProvider
from app.services.ai.security_analysis_service import SecurityAnalysisService
from app.services.ai.mock_llm_provider import MockLLMProvider
from app.schemas.ai_analysis_schema import (
    AIAnalysisInputOut,
    AIAnalysisSummaryOut,
    AIAnalysisContextOut,
)
from app.schemas.ai_analysis_result_schema import (
    AIAnalysisResultOut,
    AIFindingAnalysisOut,
    AnalyzeRequest,
)
from app.api.findings import _finding_to_out
from app.utils.logger import get_logger

logger = get_logger(__name__)

router = APIRouter(
    prefix="/api/v1/ai-analysis",
    tags=["AI Analysis"],
)

_provider = SecurityAnalysisInputProvider()
_analysis_service = SecurityAnalysisService(llm_provider=MockLLMProvider())

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


@router.post(
    "/analyze",
    response_model=AIAnalysisResultOut,
    summary="Run AI Security Analysis",
    description=(
        "Runs the full vulnerability pipeline and then performs AI Security Analysis "
        "using the canonical VulnerabilityFinding contract.\n\n"
        "**AI failures are isolated** — a failed AI analysis does NOT mean the "
        "vulnerability scan failed. Check ai_status in the response.\n\n"
        "Current provider: MockLLMProvider (deterministic, offline)."
    ),
)
def run_ai_analysis(request: AnalyzeRequest) -> AIAnalysisResultOut:
    """
    POST /api/v1/ai-analysis/analyze

    Orchestrates: VulnerabilityFindings → AI Analysis → AIAnalysisResult
    """
    logger.info(
        "API | POST /api/v1/ai-analysis/analyze — scan_id=%s max_findings=%d",
        request.scan_id or "N/A", request.max_findings,
    )
    try:
        analysis_input = _provider.get_analysis_input(
            scan_id=request.scan_id,
            max_findings=request.max_findings,
        )
        ai_result = _analysis_service.analyze(analysis_input)
    except Exception as exc:
        logger.exception("API | Unhandled analysis error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"AI analysis failed: {str(exc)}",
        )

    return AIAnalysisResultOut(
        contract_version=ai_result.contract_version,
        scan_id=ai_result.scan_id,
        ai_status=ai_result.ai_status,
        ai_error=ai_result.ai_error,
        llm_provider=ai_result.llm_provider,
        executive_summary=ai_result.executive_summary,
        overall_risk=ai_result.overall_risk,
        total_findings_analyzed=ai_result.total_findings_analyzed,
        finding_analyses=[
            AIFindingAnalysisOut(**fa.model_dump())
            for fa in ai_result.finding_analyses
        ],
    )

