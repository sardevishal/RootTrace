"""
schemas/ai_analysis_result_schema.py

API output schemas for AIAnalysisResult — P2G.
"""

from typing import Optional
from pydantic import BaseModel, Field


class AIFindingAnalysisOut(BaseModel):
    finding_id: str
    priority: int = 1
    explanation: Optional[str] = None
    impact: Optional[str] = None
    exploitability: Optional[str] = None
    remediation: Optional[str] = None
    dependency_context_note: Optional[str] = None
    attack_surface: Optional[str] = None
    confidence: Optional[str] = None


class AIAnalysisResultOut(BaseModel):
    contract_version: str = "1.0"
    scan_id: Optional[str] = None
    ai_status: str
    ai_error: Optional[str] = None
    llm_provider: Optional[str] = None
    executive_summary: Optional[str] = None
    overall_risk: Optional[str] = None
    total_findings_analyzed: int = 0
    finding_analyses: list[AIFindingAnalysisOut] = Field(default_factory=list)


class AnalyzeRequest(BaseModel):
    scan_id: Optional[str] = Field(
        default=None,
        description="Optional scan identifier to propagate through the analysis.",
    )
    max_findings: int = Field(
        default=50,
        ge=1,
        le=200,
        description="Maximum findings to include in AI context.",
    )
