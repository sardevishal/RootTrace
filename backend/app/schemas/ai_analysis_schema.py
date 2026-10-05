"""
schemas/ai_analysis_schema.py

Serialization schemas for the AI Security Analysis input.
"""

from typing import Optional
from pydantic import BaseModel, Field
from app.schemas.finding_schema import VulnerabilityFindingOut

class AIAnalysisSummaryOut(BaseModel):
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int
    direct_dependencies: int
    transitive_dependencies: int
    affected_packages: int

class AIAnalysisContextOut(BaseModel):
    total_findings: int
    included_findings: int
    omitted_findings: int

class AIAnalysisInputOut(BaseModel):
    """Stable JSON serialization schema for AI Security Analysis."""
    contract_version: str = Field(default="1.0")
    scan_id: Optional[str] = None
    summary: AIAnalysisSummaryOut
    findings: list[VulnerabilityFindingOut]
    context: AIAnalysisContextOut
