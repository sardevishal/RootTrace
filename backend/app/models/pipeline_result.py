from pydantic import BaseModel, Field
from typing import Any, Optional

from app.models.dependency_scan import DependencyScanResult
from app.models.response import VulnerabilityResponse


class RootTracePipelineResult(BaseModel):
    """Unified result of the entire RootTrace pipeline."""
    scan_id: str = Field(..., description="Unique identifier for the scan.")
    status: str = Field(..., description="Pipeline execution status.")

    dependency_scan: DependencyScanResult = Field(..., description="Full dependency graph and inventory.")
    vulnerability_scan: VulnerabilityResponse = Field(..., description="Vulnerability findings.")

    paths: dict[str, list[list[str]]] = Field(
        default_factory=dict,
        description="Dependency paths mapping a dependency ID to a list of paths from the root."
    )

    # P2G: AI analysis result — optional so pipeline works without AI
    ai_analysis: Optional[Any] = Field(
        default=None,
        description="AIAnalysisResult from the AI Security Analysis Engine (P2G). None if not requested."
    )
    ai_status: str = Field(
        default="not_requested",
        description="AI analysis status: not_requested | completed | completed_with_warnings | unavailable | failed"
    )
