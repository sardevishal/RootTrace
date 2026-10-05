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
