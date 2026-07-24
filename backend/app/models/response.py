"""
models/response.py

Pydantic models for the API response layer.
These are the shapes returned by /api/v1/vulnerabilities.
"""

from typing import Optional
from pydantic import BaseModel, Field
from app.models.vulnerability import Vulnerability


class PackageScanResult(BaseModel):
    """
    Aggregated scan result for a single package.
    Groups all discovered vulnerabilities under the scanned package.
    """

    package_name: str = Field(..., description="Name of the scanned package.")
    version: str = Field(..., description="Version of the scanned package.")
    ecosystem: str = Field(..., description="Ecosystem of the scanned package.")
    vulnerability_count: int = Field(
        default=0,
        description="Total number of vulnerabilities found for this package.",
    )
    highest_severity: str = Field(
        default="NONE",
        description="Highest severity level found across all vulnerabilities.",
    )
    vulnerabilities: list[Vulnerability] = Field(
        default_factory=list,
        description="List of normalized vulnerability records.",
    )


class VulnerabilityResponse(BaseModel):
    """
    Top-level API response returned by GET /api/v1/vulnerabilities.
    """

    scan_id: Optional[str] = Field(
        default=None,
        description="Unique identifier for this scan run (future use).",
    )
    total_packages_scanned: int = Field(
        ...,
        description="Number of packages that were scanned.",
    )
    total_vulnerabilities_found: int = Field(
        ...,
        description="Total vulnerability count across all packages.",
    )
    packages: list[PackageScanResult] = Field(
        default_factory=list,
        description="Per-package scan results.",
    )
    errors: list[str] = Field(
        default_factory=list,
        description="Any non-fatal errors encountered during the scan.",
    )
