"""
models/response.py

Pydantic models for the API response layer.
These are the shapes returned by /api/v1/vulnerabilities.
"""

from typing import Any, Optional
from pydantic import BaseModel, Field
from app.models.vulnerability import Vulnerability


class SourceError(BaseModel):
    """Structured error record for a single vulnerability source failure."""
    source: str = Field(..., description="Source name: OSV, NVD, GitHubAdvisory.")
    error_type: str = Field(..., description="timeout | network | rate_limit | http_4xx | http_5xx | invalid_response | unknown")
    message: str = Field(..., description="Human-readable error description.")


class PackageScanResult(BaseModel):
    """
    Aggregated scan result for a single package.
    Groups all discovered vulnerabilities under the scanned package.
    """

    package_name: str = Field(..., description="Name of the scanned package.")
    version: Optional[str] = Field(default=None, description="Version of the scanned package.")
    version_spec: Optional[str] = Field(default=None, description="Version specifier if unresolved.")
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
    source_errors: list[SourceError] = Field(
        default_factory=list,
        description="Per-source errors encountered while scanning this package.",
    )


class VulnerabilityResponse(BaseModel):
    """
    Top-level API response returned by GET /api/v1/vulnerabilities.
    """

    scan_id: Optional[str] = Field(
        default=None,
        description="Unique identifier for this scan run.",
    )
    status: str = Field(
        default="completed",
        description="completed | completed_with_warnings | failed",
    )
    total_packages_scanned: int = Field(
        ...,
        description="Number of packages that were scanned.",
    )
    total_vulnerabilities_found: int = Field(
        ...,
        description="Total vulnerability count across all packages.",
    )
    source_status: dict[str, str] = Field(
        default_factory=dict,
        description="Status of each vulnerability source: 'ok' | 'unavailable' | 'partial'.",
    )
    packages: list[PackageScanResult] = Field(
        default_factory=list,
        description="Per-package scan results.",
    )
    errors: list[str] = Field(
        default_factory=list,
        description="Any non-fatal errors encountered during the scan.",
    )
    source_errors: list[SourceError] = Field(
        default_factory=list,
        description="Structured per-source error records.",
    )
