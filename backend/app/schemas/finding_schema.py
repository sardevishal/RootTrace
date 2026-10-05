"""
schemas/finding_schema.py

Downstream-facing API schemas for VulnerabilityFinding — P2E contract.

These are the shapes exposed to:
    - AI Security Analysis module
    - Dashboard / Visualization
    - Reporting module
    - Any external DevSecOps integration

Downstream consumers MUST NOT need to understand:
    - OSV API structure
    - NVD API structure
    - GitHub GraphQL response structure
    - EPSS API response structure

They consume DependencyContextOut, VulnerabilityFindingOut, and FindingResponseOut only.

Contract version: "1.0"
Backward compatible with existing ScanResponseOut (additive changes only).
"""

from typing import Optional
from pydantic import BaseModel, Field


CONTRACT_VERSION = "1.0"


class DependencyContextOut(BaseModel):
    """Dependency graph context for a finding."""
    direct: bool = Field(default=True, description="True if directly declared in project manifest.")
    transitive: bool = Field(default=False, description="True if pulled in by another dependency.")
    depth: int = Field(default=0, description="Depth in the dependency tree (0=root, 1=direct, 2+=transitive).")
    parent: Optional[str] = Field(default=None, description="Immediate parent dependency name (if transitive).")
    dependency_path: list[str] = Field(
        default_factory=list,
        description="Full path from project root to this package. E.g. ['root-project', 'express', 'lodash']",
    )


class PackageInfoOut(BaseModel):
    """Package information embedded in a finding."""
    name: str
    version: Optional[str] = None
    ecosystem: str


class VulnerabilityInfoOut(BaseModel):
    """Vulnerability identity and scoring fields in a finding."""
    cve_id: Optional[str] = None
    osv_id: Optional[str] = None
    ghsa_id: Optional[str] = None
    nvd_id: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None
    severity: str = "UNKNOWN"
    affected_versions: list[str] = Field(default_factory=list)
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    epss_score: Optional[float] = None
    risk_score: Optional[float] = None
    risk_label: Optional[str] = None


class RemediationOut(BaseModel):
    """Remediation information for a finding."""
    fixed_version: Optional[str] = Field(
        default=None,
        description="First version in which the vulnerability is fixed. None if unknown. Never fabricated.",
    )


class SourceAttributionOut(BaseModel):
    """Source attribution information for a finding."""
    primary: str = Field(default="UNKNOWN", description="Primary source: OSV / NVD / GITHUB_ADVISORY / COMBINED.")
    contributing: list[str] = Field(
        default_factory=list,
        description="All sources that confirmed this vulnerability.",
    )


class SourceErrorOut(BaseModel):
    """Source error record for the API response."""
    source: str
    error_type: str
    message: str


class VulnerabilityFindingOut(BaseModel):
    """
    Canonical downstream API schema for a single VulnerabilityFinding.

    Contract version: 1.0
    """

    contract_version: str = Field(default=CONTRACT_VERSION)
    finding_id: str = Field(..., description="Deterministic SHA-256 finding identity.")
    scan_id: Optional[str] = None

    package: PackageInfoOut
    dependency: DependencyContextOut = Field(default_factory=DependencyContextOut)
    vulnerability: VulnerabilityInfoOut
    remediation: RemediationOut = Field(default_factory=RemediationOut)
    sources: SourceAttributionOut = Field(default_factory=SourceAttributionOut)
    references: list[str] = Field(default_factory=list)


class FindingResponseOut(BaseModel):
    """
    Top-level API response for the /api/v1/findings endpoint.

    This is the canonical downstream contract for the entire scan result.
    Backward compatible — existing /api/v1/vulnerabilities endpoint unchanged.
    """

    contract_version: str = Field(default=CONTRACT_VERSION)
    scan_id: Optional[str] = None
    scan_status: str = Field(default="completed")
    source_status: dict[str, str] = Field(default_factory=dict)
    total_packages_scanned: int = 0
    total_findings: int = 0
    findings: list[VulnerabilityFindingOut] = Field(default_factory=list)
    source_errors: list[SourceErrorOut] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
