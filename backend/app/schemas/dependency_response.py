"""
schemas/dependency_response.py

API output schemas for the Dependency Analysis Engine.
These are the shapes returned by POST /api/v1/dependencies/analyze.
"""

from typing import Optional, Any
from pydantic import BaseModel, Field

from app.schemas.dependency_graph_schema import DependencyGraphOut


class ManifestOut(BaseModel):
    """Manifest file metadata as returned by the API."""
    path: str
    manifest_type: str
    ecosystem: str
    has_lockfile: bool
    lockfile_path: Optional[str] = None


class DependencyOut(BaseModel):
    """A single dependency as returned by the API."""
    id: str
    name: str
    version: Optional[str] = None
    version_spec: Optional[str] = None
    ecosystem: str
    dependency_type: str
    direct: bool
    transitive: bool
    depth: int
    source_manifest: str
    source_path: str
    group_id: Optional[str] = None
    artifact_id: Optional[str] = None
    maven_scope: Optional[str] = None
    go_indirect: bool = False
    dockerfile_line: Optional[int] = None


class NormalizedPackageOut(BaseModel):
    """
    Minimal downstream-compatible package representation.

    This is the format directly consumable by the Vulnerability
    Intelligence Engine and downstream systems.
    """
    package_name: str
    version: Optional[str] = None
    version_spec: Optional[str] = None
    ecosystem: str
    dependency_id: Optional[str] = None


class ScanErrorOut(BaseModel):
    """Structured error from the dependency scan."""
    path: Optional[str] = None
    error_type: str
    message: str
    ecosystem: Optional[str] = None


class ScanWarningOut(BaseModel):
    """Structured warning from the dependency scan."""
    path: Optional[str] = None
    warning_type: str
    message: str


class DependencyAnalysisResponse(BaseModel):
    """
    Top-level API response for POST /api/v1/dependencies/analyze.

    Contains:
      - Scan metadata
      - Discovered manifests
      - Full dependency list
      - Dependency graph
      - Downstream-compatible normalized package inventory
      - Errors and warnings
    """

    scan_id: Optional[str] = Field(None, description="Unique scan identifier.")
    repository_path: str = Field(..., description="Analyzed repository path.")
    status: str = Field(..., description="completed / completed_with_warnings / failed")

    # Summary
    total_dependencies: int = Field(default=0)
    direct_dependencies: int = Field(default=0)
    transitive_dependencies: int = Field(default=0)
    manifests_found: int = Field(default=0)
    manifests_parsed: int = Field(default=0)

    # Data
    manifests: list[ManifestOut] = Field(default_factory=list)
    dependencies: list[DependencyOut] = Field(default_factory=list)
    graph: Optional[DependencyGraphOut] = Field(
        default=None,
        description="Dependency graph (nodes + edges + stats).",
    )

    # Downstream-compatible flat inventory
    normalized_packages: list[NormalizedPackageOut] = Field(
        default_factory=list,
        description=(
            "Flat package list consumable by the Vulnerability Intelligence Engine. "
            "Each entry: {package_name, version, ecosystem}"
        ),
    )

    # Errors & warnings
    errors: list[ScanErrorOut] = Field(default_factory=list)
    warnings: list[ScanWarningOut] = Field(default_factory=list)
