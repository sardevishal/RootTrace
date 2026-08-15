"""
models/dependency_scan.py

Pydantic model for the complete result produced by one execution of
the Dependency Analysis Engine.

This is the top-level output object returned by:
    DependencyAnalysisEngine.analyze(repository_path)

It contains:
  - scan identity and status
  - all discovered manifests
  - all parsed and normalized dependencies (flat list)
  - the dependency graph
  - downstream-compatible normalized package inventory
  - errors and warnings encountered during the scan
"""

from typing import Optional, Any
from pydantic import BaseModel, Field

from app.models.dependency import Dependency
from app.models.dependency_graph import DependencyGraph
from app.models.manifest import ManifestInfo


class ScanError(BaseModel):
    """A single structured error record from the dependency scan."""

    path: Optional[str] = Field(
        default=None,
        description="File or resource path where the error occurred.",
    )
    error_type: str = Field(
        default="unknown_error",
        description=(
            "Machine-readable error type: "
            "parse_error / file_not_found / permission_error / "
            "path_traversal / unsupported_manifest / unknown_error"
        ),
    )
    message: str = Field(
        ...,
        description="Human-readable error description.",
    )
    ecosystem: Optional[str] = Field(
        default=None,
        description="Ecosystem associated with the error, if applicable.",
    )


class ScanWarning(BaseModel):
    """A single structured warning from the dependency scan."""

    path: Optional[str] = Field(
        default=None,
        description="File or resource path associated with this warning.",
    )
    warning_type: str = Field(
        default="general",
        description="Machine-readable warning type.",
    )
    message: str = Field(
        ...,
        description="Human-readable warning description.",
    )


class NormalizedPackage(BaseModel):
    """
    Minimal downstream-compatible package representation.

    This is the format consumed by the Vulnerability Intelligence Engine.
    See: VulnerabilityEngine.run_scan(packages=[...])

    IMPORTANT: version may be None when only a version_spec was available.
    The VulnerabilityEngine adapter must handle None → 'unknown' conversion.
    """

    package_name: str
    version: Optional[str] = None
    version_spec: Optional[str] = None
    ecosystem: str
    dependency_id: Optional[str] = None
    scan_id: Optional[str] = None


class DependencyScanResult(BaseModel):
    """
    Complete output of one Dependency Analysis Engine execution.

    Produced by DependencyAnalysisEngine.analyze(repository_path).
    """

    # ── Scan Identity ─────────────────────────────────────────────────────────
    scan_id: Optional[str] = Field(
        default=None,
        description="Unique identifier for this scan run.",
    )
    repository_path: str = Field(
        ...,
        description="The repository path that was analyzed.",
    )
    repository_id: Optional[str] = Field(
        default=None,
        description="External repository identifier (future use).",
    )

    # ── Status ────────────────────────────────────────────────────────────────
    status: str = Field(
        default="completed",
        description=(
            "Scan completion status: "
            "completed / completed_with_warnings / failed"
        ),
    )

    # ── Manifests ─────────────────────────────────────────────────────────────
    manifests: list[ManifestInfo] = Field(
        default_factory=list,
        description="All manifest files discovered in the repository.",
    )

    # ── Dependencies ──────────────────────────────────────────────────────────
    dependencies: list[Dependency] = Field(
        default_factory=list,
        description="Flat list of all discovered and normalized dependencies.",
    )

    # ── Graph ─────────────────────────────────────────────────────────────────
    graph: DependencyGraph = Field(
        default_factory=DependencyGraph,
        description="The full dependency graph (nodes + edges + stats).",
    )

    # ── Downstream-Compatible Inventory ───────────────────────────────────────
    normalized_packages: list[NormalizedPackage] = Field(
        default_factory=list,
        description=(
            "Minimal downstream-compatible package list. "
            "Directly consumable by the Vulnerability Intelligence Engine."
        ),
    )

    # ── Summary Counts ────────────────────────────────────────────────────────
    total_dependencies: int = Field(default=0, description="Total unique dependencies found.")
    direct_dependencies: int = Field(default=0, description="Count of direct dependencies.")
    transitive_dependencies: int = Field(default=0, description="Count of transitive dependencies.")
    manifests_found: int = Field(default=0, description="Number of manifest files discovered.")
    manifests_parsed: int = Field(default=0, description="Number of manifests successfully parsed.")

    # ── Errors & Warnings ─────────────────────────────────────────────────────
    errors: list[ScanError] = Field(
        default_factory=list,
        description="Structured errors encountered during the scan.",
    )
    warnings: list[ScanWarning] = Field(
        default_factory=list,
        description="Non-fatal warnings encountered during the scan.",
    )

    # ── Metadata ──────────────────────────────────────────────────────────────
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional scan metadata (future use).",
    )
