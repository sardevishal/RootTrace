"""
models/dependency.py

Canonical Pydantic model for a single dependency discovered during repository analysis.

This is the internal domain object for the Dependency Analysis Engine.
All parsers produce ParsedDependency objects; the normalizer converts
them into Dependency objects.

The Dependency object is the stable unit consumed by:
  - GraphBuilder
  - DependencyAnalysisService
  - (adapter) → VulnerabilityEngine via Package

Version semantics:
  - version_spec: the raw specifier from the manifest ("^4.17.0", ">=2.0", "5.3.20")
  - version:      the resolved/exact version, or None if not resolved

Never store None in version_spec when a spec exists in the manifest.
Never fabricate a version value when resolution did not occur.
"""

from typing import Optional, Any
from pydantic import BaseModel, Field


class Dependency(BaseModel):
    """
    Canonical dependency record produced by the Dependency Analysis Engine.

    Covers all five supported ecosystems:
    npm, PyPI, Maven, Go, Dockerfile (mixed)
    """

    # ── Identity ──────────────────────────────────────────────────────────────
    id: str = Field(
        ...,
        description=(
            "Globally unique dependency ID within this scan. "
            "Format: '<ecosystem>:<name>@<version or version_spec>'. "
            "Example: 'npm:lodash@4.17.15'"
        ),
    )
    name: str = Field(
        ...,
        description="Package name as declared in the manifest.",
    )

    # ── Version ───────────────────────────────────────────────────────────────
    version: Optional[str] = Field(
        default=None,
        description=(
            "Resolved/exact version string (e.g. '4.17.15'). "
            "None if exact version is not known (only a range was declared "
            "and no lockfile resolved it)."
        ),
    )
    version_spec: Optional[str] = Field(
        default=None,
        description=(
            "Raw version specifier from the manifest "
            "(e.g. '^4.17.0', '>=2.0', '~=4.2', 'v1.2.3'). "
            "Preserved for downstream vulnerability matching."
        ),
    )

    # ── Ecosystem ─────────────────────────────────────────────────────────────
    ecosystem: str = Field(
        ...,
        description=(
            "Canonical ecosystem name: npm / PyPI / Maven / Go / "
            "RubyGems / NuGet / crates.io / apt / apk / mixed / unknown."
        ),
    )

    # ── Dependency Classification ─────────────────────────────────────────────
    dependency_type: str = Field(
        default="runtime",
        description=(
            "How the package is declared: runtime / development / "
            "optional / peer / indirect / build / provided / test / "
            "system / unknown."
        ),
    )
    direct: bool = Field(
        default=True,
        description="True if declared directly in a manifest (not pulled in by another package).",
    )
    transitive: bool = Field(
        default=False,
        description="True if pulled in by another dependency, not directly declared.",
    )
    depth: int = Field(
        default=0,
        ge=0,
        description=(
            "Depth in the dependency tree. 0 = root/application level. "
            "1 = direct dependency. 2+ = transitive."
        ),
    )

    # ── Source Tracking ───────────────────────────────────────────────────────
    source_manifest: str = Field(
        ...,
        description="Manifest file type that declared this dependency (e.g. 'package.json').",
    )
    source_path: str = Field(
        ...,
        description="Relative path to the manifest file within the repository.",
    )

    # ── Relationship ──────────────────────────────────────────────────────────
    parent_ids: list[str] = Field(
        default_factory=list,
        description="IDs of parent Dependency objects that depend on this one.",
    )
    child_ids: list[str] = Field(
        default_factory=list,
        description="IDs of Dependency objects that this one depends on.",
    )

    # ── Maven-Specific ────────────────────────────────────────────────────────
    group_id: Optional[str] = Field(
        default=None,
        description="Maven groupId (e.g. 'org.springframework').",
    )
    artifact_id: Optional[str] = Field(
        default=None,
        description="Maven artifactId (e.g. 'spring-core').",
    )
    maven_scope: Optional[str] = Field(
        default=None,
        description="Maven dependency scope (compile, test, provided, runtime, system).",
    )

    # ── Go-Specific ───────────────────────────────────────────────────────────
    go_indirect: bool = Field(
        default=False,
        description="True if this is an indirect dependency as marked in go.mod.",
    )
    go_module_path: Optional[str] = Field(
        default=None,
        description="Full Go module path (e.g. 'github.com/example/pkg').",
    )

    # ── Dockerfile-Specific ───────────────────────────────────────────────────
    dockerfile_line: Optional[int] = Field(
        default=None,
        description="Line number in the Dockerfile where this dependency was detected.",
    )
    dockerfile_command: Optional[str] = Field(
        default=None,
        description="The installation command that revealed this dependency (e.g. 'RUN pip install ...').",
    )

    # ── Generic Metadata ──────────────────────────────────────────────────────
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Ecosystem-specific or parser-specific additional metadata.",
    )

    model_config = {"str_strip_whitespace": True}

    def normalized(self) -> dict:
        """
        Return the minimal downstream-compatible representation.

        This is the format consumed by the Vulnerability Intelligence Engine.

        Returns:
            dict with keys: package_name, version, ecosystem
        """
        return {
            "package_name": self.name,
            "version": self.version,
            "ecosystem": self.ecosystem,
        }
