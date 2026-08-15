"""
models/manifest.py

Pydantic model representing a discovered manifest file within a repository.

A manifest is any file that declares software dependencies:
  - package.json      (npm)
  - requirements.txt  (PyPI)
  - pom.xml           (Maven)
  - go.mod            (Go)
  - Dockerfile        (mixed — static detection only)
"""

from typing import Optional
from pydantic import BaseModel, Field


class ManifestInfo(BaseModel):
    """
    Metadata record for a single manifest discovered in a repository.

    Produced by ManifestDetector.
    Consumed by the parser selection logic in DependencyAnalysisEngine.
    """

    path: str = Field(
        ...,
        description=(
            "Path to the manifest relative to the repository root. "
            "Example: 'frontend/package.json'"
        ),
    )
    absolute_path: str = Field(
        ...,
        description="Absolute filesystem path to the manifest file.",
    )
    manifest_type: str = Field(
        ...,
        description=(
            "Canonical manifest type identifier. "
            "One of: package.json / requirements.txt / pom.xml / go.mod / Dockerfile"
        ),
    )
    ecosystem: str = Field(
        ...,
        description="Primary ecosystem associated with this manifest type.",
    )
    size_bytes: Optional[int] = Field(
        default=None,
        description="File size in bytes.",
    )
    has_lockfile: bool = Field(
        default=False,
        description="True if a corresponding lockfile was detected alongside this manifest.",
    )
    lockfile_path: Optional[str] = Field(
        default=None,
        description="Relative path to the lockfile if found (e.g. 'frontend/package-lock.json').",
    )
    lockfile_absolute_path: Optional[str] = Field(
        default=None,
        description="Absolute path to the lockfile.",
    )

    model_config = {"str_strip_whitespace": True}
