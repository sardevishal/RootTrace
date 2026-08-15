"""
schemas/dependency_request.py

API request schemas for the Dependency Analysis Engine endpoints.
"""

from typing import Optional
from pydantic import BaseModel, Field, field_validator
import os


class DependencyAnalysisRequest(BaseModel):
    """
    Request body for POST /api/v1/dependencies/analyze

    Specifies the repository to analyze and optional scan parameters.
    """

    repository_path: str = Field(
        ...,
        description=(
            "Absolute or relative path to the repository root directory. "
            "The directory must exist and be readable."
        ),
        examples=["/home/user/myproject", "./myproject", "C:/Projects/myapp"],
    )
    scan_id: Optional[str] = Field(
        default=None,
        description=(
            "Optional scan identifier. If not provided, a UUID will be generated. "
            "Use this to correlate scans with external systems."
        ),
        examples=["scan-2024-001", "abc123"],
    )
    repository_id: Optional[str] = Field(
        default=None,
        description=(
            "Optional external repository identifier "
            "(e.g. GitHub repo ID, internal project ID)."
        ),
        examples=["github:myorg/myrepo", "project-42"],
    )
    include_dev_dependencies: bool = Field(
        default=True,
        description=(
            "If True, include development dependencies (devDependencies, test scope). "
            "Default: True."
        ),
    )

    @field_validator("repository_path")
    @classmethod
    def validate_repository_path(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("repository_path must not be empty.")
        return v

    model_config = {"str_strip_whitespace": True}
