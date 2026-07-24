"""
schemas/package_schema.py

FastAPI-facing request/input schemas for package data.
These are separate from the domain model (models/package.py) so that
API validation and internal representation can evolve independently.
"""

from pydantic import BaseModel, Field, field_validator
from app.utils.constants import SUPPORTED_ECOSYSTEMS


class PackageInput(BaseModel):
    """
    Schema for a single package entry submitted via API request body
    (future use: POST /api/v1/scan) or read from mock_data/packages.json.
    """

    package_name: str = Field(
        ...,
        min_length=1,
        description="Name of the package.",
        examples=["lodash", "requests", "log4j-core"],
    )
    version: str = Field(
        ...,
        min_length=1,
        description="Exact version string.",
        examples=["4.17.15", "2.25.0"],
    )
    ecosystem: str = Field(
        ...,
        description=f"Package ecosystem. Supported: {SUPPORTED_ECOSYSTEMS}",
        examples=["npm", "PyPI", "Maven"],
    )

    @field_validator("ecosystem")
    @classmethod
    def validate_ecosystem(cls, v: str) -> str:
        if v not in SUPPORTED_ECOSYSTEMS:
            raise ValueError(
                f"Ecosystem '{v}' is not supported. "
                f"Choose from: {SUPPORTED_ECOSYSTEMS}"
            )
        return v

    @field_validator("package_name", "version")
    @classmethod
    def strip_and_check_blank(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("This field must not be blank.")
        return v

    model_config = {"str_strip_whitespace": True}


class PackageBatchInput(BaseModel):
    """
    Schema for submitting multiple packages in one request (future POST endpoint).
    """

    packages: list[PackageInput] = Field(
        ...,
        min_length=1,
        description="List of packages to scan.",
    )
