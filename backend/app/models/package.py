"""
models/package.py

Pydantic model representing a single software package to be scanned.
This is the internal domain object — never pass raw dicts around.
"""

from pydantic import BaseModel, Field, field_validator
from app.utils.constants import SUPPORTED_ECOSYSTEMS


class Package(BaseModel):
    """
    Represents one package entry as received from the mock loader
    (or, in the future, from the Dependency Analysis Engine).
    """

    package_name: str = Field(
        ...,
        min_length=1,
        description="Name of the package (e.g. 'lodash', 'requests').",
    )
    version: str = Field(
        ...,
        min_length=1,
        description="Exact version string (e.g. '4.17.15').",
    )
    ecosystem: str = Field(
        ...,
        description="Package ecosystem (e.g. 'npm', 'PyPI', 'Maven').",
    )

    @field_validator("ecosystem")
    @classmethod
    def ecosystem_must_be_supported(cls, v: str) -> str:
        if v not in SUPPORTED_ECOSYSTEMS:
            raise ValueError(
                f"Unsupported ecosystem '{v}'. "
                f"Supported: {SUPPORTED_ECOSYSTEMS}"
            )
        return v

    @field_validator("package_name", "version")
    @classmethod
    def must_not_be_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Field must not be blank or whitespace only.")
        return v.strip()

    model_config = {"str_strip_whitespace": True}
