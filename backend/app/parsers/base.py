"""
parsers/base.py

Abstract base class for all manifest parsers.

Every parser:
  1. Accepts a ManifestInfo object
  2. Reads the manifest file from disk (static analysis only — no execution)
  3. Returns a list of ParsedDependency objects

ParsedDependency is a lightweight intermediate data class.
The DependencyNormalizer converts it into a full Dependency model.

Security contract:
  - Parsers must NEVER execute any code from the repository.
  - Parsers must NEVER spawn subprocesses.
  - Parsers must NEVER make network requests.
  - Parsers operate only on file content read via standard I/O.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, Any

from app.models.manifest import ManifestInfo


@dataclass
class ParsedDependency:
    """
    Lightweight intermediate result from a parser.

    The normalizer converts this into a canonical Dependency model.
    Fields use native Python types for simplicity (no Pydantic overhead
    during parsing).
    """

    # Required
    name: str
    ecosystem: str
    source_manifest: str
    source_path: str

    # Version (may be None — never fabricate)
    version: Optional[str] = None
    version_spec: Optional[str] = None

    # Classification
    dependency_type: str = "runtime"

    # Maven-specific
    group_id: Optional[str] = None
    artifact_id: Optional[str] = None
    maven_scope: Optional[str] = None

    # Go-specific
    go_indirect: bool = False
    go_module_path: Optional[str] = None

    # Dockerfile-specific
    dockerfile_line: Optional[int] = None
    dockerfile_command: Optional[str] = None

    # Extra metadata
    metadata: dict[str, Any] = field(default_factory=dict)

    def display_name(self) -> str:
        """Human-readable identifier for logging."""
        ver = self.version or self.version_spec or "?"
        return f"{self.ecosystem}:{self.name}@{ver}"


class BaseParser(ABC):
    """
    Abstract base for all manifest parsers.

    Subclasses implement parse() for a specific manifest type.
    Parsers are stateless — create one instance and call parse() multiple times.
    """

    @property
    @abstractmethod
    def supported_manifest_type(self) -> str:
        """
        Return the manifest type this parser handles.
        Must match one of SUPPORTED_MANIFEST_TYPES.
        Example: "package.json"
        """

    @abstractmethod
    def parse(self, manifest: ManifestInfo) -> list[ParsedDependency]:
        """
        Parse a manifest file and return its direct dependency declarations.

        Args:
            manifest: ManifestInfo describing the file to parse.

        Returns:
            List of ParsedDependency objects.
            Returns an empty list (not raises) if the file is empty or has no deps.

        Raises:
            ValueError:  If the file content is fundamentally malformed
                         (e.g. invalid JSON, invalid XML).
            FileNotFoundError: If the file does not exist.
            PermissionError:   If the file cannot be read.

        Security:
            Must not execute any code. Must not spawn subprocesses.
            Must not make network requests.
        """

    def _read_file(self, path: str) -> str:
        """
        Safely read a file as UTF-8 text.
        Falls back to latin-1 if UTF-8 decoding fails.

        Args:
            path: Absolute path to the file.

        Returns:
            File content as a string.

        Raises:
            FileNotFoundError, PermissionError, OSError
        """
        try:
            with open(path, "r", encoding="utf-8") as f:
                return f.read()
        except UnicodeDecodeError:
            with open(path, "r", encoding="latin-1") as f:
                return f.read()
