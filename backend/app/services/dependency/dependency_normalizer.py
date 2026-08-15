"""
services/dependency/dependency_normalizer.py

Converts raw ParsedDependency objects (from parsers) into canonical
Dependency model instances.

Responsibilities:
  - Normalize ecosystem names to canonical form
  - Generate stable dependency IDs
  - Deduplicate dependencies across manifests
  - Validate and clean names and versions
  - Apply ecosystem-specific normalization rules
    (e.g., npm package name casing, PyPI package name normalization)
"""

import re
from typing import Optional

from app.parsers.base import ParsedDependency
from app.models.dependency import Dependency
from app.utils.constants import ECOSYSTEM_ALIAS_MAP
from app.utils.logger import get_logger

logger = get_logger(__name__)


def _normalize_ecosystem(raw: str) -> str:
    """
    Convert a raw ecosystem string to canonical form.

    Examples:
      "pypi" → "PyPI"
      "python" → "PyPI"
      "npm" → "npm"
      "maven" → "Maven"
    """
    lower = raw.strip().lower()
    return ECOSYSTEM_ALIAS_MAP.get(lower, raw.strip())


def _build_dependency_id(name: str, version: Optional[str], version_spec: Optional[str], ecosystem: str) -> str:
    """
    Build a stable, unique dependency ID string.

    Format: "<ecosystem>:<name>@<version_or_spec>"

    If both version and version_spec are None, use "unresolved".
    """
    ver_part = version or version_spec or "unresolved"
    # Sanitize for use in IDs (remove chars problematic in URLs/filenames)
    safe_name = re.sub(r"[^\w:@./+-]", "_", name)
    safe_ver = re.sub(r"[^\w.^~>=<!@*-]", "_", ver_part)
    return f"{ecosystem}:{safe_name}@{safe_ver}"


def _normalize_npm_name(name: str) -> str:
    """npm package names are case-sensitive but conventionally lowercase."""
    return name.strip()


def _normalize_pypi_name(name: str) -> str:
    """
    Normalize PyPI package names per PEP 508.
    Replace [-_.] sequences with a single hyphen and lowercase.
    """
    return re.sub(r"[-_.]+", "-", name.strip()).lower()


def _normalize_name(name: str, ecosystem: str) -> str:
    """Apply ecosystem-specific name normalization."""
    if ecosystem == "PyPI":
        return _normalize_pypi_name(name)
    if ecosystem == "npm":
        return _normalize_npm_name(name)
    return name.strip()


class DependencyNormalizer:
    """
    Converts ParsedDependency objects into canonical Dependency models.

    A single instance can be reused across multiple manifests.
    """

    def normalize(self, parsed: ParsedDependency) -> Optional[Dependency]:
        """
        Normalize a single ParsedDependency into a Dependency model.

        Returns:
            A Dependency instance, or None if normalization fails
            (e.g., the package name is empty after cleaning).
        """
        # Normalize ecosystem
        ecosystem = _normalize_ecosystem(parsed.ecosystem)

        # Normalize name
        name = _normalize_name(parsed.name, ecosystem)
        if not name:
            logger.warning(
                "DependencyNormalizer | Empty name after normalization, skipping: %r",
                parsed,
            )
            return None

        # Build ID
        dep_id = _build_dependency_id(name, parsed.version, parsed.version_spec, ecosystem)

        try:
            dep = Dependency(
                id=dep_id,
                name=name,
                version=parsed.version,
                version_spec=parsed.version_spec,
                ecosystem=ecosystem,
                dependency_type=parsed.dependency_type,
                direct=True,      # All parsed deps are direct by default
                transitive=False, # Transitive analysis happens later
                depth=0,          # Depth set by TransitiveAnalyzer
                source_manifest=parsed.source_manifest,
                source_path=parsed.source_path,
                group_id=parsed.group_id,
                artifact_id=parsed.artifact_id,
                maven_scope=parsed.maven_scope,
                go_indirect=parsed.go_indirect,
                go_module_path=parsed.go_module_path,
                dockerfile_line=parsed.dockerfile_line,
                dockerfile_command=parsed.dockerfile_command,
                metadata=parsed.metadata or {},
            )
        except Exception as exc:
            logger.warning(
                "DependencyNormalizer | Failed to create Dependency for %r: %s",
                parsed.display_name(),
                exc,
            )
            return None

        return dep

    def normalize_all(
        self,
        parsed_list: list[ParsedDependency],
    ) -> tuple[list[Dependency], list[str]]:
        """
        Normalize a list of ParsedDependency objects.

        Handles deduplication: if the same (id) appears more than once,
        the first occurrence is kept.

        Args:
            parsed_list: Raw ParsedDependency objects from parsers.

        Returns:
            Tuple of:
              - List of unique, normalized Dependency objects
              - List of warning messages for any skipped/failed entries
        """
        seen_ids: set[str] = set()
        results: list[Dependency] = []
        warnings: list[str] = []

        for parsed in parsed_list:
            dep = self.normalize(parsed)
            if dep is None:
                warnings.append(
                    f"Failed to normalize dependency: {parsed.display_name()}"
                )
                continue

            if dep.id in seen_ids:
                logger.debug(
                    "DependencyNormalizer | Deduplicating %s (already seen)",
                    dep.id,
                )
                continue

            seen_ids.add(dep.id)
            results.append(dep)

        logger.info(
            "DependencyNormalizer | Normalized %d dependencies (%d unique, %d warnings)",
            len(parsed_list),
            len(results),
            len(warnings),
        )
        return results, warnings
