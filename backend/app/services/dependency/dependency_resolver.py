"""
services/dependency/dependency_resolver.py

Attempts to resolve version specifiers to exact versions.

Phase 1: Uses lockfile data already captured by parsers.
  - If a dependency's version was resolved by the parser (from lockfile),
    no further resolution is needed.
  - If version is still None, DependencyResolver records this honestly.

Phase 2 (future): May integrate with ecosystem APIs or local caches.

IMPORTANT: This module NEVER fabricates versions.
If a version cannot be resolved statically, it remains None.
Downstream consumers must handle None versions gracefully.

Resolution sources (Phase 1):
  - package-lock.json (via PackageJsonParser)
  - go.mod (direct version declarations)
  - pom.xml (explicit version elements)
  - requirements.txt (==exact_version specifiers)
"""

from typing import Optional
from app.models.dependency import Dependency
from app.utils.logger import get_logger

logger = get_logger(__name__)


class DependencyResolver:
    """
    Attempts to resolve unresolved version specifiers to exact versions.

    Phase 1: Purely static — uses only data already present in the
    Dependency objects (populated by parsers from lockfiles).

    Returns the dependency list unchanged but may add resolution notes
    to metadata.
    """

    def resolve(self, dependencies: list[Dependency]) -> tuple[list[Dependency], list[str]]:
        """
        Attempt to resolve unresolved dependencies.

        Args:
            dependencies: List of Dependency objects from the normalizer.

        Returns:
            Tuple of:
              - Updated dependency list (version fields updated where resolvable)
              - List of informational messages about unresolved dependencies
        """
        resolved_count = 0
        unresolved: list[str] = []

        for dep in dependencies:
            if dep.version is not None:
                # Already resolved by the parser (e.g., from lockfile)
                resolved_count += 1
                continue

            # Phase 1: Try to extract exact version from version_spec
            # Only if the spec is a simple equality
            extracted = self._try_extract_exact(dep.version_spec)
            if extracted is not None:
                dep.version = extracted
                resolved_count += 1
                logger.debug(
                    "DependencyResolver | Resolved %s → %s from spec",
                    dep.id,
                    extracted,
                )
            else:
                unresolved.append(
                    f"{dep.ecosystem}:{dep.name} — version_spec={dep.version_spec!r} (unresolved)"
                )

        logger.info(
            "DependencyResolver | Resolved: %d / %d dependencies. Unresolved: %d",
            resolved_count,
            len(dependencies),
            len(unresolved),
        )

        if unresolved:
            logger.debug(
                "DependencyResolver | Unresolved dependencies:\n%s",
                "\n".join(f"  - {u}" for u in unresolved),
            )

        return dependencies, unresolved

    def _try_extract_exact(self, version_spec: Optional[str]) -> Optional[str]:
        """
        Attempt to extract an exact version from a version specifier.

        Returns the exact version string if:
          - The spec is exactly "==<version>" (PyPI)
          - The spec is exactly "v<version>" or "<version>" (Go-style, Maven)

        Returns None otherwise. Never fabricates a version.
        """
        if version_spec is None:
            return None

        spec = version_spec.strip()

        # PyPI: ==1.2.3
        if spec.startswith("=="):
            candidate = spec[2:].strip()
            if candidate and self._looks_like_version(candidate):
                return candidate

        # Go / Maven: v1.2.3 or 1.2.3 (exact without operators)
        if not any(spec.startswith(op) for op in ("^", "~", ">=", "<=", "!=", ">", "<", "~=")):
            # Remove leading 'v' for Go versions
            candidate = spec.lstrip("v") if spec.startswith("v") else spec
            if candidate and self._looks_like_version(candidate):
                return candidate

        return None

    def _looks_like_version(self, candidate: str) -> bool:
        """
        Check if a string looks like an actual version (not a range, wildcard, or variable).

        A valid version:
          - Contains at least one digit
          - Does not contain operators (^, ~, >, <, !, =)
          - Does not contain shell variables ($)
          - Does not contain wildcards (*)
        """
        if not candidate:
            return False
        if any(c in candidate for c in ("^", "~", ">", "<", "!", "$", "*", "?")):
            return False
        if not any(c.isdigit() for c in candidate):
            return False
        return True
