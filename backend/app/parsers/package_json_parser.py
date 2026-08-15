"""
parsers/package_json_parser.py

Parser for npm package.json manifests.

Handles:
  - dependencies        → runtime
  - devDependencies     → development
  - optionalDependencies → optional
  - peerDependencies    → peer

Also reads package-lock.json (v1/v2/v3) when available to resolve
exact versions from version range specifiers.

Version semantics:
  - version_spec: the range string from package.json  ("^4.17.0")
  - version:      the resolved version from lock file  ("4.17.15")
                  or None if no lock file was found

Does NOT execute npm or any scripts.
Does NOT install packages.
"""

import json
from typing import Optional
from app.parsers.base import BaseParser, ParsedDependency
from app.models.manifest import ManifestInfo
from app.utils.logger import get_logger

logger = get_logger(__name__)

# Mapping from package.json section → dependency_type
_SECTION_TYPE_MAP = {
    "dependencies": "runtime",
    "devDependencies": "development",
    "optionalDependencies": "optional",
    "peerDependencies": "peer",
}


class PackageJsonParser(BaseParser):
    """
    Parser for npm package.json manifests.

    Reads up to four dependency sections and optionally resolves
    versions from a co-located package-lock.json.
    """

    @property
    def supported_manifest_type(self) -> str:
        return "package.json"

    def parse(self, manifest: ManifestInfo) -> list[ParsedDependency]:
        """
        Parse package.json and (optionally) package-lock.json.

        Returns:
            List of ParsedDependency objects — one per declared dependency.
        """
        logger.info("PackageJsonParser | Parsing: %s", manifest.path)

        content = self._read_file(manifest.absolute_path)

        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Invalid JSON in {manifest.path}: {exc}"
            ) from exc

        if not isinstance(data, dict):
            raise ValueError(
                f"package.json must be a JSON object, got {type(data).__name__}: {manifest.path}"
            )

        # ── Load lockfile resolved versions if available ───────────────────
        resolved: dict[str, str] = {}
        if manifest.has_lockfile and manifest.lockfile_absolute_path:
            resolved = self._load_lock_resolved(manifest.lockfile_absolute_path, manifest.lockfile_path or "")

        # ── Parse each dependency section ─────────────────────────────────
        results: list[ParsedDependency] = []

        for section, dep_type in _SECTION_TYPE_MAP.items():
            section_data = data.get(section)
            if not section_data or not isinstance(section_data, dict):
                continue

            for pkg_name, version_spec in section_data.items():
                pkg_name = pkg_name.strip()
                if not pkg_name:
                    continue

                # version_spec may be a URL, git ref, "file:...", etc.
                raw_spec = str(version_spec).strip() if version_spec else None

                # Only treat pure semver ranges as version specs
                cleaned_spec = _clean_version_spec(raw_spec)
                exact_version = resolved.get(pkg_name)

                results.append(ParsedDependency(
                    name=pkg_name,
                    ecosystem="npm",
                    source_manifest="package.json",
                    source_path=manifest.path,
                    version=exact_version,
                    version_spec=cleaned_spec,
                    dependency_type=dep_type,
                    metadata={"raw_version_spec": raw_spec},
                ))

        logger.info(
            "PackageJsonParser | Found %d dependencies in %s",
            len(results),
            manifest.path,
        )
        return results

    def _load_lock_resolved(self, lockfile_path: str, relative_path: str) -> dict[str, str]:
        """
        Parse package-lock.json and return a mapping of package_name → resolved_version.

        Supports lockfile formats v1, v2, and v3.

        Args:
            lockfile_path: Absolute path to package-lock.json.
            relative_path: Relative path (for logging only).

        Returns:
            dict mapping package name → exact resolved version string.
        """
        resolved: dict[str, str] = {}

        try:
            content = self._read_file(lockfile_path)
            data = json.loads(content)
        except (FileNotFoundError, json.JSONDecodeError, OSError) as exc:
            logger.warning(
                "PackageJsonParser | Could not read lockfile %s — %s",
                relative_path,
                exc,
            )
            return resolved

        lock_version = data.get("lockfileVersion", 1)

        if lock_version in (2, 3):
            # v2/v3: use "packages" field
            packages = data.get("packages", {})
            for key, val in packages.items():
                if not isinstance(val, dict):
                    continue
                # Key format: "node_modules/lodash" or "node_modules/a/node_modules/b"
                if key.startswith("node_modules/"):
                    pkg_name = key.split("node_modules/")[-1]
                    version = val.get("version")
                    if pkg_name and version:
                        resolved[pkg_name] = version

        # v1 (and v2 fallback): use "dependencies" field
        deps_v1 = data.get("dependencies", {})
        if isinstance(deps_v1, dict):
            for pkg_name, val in deps_v1.items():
                if isinstance(val, dict) and "version" in val:
                    # Don't overwrite a v2/v3 entry
                    resolved.setdefault(pkg_name, val["version"])

        logger.debug(
            "PackageJsonParser | Lockfile v%s resolved %d packages from %s",
            lock_version,
            len(resolved),
            relative_path,
        )
        return resolved


def _clean_version_spec(raw: Optional[str]) -> Optional[str]:
    """
    Return the version spec only if it looks like a semver range.
    Returns None for git URLs, file: paths, or other non-semver specs.

    We preserve the raw_version_spec in metadata for full fidelity.
    """
    if raw is None:
        return None

    lower = raw.lower()

    # Non-semver patterns — treat as None for version matching purposes
    skip_prefixes = ("http://", "https://", "git+", "git://", "github:", "file:", "link:")
    if any(lower.startswith(p) for p in skip_prefixes):
        return None

    # Common semver range prefixes are fine
    return raw
