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

        resolved, transitive_deps = {}, []
        if manifest.has_lockfile and manifest.lockfile_absolute_path:
            resolved, transitive_deps = self._load_lock_full(manifest.lockfile_absolute_path, manifest.lockfile_path or "", manifest.path)

        # ── Parse each dependency section ─────────────────────────────────
        results: list[ParsedDependency] = []

        direct_names = set()
        for section, dep_type in _SECTION_TYPE_MAP.items():
            section_data = data.get(section)
            if not section_data or not isinstance(section_data, dict):
                continue

            for pkg_name, version_spec in section_data.items():
                pkg_name = pkg_name.strip()
                if not pkg_name:
                    continue

                direct_names.add(pkg_name)
                # version_spec may be a URL, git ref, "file:...", etc.
                raw_spec = str(version_spec).strip() if version_spec else None

                # Only treat pure semver ranges as version specs
                cleaned_spec = _clean_version_spec(raw_spec)
                exact_version = resolved.get(pkg_name)
                
                # If no lockfile, and cleaned_spec is a strict version (no range chars)
                if exact_version is None and cleaned_spec:
                    if not any(c in cleaned_spec for c in "^~><*x|"):
                        exact_version = cleaned_spec

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

        # Add transitive dependencies
        for t_dep in transitive_deps:
            if t_dep.name not in direct_names:
                results.append(t_dep)

        logger.info(
            "PackageJsonParser | Found %d dependencies in %s",
            len(results),
            manifest.path,
        )
        return results

    def _load_lock_full(self, lockfile_path: str, relative_path: str, manifest_path: str) -> tuple[dict[str, str], list[ParsedDependency]]:
        resolved: dict[str, str] = {}
        transitive_deps: list[ParsedDependency] = []

        try:
            content = self._read_file(lockfile_path)
            data = json.loads(content)
        except Exception as exc:
            logger.warning("PackageJsonParser | Could not read lockfile %s — %s", relative_path, exc)
            return resolved, transitive_deps

        lock_version = data.get("lockfileVersion", 1)

        # Process v1 "dependencies" tree for full transitive graph (also included in v2)
        deps_tree = data.get("dependencies", {})
        
        def _traverse(node: dict, parent_id: Optional[str] = None):
            for pkg_name, val in node.items():
                if not isinstance(val, dict):
                    continue
                version = val.get("version")
                if not version:
                    continue
                
                # Deduplicate and build basic parent mapping (simple version for Phase 2B)
                resolved.setdefault(pkg_name, version)
                
                dep_id = f"npm:{pkg_name}@{version}"
                parents = [parent_id] if parent_id else []
                
                t_dep = ParsedDependency(
                    name=pkg_name,
                    ecosystem="npm",
                    source_manifest="package.json",
                    source_path=manifest_path,
                    version=version,
                    dependency_type="indirect",
                    metadata={"parents": parents}
                )
                transitive_deps.append(t_dep)
                
                if "dependencies" in val:
                    _traverse(val["dependencies"], dep_id)

        _traverse(deps_tree)

        # For v2/v3 fallback to get resolved versions if dependencies tree is missing
        if lock_version in (2, 3) and not deps_tree:
            packages = data.get("packages", {})
            for key, val in packages.items():
                if isinstance(val, dict) and key.startswith("node_modules/"):
                    pkg_name = key.split("node_modules/")[-1]
                    version = val.get("version")
                    if pkg_name and version:
                        resolved[pkg_name] = version

        return resolved, transitive_deps


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
