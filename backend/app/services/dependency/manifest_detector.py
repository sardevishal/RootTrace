"""
services/dependency/manifest_detector.py

Identifies manifest files from a list of repository files.

Supports the five project-defined manifest types:
  - package.json      (npm)
  - requirements.txt  (PyPI)
  - pom.xml           (Maven)
  - go.mod            (Go)
  - Dockerfile        (mixed)

Also detects associated lockfiles:
  - package-lock.json (npm lockfile v1/v2/v3)
  - yarn.lock         (Yarn lockfile — detected but not parsed for now)

Designed for monorepository structures — multiple manifests of the
same type at different paths are all detected.
"""

import os
from app.models.manifest import ManifestInfo
from app.utils.constants import MANIFEST_ECOSYSTEM_MAP, SUPPORTED_MANIFEST_TYPES
from app.utils.logger import get_logger

logger = get_logger(__name__)

# Supported lockfile names and which manifest they correspond to
_LOCKFILE_MAP = {
    "package-lock.json": "package.json",
    "yarn.lock": "package.json",
    "npm-shrinkwrap.json": "package.json",
}


class ManifestDetector:
    """
    Scans a file list (from RepositoryScanner) and identifies all
    supported manifest files and their associated lockfiles.
    """

    def detect(
        self,
        files: list[tuple[str, str]],
        root_path: str,
    ) -> list[ManifestInfo]:
        """
        Detect all supported manifest files and their lockfiles.

        Args:
            files:      List of (relative_path, absolute_path) from RepositoryScanner.
            root_path:  Absolute repository root path (used to compute lockfile paths).

        Returns:
            List of ManifestInfo objects, one per detected manifest.
        """
        logger.info("ManifestDetector | Scanning %d files for manifests", len(files))

        # Build a quick lookup: directory → lockfiles present
        # Key: directory (relative), Value: dict of lockfile_name → absolute_path
        dir_lockfiles: dict[str, dict[str, str]] = {}

        # Also build a set of all relative paths for fast lookup
        all_relative: set[str] = {rel for rel, _ in files}

        for rel_path, abs_path in files:
            filename = os.path.basename(rel_path)
            directory = os.path.dirname(rel_path)

            if filename in _LOCKFILE_MAP:
                if directory not in dir_lockfiles:
                    dir_lockfiles[directory] = {}
                dir_lockfiles[directory][filename] = abs_path

        # Now detect manifests
        manifests: list[ManifestInfo] = []

        for rel_path, abs_path in files:
            filename = os.path.basename(rel_path)
            directory = os.path.dirname(rel_path)

            if filename not in SUPPORTED_MANIFEST_TYPES:
                continue

            manifest_type = filename
            ecosystem = MANIFEST_ECOSYSTEM_MAP.get(manifest_type, "unknown")

            # Check for lockfile in the same directory
            lockfile_found = False
            lockfile_rel: str | None = None
            lockfile_abs: str | None = None

            dir_locks = dir_lockfiles.get(directory, {})
            # For package.json: check for package-lock.json, yarn.lock, npm-shrinkwrap.json
            if manifest_type == "package.json":
                for lock_name in ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock"):
                    if lock_name in dir_locks:
                        lockfile_found = True
                        lockfile_abs = dir_locks[lock_name]
                        lockfile_rel = os.path.join(directory, lock_name).replace(os.sep, "/")
                        if lockfile_rel.startswith("/"):
                            lockfile_rel = lockfile_rel[1:]
                        break

            try:
                size = os.path.getsize(abs_path)
            except OSError:
                size = None

            manifest = ManifestInfo(
                path=rel_path,
                absolute_path=abs_path,
                manifest_type=manifest_type,
                ecosystem=ecosystem,
                size_bytes=size,
                has_lockfile=lockfile_found,
                lockfile_path=lockfile_rel,
                lockfile_absolute_path=lockfile_abs,
            )
            manifests.append(manifest)

            logger.debug(
                "ManifestDetector | Found: %s (%s)%s",
                rel_path,
                ecosystem,
                " [has lockfile]" if lockfile_found else "",
            )

        logger.info(
            "ManifestDetector | Detected %d manifest(s) from %d files",
            len(manifests),
            len(files),
        )
        return manifests
