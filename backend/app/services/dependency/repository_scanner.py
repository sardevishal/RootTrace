"""
services/dependency/repository_scanner.py

Responsible for:
  - Validating the repository path
  - Preventing path traversal attacks
  - Recursively listing all files in the repository
  - Returning a safe, filtered file list for manifest detection

Security:
  - All paths are resolved to absolute paths before use.
  - Symlinks are followed only if they remain within the repository root.
  - Maximum recursion depth is enforced.
  - The repository path must be a directory that exists.
"""

import os
from typing import Optional
from app.utils.logger import get_logger
from app.utils.constants import MAX_SCAN_DEPTH

logger = get_logger(__name__)

# Directories to skip during scanning (version control, build artifacts, etc.)
_SKIP_DIRS = {
    ".git",
    ".svn",
    ".hg",
    ".bzr",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".tox",
    ".eggs",
    "dist",
    "build",
    "target",           # Maven
    ".gradle",          # Gradle
    "vendor",           # Go
    ".vendor",
    "venv",
    ".venv",
    "env",
    ".env",
    ".idea",
    ".vscode",
    ".DS_Store",
    "*.egg-info",
    ".cache",
}


class RepositoryScanner:
    """
    Validates and recursively scans a repository directory.

    Returns a list of (relative_path, absolute_path) tuples for all
    regular files within the repository, up to MAX_SCAN_DEPTH levels deep.
    """

    def __init__(self, max_depth: int = MAX_SCAN_DEPTH) -> None:
        self._max_depth = max_depth

    def scan(self, repository_path: str) -> list[tuple[str, str]]:
        """
        Validate and recursively scan a repository directory.

        Args:
            repository_path: Path to the repository root (may be relative or absolute).

        Returns:
            List of (relative_path, absolute_path) tuples for all scanned files.

        Raises:
            ValueError:      If the path is invalid, empty, or fails security checks.
            FileNotFoundError: If the path does not exist.
            NotADirectoryError: If the path is not a directory.
        """
        abs_root = self._validate_path(repository_path)
        logger.info("RepositoryScanner | Scanning: %s", abs_root)

        files: list[tuple[str, str]] = []
        self._walk(abs_root, abs_root, depth=0, files=files)

        logger.info(
            "RepositoryScanner | Found %d files in %s",
            len(files),
            abs_root,
        )
        return files

    def _validate_path(self, repository_path: str) -> str:
        """
        Validate and resolve the repository path.

        Returns the resolved absolute path.

        Raises:
            ValueError, FileNotFoundError, NotADirectoryError
        """
        if not repository_path or not repository_path.strip():
            raise ValueError("Repository path must not be empty.")

        # Resolve to absolute path
        abs_path = os.path.realpath(os.path.abspath(repository_path.strip()))

        if not os.path.exists(abs_path):
            raise FileNotFoundError(
                f"Repository path does not exist: {abs_path}"
            )

        if not os.path.isdir(abs_path):
            raise NotADirectoryError(
                f"Repository path is not a directory: {abs_path}"
            )

        # Basic path traversal check: resolved path must not contain ".."
        # (realpath already resolves this, but we double-check)
        if ".." in abs_path.split(os.sep):
            raise ValueError(
                f"Path traversal detected in repository path: {repository_path}"
            )

        return abs_path

    def _walk(
        self,
        root: str,
        current_dir: str,
        depth: int,
        files: list[tuple[str, str]],
    ) -> None:
        """
        Recursively walk a directory and collect file paths.

        Args:
            root:        The repository root (used for computing relative paths).
            current_dir: The current directory being walked.
            depth:       Current recursion depth.
            files:       Accumulator list of (relative_path, absolute_path).
        """
        if depth > self._max_depth:
            logger.warning(
                "RepositoryScanner | Max depth %d reached at: %s",
                self._max_depth,
                current_dir,
            )
            return

        try:
            entries = os.scandir(current_dir)
        except PermissionError:
            logger.warning(
                "RepositoryScanner | Permission denied: %s",
                current_dir,
            )
            return
        except OSError as exc:
            logger.warning(
                "RepositoryScanner | OS error scanning %s: %s",
                current_dir,
                exc,
            )
            return

        for entry in entries:
            try:
                if entry.is_dir(follow_symlinks=False):
                    # Skip known non-source directories
                    if entry.name in _SKIP_DIRS:
                        continue
                    # Skip hidden directories (except .github, etc. if needed)
                    if entry.name.startswith("."):
                        continue

                    # Symlink safety: ensure resolved path stays within root
                    if entry.is_symlink():
                        real = os.path.realpath(entry.path)
                        if not real.startswith(root):
                            logger.warning(
                                "RepositoryScanner | Symlink escapes root, skipping: %s",
                                entry.path,
                            )
                            continue

                    self._walk(root, entry.path, depth + 1, files)

                elif entry.is_file(follow_symlinks=False):
                    relative = os.path.relpath(entry.path, root)
                    # Normalize to forward slashes
                    relative = relative.replace(os.sep, "/")
                    files.append((relative, entry.path))

            except OSError as exc:
                logger.warning(
                    "RepositoryScanner | Cannot access %s: %s",
                    entry.path,
                    exc,
                )
