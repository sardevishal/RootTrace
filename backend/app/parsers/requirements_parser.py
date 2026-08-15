"""
parsers/requirements_parser.py

Parser for Python requirements.txt manifests.

Handles all common pip requirements.txt formats:
  - Exact:         requests==2.31.0
  - Greater-than:  flask>=2.0
  - Compatible:    django~=4.2
  - Less-than:     numpy<2.0
  - Not-equal:     package!=1.0
  - Extras:        package[extra1,extra2]==1.2.3
  - No version:    numpy
  - Comments:      # This is a comment
  - Blank lines
  - Inline comments:  requests==2.31.0  # HTTP library
  - Continuation:   (backslash line continuation — treated as one entry)

Does NOT handle:
  - -r /other/requirements.txt  (recursive includes — not followed)
  - -c constraints.txt          (constraints files — ignored)
  - --index-url, --extra-index-url (index options — ignored)
  - VCS requirements:  git+https://...  (recorded as metadata, version=None)

Does NOT execute pip, setup.py, or any other program.
"""

import re
from typing import Optional
from app.parsers.base import BaseParser, ParsedDependency
from app.models.manifest import ManifestInfo
from app.utils.logger import get_logger

logger = get_logger(__name__)

# Regex to parse a PEP 508 requirement line:
#   name[extras] operator version, ...
#   Captures: name, extras (optional), version_spec (optional)
_REQ_PATTERN = re.compile(
    r"^"
    r"(?P<name>[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)"   # package name
    r"(?:\[(?P<extras>[^\]]+)\])?"                              # optional [extras]
    r"(?P<spec>\s*(?:[><=!~^]+[^\s,;#]+(?:\s*,\s*[><=!~^]+[^\s,;#]+)*)?)?"  # version spec
    r"(?:\s*;.*)?$",                                            # optional env markers
    re.IGNORECASE,
)

# PEP 508 operators
_VERSION_OPERATORS = re.compile(r"^[><=!~^]")


class RequirementsParser(BaseParser):
    """
    Parser for requirements.txt files.

    Returns one ParsedDependency per valid package line.
    Invalid or unsupported lines are skipped with a warning.
    """

    @property
    def supported_manifest_type(self) -> str:
        return "requirements.txt"

    def parse(self, manifest: ManifestInfo) -> list[ParsedDependency]:
        """
        Parse requirements.txt and return ParsedDependency objects.

        Returns:
            List of ParsedDependency objects. Empty list for empty files.
        """
        logger.info("RequirementsParser | Parsing: %s", manifest.path)

        content = self._read_file(manifest.absolute_path)
        lines = self._preprocess(content)
        results: list[ParsedDependency] = []

        for line in lines:
            dep = self._parse_line(line, manifest.path)
            if dep is not None:
                results.append(dep)

        logger.info(
            "RequirementsParser | Found %d dependencies in %s",
            len(results),
            manifest.path,
        )
        return results

    def _preprocess(self, content: str) -> list[str]:
        """
        Preprocess file content:
        - Strip blank lines
        - Strip comments
        - Join line continuations
        - Skip pip option lines (-r, -c, --index-url, etc.)
        """
        # Handle line continuations first
        content = content.replace("\\\n", " ").replace("\\\r\n", " ")

        processed = []
        for raw_line in content.splitlines():
            line = raw_line.strip()

            # Skip blank lines
            if not line:
                continue

            # Skip comment-only lines
            if line.startswith("#"):
                continue

            # Skip pip option lines
            if line.startswith("-"):
                continue

            # Strip inline comments
            if " #" in line:
                line = line[:line.index(" #")].strip()
            elif "\t#" in line:
                line = line[:line.index("\t#")].strip()

            if line:
                processed.append(line)

        return processed

    def _parse_line(self, line: str, source_path: str) -> Optional[ParsedDependency]:
        """
        Parse a single preprocessed requirement line.

        Returns a ParsedDependency or None if the line cannot be parsed.
        """
        # Detect and skip VCS/URL requirements
        lower = line.lower()
        vcs_prefixes = ("git+", "git://", "svn+", "hg+", "bzr+", "http://", "https://")
        if any(lower.startswith(p) for p in vcs_prefixes):
            logger.debug(
                "RequirementsParser | Skipping VCS/URL requirement: %s",
                line[:80],
            )
            return None

        match = _REQ_PATTERN.match(line)
        if not match:
            logger.warning(
                "RequirementsParser | Could not parse line: %r in %s",
                line,
                source_path,
            )
            return None

        name = match.group("name").strip()
        if not name:
            return None

        extras_raw = match.group("extras")
        spec_raw = (match.group("spec") or "").strip()

        # Normalize package name (PEP 508: replace [-_.] with -)
        normalized_name = re.sub(r"[-_.]+", "-", name).lower()

        # Extract exact version if spec is a single equality
        version: Optional[str] = None
        version_spec: Optional[str] = spec_raw if spec_raw else None

        if spec_raw:
            exact_match = re.match(r"^==\s*([^\s,]+)$", spec_raw)
            if exact_match:
                version = exact_match.group(1).strip()

        return ParsedDependency(
            name=normalized_name,
            ecosystem="PyPI",
            source_manifest="requirements.txt",
            source_path=source_path,
            version=version,
            version_spec=version_spec,
            dependency_type="runtime",
            metadata={
                "original_name": name,
                "extras": [e.strip() for e in extras_raw.split(",")] if extras_raw else [],
                "raw_line": line,
            },
        )
