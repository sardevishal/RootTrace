"""
parsers/go_mod_parser.py

Parser for Go module go.mod files.

Handles:
  - Single-line require directives:
      require github.com/example/pkg v1.2.3
  - Block require directives:
      require (
          github.com/example/pkg v1.2.3
          github.com/other/pkg  v0.1.0 // indirect
      )
  - Indirect marker: "// indirect"
  - Replace directives (recorded in metadata, not followed)
  - Exclude directives (recorded in metadata)

Does NOT:
  - Run 'go mod download' or any go toolchain command.
  - Follow replace directives to substitute packages.
  - Fetch transitive dependencies from the internet.

The project's own module declaration (module line) is identified
and excluded from the dependency list.

Ecosystem: "Go"
Version: the vX.Y.Z string from the require directive
"""

import re
from typing import Optional

from app.parsers.base import BaseParser, ParsedDependency
from app.models.manifest import ManifestInfo
from app.utils.logger import get_logger

logger = get_logger(__name__)

# Regex patterns
_MODULE_PATTERN = re.compile(r"^module\s+(\S+)", re.MULTILINE)
_SINGLE_REQUIRE = re.compile(
    r"^require\s+(\S+)\s+(v\S+)(\s*//\s*indirect)?",
    re.MULTILINE | re.IGNORECASE,
)
_BLOCK_REQUIRE_START = re.compile(r"^require\s*\(", re.MULTILINE)
_BLOCK_REQUIRE_END = re.compile(r"^\s*\)", re.MULTILINE)
_BLOCK_ENTRY = re.compile(
    r"^\s+(\S+)\s+(v\S+)(\s*//\s*indirect)?",
)
_REPLACE_PATTERN = re.compile(
    r"^replace\s+(\S+)(?:\s+\S+)?\s*=>\s*(\S+)(?:\s+(\S+))?",
    re.MULTILINE,
)


class GoModParser(BaseParser):
    """
    Parser for go.mod files.

    Produces one ParsedDependency per required module.
    The project's own module is excluded.
    """

    @property
    def supported_manifest_type(self) -> str:
        return "go.mod"

    def parse(self, manifest: ManifestInfo) -> list[ParsedDependency]:
        """
        Parse go.mod and return ParsedDependency objects.

        Returns:
            List of ParsedDependency objects.

        Raises:
            ValueError: If the file is completely unparseable.
        """
        logger.info("GoModParser | Parsing: %s", manifest.path)

        content = self._read_file(manifest.absolute_path)

        # Identify project's own module path to exclude it
        own_module = self._extract_module_name(content)
        if own_module:
            logger.debug("GoModParser | Own module: %s", own_module)

        # Parse replace directives (recorded in metadata)
        replacements = self._extract_replacements(content)

        results: list[ParsedDependency] = []
        seen: set[str] = set()

        # ── Parse block require statements ────────────────────────────────
        block_deps = self._parse_require_blocks(content, manifest.path, own_module, replacements)
        for dep in block_deps:
            key = f"{dep.name}@{dep.version}"
            if key not in seen:
                seen.add(key)
                results.append(dep)

        # ── Parse single-line require statements ─────────────────────────
        for match in _SINGLE_REQUIRE.finditer(content):
            module_path = match.group(1).strip()
            version = match.group(2).strip()
            indirect_marker = match.group(3)

            if own_module and module_path == own_module:
                continue

            key = f"{module_path}@{version}"
            if key in seen:
                continue
            seen.add(key)

            is_indirect = bool(indirect_marker)
            dep_type = "indirect" if is_indirect else "runtime"

            replacement = replacements.get(module_path)

            results.append(ParsedDependency(
                name=module_path,
                ecosystem="Go",
                source_manifest="go.mod",
                source_path=manifest.path,
                version=version,
                version_spec=version,
                dependency_type=dep_type,
                go_indirect=is_indirect,
                go_module_path=module_path,
                metadata={
                    "replacement": replacement,
                    "own_module": own_module,
                },
            ))

        logger.info(
            "GoModParser | Found %d dependencies in %s",
            len(results),
            manifest.path,
        )
        return results

    def _extract_module_name(self, content: str) -> Optional[str]:
        """Extract the project's own module path from the 'module' line."""
        match = _MODULE_PATTERN.search(content)
        if match:
            return match.group(1).strip()
        return None

    def _extract_replacements(self, content: str) -> dict[str, str]:
        """Extract replace directives into a mapping: original_module → replacement."""
        replacements: dict[str, str] = {}
        for match in _REPLACE_PATTERN.finditer(content):
            original = match.group(1).strip()
            replacement_mod = match.group(2).strip()
            replacement_ver = match.group(3)
            if replacement_ver:
                replacements[original] = f"{replacement_mod}@{replacement_ver.strip()}"
            else:
                replacements[original] = replacement_mod
        return replacements

    def _parse_require_blocks(
        self,
        content: str,
        source_path: str,
        own_module: Optional[str],
        replacements: dict[str, str],
    ) -> list[ParsedDependency]:
        """
        Parse all require ( ... ) block statements.

        Returns list of ParsedDependency objects from inside blocks.
        """
        results: list[ParsedDependency] = []
        lines = content.splitlines()
        in_block = False

        for line in lines:
            stripped = line.strip()

            # Detect block start: "require ("
            if re.match(r"^require\s*\($", stripped):
                in_block = True
                continue

            # Detect block end
            if in_block and stripped == ")":
                in_block = False
                continue

            if not in_block:
                continue

            # Skip blank lines and comments inside block
            if not stripped or stripped.startswith("//"):
                continue

            # Parse a block entry
            entry_match = _BLOCK_ENTRY.match(line)
            if not entry_match:
                logger.debug("GoModParser | Cannot parse block entry: %r", line)
                continue

            module_path = entry_match.group(1).strip()
            version = entry_match.group(2).strip()
            indirect_marker = entry_match.group(3)

            if own_module and module_path == own_module:
                continue

            is_indirect = bool(indirect_marker)
            dep_type = "indirect" if is_indirect else "runtime"
            replacement = replacements.get(module_path)

            results.append(ParsedDependency(
                name=module_path,
                ecosystem="Go",
                source_manifest="go.mod",
                source_path=source_path,
                version=version,
                version_spec=version,
                dependency_type=dep_type,
                go_indirect=is_indirect,
                go_module_path=module_path,
                metadata={
                    "replacement": replacement,
                    "own_module": own_module,
                },
            ))

        return results
