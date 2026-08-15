"""
parsers/dockerfile_parser.py

Conservative static parser for Dockerfile manifests.

This parser performs STATIC ANALYSIS ONLY.
It does NOT:
  - Execute the Dockerfile
  - Build Docker images
  - Run docker build
  - Run any shell commands
  - Interpret shell variables or ARG substitutions

It identifies explicit package installation patterns in RUN instructions
where the package name and optionally a version are clearly identifiable.

Supported patterns:
  - npm install <package>[@<version>]         → ecosystem: npm
  - npm i <package>[@<version>]
  - pip install <package>[==<version>]        → ecosystem: PyPI
  - pip3 install <package>[==<version>]
  - apt-get install <package>[=<version>]     → ecosystem: apt
  - apt install <package>[=<version>]
  - apk add <package>[=<version>]             → ecosystem: apk
  - yum install <package>                     → ecosystem: yum
  - dnf install <package>                     → ecosystem: dnf

Limitations (documented honestly per spec §31):
  - Multi-variable commands (apt-get install -y pkg1 pkg2) detect all
    non-flag tokens as packages.
  - Shell variable substitution ($VERSION etc.) is NOT resolved.
  - Packages installed inside if/for/while constructs are detected
    but may have false positives.
  - --no-install-recommends and similar flags are skipped correctly.
"""

import re
from typing import Optional

from app.parsers.base import BaseParser, ParsedDependency
from app.models.manifest import ManifestInfo
from app.utils.logger import get_logger

logger = get_logger(__name__)

# Patterns for supported installers
_INSTALLERS = [
    # npm / yarn
    {
        "pattern": re.compile(
            r"\bnpm\s+(?:install|i|add)\s+(?:--save(?:-dev|-optional|-peer)?\s+)?([^\\\n&|;]+)",
            re.IGNORECASE,
        ),
        "ecosystem": "npm",
        "version_sep": "@",
    },
    {
        "pattern": re.compile(
            r"\byarn\s+(?:add|install)\s+(?:--dev\s+|--peer\s+|--optional\s+)?([^\\\n&|;]+)",
            re.IGNORECASE,
        ),
        "ecosystem": "npm",
        "version_sep": "@",
    },
    # pip
    {
        "pattern": re.compile(
            r"\bpip3?\s+install\s+(?:--upgrade\s+|--quiet\s+|-q\s+|-U\s+)?([^\\\n&|;]+)",
            re.IGNORECASE,
        ),
        "ecosystem": "PyPI",
        "version_sep": "==",
    },
    # apt / apt-get
    {
        "pattern": re.compile(
            r"\bapt(?:-get)?\s+install\s+(?:-y\s+|--yes\s+|--no-install-recommends\s+|--quiet\s+|-qq?\s+)*([^\\\n&|;]+)",
            re.IGNORECASE,
        ),
        "ecosystem": "apt",
        "version_sep": "=",
    },
    # apk
    {
        "pattern": re.compile(
            r"\bapk\s+(?:add|install)\s+(?:--no-cache\s+|--update\s+|-q\s+)*([^\\\n&|;]+)",
            re.IGNORECASE,
        ),
        "ecosystem": "apk",
        "version_sep": "=",
    },
    # yum / dnf
    {
        "pattern": re.compile(
            r"\b(?:yum|dnf)\s+install\s+(?:-y\s+|--assumeyes\s+)?([^\\\n&|;]+)",
            re.IGNORECASE,
        ),
        "ecosystem": "yum",
        "version_sep": "-",
    },
]

# Tokens to skip when splitting a package list
_SKIP_TOKENS = re.compile(
    r"^(-{1,2}[a-zA-Z]|&&|\|\||;|>|<|\\|/dev/null|"
    r"no-install-recommends|update|upgrade|clean|autoclean|autoremove|purge|remove)$",
    re.IGNORECASE,
)

# RUN instruction from a Dockerfile
_RUN_PATTERN = re.compile(r"^RUN\s+(.*)", re.MULTILINE | re.IGNORECASE)

# Shell variable - skip tokens containing $VAR
_SHELL_VAR = re.compile(r"\$[{(]?\w+[})]?")


class DockerfileParser(BaseParser):
    """
    Conservative static parser for Dockerfiles.

    Identifies explicit package installations in RUN instructions
    using known installer command patterns.
    """

    @property
    def supported_manifest_type(self) -> str:
        return "Dockerfile"

    def parse(self, manifest: ManifestInfo) -> list[ParsedDependency]:
        """
        Parse a Dockerfile and return detected package dependencies.

        Returns:
            List of ParsedDependency objects. May be empty if no
            identifiable package installations are found.
        """
        logger.info("DockerfileParser | Parsing: %s", manifest.path)

        content = self._read_file(manifest.absolute_path)

        # Join line continuations within RUN instructions
        normalized = self._join_continuations(content)

        results: list[ParsedDependency] = []
        seen: set[str] = set()

        # Find all RUN instructions and their line numbers
        run_line_map = self._build_run_line_map(content)

        for run_match in _RUN_PATTERN.finditer(normalized):
            run_command = run_match.group(1).strip()

            # Estimate line number from position in original content
            line_num = self._estimate_line_number(run_match.start(), content)

            for installer in _INSTALLERS:
                for pkg_match in installer["pattern"].finditer(run_command):
                    raw_args = pkg_match.group(1).strip()
                    packages = self._extract_packages(
                        raw_args,
                        installer["ecosystem"],
                        installer["version_sep"],
                    )

                    for pkg_name, pkg_version, version_spec in packages:
                        key = f"{installer['ecosystem']}:{pkg_name}"
                        if key in seen:
                            continue
                        seen.add(key)

                        results.append(ParsedDependency(
                            name=pkg_name,
                            ecosystem=installer["ecosystem"],
                            source_manifest="Dockerfile",
                            source_path=manifest.path,
                            version=pkg_version,
                            version_spec=version_spec,
                            dependency_type="system" if installer["ecosystem"] in ("apt", "apk", "yum") else "runtime",
                            dockerfile_line=line_num,
                            dockerfile_command=run_command[:200],
                            metadata={
                                "installer": installer["ecosystem"],
                                "raw_args": raw_args[:500],
                            },
                        ))

        logger.info(
            "DockerfileParser | Found %d package references in %s",
            len(results),
            manifest.path,
        )
        return results

    def _join_continuations(self, content: str) -> str:
        """Join backslash line continuations in Dockerfile RUN instructions."""
        return re.sub(r"\\\s*\n", " ", content)

    def _build_run_line_map(self, content: str) -> dict[int, int]:
        """Build a map of character position → line number in original content."""
        line_map: dict[int, int] = {}
        pos = 0
        for line_num, line in enumerate(content.splitlines(), start=1):
            line_map[pos] = line_num
            pos += len(line) + 1  # +1 for newline
        return line_map

    def _estimate_line_number(self, char_pos: int, original_content: str) -> int:
        """Estimate the line number of a character position in the original content."""
        return original_content[:char_pos].count("\n") + 1

    def _extract_packages(
        self,
        raw_args: str,
        ecosystem: str,
        version_sep: str,
    ) -> list[tuple[str, Optional[str], Optional[str]]]:
        """
        Extract (package_name, version, version_spec) tuples from installer arguments.

        Skips:
          - Flags (starting with -)
          - Shell variable references ($VAR)
          - Known non-package tokens (&&, ||, etc.)
          - Very short tokens (1 char)

        Returns:
            List of (name, version, version_spec) tuples.
            version is None when no exact version was specified.
        """
        tokens = raw_args.split()
        packages = []

        i = 0
        while i < len(tokens):
            token = tokens[i]
            i += 1

            # Skip flags, operators, shell vars
            if _SKIP_TOKENS.match(token):
                continue
            if _SHELL_VAR.search(token):
                continue
            if len(token) <= 1:
                continue
            # Skip tokens that look like file paths or URLs
            if token.startswith("/") or "://" in token:
                continue
            # Skip -y, --yes, etc. (flags with values)
            if token.startswith("-"):
                continue

            # Extract version from token if version separator is present
            version: Optional[str] = None
            version_spec: Optional[str] = None
            pkg_name = token

            if ecosystem == "npm":
                # npm: package@version or @scope/package@version
                if "@" in token and not token.startswith("@"):
                    parts = token.rsplit("@", 1)
                    pkg_name = parts[0]
                    version = version_spec = parts[1] if len(parts) > 1 else None
                elif token.count("@") >= 2 and token.startswith("@"):
                    # @scope/package@version
                    last_at = token.rfind("@", 1)
                    pkg_name = token[:last_at]
                    version = version_spec = token[last_at + 1:]

            elif ecosystem == "PyPI":
                # pip: package==version or package>=version etc.
                for op in ("==", ">=", "<=", "!=", "~=", "^=", ">", "<"):
                    if op in token:
                        parts = token.split(op, 1)
                        pkg_name = parts[0].strip()
                        raw_spec = op + parts[1].strip()
                        version_spec = raw_spec
                        if op == "==":
                            version = parts[1].strip()
                        break

            elif ecosystem in ("apt", "apk"):
                # apt: package=version
                if "=" in token and not token.startswith("="):
                    parts = token.split("=", 1)
                    pkg_name = parts[0].strip()
                    version = version_spec = parts[1].strip() if parts[1] else None

            elif ecosystem == "yum":
                # yum: package-version (ambiguous — best effort)
                # Only split if there's a clear version pattern
                ver_match = re.match(r"^([a-zA-Z][a-zA-Z0-9+._-]*)-(\d[\d.a-zA-Z-]*)$", token)
                if ver_match:
                    pkg_name = ver_match.group(1)
                    version = version_spec = ver_match.group(2)

            # Final cleanup
            pkg_name = pkg_name.strip().rstrip("\\")
            if not pkg_name or len(pkg_name) < 2:
                continue

            packages.append((pkg_name, version, version_spec))

        return packages
