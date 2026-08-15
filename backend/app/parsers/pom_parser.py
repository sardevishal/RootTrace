"""
parsers/pom_parser.py

Parser for Maven pom.xml manifests.

Parses the <dependencies> section of a Maven POM file.
Uses stdlib xml.etree.ElementTree — no third-party XML libraries required.

Handles:
  - Standard <dependency> blocks with groupId, artifactId, version, scope
  - Maven namespace (xmlns="http://maven.apache.org/POM/4.0.0")
  - Both namespaced and non-namespaced XML
  - Missing version (e.g. version managed by parent POM or BOM)
  - Multiple scope types: compile, test, provided, runtime, system, import

Does NOT:
  - Resolve property placeholders (${project.version}, ${spring.version})
    These are recorded as-is in version_spec; version stays None.
  - Download parent POMs or BOMs.
  - Execute Maven or any subprocess.

Package identity: "groupId:artifactId"
Ecosystem: "Maven"
"""

import re
import xml.etree.ElementTree as ET
from typing import Optional

from app.parsers.base import BaseParser, ParsedDependency
from app.models.manifest import ManifestInfo
from app.utils.logger import get_logger

logger = get_logger(__name__)

# Maven POM namespace
_MAVEN_NS = "http://maven.apache.org/POM/4.0.0"

# Maven scope → dependency_type mapping
_SCOPE_TYPE_MAP = {
    "compile": "runtime",
    "runtime": "runtime",
    "provided": "provided",
    "test": "test",
    "system": "system",
    "import": "build",
}

# Property placeholder pattern
_PROPERTY_PATTERN = re.compile(r"^\$\{.+\}$")


def _tag(name: str, ns: Optional[str] = None) -> str:
    """Return a namespaced ElementTree tag string."""
    if ns:
        return f"{{{ns}}}{name}"
    return name


def _find_text(element: ET.Element, tag: str, ns: Optional[str] = None) -> Optional[str]:
    """Find child element text, trying with and without namespace."""
    # Try with namespace first
    if ns:
        child = element.find(_tag(tag, ns))
        if child is not None and child.text:
            return child.text.strip()

    # Fall back to no namespace
    child = element.find(tag)
    if child is not None and child.text:
        return child.text.strip()

    return None


class PomParser(BaseParser):
    """
    Parser for Maven pom.xml files.

    Returns one ParsedDependency per <dependency> entry.
    """

    @property
    def supported_manifest_type(self) -> str:
        return "pom.xml"

    def parse(self, manifest: ManifestInfo) -> list[ParsedDependency]:
        """
        Parse pom.xml and return ParsedDependency objects.

        Returns:
            List of ParsedDependency objects.

        Raises:
            ValueError: If the XML is malformed.
        """
        logger.info("PomParser | Parsing: %s", manifest.path)

        content = self._read_file(manifest.absolute_path)

        try:
            root = ET.fromstring(content)
        except ET.ParseError as exc:
            raise ValueError(
                f"Invalid XML in {manifest.path}: {exc}"
            ) from exc

        # Detect namespace
        ns: Optional[str] = None
        if root.tag.startswith(f"{{{_MAVEN_NS}}}"):
            ns = _MAVEN_NS

        results: list[ParsedDependency] = []

        # Find the <dependencies> section
        # Some POMs have it directly under root, others under <dependencyManagement>
        dependency_containers = []

        deps_direct = root.find(_tag("dependencies", ns)) if ns else root.find("dependencies")
        if deps_direct is not None:
            dependency_containers.append(("direct", deps_direct))

        # Also parse dependencyManagement
        dep_mgmt = root.find(_tag("dependencyManagement", ns)) if ns else root.find("dependencyManagement")
        if dep_mgmt is not None:
            dep_mgmt_deps = dep_mgmt.find(_tag("dependencies", ns)) if ns else dep_mgmt.find("dependencies")
            if dep_mgmt_deps is not None:
                dependency_containers.append(("managed", dep_mgmt_deps))

        for container_type, container in dependency_containers:
            dep_tag = _tag("dependency", ns) if ns else "dependency"
            for dep_elem in container.findall(dep_tag):
                parsed = self._parse_dependency(dep_elem, manifest.path, ns, container_type)
                if parsed is not None:
                    results.append(parsed)

        logger.info(
            "PomParser | Found %d dependencies in %s",
            len(results),
            manifest.path,
        )
        return results

    def _parse_dependency(
        self,
        dep_elem: ET.Element,
        source_path: str,
        ns: Optional[str],
        container_type: str,
    ) -> Optional[ParsedDependency]:
        """
        Parse a single <dependency> element.

        Returns ParsedDependency or None if groupId/artifactId are missing.
        """
        group_id = _find_text(dep_elem, "groupId", ns)
        artifact_id = _find_text(dep_elem, "artifactId", ns)
        raw_version = _find_text(dep_elem, "version", ns)
        scope = _find_text(dep_elem, "scope", ns) or "compile"
        optional_flag = _find_text(dep_elem, "optional", ns)

        if not group_id or not artifact_id:
            logger.warning(
                "PomParser | Skipping dependency missing groupId/artifactId in %s",
                source_path,
            )
            return None

        # Canonical package identity: "groupId:artifactId"
        package_name = f"{group_id}:{artifact_id}"

        # Version: may be a property placeholder like ${spring.version}
        version: Optional[str] = None
        version_spec: Optional[str] = raw_version

        if raw_version:
            if not _PROPERTY_PATTERN.match(raw_version):
                # It looks like an actual version string
                version = raw_version
                version_spec = raw_version

        # Determine dependency type from scope
        dep_type = _SCOPE_TYPE_MAP.get(scope.lower(), "runtime")

        # Override: optional=true in pom means "optional"
        if optional_flag and optional_flag.lower() == "true":
            dep_type = "optional"

        return ParsedDependency(
            name=package_name,
            ecosystem="Maven",
            source_manifest="pom.xml",
            source_path=source_path,
            version=version,
            version_spec=version_spec,
            dependency_type=dep_type,
            group_id=group_id,
            artifact_id=artifact_id,
            maven_scope=scope,
            metadata={
                "container_type": container_type,
                "optional": optional_flag == "true" if optional_flag else False,
                "raw_version": raw_version,
            },
        )
