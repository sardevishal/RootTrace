"""
services/dependency/engine.py

The Dependency Analysis Engine — main orchestrator.

This is the single entry point for all dependency analysis operations.
API routes, downstream services, and integration tests interact ONLY
with this class.

Pipeline:
    1. Validate repository path          (RepositoryScanner)
    2. Scan repository files             (RepositoryScanner)
    3. Detect manifests + lockfiles      (ManifestDetector)
    4. Select parsers per manifest       (parser registry)
    5. Parse each manifest               (parsers/)
    6. Normalize dependencies            (DependencyNormalizer)
    7. Resolve version specs             (DependencyResolver)
    8. Classify direct vs. transitive    (TransitiveAnalyzer)
    9. Build dependency graph            (GraphBuilder)
   10. Analyze graph                     (GraphAnalyzer)
   11. Build downstream-compatible list  (adapter)
   12. Return DependencyScanResult

Error handling:
    - A single failed manifest does NOT abort the entire scan.
    - All errors are structured into ScanError objects.
    - The scan status reflects partial failures:
      completed / completed_with_warnings / failed

Security:
    - Path traversal prevention via RepositoryScanner
    - No subprocess execution
    - No network requests
    - No evaluation of repository code
"""

import uuid
from typing import Optional

from app.models.dependency import Dependency
from app.models.dependency_scan import DependencyScanResult, ScanError, ScanWarning, NormalizedPackage
from app.models.manifest import ManifestInfo
from app.models.package import Package

from app.parsers.base import BaseParser
from app.parsers.package_json_parser import PackageJsonParser
from app.parsers.requirements_parser import RequirementsParser
from app.parsers.pom_parser import PomParser
from app.parsers.go_mod_parser import GoModParser
from app.parsers.dockerfile_parser import DockerfileParser

from app.services.dependency.repository_scanner import RepositoryScanner
from app.services.dependency.manifest_detector import ManifestDetector
from app.services.dependency.dependency_normalizer import DependencyNormalizer
from app.services.dependency.dependency_resolver import DependencyResolver
from app.services.dependency.transitive_analyzer import TransitiveAnalyzer
from app.services.dependency.graph_builder import GraphBuilder
from app.services.dependency.graph_analyzer import GraphAnalyzer

from app.utils.constants import (
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_COMPLETED_WITH_WARNINGS,
    SCAN_STATUS_FAILED,
)
from app.utils.logger import get_logger

logger = get_logger(__name__)

# Parser registry: manifest_type → parser instance
_PARSER_REGISTRY: dict[str, BaseParser] = {
    "package.json": PackageJsonParser(),
    "requirements.txt": RequirementsParser(),
    "pom.xml": PomParser(),
    "go.mod": GoModParser(),
    "Dockerfile": DockerfileParser(),
}


class DependencyAnalysisEngine:
    """
    Central orchestrator for the Dependency Analysis Engine.

    Usage:
        engine = DependencyAnalysisEngine()
        result = engine.analyze("/path/to/repository")

    Downstream integration:
        packages = engine.get_packages_for_vulnerability_scan(result)
        # → list[Package] compatible with VulnerabilityEngine.run_scan()
    """

    def __init__(self) -> None:
        self._scanner = RepositoryScanner()
        self._detector = ManifestDetector()
        self._normalizer = DependencyNormalizer()
        self._resolver = DependencyResolver()
        self._transitive = TransitiveAnalyzer()
        self._graph_builder = GraphBuilder()
        self._graph_analyzer = GraphAnalyzer()

    # ─────────────────────────────────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────────────────────────────────

    def analyze(
        self,
        repository_path: str,
        scan_id: Optional[str] = None,
        repository_id: Optional[str] = None,
    ) -> DependencyScanResult:
        """
        Analyze a repository and return the complete dependency scan result.

        Args:
            repository_path: Path to the repository root directory.
            scan_id:         Optional scan identifier. Auto-generated if None.
            repository_id:   Optional external repository reference.

        Returns:
            DependencyScanResult containing all dependencies, graph, and metadata.
        """
        scan_id = scan_id or str(uuid.uuid4())
        errors: list[ScanError] = []
        warnings: list[ScanWarning] = []

        logger.info("═" * 60)
        logger.info("DependencyEngine | Starting scan (id=%s)", scan_id)
        logger.info("DependencyEngine | Repository: %s", repository_path)

        # ── Step 1: Scan repository ─────────────────────────────────────────
        try:
            files = self._scanner.scan(repository_path)
        except (ValueError, FileNotFoundError, NotADirectoryError) as exc:
            logger.error("DependencyEngine | Repository scan failed: %s", exc)
            return DependencyScanResult(
                scan_id=scan_id,
                repository_path=repository_path,
                repository_id=repository_id,
                status=SCAN_STATUS_FAILED,
                errors=[ScanError(
                    error_type="path_traversal" if "traversal" in str(exc).lower() else "file_not_found",
                    message=str(exc),
                )],
            )

        logger.info("DependencyEngine | Found %d files in repository", len(files))

        # ── Step 2: Detect manifests ────────────────────────────────────────
        manifests = self._detector.detect(files, repository_path)

        if not manifests:
            warnings.append(ScanWarning(
                warning_type="no_manifests_found",
                message="No supported manifest files found in repository.",
            ))
            logger.warning("DependencyEngine | No manifests found.")
            return DependencyScanResult(
                scan_id=scan_id,
                repository_path=repository_path,
                repository_id=repository_id,
                status=SCAN_STATUS_COMPLETED_WITH_WARNINGS,
                manifests=[],
                manifests_found=0,
                manifests_parsed=0,
                warnings=warnings,
            )

        logger.info("DependencyEngine | Detected %d manifest(s)", len(manifests))

        # ── Step 3-5: Parse manifests ────────────────────────────────────────
        all_parsed = []
        parsed_count = 0

        for manifest in manifests:
            parser = _PARSER_REGISTRY.get(manifest.manifest_type)
            if parser is None:
                warnings.append(ScanWarning(
                    path=manifest.path,
                    warning_type="no_parser",
                    message=f"No parser registered for manifest type: {manifest.manifest_type}",
                ))
                continue

            logger.info(
                "DependencyEngine | Parsing [%s] %s",
                manifest.manifest_type,
                manifest.path,
            )

            try:
                parsed = parser.parse(manifest)
                all_parsed.extend(parsed)
                parsed_count += 1
                logger.info(
                    "DependencyEngine | → %d dependencies from %s",
                    len(parsed),
                    manifest.path,
                )
            except (ValueError, FileNotFoundError, PermissionError) as exc:
                error_type = "parse_error"
                if isinstance(exc, FileNotFoundError):
                    error_type = "file_not_found"
                elif isinstance(exc, PermissionError):
                    error_type = "permission_error"

                logger.error(
                    "DependencyEngine | Parse error in %s: %s",
                    manifest.path,
                    exc,
                )
                errors.append(ScanError(
                    path=manifest.path,
                    error_type=error_type,
                    message=str(exc),
                    ecosystem=manifest.ecosystem,
                ))
            except Exception as exc:
                logger.exception(
                    "DependencyEngine | Unexpected error parsing %s: %s",
                    manifest.path,
                    exc,
                )
                errors.append(ScanError(
                    path=manifest.path,
                    error_type="parse_error",
                    message=f"Unexpected error: {exc}",
                    ecosystem=manifest.ecosystem,
                ))

        logger.info(
            "DependencyEngine | Total raw parsed: %d from %d manifests",
            len(all_parsed),
            parsed_count,
        )

        # ── Step 6: Normalize ───────────────────────────────────────────────
        dependencies, norm_warnings = self._normalizer.normalize_all(all_parsed)
        for w in norm_warnings:
            warnings.append(ScanWarning(warning_type="normalization_warning", message=w))

        logger.info("DependencyEngine | Normalized: %d unique dependencies", len(dependencies))

        # ── Step 7: Resolve versions ────────────────────────────────────────
        dependencies, unresolved = self._resolver.resolve(dependencies)
        if unresolved:
            warnings.append(ScanWarning(
                warning_type="unresolved_versions",
                message=f"{len(unresolved)} dependencies have unresolved versions. "
                        "Vulnerability matching may be incomplete.",
            ))

        # ── Step 8: Classify transitive ─────────────────────────────────────
        dependencies = self._transitive.analyze(dependencies)

        # ── Step 9: Build graph ──────────────────────────────────────────────
        graph = self._graph_builder.build(dependencies)

        # ── Step 10: Analyze graph ───────────────────────────────────────────
        graph = self._graph_analyzer.analyze(graph)

        # ── Step 11: Build downstream-compatible inventory ───────────────────
        normalized_packages = self._build_normalized_packages(dependencies, scan_id)

        # ── Step 12: Determine scan status ──────────────────────────────────
        if errors and dependencies:
            status = SCAN_STATUS_COMPLETED_WITH_WARNINGS
        elif errors and not dependencies:
            status = SCAN_STATUS_FAILED
        elif warnings:
            status = SCAN_STATUS_COMPLETED_WITH_WARNINGS
        else:
            status = SCAN_STATUS_COMPLETED

        direct_count = sum(1 for d in dependencies if d.direct)
        transitive_count = sum(1 for d in dependencies if d.transitive)

        result = DependencyScanResult(
            scan_id=scan_id,
            repository_path=repository_path,
            repository_id=repository_id,
            status=status,
            manifests=manifests,
            dependencies=dependencies,
            graph=graph,
            normalized_packages=normalized_packages,
            total_dependencies=len(dependencies),
            direct_dependencies=direct_count,
            transitive_dependencies=transitive_count,
            manifests_found=len(manifests),
            manifests_parsed=parsed_count,
            errors=errors,
            warnings=warnings,
        )

        logger.info(
            "DependencyEngine | Scan complete — status=%s | deps=%d (direct=%d, transitive=%d) | "
            "manifests=%d/%d | errors=%d | warnings=%d",
            status,
            len(dependencies),
            direct_count,
            transitive_count,
            parsed_count,
            len(manifests),
            len(errors),
            len(warnings),
        )
        logger.info("═" * 60)

        return result

    def get_packages_for_vulnerability_scan(
        self,
        result: DependencyScanResult,
        include_unresolved: bool = False,
    ) -> list[Package]:
        """
        Convert dependency scan results to Package objects for the
        Vulnerability Intelligence Engine.

        This is the downstream integration adapter.

        Usage:
            engine = DependencyAnalysisEngine()
            scan = engine.analyze("/repo")
            packages = engine.get_packages_for_vulnerability_scan(scan)
            vuln_engine.run_scan(packages=packages)

        Args:
            result:             DependencyScanResult from analyze().
            include_unresolved: If True, include deps with version=None
                                (version will be set to "unresolved").
                                Default False — only exact versions are included.

        Returns:
            List of Package objects consumable by VulnerabilityEngine.run_scan().
        """
        packages: list[Package] = []

        for dep in result.dependencies:
            version = dep.version

            if version is None:
                if not include_unresolved:
                    continue
                version = "unresolved"

            # Skip empty/blank versions
            if not version.strip():
                continue

            try:
                pkg = Package(
                    package_name=dep.name,
                    version=version,
                    ecosystem=dep.ecosystem,
                )
                packages.append(pkg)
            except Exception as exc:
                logger.debug(
                    "DependencyEngine | Skipped %s for vuln scan: %s",
                    dep.id,
                    exc,
                )

        logger.info(
            "DependencyEngine | Downstream adapter: %d/%d deps exported for vuln scan",
            len(packages),
            len(result.dependencies),
        )
        return packages

    # ─────────────────────────────────────────────────────────────────────────
    # Private helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _build_normalized_packages(
        self,
        dependencies: list[Dependency],
        scan_id: Optional[str],
    ) -> list[NormalizedPackage]:
        """
        Build the minimal downstream-compatible package inventory.

        Returns:
            List of NormalizedPackage objects — directly consumable by
            the Vulnerability Intelligence Engine.
        """
        return [
            NormalizedPackage(
                package_name=dep.name,
                version=dep.version,
                version_spec=dep.version_spec,
                ecosystem=dep.ecosystem,
                dependency_id=dep.id,
                scan_id=scan_id,
            )
            for dep in dependencies
        ]
