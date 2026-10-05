"""
services/pipeline.py

PipelineOrchestrator: Coordinates the full end-to-end RootTrace scan.

Flow:
  1. Run DependencyAnalysisEngine once → DependencyScanResult (graph + inventory)
  2. Build Package list from scan result (no double-run)
  3. Feed into VulnerabilityEngine via a lightweight StaticProvider
  4. Compute dependency paths from the graph
  5. Return unified RootTracePipelineResult (scan_id propagated throughout)
"""

import uuid
from typing import Optional

from app.models.pipeline_result import RootTracePipelineResult
from app.models.package import Package
from app.models.dependency_graph import DependencyGraph
from app.services.dependency.engine import DependencyAnalysisEngine
from app.services.dependency.graph_builder import ROOT_NODE_ID
from app.services.vulnerability.engine import VulnerabilityEngine
from app.services.vulnerability.package_provider import PackageProvider
from app.utils.logger import get_logger

logger = get_logger(__name__)


class PipelineOrchestrator:
    """Orchestrates the full end-to-end RootTrace pipeline with a shared scan_id."""

    def run_pipeline(
        self,
        repository_path: str,
        scan_id: Optional[str] = None,
    ) -> RootTracePipelineResult:
        if not scan_id:
            scan_id = f"scan-{uuid.uuid4()}"

        logger.info("Pipeline | Starting scan_id=%s for %s", scan_id, repository_path)

        # ── 1. Dependency Analysis ─────────────────────────────────────────
        dep_engine = DependencyAnalysisEngine()
        result_deps = dep_engine.analyze(repository_path=repository_path, scan_id=scan_id)

        # ── 2. Build Package list (same logic as DependencyVulnerabilityAdapter) ──
        packages: list[Package] = []
        seen: set = set()
        for dep in result_deps.dependencies:
            version = dep.version
            version_spec = dep.version_spec
            if version is not None and not version.strip():
                version = None
            key = (dep.name, version, version_spec, dep.ecosystem)
            if key in seen:
                continue
            seen.add(key)
            packages.append(Package(
                package_name=dep.name,
                version=version,
                version_spec=version_spec,
                ecosystem=dep.ecosystem,
            ))

        # ── 3. Vulnerability Intelligence via a static provider ────────────
        class _StaticProvider(PackageProvider):
            """Thin provider wrapping a pre-built package list."""
            def get_packages(self, scan_id: Optional[str] = None) -> list[Package]:
                return packages

        vuln_engine = VulnerabilityEngine()
        vuln_response = vuln_engine.run_scan(
            package_provider=_StaticProvider(),
            scan_id=scan_id,
        )

        # ── 4. Compute dependency paths ────────────────────────────────────
        paths = self._compute_paths(result_deps.graph)

        # ── 5. Assemble unified result ─────────────────────────────────────
        status = "completed" if not result_deps.errors else "completed_with_warnings"
        logger.info(
            "Pipeline | Completed scan_id=%s | status=%s | deps=%d | vulns=%d",
            scan_id,
            status,
            result_deps.total_dependencies,
            vuln_response.total_vulnerabilities_found,
        )

        return RootTracePipelineResult(
            scan_id=scan_id,
            status=status,
            dependency_scan=result_deps,
            vulnerability_scan=vuln_response,
            paths=paths,
        )

    def _compute_paths(
        self, graph: DependencyGraph
    ) -> dict[str, list[list[str]]]:
        """
        DFS from the virtual root to compute all paths to each dependency.

        Returns:
            Mapping of dependency_id → list of paths (each path is a list of IDs
            from the first direct dependency down to the node, root excluded).
        """
        paths: dict[str, list[list[str]]] = {}

        def dfs(node_id: str, current_path: list[str]) -> None:
            if node_id in current_path:  # cycle guard
                return
            new_path = current_path + [node_id]
            paths.setdefault(node_id, []).append(new_path)
            for child_id in graph.adjacency.get(node_id, []):
                dfs(child_id, new_path)

        dfs(ROOT_NODE_ID, [])

        # Strip the virtual root from every path for readability
        cleaned: dict[str, list[list[str]]] = {}
        for node_id, path_list in paths.items():
            if node_id == ROOT_NODE_ID:
                continue
            trimmed = [p[1:] for p in path_list if len(p) > 1]
            if trimmed:
                cleaned[node_id] = trimmed

        return cleaned
