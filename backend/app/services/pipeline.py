"""
services/pipeline.py

PipelineOrchestrator: Coordinates the full end-to-end RootTrace scan.

Flow:
  1. Run DependencyAnalysisEngine once → DependencyScanResult (graph + inventory)
  2. Build Package list from scan result (no double-run)
  3. Build dep_context_map from Dependency records (P2G fix — no longer deferred)
  4. Feed into VulnerabilityEngine via a lightweight StaticProvider
  5. Generate canonical VulnerabilityFinding records via FindingProvider
  6. Compute dependency paths from the graph
  7. Optionally run AI Security Analysis via SecurityAnalysisService
  8. Return unified RootTracePipelineResult (scan_id propagated throughout)

scan_id is IDENTICAL throughout all stages — dependency, vulnerability, findings, AI.
"""

import uuid
from typing import Optional

from app.models.pipeline_result import RootTracePipelineResult
from app.models.package import Package
from app.models.dependency import Dependency
from app.models.dependency_graph import DependencyGraph
from app.models.vulnerability_finding import DependencyContext
from app.services.dependency.engine import DependencyAnalysisEngine
from app.services.dependency.graph_builder import ROOT_NODE_ID
from app.services.vulnerability.engine import VulnerabilityEngine
from app.services.vulnerability.package_provider import PackageProvider
from app.services.vulnerability.providers.finding_provider import VulnerabilityFindingProvider
from app.services.ai.ai_input_provider import SecurityAnalysisInputProvider
from app.services.ai.security_analysis_service import SecurityAnalysisService
from app.services.ai.mock_llm_provider import MockLLMProvider
from app.models.ai_analysis_result import (
    AI_STATUS_NOT_REQUESTED,
    AI_STATUS_FAILED,
)
from app.utils.logger import get_logger

logger = get_logger(__name__)


class PipelineOrchestrator:
    """Orchestrates the full end-to-end RootTrace pipeline with a shared scan_id."""

    def run_pipeline(
        self,
        repository_path: str,
        scan_id: Optional[str] = None,
        include_ai_analysis: bool = False,
        ai_service: Optional[SecurityAnalysisService] = None,
        max_ai_findings: int = 50,
    ) -> RootTracePipelineResult:
        """
        Run the full RootTrace pipeline.

        Args:
            repository_path:     Path to the repository to analyze.
            scan_id:             Optional scan identifier (generated if not supplied).
            include_ai_analysis: Whether to run AI Security Analysis (P2G).
                                 Defaults to False — keeps pipeline fast when AI not needed.
            ai_service:          Optional SecurityAnalysisService. Defaults to
                                 MockLLMProvider-backed service if include_ai_analysis=True.
            max_ai_findings:     Context limit for AI analysis (default 50).

        Returns:
            RootTracePipelineResult with scan_id propagated throughout all stages.
        """
        if not scan_id:
            scan_id = f"scan-{uuid.uuid4()}"

        logger.info("Pipeline | Starting scan_id=%s for %s", scan_id, repository_path)

        # ── 1. Dependency Analysis ─────────────────────────────────────────────
        dep_engine = DependencyAnalysisEngine()
        result_deps = dep_engine.analyze(repository_path=repository_path, scan_id=scan_id)

        # ── 2. Build Package list ──────────────────────────────────────────────
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

        # ── 3. Build dep_context_map (P2G — resolves P2F deferred gap) ─────────
        # This maps package_name → DependencyContext built from the real Dependency
        # records produced by the Dependency Analysis Engine.
        dep_context_map: dict[str, DependencyContext] = _build_dep_context_map(
            result_deps.dependencies
        )
        logger.info(
            "Pipeline | Built dep_context_map for %d unique packages.",
            len(dep_context_map),
        )

        # ── 4. Vulnerability Intelligence ──────────────────────────────────────
        class _StaticProvider(PackageProvider):
            """Thin provider wrapping a pre-built package list."""
            def get_packages(self, scan_id: Optional[str] = None) -> list[Package]:
                return packages

        vuln_engine = VulnerabilityEngine()
        vuln_response = vuln_engine.run_scan(
            package_provider=_StaticProvider(),
            scan_id=scan_id,
        )

        # ── 5. Compute dependency paths ────────────────────────────────────────
        paths = self._compute_paths(result_deps.graph)

        # ── 6. Assemble unified result ─────────────────────────────────────────
        status = "completed" if not result_deps.errors else "completed_with_warnings"
        logger.info(
            "Pipeline | Completed scan_id=%s | status=%s | deps=%d | vulns=%d",
            scan_id, status,
            result_deps.total_dependencies,
            vuln_response.total_vulnerabilities_found,
        )

        pipeline_result = RootTracePipelineResult(
            scan_id=scan_id,
            status=status,
            dependency_scan=result_deps,
            vulnerability_scan=vuln_response,
            paths=paths,
        )

        # ── 7. Optional AI Security Analysis ──────────────────────────────────
        if include_ai_analysis:
            pipeline_result = self._run_ai_analysis(
                pipeline_result=pipeline_result,
                packages=packages,
                dep_context_map=dep_context_map,
                scan_id=scan_id,
                ai_service=ai_service,
                max_ai_findings=max_ai_findings,
            )

        return pipeline_result

    def _run_ai_analysis(
        self,
        pipeline_result: RootTracePipelineResult,
        packages: list[Package],
        dep_context_map: dict[str, DependencyContext],
        scan_id: str,
        ai_service: Optional[SecurityAnalysisService],
        max_ai_findings: int,
    ) -> RootTracePipelineResult:
        """
        Run AI Security Analysis and attach the result to the pipeline result.

        AI failures are isolated — they set ai_status on the pipeline result
        without invalidating the vulnerability scan.
        """
        try:
            # Build canonical findings with dep_context_map for full path injection
            class _StaticProvider(PackageProvider):
                def get_packages(self, scan_id: Optional[str] = None) -> list[Package]:
                    return packages

            finding_provider = VulnerabilityFindingProvider()
            ai_input_provider = SecurityAnalysisInputProvider(
                finding_provider=finding_provider,
            )
            analysis_input = ai_input_provider.get_analysis_input(
                package_provider=_StaticProvider(),
                dep_context_map=dep_context_map,
                scan_id=scan_id,
                max_findings=max_ai_findings,
            )

            service = ai_service or SecurityAnalysisService(llm_provider=MockLLMProvider())
            ai_result = service.analyze(analysis_input)

            logger.info(
                "Pipeline | AI analysis complete — ai_status=%s, analyses=%d",
                ai_result.ai_status, len(ai_result.finding_analyses),
            )
            pipeline_result.ai_analysis = ai_result
            pipeline_result.ai_status = ai_result.ai_status

        except Exception as exc:
            logger.exception("Pipeline | AI analysis failed unexpectedly: %s", exc)
            pipeline_result.ai_status = AI_STATUS_FAILED
            # ai_analysis remains None — vulnerability scan result is untouched

        return pipeline_result

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


def _build_dep_context_map(
    dependencies: list[Dependency],
) -> dict[str, DependencyContext]:
    """
    Build a package_name → DependencyContext map from Dependency records.

    Resolution rule: if a package appears multiple times (different versions),
    the entry with the smallest depth (most direct) wins. This ensures the most
    conservative (highest priority) context is presented to the AI.

    This function resolves the P2F deferred integration gap.
    Callers no longer need to manually construct dep_context_map.
    """
    context_map: dict[str, DependencyContext] = {}
    depth_tracker: dict[str, int] = {}

    for dep in dependencies:
        existing_depth = depth_tracker.get(dep.name)
        if existing_depth is not None and dep.depth >= existing_depth:
            continue  # keep the shallower (more direct) entry

        # Build dependency_path from parent_ids — use name-based path for clarity
        # parent_ids are IDs (ecosystem:name@version), extract names for the path
        dep_path = _extract_path_names(dep)

        context_map[dep.name] = DependencyContext(
            direct=dep.direct,
            transitive=dep.transitive,
            depth=dep.depth,
            parent=dep.parent_ids[0].split(":")[1].split("@")[0] if dep.parent_ids else None,
            dependency_path=dep_path,
        )
        depth_tracker[dep.name] = dep.depth

    return context_map


def _extract_path_names(dep: Dependency) -> list[str]:
    """
    Extract a human-readable dependency path for a dependency.

    For direct dependencies: [dep.name]
    For transitive: parent names would require graph traversal —
    we use the parent_ids to build a simple path for now.
    """
    if not dep.parent_ids:
        return [dep.name]
    # Build path: extract package name from parent ID format "ecosystem:name@version"
    path_parts = []
    for pid in dep.parent_ids:
        try:
            name_part = pid.split(":")[1].split("@")[0]
            path_parts.append(name_part)
        except (IndexError, AttributeError):
            pass
    path_parts.append(dep.name)
    return path_parts
