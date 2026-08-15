"""
tests/integration/test_dependency_integration.py

End-to-end integration tests for RootTrace Dependency Analysis Engine:
  1. Full scan on test_fixtures directory containing all 5 manifests + nested manifest
  2. Dependency graph construction and node/edge verification
  3. API endpoints: POST /api/v1/dependencies/analyze & GET /api/v1/dependencies/health
  4. Downstream integration adapter converting Dependency objects to Package objects
  5. Consuming output with VulnerabilityEngine.run_scan(packages=packages)
"""

import os
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services.dependency.engine import DependencyAnalysisEngine
from app.services.vulnerability.engine import VulnerabilityEngine
from app.models.dependency_scan import DependencyScanResult
from app.models.package import Package


@pytest.fixture
def fixtures_path() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "test_fixtures"))


@pytest.fixture
def api_client() -> TestClient:
    return TestClient(app)


class TestDependencyAnalysisIntegration:
    def test_full_repository_scan(self, fixtures_path):
        """
        Verify that the engine discovers all manifests, normalizes dependencies,
        builds the dependency graph, and produces a normalized package inventory.
        """
        engine = DependencyAnalysisEngine()
        result: DependencyScanResult = engine.analyze(fixtures_path)

        assert result.status in ("completed", "completed_with_warnings")
        assert result.manifests_found == 6
        assert result.manifests_parsed == 6
        assert result.total_dependencies > 10
        assert result.direct_dependencies > 0

        # Check that graph is populated
        assert len(result.graph.nodes) > 10
        assert len(result.graph.edges) > 0
        assert "npm" in result.graph.stats.ecosystems
        assert "PyPI" in result.graph.stats.ecosystems
        assert "Maven" in result.graph.stats.ecosystems
        assert "Go" in result.graph.stats.ecosystems

        # Check normalized package inventory
        assert len(result.normalized_packages) == result.total_dependencies
        pkg_names = [p.package_name for p in result.normalized_packages]
        assert "express" in pkg_names
        assert "lodash" in pkg_names
        assert "requests" in pkg_names
        assert "org.apache.logging.log4j:log4j-core" in pkg_names

    def test_api_dependency_endpoints(self, api_client, fixtures_path):
        """
        Test FastAPI endpoints:
        - GET /api/v1/dependencies/health
        - POST /api/v1/dependencies/analyze
        """
        # Health check
        health_resp = api_client.get("/api/v1/dependencies/health")
        assert health_resp.status_code == 200
        health_data = health_resp.json()
        assert health_data["status"] == "ok"
        assert health_data["module"] == "Dependency Analysis Engine"

        # Scan analyze endpoint
        scan_resp = api_client.post(
            "/api/v1/dependencies/analyze",
            json={"repository_path": fixtures_path, "scan_id": "test-int-scan-01"},
        )
        assert scan_resp.status_code == 200
        scan_data = scan_resp.json()

        assert scan_data["scan_id"] == "test-int-scan-01"
        assert scan_data["total_dependencies"] > 10
        assert scan_data["manifests_found"] == 6
        assert "graph" in scan_data
        assert "nodes" in scan_data["graph"]
        assert "edges" in scan_data["graph"]
        assert len(scan_data["normalized_packages"]) > 0

    def test_vulnerability_engine_compatibility(self, fixtures_path):
        """
        Verify downstream integration:
        Dependency Analysis Engine -> get_packages_for_vulnerability_scan() -> VulnerabilityEngine.run_scan()
        """
        dep_engine = DependencyAnalysisEngine()
        scan_result = dep_engine.analyze(fixtures_path)

        # Convert to downstream Package list
        packages: list[Package] = dep_engine.get_packages_for_vulnerability_scan(
            scan_result,
            include_unresolved=False,
        )

        assert len(packages) > 0
        for pkg in packages:
            assert isinstance(pkg, Package)
            assert pkg.package_name
            assert pkg.version
            assert pkg.ecosystem in ("npm", "PyPI", "Maven", "Go", "RubyGems", "NuGet", "crates.io", "Packagist")

        # Now pass directly to VulnerabilityEngine
        vuln_engine = VulnerabilityEngine()
        vuln_response = vuln_engine.run_scan(packages=packages, scan_id=scan_result.scan_id)

        assert vuln_response.total_packages_scanned == len(packages)
        assert isinstance(vuln_response.packages, list)
        assert len(vuln_response.packages) == len(packages)
