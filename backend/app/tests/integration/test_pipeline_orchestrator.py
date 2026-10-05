"""
tests/integration/test_pipeline_orchestrator.py

Validates the full E2E pipeline via PipelineOrchestrator.
Covers:
- Task 7 (scan_id E2E propagation)
- Task 5, 6, 8 (Paths, Depth, Deduplication, Cycle Protection)
- Task 10, 11 (Vulnerability partial failure handled in E2E)
"""

import os
import pytest
from unittest.mock import patch
from app.services.pipeline import PipelineOrchestrator
from app.clients.osv_client import OSVClientError
from app.models.dependency_scan import DependencyScanResult
from app.models.dependency_graph import DependencyGraph, DependencyNode
from app.models.dependency import Dependency

@pytest.fixture
def fixtures_path() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "test_fixtures"))

def test_pipeline_scan_id_propagation(fixtures_path):
    """
    Task 7: Verify that a single scan_id survives the entire pipeline
    from Dependency Engine -> Graph -> Vulnerability Engine -> Final output.
    """
    scan_id = "test-scan-001"
    orchestrator = PipelineOrchestrator()
    
    with patch("app.clients.osv_client.OSVClient.query", return_value=[]):
        result = orchestrator.run_pipeline(fixtures_path, scan_id=scan_id)
        
        assert result.scan_id == scan_id
        assert result.dependency_scan.scan_id == scan_id
        assert result.vulnerability_scan.scan_id == scan_id
        
def test_pipeline_cycle_protection():
    """
    Verify DFS path computation does not hang when graphs contain cycles.
    """
    # Mocking DependencyScanResult to inject a cyclic graph
    scan_result = DependencyScanResult(scan_id="cyc-01", repository_path=".")
    
    from app.services.dependency.graph_builder import ROOT_NODE_ID
    
    graph = DependencyGraph()
    # A -> B -> C -> A
    for nid in ["npm:A@1.0", "npm:B@1.0", "npm:C@1.0"]:
        graph.nodes[nid] = DependencyNode(id=nid, name=nid.split(":")[1].split("@")[0], ecosystem="npm", source_manifest="pkg.json", source_path="pkg.json")
    
    graph.adjacency = {
        ROOT_NODE_ID: ["npm:A@1.0"],
        "npm:A@1.0": ["npm:B@1.0"],
        "npm:B@1.0": ["npm:C@1.0"],
        "npm:C@1.0": ["npm:A@1.0"], # Cycle
    }
    scan_result.graph = graph
    scan_result.normalized_packages = [
        Dependency(id="npm:A@1.0", name="A", version="1.0", ecosystem="npm", source_manifest="pkg.json", source_path="pkg.json", depth=1),
        Dependency(id="npm:B@1.0", name="B", version="1.0", ecosystem="npm", source_manifest="pkg.json", source_path="pkg.json", depth=2),
        Dependency(id="npm:C@1.0", name="C", version="1.0", ecosystem="npm", source_manifest="pkg.json", source_path="pkg.json", depth=3),
    ]
    
    orchestrator = PipelineOrchestrator()
    paths = orchestrator._compute_paths(scan_result.graph)
    
    # Should not hang, and should return paths
    assert "npm:A@1.0" in paths
    assert "npm:B@1.0" in paths
    assert "npm:C@1.0" in paths
    
    # Path to C should be root -> A -> B -> C
    assert len(paths["npm:C@1.0"]) > 0
    assert paths["npm:C@1.0"][0] == ["npm:A@1.0", "npm:B@1.0", "npm:C@1.0"]

def test_pipeline_partial_failure(fixtures_path):
    """
    Task 11 / Task 8: E2E partial failure simulation.
    Some fail, some succeed. Overall scan completes with warnings.
    """
    orchestrator = PipelineOrchestrator()
    
    def mock_query(package_name, version, ecosystem):
        if package_name == "lodash":
            return [{"id": "GHSA-lodash", "summary": "Vuln", "affected": [{"package": {"name": "lodash"}, "versions": [version]}]}]
        elif package_name == "express":
            raise OSVClientError("Timeout", error_type="timeout", status_code=504)
        return []

    from app.services.vulnerability.sources.osv_source import OSVSource
    from app.services.vulnerability.fetcher import VulnerabilityFetcher
    from app.services.vulnerability.engine import VulnerabilityEngine

    test_engine = VulnerabilityEngine()
    test_engine._fetcher = VulnerabilityFetcher(sources=[OSVSource()])

    with patch("app.clients.osv_client.OSVClient.query", side_effect=mock_query):
        with patch("app.services.pipeline.VulnerabilityEngine", return_value=test_engine):
            result = orchestrator.run_pipeline(fixtures_path)
        
        # express fails, lodash succeeds. Other packages have no vulns.
        # So we should get a warning.
        assert result.vulnerability_scan.status == "completed_with_warnings"
        assert result.vulnerability_scan.source_status["OSV"] == "partial"
        
        # Check that lodash has a vuln, express has an error
        pkgs = {p.package_name: p for p in result.vulnerability_scan.packages}
        
        if "lodash" in pkgs:
            assert pkgs["lodash"].vulnerability_count >= 1
            
        if "express" in pkgs:
            assert len(pkgs["express"].source_errors) == 1
            assert pkgs["express"].source_errors[0].error_type == "timeout"
