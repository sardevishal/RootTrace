"""
tests/test_error_isolation.py

Validates Task 11 (Error Isolation) and OSV Semantics.
Proves that one failed vulnerability lookup does not stop the entire scan,
and that partial failures result in correct scan_status and source_status.
"""

import pytest
from unittest.mock import patch
from app.models.package import Package
from app.services.vulnerability.engine import VulnerabilityEngine
from app.clients.osv_client import OSVClientError


def test_osv_partial_failure_error_isolation():
    """
    Test scenario:
      Package A → OSV → success (vulns found)
      Package B → OSV → success (0 vulns)
      Package C → OSV → NETWORK ERROR
      Package D → OSV → success (vulns found)

    Expected:
      - A's result is preserved
      - B's result is preserved
      - C's failure is recorded in source_errors
      - D is still processed
      - total_packages_scanned = 4
      - total_vulnerabilities_found = 2
      - source_status["OSV"] = "partial"
      - scan_status = "completed_with_warnings"
    """
    packages = [
        Package(package_name="pkg-a", version="1.0.0", ecosystem="npm"),
        Package(package_name="pkg-b", version="1.0.0", ecosystem="npm"),
        Package(package_name="pkg-c", version="1.0.0", ecosystem="npm"),
        Package(package_name="pkg-d", version="1.0.0", ecosystem="npm"),
    ]

    engine = VulnerabilityEngine()
    
    class DummyPackageProvider:
        def __init__(self, pkgs):
            self.pkgs = pkgs
        def get_packages(self, scan_id=None):
            return self.pkgs
            
    provider = DummyPackageProvider(packages)

    def mock_query(package_name, version, ecosystem):
        if package_name == "pkg-a":
            return [{"id": "GHSA-A", "summary": "Vuln A", "affected": [{"package": {"name": "pkg-a"}, "versions": ["1.0.0"]}]}]
        elif package_name == "pkg-b":
            return []
        elif package_name == "pkg-c":
            raise OSVClientError("Network error occurred", error_type="network", status_code=None)
        elif package_name == "pkg-d":
            return [{"id": "GHSA-D", "summary": "Vuln D", "affected": [{"package": {"name": "pkg-d"}, "versions": ["1.0.0"]}]}]
        return []

    with patch("app.clients.osv_client.OSVClient.query", side_effect=mock_query):
        result = engine.run_scan(package_provider=provider)

        # Overall scan assertions
        assert result.status == "completed_with_warnings"
        assert result.source_status["OSV"] == "partial"
        assert result.total_packages_scanned == 4
        assert result.total_vulnerabilities_found == 2
        assert len(result.source_errors) == 1
        assert result.source_errors[0].source == "OSV"
        assert result.source_errors[0].error_type == "network"

        # Per-package assertions
        # pkg-a
        assert result.packages[0].package_name == "pkg-a"
        assert result.packages[0].vulnerability_count == 1
        assert len(result.packages[0].source_errors) == 0

        # pkg-b
        assert result.packages[1].package_name == "pkg-b"
        assert result.packages[1].vulnerability_count == 0
        assert len(result.packages[1].source_errors) == 0

        # pkg-c
        assert result.packages[2].package_name == "pkg-c"
        assert result.packages[2].vulnerability_count == 0
        assert len(result.packages[2].source_errors) == 1
        assert result.packages[2].source_errors[0].error_type == "network"

        # pkg-d
        assert result.packages[3].package_name == "pkg-d"
        assert result.packages[3].vulnerability_count == 1
        assert len(result.packages[3].source_errors) == 0


def test_osv_total_success():
    """
    OSV -> 200 for all packages.
    Expected: source_status OSV = ok, scan_status = completed
    """
    packages = [
        Package(package_name="pkg-a", version="1.0.0", ecosystem="npm"),
    ]
    engine = VulnerabilityEngine()
    
    class DummyPackageProvider:
        def __init__(self, pkgs):
            self.pkgs = pkgs
        def get_packages(self, scan_id=None):
            return self.pkgs
            
    provider = DummyPackageProvider(packages)
    
    with patch("app.clients.osv_client.OSVClient.query", return_value=[]):
        result = engine.run_scan(package_provider=provider)
        assert result.status == "completed"
        assert result.source_status["OSV"] == "ok"


def test_osv_total_failure():
    """
    OSV -> 500 for all packages.
    Expected: source_status OSV = unavailable, scan_status = completed_with_warnings
    """
    packages = [
        Package(package_name="pkg-a", version="1.0.0", ecosystem="npm"),
        Package(package_name="pkg-b", version="1.0.0", ecosystem="npm"),
    ]
    engine = VulnerabilityEngine()
    
    class DummyPackageProvider:
        def __init__(self, pkgs):
            self.pkgs = pkgs
        def get_packages(self, scan_id=None):
            return self.pkgs
            
    provider = DummyPackageProvider(packages)
    
    with patch("app.clients.osv_client.OSVClient.query", side_effect=OSVClientError("Timeout", error_type="timeout")):
        result = engine.run_scan(package_provider=provider)
        assert result.status == "completed_with_warnings"
        assert result.source_status["OSV"] == "unavailable"
        assert len(result.source_errors) == 2
