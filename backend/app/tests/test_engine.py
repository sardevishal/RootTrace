"""
tests/test_engine.py

Unit tests for the Vulnerability Intelligence Engine — Phase 1.

Tests cover:
    - mock_loader: JSON loading and validation
    - validator: valid/invalid package detection
    - risk_score: CVSS-based scoring
    - engine: full end-to-end scan with mock data
    - API endpoint: /api/v1/vulnerabilities health check

Run with:
    cd backend
    pytest app/tests/ -v
"""

import json
import os
import tempfile
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models.package import Package
from app.models.vulnerability import Vulnerability
from app.services.vulnerability.mock_loader import load_mock_packages
from app.services.vulnerability.validator import validate_packages
from app.services.vulnerability.risk_score import calculate_risk
from app.services.vulnerability.engine import VulnerabilityEngine


# ─── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def valid_packages() -> list[Package]:
    return [
        Package(package_name="lodash", version="4.17.15", ecosystem="npm"),
        Package(package_name="requests", version="2.25.0", ecosystem="PyPI"),
    ]


@pytest.fixture
def sample_vulnerability() -> Vulnerability:
    return Vulnerability(
        cve_id="CVE-2021-44228",
        osv_id="GHSA-jfh8-c2jp-hdp8",
        title="Log4Shell",
        package_name="log4j-core",
        ecosystem="Maven",
        severity="CRITICAL",
        cvss_score=10.0,
    )


@pytest.fixture
def api_client() -> TestClient:
    return TestClient(app)


# ─── mock_loader tests ────────────────────────────────────────────────────────

class TestMockLoader:
    def test_load_valid_json(self, tmp_path):
        """Should load and validate all valid packages from JSON."""
        data = [
            {"package_name": "lodash", "version": "4.17.15", "ecosystem": "npm"},
            {"package_name": "requests", "version": "2.25.0", "ecosystem": "PyPI"},
        ]
        json_file = tmp_path / "packages.json"
        json_file.write_text(json.dumps(data), encoding="utf-8")

        packages = load_mock_packages(str(json_file))
        assert len(packages) == 2
        assert packages[0].package_name == "lodash"
        assert packages[1].ecosystem == "PyPI"

    def test_skips_invalid_entry(self, tmp_path):
        """Should skip entries with unsupported ecosystems."""
        data = [
            {"package_name": "lodash", "version": "4.17.15", "ecosystem": "npm"},
            {"package_name": "bad-pkg", "version": "1.0.0", "ecosystem": "FakeEcosystem"},
        ]
        json_file = tmp_path / "packages.json"
        json_file.write_text(json.dumps(data), encoding="utf-8")

        packages = load_mock_packages(str(json_file))
        assert len(packages) == 1
        assert packages[0].package_name == "lodash"

    def test_raises_file_not_found(self):
        """Should raise FileNotFoundError for non-existent path."""
        with pytest.raises(FileNotFoundError):
            load_mock_packages("/non/existent/path/packages.json")


# ─── validator tests ──────────────────────────────────────────────────────────

class TestValidator:
    def test_all_valid(self, valid_packages):
        """All valid packages should pass validation."""
        valid, errors = validate_packages(valid_packages)
        assert len(valid) == 2
        assert len(errors) == 0

    def test_rejects_invalid_ecosystem(self):
        """Packages with unsupported ecosystems should fail at model level."""
        with pytest.raises(Exception):
            Package(package_name="bad", version="1.0.0", ecosystem="FakeEco")

    def test_rejects_blank_version(self):
        """Packages with blank versions should fail at model level."""
        with pytest.raises(Exception):
            Package(package_name="lodash", version="   ", ecosystem="npm")

    def test_empty_list(self):
        """Empty input should return empty valid list and no errors."""
        valid, errors = validate_packages([])
        assert valid == []
        assert errors == []


# ─── risk_score tests ─────────────────────────────────────────────────────────

class TestRiskScore:
    def test_critical_cvss(self, sample_vulnerability):
        """CVSS 10.0 should produce CRITICAL risk label."""
        result = calculate_risk(sample_vulnerability)
        assert result.risk_label == "CRITICAL"
        assert result.risk_score == 10.0

    def test_high_cvss(self):
        """CVSS 8.5 should produce HIGH risk label."""
        vuln = Vulnerability(
            package_name="test-pkg", ecosystem="npm", cvss_score=8.5
        )
        result = calculate_risk(vuln)
        assert result.risk_label == "HIGH"

    def test_medium_cvss(self):
        """CVSS 5.0 should produce MEDIUM risk label."""
        vuln = Vulnerability(
            package_name="test-pkg", ecosystem="npm", cvss_score=5.0
        )
        result = calculate_risk(vuln)
        assert result.risk_label == "MEDIUM"

    def test_low_cvss(self):
        """CVSS 2.0 should produce LOW risk label."""
        vuln = Vulnerability(
            package_name="test-pkg", ecosystem="npm", cvss_score=2.0
        )
        result = calculate_risk(vuln)
        assert result.risk_label == "LOW"

    def test_no_cvss_unknown(self):
        """No CVSS score with UNKNOWN severity should produce UNKNOWN risk label."""
        vuln = Vulnerability(
            package_name="test-pkg", ecosystem="npm", cvss_score=None, severity="UNKNOWN"
        )
        result = calculate_risk(vuln)
        assert result.risk_label == "UNKNOWN"

    def test_no_cvss_with_severity_fallback(self):
        """No CVSS score but CRITICAL severity should map to CRITICAL."""
        vuln = Vulnerability(
            package_name="test-pkg", ecosystem="npm", cvss_score=None, severity="CRITICAL"
        )
        result = calculate_risk(vuln)
        assert result.risk_label == "CRITICAL"


# ─── API endpoint tests ───────────────────────────────────────────────────────

class TestAPI:
    def test_health_check(self, api_client):
        """Health endpoint should return 200 with status ok."""
        response = api_client.get("/api/v1/vulnerabilities/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["phase"] == 1

    def test_root_endpoint(self, api_client):
        """Root endpoint should confirm service is running."""
        response = api_client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["project"] == "RootTrace"
        assert data["status"] == "running"

    def test_vulnerabilities_returns_200(self, api_client):
        """
        GET /api/v1/vulnerabilities should return 200 and a valid response shape.
        (OSV will be called — in CI/offline, may return 0 vulns but no crash.)
        """
        response = api_client.get("/api/v1/vulnerabilities")
        assert response.status_code == 200
        data = response.json()
        assert "total_packages_scanned" in data
        assert "total_vulnerabilities_found" in data
        assert "packages" in data
        assert isinstance(data["packages"], list)


# ─── engine integration test ──────────────────────────────────────────────────

class TestEngine:
    def test_run_scan_returns_response(self, valid_packages):
        """Engine should return a VulnerabilityResponse with correct package count."""
        engine = VulnerabilityEngine()
        result = engine.run_scan(packages=valid_packages)
        assert result.total_packages_scanned == 2
        assert isinstance(result.packages, list)
        assert len(result.packages) == 2

    def test_run_scan_no_crash_on_empty(self):
        """Engine should handle zero valid packages gracefully."""
        engine = VulnerabilityEngine()
        result = engine.run_scan(packages=[])
        assert result.total_packages_scanned == 0
        assert result.total_vulnerabilities_found == 0
