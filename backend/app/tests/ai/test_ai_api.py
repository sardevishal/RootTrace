"""
tests/ai/test_ai_api.py

Tests for the AI Security Analysis input API endpoint.
"""

from fastapi.testclient import TestClient
from unittest.mock import patch

from app.main import app
from app.models.ai_analysis import AIAnalysisInput, AIAnalysisSummary, AIAnalysisContext
from app.models.vulnerability_finding import VulnerabilityFinding, DependencyContext

client = TestClient(app)

def _mock_ai_analysis_input():
    f = VulnerabilityFinding(
        finding_id="123",
        package_name="lodash",
        ecosystem="npm",
        dependency=DependencyContext(direct=True),
        risk_label="HIGH"
    )
    return AIAnalysisInput(
        contract_version="1.0",
        scan_id="scan-xyz",
        summary=AIAnalysisSummary(total_findings=1, high=1, direct_dependencies=1, affected_packages=1),
        findings=[f],
        context=AIAnalysisContext(total_findings=1, included_findings=1, omitted_findings=0)
    )

def test_get_ai_analysis_input_success():
    with patch("app.api.ai_analysis._provider.get_analysis_input", return_value=_mock_ai_analysis_input()):
        response = client.get("/api/v1/ai-analysis/input?max_findings=10")
        assert response.status_code == 200
        data = response.json()
        assert data["contract_version"] == "1.0"
        assert data["scan_id"] == "scan-xyz"
        assert data["summary"]["total_findings"] == 1
        assert data["summary"]["high"] == 1
        assert data["context"]["included_findings"] == 1
        assert data["context"]["omitted_findings"] == 0
        assert len(data["findings"]) == 1
        assert data["findings"][0]["finding_id"] == "123"

def test_get_ai_analysis_input_error():
    with patch("app.api.ai_analysis._provider.get_analysis_input", side_effect=RuntimeError("Some error")):
        response = client.get("/api/v1/ai-analysis/input?max_findings=10")
        assert response.status_code == 500
        assert "Some error" in response.json()["detail"]
