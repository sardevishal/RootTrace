"""
tests/ai/test_p2g_e2e_verify.py

P2G Manual E2E Verification Test.

Runs as a standard pytest test — validates the complete mock pipeline
end-to-end and verifies all P2G safety boundaries.
"""

import json
import pytest

from app.models.vulnerability_finding import VulnerabilityFinding, DependencyContext
from app.models.ai_analysis import (
    AIAnalysisInput, AIAnalysisContext, AIAnalysisSummary, build_summary,
)
from app.services.ai.mock_llm_provider import MockLLMProvider
from app.services.ai.security_analysis_service import SecurityAnalysisService
from app.models.ai_analysis_result import (
    AI_STATUS_COMPLETED, AI_STATUS_COMPLETED_WITH_WARNINGS,
    AI_STATUS_UNAVAILABLE, AI_STATUS_FAILED,
)

SCAN_ID = "verify-scan-001"


def _build_test_findings():
    return [
        VulnerabilityFinding(
            finding_id="f-critical-001",
            scan_id=SCAN_ID,
            package_name="lodash",
            version="4.17.15",
            ecosystem="npm",
            cve_id="CVE-2021-23337",
            severity="CRITICAL",
            risk_label="CRITICAL",
            risk_score=9.5,
            cvss_score=9.8,
            epss_score=0.75,
            fixed_version="4.17.21",
            source="COMBINED",
            sources_contributing=["OSV", "NVD", "GITHUB_ADVISORY"],
            dependency=DependencyContext(direct=True, transitive=False, depth=0),
        ),
        VulnerabilityFinding(
            finding_id="f-high-002",
            scan_id=SCAN_ID,
            package_name="express",
            version="4.18.1",
            ecosystem="npm",
            cve_id=None,
            osv_id="GHSA-rv95-896h-c2vc",
            severity="HIGH",
            risk_label="HIGH",
            risk_score=7.0,
            cvss_score=7.5,
            epss_score=None,
            fixed_version=None,
            source="GITHUB_ADVISORY",
            sources_contributing=["GITHUB_ADVISORY"],
            dependency=DependencyContext(
                direct=False, transitive=True, depth=2,
                parent="body-parser",
                dependency_path=["root-project", "body-parser", "express"],
            ),
        ),
    ]


def _build_test_input(findings=None):
    fs = findings if findings is not None else _build_test_findings()
    return AIAnalysisInput(
        scan_id=SCAN_ID,
        summary=build_summary(fs),
        findings=fs,
        context=AIAnalysisContext(
            total_findings=len(fs),
            included_findings=len(fs),
            omitted_findings=0,
        ),
    )


class TestP2GE2EVerification:
    """
    Full end-to-end mock verification of P2G AI Security Analysis Engine.

    This test class is the authoritative P2G acceptance test.
    All checks must pass for P2G to be considered COMPLETE.
    """

    def test_e2e_successful_analysis(self):
        """Full happy-path: findings → AI analysis → result."""
        findings = _build_test_findings()
        ai_input = _build_test_input(findings)
        svc = SecurityAnalysisService(
            llm_provider=MockLLMProvider(
                finding_ids_override=["f-critical-001", "f-high-002"]
            )
        )
        result = svc.analyze(ai_input)

        assert result.ai_status == AI_STATUS_COMPLETED
        assert result.total_findings_analyzed == 2
        assert len(result.finding_analyses) == 2
        assert result.executive_summary is not None
        assert result.overall_risk in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
        assert result.llm_provider == "MockLLMProvider"

    def test_e2e_scan_id_preserved(self):
        """scan_id must be identical from input to output."""
        ai_input = _build_test_input()
        svc = SecurityAnalysisService(
            llm_provider=MockLLMProvider(
                finding_ids_override=["f-critical-001", "f-high-002"]
            )
        )
        result = svc.analyze(ai_input)
        assert result.scan_id == SCAN_ID

    def test_e2e_finding_id_preserved(self):
        """Every AIFindingAnalysis must map to a valid VulnerabilityFinding.finding_id."""
        findings = _build_test_findings()
        valid_ids = {f.finding_id for f in findings}
        ai_input = _build_test_input(findings)
        svc = SecurityAnalysisService(
            llm_provider=MockLLMProvider(
                finding_ids_override=list(valid_ids)
            )
        )
        result = svc.analyze(ai_input)

        for fa in result.finding_analyses:
            assert fa.finding_id in valid_ids, (
                f"finding_id '{fa.finding_id}' is not in the original finding set"
            )

    def test_e2e_cvss_score_not_mutated(self):
        """AI analysis must NEVER modify CVSS score."""
        ai_input = _build_test_input()
        original_cvss = ai_input.findings[0].cvss_score
        svc = SecurityAnalysisService(
            llm_provider=MockLLMProvider(
                finding_ids_override=["f-critical-001", "f-high-002"]
            )
        )
        svc.analyze(ai_input)
        assert ai_input.findings[0].cvss_score == pytest.approx(original_cvss)

    def test_e2e_epss_score_not_mutated(self):
        """AI analysis must NEVER modify EPSS score."""
        ai_input = _build_test_input()
        original_epss = ai_input.findings[0].epss_score
        svc = SecurityAnalysisService(
            llm_provider=MockLLMProvider(
                finding_ids_override=["f-critical-001", "f-high-002"]
            )
        )
        svc.analyze(ai_input)
        assert ai_input.findings[0].epss_score == pytest.approx(original_epss)

    def test_e2e_risk_score_not_mutated(self):
        """AI analysis must NEVER modify risk_score."""
        ai_input = _build_test_input()
        original_risk = ai_input.findings[0].risk_score
        svc = SecurityAnalysisService(
            llm_provider=MockLLMProvider(
                finding_ids_override=["f-critical-001", "f-high-002"]
            )
        )
        svc.analyze(ai_input)
        assert ai_input.findings[0].risk_score == pytest.approx(original_risk)

    def test_e2e_fixed_version_not_mutated(self):
        """AI analysis must NEVER modify fixed_version."""
        ai_input = _build_test_input()
        assert ai_input.findings[0].fixed_version == "4.17.21"
        assert ai_input.findings[1].fixed_version is None
        svc = SecurityAnalysisService(
            llm_provider=MockLLMProvider(
                finding_ids_override=["f-critical-001", "f-high-002"]
            )
        )
        svc.analyze(ai_input)
        assert ai_input.findings[0].fixed_version == "4.17.21"
        assert ai_input.findings[1].fixed_version is None

    def test_e2e_risk_label_not_mutated(self):
        """AI analysis must NEVER modify risk_label."""
        ai_input = _build_test_input()
        original_label = ai_input.findings[0].risk_label
        svc = SecurityAnalysisService(
            llm_provider=MockLLMProvider(
                finding_ids_override=["f-critical-001", "f-high-002"]
            )
        )
        svc.analyze(ai_input)
        assert ai_input.findings[0].risk_label == original_label

    def test_e2e_source_not_mutated(self):
        """AI analysis must NEVER modify source attribution."""
        ai_input = _build_test_input()
        original_source = ai_input.findings[0].source
        original_contributing = list(ai_input.findings[0].sources_contributing)
        svc = SecurityAnalysisService(
            llm_provider=MockLLMProvider(
                finding_ids_override=["f-critical-001", "f-high-002"]
            )
        )
        svc.analyze(ai_input)
        assert ai_input.findings[0].source == original_source
        assert ai_input.findings[0].sources_contributing == original_contributing

    def test_e2e_timeout_failure_isolated(self):
        """LLM timeout must not affect vulnerability facts."""
        ai_input = _build_test_input()
        original_findings_count = len(ai_input.findings)
        svc = SecurityAnalysisService(llm_provider=MockLLMProvider(fail_with="timeout"))
        result = svc.analyze(ai_input)
        # AI is unavailable but input is unharmed
        assert result.ai_status == AI_STATUS_UNAVAILABLE
        assert result.scan_id == SCAN_ID
        assert result.ai_error is not None
        assert len(ai_input.findings) == original_findings_count

    def test_e2e_network_failure_isolated(self):
        """LLM network failure must not affect vulnerability facts."""
        ai_input = _build_test_input()
        svc = SecurityAnalysisService(llm_provider=MockLLMProvider(fail_with="network"))
        result = svc.analyze(ai_input)
        assert result.ai_status == AI_STATUS_UNAVAILABLE

    def test_e2e_invalid_json_returns_failed(self):
        """LLM returning invalid JSON produces ai_status=failed, not a crash."""
        ai_input = _build_test_input()
        svc = SecurityAnalysisService(llm_provider=MockLLMProvider(fail_with="invalid_json"))
        result = svc.analyze(ai_input)
        assert result.ai_status == AI_STATUS_FAILED
        assert result.ai_error is not None
        # Findings still accessible from the input
        assert len(ai_input.findings) == 2

    def test_e2e_fabricated_finding_id_discarded(self):
        """LLM returning unknown finding_id must be discarded — not passed to caller."""
        ai_input = _build_test_input()
        svc = SecurityAnalysisService(llm_provider=MockLLMProvider(fail_with="unknown_finding_id"))
        result = svc.analyze(ai_input)
        assert result.ai_status == AI_STATUS_COMPLETED_WITH_WARNINGS
        assert len(result.finding_analyses) == 0

    def test_e2e_no_findings_completes_cleanly(self):
        """Empty finding set returns completed with clean summary — no errors."""
        empty_input = AIAnalysisInput(
            scan_id="scan-empty",
            summary=AIAnalysisSummary(),
            findings=[],
            context=AIAnalysisContext(),
        )
        svc = SecurityAnalysisService(llm_provider=MockLLMProvider())
        result = svc.analyze(empty_input)
        assert result.ai_status == AI_STATUS_COMPLETED
        assert result.total_findings_analyzed == 0
        assert result.executive_summary is not None

    def test_e2e_no_cve_finding_analyzable(self):
        """GHSA-only finding with no CVE must be analyzable."""
        f = VulnerabilityFinding(
            finding_id="ghsa-no-cve",
            package_name="pkg",
            ecosystem="npm",
            cve_id=None,
            osv_id="GHSA-xxxx-0001",
            severity="MEDIUM",
        )
        ai_input = _build_test_input([f])
        svc = SecurityAnalysisService(
            llm_provider=MockLLMProvider(finding_ids_override=["ghsa-no-cve"])
        )
        result = svc.analyze(ai_input)
        assert result.ai_status == AI_STATUS_COMPLETED

    def test_e2e_transitive_dependency_path_preserved(self):
        """Transitive dependency context must be preserved through to the prompt."""
        from app.services.ai.prompt_builder import SecurityAnalysisPromptBuilder
        f = VulnerabilityFinding(
            finding_id="transitive-f",
            package_name="lodash",
            ecosystem="npm",
            cve_id="CVE-X",
            dependency=DependencyContext(
                direct=False, transitive=True, depth=3,
                parent="body-parser",
                dependency_path=["root", "express", "body-parser", "lodash"],
            ),
        )
        builder = SecurityAnalysisPromptBuilder()
        ai_input = _build_test_input([f])
        req = builder.build_request(ai_input)
        assert "transitive" in req.user_message.lower() or "false" in req.user_message.lower()
        assert "body-parser" in req.user_message

    def test_e2e_api_get_input_backward_compat(self):
        """GET /api/v1/ai-analysis/input must still work unchanged."""
        from fastapi.testclient import TestClient
        from app.main import app
        client = TestClient(app)
        resp = client.get("/api/v1/ai-analysis/input?max_findings=5")
        assert resp.status_code == 200
        data = resp.json()
        assert data["contract_version"] == "1.0"
        assert "findings" in data
        assert "summary" in data
        assert "context" in data

    def test_e2e_api_post_analyze_returns_valid_structure(self):
        """POST /api/v1/ai-analysis/analyze must return AIAnalysisResultOut schema."""
        from fastapi.testclient import TestClient
        from unittest.mock import patch
        from app.main import app

        mock_result = SecurityAnalysisService(
            llm_provider=MockLLMProvider(finding_ids_override=[])
        ).analyze(
            AIAnalysisInput(
                scan_id="api-test",
                summary=AIAnalysisSummary(),
                findings=[],
                context=AIAnalysisContext(),
            )
        )

        client = TestClient(app)
        with patch("app.api.ai_analysis._analysis_service.analyze", return_value=mock_result):
            with patch("app.api.ai_analysis._provider.get_analysis_input",
                       return_value=AIAnalysisInput(
                           scan_id="api-test",
                           summary=AIAnalysisSummary(),
                           findings=[],
                           context=AIAnalysisContext(),
                       )):
                resp = client.post("/api/v1/ai-analysis/analyze", json={"scan_id": "api-test"})

        assert resp.status_code == 200
        data = resp.json()
        required_fields = {"contract_version", "scan_id", "ai_status",
                           "total_findings_analyzed", "finding_analyses"}
        for field in required_fields:
            assert field in data, f"Missing required field: {field}"
