"""
tests/ai/test_p2g_security_analysis.py

P2G — Comprehensive AI Security Analysis Engine tests.

Covers:
    Basic:
        - one finding
        - multiple findings
        - no findings

    Risk:
        - CRITICAL / HIGH / MEDIUM / LOW risk label handling

    Dependency:
        - direct dependency
        - transitive dependency
        - deep transitive dependency

    Evidence:
        - CVE available / unavailable
        - EPSS available / unavailable
        - fixed_version available / unavailable
        - multiple sources / single source

    LLM:
        - successful response
        - timeout, network, rate_limit, auth, context_limit failures
        - invalid JSON
        - empty response
        - partial response
        - missing finding_id in LLM response
        - unknown/fabricated finding_id in LLM response

    Pipeline:
        - scan_id preserved end-to-end
        - finding_id preserved end-to-end
        - AI failure does NOT fail vulnerability scan

    API:
        - successful POST /analyze
        - provider failure returns 500

    Traceability:
        - every AIFindingAnalysis maps to a valid input finding_id
        - fabricated finding_ids are discarded
        - missing finding_ids are discarded
"""

import json
import pytest
from unittest.mock import MagicMock, patch

from app.models.ai_analysis import AIAnalysisInput, AIAnalysisContext, AIAnalysisSummary, build_summary
from app.models.ai_analysis_result import (
    AIAnalysisResult, AIFindingAnalysis,
    AI_STATUS_COMPLETED, AI_STATUS_COMPLETED_WITH_WARNINGS,
    AI_STATUS_FAILED, AI_STATUS_UNAVAILABLE,
)
from app.models.vulnerability_finding import VulnerabilityFinding, DependencyContext
from app.services.ai.llm_provider import LLMRequest, LLMResponse
from app.services.ai.mock_llm_provider import MockLLMProvider
from app.services.ai.prompt_builder import SecurityAnalysisPromptBuilder
from app.services.ai.security_analysis_service import SecurityAnalysisService
from app.utils.constants import (
    SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW,
)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _finding(
    fid: str = "abc123",
    pkg: str = "lodash",
    version: str = "4.17.15",
    ecosystem: str = "npm",
    cve_id: str = "CVE-2021-23337",
    severity: str = "HIGH",
    risk_label: str = SEVERITY_HIGH,
    risk_score: float = 7.5,
    cvss: float = 7.5,
    epss: float = 0.45,
    fixed_version: str = "4.17.21",
    source: str = "COMBINED",
    sources_contributing=None,
    direct: bool = True,
    depth: int = 0,
    dep_path=None,
) -> VulnerabilityFinding:
    return VulnerabilityFinding(
        finding_id=fid,
        scan_id="scan-test",
        package_name=pkg,
        version=version,
        ecosystem=ecosystem,
        cve_id=cve_id,
        severity=severity,
        risk_label=risk_label,
        risk_score=risk_score,
        cvss_score=cvss,
        epss_score=epss,
        fixed_version=fixed_version,
        source=source,
        sources_contributing=sources_contributing or ["OSV", "NVD"],
        dependency=DependencyContext(
            direct=direct,
            transitive=not direct,
            depth=depth,
            parent=None if direct else "express",
            dependency_path=dep_path or ([pkg] if direct else ["root", "express", pkg]),
        ),
    )


def _analysis_input(findings=None, scan_id="scan-test") -> AIAnalysisInput:
    fs = findings if findings is not None else [_finding()]
    return AIAnalysisInput(
        scan_id=scan_id,
        summary=build_summary(fs),
        findings=fs,
        context=AIAnalysisContext(
            total_findings=len(fs),
            included_findings=len(fs),
            omitted_findings=0,
        ),
    )


def _service(fail_with=None, finding_ids_override=None) -> SecurityAnalysisService:
    return SecurityAnalysisService(
        llm_provider=MockLLMProvider(
            fail_with=fail_with,
            finding_ids_override=finding_ids_override,
        )
    )


# ─── LLMProvider abstraction tests ───────────────────────────────────────────

class TestLLMProviderAbstraction:
    def test_mock_provider_has_provider_name(self):
        p = MockLLMProvider()
        assert p.provider_name == "MockLLMProvider"

    def test_mock_provider_returns_llm_response(self):
        p = MockLLMProvider()
        req = LLMRequest(system_prompt="sys", user_message="user")
        resp = p.generate(req)
        assert isinstance(resp, LLMResponse)

    def test_mock_provider_success_has_content(self):
        finding = _finding()
        p = MockLLMProvider(finding_ids_override=[finding.finding_id])
        req = LLMRequest(system_prompt="sys", user_message=json.dumps({"findings": [{"finding_id": finding.finding_id}]}))
        resp = p.generate(req)
        assert resp.success is True
        assert resp.content is not None
        data = json.loads(resp.content)
        assert "executive_summary" in data
        assert "overall_risk" in data
        assert "finding_analyses" in data


# ─── MockLLMProvider failure modes ───────────────────────────────────────────

class TestMockLLMProviderFailures:
    @pytest.mark.parametrize("fail_mode,expected_type", [
        ("timeout", "timeout"),
        ("network", "network"),
        ("rate_limit", "rate_limit"),
        ("auth", "auth"),
        ("context_limit", "context_limit"),
    ])
    def test_network_failures_return_failure_response(self, fail_mode, expected_type):
        p = MockLLMProvider(fail_with=fail_mode)
        resp = p.generate(LLMRequest(system_prompt="s", user_message="u"))
        assert resp.success is False
        assert resp.error_type == expected_type

    def test_invalid_json_returns_success_but_bad_content(self):
        p = MockLLMProvider(fail_with="invalid_json")
        resp = p.generate(LLMRequest(system_prompt="s", user_message="u"))
        assert resp.success is True
        with pytest.raises(json.JSONDecodeError):
            json.loads(resp.content)

    def test_empty_response(self):
        p = MockLLMProvider(fail_with="empty")
        resp = p.generate(LLMRequest(system_prompt="s", user_message="u"))
        assert resp.success is True
        assert resp.content == ""

    def test_partial_response(self):
        p = MockLLMProvider(fail_with="partial")
        resp = p.generate(LLMRequest(system_prompt="s", user_message="u"))
        assert resp.success is True
        data = json.loads(resp.content)
        assert "executive_summary" in data
        assert "finding_analyses" not in data  # partial — missing this key

    def test_invalid_failure_mode_raises(self):
        with pytest.raises(ValueError, match="Unknown failure mode"):
            MockLLMProvider(fail_with="not_a_real_mode")


# ─── PromptBuilder tests ──────────────────────────────────────────────────────

class TestPromptBuilder:
    def test_builds_llm_request(self):
        builder = SecurityAnalysisPromptBuilder()
        inp = _analysis_input()
        req = builder.build_request(inp)
        assert isinstance(req, LLMRequest)
        assert req.system_prompt
        assert req.user_message
        assert req.response_format == "json"

    def test_user_message_contains_finding_id(self):
        f = _finding(fid="find-001")
        builder = SecurityAnalysisPromptBuilder()
        req = builder.build_request(_analysis_input([f]))
        assert "find-001" in req.user_message

    def test_user_message_contains_scan_id(self):
        builder = SecurityAnalysisPromptBuilder()
        req = builder.build_request(_analysis_input(scan_id="scan-XYZ"))
        assert "scan-XYZ" in req.user_message

    def test_user_message_is_json_parseable_context(self):
        f = _finding(fid="f1", cvss=7.5, epss=0.45)
        builder = SecurityAnalysisPromptBuilder()
        req = builder.build_request(_analysis_input([f]))
        # Extract JSON block from message
        import re
        match = re.search(r'\{.*\}', req.user_message, re.DOTALL)
        assert match, "User message must contain a JSON block"
        data = json.loads(match.group())
        assert data["findings"][0]["finding_id"] == "f1"

    def test_evidence_confidence_high_when_all_data_present(self):
        f = _finding(cve_id="CVE-X", cvss=7.5, epss=0.45)
        builder = SecurityAnalysisPromptBuilder()
        serialized = builder._serialize_finding(1, f)
        assert serialized["evidence_confidence"] == "HIGH"

    def test_evidence_confidence_medium_when_no_epss(self):
        f = VulnerabilityFinding(
            finding_id="x", package_name="pkg", ecosystem="npm",
            cve_id="CVE-X", cvss_score=7.5, epss_score=None,
        )
        builder = SecurityAnalysisPromptBuilder()
        serialized = builder._serialize_finding(1, f)
        assert serialized["evidence_confidence"] == "MEDIUM"

    def test_evidence_confidence_low_when_no_cve_no_cvss(self):
        f = VulnerabilityFinding(
            finding_id="x", package_name="pkg", ecosystem="npm",
            cve_id=None, cvss_score=None, epss_score=None,
        )
        builder = SecurityAnalysisPromptBuilder()
        serialized = builder._serialize_finding(1, f)
        assert serialized["evidence_confidence"] == "LOW"

    def test_dependency_context_in_prompt(self):
        f = _finding(direct=False, depth=2, dep_path=["root", "express", "lodash"])
        builder = SecurityAnalysisPromptBuilder()
        serialized = builder._serialize_finding(1, f)
        assert serialized["dependency"]["direct"] is False
        assert serialized["dependency"]["depth"] == 2
        assert serialized["dependency"]["dependency_path"] == ["root", "express", "lodash"]


# ─── SecurityAnalysisService core tests ──────────────────────────────────────

class TestSecurityAnalysisService:

    def test_no_findings_returns_completed(self):
        svc = _service()
        result = svc.analyze(_analysis_input(findings=[]))
        assert result.ai_status == AI_STATUS_COMPLETED
        assert result.total_findings_analyzed == 0
        assert result.finding_analyses == []

    def test_one_finding_success(self):
        f = _finding(fid="find-001")
        svc = SecurityAnalysisService(
            llm_provider=MockLLMProvider(finding_ids_override=["find-001"])
        )
        result = svc.analyze(_analysis_input([f]))
        assert result.ai_status == AI_STATUS_COMPLETED
        assert result.total_findings_analyzed == 1
        assert len(result.finding_analyses) == 1
        assert result.finding_analyses[0].finding_id == "find-001"

    def test_multiple_findings_success(self):
        findings = [_finding(fid=f"f{i}") for i in range(5)]
        fids = [f.finding_id for f in findings]
        svc = SecurityAnalysisService(
            llm_provider=MockLLMProvider(finding_ids_override=fids)
        )
        result = svc.analyze(_analysis_input(findings))
        assert result.ai_status == AI_STATUS_COMPLETED
        assert result.total_findings_analyzed == 5
        assert len(result.finding_analyses) == 5

    def test_executive_summary_populated(self):
        f = _finding(fid="f1")
        svc = SecurityAnalysisService(
            llm_provider=MockLLMProvider(finding_ids_override=["f1"])
        )
        result = svc.analyze(_analysis_input([f]))
        assert result.executive_summary is not None
        assert len(result.executive_summary) > 0

    def test_overall_risk_populated(self):
        f = _finding(fid="f1")
        svc = SecurityAnalysisService(
            llm_provider=MockLLMProvider(finding_ids_override=["f1"])
        )
        result = svc.analyze(_analysis_input([f]))
        assert result.overall_risk in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")

    def test_scan_id_preserved(self):
        f = _finding(fid="f1")
        svc = SecurityAnalysisService(
            llm_provider=MockLLMProvider(finding_ids_override=["f1"])
        )
        result = svc.analyze(_analysis_input([f], scan_id="scan-preserve-test"))
        assert result.scan_id == "scan-preserve-test"

    def test_llm_provider_name_in_result(self):
        svc = SecurityAnalysisService(
            llm_provider=MockLLMProvider(finding_ids_override=[])
        )
        result = svc.analyze(_analysis_input([]))
        assert result.llm_provider == "MockLLMProvider"


# ─── LLM failure handling tests ───────────────────────────────────────────────

class TestAIFailureHandling:

    @pytest.mark.parametrize("fail_mode", ["timeout", "network", "rate_limit", "auth", "context_limit"])
    def test_llm_unavailable_returns_unavailable_status(self, fail_mode):
        svc = _service(fail_with=fail_mode)
        result = svc.analyze(_analysis_input([_finding()]))
        assert result.ai_status == AI_STATUS_UNAVAILABLE
        assert result.ai_error is not None

    def test_invalid_json_returns_failed(self):
        svc = _service(fail_with="invalid_json")
        result = svc.analyze(_analysis_input([_finding()]))
        assert result.ai_status == AI_STATUS_FAILED
        assert "JSON" in (result.ai_error or "") or result.ai_error is not None

    def test_empty_response_returns_failed(self):
        svc = _service(fail_with="empty")
        result = svc.analyze(_analysis_input([_finding()]))
        assert result.ai_status == AI_STATUS_FAILED

    def test_partial_response_is_graceful(self):
        # Partial response has no finding_analyses → completed with 0 analyses
        svc = _service(fail_with="partial")
        result = svc.analyze(_analysis_input([_finding()]))
        assert result.ai_status in (AI_STATUS_COMPLETED, AI_STATUS_COMPLETED_WITH_WARNINGS)
        assert result.executive_summary is not None  # partial had exec_summary

    def test_missing_finding_id_discarded(self):
        svc = _service(fail_with="missing_finding_id")
        result = svc.analyze(_analysis_input([_finding()]))
        # Entry without finding_id must be discarded
        assert len(result.finding_analyses) == 0
        assert result.ai_status == AI_STATUS_COMPLETED_WITH_WARNINGS

    def test_unknown_finding_id_discarded(self):
        svc = _service(fail_with="unknown_finding_id")
        result = svc.analyze(_analysis_input([_finding(fid="real-id")]))
        # LLM returned FABRICATED-ID-NOT-IN-INPUT — must be discarded
        assert len(result.finding_analyses) == 0
        assert result.ai_status == AI_STATUS_COMPLETED_WITH_WARNINGS

    def test_ai_failure_does_not_raise(self):
        """AI failures must NEVER propagate as exceptions."""
        svc = _service(fail_with="timeout")
        try:
            result = svc.analyze(_analysis_input([_finding()]))
            assert result.ai_status == AI_STATUS_UNAVAILABLE
        except Exception as exc:
            pytest.fail(f"AI failure should not raise, but got: {exc}")

    def test_unhandled_exception_returns_failed(self):
        """Even unhandled exceptions inside the service must be caught."""
        class BrokenProvider(MockLLMProvider):
            def generate(self, request):
                raise RuntimeError("Unexpected crash in provider")

        svc = SecurityAnalysisService(llm_provider=BrokenProvider())
        result = svc.analyze(_analysis_input([_finding()]))
        assert result.ai_status == AI_STATUS_FAILED
        assert result.ai_error is not None


# ─── Traceability tests ───────────────────────────────────────────────────────

class TestFindingTraceability:

    def test_every_analysis_has_finding_id(self):
        findings = [_finding(fid=f"f{i}") for i in range(3)]
        fids = [f.finding_id for f in findings]
        svc = SecurityAnalysisService(
            llm_provider=MockLLMProvider(finding_ids_override=fids)
        )
        result = svc.analyze(_analysis_input(findings))
        for fa in result.finding_analyses:
            assert fa.finding_id, "Every AIFindingAnalysis must have a finding_id"

    def test_all_finding_ids_in_valid_set(self):
        findings = [_finding(fid=f"f{i}") for i in range(3)]
        valid_ids = {f.finding_id for f in findings}
        fids = list(valid_ids)
        svc = SecurityAnalysisService(
            llm_provider=MockLLMProvider(finding_ids_override=fids)
        )
        result = svc.analyze(_analysis_input(findings))
        for fa in result.finding_analyses:
            assert fa.finding_id in valid_ids, (
                f"finding_id '{fa.finding_id}' not in original finding set"
            )

    def test_finding_id_joins_back_to_input(self):
        """Verify that every AIFindingAnalysis finding_id exists in the AIAnalysisInput."""
        findings = [
            _finding(fid="id-A"),
            _finding(fid="id-B"),
        ]
        svc = SecurityAnalysisService(
            llm_provider=MockLLMProvider(finding_ids_override=["id-A", "id-B"])
        )
        analysis_input = _analysis_input(findings)
        result = svc.analyze(analysis_input)

        input_finding_ids = {f.finding_id for f in analysis_input.findings}
        for fa in result.finding_analyses:
            assert fa.finding_id in input_finding_ids


# ─── Evidence / risk scenario tests ──────────────────────────────────────────

class TestEvidenceScenarios:

    def test_critical_finding_analyzable(self):
        f = _finding(fid="crit", severity="CRITICAL", risk_label=SEVERITY_CRITICAL, risk_score=9.8)
        svc = SecurityAnalysisService(llm_provider=MockLLMProvider(finding_ids_override=["crit"]))
        result = svc.analyze(_analysis_input([f]))
        assert result.ai_status == AI_STATUS_COMPLETED

    def test_no_cve_finding_analyzable(self):
        f = VulnerabilityFinding(
            finding_id="ghsa-only",
            package_name="pkg",
            ecosystem="npm",
            cve_id=None,
            osv_id="GHSA-abcd-0001",
            severity="MEDIUM",
        )
        svc = SecurityAnalysisService(
            llm_provider=MockLLMProvider(finding_ids_override=["ghsa-only"])
        )
        result = svc.analyze(_analysis_input([f]))
        assert result.ai_status == AI_STATUS_COMPLETED

    def test_no_epss_finding_analyzable(self):
        f = VulnerabilityFinding(
            finding_id="no-epss",
            package_name="pkg",
            ecosystem="npm",
            cve_id="CVE-2021-X",
            epss_score=None,
            cvss_score=7.5,
            severity="HIGH",
        )
        svc = SecurityAnalysisService(
            llm_provider=MockLLMProvider(finding_ids_override=["no-epss"])
        )
        result = svc.analyze(_analysis_input([f]))
        assert result.ai_status == AI_STATUS_COMPLETED

    def test_no_fixed_version_finding_analyzable(self):
        f = VulnerabilityFinding(
            finding_id="no-fix",
            package_name="pkg",
            ecosystem="npm",
            cve_id="CVE-2021-X",
            fixed_version=None,
            severity="HIGH",
        )
        svc = SecurityAnalysisService(
            llm_provider=MockLLMProvider(finding_ids_override=["no-fix"])
        )
        result = svc.analyze(_analysis_input([f]))
        assert result.ai_status == AI_STATUS_COMPLETED

    def test_transitive_finding_carries_dep_context(self):
        f = _finding(
            fid="transitive-1",
            direct=False,
            depth=3,
            dep_path=["root-project", "express", "body-parser", "lodash"],
        )
        builder = SecurityAnalysisPromptBuilder()
        serialized = builder._serialize_finding(1, f)
        assert serialized["dependency"]["transitive"] is True
        assert serialized["dependency"]["depth"] == 3
        assert serialized["dependency"]["dependency_path"] == [
            "root-project", "express", "body-parser", "lodash"
        ]

    def test_single_source_finding_analyzable(self):
        f = VulnerabilityFinding(
            finding_id="osv-only",
            package_name="pkg",
            ecosystem="npm",
            cve_id="CVE-X",
            source="OSV",
            sources_contributing=["OSV"],
            severity="LOW",
        )
        svc = SecurityAnalysisService(
            llm_provider=MockLLMProvider(finding_ids_override=["osv-only"])
        )
        result = svc.analyze(_analysis_input([f]))
        assert result.ai_status == AI_STATUS_COMPLETED

    def test_multiple_sources_finding_analyzable(self):
        f = _finding(source="COMBINED", sources_contributing=["OSV", "NVD", "GITHUB_ADVISORY"])
        svc = SecurityAnalysisService(
            llm_provider=MockLLMProvider(finding_ids_override=[f.finding_id])
        )
        result = svc.analyze(_analysis_input([f]))
        assert result.ai_status == AI_STATUS_COMPLETED


# ─── API endpoint tests ────────────────────────────────────────────────────────

class TestAIAnalysisAPI:
    def setup_method(self):
        from fastapi.testclient import TestClient
        from app.main import app
        self.client = TestClient(app)

    def test_post_analyze_success(self):
        f = _finding(fid="api-f1")
        mock_result = AIAnalysisResult(
            scan_id="scan-api",
            ai_status=AI_STATUS_COMPLETED,
            llm_provider="MockLLMProvider",
            executive_summary="Test summary.",
            overall_risk="HIGH",
            total_findings_analyzed=1,
            finding_analyses=[
                AIFindingAnalysis(
                    finding_id="api-f1",
                    explanation="Test explanation.",
                )
            ],
        )
        with patch("app.api.ai_analysis._analysis_service.analyze", return_value=mock_result):
            with patch("app.api.ai_analysis._provider.get_analysis_input",
                       return_value=_analysis_input([f], scan_id="scan-api")):
                resp = self.client.post(
                    "/api/v1/ai-analysis/analyze",
                    json={"scan_id": "scan-api", "max_findings": 10},
                )
        assert resp.status_code == 200
        data = resp.json()
        assert data["scan_id"] == "scan-api"
        assert data["ai_status"] == "completed"
        assert data["overall_risk"] == "HIGH"
        assert len(data["finding_analyses"]) == 1
        assert data["finding_analyses"][0]["finding_id"] == "api-f1"

    def test_post_analyze_provider_error_returns_500(self):
        with patch("app.api.ai_analysis._provider.get_analysis_input",
                   side_effect=RuntimeError("provider crashed")):
            resp = self.client.post(
                "/api/v1/ai-analysis/analyze",
                json={"scan_id": "scan-fail", "max_findings": 10},
            )
        assert resp.status_code == 500

    def test_get_input_still_works(self):
        """Backward compatibility: GET /input endpoint unchanged."""
        resp = self.client.get("/api/v1/ai-analysis/input?max_findings=1")
        assert resp.status_code == 200
        data = resp.json()
        assert "contract_version" in data
        assert "findings" in data


# ─── Pipeline integration test ─────────────────────────────────────────────────

class TestPipelineIntegration:
    """
    Verifies that scan_id and finding_id are preserved end-to-end
    through the full pipeline when AI analysis is included.
    Uses MockLLMProvider — no network calls.
    """

    def test_ai_analysis_does_not_change_scan_id(self):
        f = _finding(fid="pipeline-f1")
        ai_input = _analysis_input([f], scan_id="scan-pipeline-001")
        svc = SecurityAnalysisService(
            llm_provider=MockLLMProvider(finding_ids_override=["pipeline-f1"])
        )
        result = svc.analyze(ai_input)
        assert result.scan_id == "scan-pipeline-001"

    def test_ai_analysis_does_not_modify_risk_score(self):
        f = _finding(fid="pipeline-f2", risk_score=7.5)
        ai_input = _analysis_input([f])
        svc = SecurityAnalysisService(
            llm_provider=MockLLMProvider(finding_ids_override=["pipeline-f2"])
        )
        svc.analyze(ai_input)
        # The original finding in ai_input must be unchanged
        assert ai_input.findings[0].risk_score == pytest.approx(7.5)

    def test_ai_analysis_does_not_modify_fixed_version(self):
        f = _finding(fid="pipeline-f3", fixed_version="4.17.21")
        ai_input = _analysis_input([f])
        svc = SecurityAnalysisService(
            llm_provider=MockLLMProvider(finding_ids_override=["pipeline-f3"])
        )
        svc.analyze(ai_input)
        assert ai_input.findings[0].fixed_version == "4.17.21"

    def test_ai_failure_does_not_affect_finding_data(self):
        """AI failure status is isolated — the input findings must be unchanged."""
        f = _finding(fid="pipeline-f4", cvss=9.8)
        ai_input = _analysis_input([f])
        svc = _service(fail_with="timeout")
        result = svc.analyze(ai_input)
        assert result.ai_status == AI_STATUS_UNAVAILABLE
        # Input findings untouched
        assert ai_input.findings[0].cvss_score == pytest.approx(9.8)
        assert ai_input.findings[0].finding_id == "pipeline-f4"
