"""
tests/ai/test_ai_input_contract.py

P2F - Tests for AI Security Analysis Input Foundation.
"""

import json
import pytest
from unittest.mock import MagicMock

from app.models.ai_analysis import (
    AIAnalysisInput,
    AIAnalysisContext,
    AIAnalysisSummary,
    build_summary,
    prioritize_findings,
)
from app.models.vulnerability_finding import VulnerabilityFinding, DependencyContext
from app.services.ai.ai_input_provider import SecurityAnalysisInputProvider
from app.schemas.ai_analysis_schema import AIAnalysisInputOut
from app.utils.constants import SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_LOW

def _create_finding(
    fid="1", 
    pkg="lodash", 
    risk=SEVERITY_HIGH, 
    risk_score=7.5,
    epss=0.1,
    cvss=7.5,
    direct=True,
    depth=0
):
    return VulnerabilityFinding(
        finding_id=fid,
        package_name=pkg,
        ecosystem="npm",
        dependency=DependencyContext(direct=direct, transitive=not direct, depth=depth),
        risk_label=risk,
        risk_score=risk_score,
        epss_score=epss,
        cvss_score=cvss,
    )

class TestAIAnalysisModels:
    def test_build_summary(self):
        f1 = _create_finding("1", "pkg1", SEVERITY_CRITICAL, direct=True)
        f2 = _create_finding("2", "pkg2", SEVERITY_HIGH, direct=False)
        f3 = _create_finding("3", "pkg1", SEVERITY_CRITICAL, direct=True)
        
        summary = build_summary([f1, f2, f3])
        
        assert summary.total_findings == 3
        assert summary.critical == 2
        assert summary.high == 1
        assert summary.medium == 0
        assert summary.low == 0
        assert summary.direct_dependencies == 2
        assert summary.transitive_dependencies == 1
        assert summary.affected_packages == 2

    def test_prioritize_findings(self):
        f_low = _create_finding("low", risk=SEVERITY_LOW, risk_score=2.0)
        f_high = _create_finding("high", risk=SEVERITY_HIGH, risk_score=7.0)
        f_crit = _create_finding("crit", risk=SEVERITY_CRITICAL, risk_score=9.5)
        
        # Should prioritize by risk_label then risk_score
        res = prioritize_findings([f_low, f_crit, f_high])
        assert [f.finding_id for f in res] == ["crit", "high", "low"]
        
        # Tie breaker on risk_score
        f_crit_2 = _create_finding("crit2", risk=SEVERITY_CRITICAL, risk_score=9.9)
        res = prioritize_findings([f_crit, f_crit_2])
        assert [f.finding_id for f in res] == ["crit2", "crit"]
        
        # Tie breaker on epss
        f_epss_1 = _create_finding("e1", risk=SEVERITY_HIGH, risk_score=7.5, epss=0.5)
        f_epss_2 = _create_finding("e2", risk=SEVERITY_HIGH, risk_score=7.5, epss=0.9)
        res = prioritize_findings([f_epss_1, f_epss_2])
        assert [f.finding_id for f in res] == ["e2", "e1"]
        
        # Tie breaker on direct dependency
        f_dir = _create_finding("dir", risk=SEVERITY_HIGH, risk_score=7.5, epss=0.5, direct=True)
        f_trans = _create_finding("trans", risk=SEVERITY_HIGH, risk_score=7.5, epss=0.5, direct=False)
        res = prioritize_findings([f_trans, f_dir])
        assert [f.finding_id for f in res] == ["dir", "trans"]


class TestSecurityAnalysisInputProvider:
    def test_context_limiting(self):
        findings = [_create_finding(str(i)) for i in range(100)]
        mock_finding_provider = MagicMock()
        mock_finding_result = MagicMock()
        mock_finding_result.findings = findings
        mock_finding_result.scan_id = "scan-123"
        mock_finding_provider.get_findings.return_value = mock_finding_result
        
        provider = SecurityAnalysisInputProvider(finding_provider=mock_finding_provider)
        
        result = provider.get_analysis_input(max_findings=30)
        
        assert len(result.findings) == 30
        assert result.context.total_findings == 100
        assert result.context.included_findings == 30
        assert result.context.omitted_findings == 70
        assert result.summary.total_findings == 100

class FakeSecurityAnalyzer:
    """Mock AI Consumer for integration testing."""
    def analyze(self, input_data: AIAnalysisInput) -> dict:
        highest_risk = "UNKNOWN"
        if input_data.summary.critical > 0:
            highest_risk = "CRITICAL"
        elif input_data.summary.high > 0:
            highest_risk = "HIGH"
            
        return {
            "scan_id": input_data.scan_id,
            "findings_analyzed": len(input_data.findings),
            "highest_risk": highest_risk,
            "status": "ready_for_ai_analysis"
        }

class TestMockAIConsumer:
    def test_fake_ai_consumer(self):
        f = _create_finding("1", risk=SEVERITY_CRITICAL)
        inp = AIAnalysisInput(
            scan_id="scan-xyz",
            summary=build_summary([f]),
            findings=[f],
            context=AIAnalysisContext(total_findings=1, included_findings=1, omitted_findings=0)
        )
        
        analyzer = FakeSecurityAnalyzer()
        res = analyzer.analyze(inp)
        
        assert res["scan_id"] == "scan-xyz"
        assert res["findings_analyzed"] == 1
        assert res["highest_risk"] == "CRITICAL"
        assert res["status"] == "ready_for_ai_analysis"

class TestAIAnalysisSerialization:
    def test_ai_analysis_schema_out(self):
        f = _create_finding("1", "pkg", risk=SEVERITY_HIGH)
        inp = AIAnalysisInput(
            scan_id="scan-xyz",
            summary=build_summary([f]),
            findings=[f],
            context=AIAnalysisContext(total_findings=1, included_findings=1, omitted_findings=0)
        )
        
        # Dump input into dict, we just need to ensure the schema can accept it
        # Note findings needs to be processed to API schema out via _finding_to_out if we do exactly what router does
        # Let's just test that the schema is correct.
        from app.api.findings import _finding_to_out
        
        findings_out = [_finding_to_out(item) for item in inp.findings]
        
        out = AIAnalysisInputOut(
            contract_version=inp.contract_version,
            scan_id=inp.scan_id,
            summary=inp.summary.model_dump(),
            findings=findings_out,
            context=inp.context.model_dump()
        )
        
        data = json.loads(out.model_dump_json())
        assert data["contract_version"] == "1.0"
        assert data["scan_id"] == "scan-xyz"
        assert data["summary"]["high"] == 1
        assert data["context"]["included_findings"] == 1
        assert len(data["findings"]) == 1
