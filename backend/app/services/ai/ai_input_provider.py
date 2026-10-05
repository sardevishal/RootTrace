"""
services/ai/ai_input_provider.py

Provider for AI Security Analysis Input - P2F.

This service fetches the canonical VulnerabilityFindings, prioritizes them,
applies the context limit, and builds the AIAnalysisInput.
"""

from typing import Optional
from app.models.ai_analysis import (
    AIAnalysisInput,
    AIAnalysisContext,
    build_summary,
    prioritize_findings,
)
from app.services.vulnerability.providers.finding_provider import VulnerabilityFindingProvider
from app.models.vulnerability_finding import DependencyContext
from app.services.vulnerability.package_provider import PackageProvider
from app.utils.logger import get_logger

logger = get_logger(__name__)


class SecurityAnalysisInputProvider:
    """
    Interface for providing canonical input to the AI Security Analysis module.
    """

    def __init__(self, finding_provider: Optional[VulnerabilityFindingProvider] = None):
        self._finding_provider = finding_provider or VulnerabilityFindingProvider()

    def get_analysis_input(
        self,
        package_provider: Optional[PackageProvider] = None,
        dep_context_map: Optional[dict[str, DependencyContext]] = None,
        scan_id: Optional[str] = None,
        max_findings: int = 50,
    ) -> AIAnalysisInput:
        """
        Produce a normalized AIAnalysisInput.

        Args:
            package_provider: Package provider (for finding provider).
            dep_context_map: Dependency context map.
            scan_id: Unique scan run identifier.
            max_findings: Configurable context limit (default: 50).
        """
        logger.info(
            "SecurityAnalysisInputProvider | get_analysis_input() scan_id=%s max_findings=%d",
            scan_id or "N/A", max_findings
        )
        
        # 1. Fetch canonical findings
        finding_result = self._finding_provider.get_findings(
            package_provider=package_provider,
            dep_context_map=dep_context_map,
            scan_id=scan_id,
        )
        all_findings = finding_result.findings
        
        # 2. Build summary from all findings (before limiting)
        summary = build_summary(all_findings)
        
        # 3. Prioritize findings deterministically
        prioritized = prioritize_findings(all_findings)
        
        # 4. Apply context limit
        total_findings = len(prioritized)
        included_findings = min(total_findings, max_findings)
        omitted_findings = total_findings - included_findings
        
        selected_findings = prioritized[:included_findings]
        
        context = AIAnalysisContext(
            total_findings=total_findings,
            included_findings=included_findings,
            omitted_findings=omitted_findings,
        )
        
        logger.info(
            "SecurityAnalysisInputProvider | Total findings: %d, Included: %d, Omitted: %d",
            total_findings, included_findings, omitted_findings
        )
        
        return AIAnalysisInput(
            contract_version="1.0",
            scan_id=finding_result.scan_id,
            summary=summary,
            findings=selected_findings,
            context=context,
        )
