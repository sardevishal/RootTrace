"""
services/ai/mock_llm_provider.py

MockLLMProvider — P2G

A deterministic, offline LLM provider for testing.

This provider returns structured AI analysis WITHOUT:
    - Internet connection
    - API keys
    - Paid APIs
    - External services
    - Non-deterministic output

Output is clearly labeled as mock/test behavior.
The mock analysis reflects the actual finding data supplied to it
(severity, EPSS, fixed_version, etc.) to enable realistic test assertions,
but it NEVER invents factual security information.

Usage:
    provider = MockLLMProvider()
    response = provider.generate(request)
    # response.content is a deterministic JSON string

Failure simulation:
    provider = MockLLMProvider(fail_with="timeout")
    provider = MockLLMProvider(fail_with="network")
    provider = MockLLMProvider(fail_with="invalid_json")
    provider = MockLLMProvider(fail_with="empty")
    provider = MockLLMProvider(fail_with="partial")
"""

import json
from typing import Optional

from app.services.ai.llm_provider import LLMProvider, LLMRequest, LLMResponse
from app.utils.logger import get_logger

logger = get_logger(__name__)

# Valid failure modes for testing
VALID_FAILURE_MODES = frozenset({
    "timeout", "network", "rate_limit", "invalid_response",
    "context_limit", "auth", "invalid_json", "empty", "partial",
    "missing_finding_id", "unknown_finding_id",
})


class MockLLMProvider(LLMProvider):
    """
    Deterministic offline LLM provider for testing.

    DO NOT use in production. This provider's output is clearly labeled
    as mock analysis and should never be presented as real AI intelligence.

    Failure simulation is available for all error scenarios defined in P2G.
    """

    PROVIDER_NAME = "MockLLMProvider"

    def __init__(
        self,
        fail_with: Optional[str] = None,
        finding_ids_override: Optional[list[str]] = None,
    ) -> None:
        """
        Args:
            fail_with: Simulate a specific failure mode. None = success.
            finding_ids_override: Override finding IDs in the mock response (for testing).
        """
        if fail_with and fail_with not in VALID_FAILURE_MODES:
            raise ValueError(
                f"Unknown failure mode '{fail_with}'. "
                f"Valid modes: {sorted(VALID_FAILURE_MODES)}"
            )
        self._fail_with = fail_with
        self._finding_ids_override = finding_ids_override

    @property
    def provider_name(self) -> str:
        return self.PROVIDER_NAME

    def generate(self, request: LLMRequest) -> LLMResponse:
        """
        Generate a deterministic mock analysis response.

        Parses finding IDs out of the user_message to build per-finding analysis.
        Never invents factual security information.
        """
        logger.debug("MockLLMProvider | generate() fail_with=%s", self._fail_with or "none")

        # ── Failure simulations ───────────────────────────────────────────────
        if self._fail_with == "timeout":
            return LLMResponse(
                success=False, provider=self.PROVIDER_NAME,
                error="Request timed out after 30s", error_type="timeout",
            )
        if self._fail_with == "network":
            return LLMResponse(
                success=False, provider=self.PROVIDER_NAME,
                error="Network connection failed", error_type="network",
            )
        if self._fail_with == "rate_limit":
            return LLMResponse(
                success=False, provider=self.PROVIDER_NAME,
                error="Rate limit exceeded", error_type="rate_limit",
            )
        if self._fail_with == "auth":
            return LLMResponse(
                success=False, provider=self.PROVIDER_NAME,
                error="Authentication failed — invalid API key", error_type="auth",
            )
        if self._fail_with == "context_limit":
            return LLMResponse(
                success=False, provider=self.PROVIDER_NAME,
                error="Input exceeds maximum context length", error_type="context_limit",
            )
        if self._fail_with == "invalid_json":
            return LLMResponse(
                success=True, provider=self.PROVIDER_NAME,
                content="this is not valid json {{{",
            )
        if self._fail_with == "empty":
            return LLMResponse(
                success=True, provider=self.PROVIDER_NAME,
                content="",
            )
        if self._fail_with == "partial":
            # Valid JSON but missing required structure
            return LLMResponse(
                success=True, provider=self.PROVIDER_NAME,
                content=json.dumps({"executive_summary": "Partial response only."}),
            )
        if self._fail_with == "missing_finding_id":
            # Finding analysis with no finding_id key
            return LLMResponse(
                success=True, provider=self.PROVIDER_NAME,
                content=json.dumps({
                    "executive_summary": "Mock summary.",
                    "overall_risk": "HIGH",
                    "finding_analyses": [
                        {"explanation": "No finding_id present — should be handled gracefully."}
                    ],
                }),
            )
        if self._fail_with == "unknown_finding_id":
            # Finding analysis with a fabricated finding_id not in the input
            return LLMResponse(
                success=True, provider=self.PROVIDER_NAME,
                content=json.dumps({
                    "executive_summary": "Mock summary.",
                    "overall_risk": "HIGH",
                    "finding_analyses": [
                        {
                            "finding_id": "FABRICATED-ID-NOT-IN-INPUT",
                            "explanation": "This ID was not in the original findings.",
                        }
                    ],
                }),
            )

        # ── Success — build deterministic mock response ───────────────────────
        finding_ids = self._extract_finding_ids(request.user_message)
        finding_analyses = self._build_finding_analyses(finding_ids)

        overall_risk = "HIGH"  # deterministic default for mock

        mock_response = {
            "executive_summary": (
                "[MOCK ANALYSIS] This is a deterministic mock analysis produced by "
                f"MockLLMProvider for testing purposes. {len(finding_ids)} finding(s) analyzed. "
                "This output is NOT real AI security intelligence. "
                "Refer to VulnerabilityFinding records for authoritative facts."
            ),
            "overall_risk": overall_risk,
            "finding_analyses": finding_analyses,
        }

        return LLMResponse(
            success=True,
            provider=self.PROVIDER_NAME,
            content=json.dumps(mock_response),
        )

    def _extract_finding_ids(self, user_message: str) -> list[str]:
        """Extract finding IDs from the prompt message."""
        if self._finding_ids_override is not None:
            return self._finding_ids_override

        # Parse finding IDs from the structured JSON context in the prompt
        finding_ids = []
        try:
            # Try to parse the JSON block from the user message
            import re
            json_match = re.search(r'\{.*\}', user_message, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
                for f in data.get("findings", []):
                    fid = f.get("finding_id")
                    if fid:
                        finding_ids.append(fid)
        except Exception:
            pass  # Fallback to empty list — service handles gracefully

        return finding_ids

    def _build_finding_analyses(self, finding_ids: list[str]) -> list[dict]:
        """Build deterministic per-finding mock analyses."""
        return [
            {
                "finding_id": fid,
                "explanation": (
                    f"[MOCK] Vulnerability in finding {fid[:8]}... has been identified "
                    "in the supplied dependency. Review the VulnerabilityFinding record "
                    "for authoritative CVE, CVSS, and EPSS data."
                ),
                "impact": (
                    "[MOCK] Potential security impact based on severity and CVSS vector. "
                    "This is an inference from the evidence supplied — not a verified exploit claim."
                ),
                "exploitability": (
                    "[MOCK] Exploitability commentary based on EPSS score and available references. "
                    "No exploit is claimed or verified by this analysis."
                ),
                "remediation": (
                    "[MOCK] Upgrade to the fixed version specified in the VulnerabilityFinding, "
                    "if available. No version is invented by this mock provider."
                ),
                "dependency_context_note": (
                    "[MOCK] Dependency context (direct/transitive/depth) has been noted. "
                    "See the VulnerabilityFinding dependency field for exact path data."
                ),
                "confidence": "MEDIUM",
            }
            for fid in finding_ids
        ]
