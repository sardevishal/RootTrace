"""
services/ai/security_analysis_service.py

SecurityAnalysisService — P2G

The central AI analysis orchestrator.

Flow:
    1. Receive AIAnalysisInput
    2. Build LLMRequest via SecurityAnalysisPromptBuilder
    3. Call LLMProvider.generate()
    4. Parse structured JSON response
    5. Validate finding_id traceability
    6. Assemble AIAnalysisResult
    7. Return gracefully on any failure (never crash the vulnerability scan)

Key design rules:
    - AI failures return AIAnalysisResult with ai_status="failed"/"unavailable"
    - NEVER modifies vulnerability facts (CVE, CVSS, EPSS, risk_score, fixed_version)
    - Every AIFindingAnalysis must map to a known finding_id from the input
    - Unknown/fabricated finding_ids from the LLM are discarded with a warning
    - All exceptions are caught and converted to graceful failure responses

Usage:
    service = SecurityAnalysisService(llm_provider=MockLLMProvider())
    result = service.analyze(analysis_input)
"""

import json
from typing import Optional

from app.models.ai_analysis import AIAnalysisInput
from app.models.ai_analysis_result import (
    AIAnalysisResult,
    AIFindingAnalysis,
    AI_STATUS_COMPLETED,
    AI_STATUS_COMPLETED_WITH_WARNINGS,
    AI_STATUS_FAILED,
    AI_STATUS_UNAVAILABLE,
)
from app.services.ai.llm_provider import LLMProvider, LLMRequest
from app.services.ai.mock_llm_provider import MockLLMProvider
from app.services.ai.prompt_builder import SecurityAnalysisPromptBuilder
from app.utils.logger import get_logger

logger = get_logger(__name__)


class SecurityAnalysisService:
    """
    AI Security Analysis Engine — orchestrates LLM analysis of vulnerability findings.

    The source of truth for vulnerability facts always remains the VulnerabilityFinding
    contract. This service adds explanation, prioritization context, and remediation
    reasoning on top of the existing evidence — it never replaces it.

    Args:
        llm_provider: Any LLMProvider implementation. Defaults to MockLLMProvider
                      (safe, offline, deterministic) if not supplied.
    """

    def __init__(
        self,
        llm_provider: Optional[LLMProvider] = None,
        prompt_builder: Optional[SecurityAnalysisPromptBuilder] = None,
    ) -> None:
        self._llm = llm_provider or MockLLMProvider()
        self._prompt_builder = prompt_builder or SecurityAnalysisPromptBuilder()

    def analyze(
        self,
        analysis_input: AIAnalysisInput,
        max_tokens: int = 4096,
        temperature: float = 0.1,
    ) -> AIAnalysisResult:
        """
        Run AI security analysis on a set of VulnerabilityFinding records.

        AI failures return a graceful AIAnalysisResult with ai_status='failed'
        or 'unavailable'. They NEVER propagate as exceptions to callers.
        Vulnerability scan results are unaffected.

        Args:
            analysis_input: Normalized input from SecurityAnalysisInputProvider.
            max_tokens: Token budget for the LLM response.
            temperature: LLM sampling temperature.

        Returns:
            AIAnalysisResult — always, never raises.
        """
        scan_id = analysis_input.scan_id
        logger.info(
            "SecurityAnalysisService | analyze() scan_id=%s findings=%d provider=%s",
            scan_id or "N/A",
            len(analysis_input.findings),
            self._llm.provider_name,
        )

        # Edge case: no findings to analyze
        if not analysis_input.findings:
            logger.info("SecurityAnalysisService | No findings to analyze — returning empty result.")
            return AIAnalysisResult(
                scan_id=scan_id,
                ai_status=AI_STATUS_COMPLETED,
                llm_provider=self._llm.provider_name,
                executive_summary=(
                    "No vulnerability findings were identified in this scan. "
                    "The dependency graph appears to be clean based on the scanned sources."
                ),
                overall_risk="UNKNOWN",
                total_findings_analyzed=0,
                finding_analyses=[],
            )

        # ── Build a valid finding_id set for traceability validation ──────────
        valid_finding_ids: set[str] = {f.finding_id for f in analysis_input.findings}

        try:
            # ── Step 1: Build LLM prompt ──────────────────────────────────────
            request: LLMRequest = self._prompt_builder.build_request(
                analysis_input=analysis_input,
                max_tokens=max_tokens,
                temperature=temperature,
            )

            # ── Step 2: Call LLM provider ─────────────────────────────────────
            llm_response = self._llm.generate(request)

            # ── Step 3: Handle provider failure ───────────────────────────────
            if not llm_response.success:
                logger.warning(
                    "SecurityAnalysisService | LLM failure: %s (type=%s)",
                    llm_response.error, llm_response.error_type,
                )
                return AIAnalysisResult(
                    scan_id=scan_id,
                    ai_status=AI_STATUS_UNAVAILABLE,
                    ai_error=llm_response.error,
                    llm_provider=llm_response.provider,
                    total_findings_analyzed=len(analysis_input.findings),
                )

            # ── Step 4: Parse structured JSON response ─────────────────────────
            parsed = self._parse_response(llm_response.content)
            if parsed is None:
                return AIAnalysisResult(
                    scan_id=scan_id,
                    ai_status=AI_STATUS_FAILED,
                    ai_error="LLM returned invalid or unparseable JSON response.",
                    llm_provider=llm_response.provider,
                    total_findings_analyzed=len(analysis_input.findings),
                )

            # ── Step 5: Build per-finding analyses with traceability validation ─
            warnings: list[str] = []
            finding_analyses: list[AIFindingAnalysis] = []

            raw_analyses = parsed.get("finding_analyses", [])
            for i, raw in enumerate(raw_analyses):
                finding_id = raw.get("finding_id")

                # Discard entries with no finding_id
                if not finding_id:
                    msg = f"LLM returned finding_analyses[{i}] without finding_id — discarded."
                    logger.warning("SecurityAnalysisService | %s", msg)
                    warnings.append(msg)
                    continue

                # Discard entries with fabricated/unknown finding_id
                if finding_id not in valid_finding_ids:
                    msg = f"LLM returned unknown finding_id '{finding_id[:16]}...' — discarded."
                    logger.warning("SecurityAnalysisService | %s", msg)
                    warnings.append(msg)
                    continue

                finding_analyses.append(AIFindingAnalysis(
                    finding_id=finding_id,
                    priority=i + 1,
                    explanation=raw.get("explanation"),
                    impact=raw.get("impact"),
                    exploitability=raw.get("exploitability"),
                    remediation=raw.get("remediation"),
                    dependency_context_note=raw.get("dependency_context_note"),
                    attack_surface=raw.get("attack_surface"),
                    confidence=raw.get("confidence"),
                ))

            ai_status = AI_STATUS_COMPLETED_WITH_WARNINGS if warnings else AI_STATUS_COMPLETED

            logger.info(
                "SecurityAnalysisService | Done — status=%s, analyses=%d, warnings=%d",
                ai_status, len(finding_analyses), len(warnings),
            )

            return AIAnalysisResult(
                scan_id=scan_id,
                ai_status=ai_status,
                llm_provider=llm_response.provider,
                executive_summary=parsed.get("executive_summary"),
                overall_risk=parsed.get("overall_risk", "UNKNOWN"),
                total_findings_analyzed=len(analysis_input.findings),
                finding_analyses=finding_analyses,
            )

        except Exception as exc:
            # ── Catch-all — AI failure never propagates ────────────────────────
            logger.exception("SecurityAnalysisService | Unhandled error: %s", exc)
            return AIAnalysisResult(
                scan_id=scan_id,
                ai_status=AI_STATUS_FAILED,
                ai_error=f"Unexpected analysis error: {str(exc)}",
                llm_provider=self._llm.provider_name,
                total_findings_analyzed=len(analysis_input.findings),
            )

    def _parse_response(self, content: Optional[str]) -> Optional[dict]:
        """
        Parse and validate the LLM JSON response.

        Returns None on any parse failure — caller handles gracefully.
        """
        if not content:
            logger.warning("SecurityAnalysisService | LLM returned empty content.")
            return None
        try:
            parsed = json.loads(content)
            if not isinstance(parsed, dict):
                logger.warning("SecurityAnalysisService | LLM response is not a JSON object.")
                return None
            return parsed
        except json.JSONDecodeError as exc:
            logger.warning("SecurityAnalysisService | JSON parse failed: %s", exc)
            return None
