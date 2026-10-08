"""
services/ai/prompt_builder.py

SecurityAnalysisPromptBuilder — P2G

Constructs the structured LLM prompt from AIAnalysisInput.

Responsibilities:
    - Assemble system instructions
    - Serialize findings into a concise, evidence-only context block
    - Enforce output structure requirements
    - Prevent prompt injection from finding data
    - Distinguish FACT fields from INFERENCE/RECOMMENDATION fields

Isolation rule:
    Prompt construction MUST NOT live in:
        - API routes
        - models
        - VulnerabilityEngine
        - FindingAssembler

    It lives HERE only.

The prompt instructs the AI to:
    1. Reason from supplied evidence only
    2. Mark inferences explicitly
    3. Mark recommendations explicitly
    4. Never invent CVEs, versions, scores, or exploit claims
    5. Always include finding_id in every per-finding analysis
    6. Return only valid JSON
"""

import json
from app.models.ai_analysis import AIAnalysisInput
from app.models.vulnerability_finding import VulnerabilityFinding
from app.services.ai.llm_provider import LLMRequest
from app.utils.logger import get_logger

logger = get_logger(__name__)


# ── System instructions (static) ──────────────────────────────────────────────
_SYSTEM_PROMPT = """You are a security analysis assistant for RootTrace, a supply chain security platform.

ROLE:
Your role is to EXPLAIN, PRIORITIZE, and CONTEXTUALIZE vulnerability findings
based entirely on the structured evidence provided to you. You are NOT the source
of truth for vulnerability facts.

SOURCE OF TRUTH:
The VulnerabilityFinding records provided to you ARE the source of truth for:
  - CVE identifiers
  - CVSS scores
  - EPSS scores
  - Composite risk scores
  - Fixed versions
  - Package versions
  - Affected versions
  - Severity labels
  - Source attribution

ABSOLUTE RULES:
1. NEVER invent, modify, or contradict any factual field (CVE, CVSS, EPSS, risk_score, version)
2. NEVER claim a vulnerability exists that is not in the findings provided
3. NEVER claim a fixed version that is not in the findings provided
4. NEVER assign a different severity than what is supplied
5. If evidence is unavailable for a field, say so explicitly

REASONING:
When generating analysis, explicitly label:
  - FACT: directly from supplied finding data
  - INFERENCE: logical extrapolation from the evidence (clearly labeled)
  - RECOMMENDATION: actionable advice (clearly labeled)

OUTPUT FORMAT:
Return ONLY valid JSON matching this exact structure:
{
  "executive_summary": "string",
  "overall_risk": "CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN",
  "finding_analyses": [
    {
      "finding_id": "exact-finding-id-from-input",
      "explanation": "string",
      "impact": "string",
      "exploitability": "string",
      "remediation": "string",
      "dependency_context_note": "string",
      "attack_surface": "string or null",
      "confidence": "HIGH|MEDIUM|LOW"
    }
  ]
}

CONFIDENCE LEVELS (evidence-based, NOT model confidence):
  HIGH: CVE + CVSS + EPSS all present
  MEDIUM: CVE present but EPSS or CVSS missing
  LOW: No CVE, severity label only

CRITICAL REQUIREMENT:
Every entry in finding_analyses MUST contain the exact finding_id from the input.
Do NOT fabricate finding_ids. Do NOT omit finding_ids.
"""


class SecurityAnalysisPromptBuilder:
    """
    Builds structured LLM prompts from AIAnalysisInput.

    This class is stateless and thread-safe.
    """

    def build_request(
        self,
        analysis_input: AIAnalysisInput,
        max_tokens: int = 4096,
        temperature: float = 0.1,
    ) -> LLMRequest:
        """
        Construct an LLMRequest from AIAnalysisInput.

        Args:
            analysis_input: The normalized AI analysis input.
            max_tokens: Token budget for the response.
            temperature: LLM temperature (low for structured analysis).

        Returns:
            LLMRequest ready to be passed to any LLMProvider.
        """
        user_message = self._build_user_message(analysis_input)
        logger.debug(
            "PromptBuilder | Built prompt for scan_id=%s with %d finding(s)",
            analysis_input.scan_id or "N/A",
            len(analysis_input.findings),
        )
        return LLMRequest(
            system_prompt=_SYSTEM_PROMPT,
            user_message=user_message,
            max_tokens=max_tokens,
            temperature=temperature,
            response_format="json",
        )

    def _build_user_message(self, analysis_input: AIAnalysisInput) -> str:
        """
        Serialize the AIAnalysisInput into a concise evidence-only JSON context block.
        """
        context = {
            "scan_id": analysis_input.scan_id,
            "summary": {
                "total_findings": analysis_input.summary.total_findings,
                "critical": analysis_input.summary.critical,
                "high": analysis_input.summary.high,
                "medium": analysis_input.summary.medium,
                "low": analysis_input.summary.low,
                "direct_dependencies": analysis_input.summary.direct_dependencies,
                "transitive_dependencies": analysis_input.summary.transitive_dependencies,
                "affected_packages": analysis_input.summary.affected_packages,
            },
            "context": {
                "included_findings": analysis_input.context.included_findings,
                "omitted_findings": analysis_input.context.omitted_findings,
            },
            "findings": [
                self._serialize_finding(i + 1, f)
                for i, f in enumerate(analysis_input.findings)
            ],
        }

        return (
            "Analyze the following vulnerability findings from a RootTrace security scan.\n\n"
            "Evidence context:\n"
            f"{json.dumps(context, indent=2)}\n\n"
            "Instructions:\n"
            "1. Produce an executive summary of the overall security posture.\n"
            "2. For EACH finding, provide structured analysis (explanation, impact, "
            "exploitability, remediation, dependency_context_note).\n"
            "3. Assign evidence_confidence (HIGH/MEDIUM/LOW) per finding.\n"
            "4. Use ONLY the evidence provided. Label inferences and recommendations explicitly.\n"
            "5. Return valid JSON matching the required output structure exactly.\n"
            "6. Include the exact finding_id in every finding_analyses entry."
        )

    def _serialize_finding(
        self, priority: int, f: VulnerabilityFinding
    ) -> dict:
        """Serialize a VulnerabilityFinding to a compact evidence-only dict for the prompt."""
        # Evidence confidence derived from data availability (not model confidence)
        has_cve = f.cve_id is not None
        has_cvss = f.cvss_score is not None
        has_epss = f.epss_score is not None
        if has_cve and has_cvss and has_epss:
            evidence_confidence = "HIGH"
        elif has_cve or has_cvss:
            evidence_confidence = "MEDIUM"
        else:
            evidence_confidence = "LOW"

        return {
            "finding_id": f.finding_id,
            "priority": priority,
            "package": {
                "name": f.package_name,
                "version": f.version,
                "ecosystem": f.ecosystem,
            },
            "dependency": {
                "direct": f.dependency.direct,
                "transitive": f.dependency.transitive,
                "depth": f.dependency.depth,
                "parent": f.dependency.parent,
                "dependency_path": f.dependency.dependency_path,
            },
            "vulnerability": {
                "cve_id": f.cve_id,
                "osv_id": f.osv_id,
                "ghsa_id": f.ghsa_id,
                "title": f.title,
                "severity": f.severity,
                "cvss_score": f.cvss_score,
                "cvss_vector": f.cvss_vector,
                "epss_score": f.epss_score,
                "risk_score": f.risk_score,
                "risk_label": f.risk_label,
                "affected_versions": f.affected_versions,
            },
            "remediation": {
                "fixed_version": f.fixed_version,
            },
            "sources": {
                "primary": f.source,
                "contributing": f.sources_contributing,
                "references": f.references[:3],  # limit refs in prompt
            },
            "evidence_confidence": evidence_confidence,
        }
