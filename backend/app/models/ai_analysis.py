"""
models/ai_analysis.py

AI Security Analysis Input Contract - P2F

Defines the normalized context and prioritization rules for the AI module.
"""

from typing import Optional, Any
from pydantic import BaseModel, Field
from app.models.vulnerability_finding import VulnerabilityFinding
from app.utils.constants import (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
)

class AIAnalysisSummary(BaseModel):
    total_findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    direct_dependencies: int = 0
    transitive_dependencies: int = 0
    affected_packages: int = 0


class AIAnalysisContext(BaseModel):
    total_findings: int = 0
    included_findings: int = 0
    omitted_findings: int = 0


class AIAnalysisInput(BaseModel):
    """Normalized context for the AI module."""
    contract_version: str = Field(default="1.0")
    scan_id: Optional[str] = None
    summary: AIAnalysisSummary = Field(default_factory=AIAnalysisSummary)
    findings: list[VulnerabilityFinding] = Field(default_factory=list)
    context: AIAnalysisContext = Field(default_factory=AIAnalysisContext)


def build_summary(findings: list[VulnerabilityFinding]) -> AIAnalysisSummary:
    summary = AIAnalysisSummary(total_findings=len(findings))
    packages = set()

    for f in findings:
        packages.add((f.package_name, f.version, f.ecosystem))

        if f.risk_label == SEVERITY_CRITICAL:
            summary.critical += 1
        elif f.risk_label == SEVERITY_HIGH:
            summary.high += 1
        elif f.risk_label == SEVERITY_MEDIUM:
            summary.medium += 1
        elif f.risk_label == SEVERITY_LOW:
            summary.low += 1

        if f.dependency.direct:
            summary.direct_dependencies += 1
        else:
            summary.transitive_dependencies += 1

    summary.affected_packages = len(packages)
    return summary


def prioritize_findings(findings: list[VulnerabilityFinding]) -> list[VulnerabilityFinding]:
    """
    Deterministic prioritization layer.
    
    Sorting rules (descending priority):
    1. Risk Label (CRITICAL > HIGH > MEDIUM > LOW > UNKNOWN)
    2. Risk Score (Higher is better)
    3. EPSS Score (Higher is better)
    4. CVSS Score (Higher is better)
    5. Direct dependency before transitive
    6. Depth (Lower depth is better)
    """
    
    severity_rank = {
        SEVERITY_CRITICAL: 5,
        SEVERITY_HIGH: 4,
        SEVERITY_MEDIUM: 3,
        SEVERITY_LOW: 2,
        "UNKNOWN": 1,
    }
    
    def sort_key(f: VulnerabilityFinding) -> tuple:
        return (
            severity_rank.get(f.risk_label, 0),
            f.risk_score or 0.0,
            f.epss_score or 0.0,
            f.cvss_score or 0.0,
            1 if f.dependency.direct else 0,
            -f.dependency.depth,  # negative so smaller depth is larger
        )
    
    return sorted(findings, key=sort_key, reverse=True)
