"""
api/findings.py

FastAPI router for the canonical Vulnerability Findings API — P2E.

This endpoint exposes VulnerabilityFinding records through the stable
downstream contract. The AI module, Dashboard, and Reporting modules
should consume this endpoint, NOT /api/v1/vulnerabilities.

Endpoints:
    GET  /api/v1/findings         — Run a scan and return canonical findings
    GET  /api/v1/findings/health  — Health check

This file is thin by design.
All business logic lives in:
    services/vulnerability/providers/finding_provider.py

The existing /api/v1/vulnerabilities endpoint is UNCHANGED (backward compat).
"""

from fastapi import APIRouter, HTTPException, status
from app.services.vulnerability.providers.finding_provider import (
    VulnerabilityFindingProvider,
    FindingResult,
)
from app.schemas.finding_schema import (
    FindingResponseOut,
    VulnerabilityFindingOut,
    PackageInfoOut,
    DependencyContextOut,
    VulnerabilityInfoOut,
    RemediationOut,
    SourceAttributionOut,
    SourceErrorOut,
)
from app.models.vulnerability_finding import VulnerabilityFinding
from app.utils.logger import get_logger

logger = get_logger(__name__)

router = APIRouter(
    prefix="/api/v1/findings",
    tags=["Findings"],
)

# Single provider instance (stateless — safe to reuse across requests)
_provider = VulnerabilityFindingProvider()


def _finding_to_out(f: VulnerabilityFinding) -> VulnerabilityFindingOut:
    """Convert internal VulnerabilityFinding → API schema VulnerabilityFindingOut."""
    return VulnerabilityFindingOut(
        contract_version=f.contract_version,
        finding_id=f.finding_id,
        scan_id=f.scan_id,
        package=PackageInfoOut(
            name=f.package_name,
            version=f.version,
            ecosystem=f.ecosystem,
        ),
        dependency=DependencyContextOut(
            direct=f.dependency.direct,
            transitive=f.dependency.transitive,
            depth=f.dependency.depth,
            parent=f.dependency.parent,
            dependency_path=f.dependency.dependency_path,
        ),
        vulnerability=VulnerabilityInfoOut(
            cve_id=f.cve_id,
            osv_id=f.osv_id,
            ghsa_id=f.ghsa_id,
            nvd_id=f.nvd_id,
            title=f.title,
            description=f.description,
            severity=f.severity,
            affected_versions=f.affected_versions,
            cvss_score=f.cvss_score,
            cvss_vector=f.cvss_vector,
            epss_score=f.epss_score,
            risk_score=f.risk_score,
            risk_label=f.risk_label,
        ),
        remediation=RemediationOut(fixed_version=f.fixed_version),
        sources=SourceAttributionOut(
            primary=f.source,
            contributing=f.sources_contributing,
        ),
        references=f.references,
    )


@router.get(
    "",
    response_model=FindingResponseOut,
    summary="Get Canonical Vulnerability Findings",
    description=(
        "Runs the full vulnerability pipeline (OSV + NVD + GitHub Advisory + "
        "EPSS + deduplication + composite risk scoring) and returns canonical "
        "VulnerabilityFinding records for downstream consumption.\n\n"
        "**Contract version**: 1.0\n\n"
        "Downstream modules (AI, Dashboard, Reporting) should consume this "
        "endpoint instead of /api/v1/vulnerabilities."
    ),
)
def get_findings() -> FindingResponseOut:
    """
    GET /api/v1/findings

    Returns canonical VulnerabilityFinding records for all packages.
    """
    logger.info("API | GET /api/v1/findings — finding scan requested.")

    try:
        result: FindingResult = _provider.get_findings()
    except Exception as exc:
        logger.exception("API | Unhandled finding provider error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Finding scan failed: {str(exc)}",
        )

    findings_out = [_finding_to_out(f) for f in result.findings]

    logger.info(
        "API | Findings scan complete — %d package(s), %d finding(s).",
        result.total_packages_scanned,
        result.total_findings,
    )

    return FindingResponseOut(
        scan_id=result.scan_id,
        scan_status=result.scan_status,
        source_status=result.source_status,
        total_packages_scanned=result.total_packages_scanned,
        total_findings=result.total_findings,
        findings=findings_out,
        source_errors=[
            SourceErrorOut(
                source=e.source,
                error_type=e.error_type,
                message=e.message,
            )
            for e in result.source_errors
        ],
        errors=result.errors,
    )


@router.get(
    "/health",
    summary="Findings API Health Check",
)
def health_check() -> dict:
    """GET /api/v1/findings/health"""
    return {
        "status": "ok",
        "module": "Vulnerability Finding Provider",
        "contract_version": "1.0",
        "phase": "P2E",
    }
