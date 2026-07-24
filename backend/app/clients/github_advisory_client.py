"""
clients/github_advisory_client.py

Responsible ONLY for communicating with the GitHub Security Advisory GraphQL API.
https://docs.github.com/en/graphql/reference/objects#securityadvisory

Phase 2 integration — currently returns an empty list (stub).
Replace the `query` method body when Phase 4 begins.
"""

from typing import Optional
from app.utils.logger import get_logger
from app.utils.constants import GITHUB_GRAPHQL_URL, DEFAULT_HTTP_TIMEOUT

logger = get_logger(__name__)


class GitHubAdvisoryClient:
    """
    Client for the GitHub Security Advisory GraphQL API.

    Phase 1 Status: STUB — always returns [].
    Phase 4 TODO   : Implement real GraphQL queries using a GitHub personal
                     access token (read:packages scope required).
    """

    def __init__(
        self,
        github_token: Optional[str] = None,
        timeout: int = DEFAULT_HTTP_TIMEOUT,
    ) -> None:
        self._graphql_url = GITHUB_GRAPHQL_URL
        self._token = github_token
        self._timeout = timeout

    def query(
        self,
        package_name: str,
        version: str,
        ecosystem: str,
    ) -> list[dict]:
        """
        Query GitHub Security Advisories for vulnerabilities related to the package.

        Args:
            package_name: Name of the package.
            version:      Exact version string.
            ecosystem:    Package ecosystem.

        Returns:
            List of raw GitHub Advisory dicts.

        Phase 1:
            Returns empty list — GitHub Advisories integration is planned for Phase 4.
        """
        # ── Phase 1 stub ──────────────────────────────────────────────────────
        logger.info(
            "GitHub Advisory | Skipping %s@%s (Phase 4 — not yet integrated).",
            package_name,
            version,
        )
        return []

        # ── Phase 4 implementation template (do NOT delete) ───────────────────
        # import httpx
        # query = """
        # query($package: String!, $ecosystem: SecurityAdvisoryEcosystem!) {
        #   securityVulnerabilities(first: 20, package: $package, ecosystem: $ecosystem) {
        #     nodes {
        #       advisory {
        #         ghsaId
        #         summary
        #         description
        #         severity
        #         identifiers { type value }
        #         references { url }
        #       }
        #       vulnerableVersionRange
        #       firstPatchedVersion { identifier }
        #     }
        #   }
        # }
        # """
        # headers = {"Authorization": f"Bearer {self._token}"}
        # payload = {"query": query, "variables": {"package": package_name, "ecosystem": ecosystem.upper()}}
        # try:
        #     with httpx.Client(timeout=self._timeout) as client:
        #         resp = client.post(self._graphql_url, json=payload, headers=headers)
        #         resp.raise_for_status()
        #         return resp.json().get("data", {}).get("securityVulnerabilities", {}).get("nodes", [])
        # except Exception as exc:
        #     logger.error("GitHub Advisory | Request failed for %s@%s — %s", package_name, version, exc)
        #     return []
