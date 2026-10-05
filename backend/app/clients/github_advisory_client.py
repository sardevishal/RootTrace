"""
clients/github_advisory_client.py

Client for the GitHub Security Advisory GraphQL API.
https://docs.github.com/en/graphql/reference/objects#securityadvisory

API:
    POST https://api.github.com/graphql
    Authorization: Bearer <GITHUB_TOKEN>

GitHub ecosystem names differ from our canonical names:
    npm → NPM
    PyPI → PIP
    Maven → MAVEN
    Go → GO
    RubyGems → RUBYGEMS
    NuGet → NUGET
    crates.io → RUST
    Packagist → COMPOSER

Authentication:
    Set GITHUB_TOKEN environment variable.
    Without a token, the API returns 401.
    Tokens need NO special scopes for public advisory data (classic PAT or fine-grained PAT).

Rate limits:
    - Authenticated: 5000 points/hour (queries cost ~1 point each)
    - Unauthenticated: not supported (always 401)

GraphQL response structure for securityVulnerabilities:
{
  "data": {
    "securityVulnerabilities": {
      "nodes": [
        {
          "advisory": {
            "ghsaId": "GHSA-xxxx-yyyy-zzzz",
            "summary": "...",
            "description": "...",
            "severity": "HIGH",
            "identifiers": [{"type": "CVE", "value": "CVE-2021-23337"}, ...],
            "references": [{"url": "..."}],
            "cvss": {"score": 7.2, "vectorString": "CVSS:3.1/..."},
            "publishedAt": "..."
          },
          "vulnerableVersionRange": ">= 1.0.0, < 4.17.21",
          "firstPatchedVersion": {"identifier": "4.17.21"}
        }
      ],
      "pageInfo": {"hasNextPage": false}
    }
  }
}

Reliability:
    - Configurable timeout
    - Bounded exponential-backoff retry (5xx, network errors)
    - 429 → honour Retry-After
    - 401/403 → immediate GitHubClientError (no token/invalid)
    - Invalid/malformed GraphQL response → structured error
    - GITHUB_TOKEN read from environment; missing token raises on first query
"""

import os
import time
from typing import Optional
import httpx

from app.utils.logger import get_logger
from app.utils.constants import GITHUB_GRAPHQL_URL, DEFAULT_HTTP_TIMEOUT

logger = get_logger(__name__)

# Retry configuration
_MAX_RETRIES = 3
_BASE_BACKOFF_SECONDS = 1.0
_BACKOFF_MULTIPLIER = 2.0
_MAX_BACKOFF_SECONDS = 16.0

# Ecosystem mapping: RootTrace canonical → GitHub GraphQL SecurityAdvisoryEcosystem enum
_ECOSYSTEM_TO_GITHUB: dict[str, str] = {
    "npm": "NPM",
    "PyPI": "PIP",
    "Maven": "MAVEN",
    "Go": "GO",
    "RubyGems": "RUBYGEMS",
    "NuGet": "NUGET",
    "crates.io": "RUST",
    "Packagist": "COMPOSER",
}

# GraphQL query: search by package name + ecosystem, get up to 20 advisories
_ADVISORY_QUERY = """
query($package: String!, $ecosystem: SecurityAdvisoryEcosystem!) {
  securityVulnerabilities(
    first: 20
    package: $package
    ecosystem: $ecosystem
    orderBy: {field: UPDATED_AT, direction: DESC}
  ) {
    nodes {
      advisory {
        ghsaId
        summary
        description
        severity
        identifiers { type value }
        references { url }
        cvss { score vectorString }
        publishedAt
        withdrawnAt
      }
      vulnerableVersionRange
      firstPatchedVersion { identifier }
    }
    pageInfo { hasNextPage }
  }
}
"""


class GitHubClientError(Exception):
    """Structured error raised when GitHub Advisory API cannot return a usable result."""

    def __init__(
        self,
        message: str,
        error_type: str = "unknown",
        status_code: Optional[int] = None,
    ) -> None:
        super().__init__(message)
        self.error_type = error_type  # auth | rate_limit | timeout | network | http_5xx | invalid_response | unsupported_ecosystem | no_token
        self.status_code = status_code
        self.message = message


class GitHubAdvisoryClient:
    """
    Client for the GitHub Security Advisory GraphQL API.

    Queries advisories by package name + ecosystem.
    Returns a list of raw advisory node dicts for normalization.

    Token:
        Pass explicitly or set GITHUB_TOKEN environment variable.
        Missing token causes GitHubClientError(error_type='no_token') on query.
    """

    def __init__(
        self,
        github_token: Optional[str] = None,
        timeout: int = DEFAULT_HTTP_TIMEOUT,
    ) -> None:
        self._url = GITHUB_GRAPHQL_URL
        self._timeout = timeout
        # Token: explicit arg takes priority over environment
        self._token: Optional[str] = github_token or os.environ.get("GITHUB_TOKEN")
        if self._token:
            logger.debug("GitHub Advisory | Token configured.")
        else:
            logger.warning(
                "GitHub Advisory | No GITHUB_TOKEN set. Queries will fail. "
                "Set GITHUB_TOKEN environment variable."
            )

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        }

    def query(
        self,
        package_name: str,
        version: str,
        ecosystem: str,
    ) -> list[dict]:
        """
        Query GitHub Security Advisories for the given package + ecosystem.

        Args:
            package_name: Name of the package (e.g. 'lodash').
            version:      Exact version string. Used by the caller to filter
                          advisories by affected version range.
            ecosystem:    Canonical ecosystem (e.g. 'npm', 'PyPI').

        Returns:
            List of raw advisory node dicts (each has 'advisory' + 'vulnerableVersionRange').
            Caller (GitHubAdvisorySource) is responsible for filtering by version range.

        Raises:
            GitHubClientError: On auth failure, rate limit, timeout, network, or parse error.
        """
        # ── Missing token → fail immediately, no retry ────────────────────────
        if not self._token:
            raise GitHubClientError(
                "No GITHUB_TOKEN configured. GitHub Advisory queries are unavailable.",
                error_type="no_token",
            )

        # ── Ecosystem translation ─────────────────────────────────────────────
        github_ecosystem = _ECOSYSTEM_TO_GITHUB.get(ecosystem)
        if github_ecosystem is None:
            logger.info(
                "GitHub Advisory | Unsupported ecosystem '%s' for %s@%s — skipping.",
                ecosystem, package_name, version,
            )
            raise GitHubClientError(
                f"Ecosystem '{ecosystem}' is not supported by the GitHub Advisory API.",
                error_type="unsupported_ecosystem",
            )

        logger.info(
            "GitHub Advisory | Querying %s/%s (GitHub ecosystem: %s)",
            ecosystem, package_name, github_ecosystem,
        )

        payload = {
            "query": _ADVISORY_QUERY,
            "variables": {
                "package": package_name,
                "ecosystem": github_ecosystem,
            },
        }

        last_error: Optional[GitHubClientError] = None
        backoff = _BASE_BACKOFF_SECONDS

        for attempt in range(1, _MAX_RETRIES + 1):
            try:
                with httpx.Client(timeout=self._timeout) as client:
                    response = client.post(
                        self._url,
                        json=payload,
                        headers=self._headers(),
                    )

                # ── Authentication failure — do NOT retry ─────────────────
                if response.status_code in (401, 403):
                    raise GitHubClientError(
                        f"GitHub Advisory authentication failed (HTTP {response.status_code}). "
                        "Check your GITHUB_TOKEN.",
                        error_type="auth",
                        status_code=response.status_code,
                    )

                # ── Rate limiting ─────────────────────────────────────────
                if response.status_code == 429:
                    retry_after = float(response.headers.get("Retry-After", backoff))
                    wait = min(retry_after, _MAX_BACKOFF_SECONDS)
                    logger.warning(
                        "GitHub Advisory | 429 rate limit for %s@%s — waiting %.1fs (attempt %d/%d)",
                        package_name, version, wait, attempt, _MAX_RETRIES,
                    )
                    time.sleep(wait)
                    backoff = min(backoff * _BACKOFF_MULTIPLIER, _MAX_BACKOFF_SECONDS)
                    last_error = GitHubClientError(
                        f"Rate limited by GitHub Advisory after {attempt} attempt(s)",
                        error_type="rate_limit",
                        status_code=429,
                    )
                    continue

                # ── 5xx server errors — retry ─────────────────────────────
                if response.status_code >= 500:
                    logger.warning(
                        "GitHub Advisory | HTTP %d for %s@%s (attempt %d/%d) — retrying",
                        response.status_code, package_name, version, attempt, _MAX_RETRIES,
                    )
                    last_error = GitHubClientError(
                        f"GitHub Advisory HTTP {response.status_code} for {package_name}@{version}",
                        error_type="http_5xx",
                        status_code=response.status_code,
                    )
                    time.sleep(min(backoff, _MAX_BACKOFF_SECONDS))
                    backoff = min(backoff * _BACKOFF_MULTIPLIER, _MAX_BACKOFF_SECONDS)
                    continue

                response.raise_for_status()

                # ── Parse response ────────────────────────────────────────
                try:
                    data = response.json()
                except Exception as parse_exc:
                    raise GitHubClientError(
                        f"GitHub Advisory returned invalid JSON for {package_name}@{version}: {parse_exc}",
                        error_type="invalid_response",
                    ) from parse_exc

                # GraphQL errors in 200 response body
                if "errors" in data:
                    error_msgs = "; ".join(
                        e.get("message", "unknown") for e in data["errors"]
                    )
                    raise GitHubClientError(
                        f"GitHub Advisory GraphQL error for {package_name}@{version}: {error_msgs}",
                        error_type="invalid_response",
                    )

                nodes: list[dict] = (
                    data
                    .get("data", {})
                    .get("securityVulnerabilities", {})
                    .get("nodes", [])
                )

                # Filter out withdrawn advisories
                active_nodes = [
                    n for n in nodes
                    if not n.get("advisory", {}).get("withdrawnAt")
                ]

                logger.info(
                    "GitHub Advisory | Found %d advisory/ies for %s/%s (filtered %d withdrawn)",
                    len(active_nodes), ecosystem, package_name,
                    len(nodes) - len(active_nodes),
                )
                return active_nodes

            except GitHubClientError:
                raise

            except httpx.TimeoutException as exc:
                logger.warning(
                    "GitHub Advisory | Timeout for %s@%s (attempt %d/%d): %s",
                    package_name, version, attempt, _MAX_RETRIES, exc,
                )
                last_error = GitHubClientError(
                    f"GitHub Advisory request timed out for {package_name}@{version}",
                    error_type="timeout",
                )
                time.sleep(min(backoff, _MAX_BACKOFF_SECONDS))
                backoff = min(backoff * _BACKOFF_MULTIPLIER, _MAX_BACKOFF_SECONDS)

            except httpx.RequestError as exc:
                logger.warning(
                    "GitHub Advisory | Network error for %s@%s (attempt %d/%d): %s",
                    package_name, version, attempt, _MAX_RETRIES, exc,
                )
                last_error = GitHubClientError(
                    f"GitHub Advisory network error for {package_name}@{version}: {exc}",
                    error_type="network",
                )
                time.sleep(min(backoff, _MAX_BACKOFF_SECONDS))
                backoff = min(backoff * _BACKOFF_MULTIPLIER, _MAX_BACKOFF_SECONDS)

        logger.error(
            "GitHub Advisory | All %d retries exhausted for %s@%s",
            _MAX_RETRIES, package_name, version,
        )
        raise last_error or GitHubClientError(
            f"GitHub Advisory failed for {package_name}@{version} after {_MAX_RETRIES} retries",
            error_type="unknown",
        )
