"""
clients/osv_client.py

Responsible ONLY for communicating with the OSV (Open Source Vulnerabilities) API.
https://osv.dev/docs/

This client knows nothing about NVD, GitHub, or any other source.

Reliability features (Phase 2B - Task 9):
  - Configurable request timeout
  - Bounded exponential-backoff retry (non-2xx and network errors)
  - 429 Too Many Requests → honour Retry-After header or use backoff
  - Per-request structured error semantics (OSVClientError)
  - Invalid/malformed response handling (no crash, structured error)
  - HTTP 4xx/5xx classification
"""

import time
from typing import Optional
import httpx

from app.utils.logger import get_logger
from app.utils.constants import OSV_API_BASE_URL, OSV_QUERY_ENDPOINT, DEFAULT_HTTP_TIMEOUT

logger = get_logger(__name__)

# Retry configuration
_MAX_RETRIES = 3
_BASE_BACKOFF_SECONDS = 1.0   # first retry wait
_BACKOFF_MULTIPLIER = 2.0     # exponential factor
_MAX_BACKOFF_SECONDS = 16.0

# HTTP status codes that should NOT be retried (client errors)
_NO_RETRY_STATUSES = {400, 401, 403, 404, 422}

class OSVClientError(Exception):
    """Structured error raised when OSV cannot return a usable result."""

    def __init__(self, message: str, error_type: str = "unknown", status_code: Optional[int] = None):
        super().__init__(message)
        self.error_type = error_type          # "timeout" | "network" | "http_4xx" | "http_5xx" | "rate_limit" | "invalid_response"
        self.status_code = status_code
        self.message = message


class OSVClient:
    """
    Client for the OSV REST API v1.

    Queries the /query endpoint to find vulnerabilities for a specific package version.
    Raises OSVClientError on failure instead of silently returning [].
    The caller (VulnerabilityFetcher) is responsible for deciding how to handle errors.
    """

    def __init__(self, timeout: int = DEFAULT_HTTP_TIMEOUT) -> None:
        self._base_url = OSV_API_BASE_URL
        self._timeout = timeout

    def query(
        self,
        package_name: str,
        version: str,
        ecosystem: str,
    ) -> list[dict]:
        """
        Query OSV for vulnerabilities affecting the given package + version.

        Args:
            package_name: Name of the package (e.g. 'lodash').
            version:      Exact version string (e.g. '4.17.15').
            ecosystem:    OSV ecosystem name (e.g. 'npm', 'PyPI').

        Returns:
            List of raw OSV vulnerability dicts.

        Raises:
            OSVClientError: If OSV could not be reached or returned an unusable response.
        """
        url = f"{self._base_url}{OSV_QUERY_ENDPOINT}"
        payload = {
            "version": version,
            "package": {
                "name": package_name,
                "ecosystem": ecosystem,
            },
        }

        logger.info("OSV | Querying %s %s@%s", ecosystem, package_name, version)

        last_error: Optional[OSVClientError] = None
        backoff = _BASE_BACKOFF_SECONDS

        for attempt in range(1, _MAX_RETRIES + 1):
            try:
                with httpx.Client(timeout=self._timeout) as client:
                    response = client.post(url, json=payload)

                # ── Rate limiting ────────────────────────────────────────
                if response.status_code == 429:
                    retry_after = float(response.headers.get("Retry-After", backoff))
                    wait = min(retry_after, _MAX_BACKOFF_SECONDS)
                    logger.warning(
                        "OSV | 429 Too Many Requests for %s@%s — waiting %.1fs (attempt %d/%d)",
                        package_name, version, wait, attempt, _MAX_RETRIES,
                    )
                    time.sleep(wait)
                    backoff = min(backoff * _BACKOFF_MULTIPLIER, _MAX_BACKOFF_SECONDS)
                    last_error = OSVClientError(
                        f"Rate limited by OSV after {attempt} attempt(s)",
                        error_type="rate_limit",
                        status_code=429,
                    )
                    continue

                # ── Non-retryable 4xx ────────────────────────────────────
                if response.status_code in _NO_RETRY_STATUSES:
                    raise OSVClientError(
                        f"OSV HTTP {response.status_code} for {package_name}@{version}",
                        error_type="http_4xx",
                        status_code=response.status_code,
                    )

                # ── 5xx server errors — retry ────────────────────────────
                if response.status_code >= 500:
                    logger.warning(
                        "OSV | HTTP %d for %s@%s (attempt %d/%d) — retrying",
                        response.status_code, package_name, version, attempt, _MAX_RETRIES,
                    )
                    last_error = OSVClientError(
                        f"OSV HTTP {response.status_code} for {package_name}@{version}",
                        error_type="http_5xx",
                        status_code=response.status_code,
                    )
                    time.sleep(min(backoff, _MAX_BACKOFF_SECONDS))
                    backoff = min(backoff * _BACKOFF_MULTIPLIER, _MAX_BACKOFF_SECONDS)
                    continue

                response.raise_for_status()

                # ── Parse response ───────────────────────────────────────
                try:
                    data = response.json()
                except Exception as parse_exc:
                    raise OSVClientError(
                        f"OSV returned invalid JSON for {package_name}@{version}: {parse_exc}",
                        error_type="invalid_response",
                    ) from parse_exc

                if not isinstance(data, dict):
                    raise OSVClientError(
                        f"OSV returned unexpected response type ({type(data).__name__}) for {package_name}@{version}",
                        error_type="invalid_response",
                    )

                vulns: list[dict] = data.get("vulns", [])
                logger.info(
                    "OSV | Found %d vulnerability/ies for %s@%s",
                    len(vulns), package_name, version,
                )
                return vulns

            except OSVClientError:
                raise   # already structured, let it propagate

            except httpx.TimeoutException as exc:
                logger.warning(
                    "OSV | Timeout for %s@%s (attempt %d/%d): %s",
                    package_name, version, attempt, _MAX_RETRIES, exc,
                )
                last_error = OSVClientError(
                    f"OSV request timed out for {package_name}@{version}",
                    error_type="timeout",
                )
                time.sleep(min(backoff, _MAX_BACKOFF_SECONDS))
                backoff = min(backoff * _BACKOFF_MULTIPLIER, _MAX_BACKOFF_SECONDS)

            except httpx.RequestError as exc:
                logger.warning(
                    "OSV | Network error for %s@%s (attempt %d/%d): %s",
                    package_name, version, attempt, _MAX_RETRIES, exc,
                )
                last_error = OSVClientError(
                    f"OSV network error for {package_name}@{version}: {exc}",
                    error_type="network",
                )
                time.sleep(min(backoff, _MAX_BACKOFF_SECONDS))
                backoff = min(backoff * _BACKOFF_MULTIPLIER, _MAX_BACKOFF_SECONDS)

        # All retries exhausted
        logger.error(
            "OSV | All %d retries exhausted for %s@%s",
            _MAX_RETRIES, package_name, version,
        )
        raise last_error or OSVClientError(
            f"OSV failed for {package_name}@{version} after {_MAX_RETRIES} retries",
            error_type="unknown",
        )
