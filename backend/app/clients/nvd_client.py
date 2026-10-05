"""
clients/nvd_client.py

Client for the NIST National Vulnerability Database (NVD) REST API 2.0.
https://nvd.nist.gov/developers/vulnerabilities

API endpoint:
    GET https://services.nvd.nist.gov/rest/json/cves/2.0
    ?keywordSearch=<name> <version>

NVD rate limits:
    - Without API key: 5 requests per 30 seconds
    - With API key:    50 requests per 30 seconds

Reliability features (mirrors OSVClient design):
    - Configurable request timeout
    - Bounded exponential-backoff retry
    - 429 Too Many Requests → honour Retry-After or backoff
    - Per-request structured error semantics (NVDClientError)
    - Invalid/malformed response handling
    - HTTP 4xx/5xx classification
    - Optional API key support (NVD_API_KEY env var)
"""

import os
import time
from typing import Optional
import httpx

from app.utils.logger import get_logger
from app.utils.constants import DEFAULT_HTTP_TIMEOUT

logger = get_logger(__name__)

# NVD API constants
NVD_API_BASE_URL = "https://services.nvd.nist.gov"
NVD_CVE_ENDPOINT = "/rest/json/cves/2.0"

# Retry configuration (same pattern as OSVClient)
_MAX_RETRIES = 3
_BASE_BACKOFF_SECONDS = 2.0   # NVD is stricter on rate limits — start higher
_BACKOFF_MULTIPLIER = 2.0
_MAX_BACKOFF_SECONDS = 30.0

# HTTP status codes that should NOT be retried
_NO_RETRY_STATUSES = {400, 401, 403, 404, 422}


class NVDClientError(Exception):
    """Structured error raised when NVD cannot return a usable result."""

    def __init__(
        self,
        message: str,
        error_type: str = "unknown",
        status_code: Optional[int] = None,
    ) -> None:
        super().__init__(message)
        self.error_type = error_type  # timeout | network | http_4xx | http_5xx | rate_limit | invalid_response
        self.status_code = status_code
        self.message = message


class NVDClient:
    """
    Client for the NVD REST API 2.0.

    Searches CVE records by package name + version keyword.

    The NVD API does not offer a native package-version query like OSV does.
    We use keyword search, which may return false positives. The caller
    (NVDSource → VulnerabilityFetcher → Deduplicator) filters by CVE identity.

    API key:
        Set NVD_API_KEY environment variable to increase rate limits.
        If not set, client operates in anonymous mode (5 req/30s).
    """

    def __init__(self, timeout: int = DEFAULT_HTTP_TIMEOUT) -> None:
        self._timeout = timeout
        self._api_key: Optional[str] = os.environ.get("NVD_API_KEY")
        if self._api_key:
            logger.info("NVD | API key configured (rate limit: 50 req/30s)")
        else:
            logger.debug("NVD | No API key — anonymous mode (rate limit: 5 req/30s)")

    def _headers(self) -> dict:
        """Build request headers, injecting API key if available."""
        h = {"Accept": "application/json"}
        if self._api_key:
            h["apiKey"] = self._api_key
        return h

    def query(
        self,
        package_name: str,
        version: str,
        ecosystem: str,  # noqa: ARG002
    ) -> list[dict]:
        """
        Query NVD for CVE records related to the given package + version.

        Uses keyword search (package_name + version). Results may include
        false positives — the normalizer and deduplicator handle filtering.

        Args:
            package_name: Name of the package (e.g. 'lodash').
            version:      Exact version string (e.g. '4.17.15').
            ecosystem:    Ecosystem (unused by NVD — kept for interface compatibility).

        Returns:
            List of raw NVD CVE item dicts (NVD JSON 2.0 format).
            Each item: {"cve": {"id": "CVE-...", "descriptions": [...], ...}}

        Raises:
            NVDClientError: If NVD could not be reached or returned an unusable response.
        """
        url = f"{NVD_API_BASE_URL}{NVD_CVE_ENDPOINT}"
        keyword = f"{package_name} {version}"
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": 20,
        }

        logger.info("NVD | Querying: %s@%s (keyword: '%s')", package_name, version, keyword)

        last_error: Optional[NVDClientError] = None
        backoff = _BASE_BACKOFF_SECONDS

        for attempt in range(1, _MAX_RETRIES + 1):
            try:
                with httpx.Client(timeout=self._timeout) as client:
                    response = client.get(
                        url,
                        params=params,
                        headers=self._headers(),
                    )

                # ── Rate limiting ────────────────────────────────────────
                if response.status_code == 429:
                    retry_after = float(response.headers.get("Retry-After", backoff))
                    wait = min(retry_after, _MAX_BACKOFF_SECONDS)
                    logger.warning(
                        "NVD | 429 Too Many Requests for %s@%s — waiting %.1fs (attempt %d/%d)",
                        package_name, version, wait, attempt, _MAX_RETRIES,
                    )
                    time.sleep(wait)
                    backoff = min(backoff * _BACKOFF_MULTIPLIER, _MAX_BACKOFF_SECONDS)
                    last_error = NVDClientError(
                        f"Rate limited by NVD after {attempt} attempt(s)",
                        error_type="rate_limit",
                        status_code=429,
                    )
                    continue

                # ── Non-retryable 4xx ────────────────────────────────────
                if response.status_code in _NO_RETRY_STATUSES:
                    raise NVDClientError(
                        f"NVD HTTP {response.status_code} for {package_name}@{version}",
                        error_type="http_4xx",
                        status_code=response.status_code,
                    )

                # ── 5xx server errors — retry ────────────────────────────
                if response.status_code >= 500:
                    logger.warning(
                        "NVD | HTTP %d for %s@%s (attempt %d/%d) — retrying",
                        response.status_code, package_name, version, attempt, _MAX_RETRIES,
                    )
                    last_error = NVDClientError(
                        f"NVD HTTP {response.status_code} for {package_name}@{version}",
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
                    raise NVDClientError(
                        f"NVD returned invalid JSON for {package_name}@{version}: {parse_exc}",
                        error_type="invalid_response",
                    ) from parse_exc

                if not isinstance(data, dict):
                    raise NVDClientError(
                        f"NVD returned unexpected type ({type(data).__name__}) for {package_name}@{version}",
                        error_type="invalid_response",
                    )

                raw_items: list[dict] = data.get("vulnerabilities", [])
                logger.info(
                    "NVD | Found %d CVE record(s) for keyword '%s'",
                    len(raw_items),
                    keyword,
                )
                return raw_items

            except NVDClientError:
                raise

            except httpx.TimeoutException as exc:
                logger.warning(
                    "NVD | Timeout for %s@%s (attempt %d/%d): %s",
                    package_name, version, attempt, _MAX_RETRIES, exc,
                )
                last_error = NVDClientError(
                    f"NVD request timed out for {package_name}@{version}",
                    error_type="timeout",
                )
                time.sleep(min(backoff, _MAX_BACKOFF_SECONDS))
                backoff = min(backoff * _BACKOFF_MULTIPLIER, _MAX_BACKOFF_SECONDS)

            except httpx.RequestError as exc:
                logger.warning(
                    "NVD | Network error for %s@%s (attempt %d/%d): %s",
                    package_name, version, attempt, _MAX_RETRIES, exc,
                )
                last_error = NVDClientError(
                    f"NVD network error for {package_name}@{version}: {exc}",
                    error_type="network",
                )
                time.sleep(min(backoff, _MAX_BACKOFF_SECONDS))
                backoff = min(backoff * _BACKOFF_MULTIPLIER, _MAX_BACKOFF_SECONDS)

        # All retries exhausted
        logger.error(
            "NVD | All %d retries exhausted for %s@%s",
            _MAX_RETRIES, package_name, version,
        )
        raise last_error or NVDClientError(
            f"NVD failed for {package_name}@{version} after {_MAX_RETRIES} retries",
            error_type="unknown",
        )
