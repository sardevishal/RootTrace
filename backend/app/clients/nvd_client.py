"""
clients/nvd_client.py

Responsible ONLY for communicating with the NVD (National Vulnerability Database) API.
https://nvd.nist.gov/developers/vulnerabilities

Phase 2 integration — currently returns an empty list (stub).
Replace the `query` method body when Phase 3 begins.
"""

from typing import Optional
from app.utils.logger import get_logger
from app.utils.constants import NVD_API_BASE_URL, DEFAULT_HTTP_TIMEOUT

logger = get_logger(__name__)


class NVDClient:
    """
    Client for the NVD REST API v2.0.

    Phase 1 Status: STUB — always returns [].
    Phase 3 TODO   : Implement real HTTP calls to NVD using a CVE keyword or
                     CPE match string derived from the package name/version.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        timeout: int = DEFAULT_HTTP_TIMEOUT,
    ) -> None:
        self._base_url = NVD_API_BASE_URL
        self._api_key = api_key  # NVD allows higher rate limits with an API key
        self._timeout = timeout

    def query(
        self,
        package_name: str,
        version: str,
        ecosystem: str,
    ) -> list[dict]:
        """
        Query NVD for vulnerabilities related to the given package.

        Args:
            package_name: Name of the package.
            version:      Exact version string.
            ecosystem:    Package ecosystem (informational only for NVD).

        Returns:
            List of raw NVD CVE item dicts.

        Phase 1:
            Returns empty list — NVD integration is planned for Phase 3.
        """
        # ── Phase 1 stub ──────────────────────────────────────────────────────
        logger.info(
            "NVD | Skipping %s@%s (Phase 3 — not yet integrated).",
            package_name,
            version,
        )
        return []

        # ── Phase 3 implementation template (do NOT delete) ───────────────────
        # import httpx
        # params = {
        #     "keywordSearch": f"{package_name} {version}",
        #     "resultsPerPage": NVD_RESULTS_PER_PAGE,
        # }
        # headers = {}
        # if self._api_key:
        #     headers["apiKey"] = self._api_key
        #
        # try:
        #     with httpx.Client(timeout=self._timeout) as client:
        #         response = client.get(self._base_url, params=params, headers=headers)
        #         response.raise_for_status()
        #         data = response.json()
        #         return data.get("vulnerabilities", [])
        # except Exception as exc:
        #     logger.error("NVD | Request failed for %s@%s — %s", package_name, version, exc)
        #     return []
