"""
clients/osv_client.py

Responsible ONLY for communicating with the OSV (Open Source Vulnerabilities) API.
https://osv.dev/docs/

This client knows nothing about NVD, GitHub, or any other source.
It takes a package and returns raw OSV response data which is then
passed to the normalizer.
"""

import httpx
from typing import Optional
from app.utils.logger import get_logger
from app.utils.constants import OSV_API_BASE_URL, OSV_QUERY_ENDPOINT, DEFAULT_HTTP_TIMEOUT

logger = get_logger(__name__)


class OSVClient:
    """
    Client for the OSV REST API v1.
    Queries the /query endpoint to find vulnerabilities for a specific package version.
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
            Returns empty list on error (non-fatal — logged and swallowed).
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

        try:
            with httpx.Client(timeout=self._timeout) as client:
                response = client.post(url, json=payload)
                response.raise_for_status()
                data = response.json()
                vulns: list[dict] = data.get("vulns", [])
                logger.info(
                    "OSV | Found %d vulnerability/ies for %s@%s",
                    len(vulns),
                    package_name,
                    version,
                )
                return vulns

        except httpx.HTTPStatusError as exc:
            logger.error(
                "OSV | HTTP %s for %s@%s — %s",
                exc.response.status_code,
                package_name,
                version,
                exc,
            )
            return []

        except httpx.RequestError as exc:
            logger.error(
                "OSV | Request failed for %s@%s — %s",
                package_name,
                version,
                exc,
            )
            return []
