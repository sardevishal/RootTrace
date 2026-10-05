"""
clients/epss_client.py

EPSS (Exploit Prediction Scoring System) client for RootTrace.

EPSS is a machine-learning model from FIRST (first.org) that estimates the
probability that a CVE will be exploited in the next 30 days.

API: GET https://api.first.org/data/v1/epss?cve=CVE-XXXX-YYYY[,CVE-...]
     Returns: { data: [{ cve, epss, percentile, date }] }

Design notes:
    - Only CVEs are supported (no GHSA, no OSV-only IDs)
    - Missing / unknown CVEs silently return None — not an error
    - Batch queries accepted (up to 100 CVEs per request)
    - Network / HTTP failures raise EPSSClientError
    - All epss floats are in [0.0, 1.0]
"""

from typing import Optional
import httpx

from app.utils.constants import EPSS_API_BASE_URL, DEFAULT_HTTP_TIMEOUT
from app.utils.logger import get_logger

logger = get_logger(__name__)

# Maximum CVEs per single EPSS API call (FIRST API supports comma-separated list)
_EPSS_BATCH_SIZE = 100


class EPSSClientError(Exception):
    """Raised when the EPSS API call cannot be completed."""

    def __init__(self, message: str, error_type: str, status_code: Optional[int] = None) -> None:
        super().__init__(message)
        self.message = message
        self.error_type = error_type
        self.status_code = status_code

    def __repr__(self) -> str:
        return f"EPSSClientError(type={self.error_type!r}, code={self.status_code}, msg={self.message!r})"


class EPSSClient:
    """
    FIRST EPSS API client — Phase 2D (active).

    Provides both single-CVE and batch-CVE lookups.

    Single CVE usage (backward-compatible with Phase 1 callers):
        client = EPSSClient()
        score = client.get_score("CVE-2021-44228")   # float | None

    Batch usage (preferred — fewer API calls):
        scores = client.query(["CVE-2021-44228", "CVE-2021-23337"])
        # → {"CVE-2021-44228": 0.97321, "CVE-2021-23337": 0.45103}
    """

    def __init__(self, timeout: int = DEFAULT_HTTP_TIMEOUT) -> None:
        self._base_url = EPSS_API_BASE_URL
        self._timeout = timeout

    # ── Public API ────────────────────────────────────────────────────────────

    def get_score(self, cve_id: Optional[str]) -> Optional[float]:
        """
        Fetch the EPSS probability for a single CVE.

        Returns:
            Float in [0.0, 1.0], or None if CVE not found or cve_id is blank.

        Raises:
            EPSSClientError: On network or HTTP errors.
        """
        if not cve_id or not cve_id.upper().startswith("CVE-"):
            return None
        result = self.query([cve_id])
        return result.get(cve_id)

    def query(self, cve_ids: list[str]) -> dict[str, float]:
        """
        Query EPSS scores for a list of CVE IDs.

        Args:
            cve_ids: List of CVE IDs. Non-CVE IDs are silently ignored.

        Returns:
            Dict mapping CVE-ID → epss_score in [0.0, 1.0].
            CVEs not found in the EPSS database are absent from the dict.

        Raises:
            EPSSClientError: On network or API error.
        """
        real_cves = [c for c in cve_ids if c and c.upper().startswith("CVE-")]
        if not real_cves:
            return {}

        result: dict[str, float] = {}
        for i in range(0, len(real_cves), _EPSS_BATCH_SIZE):
            batch = real_cves[i : i + _EPSS_BATCH_SIZE]
            result.update(self._query_batch(batch))

        return result

    # ── Internal ──────────────────────────────────────────────────────────────

    def _query_batch(self, cve_ids: list[str]) -> dict[str, float]:
        cve_param = ",".join(cve_ids)
        logger.info("EPSS | Querying %d CVE(s): %s", len(cve_ids), cve_param[:80])

        try:
            with httpx.Client(timeout=self._timeout) as client:
                response = client.get(self._base_url, params={"cve": cve_param})
        except httpx.TimeoutException as exc:
            raise EPSSClientError(
                f"EPSS request timed out after {self._timeout}s",
                error_type="timeout",
            ) from exc
        except httpx.RequestError as exc:
            raise EPSSClientError(
                f"Network error querying EPSS: {exc}",
                error_type="network",
            ) from exc

        if response.status_code == 429:
            raise EPSSClientError("Rate limited by EPSS API", error_type="rate_limit", status_code=429)
        if response.status_code >= 500:
            raise EPSSClientError(
                f"EPSS server error: HTTP {response.status_code}",
                error_type="http_5xx",
                status_code=response.status_code,
            )
        if response.status_code >= 400:
            raise EPSSClientError(
                f"EPSS client error: HTTP {response.status_code}",
                error_type="http_4xx",
                status_code=response.status_code,
            )

        try:
            data = response.json()
        except (ValueError, KeyError) as exc:
            raise EPSSClientError("EPSS returned invalid JSON", error_type="invalid_response") from exc

        result: dict[str, float] = {}
        for entry in data.get("data", []):
            cve = entry.get("cve")
            epss_str = entry.get("epss")
            if cve and epss_str is not None:
                try:
                    result[cve] = float(epss_str)
                except (ValueError, TypeError):
                    logger.warning("EPSS | Could not parse score for %s: %r", cve, epss_str)

        logger.info("EPSS | Received %d score(s) for %d requested CVE(s)", len(result), len(cve_ids))
        return result
