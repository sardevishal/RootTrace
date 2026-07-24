"""
clients/epss_client.py

Responsible ONLY for fetching EPSS (Exploit Prediction Scoring System) scores.
https://www.first.org/epss/api

Phase 5 integration — currently returns 0.0 for every CVE (stub).
EPSS gives the probability (0–1) that a CVE will be exploited in the wild.
"""

from typing import Optional
from app.utils.logger import get_logger
from app.utils.constants import EPSS_API_BASE_URL, DEFAULT_HTTP_TIMEOUT

logger = get_logger(__name__)


class EPSSClient:
    """
    Client for the FIRST.org EPSS API.

    Phase 1 Status: STUB — returns 0.0 for all CVEs.
    Phase 5 TODO   : Implement real HTTP calls using the CVE ID.
    """

    def __init__(self, timeout: int = DEFAULT_HTTP_TIMEOUT) -> None:
        self._base_url = EPSS_API_BASE_URL
        self._timeout = timeout

    def get_score(self, cve_id: Optional[str]) -> float:
        """
        Fetch the EPSS probability score for the given CVE.

        Args:
            cve_id: CVE identifier (e.g. 'CVE-2021-44228').
                    None if the vulnerability has no CVE assigned yet.

        Returns:
            Float in [0.0, 1.0] representing exploit probability.

        Phase 1:
            Always returns 0.0.
        """
        if not cve_id:
            return 0.0

        # ── Phase 1 stub ──────────────────────────────────────────────────────
        logger.debug(
            "EPSS | Returning stub score 0.0 for %s (Phase 5 — not yet integrated).",
            cve_id,
        )
        return 0.0

        # ── Phase 5 implementation template (do NOT delete) ───────────────────
        # import httpx
        # try:
        #     with httpx.Client(timeout=self._timeout) as client:
        #         resp = client.get(self._base_url, params={"cve": cve_id})
        #         resp.raise_for_status()
        #         data = resp.json()
        #         scores = data.get("data", [])
        #         if scores:
        #             return float(scores[0].get("epss", 0.0))
        #         return 0.0
        # except Exception as exc:
        #     logger.error("EPSS | Request failed for %s — %s", cve_id, exc)
        #     return 0.0
