"""
utils/constants.py

Project-wide constants for the Vulnerability Intelligence Engine.
"""

# ─── Supported Ecosystems ────────────────────────────────────────────────────
SUPPORTED_ECOSYSTEMS = [
    "npm",
    "PyPI",
    "Maven",
    "Go",
    "RubyGems",
    "NuGet",
    "crates.io",
    "Packagist",
]

# ─── OSV API ─────────────────────────────────────────────────────────────────
OSV_API_BASE_URL = "https://api.osv.dev/v1"
OSV_QUERY_ENDPOINT = "/query"
OSV_BATCH_ENDPOINT = "/querybatch"

# ─── NVD API ─────────────────────────────────────────────────────────────────
NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RESULTS_PER_PAGE = 20

# ─── GitHub Advisory API ─────────────────────────────────────────────────────
GITHUB_GRAPHQL_URL = "https://api.github.com/graphql"

# ─── EPSS API ────────────────────────────────────────────────────────────────
EPSS_API_BASE_URL = "https://api.first.org/data/v1/epss"

# ─── Risk Score Thresholds (CVSS-based, Phase 1) ─────────────────────────────
CVSS_CRITICAL_THRESHOLD = 9.0
CVSS_HIGH_THRESHOLD = 7.0
CVSS_MEDIUM_THRESHOLD = 4.0
# Anything below MEDIUM is LOW

# ─── Severity Labels ─────────────────────────────────────────────────────────
SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"
SEVERITY_NONE = "NONE"
SEVERITY_UNKNOWN = "UNKNOWN"

# ─── HTTP Timeouts (seconds) ─────────────────────────────────────────────────
DEFAULT_HTTP_TIMEOUT = 15

# ─── Mock Data Path ──────────────────────────────────────────────────────────
MOCK_PACKAGES_PATH = "app/mock_data/packages.json"
