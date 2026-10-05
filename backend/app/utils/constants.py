"""
utils/constants.py

Project-wide constants for RootTrace.
Covers the Vulnerability Intelligence Engine and the Dependency Analysis Engine.
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
    "apt",
    "apk",
    "yum",
    "mixed",
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

# ─── Dependency Analysis Engine ───────────────────────────────────────────────
DEPENDENCY_ANALYSIS_VERSION = "1.0.0"

# Supported manifest file types
SUPPORTED_MANIFEST_TYPES = [
    "package.json",
    "requirements.txt",
    "pom.xml",
    "go.mod",
    "Dockerfile",
]

# Manifest type → ecosystem mapping
MANIFEST_ECOSYSTEM_MAP: dict[str, str] = {
    "package.json": "npm",
    "requirements.txt": "PyPI",
    "pom.xml": "Maven",
    "go.mod": "Go",
    "Dockerfile": "mixed",
}

# Dependency types
DEP_TYPE_RUNTIME = "runtime"
DEP_TYPE_DEVELOPMENT = "development"
DEP_TYPE_OPTIONAL = "optional"
DEP_TYPE_PEER = "peer"
DEP_TYPE_INDIRECT = "indirect"
DEP_TYPE_BUILD = "build"
DEP_TYPE_PROVIDED = "provided"
DEP_TYPE_TEST = "test"
DEP_TYPE_SYSTEM = "system"
DEP_TYPE_UNKNOWN = "unknown"

# Scan status
SCAN_STATUS_COMPLETED = "completed"
SCAN_STATUS_COMPLETED_WITH_WARNINGS = "completed_with_warnings"
SCAN_STATUS_FAILED = "failed"
SCAN_STATUS_RUNNING = "running"

# Graph edge relationship labels
EDGE_DEPENDS_ON = "depends_on"
EDGE_DEV_DEPENDS_ON = "dev_depends_on"
EDGE_PEER_DEPENDS_ON = "peer_depends_on"
EDGE_OPTIONAL_DEPENDS_ON = "optional_depends_on"

# Ecosystem name normalization map (raw → canonical)
ECOSYSTEM_ALIAS_MAP: dict[str, str] = {
    "npm": "npm",
    "node": "npm",
    "nodejs": "npm",
    "pypi": "PyPI",
    "python": "PyPI",
    "pip": "PyPI",
    "maven": "Maven",
    "java": "Maven",
    "go": "Go",
    "golang": "Go",
    "rubygems": "RubyGems",
    "ruby": "RubyGems",
    "nuget": "NuGet",
    "dotnet": "NuGet",
    "crates.io": "crates.io",
    "rust": "crates.io",
    "cargo": "crates.io",
    "packagist": "Packagist",
    "composer": "Packagist",
    "php": "Packagist",
    "apt": "apt",
    "apt-get": "apt",
    "apk": "apk",
    "yum": "yum",
    "mixed": "mixed",
    "unknown": "unknown",
}

# Max filesystem recursion depth for repository scanning
MAX_SCAN_DEPTH = 20

