import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend')))

from app.models.package import Package
from app.services.vulnerability.fetcher import VulnerabilityFetcher

def main():
    fetcher = VulnerabilityFetcher()
    pkg = Package(package_name="lodash", version="4.17.15", ecosystem="npm")
    vulns = fetcher.fetch(pkg)
    print(f"Found {len(vulns)} vulnerabilities for lodash@4.17.15:")
    for v in vulns:
        print(f" - {v.osv_id}: {v.cve_id} (Severity: {v.severity})")

if __name__ == "__main__":
    main()
