import sys
import os
import json

# Add backend to path so we can import app modules
backend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'backend'))
sys.path.insert(0, backend_path)

from app.services.dependency.integration.vulnerability_adapter import DependencyVulnerabilityAdapter
from app.services.vulnerability.engine import VulnerabilityEngine

def main():
    repo_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'integration_test_repository'))
    scan_id = "scan-e2e-001"

    print("==================================================")
    print("🚀 RootTrace End-to-End Pipeline Test")
    print("==================================================")

    # 1. Initialize the adapter (which wraps the Dependency Engine)
    print(f"\n[1] Initializing DependencyVulnerabilityAdapter for repo: {repo_path}")
    adapter = DependencyVulnerabilityAdapter(repository_path=repo_path)

    # 2. Initialize the Vulnerability Engine
    print("\n[2] Initializing VulnerabilityEngine")
    vuln_engine = VulnerabilityEngine()

    # 3. Run the scan!
    print("\n[3] Running VulnerabilityEngine.run_scan() with the Adapter...")
    result = vuln_engine.run_scan(package_provider=adapter, scan_id=scan_id)

    # 4. Output the results
    print("\n[4] Scan Complete! Final Output:")
    print("==================================================")
    print(json.dumps(result.model_dump(), indent=2))
    print("==================================================")

if __name__ == "__main__":
    main()
