import sys
import os
import json

# Add backend to path so we can import app modules
backend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'backend'))
sys.path.insert(0, backend_path)

from app.services.pipeline import PipelineOrchestrator

def main():
    repo_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'integration_test_repository'))
    
    print("==================================================")
    print("🚀 RootTrace Unified Pipeline Test (Phase 2B)")
    print("==================================================")

    orchestrator = PipelineOrchestrator()
    result = orchestrator.run_pipeline(repository_path=repo_path, scan_id="scan-pipeline-001")

    print("\n[Unified Scan Complete!] Final Output:")
    print("==================================================")
    print(json.dumps(result.model_dump(), indent=2))
    print("==================================================")

if __name__ == "__main__":
    main()
