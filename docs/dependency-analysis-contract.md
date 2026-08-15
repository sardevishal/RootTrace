# RootTrace — Dependency Analysis Contract
## Downstream Integration Contract for Vulnerability Intelligence

This document defines the exact contract between the **Dependency Analysis Engine** and downstream consumers (specifically the **Vulnerability Intelligence Engine**, Context Builder / RAG, and AI Explanation modules).

---

### 1. Direct Python Service Interface

Downstream modules inside the backend can invoke the `DependencyAnalysisEngine` directly:

```python
from app.services.dependency.engine import DependencyAnalysisEngine
from app.services.vulnerability.engine import VulnerabilityEngine

# 1. Initialize engines
dep_engine = DependencyAnalysisEngine()
vuln_engine = VulnerabilityEngine()

# 2. Run dependency analysis on a repository
scan_result = dep_engine.analyze(repository_path="/path/to/repo")

# 3. Convert to downstream Package list (adapter)
packages = dep_engine.get_packages_for_vulnerability_scan(
    scan_result,
    include_unresolved=False  # Only packages with exact/resolved versions
)

# 4. Feed directly into the Vulnerability Intelligence Engine
vuln_report = vuln_engine.run_scan(
    packages=packages,
    scan_id=scan_result.scan_id
)
```

---

### 2. Standardized Package Format (Flat Inventory)

Every dependency exported for vulnerability scanning conforms to the canonical `Package` model:

```python
class Package(BaseModel):
    package_name: str  # e.g., "lodash", "requests", "org.springframework:spring-core"
    version: str       # exact resolved version, e.g., "4.17.21", "2.31.0"
    ecosystem: str     # "npm", "PyPI", "Maven", "Go", etc.
```

JSON representation:
```json
[
  {
    "package_name": "lodash",
    "version": "4.17.21",
    "ecosystem": "npm"
  },
  {
    "package_name": "requests",
    "version": "2.31.0",
    "ecosystem": "PyPI"
  },
  {
    "package_name": "org.apache.logging.log4j:log4j-core",
    "version": "2.14.1",
    "ecosystem": "Maven"
  }
]
```

---

### 3. REST API Contract

#### Scan Request
`POST /api/v1/dependencies/analyze`

```json
{
  "repository_path": "/path/to/target/project",
  "scan_id": "optional-uuid-or-job-id",
  "repository_id": "optional-repo-identifier",
  "include_dev_dependencies": true
}
```

#### Scan Response Body
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "repository_path": "/path/to/target/project",
  "status": "completed",
  "total_dependencies": 25,
  "direct_dependencies": 18,
  "transitive_dependencies": 7,
  "manifests_found": 3,
  "manifests_parsed": 3,
  "manifests": [
    {
      "path": "frontend/package.json",
      "manifest_type": "package.json",
      "ecosystem": "npm",
      "has_lockfile": true,
      "lockfile_path": "frontend/package-lock.json"
    }
  ],
  "dependencies": [
    {
      "id": "npm:express@4.18.2",
      "name": "express",
      "version": "4.18.2",
      "version_spec": "^4.18.2",
      "ecosystem": "npm",
      "dependency_type": "runtime",
      "direct": true,
      "transitive": false,
      "depth": 1,
      "source_manifest": "package.json",
      "source_path": "frontend/package.json"
    }
  ],
  "graph": {
    "nodes": {
      "npm:express@4.18.2": { ... }
    },
    "edges": [
      {
        "source": "root:application@0.0.0",
        "target": "npm:express@4.18.2",
        "relationship": "depends_on"
      }
    ],
    "stats": {
      "total_nodes": 26,
      "total_edges": 18,
      "direct_nodes": 18,
      "transitive_nodes": 7,
      "maximum_depth": 2,
      "ecosystems": ["npm", "PyPI"],
      "root_dependency_ids": ["npm:express@4.18.2"],
      "cycles_detected": false,
      "cycle_paths": []
    }
  },
  "normalized_packages": [
    {
      "package_name": "express",
      "version": "4.18.2",
      "version_spec": "^4.18.2",
      "ecosystem": "npm",
      "dependency_id": "npm:express@4.18.2"
    }
  ],
  "errors": [],
  "warnings": []
}
```

---

### 4. Transition Strategy from Mock Loader

1. **Current State (Phase 1 Baseline)**:
   `VulnerabilityEngine` uses `load_mock_packages()` from `mock_data/packages.json`.
2. **Integrated State**:
   `VulnerabilityEngine.run_scan(packages=...)` accepts the package list from `dep_engine.get_packages_for_vulnerability_scan()`.
3. **No Breaking Changes**:
   `load_mock_packages()` remains functional for standalone and offline vulnerability tests.
