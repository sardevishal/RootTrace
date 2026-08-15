# RootTrace — Dependency Analysis Engine
## Architecture & Technical Specification

### 1. Purpose
The **Dependency Analysis Engine** is a core software supply-chain intelligence module in RootTrace. It sits immediately after repository ingestion and upstream of the Vulnerability Intelligence Engine. It is responsible for recursively discovering, parsing, normalizing, and modeling software dependencies across multiple ecosystems, constructing a directed dependency graph, and providing a clean dependency inventory for downstream vulnerability intelligence.

```
Repository / Codebase
        ↓
Dependency Analysis Engine
        ↓ (Normalized Dependency Inventory + Graph)
Vulnerability Intelligence Engine
        ↓ (OSV, NVD, GitHub Advisories, EPSS)
Context Builder / RAG
        ↓
LLM Security Explanation
        ↓
Dashboard / Reports
```

---

### 2. Core Responsibilities
- **Manifest Detection**: Recursively discovers package manifests (`package.json`, `requirements.txt`, `pom.xml`, `go.mod`, `Dockerfile`) and associated lockfiles in mono-repo and standard repositories.
- **Static Multi-Ecosystem Parsing**: Pure static extraction without code execution or dynamic package installation.
- **Dependency Normalization**: Standardizes naming conventions, versions, and ecosystem identifiers.
- **Resolution Strategy**: Leverages lockfiles (`package-lock.json`), exact specifiers, and manifest declarations to capture exact versions without fabricating non-existent versions.
- **Direct vs. Transitive Analysis**: Identifies directly declared dependencies vs. transitive/indirect dependencies, assigning graph depths.
- **Graph Construction & Analysis**: Models dependencies as directed graphs with nodes, edges, cycle detection, depth computation, and graph metrics.
- **Downstream Integration Contract**: Provides clean, standardized inputs to the Vulnerability Intelligence Engine.

---

### 3. Architecture Overview

```
DependencyAnalysisEngine
    │
    ├── RepositoryScanner        (Validates repo path, prevents path traversal, filters ignore paths)
    │
    ├── ManifestDetector         (Recursively finds package manifests & links lockfiles)
    │
    ├── Parsers
    │   ├── PackageJsonParser    (npm dependencies, devDeps, optionalDeps, peerDeps, lockfile v1/v2/v3)
    │   ├── RequirementsParser   (PyPI PEP 508 parsing, version operators, extras, comments)
    │   ├── PomParser            (Maven XML parsing, groupId:artifactId, scopes, optional tags)
    │   ├── GoModParser          (Go module require blocks, indirect markers, module exclusions)
    │   └── DockerfileParser     (Static regex detection for npm, pip, apt-get, apk, yum)
    │
    ├── DependencyNormalizer     (Ecosystem aliases, canonical package identity, deduplication)
    │
    ├── DependencyResolver       (Exact version extraction, lockfile linkage, unresolved tracking)
    │
    ├── TransitiveAnalyzer       (Direct/transitive classification, depth assignment)
    │
    ├── GraphBuilder             (Constructs directed nodes & edges from virtual ROOT)
    │
    └── GraphAnalyzer            (DFS cycle detection, BFS shortest paths, depth & metrics)
```

---

### 4. Supported Manifests & Parsers

| Manifest | Ecosystem | Supported Features | Resolution Source |
|---|---|---|---|
| `package.json` | `npm` | dependencies, devDependencies, optionalDependencies, peerDependencies | `package-lock.json` (v1/v2/v3) |
| `requirements.txt` | `PyPI` | PEP 508 specifiers (`==`, `>=`, `~=`, `<=`, `<`, `!=`), `[extras]`, inline comments | Exact equality (`==`) |
| `pom.xml` | `Maven` | XML namespaces, direct/managed deps, scopes (`compile`, `test`, `provided`), optional flags | `<version>` tags |
| `go.mod` | `Go` | Single & block `require`, `// indirect` markers, `replace` metadata, self-module exclusion | Directive version |
| `Dockerfile` | `mixed` / `apt` / `apk` | `RUN npm install`, `RUN pip install`, `RUN apt-get install`, `RUN apk add` | Explicit version separators |

---

### 5. Dependency & Graph Data Models

#### Dependency Model (`models/dependency.py`)
```json
{
  "id": "npm:lodash@4.17.21",
  "name": "lodash",
  "version": "4.17.21",
  "version_spec": "^4.17.0",
  "ecosystem": "npm",
  "dependency_type": "runtime",
  "direct": true,
  "transitive": false,
  "depth": 1,
  "source_manifest": "package.json",
  "source_path": "frontend/package.json"
}
```

#### Graph Model (`models/dependency_graph.py`)
- **Nodes**: Uniquely identified by `id`, contains package metadata, classification, and depth.
- **Edges**: Directed relationships (`source` -> `target`, `relationship: "depends_on" | "dev_depends_on" | "peer_depends_on" | "optional_depends_on"`).
- **Virtual Root**: `root:application@0.0.0` acts as origin for all direct dependencies.
- **Stats**: Total nodes, total edges, direct/transitive node counts, maximum depth, detected cycles.

---

### 6. API Reference

#### `POST /api/v1/dependencies/analyze`
**Request Body**:
```json
{
  "repository_path": "/absolute/or/relative/path/to/repo",
  "scan_id": "optional-custom-scan-id",
  "repository_id": "optional-repo-identifier",
  "include_dev_dependencies": true
}
```

**Response**:
```json
{
  "scan_id": "scan-123",
  "repository_path": "/path/to/repo",
  "status": "completed",
  "total_dependencies": 15,
  "direct_dependencies": 12,
  "transitive_dependencies": 3,
  "manifests_found": 3,
  "manifests_parsed": 3,
  "manifests": [...],
  "dependencies": [...],
  "graph": {
    "nodes": {...},
    "edges": [...],
    "stats": {...}
  },
  "normalized_packages": [
    {
      "package_name": "lodash",
      "version": "4.17.21",
      "ecosystem": "npm"
    }
  ],
  "errors": [],
  "warnings": []
}
```

#### `GET /api/v1/dependencies/health`
Returns health status and module version.

---

### 7. Security Model
- **Zero Execution Policy**: No `npm`, `pip`, `mvn`, `go`, or `docker` processes are executed.
- **Path Traversal Prevention**: Resolves canonical realpaths, verifies directory boundaries, and enforces depth recursion limits.
- **Resilient Error Handling**: Manifest syntax failures in one file (e.g. malformed XML) do not crash the entire scan; errors are recorded as structured objects and other manifests continue processing.

---

### 8. Testing & Verification
- **Unit Tests**: Manifest detection, each parser type, normalizer, resolver, transitive analyzer, and graph builder.
- **Integration Tests**: Full end-to-end repository scan on sample multi-ecosystem repository, API verification, and direct feeding into `VulnerabilityEngine`.
