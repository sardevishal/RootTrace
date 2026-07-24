# RootTrace — Vulnerability Intelligence Engine

## Module: Vulnerability Intelligence Engine (Phase 1)

Built with clean architecture and mock data.  
Ready to connect with the Dependency Analysis Engine (your teammate's module) without changing anything except `mock_loader.py`.

---

## Folder Structure

```
backend/
└── app/
    ├── api/              ← FastAPI routes (thin layer only)
    │   └── vulnerability.py
    ├── services/
    │   └── vulnerability/
    │       ├── engine.py       ← Heart of the module
    │       ├── fetcher.py      ← Coordinates all sources
    │       ├── normalizer.py   ← Converts raw API → Vulnerability model
    │       ├── risk_score.py   ← CVSS-based scoring (Phase 1)
    │       ├── validator.py    ← Package validation
    │       └── mock_loader.py  ← REPLACE THIS when teammate's module is ready
    ├── clients/
    │   ├── osv_client.py           ← ACTIVE (Phase 2)
    │   ├── nvd_client.py           ← Stub (Phase 3)
    │   ├── github_advisory_client.py ← Stub (Phase 4)
    │   └── epss_client.py          ← Stub (Phase 5)
    ├── models/           ← Pydantic domain models
    ├── schemas/          ← Pydantic API schemas
    ├── mock_data/
    │   └── packages.json ← Temporary input
    ├── utils/
    │   ├── logger.py
    │   ├── constants.py
    │   └── helpers.py
    ├── tests/
    │   └── test_engine.py
    └── main.py           ← FastAPI app entry point
```

---

## Setup

```bash
cd backend
pip install -r requirements.txt
```

---

## Run

```bash
cd backend
uvicorn app.main:app --reload
```

Open:
- **Swagger UI**: http://localhost:8000/docs
- **Scan API**:   http://localhost:8000/api/v1/vulnerabilities
- **Health**:     http://localhost:8000/api/v1/vulnerabilities/health

---

## Run Tests

```bash
cd backend
pytest app/tests/ -v
```

---

## API Response Shape

```json
{
  "scan_id": null,
  "total_packages_scanned": 5,
  "total_vulnerabilities_found": 12,
  "packages": [
    {
      "package_name": "lodash",
      "version": "4.17.15",
      "ecosystem": "npm",
      "vulnerability_count": 3,
      "highest_severity": "HIGH",
      "vulnerabilities": [
        {
          "cve_id": "CVE-2021-23337",
          "osv_id": "GHSA-35jh-r3h4-6jhm",
          "title": "...",
          "severity": "HIGH",
          "cvss_score": 7.2,
          "risk_label": "HIGH",
          "risk_score": 7.2,
          "fixed_version": "4.17.21",
          "references": ["..."],
          "source": "OSV"
        }
      ]
    }
  ],
  "errors": []
}
```

---

## Development Roadmap

| Phase | Status | Description |
|-------|--------|-------------|
| 1 | ✅ **Done** | Mock JSON, architecture, OSV stub, API endpoint |
| 2 | 🔜 Next | Connect real OSV API |
| 3 | ⏳ | NVD integration |
| 4 | ⏳ | GitHub Advisories |
| 5 | ⏳ | EPSS scores + composite risk scoring |
| 6 | ⏳ | Database integration |
| 7 | ⏳ | AI Module consumes output |
| 8 | ⏳ | Dashboard consumes output |

---

## How to Connect the Dependency Analysis Engine (Future)

In `services/vulnerability/mock_loader.py`, change:

```python
# Phase 1 (current)
packages = load_mock_packages()
```

to:

```python
# Future (when teammate's module is ready)
packages = dependency_analysis_service.get_dependencies(scan_id)
```

**Nothing else changes.**
