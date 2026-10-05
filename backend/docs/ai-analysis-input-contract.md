# AI Security Analysis Input Contract - P2F

**Phase:** P2F — AI Security Analysis Input Foundation
**Date:** 2026-10-06

---

## 1. Purpose

The AI Security Analysis Input Contract defines the deterministic, prioritized, and context-limited boundary between the RootTrace Vulnerability Intelligence Engine and the downstream AI Security Analysis module.

The AI module MUST NOT import or interact directly with any internal clients (e.g., OSVClient, NVDClient). Instead, it consumes `AIAnalysisInput` provided by `SecurityAnalysisInputProvider`.

---

## 2. Architecture

```text
       VulnerabilityIntelligenceEngine
                    ↓
         VulnerabilityFindingProvider
                    ↓
        SecurityAnalysisInputProvider
          (Prioritization & Limits)
                    ↓
             AIAnalysisInput
                    ↓
           AI Security Analysis
```

---

## 3. Input Schema

```json
{
  "contract_version": "1.0",
  "scan_id": "scan-001",
  "summary": {
    "total_findings": 137,
    "critical": 5,
    "high": 12,
    "medium": 20,
    "low": 100,
    "direct_dependencies": 15,
    "transitive_dependencies": 122,
    "affected_packages": 30
  },
  "findings": [
    {
      "finding_id": "...",
      "package": { "name": "lodash", "version": "4.17.15", "ecosystem": "npm" },
      "dependency": { "direct": false, "transitive": true, "depth": 2, "parent": "express", "dependency_path": ["root-project", "express", "lodash"] },
      "vulnerability": {
        "cve_id": "CVE-2021-23337",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "epss_score": 0.45,
        "risk_score": 6.3,
        "risk_label": "MEDIUM"
      },
      "remediation": { "fixed_version": "4.17.21" },
      "sources": { "primary": "COMBINED", "contributing": ["OSV", "NVD"] },
      "references": []
    }
  ],
  "context": {
    "total_findings": 137,
    "included_findings": 50,
    "omitted_findings": 87
  }
}
```

---

## 4. Prioritization Rules

To ensure the AI analyzes the most critical issues when context limits are reached, findings are prioritized deterministically:

1. **Risk Label**: `CRITICAL` > `HIGH` > `MEDIUM` > `LOW` > `UNKNOWN`
2. **Risk Score**: Higher is better
3. **EPSS Score**: Higher is better
4. **CVSS Score**: Higher is better
5. **Dependency Directness**: Direct > Transitive
6. **Dependency Depth**: Shallower > Deeper

---

## 5. Context Limits

The provider applies a configurable context limit (`max_findings`, default 50). 
If the total number of findings exceeds this limit, the provider returns the top `N` prioritized findings.

The `context` block tracks omitted findings, so the AI knows if it is analyzing a partial dataset.

---

## 6. How the AI Team Consumes It

The AI module should rely on `SecurityAnalysisInputProvider`.

```python
from app.services.ai.ai_input_provider import SecurityAnalysisInputProvider

provider = SecurityAnalysisInputProvider()
ai_input = provider.get_analysis_input(scan_id="scan-001", max_findings=50)

print(f"Total findings: {ai_input.context.total_findings}")
print(f"Omitted: {ai_input.context.omitted_findings}")

for finding in ai_input.findings:
    print(f"Analyzing {finding.finding_id}: {finding.package_name}")
```

Or via API:

```text
GET /api/v1/ai-analysis/input?max_findings=50
```

---

## 7. Error Semantics

- **Source Errors**: Do NOT cause zero-finding AI analysis unless all sources fail. Handled at the finding level.
- **Missing EPSS/CVSS**: The prioritization safely handles `None` values (treating them as 0).
- **Missing Dep Context**: Safely defaults to `direct=True, depth=0`.

---

## 8. Versioning

`contract_version`: `1.0`. Additive changes will remain on `1.0`. Breaking changes will bump to `2.0`.
