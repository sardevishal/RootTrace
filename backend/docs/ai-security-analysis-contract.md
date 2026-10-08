# AI Security Analysis Contract — P2G

**Contract Version:** `1.0`  
**Phase:** P2G — AI Security Analysis Engine  
**Date:** 2026-10-09

---

## 1. Architecture

```text
Repository
    │
    ▼
DependencyAnalysisEngine
    │
    ▼
VulnerabilityIntelligenceEngine (OSV + NVD + GitHub + EPSS + Risk)
    │
    ▼
VulnerabilityFinding  ← SOURCE OF TRUTH
    │
    ▼
SecurityAnalysisInputProvider  (P2F — prioritization, context limit)
    │
    ▼
SecurityAnalysisService        (P2G — orchestration)
    │
    ▼
SecurityAnalysisPromptBuilder  (P2G — context construction)
    │
    ▼
LLMProvider  (abstraction)
    │
    ├── MockLLMProvider        (deterministic, offline — tests)
    └── [Future: OpenAI / Gemini / Claude]
    │
    ▼
AIAnalysisResult  ← STRUCTURED OUTPUT
    │
    ├── Dashboard
    ├── Report Generator
    └── DevSecOps integrations
```

---

## 2. Non-Negotiable Boundary

| Layer | Responsibility |
|---|---|
| **VulnerabilityFinding** | SOURCE OF TRUTH for all security facts |
| **SecurityAnalysisService** | Orchestration, failure isolation |
| **SecurityAnalysisPromptBuilder** | Prompt construction only |
| **LLMProvider** | Raw generation only |
| **AIAnalysisResult** | EXPLANATION / REASONING about the facts |

The AI **MUST NOT**:
- Invent CVEs, package versions, or fixed versions
- Modify CVSS, EPSS, or risk_score
- Claim exploit activity not evidenced by EPSS data
- Change vulnerability severity labels

---

## 3. Input (AIAnalysisInput → P2F contract)

See `docs/ai-analysis-input-contract.md` for the full input schema.

---

## 4. Output Schema

```json
{
  "contract_version": "1.0",
  "scan_id": "scan-001",
  "ai_status": "completed",
  "ai_error": null,
  "llm_provider": "MockLLMProvider",
  "executive_summary": "string",
  "overall_risk": "HIGH",
  "total_findings_analyzed": 3,
  "finding_analyses": [
    {
      "finding_id": "<sha256-hex from VulnerabilityFinding>",
      "priority": 1,
      "explanation": "string",
      "impact": "string",
      "exploitability": "string",
      "remediation": "string",
      "dependency_context_note": "string",
      "attack_surface": "string or null",
      "confidence": "HIGH|MEDIUM|LOW"
    }
  ]
}
```

---

## 5. AI Status Semantics

| Status | Meaning |
|---|---|
| `completed` | AI analysis ran successfully |
| `completed_with_warnings` | AI ran but some findings were discarded (e.g., missing finding_id) |
| `unavailable` | LLM provider failed (timeout, network, auth, rate_limit) |
| `failed` | Invalid/unparseable LLM response |
| `not_requested` | AI was not run (e.g. pipeline without AI) |

**CRITICAL**: `ai_status=unavailable` or `ai_status=failed` does NOT mean the vulnerability scan failed.

---

## 6. Finding Traceability

Every `AIFindingAnalysis` contains the exact `finding_id` from the corresponding `VulnerabilityFinding`.

Dashboard and reporting modules MUST join on `finding_id`:

```
VulnerabilityFinding.finding_id
        ↕  (join)
AIFindingAnalysis.finding_id
```

If the LLM returns a fabricated or missing `finding_id`, that entry is **discarded** with a warning.

---

## 7. LLM Provider Abstraction

```python
class LLMProvider(ABC):
    @property
    def provider_name(self) -> str: ...
    def generate(self, request: LLMRequest) -> LLMResponse: ...
```

Rules:
- `generate()` must NEVER raise — always returns `LLMResponse`
- On success: `LLMResponse(success=True, content="<json string>")`
- On failure: `LLMResponse(success=False, error="...", error_type="...")`

Error types: `timeout | network | rate_limit | invalid_response | context_limit | auth | unknown`

---

## 8. Mock Provider

`MockLLMProvider` runs offline with no API keys. 10 failure modes available:

```python
MockLLMProvider()                              # success
MockLLMProvider(fail_with="timeout")           # timeout
MockLLMProvider(fail_with="network")           # network failure
MockLLMProvider(fail_with="rate_limit")        # rate limited
MockLLMProvider(fail_with="auth")              # auth failed
MockLLMProvider(fail_with="context_limit")     # input too long
MockLLMProvider(fail_with="invalid_json")      # bad JSON returned
MockLLMProvider(fail_with="empty")             # empty response
MockLLMProvider(fail_with="partial")           # partial structure
MockLLMProvider(fail_with="missing_finding_id")  # no finding_id in analysis
MockLLMProvider(fail_with="unknown_finding_id")  # fabricated finding_id
```

---

## 9. Evidence Confidence

Evidence confidence is derived from data availability, not model confidence:

| Confidence | Criteria |
|---|---|
| `HIGH` | CVE + CVSS + EPSS all present |
| `MEDIUM` | CVE present, but CVSS or EPSS missing |
| `LOW` | No CVE, severity label only |

This is NOT the LLM's subjective confidence — it reflects the quality of the evidence supplied.

---

## 10. API Endpoints

```
POST /api/v1/ai-analysis/analyze   ← P2G: Run AI analysis
GET  /api/v1/ai-analysis/input     ← P2F: Get prioritized input (unchanged)
```

### Example Request

```http
POST /api/v1/ai-analysis/analyze
Content-Type: application/json

{
  "scan_id": "scan-001",
  "max_findings": 50
}
```

### Example Response

```json
{
  "contract_version": "1.0",
  "scan_id": "scan-001",
  "ai_status": "completed",
  "llm_provider": "MockLLMProvider",
  "executive_summary": "...",
  "overall_risk": "HIGH",
  "total_findings_analyzed": 3,
  "finding_analyses": [...]
}
```

---

## 11. Security Limitations

1. Current LLM: `MockLLMProvider` — output is clearly labeled mock analysis, not real AI intelligence.
2. The mock output reflects the supplied finding data but is NOT real security reasoning.
3. To use a real LLM, implement `LLMProvider` and inject into `SecurityAnalysisService`.
4. The AI analysis adds EXPLANATION only — it never becomes a vulnerability source of truth.
5. AI context is limited to `max_findings` (default 50) — high-finding scans will omit lower-priority findings.
