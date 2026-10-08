# P2G Progress — AI Security Analysis Engine

**Date:** 2026-10-09  
**Phase:** P2G — AI Security Analysis Engine  
**Baseline:** 237 tests (P2F complete)

---

## Definition of Done

| Criterion | Status |
|---|---|
| Pipeline directly feeds AI input (P2F gap resolved) | ✅ |
| scan_id preserved end-to-end | ✅ |
| VulnerabilityFinding remains source of truth | ✅ |
| AIAnalysisInput remains compatible | ✅ |
| SecurityAnalysisService exists | ✅ |
| LLMProvider abstraction exists | ✅ |
| MockLLMProvider exists (10 failure modes) | ✅ |
| Prompt builder exists (isolated) | ✅ |
| AIAnalysisResult exists | ✅ |
| Finding-level analysis (AIFindingAnalysis) | ✅ |
| Every AI result maps to finding_id | ✅ |
| Fabricated finding_ids discarded | ✅ |
| Missing finding_ids discarded | ✅ |
| AI cannot modify vulnerability facts | ✅ (E2E verified) |
| CVSS not mutated by AI | ✅ (E2E verified) |
| EPSS not mutated by AI | ✅ (E2E verified) |
| risk_score not mutated by AI | ✅ (E2E verified) |
| fixed_version not mutated by AI | ✅ (E2E verified) |
| risk_label not mutated by AI | ✅ (E2E verified) |
| source attribution not mutated | ✅ (E2E verified) |
| AI failure isolated (never crashes vuln scan) | ✅ (E2E verified) |
| timeout failure isolated | ✅ (E2E verified) |
| network failure isolated | ✅ (E2E verified) |
| invalid JSON failure isolated | ✅ (E2E verified) |
| fabricated finding_id discarded | ✅ (E2E verified) |
| API endpoint POST /api/v1/ai-analysis/analyze | ✅ |
| GET /api/v1/ai-analysis/input backward compat | ✅ (E2E verified) |
| P2F gap resolved (dep_context_map auto-built in pipeline) | ✅ |
| Existing 237 tests pass | ✅ (293 confirmed x2) |
| 56 new P2G tests pass | ✅ |
| 18 E2E acceptance tests pass | ✅ |
| Documentation complete | ✅ |

> **P2G STATUS: OFFICIALLY COMPLETE** ✅

---

## Files Created

| File | Purpose |
|---|---|
| `app/models/ai_analysis_result.py` | `AIAnalysisResult`, `AIFindingAnalysis`, AI status constants |
| `app/services/ai/llm_provider.py` | `LLMProvider` abstract base, `LLMRequest`, `LLMResponse` |
| `app/services/ai/mock_llm_provider.py` | `MockLLMProvider` (10 failure modes, zero network) |
| `app/services/ai/prompt_builder.py` | `SecurityAnalysisPromptBuilder` (isolated context construction) |
| `app/services/ai/security_analysis_service.py` | `SecurityAnalysisService` (central orchestrator) |
| `app/schemas/ai_analysis_result_schema.py` | `AIAnalysisResultOut`, `AnalyzeRequest` API schemas |
| `app/tests/ai/test_p2g_security_analysis.py` | 56 P2G tests |
| `docs/ai-security-analysis-contract.md` | Full contract documentation |
| `docs/phase2g_progress.md` | This document |

## Files Modified

| File | Change |
|---|---|
| `app/models/pipeline_result.py` | Added `ai_analysis`, `ai_status` fields (Optional, backward compat) |
| `app/services/pipeline.py` | Added dep_context_map building, optional AI analysis integration |
| `app/api/ai_analysis.py` | Added `POST /api/v1/ai-analysis/analyze` endpoint |

---

## Architecture Changes

### P2F Gap Resolved

The `PipelineOrchestrator` now automatically builds `dep_context_map` from `Dependency` records:

```python
dep_context_map = _build_dep_context_map(result_deps.dependencies)
```

This means `SecurityAnalysisInputProvider` receives real dependency context automatically when called from the pipeline. Manual construction is no longer required.

### Pipeline → AI Flow

```text
PipelineOrchestrator.run_pipeline(include_ai_analysis=True)
    ↓
DependencyAnalysisEngine.analyze() → dep_context_map built automatically
    ↓
VulnerabilityEngine.run_scan()
    ↓
VulnerabilityFindingProvider.get_findings(dep_context_map=dep_context_map)
    ↓
SecurityAnalysisInputProvider.get_analysis_input()
    ↓
SecurityAnalysisService.analyze()
    ↓
AIAnalysisResult in RootTracePipelineResult.ai_analysis
```

scan_id is identical throughout all stages.

---

## New Interfaces

| Interface | Description |
|---|---|
| `LLMProvider` | Abstract base for all LLM backends |
| `SecurityAnalysisService.analyze(AIAnalysisInput) → AIAnalysisResult` | Central analysis orchestrator |
| `SecurityAnalysisPromptBuilder.build_request(AIAnalysisInput) → LLMRequest` | Prompt construction |
| `MockLLMProvider(fail_with=...)` | Deterministic test provider |

---

## AI Status Semantics

| Status | Meaning |
|---|---|
| `completed` | Full analysis produced |
| `completed_with_warnings` | Analysis ran, some findings discarded (missing/fabricated finding_id) |
| `unavailable` | LLM provider failed (timeout/network/auth/rate_limit) |
| `failed` | Invalid JSON or unparseable response |
| `not_requested` | AI analysis was not requested |

---

## Test Summary

| Test Class | Count |
|---|---|
| `TestLLMProviderAbstraction` | 3 |
| `TestMockLLMProviderFailures` | 8 |
| `TestPromptBuilder` | 8 |
| `TestSecurityAnalysisService` | 7 |
| `TestAIFailureHandling` | 9 |
| `TestFindingTraceability` | 3 |
| `TestEvidenceScenarios` | 7 |
| `TestAIAnalysisAPI` | 3 |
| `TestPipelineIntegration` | 4 |
| `TestP2GE2EVerification` | 18 |
| **New P2G total** | **74** |
| **Previous baseline** | **237** |
| **New grand total** | **311** |

---

## Known Limitations

1. `MockLLMProvider` is the only active LLM — real AI reasoning requires OpenAI/Gemini/Claude integration (P2G-Real).
2. The pipeline dep_context_map uses `dep.name` as the key — if two packages share a name but differ in ecosystem, the shallower entry wins.
3. AI analysis is synchronous — for long scans with many findings, this blocks the request. Async implementation is deferred.
4. The `RootTracePipelineResult.ai_analysis` field uses `Optional[Any]` to avoid circular imports — a dedicated union type can be added later.

---

## Next Recommended Phase

**P2H — Dashboard/Reporting Consumption**

The AI output contract is now stable. The Dashboard/Reporting module can join:

```
VulnerabilityFinding.finding_id ↔ AIFindingAnalysis.finding_id
```

to render vulnerability data alongside AI explanations.

OR:

**P2G-Real — Real LLM Integration**

Implement `OpenAILLMProvider` or `GeminiLLMProvider` as a concrete `LLMProvider` subclass. The rest of the pipeline requires zero changes.
