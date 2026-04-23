# gireng Project Review — Comprehensive Audit

**Date:** 2026-04-16  
**Scope:** Full-stack review of backend, frontend, Docker infrastructure, tests, and production readiness.

---

## 1. Current Status

**gireng** is a **tri-engine AI-powered reverse engineering platform** (Ghidra + Radare2 + Qiling) with a React frontend and FastAPI backend. Architecturally, it is **ambitious and largely implemented**:

- **LangGraph pipeline** is complete with 6+ nodes (`parse_intent` → `initialize` → `discovery` → `focus_analysis` → `cross_reference` → `synthesize`).
- **Ghidra integration** is production-ready with 11 PyGhidra headless scripts, project caching, and retry logic.
- **Radare2 integration** is solid with JSON parsing, decompiler fallback chain (`pdg` → `pdd` → `pdf`), and timeout handling.
- **Qiling integration** has 10 emulation scripts covering syscalls, API tracing, memory analysis, network analysis, evasion detection, and instruction tracing.
- **Auth/RBAC** is fully implemented (JWT, 3 roles, quotas, admin panel).
- **Database layer** is comprehensive with async PostgreSQL, normalized tables (functions, strings, decompilations, IOCs, attack chains), and cross-binary search.
- **Reporting** supports HTML, PDF (Playwright/Chromium), and text exports.
- **Frontend** is a modern React 19 SPA with WebSocket streaming, resizable panels, and dark theme.

**However, there are critical runtime bugs, missing implementations, and significant code duplication that will cause failures in production.**

---

## 2. Critical Bugs / Broken Implementations

These will cause **runtime errors** or **ImportErrors** when specific code paths are hit.

### A. `r2_search_bytes` tool does NOT exist but is imported
**Location:** `backend/src/ghidra_agent/glm_function_tools.py:222`
```python
from ghidra_agent.r2_tools import (
    ...
    r2_search_bytes,  # ← DOES NOT EXIST
)
```

`r2_tools.py` only exports: `r2_analyze_binary`, `r2_list_functions`, `r2_build_call_graph`, `r2_decompile_function`, `r2_disassemble_at`, `r2_find_strings`, `r2_find_xrefs`, `r2_syscall_analysis`.

**Impact:** Calling `register_all_radare2_tools()` or hitting `/query_with_tools` will raise an `ImportError`.

### B. `db.get_decompilation()` does NOT exist but is invoked
**Location:** `backend/src/ghidra_agent/glm_function_tools.py:298`
```python
decomp = await db.get_decompilation(program_hash, analyzer, function_name)
```

Searching `database.py` reveals **no such function**. The database has `get_binary_decompilations()` but not a single-function getter.

**Impact:** When the LLM invokes the `get_decompilation` tool (advertised in `/query_with_tools`), it will raise `AttributeError`.

### C. `/query_with_tools` advertises broken tools in its prompt
**Location:** `backend/src/ghidra_agent/api/main.py:772-781`
The system prompt lists both `r2_search_bytes` and `get_decompilation` as available tools, guaranteeing user-facing failures.

---

## 3. Missing Implementations

### A. Similar Files Detection is a hardcoded stub
**Location:** `backend/src/ghidra_agent/ui_adapter.py:640`
```python
def build_similar_files(state: AgentState) -> list[Dict[str, Any]]:
    return []
```

The frontend has a full UI section for "Similar Files Found" (`App.tsx:1061`), but `mockSimilarFiles` is always empty and the backend returns `[]`. **Feature is completely unimplemented.**

### B. `r2_search_bytes` tool is missing
There is no byte-pattern search for Radare2, even though the GLM tool registry expects it. This should be a straightforward wrapper around `radare2` `/x` command.

### C. `get_decompilation` database helper is missing
Need to add `get_decompilation(program_hash, analyzer, function_name)` to `database.py` to support the tool.

### D. Semantic memory embeddings are a placeholder
**Location:** `backend/src/ghidra_agent/memory.py:381-388`
```python
# Note: Zai API may have different embedding endpoints
# This is a placeholder for the actual implementation
```

The `SemanticMemory.add_entry()` method never actually generates embeddings.

---

## 4. Incomplete / Partial Features

### A. `human_review` / `action_execution` nodes are dead code
**Locations:** `graph.py:1365-1402`
The LangGraph has nodes for write-mode approval (`human_review`, `action_execution`), but:
- The LLM in `synthesize` never populates `pending_actions`.
- The frontend has no UI flow for reviewing pending write actions.
- `_review_next` defaults to `synthesize` unless both `write_mode_enabled=True` AND `review_approved=True`, which never happens organically.

**Recommendation:** Remove these nodes or implement the frontend approval flow.

### B. Model selector in frontend is non-functional
**Location:** `app/src/App.tsx:244, 971`
The UI lets users select models (`glm-4.7`, Gemini, Claude, GPT-4o), but `selectedModelId` is **never sent to the backend**. The backend hardcodes `settings.llm_model_name = "glm-5"` in `config.py`. The selector is pure UI theater.

### C. `analyze.py` CLI script is incompatible with auth
**Location:** `analyze.py`
The helper script uploads to `/analyze/upload` without any JWT token. Since the API requires `Depends(get_current_user)`, this script will receive `401 Unauthorized` in any deployment with auth enabled.

### D. Quick Actions are just text queries
The welcome-screen quick actions ("CVEs Chart", "Deobfuscate", "APT Threat Report") send their label as a plain `/query` string. There is no specialized handling — the LLM just gets the label as a user question.

---

## 5. Code Quality & Architecture Issues

### A. Severe code duplication
The same utility functions are copy-pasted across **4+ files**:

| Function | Duplicated In |
|----------|---------------|
| `_to_num()` | `graph.py`, `api/main.py`, `r2_graph.py`, `ui_adapter.py` |
| `_function_priority_key()` | `graph.py`, `api/main.py`, `r2_graph.py`, `ui_adapter.py` |
| `_smart_truncate()` / prompt truncation | `graph.py`, `llm.py` |
| Auto-decompile logic | `graph.py` (Ghidra), `r2_graph.py` (R2) |

### B. `query` endpoint rebuilds context from scratch
**Location:** `api/main.py:480-698`
The `/query` endpoint manually reconstructs the exact same context that `synthesize` already builds. This is ~200 lines of duplicated logic. Any change to synthesis context must be mirrored here or query answers will be inconsistent.

### C. Race conditions in shared state
While Ghidra, R2, and Qiling write to separate result keys (`analysis_results`, `r2_analysis_results`, `qiling_analysis_results`), they all append to `reasoning_trace` (a list) and update global `progress` / `current_step`. Python lists are not thread-safe for concurrent appends, and `AgentState` is a plain `dict` passed to `asyncio.gather()`.

### D. Massive `reporting.py`
**Size:** 3,947 lines
`reporting.py` is almost 4,000 lines — larger than most modules combined. It mixes:
- HTML report generation
- PDF template generation  
- Text report generation
- Per-agent report variants

**Recommendation:** Split into `reporting/html.py`, `reporting/pdf.py`, `reporting/text.py`.

---

## 6. Testing & CI Status

### A. Tests cannot run in this environment
I attempted `python3 -m pytest tests/` but `pytest` is not installed in the system Python, and the `.venv` directory in the repo is incomplete. Dependencies like `langchain`, `asyncpg`, `litellm` are missing.

### B. CI workflow runs only a subset of tests
**Location:** `.github/workflows/ci.yml:30-37`
```yaml
pytest -q \
  backend/tests/test_api.py \
  backend/tests/test_qiling_graph.py \
  backend/tests/test_qiling_tools.py \
  backend/tests/test_qiling_runner.py \
  backend/tests/test_ioc_verdict_qiling.py
```

**Missing from CI:**
- `test_e2e.py`
- `test_chargen_e2e.py`
- `test_r2_runner.py`
- `test_r2_tools.py`
- `test_r2_graph.py`
- `test_call_graph_analyzer.py`
- `test_function_priority.py`
- `test_glm_function_calling.py` ← **This would catch the `r2_search_bytes` bug**

### C. `conftest.py` stubs out `litellm`
This is a reasonable testing strategy, but it means LiteLLM integration paths are not exercised in unit tests.

---

## 7. Frontend Issues

### A. Mock data is still heavily used
**Location:** `app/src/data/mockData.ts`
The file explicitly says "Replace with API calls" but `mockAnalysisResult`, `mockQuickActions`, `mockSimilarFiles` are still wired into `App.tsx`. The Similar Files feature is entirely dependent on this mock being empty.

### B. Type mismatch in ` AnalyzerRawResults`
**Location:** `app/src/lib/api.ts:184`
```typescript
analyzer: 'ghidra' | 'radare2' | string;
```
This union with `string` defeats the purpose of the literal union.

### C. WebSocket token param is optional with fallback to unauthenticated
**Location:** `api/main.py:887-898`
```python
token = websocket.query_params.get("token")
if token:
    try:
        decode_token(token)
    except Exception:
        await websocket.close(code=4001, reason="Invalid token")
        return
await manager.connect(session_id, websocket)
```

If no token is provided, the connection is accepted anyway ("allow unauthenticated for backward compat"). This is a security hole.

---

## 8. Deployment / DevOps Issues

### A. Agent depends on Qiling being healthy
**Location:** `docker-compose.yml:144-158`
The `agent` service has:
```yaml
depends_on:
  qiling:
    condition: service_healthy
```

Qiling's Dockerfile clones the `qilingframework/rootfs` repo, runs Git LFS, and builds stub DLLs. If this fails (network timeout, LFS quota exceeded, repo change), **the entire platform including the API and UI will not start** because the agent is blocked.

**Recommendation:** Make Qiling optional at compose level, or use `service_started` instead of `service_healthy`.

### B. Qiling rootfs clone is fragile
**Location:** `backend/Dockerfile.qiling:13-21`
Cloning a live GitHub repo with sparse checkout + LFS on every build is not reproducible. If the repo is unavailable or LFS files are missing, the build fails.

### C. Playwright installation in agent Dockerfile is unchecked
**Location:** `backend/Dockerfile:17`
```dockerfile
RUN playwright install --with-deps chromium
```
If this fails, the Docker build continues (it won't fail the layer unless the command exits non-zero, which it usually does on failure, but there's no retry or fallback).

### D. `.env.template` has insecure defaults
`JWT_SECRET` defaults to `"changeme-gireng-jwt-secret-key"`, `ADMIN_PASSWORD` defaults to `"admin"`. The `config.py` loads these directly without validation or startup warnings.

---

## 9. Security Concerns

| Issue | Severity | Location |
|-------|----------|----------|
| Default weak JWT secret | **High** | `config.py` |
| Default admin password `admin` | **High** | `config.py` / `.env.template` |
| WebSocket allows unauthenticated fallback | **Medium** | `api/main.py:887` |
| `analyze.py` has no auth support | **Medium** | `analyze.py` |
| CORS regex allows all localhost ports | **Low** | `api/main.py:88` |

---

## 10. What Can Be Improved

### Immediate (Fix Before Production)
1. **Implement `r2_search_bytes`** in `r2_tools.py` or remove it from `glm_function_tools.py` and API docs.
2. **Implement `get_decompilation`** in `database.py` or remove the tool from the registry.
3. **Add `r2_search_bytes` and GLM function calling tests to CI** so these regressions are caught.
4. **Fix `analyze.py`** to support JWT authentication (add `--token` or `--email/--password` flags).
5. **Make Qiling optional** in `docker-compose.yml` so agent/frontend can start without it.

### Short-Term (Next Sprint)
6. **Extract shared utilities** (`_to_num`, `_function_priority_key`, `_smart_truncate`, auto-decompile logic) into a shared module to eliminate duplication.
7. **Refactor `reporting.py`** into a package with separate modules per format.
8. **Implement `get_binary_decompilation` DB helper** and wire it to the tool registry.
9. **Remove or implement `build_similar_files`** — either add hash-based similarity logic or remove the frontend section.
10. **Make the model selector functional** by sending `model_id` to the backend and supporting dynamic model switching in `llm.py`.

### Medium-Term (Architecture)
11. **Unify context building** — create a single `build_llm_context(state)` function used by both `synthesize` and `/query`.
12. **Add proper concurrency safety** for `reasoning_trace` appends when running analyzers in parallel (use locks or per-analyzer trace lists).
13. **Replace live Git clone in Qiling Dockerfile** with a pinned tarball or multi-stage build with cached rootfs layers.
14. **Add startup health checks** that validate required env vars (`JWT_SECRET`, `LLM_API_KEY`) and warn if defaults are in use.

### Long-Term
15. **Implement actual semantic memory** with working embeddings and vector search.
16. **Add rate limiting** to `/analyze/upload` and `/query` endpoints.
17. **Implement the write-mode approval flow** in the frontend or remove the dead code from the graph.

---

## Summary Table

| Category | Working | Partially Working | Broken / Missing |
|----------|---------|-------------------|------------------|
| Ghidra Analysis | ✅ | | |
| Radare2 Analysis | ✅ | | |
| Qiling Analysis | ✅ | | |
| LangGraph Pipeline | ✅ | | |
| Auth / RBAC | ✅ | | |
| DB Persistence | ✅ | | |
| HTML/PDF Reports | ✅ | | |
| Frontend UI | ✅ | | |
| **Function Calling (`/query_with_tools`)** | | | ❌ **Broken** |
| **Similar Files** | | | ❌ **Missing** |
| **Model Selector** | | ❌ **Non-functional** | |
| **CLI Helper (`analyze.py`)** | | ❌ **No auth** | |
| **Semantic Memory** | | ❌ **Placeholder** | |
| **Write Mode Approval** | | | ❌ **Dead code** |
