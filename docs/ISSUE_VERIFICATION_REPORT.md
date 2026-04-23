# Gireng Issue Verification Report

**Date:** 2026-04-23  
**Purpose:** Verify implementation status of known issues from previous audits

---

## Executive Summary

All **P0 (critical)** issues from the April 16, 2026 audit have been **resolved**. The codebase is now in a functional state with all advertised tools properly implemented.

---

## Issue Status Tracking

### ✅ RESOLVED - P0 Issues

| # | Issue | Status | Evidence |
|---|-------|--------|----------|
| 1 | `r2_search_bytes` does not exist | ✅ **FIXED** | Exists at `r2_tools.py:450` |
| 2 | `db.get_decompilation()` missing | ✅ **FIXED** | Exists at `database.py:1040` |
| 3 | `/query_with_tools` prompt advertises broken tools | ✅ **FIXED** | All tools in prompt now exist |
| 4 | `analyze.py` lacks auth | ✅ **FIXED** | Supports `--token`, `--email`, `--password` |
| 5 | Agent blocked by Qiling healthcheck | ✅ **FIXED** | Agent no longer depends on Qiling |
| 6 | `build_similar_files` is stub | ✅ **FIXED** | Uses `db.find_similar_analyses()` |
| 7 | Model selector non-functional | ✅ **FIXED** | Full flow implemented |

---

## Detailed Verification

### 1. `r2_search_bytes` Tool

**Location:** `backend/src/ghidra_agent/r2_tools.py:450-474`

```python
@tool
async def r2_search_bytes(
    session_id: str,
    program_hash: str,
    binary_path: Optional[str] = None,
    pattern: Optional[str] = None,
) -> Dict[str, Any]:
    """Search for a hex byte pattern in the binary using Radare2."""
    bp = _bin(binary_path)
    runner = get_runner()
    if not pattern:
        return {"ok": False, "error": "pattern is required"}
    cmd = f"aaa;/xj {pattern}"
    result = await runner.run_json_command(bp, cmd)
    # ... returns matches with address, size, type
```

**Status:** ✅ Implemented and exported

---

### 2. `db.get_decompilation()` Function

**Location:** `backend/src/ghidra_agent/database.py:1040-1048`

```python
async def get_decompilation(program_hash: str, analyzer: str, function_name: str) -> Optional[str]:
    """Get a single decompiled function by program hash, analyzer, and function name."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT code FROM decompilations WHERE program_hash = $1 AND analyzer = $2 AND function_name = $3",
            program_hash, analyzer, function_name,
        )
    return row["code"] if row else None
```

**Status:** ✅ Implemented

---

### 3. `/query_with_tools` Prompt

**Location:** `backend/src/ghidra_agent/api/main.py:716-734`

All tools listed in the prompt now exist:
- `r2_analyze_binary` ✅ (r2_tools.py:92)
- `r2_list_functions` ✅ (r2_tools.py:155)
- `r2_build_call_graph` ✅ (r2_tools.py:189)
- `r2_decompile_function` ✅ (r2_tools.py:286)
- `r2_disassemble_at` ✅ (r2_tools.py:394)
- `r2_find_strings` ✅ (r2_tools.py:331)
- `r2_find_xrefs` ✅ (r2_tools.py:366)
- `r2_search_bytes` ✅ (r2_tools.py:450)
- `r2_syscall_analysis` ✅ (r2_tools.py:425)
- `search_functions` ✅ (glm_function_tools.py:248)
- `get_decompilation` ✅ (glm_function_tools.py:291)

**Status:** ✅ All advertised tools exist

---

### 4. `analyze.py` Auth Support

**Location:** `analyze.py:12-22`

```python
def get_token(args) -> str | None:
    if args.token:
        return args.token
    if args.email and args.password:
        resp = requests.post(
            f"{args.api}/api/auth/login",
            json={"email": args.email, "password": args.password},
        )
        resp.raise_for_status()
        return resp.json().get("token")
    return None
```

**Status:** ✅ JWT authentication implemented

---

### 5. Qiling Dependency Removed

**Location:** `docker-compose.yml:agent`

```yaml
agent:
  depends_on:
    ghidra:
      condition: service_healthy
    radare2:
      condition: service_healthy
    postgres:
      condition: service_healthy
    langfuse:
      condition: service_healthy
    # Qiling REMOVED from dependencies
```

**Status:** ✅ Agent no longer blocked by Qiling

---

### 6. `build_similar_files` Implementation

**Location:** `backend/src/ghidra_agent/ui_adapter.py:645-663`

```python
async def build_similar_files(state: AgentState) -> list[Dict[str, Any]]:
    program_hash = state.get("program_hash", "")
    if not program_hash:
        return []
    from ghidra_agent.ioc_extractor import calculate_verdict, extract_iocs_from_state
    from ghidra_agent import database as db
    iocs = extract_iocs_from_state(state)
    verdict, _, _, _ = calculate_verdict(iocs, state)
    if not verdict:
        return []
    rows = await db.find_similar_analyses(program_hash, verdict, limit=10)
    return [
        {
            "hash": r.get("program_hash", ""),
            "labels": [r.get("verdict", "Unknown")]
            + ([f"score:{r.get('threat_score')}"] if r.get("threat_score") is not None else []),
        }
        for r in rows
    ]
```

**Supporting function in database.py:**
```python
async def find_similar_analyses(program_hash: str, verdict: str, limit: int = 10)
```

**Status:** ✅ Implemented with DB query

---

### 7. Model Selector End-to-End

**Frontend:** `app/src/lib/api.ts`
```typescript
export async function uploadBinary(file: File, modelId?: string): Promise<UploadResponse> {
  const form = new FormData();
  form.append('file', file);
  if (modelId) {
    form.append('model', modelId);  // ✅ Model sent to backend
  }
  // ...
}

export async function sendQuery(sessionId: string, query: string, modelId?: string): Promise<QueryResponse> {
  // ...
  body: JSON.stringify({ session_id: sessionId, query, model: modelId }),  // ✅ Model sent
}
```

**Backend:** `backend/src/ghidra_agent/api/main.py:467-468, 508-509`
```python
if request.model:
    state["llm_model"] = request.model  # ✅ Model stored in session
```

**LLM Usage:** `backend/src/ghidra_agent/graph.py:775, 914`
```python
result = await call_llm(prompt, ..., model=state.get("llm_model"), ...)  # ✅ Model used
```

**Status:** ✅ Full flow implemented

---

## Remaining P1 Issues (Non-Critical)

These are documented but do not block functionality:

| Issue | Impact | Recommendation |
|-------|--------|----------------|
| Semantic memory embeddings placeholder | Only keyword matching | Document limitation |
| Write mode dead code | Nodes unused but harmless | Remove or implement UI |
| Quick actions are just text | Works but not specialized | Add prompt templates |
| Code duplication | Maintenance burden | Refactor later |

---

## Verification Commands

To verify the fixes yourself:

```bash
# 1. Check r2_search_bytes exists
grep "^async def r2_search_bytes" backend/src/ghidra_agent/r2_tools.py

# 2. Check get_decompilation exists
grep "async def get_decompilation" backend/src/ghidra_agent/database.py

# 3. Check analyze.py has auth
grep "token\|email\|password" analyze.py

# 4. Check Qiling not in agent dependencies
grep -A10 "agent:" docker-compose.yml | grep -q qiling && echo "FAIL" || echo "PASS"

# 5. Check model parameter in API client
grep "modelId" app/src/lib/api.ts

# 6. Test tool registration (in container)
docker exec gireng-agent-1 python3 -c "
from ghidra_agent.r2_tools import r2_search_bytes
print('r2_search_bytes:', r2_search_bytes)
"
```

---

## Conclusion

**All P0 issues from the April 16, 2026 audit have been resolved.**

The platform is now in a functional state where:
- All advertised tools exist and import correctly
- Authentication is properly implemented
- No critical service dependencies block startup
- Model selection works end-to-end
- Similar files detection is implemented

**Recommendation:** The codebase is ready for release pending successful smoke tests.

---

## Files Modified Since Audit

Based on git status, these files have changes:
- `app/src/App.tsx` - Model selector integration
- `app/src/lib/api.ts` - Model parameter in API calls
- `backend/src/ghidra_agent/api/main.py` - Various fixes
- `backend/src/ghidra_agent/reporting/html.py` - Export improvements

**Note:** The P0 fixes appear to have been implemented between the audit date (April 16) and now (April 23).
