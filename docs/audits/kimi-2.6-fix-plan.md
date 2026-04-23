# gireng Fix Plan — Feature & Function First

**Based on:** `kimi-2.6-review.md`  
**Date:** 2026-04-16  
**Priority Rule:** Feature completeness and functional correctness come first. Security hardening is secondary and scheduled after core functionality is solid.

---

## Part 1: Issue Inventory (Re-prioritized)

| # | Issue | Priority | Type | File(s) | Impact |
|---|-------|----------|------|---------|--------|
| 1 | **`r2_search_bytes` does not exist** but is imported | **P0** | Func | `glm_function_tools.py`, `r2_tools.py` | `ImportError` on `/query_with_tools` |
| 2 | **`db.get_decompilation()` does not exist** but is called | **P0** | Func | `glm_function_tools.py`, `database.py` | `AttributeError` on tool use |
| 3 | **`/query_with_tools` prompt advertises broken tools** | **P0** | Func | `api/main.py` | Guaranteed runtime failures |
| 4 | **`analyze.py` lacks auth** | **P0** | Func | `analyze.py` | CLI helper is unusable against auth-enabled API |
| 5 | **Agent blocked by Qiling `service_healthy`** | **P0** | Func | `docker-compose.yml` | Total platform outage if Qiling fails |
| 6 | **`build_similar_files` is a hardcoded stub** | **P0** | Func | `ui_adapter.py`, `App.tsx` | Feature advertised but empty |
| 7 | **Model selector is non-functional** | **P0** | Func | `App.tsx`, `llm.py`, `api/main.py` | UI theater only |
| 8 | **Semantic memory is a placeholder** | **P1** | Func | `memory.py` | Never generates embeddings |
| 9 | **`human_review` / `action_execution` dead code** | **P1** | Func | `graph.py` | Unused nodes in graph |
| 10 | **Quick actions are just text queries** | **P1** | Func | `App.tsx` | No specialized behavior |
| 11 | **Severe code duplication** (`_to_num`, `_function_priority_key`, auto-decompile) | **P1** | Func | `graph.py`, `api/main.py`, `r2_graph.py`, `ui_adapter.py` | Maintenance burden, drift risk |
| 12 | **`/query` rebuilds context from scratch** | **P1** | Func | `api/main.py`, `graph.py` | 200+ lines of duplicated logic |
| 13 | **Race condition on `reasoning_trace`** | **P1** | Func | `graph.py`, `r2_graph.py`, `qiling_graph.py` | Corrupted trace under concurrency |
| 14 | **`reporting.py` is 3,947 lines** | **P1** | Func | `reporting.py` | Unmaintainable |
| 15 | **WebSocket allows unauthenticated fallback** | **P2** | Sec | `api/main.py` | Security hole |
| 16 | **Insecure default secrets** | **P2** | Sec | `config.py`, `.env.template` | Production security risk |
| 17 | **CI skips critical tests** | **P2** | Qual | `.github/workflows/ci.yml` | `r2_search_bytes` bug would be caught |
| 18 | **Qiling Dockerfile uses live Git clone** | **P3** | Ops | `Dockerfile.qiling` | Non-reproducible builds |
| 19 | **Type mismatch in `AnalyzerRawResults`** | **P3** | Qual | `api.ts` | TypeScript hygiene |
| 20 | **No rate limiting** | **P3** | Sec | `api/main.py` | Abuse vector |
| 21 | **CORS regex too permissive** | **P3** | Sec | `api/main.py` | Localhost port wildcard |

---

## Part 2: Implementation Roadmap (Feature-First)

### Phase 1 — Make It Work (Functional Blockers)
*Goal: Eliminate runtime crashes, missing tools, and broken user-facing features.*

#### 1.1 Fix or Remove `r2_search_bytes`
**Option A (Recommended — implement it):**
1. Add `r2_search_bytes` to `backend/src/ghidra_agent/r2_tools.py`:
   - Command: `aaa;/x {pattern}`
   - Parse JSON or raw hex addresses
   - Return `{"ok": True, "matches": [{"address": "0x...", "data": "..."}]}`
2. Export it in `r2_tools.py` `__all__`.

**Option B (quick fix):**
1. Remove `r2_search_bytes` from `glm_function_tools.py`.
2. Remove it from the `/query_with_tools` prompt in `api/main.py`.

#### 1.2 Implement `get_decompilation` DB Helper
1. In `backend/src/ghidra_agent/database.py`, add:
   ```python
   async def get_decompilation(program_hash: str, analyzer: str, function_name: str) -> Optional[str]:
       pool = await get_pool()
       async with pool.acquire() as conn:
           row = await conn.fetchrow(
               "SELECT code FROM decompilations WHERE program_hash = $1 AND analyzer = $2 AND function_name = $3",
               program_hash, analyzer, function_name
           )
       return row["code"] if row else None
   ```
2. Verify `glm_function_tools.py` can import it successfully.

#### 1.3 Audit `/query_with_tools` Prompt
1. Open `backend/src/ghidra_agent/api/main.py`.
2. Ensure the "AVAILABLE TOOLS" list only includes **actually registered** tools.
3. Add a unit test that asserts `get_function_calling_tools()` names are a subset of the prompt-listed tools.

#### 1.4 Make Qiling Optional in Compose
1. In `docker-compose.yml`, change agent `depends_on` for `qiling` from `condition: service_healthy` to:
   - **Option A:** Remove Qiling from `depends_on` entirely; agent checks at runtime.
   - **Option B:** Change to `condition: service_started`.

#### 1.5 Add Auth to `analyze.py`
1. Add `--email` and `--password` CLI arguments (or `--token`).
2. Implement `login()` call to `/api/auth/login` to fetch a JWT.
3. Attach `Authorization: Bearer <token>` to all subsequent requests.

#### 1.6 Implement `build_similar_files`
**Simple version (recommended):**
1. In `database.py`, add `find_similar_binaries(program_hash, limit=10)`.
2. Query for binaries with matching `architecture`, `file_type`, or overlapping imports.
3. Return ranked list of `{hash, labels, similarity_score}`.
4. Wire into `ui_adapter.py` and remove the mock fallback in `App.tsx`.

#### 1.7 Make Model Selector Functional
1. Add `model_id` to `QueryRequest` and `SessionCreateRequest` Pydantic models.
2. In `api/main.py` `/query` and `/analyze/upload`, accept `model_id` and override `settings.llm_model_name` for that session.
3. In `App.tsx`, pass `selectedModelId` in request payloads.
4. Update `build_model_list()` in `ui_adapter.py` to include all advertised models with real IDs.

---

### Phase 2 — Feature Completion (Make Features Real)
*Goal: Turn placeholders and dead code into working product features.*

#### 2.1 Fix Semantic Memory or Remove It
**Option A (implement):**
1. Add a real embedding provider fallback (OpenAI, local `sentence-transformers`, or Zai).
2. Complete `SemanticMemory.add_entry()` embedding generation.

**Option B (deprecate — recommended for speed):**
1. Remove `SemanticMemory` class.
2. Keep `ProjectMemory` and `EpisodicMemory` only.
3. Remove the embedding client imports and `zai` dependency.

#### 2.2 Clean Up Dead Graph Nodes
1. Remove `human_review` and `action_execution` nodes from `graph.py` **OR** implement the frontend flow:
   - Add a modal in `App.tsx` for pending actions
   - Add POST `/write_mode/confirm` usage in the UI
2. If removing, delete `write_mode_enabled`, `review_approved`, and `pending_actions` from `state.py`.

#### 2.3 Make Quick Actions Useful
1. Map quick action IDs to specialized prompt templates instead of raw labels:
   - `apt` → "Generate an APT-style threat report focusing on TTPs and MITRE mapping"
   - `deobfuscate` → "Identify obfuscation techniques and attempt to reconstruct the original logic"
   - `cves` → "Search for known vulnerable API usage (strcpy, sprintf, etc.) and map to CVE patterns"
2. Send the mapped prompt to `/query` instead of the label.

---

### Phase 3 — Refactoring & Quality (Make It Maintainable)
*Goal: Reduce duplication, fix race conditions, and improve architecture.*

#### 3.1 Extract Shared Utilities
1. Create `backend/src/ghidra_agent/ranking_utils.py`:
   - Move `_to_num()`
   - Move `_function_priority_key()`
2. Create `backend/src/ghidra_agent/prompt_utils.py`:
   - Move `_smart_truncate()`
3. Replace all imports in `graph.py`, `api/main.py`, `r2_graph.py`, `ui_adapter.py`.

#### 3.2 Unify Auto-Decompile Logic
1. Create `backend/src/ghidra_agent/decompile_planner.py` with a function:
   ```python
   def plan_decompilation(func_list, binary_info, cache_key_prefix, max_funcs=40)
   ```
2. Replace duplicated planning loops in `graph.py` (`_auto_decompile_key_functions`) and `r2_graph.py` (`_r2_auto_decompile`).

#### 3.3 Unify LLM Context Building
1. Create `backend/src/ghidra_agent/context_builder.py`:
   ```python
   def build_analysis_context(state: AgentState, limit_decomp: int = 25) -> str
   ```
2. Use it in `graph.py` (`synthesize`) and `api/main.py` (`/query`).
3. Delete the duplicated ~200 lines from `/query`.

#### 3.4 Fix Race Condition on `reasoning_trace`
1. Change `reasoning_trace` from `List[str]` to `List[Dict[str, Any]]` or use per-analyzer traces:
   ```python
   "reasoning_trace": [],
   "ghidra_trace": [],
   "r2_trace": [],
   "qiling_trace": [],
   ```
2. Update all append sites in `graph.py`, `r2_graph.py`, `qiling_graph.py`.
3. Merge them into a single ordered trace in `synthesize` before persisting.

#### 3.5 Split `reporting.py`
1. Create `backend/src/ghidra_agent/reporting/` package.
2. Move functions into:
   - `reporting/html.py` — `build_report_html`, `build_agent_report_html`
   - `reporting/pdf.py` — `build_report_pdf`, `_build_pdf_html`
   - `reporting/text.py` — `build_report_text`
   - `reporting/common.py` — shared helpers (`_extract_section`, `_markdown_to_html`, etc.)
3. Update imports in `api/main.py`.

#### 3.6 Expand CI Coverage
1. Update `.github/workflows/ci.yml` to run:
   ```yaml
   pytest -q backend/tests/
   ```
   instead of the hardcoded subset.
2. Add a frontend lint gate to CI.

---

### Phase 4 — Security & Hardening (Secondary Priority)
*Goal: Close security gaps after core features are stable.*

#### 4.1 Enforce WebSocket Authentication
1. In `api/main.py` `stream()`:
   ```python
   token = websocket.query_params.get("token")
   if not token:
       await websocket.close(code=4001, reason="Token required")
       return
   try:
       decode_token(token)
   except Exception:
       await websocket.close(code=4001, reason="Invalid token")
       return
   ```

#### 4.2 Add Startup Secret Validation
1. In `backend/src/ghidra_agent/config.py` or `api/main.py` lifespan:
   ```python
   if settings.jwt_secret in ("changeme-gireng-jwt-secret-key", ""):
       logger.warning("insecure_jwt_secret")
   if settings.admin_password == "admin":
       logger.warning("insecure_admin_password")
   ```
2. Consider raising a hard error in non-dev mode.

#### 4.3 Add Rate Limiting
1. Add `slowapi` or in-memory token bucket middleware to:
   - `/analyze/upload` — e.g., 5 uploads per 15 min per user
   - `/query` — e.g., 30 queries per minute per user

#### 4.4 Harden Qiling Dockerfile
1. Pin `qilingframework/rootfs` to a specific Git commit or release tarball.
2. Pre-build the rootfs image separately and use it as a base image, or cache the clone layer aggressively.

#### 4.5 TypeScript & CORS Cleanup
1. Fix `AnalyzerRawResults.analyzer` to use a strict union or enum.
2. Remove unused mock data from `mockData.ts` if fully replaced by API calls.
3. Replace the CORS regex with an explicit allow-list built from `CORS_ORIGINS` env var.

---

## Part 3: Execution Order (Recommended Sprints)

### Sprint 1 — "Functional Blockers" (Days 1–3)
- [ ] 1.1 Fix `r2_search_bytes` (implement or remove)
- [ ] 1.2 Implement `get_decompilation` DB helper
- [ ] 1.3 Audit `/query_with_tools` prompt
- [ ] 1.4 Make Qiling optional in compose
- [ ] 1.5 Add auth to `analyze.py`
- [ ] 1.6 Implement `build_similar_files` (simple version)
- [ ] 1.7 Wire up model selector end-to-end

### Sprint 2 — "Feature Completion" (Days 4–8)
- [ ] 2.1 Fix or deprecate semantic memory
- [ ] 2.2 Remove or implement dead graph nodes
- [ ] 2.3 Add specialized quick-action prompts
- [ ] 3.6 Expand CI to full test suite

### Sprint 3 — "Refactoring & Quality" (Days 9–15)
- [ ] 3.1 Extract shared utilities
- [ ] 3.2 Unify auto-decompile logic
- [ ] 3.3 Unify LLM context builder
- [ ] 3.4 Fix race condition on `reasoning_trace`
- [ ] 3.5 Split `reporting.py` into package

### Sprint 4 — "Security & Hardening" (Days 16–22)
- [ ] 4.1 Enforce WebSocket auth
- [ ] 4.2 Startup secret validation
- [ ] 4.3 Add rate limiting
- [ ] 4.4 Harden Qiling Dockerfile
- [ ] 4.5 TS / CORS cleanup

---

## Part 4: Quick Wins (Can Do in One Session)

If you only have **1–2 hours**, do these in order to eliminate all functional P0 blockers:

1. **Remove `r2_search_bytes` import** from `glm_function_tools.py` if not implementing it immediately (5 min).
2. **Remove `get_decompilation` tool** from `glm_function_tools.py` and `api/main.py` prompt if not implementing immediately (5 min).
3. **Change Qiling `depends_on` to `service_started`** in `docker-compose.yml` (2 min).
4. **Add `--email/--password` to `analyze.py`** (20 min).
5. **Implement `get_decompilation`** in `database.py` (15 min).
6. **Add `model_id` field** to request payloads and pass `selectedModelId` from frontend (20 min).

These 6 items alone eliminate all P0 functional blockers.
