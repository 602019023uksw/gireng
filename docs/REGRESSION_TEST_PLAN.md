# Gireng Regression Test Plan & Release Gates

**Version:** 1.0  
**Date:** 2026-04-23  
**Scope:** End-to-end verification of all user-facing features, critical flows, and regression prevention.

---

## Table of Contents

1. [Feature Inventory](#1-feature-inventory)
2. [Test Commands & Scripts](#2-test-commands--scripts)
3. [Likely Breakpoints](#3-likely-breakpoints)
4. [Smoke Tests (Fast Must-Pass)](#4-smoke-tests-fast-must-pass)
5. [Full Regression Suite](#5-full-regression-suite)
6. [Release Gates](#6-release-gates)
7. [Known Issues from Audits](#7-known-issues-from-audits)

---

## 1. Feature Inventory

### 1.1 Authentication & User Management

| Feature | Expected Behavior | Test Data Needed |
|---------|-------------------|------------------|
| **User Registration** | POST `/api/auth/register` creates user with default quota | Valid email, username, password (4+ chars) |
| **User Login** | POST `/api/auth/login` returns JWT token + user profile | Existing user credentials |
| **Token Validation** | GET `/api/auth/me` returns current user profile with quota/usage | Valid JWT token |
| **Profile Update** | PUT `/api/auth/me` allows username/password change | Valid token, new username/password |
| **Admin - List Users** | GET `/api/admin/users` returns all users with quota + analysis count | Admin token |
| **Admin - Update Role** | PUT `/api/admin/users/{id}/role` changes user role | Admin token, target user ID |
| **Admin - Toggle Active** | PUT `/api/admin/users/{id}/active` disables/enables user | Admin token, target user ID |
| **Admin - Reset Password** | PUT `/api/admin/users/{id}/password` resets user password | Admin token, target user ID |
| **Admin - Update Quota** | PUT `/api/admin/users/{id}/quota` sets analysis quota (-1 = unlimited) | Admin token, target user ID |
| **Admin - Delete User** | DELETE `/api/admin/users/{id}` removes user | Admin token, target user ID |
| **Admin Bootstrap** | First startup creates admin@local / admin | Fresh database |

### 1.2 Binary Analysis Core

| Feature | Expected Behavior | Test Data Needed |
|---------|-------------------|------------------|
| **Upload Binary** | POST `/analyze/upload` accepts file, returns session_id | Valid binary (ELF/PE), JWT token |
| **Upload Size Limit** | Reject files > MAX_UPLOAD_BYTES (default 200MB) | Large file |
| **Empty File Reject** | Returns 400 for empty uploads | Empty file |
| **Analyze Existing** | POST `/analyze` starts analysis for pre-staged binary | Binary in /data/shared |
| **Status Polling** | GET `/status/{session_id}` returns progress + state | Active session_id |
| **Status States** | Progresses: initialized → running → completed/error | Session tracking |
| **WebSocket Stream** | WS `/stream/{session_id}` sends live events | Active session_id |
| **Query Agent** | POST `/query` answers natural language questions | Completed session, query text |
| **Model Selector** | `model` parameter overrides default LLM | Valid model ID |
| **Quota Enforcement** | Blocks upload when quota exceeded | User at quota limit |

### 1.3 Analysis Results & Reporting

| Feature | Expected Behavior | Test Data Needed |
|---------|-------------------|------------------|
| **Get Analysis** | GET `/api/analysis/{hash}` returns summary | Completed analysis hash |
| **List Analyzers** | GET `/api/analysis/{hash}/analyzers` returns Ghidra+R2+Qiling | Completed hash |
| **Get Files** | GET `/api/analysis/{hash}/files` returns decompiled tree | Completed hash |
| **Get File Content** | GET `/api/analysis/{hash}/files/{id}` returns function code | Completed hash, function ID |
| **HTML Export** | GET `/api/analysis/{hash}/export/html` downloads HTML report | Completed hash |
| **PDF Export** | GET `/api/analysis/{hash}/export/pdf` downloads PDF report | Completed hash |
| **Text Export** | GET `/api/analysis/{hash}/export/text` downloads text report | Completed hash |
| **Hex Dump** | GET `/api/analysis/{hash}/hex` returns hex at address | Completed hash, address |
| **Disassembly** | GET `/api/analysis/{hash}/disassembly` returns instructions | Completed hash, address |
| **Get Ghidra Raw** | GET `/api/analysis/{hash}/results/ghidra` returns full Ghidra data | Completed hash |
| **Get Radare2 Raw** | GET `/api/analysis/{hash}/results/radare2` returns full R2 data | Completed hash |
| **Get Qiling Raw** | GET `/api/analysis/{hash}/results/qiling` returns full Qiling data | Completed hash |

### 1.4 Analysis History & Search

| Feature | Expected Behavior | Test Data Needed |
|---------|-------------------|------------------|
| **List History** | GET `/api/history` returns paginated user analyses | JWT token |
| **History Filters** | Supports status, search, limit, offset | Token + filters |
| **Get History Item** | GET `/api/history/{session_id}` returns single analysis | Valid session_id |
| **Get QA History** | GET `/api/history/{session_id}/qa` returns Q&A pairs | Completed session |
| **Restore Session** | POST `/api/history/{session_id}/restore` reloads to memory | Past session_id |
| **Delete History** | DELETE `/api/history/{session_id}` removes analysis | Valid session_id |
| **Search Functions** | GET `/api/query/functions` searches across binaries | Query string |
| **Search Strings** | GET `/api/query/strings` full-text search | Query string |
| **Search IOCs** | GET `/api/query/iocs` filters by type | IOC type (ip, url, domain) |
| **Binary Functions** | GET `/api/binary/{hash}/functions` lists functions | Completed hash |
| **Binary Decompilations** | GET `/api/binary/{hash}/decompilations` returns decompiled code | Completed hash |
| **Binary IOCs** | GET `/api/binary/{hash}/iocs` returns IOCs | Completed hash |
| **Binary Attack Chains** | GET `/api/binary/{hash}/attack-chains` returns chains | Completed hash |

### 1.5 DeepSeek Reasoning Features

| Feature | Expected Behavior | Test Data Needed |
|---------|-------------------|------------------|
| **Query with Tools** | POST `/query_with_tools` allows LLM to invoke R2 tools | Session, query |
| **Reasoning Content** | API returns `reasoning_content` in responses | Query triggering reasoning |
| **Project Memory** | GET/POST `/api/memory/project/rules` manages rules | Auth token |
| **Episodic Memory** | GET `/api/memory/episodic/*` accesses past analyses | Auth token |
| **Semantic Memory** | GET `/api/memory/episodic/similar` finds related | Query params |
| **Memory Statistics** | GET `/api/memory/statistics` returns counts | Auth token |
| **Memory Context** | GET `/api/memory/context` returns formatted context | Auth token |
| **Record Memory** | POST `/api/memory/record` stores analysis | Analysis data |

### 1.6 Frontend UI Features

| Feature | Expected Behavior | Test Data Needed |
|---------|-------------------|------------------|
| **Login Page** | Validates credentials, stores token | User credentials |
| **Registration** | Creates account, redirects to welcome | Valid data |
| **Welcome Screen** | Shows upload, quick actions | Logged in user |
| **Upload Drag-Drop** | Accepts file drop, creates session | Binary file |
| **Progress Tracking** | Shows analyzer progress bars | Active analysis |
| **Chat Interface** | Sends queries, displays responses | Completed analysis |
| **Right Panel Tabs** | Resources/Code/Report/Dynamic tabs | Analysis loaded |
| **Code Viewer** | Displays decompiled function with syntax highlighting | Function selected |
| **Hex Viewer** | Shows hex dump at address | Address selected |
| **Disassembly View** | Shows disassembled instructions | Address selected |
| **Call Graph** | Visualizes function call graph | Ghidra/R2 analysis |
| **Admin Panel** | Lists users, allows edits | Admin user |
| **Model Selector** | Dropdown to select LLM model | Multiple models configured |
| **Export Buttons** | HTML/PDF/Text download | Completed analysis |
| **History Page** | Lists past analyses with filters | User with history |

### 1.7 Infrastructure & Services

| Feature | Expected Behavior | Test Data Needed |
|---------|-------------------|------------------|
| **Docker Compose** | All 7 services start healthy | Fresh docker compose up |
| **Service Health** | Agent, Ghidra, R2, Qiling, Postgres, Langfuse, UI | docker compose ps |
| **Service Dependencies** | Agent waits for Ghidra/R2/Qiling before starting | Compose startup |
| **Volume Persistence** | Ghidra projects, DB survive restart | docker compose down/up |
| **CORS Headers** | API accepts requests from UI origin | Browser request |
| **Rate Limiting** | Upload/query endpoints have limits | Repeated requests |

---

## 2. Test Commands & Scripts

### 2.1 Backend Tests

```bash
# Run all backend tests (requires venv setup)
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
python3 -m pytest tests/ -v

# Run specific test categories
python3 -m pytest tests/test_api.py -v          # API endpoints
python3 -m pytest tests/test_e2e.py -v          # End-to-end pipeline
python3 -m pytest tests/test_r2_graph.py -v     # R2 pipeline
python3 -m pytest tests/test_qiling_graph.py -v # Qiling pipeline
python3 -m pytest tests/test_glm_function_calling.py -v  # Function calling
```

### 2.2 Frontend Tests

```bash
cd app

# Type checking
npx tsc -b --noEmit

# Linting (requires working node_modules)
npm run lint

# Build
npm run build

# Unit tests (if configured)
npm run test
```

### 2.3 Docker Commands

```bash
# Full rebuild and start
docker compose up --build -d

# Check service health
docker compose ps

# View logs
docker compose logs -f agent
docker compose logs -f ghidra
docker compose logs -f radare2
docker compose logs -f qiling

# Restart specific service
docker compose restart agent

# Clean restart
docker compose down -v
docker compose up --build -d

# Database access
python3 run.py db
```

### 2.4 API Smoke Test (Curl)

```bash
# Health check
curl http://localhost:8080/health

# Login
TOKEN=$(curl -s -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@gireng.local","password":"admin"}' \
  | jq -r '.token')

# Get current user
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/auth/me

# Upload sample binary
SESSION_ID=$(curl -s -X POST http://localhost:8080/analyze/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@sample-binary/chargen" \
  | jq -r '.session_id')

# Poll status
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/status/$SESSION_ID | jq

# Get models
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/models
```

---

## 3. Likely Breakpoints

### 3.1 Error Handling Prone Areas

| Area | Edge Cases | Risk Level |
|------|-----------|------------|
| **Binary Upload** | Empty files, oversized files, non-binaries, corrupted binaries | High |
| **Async Pipeline** | Ghidra/R2/Qiling timeouts, container failures, race conditions | High |
| **Database** | Connection drops, constraint violations, migration issues | Medium |
| **LLM Calls** | API timeouts, rate limits, malformed responses, 200K+ token context | Medium |
| **WebSocket** | Abrupt disconnects, missing tokens, concurrent connections | Low |
| **PDF Generation** | Playwright crashes, missing Chromium, OOM on large reports | Medium |
| **Auth** | Expired tokens, malformed JWT, role changes during active session | Low |

### 3.2 Async Flows

- LangGraph parallel execution (Ghidra + R2 + Qiling via `asyncio.gather()`)
- WebSocket broadcast to multiple clients
- Database concurrent writes on analysis completion
- LLM streaming responses

### 3.3 Null/Empty Input Handling

| Input | Expected Behavior |
|-------|-------------------|
| Empty binary file | 400 Bad Request |
| Missing query text | 400 Bad Request |
| Invalid session_id | 404 Not Found |
| Invalid hash | 404 Not Found |
| Negative pagination offset | Clamped to 0 |
| Oversized limit | Clamped to max |
| Invalid JWT | 401 Unauthorized |
| Expired JWT | 401 Unauthorized |

### 3.4 Permissions & Config

| Config | Required | Default | Validation |
|--------|----------|---------|------------|
| `ANTHROPIC_API_KEY` | Yes | None | API fails if missing |
| `JWT_SECRET` | No (auto-gen) | "changeme-..." | Warning logged |
| `ADMIN_PASSWORD` | No | "admin" | Warning logged |
| `POSTGRES_PASSWORD` | No | "ireng_secret" | No validation |
| `RUNNER_IMAGE` | Yes | "danilid/ireng-runner:2.0.1" | Pull failure |
| `ENABLE_R2` | No | "true" | Boolean parse |
| `REGISTRATION_ENABLED` | No | "true" | Boolean parse |

### 3.5 External Dependencies

| Dependency | Failure Mode | Mitigation |
|------------|--------------|------------|
| Docker daemon | Agent cannot exec into containers | Check socket mount |
| Ghidra container | Analysis fails | R2/Qiling continue |
| Radare2 container | R2 features fail | Ghidra continues |
| Qiling container | Dynamic analysis fails | Static continues |
| PostgreSQL | History/storage fails | In-memory only |
| Langfuse | Tracing lost | Non-blocking |
| LLM API | Synthesis fails | Partial results stored |

---

## 4. Smoke Tests (Fast Must-Pass)

**Target Time:** < 5 minutes  
**Goal:** Verify core platform is functional before deeper testing.

### 4.1 Service Health

```bash
# All services running
docker compose ps | grep -q "Up" | wc -l >= 7

# API accessible
curl -sf http://localhost:8080/health | grep -q "ok"

# Frontend accessible
curl -sf http://localhost:4173 | grep -q "<!DOCTYPE html>"

# Database connected
curl -sf http://localhost:8080/health | grep -q '"db_connected":true'
```

### 4.2 Auth Smoke

```bash
# Can login
curl -sf -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@gireng.local","password":"admin"}' \
  | grep -q '"token":'

# Token validates
TOKEN=$(curl -s -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@gireng.local","password":"admin"}' \
  | jq -r '.token')

curl -sf -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/auth/me | grep -q '"role":"admin"'
```

### 4.3 Upload Smoke

```bash
# Can upload small binary
SESSION_ID=$(curl -s -X POST http://localhost:8080/analyze/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@sample-binary/chargen" \
  | jq -r '.session_id')

# Session ID returned
[ -n "$SESSION_ID" ] && [ "$SESSION_ID" != "null" ]

# Status endpoint responds
curl -sf -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8080/status/$SESSION_ID" | grep -q '"session_id"'
```

### 4.4 Analysis Smoke

```bash
# Wait for completion (max 5 min for smoke)
for i in {1..60}; do
  STATUS=$(curl -s -H "Authorization: Bearer $TOKEN" \
    "http://localhost:8080/status/$SESSION_ID" | jq -r '.status')
  if [ "$STATUS" = "completed" ] || [ "$STATUS" = "error" ]; then
    break
  fi
  sleep 5
done

[ "$STATUS" = "completed" ]
```

### 4.5 Export Smoke

```bash
# Get hash from status
HASH=$(curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8080/status/$SESSION_ID" | jq -r '.state.program_hash')

# HTML export works
curl -sf -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8080/api/analysis/$HASH/export/html" | grep -q "<!DOCTYPE html>"

# Text export works
curl -sf -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8080/api/analysis/$HASH/export/text" | grep -q "# "
```

---

## 5. Full Regression Suite

### 5.1 Authentication Tests

| Test | Command | Expected |
|------|---------|----------|
| Register new user | POST `/api/auth/register` | 200, token returned |
| Duplicate email | POST with same email | 409 conflict |
| Duplicate username | POST with same username | 409 conflict |
| Weak password | Password < 4 chars | 400 bad request |
| Invalid login | Wrong password | 401 unauthorized |
| Valid login | Correct credentials | 200, token |
| Expired token | Use expired JWT | 401/403 |
| Malformed token | "Bearer invalid" | 401/403 |
| Get profile | GET `/api/auth/me` | User data + quota |
| Update username | PUT `/api/auth/me` | 200 ok |
| Update password | PUT with new password | 200 ok |
| Admin list users | GET `/api/admin/users` | All users + counts |
| Admin change role | PUT `/api/admin/users/{id}/role` | 200 ok |
| Admin disable user | PUT `/api/admin/users/{id}/active` | 200 ok |
| User disabled login | Login with disabled user | 403 forbidden |
| Admin delete user | DELETE `/api/admin/users/{id}` | 200 ok |
| Quota enforcement | Upload at quota limit | 403 forbidden |
| Admin unlimited quota | Admin upload at limit | Succeeds |

### 5.2 Binary Analysis Tests

| Test | Input | Expected |
|------|-------|----------|
| Upload ELF | sample-binary/chargen | Session created |
| Upload PE | sample-binary/explorer.exe | Session created |
| Upload corrupted | Invalid binary | Error or graceful degradation |
| Empty file | Empty upload | 400 bad request |
| Oversized file | >200MB | 413 payload too large |
| Duplicate upload | Same binary twice | New session, same hash |
| Analyze existing | Binary in /data/shared | Session created |
| Model parameter | model=deepseek-v4-pro | Uses specified model |
| Status initialized | New session | status=initialized |
| Status running | Poll during analysis | status=running, progress>0 |
| Status completed | After analysis | status=completed |
| Status error | Failed analysis | status=error |
| WebSocket connect | WS with token | Connection accepted |
| WebSocket progress | During analysis | progress events |
| WebSocket complete | On finish | analysis:completed |
| Query agent | Natural language | Answer returned |
| Query with tools | POST `/query_with_tools` | Tool invocations |
| Query nonexistent | Invalid session | 404 not found |

### 5.3 Result & Export Tests

| Test | Expected |
|------|----------|
| Get analysis summary | Hash, status, verdict, score, tags |
| List analyzers | 3 analyzers (ghidra, radare2, qiling) |
| Get analyzer details | Functions, strings, call graph |
| List files | File tree with functions |
| Get function code | Decompiled C code |
| Similar files | Array of similar binaries (currently stub/empty) |
| HTML export | Valid HTML with dark theme |
| PDF export | Valid PDF bytes |
| Text export | Markdown text |
| Hex dump | Hex lines at address |
| Disassembly | Instruction list |
| Ghidra raw | Full Ghidra JSON |
| Radare2 raw | Full Radare2 JSON |
| Qiling raw | Full Qiling JSON |

### 5.4 History & Search Tests

| Test | Expected |
|------|----------|
| List history | Paginated analysis list |
| Filter by status | Only matching status |
| Search by name | Matching binary names |
| Pagination | limit/offset respected |
| Get history item | Single analysis details |
| Get QA history | Question/answer pairs |
| Restore session | Session reloaded to memory |
| Delete history | Analysis removed |
| Search functions | Cross-binary function results |
| Search strings | Matching strings across binaries |
| Search IOCs | IOCs by type |
| Binary functions | All functions for hash |
| Binary IOCs | All IOCs for hash |
| Binary attack chains | Attack chain data |

### 5.5 DeepSeek Feature Tests

| Test | Expected |
|------|----------|
| Query returns reasoning | response.reasoning_content exists |
| Project memory rules | GET returns rules |
| Add project rule | POST adds rule |
| Episodic memory recent | GET returns recent analyses |
| Episodic by hash | GET returns specific analysis |
| Semantic search | GET returns similar (keyword match) |
| Memory statistics | GET returns counts |
| Memory context | GET returns formatted context |

### 5.6 Frontend UI Tests

| Test | Expected |
|------|----------|
| Login form validation | Empty fields show error |
| Login success | Redirects to welcome |
| Registration form | Creates account, logs in |
| Welcome screen | Upload + quick actions visible |
| File upload | Drag-drop works |
| Upload progress | Shows progress bar |
| Analyzer progress | Shows 3 analyzers with progress |
| Chat interface | Can send query |
| Chat response | Displays LLM answer |
| Right panel tabs | All tabs functional |
| Code viewer | Shows decompiled code |
| Hex viewer | Shows hex dump |
| Disassembly view | Shows instructions |
| Call graph | Renders graph |
| Admin panel | Lists users, actions work |
| Model selector | Dropdown (currently non-functional) |
| Export buttons | Downloads files |
| History page | Lists analyses |

### 5.7 Infrastructure Tests

| Test | Expected |
|------|----------|
| All services start | docker compose ps shows 7 Up |
| Ghidra healthy | healthcheck passes |
| Radare2 healthy | healthcheck passes |
| Qiling healthy | healthcheck passes |
| Agent healthy | API responds |
| UI healthy | Frontend loads |
| Postgres healthy | DB connection works |
| Langfuse healthy | Dashboard accessible |
| Volume persistence | Data survives restart |
| CORS headers | UI can call API |
| Service dependencies | Agent waits for analyzers |

---

## 6. Release Gates

### 6.1 Pre-Release Checklist

**Must be completed before any release:**

- [ ] All services start successfully (`docker compose up --build -d`)
- [ ] Health check returns 200 with `db_connected: true`
- [ ] All smoke tests pass (Section 4)
- [ ] Admin login works with default credentials
- [ ] Sample binary (chargen) analyzes successfully
- [ ] HTML/PDF/Text exports download correctly
- [ ] Frontend loads in browser without console errors
- [ ] WebSocket connects and receives events
- [ ] Database persists analysis across restart
- [ ] No Python import errors in backend logs
- [ ] No TypeScript errors in frontend build

### 6.2 Definition of "No Broken Features"

**All of the following must be true:**

| Category | Criteria |
|----------|----------|
| **Authentication** | All auth endpoints return correct responses; tokens validate; roles enforce permissions |
| **Analysis** | Upload → analyze → status → complete flow works for ELF and PE binaries |
| **Results** | All result endpoints return data for completed analysis |
| **Exports** | HTML, PDF, and Text exports generate valid, viewable reports |
| **History** | Analyses persist to DB; list/search/restore/delete work |
| **Frontend** | All UI pages load; forms submit; data displays correctly |
| **Infrastructure** | All 7 containers healthy; no crash loops; logs error-free |

### 6.3 Test Coverage Gates

| Test Suite | Minimum Pass Rate | Notes |
|------------|-------------------|-------|
| Backend unit tests | 100% | All 183 tests pass |
| E2E pipeline | 100% | Chargen analysis completes |
| API tests | 100% | All endpoints respond |
| R2/R/Qiling tests | 100% | Individual analyzers work |
| Function calling | 100% | Tool registration works |
| Frontend type check | 0 errors | `tsc -b --noEmit` |
| Frontend lint | 0 errors (warns ok) | `npm run lint` |

### 6.4 Known Issues Acceptance

**For release, known issues must be categorized:**

| Category | Allowed for Release | Example |
|----------|---------------------|---------|
| **P0 - Runtime crashes** | NO | ImportError, unhandled exceptions |
| **P0 - Feature broken** | NO | Upload fails, exports broken |
| **P1 - Feature incomplete** | MAYBE | Documented, non-critical path |
| **P1 - UI non-functional** | MAYBE | Feature marked "beta" or "coming soon" |
| **P2 - Security** | NO | Auth bypass, data leak |
| **P2 - Quality** | YES | Code duplication, tech debt |
| **P3 - Nice to have** | YES | Performance, UX polish |

### 6.5 Rollback Criteria

**Release must be rolled back if:**

1. Any critical service (agent, postgres) fails to start
2. Auth endpoint returns 500 for valid login
3. Upload analysis fails for valid binaries
4. Export generation causes crashes
5. Database migrations fail or corrupt data
6. Frontend shows blank/error page on load
7. WebSocket connections fail for valid tokens
8. Any regression from previous working version

---

## 7. Known Issues from Audits

### 7.1 P0 - Must Fix Before Release

From `kimi-2.6-review.md`:

| Issue | Status | Fix Required |
|-------|--------|--------------|
| `r2_search_bytes` import error | **Broken** | Implement or remove from function_tools.py |
| `get_decompilation` missing | **Broken** | Implement in database.py |
| `/query_with_tools` broken tools | **Broken** | Fix prompt to match available tools |
| `analyze.py` no auth | **Broken** | Add JWT support |
| Agent blocked by Qiling health | **Broken** | Make Qiling optional in compose |
| `build_similar_files` stub | **Non-functional** | Implement or remove feature |

### 7.2 P1 - Should Fix

| Issue | Impact |
|-------|--------|
| Model selector non-functional | UI theater only |
| Semantic memory placeholder | No embeddings generated |
| Write mode dead code | Unused graph nodes |
| Quick actions are just text | No specialized handling |
| Code duplication | Maintenance burden |

### 7.3 P2/P3 - Can Defer

| Issue | Impact |
|-------|--------|
| WebSocket unauthenticated fallback | Security hole (documented) |
| Insecure default secrets | Security risk (documented) |
| CORS regex permissive | Localhost only |
| CI skips tests | Quality risk |
| Qiling live git clone | Build reproducibility |

---

## Appendix: Test Data

### Sample Binaries

| File | Type | Size | Use Case |
|------|------|------|----------|
| `chargen` | ELF | ~840KB | Basic analysis |
| `explorer.exe` | PE | ~2.7MB | Windows binary |
| `test_binary` | ELF | ~290KB | Simple test |
| `s.wnry` | ELF | ~690KB | Malware sample |
| `rop_gently` | ELF | ~850KB | Complex binary |

### Test Users

| Role | Email | Password | Quota |
|------|-------|----------|-------|
| Admin | admin@gireng.local | admin | -1 (unlimited) |
| User | test@example.com | test123 | 10 |
| Guest | guest@example.com | guest123 | 0 (read-only) |

---

## Appendix: Continuous Monitoring

### Health Check Endpoints

```bash
# API health
curl http://localhost:8080/health

# Service status
docker compose ps

# Container health
docker inspect gireng-agent-1 | jq '.[0].State.Health'

# Database connection
docker exec ireng_postgres pg_isready -U gireng
```

### Log Monitoring

```bash
# Agent errors
docker compose logs agent | grep -i error

# Ghidra failures
docker compose logs ghidra | grep -i fail

# R2 timeouts
docker compose logs radare2 | grep -i timeout

# Qiling issues
docker compose logs qiling | grep -i error
```

### Performance Metrics

| Metric | Target | Alert Threshold |
|--------|--------|-----------------|
| Analysis time (small) | < 2 min | > 5 min |
| Analysis time (large) | < 10 min | > 20 min |
| Memory per analysis | < 2GB | > 4GB |
| API response time | < 500ms | > 2s |
| WebSocket latency | < 100ms | > 1s |
