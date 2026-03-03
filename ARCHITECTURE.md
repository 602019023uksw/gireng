# Integration Architecture — Tri-Engine Binary Analysis Platform

## Overview

gireng (Ghidra and Radare Intelligent Reverse Engineering) is an AI-powered reverse engineering platform that analyses binaries using **three parallel engines** — **Ghidra**, **Radare2**, and **Qiling** — then synthesises their findings via an LLM to produce a comprehensive malware report with MITRE ATT&CK mapping, IOC extraction, call graph analysis, and professional PDF/HTML/text export.

The platform includes **JWT-based authentication** with role-based access control (admin / user / guest), **multitenancy** (users only see their own analyses), and **per-user analysis quotas**.

```
┌──────────────┐    HTTP / WS     ┌──────────────────────────────┐
│  Frontend UI │ ◄──────────────► │  FastAPI Agent  (port 8080)  │
│  Vite :4173  │                  │  api/main.py  (38 endpoints) │
└──────────────┘                  └──────────────┬───────────────┘
                                                 │
                                    ┌────────────┴────────────┐
                                    │   LangGraph StateGraph   │
                                    │   graph.py               │
                                    │                          │
                                    │  parse_intent            │
                                    │    → initialize          │
                                    │    → discovery ─────┐    │
                                    │       asyncio.gather│    │
                                    │    ┌────────────────┤    │
                                    │    │ Ghidra         │    │
                                    │    │ (tools.py)     │    │
                                    │    ├────────────────┤    │
                                    │    │ Radare2        │    │
                                    │    │ (r2_graph.py)  │    │
                                    │    └────────────────┘    │
                                    │    → focus_analysis       │
                                    │    → cross_reference      │
                                    │    → synthesize  (LLM)   │
                                    │    → END                  │
                                    └────┬──────────────┬──────┘
                                         │              │
                        docker exec      │              │      docker exec
                    ┌────────────────────┘              └──────────────────┐
                    ▼                                                      ▼
        ┌───────────────────────┐     shared volume      ┌────────────────────────┐
        │  Ghidra Container     │ ◄── ghidra_shared ──►  │  Radare2 Container     │
        │  ghidra_headless      │     /data/shared       │  radare2               │
        │  PyGhidra + scripts   │                        │  r2 + r2ghidra/r2dec   │
        └───────────────────────┘                        └────────────────────────┘
                                                                  │
                                                         ┌───────┴───────┐
                                                         │  PostgreSQL   │
                                                         │  (persistence │
                                                         │   + Langfuse) │
                                                         └───────────────┘
```

---

## Docker Services

| Service | Image | Purpose | Port |
|---------|-------|---------|------|
| `ghidra` | `danilid/ireng-runner:2.0.1` (configurable via `$RUNNER_IMAGE`) | Headless Ghidra with PyGhidra. Runs analysis scripts via `docker exec`. | internal |
| `radare2` | `radare/radare2:latest` | Headless Radare2 with r2ghidra/r2dec plugins. Runs r2 commands via `docker exec`. | internal |
| `qiling` | Built from `backend/Dockerfile.qiling` | Qiling sandbox for dynamic emulation, API/syscall tracing, evasion detection. | internal |
| `agent` | Built from `backend/Dockerfile` | FastAPI backend + Playwright/Chromium for PDF. Orchestrates all three tools, calls LLM, serves API. | **8080** |
| `ui` | Built from `app/Dockerfile.ui` | React 19 + Vite frontend. | **4173** |
| `postgres` | `postgres:16-alpine` | PostgreSQL for analysis history + Langfuse data. | internal |
| `langfuse` | `langfuse/langfuse:2` | LLM observability and tracing dashboard. | **3100** |

All containers share a Docker volume `ghidra_shared` mounted at `/data/shared`. Binaries are placed here on upload so Ghidra, R2, and Qiling can access them.

The `agent` container mounts the host Docker socket (`/var/run/docker.sock`) to issue `docker exec` commands into the sibling Ghidra, R2, and Qiling containers.

---

## Data Flow

### 1. Binary Upload

```
Client → POST /analyze/upload → Agent
  → SessionStore.create_session()
    → copy binary to /data/shared/<safe_name>
    → compute SHA-256 hash
    → init AgentState
  → asyncio.create_task(run_graph(state))
  → return { session_id }
  → persist to PostgreSQL (database.py / storage.py)
```

### 2. Analysis Pipeline (LangGraph)

The analysis is a **LangGraph StateGraph** with conditional edges:

```
parse_intent ──► initialize ──► discovery ──► focus_analysis ──► cross_reference ──► synthesize ──► END
                                    │                ▲                                    ▲
                                    │                │                                    │
                                    └── (skip) ──────┴──── (skip) ────────────────────────┘
```

#### `parse_intent`
Classifies the user query into one of: `reconnaissance`, `vulnerability`, `malware`, `protocol`.
Extracts function names (`FUN_xxxxx`) and hex addresses (`0x...`) into state.

#### `initialize`
Marks both Ghidra and R2 pipelines as initialised. Copies Ghidra scripts to the shared volume.

#### `discovery` — Parallel Execution
The core dual-agent stage. Runs both toolchains **concurrently** via `asyncio.gather()`:

```python
ghidra_result, _ = await asyncio.gather(
    _ghidra_discovery(state),   # Ghidra: analyze → functions → strings → auto-decompile → call graph
    _safe_r2(state),            # R2:     analyze → functions → strings → auto-decompile → call graph
)
```

Each pipeline writes to **separate state fields** to avoid race conditions:

| Data | Ghidra field | R2 field |
|------|-------------|----------|
| Binary info, functions, strings | `analysis_results` | `r2_analysis_results` |
| Decompiled code | `decompilation_cache` | `r2_decompilation_cache` |

**R2 / Qiling failure does not block Ghidra.** The `_safe_r2` and `_safe_qiling` wrappers catch all exceptions and log them; the pipeline continues with available results.

#### Auto-decompilation
Both pipelines automatically decompile the **top 15 functions** ranked by the function priority scorer (cross-reference count + code size + API call detection + suspicious string references), plus the entry-point function.

#### Call Graph Analysis
Both Ghidra and R2 build call graphs. The `call_graph_analyzer.py` module traces attack chains from entry points (`main`, `_start`, `entry0`) to suspicious sinks. Qiling contributes dynamic behavior data (API calls observed at runtime, network connections, evasion attempts) which enriches the synthesized report.

- **Execution**: `system`, `popen`, `execve`, `dlopen`, ...
- **Network**: `socket`, `connect`, `send`, `recv`, ...
- **File I/O**: `fopen`, `fwrite`, `unlink`, ...
- **Crypto**: `encrypt`, `decrypt`, ...
- **Recon**: `gethostname`, `uname`, `getenv`, ...
- **Timing**: `sleep`, `usleep`, ...

Max chain depth: 10, max chains: 80.

#### `focus_analysis`
If the user query targets a specific function or address, this stage decompiles/disassembles it. Falls back through: decompilation → disassembly.

#### `cross_reference`
Finds cross-references to/from the target address using both tools.

#### `synthesize`
Builds a massive context block from **both** Ghidra and R2 results:
- Architecture, binary metadata from both tools
- Merged function lists with priority scores
- All decompiled code (Ghidra + R2)
- Strings and IOCs
- Cross-reference data
- Call graph attack chains

Sends the context + `SYSTEM_PROMPT` to the LLM, which produces a structured malware report with MITRE ATT&CK mapping and automated malware type classification (12 behavioural profiles: RAT, ransomware, rootkit, spyware, etc.).

### 3. Results, Reporting & Export

```
Client → GET /status/{session_id}                     → full state
Client → GET /api/analysis/{hash}/analyzers            → [{ghidra}, {radare2}]
Client → GET /api/analysis/{hash}/reports              → HTML malware report
Client → GET /api/analysis/{hash}/export/html           → downloadable HTML
Client → GET /api/analysis/{hash}/export/pdf            → A4 PDF (Playwright)
Client → GET /api/analysis/{hash}/export/text           → plain text report
Client → WS  /stream/{session_id}                      → real-time events
```

#### Report Generation (reporting.py)

| Function | Output |
|----------|--------|
| `build_report_html(state)` | Interactive dark-themed HTML with MITRE cards, code evidence, call graphs, operational flow |
| `build_agent_report_html(state, agent)` | Per-agent (Ghidra or R2) focused HTML report |
| `build_report_pdf(state)` | Professional white-background A4 PDF via dedicated `_build_pdf_html()` template + Playwright/Chromium |
| `build_report_text(state)` | Plain text report |

The PDF template is a completely separate light-mode HTML document with inline CSS (no Tailwind CDN, no JavaScript) optimised for deterministic A4 rendering with 13 numbered sections.

### 4. Persistence, History & Multitenancy

Completed analyses are persisted to PostgreSQL via `database.py` and `storage.py`. Each analysis is linked to the user who uploaded it. The history API supports:
- Paginated listing with verdict/hash filtering
- **Multitenancy** — non-admin users only see their own analyses
- Session restore (reload into memory for follow-up queries)
- Cross-binary search (functions, strings, IOCs)

### 5. Authentication & Authorization

The platform uses **JWT-based authentication** (HS256, 24-hour expiry) with three roles:

| Role | Permissions |
|------|-------------|
| `admin` | Full access, see all analyses, manage users, unlimited quota |
| `user` | Upload & analyze (within quota), see own analyses, chat |
| `guest` | Read-only access to own analyses |

All API routes require a valid JWT token via `Authorization: Bearer <token>` header.

Key auth modules:
- `auth.py` — `get_current_user()`, `require_role()`, `can_write()`, `hash_password()`, `verify_password()`
- `database.py` — User CRUD, quota management, analysis count

### 6. User Quotas

Each user has an analysis quota (default: 10, configurable via `DEFAULT_USER_QUOTA` env var):
- `-1` = unlimited (set automatically for admin users)
- `0` = blocked from uploading
- `N` = can upload up to N binaries

Quota is enforced on both `/analyze` and `/analyze/upload` endpoints. Admins can adjust quotas per-user via the Admin Panel or API.

---

## Module Map

### Core Pipeline

| Module | File | Responsibility |
|--------|------|----------------|
| **State** | `state.py` | `AgentState` TypedDict — 20 fields including dual R2/Ghidra state |
| **Graph** | `graph.py` | LangGraph StateGraph — pipeline orchestration, parallel discovery |
| **LLM** | `llm.py` | LiteLLM `acompletion` wrapper for LLM calls |
| **Prompts** | `prompts.py` | System prompt (dual-agent aware), focused analysis prompt |
| **Sessions** | `sessions.py` | In-memory session store, `run_graph()` entry point |
| **Config** | `config.py` | Pydantic `Settings` — all env vars for Ghidra, R2, LLM |

### Analysis Modules

| Module | File | Responsibility |
|--------|------|----------------|
| **Call Graph Analyzer** | `call_graph_analyzer.py` | Build attack chains from function-call edges to suspicious sinks (209 lines) |
| **Function Priority** | `function_priority.py` | Rank functions by composite score: xrefs, size, API calls, suspicious strings (345 lines) |
| **IOC Extractor** | `ioc_extractor.py` | Regex-based extraction of IPs, URLs, domains, hashes, file paths, emails, registry keys, mutexes, crypto materials. Verdict calculation (591 lines) |
| **IANA TLDs** | `iana_tlds.py` | Valid TLD set for domain validation |

### Ghidra Integration

| Module | File | Responsibility |
|--------|------|----------------|
| **Tools** | `tools.py` | `@tool` functions — `analyze_binary_structure`, `list_functions`, `decompile_function`, `find_strings`, `find_xrefs`, `disassemble_at`, `search_bytes`, `get_function_graph`, `rename_symbol`, `add_comment` |
| **Runner** | `ghidra/runner.py` | `GhidraHeadlessRunner` — `docker exec` into `ghidra_headless` container, runs PyGhidra scripts, JSON I/O, retry logic |
| **Scripts** | `ghidra_scripts/*.py` | 11 Python scripts executed inside Ghidra's PyGhidra env |

Execution pattern:
```
Agent → docker exec ghidra_headless pyghidraRun -H /data/projects <project>
        -import /data/shared/<binary> -scriptPath /data/shared/scripts
        -postScript <script.py> input.json output.json log.txt
```

### Radare2 Integration

| Module | File | Responsibility |
|--------|------|----------------|
| **Tools** | `r2_tools.py` | `@tool` functions — `r2_analyze_binary`, `r2_list_functions`, `r2_decompile_function`, `r2_find_strings`, `r2_find_xrefs`, `r2_disassemble_at`, `r2_syscall_analysis` |
| **Runner** | `radare/runner.py` | `Radare2Runner` — `docker exec` into `radare2` container, JSON parsing with noise handling, timeout control |
| **Pipeline** | `r2_graph.py` | Sequential pipeline: `r2_discovery` → `r2_focus_analysis` → `r2_cross_reference` (called from `graph.py`) |

Execution pattern:
```
Agent → docker exec radare2 r2 -q -e bin.cache=true -c '<commands>' /data/shared/<binary>
```

R2 decompilation uses a fallback chain: `pdg` (r2ghidra) → `pdd` (r2dec) → `pdf` (disassembly).

### Qiling Integration

| Module | File | Responsibility |
|--------|------|----------------|
| **Tools** | `qiling_tools.py` | `@tool` functions — `qiling_emulate`, `qiling_trace_api`, `qiling_trace_syscalls`, `qiling_detect_evasion`, `qiling_memory_analysis`, `qiling_network_analysis` |
| **Runner** | `qiling/runner.py` | `QilingRunner` — `docker exec` into `qiling_emulator` container, sandboxed execution |
| **Pipeline** | `qiling_graph.py` | Qiling pipeline stages (called from `graph.py`) |
| **Scripts** | `qiling_scripts/*.py` | 10 emulation scripts: API tracing, syscall tracing, instruction tracing, evasion detection, memory/network analysis, stub DLL creation |

### Authentication & Authorization

| Module | File | Responsibility |
|--------|------|----------------|
| **Auth** | `auth.py` | JWT creation/validation, password hashing (bcrypt), role-based middleware: `get_current_user()`, `require_role()`, `can_write()` |
| **Database (Users)** | `database.py` | User CRUD, quota management, analysis count per user |
| **Config** | `config.py` | JWT secret, algorithm, expiry, admin bootstrap credentials, quota defaults |

### API Layer

| Module | File | Responsibility |
|--------|------|----------------|
| **API** | `api/main.py` | FastAPI app — 50+ REST endpoints + WebSocket streaming |
| **UI Adapter** | `ui_adapter.py` | Builds structured JSON for `/analyzers` — dual-analyzer details, file tree, reports |
| **Reporting** | `reporting.py` | HTML, PDF (Playwright/Chromium), text report generation. Dedicated light-mode PDF template |
| **IOC Extractor** | `ioc_extractor.py` | Multi-type IOC extraction with verdict calculation |
| **Models** | `models.py` | Pydantic request/response schemas for all endpoints |
| **Database** | `database.py` | PostgreSQL async connection pool, analysis persistence, user management, quotas |
| **Storage** | `storage.py` | Higher-level storage operations for analysis history |
| **Langfuse** | `langfuse_tracing.py` | LLM call tracing integration |

### Frontend

| Module | File | Responsibility |
|--------|------|----------------|
| **Ghidra Agent** | `agents/ghidra-agent.ts` | Agent definition, capabilities list |
| **Radare Agent** | `agents/radare-agent.ts` | R2 agent definition with R2-specific capabilities |
| **API Client** | `lib/api.ts` | REST API client with auth, export URL builders |
| **Auth Hook** | `hooks/useAuth.tsx` | AuthProvider context, login/logout/register, token management |
| **Auth Components** | `components/auth/` | AuthPage (login/register), UserMenu (header dropdown), AdminPanel (user management) |

---

## API Endpoints (50+ total)

### Authentication

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/auth/register` | Register new user |
| `POST` | `/api/auth/login` | Login, receive JWT + user profile |
| `GET` | `/api/auth/me` | Current user profile (with quota + usage) |

### Admin (requires admin role)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/admin/users` | List all users (with quota + analysis count) |
| `PUT` | `/api/admin/users/{id}/role` | Change user role |
| `PUT` | `/api/admin/users/{id}/active` | Toggle user active/disabled |
| `PUT` | `/api/admin/users/{id}/password` | Reset user password |
| `PUT` | `/api/admin/users/{id}/quota` | Update user analysis quota |
| `DELETE` | `/api/admin/users/{id}` | Delete user |

### Session Management

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/analyze` | Start analysis from binary path |
| `POST` | `/analyze/upload` | Upload binary file and start analysis |
| `GET` | `/status/{session_id}` | Poll analysis status |
| `POST` | `/query` | Send follow-up question |
| `POST` | `/write_mode` | Enable/disable write mode |
| `POST` | `/write_mode/confirm` | Approve pending write actions |
| `WS` | `/stream/{session_id}` | Real-time event streaming |

### Analysis Results (by SHA-256 hash)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/analysis/{hash}` | Analysis status |
| `GET` | `/api/analysis/{hash}/analyzers` | List analyzers (Ghidra + R2) |
| `GET` | `/api/analysis/{hash}/analyzers/{id}` | Analyzer details |
| `GET` | `/api/analysis/{hash}/files` | Decompiled file tree |
| `GET` | `/api/analysis/{hash}/files/{id}` | Decompiled function code |
| `GET` | `/api/analysis/{hash}/reports` | Report list |
| `GET` | `/api/analysis/{hash}/reports/{id}` | Report HTML content |
| `GET` | `/api/analysis/{hash}/similar` | Similar files |
| `GET` | `/api/analysis/{hash}/results/ghidra` | Raw Ghidra results |
| `GET` | `/api/analysis/{hash}/results/radare2` | Raw Radare2 results |

### Export

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/analysis/{hash}/export/html` | Export report as HTML |
| `GET` | `/api/analysis/{hash}/export/text` | Export report as plain text |
| `GET` | `/api/analysis/{hash}/export/pdf` | Export report as A4 PDF |
| `GET` | `/export/session/{session_id}/html` | Export session HTML (convenience) |
| `GET` | `/export/session/{session_id}/text` | Export session text (convenience) |
| `GET` | `/export/session/{session_id}/pdf` | Export session PDF (convenience) |
| `GET` | `/export/session/{session_id}/agent/{agent}` | Export per-agent report |

### Analysis History & Cross-Binary Search

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/history` | List past analyses (paginated, filterable) |
| `GET` | `/api/history/{session_id}` | Single past analysis summary |
| `GET` | `/api/history/{session_id}/qa` | Q&A history for session |
| `POST` | `/api/history/{session_id}/restore` | Restore past session into memory |
| `DELETE` | `/api/history/{session_id}` | Delete past analysis |
| `GET` | `/api/query/functions` | Search functions across all binaries |
| `GET` | `/api/query/strings` | Full-text search strings |
| `GET` | `/api/query/iocs` | Search IOCs across all binaries |
| `GET` | `/api/binary/{hash}/functions` | Functions for a specific binary |
| `GET` | `/api/binary/{hash}/decompilations` | Decompiled functions for a binary |
| `GET` | `/api/binary/{hash}/iocs` | IOCs for a specific binary |
| `GET` | `/api/binary/{hash}/attack-chains` | Attack chains for a binary |

### Utility

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Service health check |
| `GET` | `/api/models` | Available LLM models |

### WebSocket Events

| Event | When |
|-------|------|
| `analysis:progress` | Analysis started |
| `message:typing` | Agent processing |
| `analysis:completed` | Analysis finished |
| `analysis:error` | Analysis failed |

---

## Configuration (Environment Variables)

### Ghidra

| Variable | Default | Description |
|----------|---------|-------------|
| `RUNNER_IMAGE` | `gireng-runner` | Ghidra Docker image |
| `GHIDRA_PROJECT_ROOT` | `/data/projects` | Ghidra project storage |
| `GHIDRA_SHARED_ROOT` | `/data/shared` | Shared binary volume |
| `GHIDRA_VOLUME_CONTAINER` | `ghidra_headless` | Ghidra container name |
| `GHIDRA_SCRIPTS_ROOT` | `/data/shared/scripts` | Scripts inside container |
| `GHIDRA_SCRIPTS_SOURCE` | `/app/ghidra_scripts` | Scripts source in agent |
| `GHIDRA_HEADLESS_SCRIPT_PATH` | `/usr/share/ghidra/support/pyghidraRun` | PyGhidra launcher |
| `DEFAULT_ANALYSIS_TIMEOUT` | `120` | Ghidra analysis timeout (seconds) |

### Radare2

| Variable | Default | Description |
|----------|---------|-------------|
| `R2_CONTAINER_NAME` | `radare2` | R2 container name |
| `R2_SHARED_ROOT` | `/data/shared` | Binary volume mount inside R2 container |
| `R2_TIMEOUT` | `60` | R2 command timeout (seconds) |
| `ENABLE_R2` | `true` | Enable/disable R2 integration |

### LLM

| Variable | Default | Description |
|----------|---------|-------------|
| `LLM_MODEL_NAME` | `glm-4.7` | LLM model name |
| `LLM_PROVIDER` | `openai` | LiteLLM provider prefix |
| `LLM_API_KEY` / `ANTHROPIC_API_KEY` | — | API key |
| `LLM_BASE_URL` / `ANTHROPIC_BASE_URL` | — | API endpoint |

### Authentication & Quotas

| Variable | Default | Description |
|----------|---------|-------------|
| `JWT_SECRET` | (auto-generated) | Secret key for JWT signing |
| `JWT_ALGORITHM` | `HS256` | JWT algorithm |
| `JWT_EXPIRE_MINUTES` | `1440` | Token expiry (24 hours) |
| `ADMIN_EMAIL` | `admin@gireng.local` | Bootstrap admin email |
| `ADMIN_PASSWORD` | `admin` | Bootstrap admin password |
| `ADMIN_USERNAME` | `admin` | Bootstrap admin username |
| `REGISTRATION_ENABLED` | `true` | Allow public registration |
| `DEFAULT_USER_QUOTA` | `10` | Default analysis quota for new users (-1 = unlimited) |

---

## State Schema

The `AgentState` is a Python `TypedDict` with 20 fields that flows through every pipeline node:

```
AgentState
├── session_id: str
├── binary_path: str
├── program_hash: str              (SHA-256)
├── user_query: str
├── intent: str                    (reconnaissance|vulnerability|malware|protocol)
├── status: str                    (initialized|completed|error)
├── current_step: str
├── progress: int                  (0-100)
│
├── current_function: Optional[str]
├── current_address: Optional[str]
│
├── analysis_results: Dict         ◄── Ghidra findings
│   ├── binary: {...}              (arch, compiler, entry points, segments)
│   ├── functions: {...}           (name, address, size, xrefs)
│   ├── strings: {...}             (value, address, section)
│   ├── focus: {...}               (targeted decompilation)
│   ├── xrefs: {...}               (cross-references)
│   └── call_graph_analysis: {...} (nodes, edges, attack chains)
│
├── decompilation_cache: Dict[str, str]   ◄── Ghidra decompiled C code
│
├── r2_analysis_results: Dict      ◄── Radare2 findings (same structure)
│   ├── binary: {...}              (arch, bits, os, imports, sections)
│   ├── functions: {...}
│   ├── strings: {...}
│   ├── focus: {...}
│   ├── xrefs: {...}
│   └── call_graph_analysis: {...}
│
├── r2_decompilation_cache: Dict[str, str]  ◄── R2 decompiled C code
│
├── summary: str                   (LLM-generated report markdown)
├── reasoning_trace: List[str]
├── pending_actions: List[Dict]
├── write_mode_enabled: bool
├── review_approved: bool
└── progress_callback: Optional    (WebSocket callback for real-time updates)
```

---

## Deployment

### Prerequisites

- Docker Engine with `docker compose` v2+
- Host Docker socket accessible (agent uses `docker exec`)
- LLM API key (set in `.env`)

### Quick Start

```bash
# 1. Configure
cp .env.template .env
# Edit .env — set RUNNER_IMAGE, ANTHROPIC_API_KEY, ANTHROPIC_BASE_URL

# 2. Start all services
docker compose up --build -d

# 3. Wait for readiness
docker compose logs -f ghidra     # wait for "Ghidra container ready"
docker compose logs -f radare2    # wait for container start
docker compose logs -f agent      # wait for "Uvicorn running on 0.0.0.0:8080"

# 4. Verify
curl http://localhost:8080/docs   # Swagger UI
```

### Service Startup Order

```
postgres (immediate)
  └─► langfuse (depends on postgres)
ghidra (2-3 min first boot, installs PyGhidra venv)
radare2 (1-3 min first boot — installs r2ghidra + r2dec plugins, then healthcheck passes)
  └─► agent (waits for both: ghidra via depends_on, radare2 via service_healthy condition)
        └─► ui (independent)
```

### Volumes

| Volume | Mount Point | Purpose |
|--------|-------------|---------|
| `ghidra_projects` | `/data/projects` | Ghidra project databases (persistent across restarts) |
| `ghidra_shared` | `/data/shared` | **Shared** binary storage — accessed by ghidra, radare2, qiling, and agent |
| `pgdata` | PostgreSQL data dir | Analysis history persistence |

### Teardown

```bash
docker compose down        # stop services
docker compose down -v     # stop + wipe all data volumes
```

---

## Test Coverage

All tests live in `backend/tests/` — **183 tests, all passing**.

| Test File | Scope |
|-----------|-------|
| `test_r2_runner.py` | `Radare2Runner` — command execution, JSON parsing, timeout, POSIX path translation |
| `test_r2_tools.py` | R2 `@tool` functions — analyze, list, decompile (fallback chain), strings, xrefs, disasm |
| `test_r2_graph.py` | R2 pipeline — discovery, auto-decompile, focus, cross-reference |
| `test_api.py` | API endpoints — dual-analyzer listing, detail, 404s, status, HTML/text/PDF export |
| `test_e2e.py` | E2E pipeline flow, R2 failure isolation, ui_adapter, state integrity, prompts, config |
| `test_call_graph_analyzer.py` | Call graph attack chain building |
| `test_function_priority.py` | Function ranking and library detection |
| `test_chargen_e2e.py` | Chargen binary end-to-end test |
| `test_qiling_runner.py` | QilingRunner — emulation, container exec, timeout handling |
| `test_qiling_tools.py` | Qiling `@tool` functions — emulate, trace API, syscalls, evasion |
| `test_qiling_graph.py` | Qiling pipeline stages |
| `test_ioc_verdict_qiling.py` | IOC verdict with Qiling dynamic data |

Run tests:
```bash
cd backend
pip install -e .
python -m pytest tests/ -v
```

---

## Key Design Decisions

1. **Parallel execution** — Ghidra, R2, and Qiling run concurrently via `asyncio.gather()`, maximising discovery throughput.

2. **Separate state fields** — Each tool writes to its own state keys (`analysis_results` vs `r2_analysis_results` vs `qiling_results`), eliminating race conditions.

3. **Engine failure isolation** — If R2 or Qiling crashes or times out, the pipeline continues with available results. The `_safe_r2()` and `_safe_qiling()` wrappers catch all exceptions.

4. **Docker exec pattern** — The agent uses `docker exec` to send commands to sibling containers, keeping it lightweight and allowing independent tool upgrades.

5. **Shared volume** — All four containers (agent, ghidra, radare2, qiling) mount the same `ghidra_shared` volume, avoiding binary copies.

6. **Decompiler fallback** — R2 tries three decompilers: `pdg` (r2ghidra) → `pdd` (r2dec) → `pdf` (disassembly), auto-detected at runtime.

7. **Function priority scoring** — Functions are ranked by a composite score combining xref count, size, API call detection, and suspicious string references, with library function penalties.

8. **Attack chain analysis** — Call graphs are traced from entry points to suspicious sinks (execution, network, file I/O, crypto, recon, timing) to identify potential malicious behaviour paths.

9. **Dual report templates** — The HTML report uses a dark-themed interactive template (Tailwind CDN). The PDF uses a completely separate white-background, inline-CSS template designed for deterministic A4 rendering.

10. **PostgreSQL persistence** — Completed analyses are stored in PostgreSQL with full binary metadata, enabling cross-binary search (functions, strings, IOCs) and session restore.

11. **Auto-install & healthcheck** — R2 decompiler plugins install automatically on container start. A Docker healthcheck ensures the agent waits until plugins are compiled.

12. **Retry logic** — `Radare2Runner.run_command()` retries up to 2 times on transient errors with a 1.5s delay. Permanent errors abort immediately.

13. **JWT auth + RBAC** — All routes gated with `Depends(get_current_user)`. Three roles (admin/user/guest) with different permission levels. Multitenancy ensures data isolation between users.

14. **Per-user quotas** — Configurable analysis limits prevent resource abuse. Enforced at upload time. Admins get unlimited by default.
