# Integration Architecture — Dual-Agent Binary Analysis Platform

## Overview

gireng (Ghidra and Radare Intelligent Reverse Engineering) is an AI-powered reverse engineering platform that analyses binaries using **two parallel reverse-engineering backends** — **Ghidra** and **Radare2** — then synthesises their findings via an LLM to produce a comprehensive malware report.

```
┌──────────────┐    HTTP / WS     ┌──────────────────────────────┐
│  Frontend UI │ ◄──────────────► │  FastAPI Agent  (port 8080)  │
│  Vite :4173  │                  │  api/main.py                 │
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
```

---

## Docker Services

| Service | Image | Purpose | Port |
|---------|-------|---------|------|
| `ghidra` | `${RUNNER_IMAGE}` (gireng-runner) | Headless Ghidra with PyGhidra. Runs analysis scripts via `docker exec`. | internal |
| `radare2` | `radare/radare2:latest` | Headless Radare2. Runs r2 commands via `docker exec`. | internal |
| `agent` | Built from `backend/Dockerfile` | FastAPI backend. Orchestrates both tools, calls LLM, serves API. | **8080** |
| `ui` | Built from `app/Dockerfile.ui` | Vite/React frontend. | **4173** |

All containers share a Docker volume `ghidra_shared` mounted at `/data/shared`. Binaries are placed here on upload so both Ghidra and R2 can access them.

The `agent` container mounts the host Docker socket (`/var/run/docker.sock`) to issue `docker exec` commands into the sibling Ghidra and R2 containers.

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
    _ghidra_discovery(state),   # Ghidra: analyze → functions → strings → auto-decompile
    _safe_r2(state),            # R2:     analyze → functions → strings → auto-decompile
)
```

Each pipeline writes to **separate state fields** to avoid race conditions:

| Data | Ghidra field | R2 field |
|------|-------------|----------|
| Binary info, functions, strings | `analysis_results` | `r2_analysis_results` |
| Decompiled code | `decompilation_cache` | `r2_decompilation_cache` |

**R2 failure does not block Ghidra.** The `_safe_r2` wrapper catches all exceptions and logs them; the pipeline continues with Ghidra-only results.

#### Auto-decompilation
Both pipelines automatically decompile the **top 15 functions** ranked by cross-reference count + code size, plus the entry-point function. This ensures the LLM has substantial code context without manual intervention.

#### `focus_analysis`
If the user query targets a specific function or address, this stage decompiles/disassembles it. Falls back through: decompilation → disassembly.

#### `cross_reference`
Finds cross-references to/from the target address using both tools.

#### `synthesize`
Builds a massive context block from **both** Ghidra and R2 results:
- Architecture, binary metadata from both tools
- Merged function lists
- All decompiled code (Ghidra + R2)
- Strings and IOCs
- Cross-reference data

Sends the context + `SYSTEM_PROMPT` to the LLM, which produces a structured 11-section malware report.

### 3. Results & Reporting

```
Client → GET /status/{session_id}           → full state
Client → GET /api/analysis/{hash}/analyzers → [{ghidra}, {radare2}]
Client → GET /api/analysis/{hash}/reports   → HTML malware report
Client → WS /stream/{session_id}            → real-time events
```

---

## Module Map

### Core Pipeline

| Module | File | Responsibility |
|--------|------|----------------|
| **State** | `state.py` | `AgentState` TypedDict — all analysis data, dual R2/Ghidra fields |
| **Graph** | `graph.py` | LangGraph StateGraph — pipeline orchestration, parallel discovery |
| **LLM** | `llm.py` | LiteLLM `acompletion` wrapper for LLM calls |
| **Prompts** | `prompts.py` | System prompt (dual-agent aware), focused analysis prompt |
| **Sessions** | `sessions.py` | In-memory session store, `run_graph()` entry point |
| **Config** | `config.py` | Pydantic `Settings` — all env vars for Ghidra, R2, LLM |

### Ghidra Integration

| Module | File | Responsibility |
|--------|------|----------------|
| **Tools** | `tools.py` | `@tool` functions — `analyze_binary_structure`, `list_functions`, `decompile_function`, `find_strings`, `find_xrefs`, `disassemble_at`, `search_bytes`, `get_function_graph`, `rename_symbol`, `add_comment` |
| **Runner** | `ghidra/runner.py` | `GhidraHeadlessRunner` — `docker exec` into `ghidra_headless` container, runs PyGhidra scripts, JSON I/O, retry logic |
| **Scripts** | `ghidra_scripts/*.py` | Python scripts executed inside Ghidra's PyGhidra env |

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

### API Layer

| Module | File | Responsibility |
|--------|------|----------------|
| **API** | `api/main.py` | FastAPI app — REST endpoints + WebSocket streaming |
| **UI Adapter** | `ui_adapter.py` | Builds structured JSON for `/analyzers` — dual-analyzer details, file tree, reports |
| **Reporting** | `reporting.py` | Markdown→HTML report generator, section splitting, professional CSS |
| **IOC Extractor** | `ioc_extractor.py` | Regex-based extraction of IPs, URLs, domains, hashes, file paths from analysis results |
| **Models** | `models.py` | Pydantic request/response schemas for all endpoints |

### Frontend

| Module | File | Responsibility |
|--------|------|----------------|
| **Ghidra Agent** | `agents/ghidra-agent.ts` | Agent definition, capabilities list, agent registry |
| **Radare Agent** | `agents/radare-agent.ts` | R2 agent definition with R2-specific capabilities |

---

## API Endpoints

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
| `GET` | `/api/analysis/{hash}/analyzers` | List analyzers — returns `[ghidra, radare2]` when R2 data exists |
| `GET` | `/api/analysis/{hash}/analyzers/{id}` | Analyzer details (accepts `ghidra` or `radare2`) |
| `GET` | `/api/analysis/{hash}/files` | Decompiled file tree |
| `GET` | `/api/analysis/{hash}/files/{id}` | Decompiled function code |
| `GET` | `/api/analysis/{hash}/reports` | Report list |
| `GET` | `/api/analysis/{hash}/reports/{id}` | Report HTML content |
| `GET` | `/api/analysis/{hash}/export/html` | Export full report as HTML |
| `GET` | `/api/analysis/{hash}/export/text` | Export report as plain text |
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
docker compose logs -f radare2    # wait for container start (instant)
docker compose logs -f agent      # wait for "Uvicorn running on 0.0.0.0:8080"

# 4. Verify
curl http://localhost:8080/docs   # Swagger UI
```

### Service Startup Order

```
ghidra (2-3 min first boot, installs PyGhidra venv)
radare2 (1-3 min first boot — installs r2ghidra + r2dec plugins, then healthcheck passes)
  └─► agent (waits for both: ghidra via depends_on, radare2 via service_healthy condition)
        └─► ui (independent)
```

### Health Endpoint

The agent exposes `GET /health` returning the status of both backends:

```json
{
  "status": "ok",
  "ghidra": { "ready": true },
  "radare2": { "ready": true, "container": true, "decompilers": ["pdg", "pdd", "pdf"] }
}
```

At startup, the agent performs a best-effort R2 container verification (non-blocking).

### Volumes

| Volume | Mount Point | Purpose |
|--------|-------------|---------|
| `ghidra_projects` | `/data/projects` | Ghidra project databases (persistent across restarts) |
| `ghidra_shared` | `/data/shared` | **Shared** binary storage — accessed by ghidra, radare2, and agent |
| `r2_plugins` | `/root/.local/share/radare2/plugins` | R2 compiled plugins — persistent so r2ghidra/r2dec don't recompile on restart |

### R2 Decompiler Plugins (Auto-installed)

The R2 container entrypoint **automatically installs** `r2ghidra` and `r2dec` plugins at startup using `r2pm -Ui`. A persistent Docker volume (`r2_plugins`) caches the installed plugins across container restarts.

The container uses a **healthcheck** (`cat /tmp/.r2_ready`) that only passes after plugin installation completes. The agent service has `depends_on: radare2: condition: service_healthy`, ensuring analysis doesn't start until R2 is fully ready.

```yaml
# docker-compose.yml (radare2 service)
entrypoint: |
  r2pm -Ui r2ghidra || echo "non-fatal"
  r2pm -Ui r2dec   || echo "non-fatal"
  touch /tmp/.r2_ready
  tail -f /dev/null
healthcheck:
  test: ["CMD", "cat", "/tmp/.r2_ready"]
  interval: 10s
  start_period: 120s    # allow time for plugin compilation
  retries: 30
restart: unless-stopped
```

The runner's `detect_decompilers()` method **probes** which decompiler commands are actually available at runtime, so the fallback chain adapts automatically.

Without these plugins, R2 falls back to `pdf` (raw disassembly).

### Teardown

```bash
docker compose down        # stop services
docker compose down -v     # stop + wipe all data volumes
```

---

## State Schema

The `AgentState` is a Python `TypedDict` that flows through every pipeline node:

```
AgentState
├── session_id: str
├── binary_path: str
├── program_hash: str              (SHA-256)
├── user_query: str
├── intent: str                    (reconnaissance|vulnerability|malware|protocol)
├── status: str                    (initialized|completed|error)
│
├── current_function: Optional[str]
├── current_address: Optional[str]
│
├── analysis_results: Dict         ◄── Ghidra findings
│   ├── binary: {...}              (arch, compiler, entry points, segments)
│   ├── functions: {...}           (name, address, size, xrefs)
│   ├── strings: {...}             (value, address, section)
│   ├── focus: {...}               (targeted decompilation)
│   └── xrefs: {...}               (cross-references)
│
├── decompilation_cache: Dict[str, str]   ◄── Ghidra decompiled C code
│
├── r2_analysis_results: Dict      ◄── Radare2 findings (same structure)
│   ├── binary: {...}              (arch, bits, os, imports, sections)
│   ├── functions: {...}
│   ├── strings: {...}
│   ├── focus: {...}
│   └── xrefs: {...}
│
├── r2_decompilation_cache: Dict[str, str]  ◄── R2 decompiled C code
│
├── summary: str                   (LLM-generated report markdown)
├── reasoning_trace: List[str]
├── pending_actions: List[Dict]
├── write_mode_enabled: bool
└── review_approved: bool
```

---

## Test Coverage

All tests live in `backend/tests/` — **53 tests, all passing**.

| Test File | Count | Scope |
|-----------|-------|-------|
| `test_r2_runner.py` | 12 | `Radare2Runner` — command execution, JSON parsing, timeout, POSIX path translation |
| `test_r2_tools.py` | 11 | R2 `@tool` functions — analyze, list, decompile (fallback chain), strings, xrefs, disasm |
| `test_r2_graph.py` | 10 | R2 pipeline — discovery, auto-decompile, focus, cross-reference |
| `test_api.py` | 9 | API endpoints — dual-analyzer listing, detail, 404s, status, HTML/text export |
| `test_e2e.py` | 11 | E2E pipeline flow, R2 failure isolation, ui_adapter, state integrity, prompts, config |

Run tests:
```bash
cd backend
pip install ".[test]"
PYTHONPATH=src pytest tests/ -v
```

---

## Key Design Decisions

1. **Parallel execution** — Ghidra and R2 run concurrently via `asyncio.gather()`, roughly halving discovery time for binaries.

2. **Separate state fields** — Each tool writes to its own state keys (`analysis_results` vs `r2_analysis_results`), eliminating race conditions during parallel execution.

3. **R2 failure isolation** — If R2 crashes or times out, the pipeline continues with Ghidra-only results. The `_safe_r2()` wrapper catches all exceptions.

4. **Docker exec pattern** — Instead of embedding Ghidra/R2 libraries in the agent process, the agent uses `docker exec` to send commands to sibling containers. This keeps the agent lightweight and allows independent tool upgrades.

5. **Shared volume** — All three containers (agent, ghidra, radare2) mount the same `ghidra_shared` volume at `/data/shared`, avoiding binary copies.

6. **Decompiler fallback** — R2 tries three decompilers in order: `pdg` (r2ghidra) → `pdd` (r2dec) → `pdf` (raw disassembly), maximising coverage even with minimal plugin installs. The available decompilers are **auto-detected** at runtime by probing each command.

7. **Dual-agent LLM prompt** — The system prompt explicitly instructs the LLM to cross-reference findings from both tools and note discrepancies.

8. **Auto-install & healthcheck** — R2 decompiler plugins install automatically on container start via `r2pm`. A Docker healthcheck ensures the agent doesn't send commands until plugins are compiled. Plugin binaries persist across restarts via a dedicated volume.

9. **Retry logic** — `Radare2Runner.run_command()` retries up to 2 times on transient errors (timeouts, subprocess exceptions) with a 1.5s delay. Permanent errors (non-zero exit codes) abort immediately.

10. **Container pre-flight** — Before running the R2 pipeline in `discovery()`, the runner verifies the container is reachable (`r2 -q -v`). If down, R2 is skipped gracefully with a trace entry.
