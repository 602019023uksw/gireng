# gireng — Ghidra and Radare Intelligent Reverse Engineering

> Dual-engine AI-powered binary analysis platform — **Ghidra + Radare2** orchestrated via LangGraph, with LLM-driven malware assessment, MITRE ATT&CK mapping, IOC extraction, and professional PDF/HTML reporting.

```
 ┌─────────────────────────────────────────────────────────────────────────────────┐
 │              gireng — Ghidra and Radare Intelligent Reverse Engineering          │
 └─────────────────────────────────────────────────────────────────────────────────┘

    ┌──────────────┐         upload binary          ┌──────────────────────────┐
    │              │  ─────────────────────────────► │                          │
    │   Browser    │         stream results          │   FastAPI Agent :8080    │
    │   UI :4173   │  ◄───────────────────────────── │   (LangGraph Pipeline)   │
    │   (React)    │         REST / WebSocket         │                          │
    └──────────────┘                                 └────────────┬─────────────┘
                                                                  │
                                                     ┌────────────┴────────────┐
                                                     │    LangGraph Pipeline    │
                                                     │                         │
                                                     │  1. parse_intent        │
                                                     │  2. initialize          │
                                                     │  3. discovery ──┐       │
                                                     │     (parallel)  │       │
                                                     │  ┌──────────────┤       │
                                                     │  │              │       │
                                                     │  ▼              ▼       │
                                                     │ ┌─────────┐ ┌────────┐ │
                                                     │ │ Ghidra  │ │Radare2 │ │
                                                     │ │ Agent   │ │ Agent  │ │
                                                     │ └────┬────┘ └───┬────┘ │
                                                     │      │          │      │
                                                     │      └────┬─────┘      │
                                                     │           ▼            │
                                                     │  4. focus_analysis     │
                                                     │  5. cross_reference    │
                                                     │  6. synthesize (LLM)   │
                                                     │  7. report ──► PDF/HTML│
                                                     └─────────────────────────┘
                                                                  │
                                       ┌──────────────────────────┼──────────────────────────┐
                                       │                          │                          │
                              docker exec                docker exec              shared volume
                                       │                          │              /data/shared
                                       ▼                          ▼                          │
                              ┌─────────────────┐      ┌──────────────────┐                  │
                              │  Ghidra         │      │  Radare2         │                  │
                              │  Container      │      │  Container       │                  │
                              │                 │      │                  │                  │
                              │  • PyGhidra     │      │  • r2ghidra      │                  │
                              │  • Decompiler   │ ◄──► │  • r2dec         │ ◄────────────────┘
                              │  • 11 scripts   │      │  • 7 tools       │
                              └─────────────────┘      └──────────────────┘

 ┌─────────────────────────────────────────────────────────────────────────────────┐
 │  Supporting Services                                                            │
 │                                                                                 │
 │    ┌─────────────┐      ┌──────────────────┐                                    │
 │    │  PostgreSQL  │      │  Langfuse :3100   │                                   │
 │    │  :5432       │ ───► │  LLM Tracing &    │                                   │
 │    │  (App + LF)  │      │  Observability    │                                   │
 │    └─────────────┘      └──────────────────┘                                    │
 └─────────────────────────────────────────────────────────────────────────────────┘
```

## Features

- **Dual-engine analysis** — Ghidra and Radare2 run in parallel via `asyncio.gather()`
- **LLM-powered synthesis** — Cross-references findings from both tools for comprehensive malware assessment
- **MITRE ATT&CK mapping** — Automatically maps observed behaviours to ATT&CK techniques
- **IOC extraction** — IPs, URLs, domains, file paths, emails, registry keys, mutexes, crypto materials
- **Call graph analysis** — Builds attack chains from entry points to suspicious sinks
- **Function priority scoring** — Ranks functions by xref count, size, API calls, and suspicious strings
- **Professional reports** — Export as interactive HTML, A4 PDF (Playwright), or plain text
- **Analysis history** — PostgreSQL-backed persistence with full-text search across binaries
- **Real-time streaming** — WebSocket events for live analysis progress
- **React UI** — Modern dark-themed SPA with chat interface, code viewer, and analysis dashboard

## How It Works

```
  Upload ELF/PE ──► Copy to shared volume ──► Run LangGraph pipeline
        │
        ▼
  ┌─────────┐    ┌──────────┐    ┌───────────────────────────────────┐
  │ parse   │───►│ init     │───►│ discovery (asyncio.gather)        │
  │ intent  │    │          │    │                                   │
  └─────────┘    └──────────┘    │  ┌─────────────┐ ┌─────────────┐ │
                                 │  │ Ghidra      │ │ Radare2     │ │
                                 │  │ • functions │ │ • functions │ │
                                 │  │ • strings   │ │ • strings   │ │
                                 │  │ • xrefs     │ │ • imports   │ │
                                 │  │ • decompile │ │ • decompile │ │
                                 │  │ • call graph│ │ • call graph│ │
                                 │  └─────────────┘ └─────────────┘ │
                                 └──────────────┬────────────────────┘
                                                │
        ┌───────────────────────────────────────┘
        ▼
  ┌───────────┐    ┌───────────────┐    ┌─────────────┐    ┌─────────┐
  │ focus     │───►│ cross         │───►│ synthesize  │───►│ report  │
  │ analysis  │    │ reference     │    │ (LLM)       │    │         │
  │           │    │               │    │             │    │ HTML    │
  │ Deep-dive │    │ Correlate     │    │ Threat      │    │ PDF     │
  │ priority  │    │ Ghidra + R2   │    │ assessment  │    │ Text    │
  │ functions │    │ findings      │    │ MITRE map   │    │         │
  └───────────┘    └───────────────┘    └─────────────┘    └─────────┘
```

## Quick Start

### Prerequisites

- **Docker Engine** (with Docker Compose v2)
- **Docker socket** accessible (`/var/run/docker.sock`)
- **LLM API Key** (Anthropic, OpenAI-compatible, or ZhipuAI)

### 1. Clone & Configure

```bash
git clone https://github.com/danilchristianto/gireng.git
cd gireng

# Copy env template and set your API key
cp .env.template .env
```

Edit `.env` and set your LLM API key:

```dotenv
ANTHROPIC_API_KEY=your-api-key-here
```

Optional: set host/port placeholders so URLs stay aligned:

```dotenv
HOST=localhost
API_PORT=8080
UI_PORT=4173
LANGFUSE_PORT=3100
```

### 2. Build & Start

```bash
# Start all services (first run builds containers ~5 min)
docker compose up --build -d

# Check all services are healthy
docker compose ps
```

### 3. Use

Open **http://localhost:4173** in your browser, upload a binary, and start analyzing.

Or use the API directly:

```bash
# Upload a binary for analysis
curl -X POST http://localhost:8080/analyze/upload \
  -F "file=@/path/to/binary"

# Poll analysis status
curl http://localhost:8080/status/{session_id}

# Query the agent about the binary
curl -X POST http://localhost:8080/query \
  -H "Content-Type: application/json" \
  -d '{"session_id": "SESSION_ID", "query": "What does the main function do?"}'
```

Or use the included helper script:

```bash
python analyze.py sample-binary/chargen
```

## Architecture

```
 ┌────────────────────────────────────────────────────────────┐
 │                     Docker Services (6)                    │
 ├────────────┬──────────────────────────┬────────┬───────────┤
 │  Service   │  Image                   │  Port  │  Purpose  │
 ├────────────┼──────────────────────────┼────────┼───────────┤
 │  ui        │  app/Dockerfile.ui       │  4173  │  React UI │
 │  agent     │  backend/Dockerfile      │  8080  │  FastAPI  │
 │  ghidra    │  danilid/ireng-runner    │  ----  │  Ghidra   │
 │  radare2   │  radare/radare2          │  ----  │  Radare2  │
 │  postgres  │  postgres:16-alpine      │  ----  │  Database │
 │  langfuse  │  langfuse/langfuse:2     │  3100  │  Tracing  │
 └────────────┴──────────────────────────┴────────┴───────────┘
```

### Key Components

| Component | Location | Description |
|-----------|----------|-------------|
| **Agent Core** | `backend/src/ghidra_agent/` | LangGraph pipeline, LLM orchestration (22 modules) |
| **Ghidra Tools** | `backend/src/ghidra_agent/tools.py` | 10 Ghidra tool functions |
| **Radare2 Tools** | `backend/src/ghidra_agent/r2_tools.py` | 7 Radare2 tool functions |
| **Ghidra Scripts** | `backend/ghidra_scripts/` | 11 PyGhidra headless scripts |
| **Call Graph** | `backend/src/ghidra_agent/call_graph_analyzer.py` | Attack chain discovery |
| **IOC Extractor** | `backend/src/ghidra_agent/ioc_extractor.py` | Multi-type IOC extraction |
| **Function Priority** | `backend/src/ghidra_agent/function_priority.py` | Smart function ranking |
| **Reporting** | `backend/src/ghidra_agent/reporting.py` | HTML, PDF (Playwright), text reports |
| **API Layer** | `backend/src/ghidra_agent/api/main.py` | 38 REST + WebSocket endpoints |
| **Database** | `backend/src/ghidra_agent/database.py` | PostgreSQL persistence layer |
| **Frontend** | `app/src/` | React 19 + TypeScript SPA |

### Project Structure

```
gireng/
├── .env.template          # Environment config template
├── docker-compose.yml     # All 6 services
├── analyze.py             # CLI helper: upload + poll
├── run.py                 # Docker management script
├── init-multi-db.sh       # PostgreSQL multi-DB init
├── ARCHITECTURE.md        # Detailed architecture docs
├── DEPLOY.md              # Deployment & API guide
├── tech-spec.md           # Frontend tech spec
│
├── backend/
│   ├── Dockerfile         # Agent image (includes Playwright/Chromium)
│   ├── pyproject.toml
│   ├── ghidra_scripts/    # 11 PyGhidra headless scripts
│   └── src/ghidra_agent/  # Python package (22 modules)
│       ├── api/main.py    #   FastAPI app (38 endpoints)
│       ├── graph.py       #   LangGraph pipeline
│       ├── tools.py       #   Ghidra @tool functions
│       ├── r2_tools.py    #   Radare2 @tool functions
│       ├── r2_graph.py    #   R2 pipeline stages
│       ├── llm.py         #   LiteLLM wrapper
│       ├── sessions.py    #   Session management
│       ├── database.py    #   PostgreSQL persistence
│       ├── reporting.py   #   HTML/PDF/text reports
│       ├── ioc_extractor.py    # IOC extraction
│       ├── call_graph_analyzer.py  # Attack chains
│       ├── function_priority.py    # Function ranking
│       ├── storage.py     #   Analysis history storage
│       ├── ghidra/        #   GhidraHeadlessRunner
│       ├── radare/        #   Radare2Runner
│       └── ...
│
├── app/
│   ├── Dockerfile.ui
│   ├── package.json
│   └── src/
│       ├── App.tsx
│       ├── components/    # ~30 custom + ~50 shadcn/ui components
│       ├── agents/        # Agent configs (ghidra, radare)
│       ├── hooks/
│       ├── lib/           # API client, utilities
│       └── types/
│
└── tests/                 # 183 tests
```

## API Endpoints

### Core Analysis

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/analyze/upload` | Upload binary for analysis |
| `POST` | `/analyze` | Analyze binary already in shared volume |
| `GET` | `/status/{session_id}` | Poll analysis status |
| `POST` | `/query` | Query the agent about a binary |
| `WS` | `/stream/{session_id}` | Real-time analysis stream |
| `GET` | `/health` | Service health check |

### Results & Reports

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/analysis/{hash}/analyzers` | List Ghidra + R2 results |
| `GET` | `/api/analysis/{hash}/files` | Decompiled file tree |
| `GET` | `/api/analysis/{hash}/reports` | Report list |
| `GET` | `/api/analysis/{hash}/export/html` | Export full HTML report |
| `GET` | `/api/analysis/{hash}/export/pdf` | Export professional A4 PDF |
| `GET` | `/api/analysis/{hash}/export/text` | Export plain text report |

### Analysis History & Cross-Binary Search

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/history` | List past analyses (paginated, filterable) |
| `POST` | `/api/history/{session_id}/restore` | Restore past session into memory |
| `DELETE` | `/api/history/{session_id}` | Delete past analysis |
| `GET` | `/api/query/functions` | Search functions across all binaries |
| `GET` | `/api/query/strings` | Full-text string search |
| `GET` | `/api/query/iocs` | Search IOCs across all binaries |

See [DEPLOY.md](DEPLOY.md) for full API documentation (38 endpoints) and examples.

## Report Formats

| Format | Description |
|--------|-------------|
| **HTML** | Interactive dark-themed report with MITRE cards, code evidence, call graphs |
| **PDF** | Professional white-background A4 report (Playwright/Chromium), 13 numbered sections |
| **Text** | Plain text report for scripting and archival |

### PDF Report Sections

1. Executive Summary
2. Binary Information
3. Threat Intel & MITRE ATT&CK
4. Malware Capabilities
5. Technical Analysis
6. Functions Analysis
7. Evidence of Malicious Activity
8. Code Evidence (Suspicious API Calls)
9. Operational Flow
10. Call Graph & Attack Chains
11. Indicators of Compromise (IOCs)
12. Recommendations
13. Conclusion

## Development

### Backend (Python)

```bash
cd backend
pip install -e .
python -m pytest tests/ -v    # 183 tests
```

### Frontend (React)

```bash
cd app
npm install
npm run dev      # Dev server at :5173
npm run build    # Production build
```

## Troubleshooting

| Issue | Fix |
|-------|-----|
| Ghidra container unhealthy | Wait ~60s for PyGhidra venv setup, check `docker logs gireng-ghidra-1` |
| R2 plugins missing | R2 auto-installs r2ghidra/r2dec on first start; check `docker logs gireng-radare2-1` |
| LLM errors | Verify `ANTHROPIC_API_KEY` and `ANTHROPIC_BASE_URL` in `.env` |
| Agent can't reach containers | Ensure Docker socket is mounted (`/var/run/docker.sock`) |
| Port conflict | Set `API_PORT`, `UI_PORT`, or `LANGFUSE_PORT` in `.env` |
| PDF export fails | Playwright + Chromium are installed in the agent Docker image |

## License

MIT License
