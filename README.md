# gireng — Ghidra and Radare Intelligent Reverse Engineering

> Dual-agent reverse engineering powered by **Ghidra + Radare2**, orchestrated by LLM via LangGraph.

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
                                                     │  7. report ──► HTML    │
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

## How It Works

```
 ┌─────────────────────────────────────────────────────────────────────┐
 │                    Analysis Pipeline Flow                           │
 └─────────────────────────────────────────────────────────────────────┘

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
  ┌───────────┐    ┌───────────────┐    ┌─────────────┐    ┌────────┐
  │ focus     │───►│ cross         │───►│ synthesize  │───►│ report │
  │ analysis  │    │ reference     │    │ (LLM)       │    │ (HTML) │
  │           │    │               │    │             │    │        │
  │ Deep-dive │    │ Correlate     │    │ Threat      │    │ Full   │
  │ priority  │    │ Ghidra + R2   │    │ assessment  │    │ malware│
  │ functions │    │ findings      │    │ & summary   │    │ report │
  └───────────┘    └───────────────┘    └─────────────┘    └────────┘
```

## Quick Start

### Prerequisites

- **Docker Engine** (with Docker Compose v2)
- **Docker socket** accessible (`/var/run/docker.sock`)
- **LLM API Key** (Anthropic, OpenAI-compatible, or ZhipuAI)

### 1. Clone & Configure

```bash
git clone https://github.com/your-org/gireng.git
cd gireng

# Copy env template and set your API key
cp .env.template .env
```

Edit `.env` and set your LLM API key:

```dotenv
ANTHROPIC_API_KEY=your-api-key-here
```

### 2. Build & Start

```bash
# Start all services (first run builds containers ~5 min)
docker compose up --build -d

# Check all services are healthy
docker compose ps
```

### 3. Use

Open **http://localhost:4173** in your browser, upload a binary, and start analyzing!

Or use the API directly:

```bash
# Upload a binary for analysis
curl -X POST http://localhost:8080/analyze/upload \
  -F "file=@/path/to/binary"

# Poll analysis status
curl http://localhost:8080/status/{session_id}

# Chat with the agent about the binary
curl -X POST http://localhost:8080/chat/{session_id} \
  -H "Content-Type: application/json" \
  -d '{"message": "What does the main function do?"}'
```

Or use the included helper script:

```bash
python analyze.py sample-binary/chargen
```

## Architecture

```
 ┌────────────────────────────────────────────────────────────┐
 │                     Docker Services                        │
 ├────────────┬──────────────────────┬────────┬───────────────┤
 │  Service   │  Image               │  Port  │  Purpose      │
 ├────────────┼──────────────────────┼────────┼───────────────┤
 │  ui        │  app/Dockerfile.ui   │  4173  │  React SPA    │
 │  agent     │  backend/Dockerfile  │  8080  │  FastAPI + LG │
 │  ghidra    │  gireng-runner       │  ----  │  Ghidra RE    │
 │  radare2   │  radare/radare2      │  ----  │  Radare2 RE   │
 │  postgres  │  postgres:16-alpine  │  ----  │  Database     │
 │  langfuse  │  langfuse/langfuse:2 │  3100  │  LLM Tracing  │
 └────────────┴──────────────────────┴────────┴───────────────┘
```

### Key Components

| Component | Location | Description |
|-----------|----------|-------------|
| **Agent Core** | `backend/src/ghidra_agent/` | LangGraph pipeline, LLM orchestration |
| **Ghidra Tools** | `backend/src/ghidra_agent/tools.py` | 10 Ghidra tool functions |
| **Radare2 Tools** | `backend/src/ghidra_agent/r2_tools.py` | 7 Radare2 tool functions |
| **Ghidra Scripts** | `backend/ghidra_scripts/` | 11 PyGhidra scripts |
| **API Layer** | `backend/src/ghidra_agent/api/main.py` | REST + WebSocket endpoints |
| **Frontend** | `app/src/` | React + TypeScript SPA |

### Project Structure

```
gireng/
├── .env.template          # Environment config template
├── docker-compose.yml     # All 6 services
├── analyze.py             # CLI helper: upload + poll
├── init-multi-db.sh       # PostgreSQL multi-DB init
├── ARCHITECTURE.md        # Detailed architecture docs
├── DEPLOY.md              # Deployment & API guide
├── tech-spec.md           # Frontend tech spec
│
├── backend/
│   ├── Dockerfile
│   ├── pyproject.toml
│   ├── ghidra_scripts/    # PyGhidra headless scripts
│   ├── src/ghidra_agent/  # Python package
│   │   ├── api/main.py    #   FastAPI app
│   │   ├── graph.py       #   LangGraph pipeline
│   │   ├── tools.py       #   Ghidra @tool functions
│   │   ├── r2_tools.py    #   Radare2 @tool functions
│   │   ├── llm.py         #   LiteLLM wrapper
│   │   ├── sessions.py    #   Session management
│   │   ├── reporting.py   #   HTML report generator
│   │   └── ...
│   └── tests/             # 53 tests
│
└── app/
    ├── Dockerfile.ui
    ├── package.json
    └── src/
        ├── App.tsx
        ├── components/    # React UI components
        ├── agents/        # Frontend agent configs
        ├── hooks/
        ├── lib/
        └── types/
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/analyze/upload` | Upload binary for analysis |
| `GET` | `/status/{session_id}` | Poll analysis status |
| `POST` | `/chat/{session_id}` | Chat with the agent |
| `GET` | `/api/analysis/{hash}/analyzers` | Get Ghidra + R2 results |
| `WS` | `/stream/{session_id}` | Real-time analysis stream |
| `GET` | `/health` | Service health check |

See [DEPLOY.md](DEPLOY.md) for full API documentation and examples.

## Development

### Backend (Python)

```bash
cd backend
pip install -e ".[cli]"
pytest tests/ -v
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
| Ghidra container unhealthy | Wait ~60s for PyGhidra venv setup, check `docker logs ghidra_headless` |
| R2 plugins missing | R2 auto-installs r2ghidra/r2dec on first start; check `docker logs radare2` |
| LLM errors | Verify `ANTHROPIC_API_KEY` is set in `.env` |
| Agent can't reach containers | Ensure Docker socket is mounted (`/var/run/docker.sock`) |
| Port conflict | Change ports in `docker-compose.yml` |

## License

MIT License
