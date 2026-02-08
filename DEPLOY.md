# Deploy & Run the Backend

## 1. Prerequisites

- Docker Engine (with `docker compose` v2+)
- The host Docker socket must be accessible (the agent spawns Ghidra containers via `docker run`)

## 2. Configure environment

```bash
cp .env.template .env
```

Edit `.env`:

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `RUNNER_IMAGE` | yes | Ghidra runner Docker image | `danilid/ireng-runner:2.0.1` |
| `ANTHROPIC_API_KEY` | yes | LLM API key | `08d226c7...` |
| `ANTHROPIC_BASE_URL` | yes | LLM endpoint | `https://api.z.ai/api/anthropic` |
| `ANTHROPIC_MODEL` | no | Model name (default `glm-4.7`) | `GLM-4.7` |

## 3. Start the backend

From the repo root:

```bash
docker compose up --build -d ghidra agent
```

This starts two services:

| Service | What it does | Port |
|---------|-------------|------|
| `ghidra` | Headless Ghidra runner (PyGhidra). First boot installs python venv and initializes PyGhidra -- takes a few minutes. | (internal) |
| `agent` | FastAPI backend. Waits for `ghidra` via `depends_on`. | **8080** |

Check startup progress:

```bash
docker compose logs -f ghidra   # wait until "tail -f /dev/null" appears (ready)
docker compose logs -f agent    # wait until "Uvicorn running on 0.0.0.0:8080"
```

Verify the backend is alive:

```bash
curl http://localhost:8080/docs
```

## 4. Upload a binary and start reverse engineering

The full workflow is: **upload** -> **poll status** -> **query** -> **poll status** -> **read results**.

### 4.1 Upload a binary

```bash
curl -X POST http://localhost:8080/analyze/upload \
  -F "file=@./sample-binary/chargen"
```

Response:

```json
{"session_id": "a1b2c3d4-..."}
```

Save the `session_id` -- you need it for every subsequent call.

Or, if the binary is already inside the shared volume (`/data/shared`):

```bash
curl -X POST http://localhost:8080/analyze \
  -H "Content-Type: application/json" \
  -d '{"binary_path": "/data/shared/chargen"}'
```

### 4.2 Check analysis status

```bash
curl http://localhost:8080/status/{session_id}
```

Response:

```json
{
  "session_id": "a1b2c3d4-...",
  "status": "completed",
  "state": { ... }
}
```

Status values: `initialized` -> `completed` (or `error` if something failed).

### 4.3 Ask a question (query the agent)

Once analysis is complete, send a natural-language query:

```bash
curl -X POST http://localhost:8080/query \
  -H "Content-Type: application/json" \
  -d '{"session_id": "a1b2c3d4-...", "query": "Find potential buffer overflow vulnerabilities"}'
```

This re-runs the analysis graph with your query, focusing on the intent you described. Poll `/status/{session_id}` again to get the updated results.

### 4.4 Enable write mode (rename symbols, add comments)

Write mode lets the agent modify the Ghidra project (rename functions, add comments):

```bash
# Enable write mode
curl -X POST http://localhost:8080/write_mode \
  -H "Content-Type: application/json" \
  -d '{"session_id": "a1b2c3d4-...", "enabled": true}'

# Approve pending write actions
curl -X POST http://localhost:8080/write_mode/confirm \
  -H "Content-Type: application/json" \
  -d '{"session_id": "a1b2c3d4-...", "enabled": true}'
```

### 4.5 Get analysis results by hash

If you know the binary's SHA-256 hash, you can query results directly:

```bash
# Analysis status
curl http://localhost:8080/api/analysis/{program_hash}

# Analyzer details
curl http://localhost:8080/api/analysis/{program_hash}/analyzers

# Decompiled files
curl http://localhost:8080/api/analysis/{program_hash}/files

# Specific decompiled function
curl http://localhost:8080/api/analysis/{program_hash}/files/{function_name}

# Reports
curl http://localhost:8080/api/analysis/{program_hash}/reports
curl http://localhost:8080/api/analysis/{program_hash}/reports/summary
```

### 4.6 WebSocket (real-time events)

Connect to get live progress updates:

```
ws://localhost:8080/stream/{session_id}
```

Events pushed:

| Event type | When |
|------------|------|
| `analysis:progress` | Analysis started |
| `message:typing` | Agent is processing |
| `analysis:completed` | Analysis finished |
| `analysis:error` | Analysis failed |

## 5. Full example (end to end)

```bash
# 1. Start backend
docker compose up --build -d ghidra agent

# 2. Wait for Ghidra to be ready (~2-3 min first time)
docker compose logs -f ghidra

# 3. Upload a sample binary
SESSION=$(curl -s -X POST http://localhost:8080/analyze/upload \
  -F "file=@./sample-binary/chargen" | python -c "import sys,json; print(json.load(sys.stdin)['session_id'])")

echo "Session: $SESSION"

# 4. Poll until complete
curl -s http://localhost:8080/status/$SESSION | python -m json.tool

# 5. Ask the agent a question
curl -s -X POST http://localhost:8080/query \
  -H "Content-Type: application/json" \
  -d "{\"session_id\": \"$SESSION\", \"query\": \"What does the main function do?\"}"

# 6. Poll for results
curl -s http://localhost:8080/status/$SESSION | python -m json.tool
```

## 6. Stop / restart

```bash
docker compose down            # stop
docker compose down -v         # stop and wipe Ghidra project data
docker compose up --build -d ghidra agent   # rebuild after code changes
```

## 7. Troubleshooting

| Problem | Fix |
|---------|-----|
| Agent cannot connect to Docker | Check `/var/run/docker.sock` is mounted and accessible. |
| Ghidra analysis times out | Increase `DEFAULT_ANALYSIS_TIMEOUT` in `.env` / `docker-compose.yml` (default 120s). |
| Upload returns 413 | File exceeds `MAX_UPLOAD_BYTES` (default 200 MB). Set in `.env`. |
| 404 "Session not found" | Sessions are in-memory; they are lost on agent restart. Re-upload. |
| LLM errors in logs | Check `ANTHROPIC_API_KEY` and `ANTHROPIC_BASE_URL` in `.env`. |
