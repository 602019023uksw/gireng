# Gireng — Deployment Guide

Complete guide for deploying Gireng on **Windows** and **Linux**.

---

## Table of Contents

1. [Package Requirements](#1-package-requirements)
2. [Environment Setup](#2-environment-setup)
3. [Deploy with Docker (Recommended)](#3-deploy-with-docker-recommended)
4. [Management Script (`run.py`)](#4-management-script-runpy)
5. [Local Development (Without Docker)](#5-local-development-without-docker)
6. [Upload & Analyze a Binary](#6-upload--analyze-a-binary)
7. [API Reference (Quick)](#7-api-reference-quick)
8. [Troubleshooting](#8-troubleshooting)

---

## 1. Package Requirements

### 1.1 System Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| CPU | 2 cores | 4+ cores |
| RAM | 4 GB | 8+ GB |
| Disk | 10 GB free | 20+ GB free |
| OS | Windows 10+ / Ubuntu 20.04+ | Windows 11 / Ubuntu 22.04+ |

### 1.2 Software Prerequisites

#### Both Windows & Linux

| Package | Version | Purpose |
|---------|---------|---------|
| **Docker Engine** | 24.0+ | Container runtime |
| **Docker Compose** | v2+ (bundled with Docker Desktop on Windows) | Service orchestration |
| **Git** | 2.30+ | Clone the repository |
| **Python** | 3.11+ | Management script (`run.py`), backend dev |
| **Node.js** | 20+ | Frontend build (local dev / UI container) |
| **npm** | 9+ | Frontend dependency management |

#### Windows-Specific

```
Docker Desktop for Windows    https://www.docker.com/products/docker-desktop/
Python 3.11+                  https://www.python.org/downloads/
Node.js 20 LTS               https://nodejs.org/
Git for Windows               https://git-scm.com/download/win
```

> **Note:** Docker Desktop must have **WSL 2 backend** enabled. Ensure WSL integration
> is turned on in Docker Desktop → Settings → Resources → WSL Integration.

#### Linux-Specific (Debian/Ubuntu)

```bash
# Docker (official method)
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER   # log out & back in

# Python 3.11+
sudo apt update
sudo apt install -y python3.11 python3.11-venv python3-pip

# Node.js 20 (via NodeSource)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs

# Git
sudo apt install -y git

# Docker socket access (required — the agent container mounts it)
ls -la /var/run/docker.sock   # must be accessible to your user
```

### 1.3 Pre-Built Docker Images Required

| Image | Source | Notes |
|-------|--------|-------|
| `ireng-runner` (or `$RUNNER_IMAGE`) | Custom Ghidra image | Must be built or pulled before first run |
| `radare/radare2:latest` | Docker Hub | Pulled automatically |
| `postgres:16-alpine` | Docker Hub | Pulled automatically |
| `langfuse/langfuse:2` | Docker Hub | Pulled automatically |

### 1.4 Backend Python Dependencies

Installed automatically inside the `agent` Docker container. For local development:

```
fastapi==0.115.6          uvicorn[standard]==0.27.1
langchain==0.3.14         langgraph==0.2.52
httpx==0.27.0             structlog==24.4.0
pydantic==2.9.2           python-dotenv==1.0.1
tenacity==8.5.0           websockets==12.0
python-multipart==0.0.9   litellm==1.61.16
zhipuai>=2.0.0            langchain-community>=0.0.32
asyncpg>=0.29.0           langfuse>=2.0.0,<3.0.0
```

### 1.5 Frontend (Node.js) Dependencies

Installed automatically inside the `ui` Docker container. For local development:

```bash
cd app && npm ci
```

Key packages: React 19, Vite 7, Tailwind CSS 3, Radix UI, Recharts, react-markdown.

---

## 2. Environment Setup

### 2.1 Clone the Repository

```bash
git clone https://github.com/danilchristianto/gireng.git
cd gireng
```

### 2.2 Create `.env` File

```bash
# Linux / macOS
cp .env.template .env

# Windows (PowerShell)
Copy-Item .env.template .env
```

Edit `.env` and fill in the required variables:

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `RUNNER_IMAGE` | yes | Ghidra runner Docker image name | `ireng-runner` |
| `ANTHROPIC_API_KEY` | yes | LLM API key | `sk-abc123...` |
| `ANTHROPIC_BASE_URL` | yes | LLM API endpoint | `https://api.z.ai/api/anthropic` |
| `POSTGRES_PASSWORD` | no | Database password (default: `ireng_secret`) | `strong_password` |
| `LANGFUSE_PUBLIC_KEY` | no | Langfuse public key (for tracing) | `pk-lf-...` |
| `LANGFUSE_SECRET_KEY` | no | Langfuse secret key (for tracing) | `sk-lf-...` |

---

## 3. Deploy with Docker (Recommended)

### 3.1 Build & Start All Services

```bash
# Linux / macOS
docker compose up --build -d

# Windows (PowerShell)
docker compose up --build -d
```

Or use the management script:

```bash
python run.py rebuild
```

### 3.2 Services Overview

| Service | Image | Port | Description |
|---------|-------|------|-------------|
| `ghidra` | `ireng-runner` | (internal) | Headless Ghidra runner with PyGhidra. First boot takes ~2-3 min. |
| `radare2` | `radare/radare2` | (internal) | Radare2 with r2ghidra/r2dec decompiler plugins. |
| `postgres` | `postgres:16-alpine` | (internal) | PostgreSQL database for sessions & Langfuse. |
| `langfuse` | `langfuse/langfuse:2` | **3100** | LLM observability dashboard. |
| `agent` | Built from `backend/Dockerfile` | **8080** | FastAPI backend (the main API). |
| `ui` | Built from `app/Dockerfile.ui` | **4173** | React frontend (Vite preview server). |

### 3.3 Verify Deployment

```bash
# Check all containers are running
docker compose ps

# Check backend is alive
curl http://localhost:8080/docs

# Check frontend is alive
curl http://localhost:4173

# Check Langfuse dashboard
curl http://localhost:3100
```

### 3.4 Watch Logs

```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f agent
docker compose logs -f ghidra
```

---

## 4. Management Script (`run.py`)

A convenience wrapper around `docker compose`:

```
python run.py start           Start all containers (detached)
python run.py stop            Stop all containers
python run.py restart         Restart all containers
python run.py rebuild         Rebuild and restart all containers
python run.py rebuild agent   Rebuild only the agent container
python run.py rebuild ui      Rebuild only the ui container
python run.py logs            Tail live logs (all services)
python run.py logs agent      Tail live logs for a specific service
python run.py up              Start with live logs (foreground)
python run.py status          Show container status
python run.py db              Open psql shell to the database
python run.py test            Run backend + frontend tests locally
python run.py lint            Run backend + frontend lint checks locally
```

---

## 5. Local Development (Without Docker)

For working on the code without rebuilding containers each time.

### 5.1 Backend

```bash
# Create virtual environment
python -m venv .venv

# Activate
# Linux/macOS:
source .venv/bin/activate
# Windows PowerShell:
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -e ./backend

# Run the backend
uvicorn ghidra_agent.api.main:app --host 0.0.0.0 --port 8080 --reload
```

> You still need the Docker services (ghidra, radare2, postgres, langfuse) running.
> Start them with: `docker compose up -d ghidra radare2 postgres langfuse`

### 5.2 Frontend

```bash
cd app
npm ci
npm run dev    # Vite dev server at http://localhost:5173
```

### 5.3 Run Tests Locally

```bash
# Backend tests
python -m pytest backend/tests -v

# Frontend lint
cd app && npm run lint
```

---

## 6. Upload & Analyze a Binary

### 6.1 Upload

```bash
curl -X POST http://localhost:8080/analyze/upload \
  -F "file=@./sample-binary/chargen"
```

Response:

```json
{"session_id": "a1b2c3d4-..."}
```

### 6.2 Check Status

```bash
curl http://localhost:8080/status/{session_id}
```

Status values: `initialized` → `completed` (or `error`).

### 6.3 Query the Agent

```bash
curl -X POST http://localhost:8080/query \
  -H "Content-Type: application/json" \
  -d '{"session_id": "SESSION_ID", "query": "Find buffer overflow vulnerabilities"}'
```

### 6.4 WebSocket (Real-Time Events)

```
ws://localhost:8080/stream/{session_id}
```

| Event | When |
|-------|------|
| `analysis:progress` | Analysis started |
| `message:typing` | Agent is processing |
| `analysis:completed` | Analysis finished |
| `analysis:error` | Analysis failed |

### 6.5 Results by Hash

```bash
curl http://localhost:8080/api/analysis/{program_hash}
curl http://localhost:8080/api/analysis/{program_hash}/files
curl http://localhost:8080/api/analysis/{program_hash}/reports/summary
```

---

## 7. API Reference (Quick)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/analyze/upload` | Upload binary for analysis |
| `POST` | `/analyze` | Analyze binary already in shared volume |
| `GET` | `/status/{session_id}` | Get analysis status |
| `POST` | `/query` | Ask the agent a question |
| `POST` | `/write_mode` | Enable/disable write mode |
| `POST` | `/write_mode/confirm` | Approve pending write actions |
| `GET` | `/api/analysis/{hash}` | Get analysis by binary hash |
| `GET` | `/api/analysis/{hash}/files` | Get decompiled files |
| `GET` | `/api/analysis/{hash}/reports/summary` | Get report summary |
| `WS` | `/stream/{session_id}` | Real-time event stream |
| `GET` | `/docs` | OpenAPI (Swagger) documentation |

---

## 8. Troubleshooting

| Problem | Fix |
|---------|-----|
| Agent cannot connect to Docker | **Linux:** Check `/var/run/docker.sock` permissions. **Windows:** Ensure Docker Desktop is running and WSL integration is enabled. |
| Ghidra analysis times out | Increase `DEFAULT_ANALYSIS_TIMEOUT` in `.env` (default 120s). |
| Ghidra container takes too long on first boot | Normal — PyGhidra venv setup takes 2-3 minutes on first start. |
| Upload returns 413 | Binary exceeds `MAX_UPLOAD_BYTES` (default 200 MB). Adjust in `.env`. |
| 404 "Session not found" | Sessions are in-memory; lost on agent restart. Re-upload the binary. |
| LLM errors in logs | Verify `ANTHROPIC_API_KEY` and `ANTHROPIC_BASE_URL` in `.env`. |
| `docker compose` not found | Install Docker Compose v2 (`docker compose`, not `docker-compose`). |
| Port 8080/4173 already in use | Stop the conflicting process or change ports in `docker-compose.yml`. |
| Frontend can't reach backend | Ensure `VITE_API_BASE_URL` points to the correct backend URL. |
| Database connection errors | Check that `postgres` container is healthy: `docker compose ps`. |

---

## Stop / Clean Up

```bash
docker compose down            # Stop all containers
docker compose down -v         # Stop and remove all data (volumes)
python run.py stop             # Same as docker compose down
```
