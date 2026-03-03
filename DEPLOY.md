# Gireng — Deployment Guide

Complete guide for deploying Gireng on **Windows** and **Linux**.

---

## Table of Contents

1. [Package Requirements](#1-package-requirements)
2. [Environment Setup](#2-environment-setup)
3. [Deploy with Docker (Recommended)](#3-deploy-with-docker-recommended)
4. [Management Script (`run.py`)](#4-management-script-runpy)
5. [Local Development (Without Docker)](#5-local-development-without-docker)
6. [Authentication & Users](#6-authentication--users)
7. [Upload & Analyze a Binary](#7-upload--analyze-a-binary)
8. [API Reference](#8-api-reference)
9. [Report Export](#9-report-export)
10. [Troubleshooting](#10-troubleshooting)

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
sudo apt install -y python3 python3-venv python3-pip

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
| `danilid/ireng-runner:2.0.1` (or `$RUNNER_IMAGE`) | Docker Hub / Custom build | Headless Ghidra with PyGhidra |
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
playwright>=1.40.0        (Chromium for PDF export)
```

### 1.5 Frontend (Node.js) Dependencies

Installed automatically inside the `ui` Docker container. For local development:

```bash
cd app && npm ci
```

Key packages: React 19, Vite 7, TypeScript 5.9, Tailwind CSS 3.4, Radix UI, Framer Motion, Recharts, react-markdown, Lucide React.

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
| `HOST` | no | Public host placeholder used by UI/API/Langfuse URLs | `localhost` |
| `API_PORT` | no | Host port for backend API | `8080` |
| `UI_PORT` | no | Host port for frontend UI | `4173` |
| `LANGFUSE_PORT` | no | Host port for Langfuse dashboard | `3100` |
| `RUNNER_IMAGE` | yes | Ghidra runner Docker image name | `danilid/ireng-runner:2.0.1` |
| `ANTHROPIC_API_KEY` | yes | LLM API key | `sk-abc123...` |
| `ANTHROPIC_BASE_URL` | yes | LLM API endpoint | `https://api.anthropic.com` |
| `POSTGRES_PASSWORD` | no | Database password (default: `ireng_secret`) | `strong_password` |
| `JWT_SECRET` | no | JWT signing secret (auto-generated if unset) | `your-secret-key` |
| `ADMIN_EMAIL` | no | Bootstrap admin email (default: `admin@gireng.local`) | `admin@yourco.com` |
| `ADMIN_PASSWORD` | no | Bootstrap admin password (default: `admin`) | `strong_password` |
| `DEFAULT_USER_QUOTA` | no | Default analysis quota for new users (default: 10, -1 = unlimited) | `20` |
| `REGISTRATION_ENABLED` | no | Allow public registration (default: `true`) | `false` |
| `LANGFUSE_PUBLIC_KEY` | no | Langfuse public key (for tracing) | `pk-lf-...` |
| `LANGFUSE_SECRET_KEY` | no | Langfuse secret key (for tracing) | `sk-lf-...` |

Optional explicit overrides:

| Variable | Description | Example |
|----------|-------------|---------|
| `VITE_API_BASE_URL` | UI → backend base URL | `https://api.example.com` |
| `VITE_WS_URL` | UI → backend WebSocket URL | `wss://api.example.com/stream` |
| `LANGFUSE_URL` | Browser-facing Langfuse URL | `https://trace.example.com` |
| `LANGFUSE_HOST` | Agent → Langfuse URL | `http://langfuse:3000` |

---

## 3. Deploy with Docker (Recommended)

### 3.1 Build & Start All Services

```bash
docker compose up --build -d
```

Or use the management script:

```bash
python run.py rebuild
```

### 3.2 Services Overview

| Service | Image | Port | Description |
|---------|-------|------|-------------|
| `ghidra` | `danilid/ireng-runner:2.0.1` | (internal) | Headless Ghidra runner with PyGhidra. First boot takes ~2-3 min. |
| `radare2` | `radare/radare2` | (internal) | Radare2 with r2ghidra/r2dec decompiler plugins. |
| `qiling` | Built from `backend/Dockerfile.qiling` | (internal) | Qiling sandbox for dynamic emulation, API/syscall tracing. |
| `postgres` | `postgres:16-alpine` | (internal) | PostgreSQL database for users, sessions, history & Langfuse. |
| `langfuse` | `langfuse/langfuse:2` | **`${LANGFUSE_PORT}`** (default `3100`) | LLM observability dashboard. |
| `agent` | Built from `backend/Dockerfile` | **`${API_PORT}`** (default `8080`) | FastAPI backend + Playwright/Chromium for PDF. |
| `ui` | Built from `app/Dockerfile.ui` | **`${UI_PORT}`** (default `4173`) | React frontend (Vite preview server). |

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
python run.py test            Run backend tests + frontend lint locally
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
# Backend tests (183 tests)
cd backend
python -m pytest tests/ -v

# Frontend lint
cd app && npm run lint
```

---

## 6. Authentication & Users

The platform uses **JWT-based authentication** with role-based access control.

### 6.1 First Login

On first startup, an admin account is automatically created:
- **Email:** `admin@gireng.local` (or `$ADMIN_EMAIL`)
- **Password:** `admin` (or `$ADMIN_PASSWORD`)

> **Important:** Change the default admin password immediately via the Admin Panel or API.

### 6.2 Register a New User

```bash
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "analyst@example.com", "username": "analyst", "password": "securepass"}'
```

### 6.3 Login

```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "analyst@example.com", "password": "securepass"}'
```

Response includes a JWT token. Use it in subsequent requests:

```bash
curl -H "Authorization: Bearer <token>" http://localhost:8080/api/auth/me
```

### 6.4 Roles

| Role | Permissions |
|------|-------------|
| `admin` | Full access, see all analyses, manage users, unlimited quota |
| `user` | Upload & analyze (within quota), see own analyses only |
| `guest` | Read-only access to own analyses |

### 6.5 Quotas

Each user has an analysis quota (default: 10). Set via env var `DEFAULT_USER_QUOTA` or per-user in Admin Panel.

- `-1` = unlimited (admins get this automatically)
- `0` = blocked from uploading
- `N` = can submit up to N analyses

### 6.6 Admin Panel

Accessible from the UI header menu (admin users only). Allows:
- View all users with quota usage
- Change user roles
- Activate / deactivate users
- Reset passwords
- Adjust per-user quotas

---

## 7. Upload & Analyze a Binary

### 7.1 Upload

All analysis endpoints require a valid JWT token:

```bash
curl -X POST http://localhost:8080/analyze/upload \
  -H "Authorization: Bearer <token>" \
  -F "file=@./sample-binary/chargen"
```

Response:

```json
{"session_id": "a1b2c3d4-..."}
```

### 7.2 Check Status

```bash
curl http://localhost:8080/status/{session_id}
```

Status values: `initialized` → `completed` (or `error`).

### 7.3 Query the Agent

```bash
curl -X POST http://localhost:8080/query \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"session_id": "SESSION_ID", "query": "Find buffer overflow vulnerabilities"}'
```

### 7.4 WebSocket (Real-Time Events)

```
ws://localhost:8080/stream/{session_id}
```

| Event | When |
|-------|------|
| `analysis:progress` | Analysis started |
| `message:typing` | Agent is processing |
| `analysis:completed` | Analysis finished |
| `analysis:error` | Analysis failed |

### 7.5 Results by Hash

```bash
curl http://localhost:8080/api/analysis/{program_hash}
curl http://localhost:8080/api/analysis/{program_hash}/files
curl http://localhost:8080/api/analysis/{program_hash}/reports/summary
```

---

## 8. API Reference

### 8.1 Authentication (3 endpoints)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/auth/register` | Register new user |
| `POST` | `/api/auth/login` | Login and receive JWT token |
| `GET` | `/api/auth/me` | Get current user profile (quota + usage) |

### 8.2 Admin (6 endpoints, requires admin role)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/admin/users` | List all users (with quota + analysis count) |
| `PUT` | `/api/admin/users/{id}/role` | Change user role |
| `PUT` | `/api/admin/users/{id}/active` | Toggle user active/disabled |
| `PUT` | `/api/admin/users/{id}/password` | Reset user password |
| `PUT` | `/api/admin/users/{id}/quota` | Update user analysis quota |
| `DELETE` | `/api/admin/users/{id}` | Delete user |

### 8.3 Core Analysis (7 endpoints)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/analyze/upload` | Upload binary for analysis |
| `POST` | `/analyze` | Analyze binary already in shared volume |
| `GET` | `/status/{session_id}` | Get analysis status |
| `POST` | `/query` | Ask the agent a question |
| `POST` | `/write_mode` | Enable/disable write mode |
| `POST` | `/write_mode/confirm` | Approve pending write actions |
| `WS` | `/stream/{session_id}` | Real-time event stream |

### 8.4 Analysis Results (10 endpoints)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/analysis/{hash}` | Get analysis by binary hash |
| `GET` | `/api/analysis/{hash}/analyzers` | List analyzers (Ghidra + R2) |
| `GET` | `/api/analysis/{hash}/analyzers/{id}` | Analyzer details |
| `GET` | `/api/analysis/{hash}/files` | Get decompiled file tree |
| `GET` | `/api/analysis/{hash}/files/{id}` | Get decompiled function code |
| `GET` | `/api/analysis/{hash}/reports` | List reports |
| `GET` | `/api/analysis/{hash}/reports/{id}` | Get report content |
| `GET` | `/api/analysis/{hash}/similar` | Similar files |
| `GET` | `/api/analysis/{hash}/results/ghidra` | Raw Ghidra results |
| `GET` | `/api/analysis/{hash}/results/radare2` | Raw Radare2 results |

### 8.5 Export (7 endpoints)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/analysis/{hash}/export/html` | Export full HTML report |
| `GET` | `/api/analysis/{hash}/export/text` | Export plain text report |
| `GET` | `/api/analysis/{hash}/export/pdf` | Export A4 PDF report (Playwright) |
| `GET` | `/export/session/{session_id}/html` | Export session HTML (convenience) |
| `GET` | `/export/session/{session_id}/text` | Export session text (convenience) |
| `GET` | `/export/session/{session_id}/pdf` | Export session PDF (convenience) |
| `GET` | `/export/session/{session_id}/agent/{agent}` | Export per-agent report |

### 8.6 Analysis History (5 endpoints)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/history` | List past analyses (paginated, filterable) |
| `GET` | `/api/history/{session_id}` | Single past analysis summary |
| `GET` | `/api/history/{session_id}/qa` | Q&A history for session |
| `POST` | `/api/history/{session_id}/restore` | Restore past session into memory |
| `DELETE` | `/api/history/{session_id}` | Delete past analysis |

### 8.7 Cross-Binary Search (7 endpoints)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/query/functions` | Search functions across all binaries |
| `GET` | `/api/query/strings` | Full-text search strings |
| `GET` | `/api/query/iocs` | Search IOCs across all binaries |
| `GET` | `/api/binary/{hash}/functions` | Functions for a specific binary |
| `GET` | `/api/binary/{hash}/decompilations` | Decompiled functions for a binary |
| `GET` | `/api/binary/{hash}/iocs` | IOCs for a specific binary |
| `GET` | `/api/binary/{hash}/attack-chains` | Attack chains for a binary |

### 8.8 Utility (2 endpoints)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Service health check |
| `GET` | `/api/models` | Available LLM models |

Full interactive documentation available at: `http://localhost:8080/docs` (Swagger UI)

---

## 9. Report Export

### 9.1 Formats

| Format | Endpoint | Description |
|--------|----------|-------------|
| **HTML** | `/api/analysis/{hash}/export/html` | Interactive dark-themed report with MITRE cards, code evidence, call graphs |
| **PDF** | `/api/analysis/{hash}/export/pdf` | Professional white-background A4 report generated via Playwright/Chromium |
| **Text** | `/api/analysis/{hash}/export/text` | Plain text report for scripting and archival |

### 9.2 PDF Report

The PDF uses a dedicated light-mode HTML template (`_build_pdf_html`) — completely separate from the dark-themed web HTML — with:

- White background, clean typography, inline CSS (no external dependencies)
- 13 numbered sections: Executive Summary, Binary Information, MITRE ATT&CK, Malware Capabilities, Technical Analysis, Functions, Evidence, Code Evidence, Operational Flow, Call Graph, IOCs, Recommendations, Conclusion
- Verdict badge with risk score
- Rendered via Playwright headless Chromium at 1100px viewport, scale 0.82
- Deterministic output — no CDN, no JavaScript

### 9.3 UI Export

The React frontend provides export buttons in:
- **Analysis Completed card** (chat) — HTML + PDF download buttons
- **Report tab** (right panel) — Export dropdown with HTML, Text, and PDF options

---

## 10. Troubleshooting

| Problem | Fix |
|---------|-----|
| Agent cannot connect to Docker | **Linux:** Check `/var/run/docker.sock` permissions. **Windows:** Ensure Docker Desktop is running and WSL integration is enabled. |
| Ghidra analysis times out | Increase `DEFAULT_ANALYSIS_TIMEOUT` in `.env` (default 120s). |
| Ghidra container takes too long on first boot | Normal — PyGhidra venv setup takes 2-3 minutes on first start. |
| Upload returns 413 | Binary exceeds `MAX_UPLOAD_BYTES` (default 200 MB). Adjust in `.env`. |
| 404 "Session not found" | Sessions are in-memory; lost on agent restart. Use `/api/history/{id}/restore` to reload from DB. |
| LLM errors in logs | Verify `ANTHROPIC_API_KEY` and `ANTHROPIC_BASE_URL` in `.env`. |
| `docker compose` not found | Install Docker Compose v2 (`docker compose`, not `docker-compose`). |
| API/UI/Langfuse port already in use | Set `API_PORT`, `UI_PORT`, or `LANGFUSE_PORT` in `.env` and restart. |
| Frontend can't reach backend | Ensure `HOST` and `API_PORT` are correct, or override with `VITE_API_BASE_URL`. |
| Database connection errors | Check that `postgres` container is healthy: `docker compose ps`. |
| PDF export fails | Playwright + Chromium are installed in the agent Docker image. If running locally, run `playwright install chromium`. |

---

## Stop / Clean Up

```bash
docker compose down            # Stop all containers
docker compose down -v         # Stop and remove all data (volumes)
python run.py stop             # Same as docker compose down
```
