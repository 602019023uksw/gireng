# Gireng API Documentation — Bot Integration Guide

> **Version:** 1.0  
> **Scope:** Complete API reference for automating malware analysis workflows, designed for Telegram bot / external integration.  
> **Base URL:** `http://localhost:8080` (adjust to your deployment)

---

## Table of Contents

1. [Authentication](#1-authentication)
2. [Upload & Analyze a File](#2-upload--analyze-a-file)
3. [Check Analysis Status (Polling)](#3-check-analysis-status-polling)
4. [Real-Time Notifications (WebSocket)](#4-real-time-notifications-websocket)
5. [Get Analysis Summary](#5-get-analysis-summary)
6. [Get the Report](#6-get-the-report)
7. [Get Raw Analyzer Results](#7-get-raw-analyzer-results)
8. [Get Decompiled Files](#8-get-decompiled-files)
9. [Get Hex Dump & Disassembly](#9-get-hex-dump--disassembly)
10. [Query / Ask Follow-Up Questions](#10-query--ask-follow-up-questions)
11. [Analysis History](#11-analysis-history)
12. [Cross-Binary Search](#12-cross-binary-search)
13. [Complete Bot Example (Python)](#13-complete-bot-example-python)
14. [Notification Strategies](#14-notification-strategies)

---

## 1. Authentication

All analysis endpoints require a valid JWT token in the `Authorization: Bearer <token>` header.

### 1.1 Register a User

```http
POST /api/auth/register
Content-Type: application/json
```

**Request body:**
```json
{
  "email": "bot@gireng.local",
  "username": "telegram_bot",
  "password": "secure_password_123"
}
```

**Response:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "user": {
    "id": "user-uuid",
    "email": "bot@gireng.local",
    "username": "telegram_bot",
    "role": "user"
  }
}
```

### 1.2 Login

```http
POST /api/auth/login
Content-Type: application/json
```

**Request body:**
```json
{
  "email": "bot@gireng.local",
  "password": "secure_password_123"
}
```

**Response:** same as register — returns `token` and `user`.

### 1.3 Use the Token

Store the `token` and send it with **every** subsequent request:

```http
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

### 1.4 Get Current User Info

```http
GET /api/auth/me
Authorization: Bearer <token>
```

**Response:**
```json
{
  "id": "user-uuid",
  "email": "bot@gireng.local",
  "username": "telegram_bot",
  "role": "user",
  "quota": 10,
  "quota_used": 3
}
```

---

## 2. Upload & Analyze a File

### 2.1 Upload via Multipart

```http
POST /analyze/upload
Authorization: Bearer <token>
Content-Type: multipart/form-data
```

**Form fields:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `file` | File | Yes | The binary file to analyze |
| `model` | string | No | LLM model override (e.g. `glm-5`, `glm-4.7`) |

**cURL example:**
```bash
curl -X POST http://localhost:8080/analyze/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@/path/to/malware.exe" \
  -F "model=glm-5"
```

**Response:**
```json
{
  "session_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
}
```

> **Important:** Save `session_id` — you need it to track progress and fetch results.

### 2.2 Analyze a File Already in Shared Volume

If the binary is already on the server (e.g. pre-staged in `/data/shared`):

```http
POST /analyze
Authorization: Bearer <token>
Content-Type: application/json
```

**Request body:**
```json
{
  "binary_path": "/data/shared/malware.exe",
  "upload_name": "malware.exe",
  "model": "glm-5"
}
```

**Response:** same as upload — returns `{ "session_id": "..." }`.

---

## 3. Check Analysis Status (Polling)

Since analysis takes 30 seconds to 5+ minutes (depending on binary size), you **must** poll until completion.

```http
GET /status/{session_id}
Authorization: Bearer <token>
```

**Response:**
```json
{
  "session_id": "a1b2c3d4-...",
  "status": "running",
  "state": {
    "program_hash": "37b2ba70447d19e1...",
    "binary_path": "/data/shared/malware.exe",
    "status": "running",
    "progress": 45,
    "current_step": "discovery",
    "analyzer_progress": {
      "ghidra": 60,
      "radare2": 30,
      "qiling": 0
    },
    "analyzer_status": {
      "ghidra": "running",
      "radare2": "running",
      "qiling": "pending"
    },
    "analyzer_step": {
      "ghidra": "Decompiling functions...",
      "radare2": "Building call graph...",
      "qiling": "Waiting..."
    },
    "started_at": 1713681234.5,
    "reasoning_trace": []
  }
}
```

**Status values:**
| Status | Meaning |
|--------|---------|
| `initialized` | Session created, waiting to start |
| `running` | Analysis in progress |
| `completed` | Analysis finished successfully |
| `error` | Analysis failed |

**Recommended polling strategy:**
```python
import time

def wait_for_analysis(session_id, token, poll_interval=5):
    headers = {"Authorization": f"Bearer {token}"}
    while True:
        resp = requests.get(
            f"http://localhost:8080/status/{session_id}",
            headers=headers
        )
        data = resp.json()
        status = data["status"]

        if status == "completed":
            return data["state"]
        elif status == "error":
            raise RuntimeError(f"Analysis failed: {data['state']}")

        time.sleep(poll_interval)
```

---

## 4. Real-Time Notifications (WebSocket)

For a better user experience than polling, connect to the WebSocket stream. This gives you **live progress updates** and an instant `analysis:completed` event.

### 4.1 Connect

```
ws://localhost:8080/stream/{session_id}?token={jwt_token}
```

### 4.2 Event Types

| Event | When | Payload |
|-------|------|---------|
| `analysis:progress` | Progress update | `{ status, step, progress, analyzer_progress, analyzer_status, analyzer_step }` |
| `analysis:completed` | **Analysis done** | `{ status, analyzer_progress, analyzer_status, analyzer_step }` |
| `analysis:error` | Analysis failed | `{ status, error, ... }` |
| `message:typing` | Agent started working | `{ status: "running" }` |

### 4.3 Python WebSocket Client Example

```python
import asyncio
import json
import websockets

async def stream_analysis(session_id, token):
    uri = f"ws://localhost:8080/stream/{session_id}?token={token}"
    async with websockets.connect(uri) as ws:
        async for message in ws:
            event = json.loads(message)
            event_type = event["type"]

            if event_type == "analysis:progress":
                payload = event["payload"]
                print(f"Progress: {payload['progress']}% — {payload['step']}")

            elif event_type == "analysis:completed":
                print("✅ Analysis completed!")
                return event["payload"]

            elif event_type == "analysis:error":
                print(f"❌ Error: {event['payload']['error']}")
                raise RuntimeError(event["payload"]["error"])

# Run in an asyncio task so your bot stays responsive
asyncio.create_task(stream_analysis(session_id, token))
```

> **Note for bots:** WebSocket gives you the fastest notification. Run it in a background task while your bot handles other messages.

---

## 5. Get Analysis Summary

Once analysis is complete, get a high-level summary using the **program hash** (SHA-256 of the binary):

```http
GET /api/analysis/{program_hash}
Authorization: Bearer <token>
```

**Response:**
```json
{
  "hash": "37b2ba70447d19e1...",
  "status": "COMPLETED",
  "type": "x86:64",
  "verdict": "Malware",
  "threat_score": 85,
  "max_score": 100,
  "duration": "2m 14s",
  "started": "2025-04-21T10:00:00",
  "completed": "2025-04-21T10:02:14",
  "tags": ["trojan", "process_hollowing", "etw_patching"]
}
```

> **Where to get `program_hash`:** It is inside `state["program_hash"]` from the `/status` response.

---

## 6. Get the Report

### 6.1 HTML Report (Interactive)

```http
GET /api/analysis/{program_hash}/export/html
Authorization: Bearer <token>
```

**Response:** Raw HTML with embedded Tailwind CSS. Save to `.html` and open in a browser, or serve inline in a Telegram WebApp.

### 6.2 PDF Report (A4, Print-Ready)

```http
GET /api/analysis/{program_hash}/export/pdf
Authorization: Bearer <token>
```

**Response:** Binary PDF data. Perfect for sending as a document in Telegram.

### 6.3 Text Report (Plain)

```http
GET /api/analysis/{program_hash}/export/text
Authorization: Bearer <token>
```

**Response:** Plain text markdown report. Good for displaying in chat messages.

### 6.4 Inline HTML View (No Download Header)

```http
GET /api/analysis/{program_hash}/view/html
Authorization: Bearer <token>
```

Same as `/export/html` but without `Content-Disposition: attachment`.

---

## 7. Get Raw Analyzer Results

### 7.1 Ghidra Results

```http
GET /api/analysis/{program_hash}/results/ghidra
Authorization: Bearer <token>
```

**Response fields:**
```json
{
  "analyzer": "ghidra",
  "binary": { "architecture": "x86:64", "file_type": "PE", "imports": [...], "exports": [...] },
  "functions": { "functions": [{ "name": "FUN_180001000", "address": "0x180001000", "size": 256 }] },
  "strings": { "strings": [{ "address": "0x180002000", "value": "http://evil.com" }] },
  "call_graph": { "nodes": [...], "edges": [...] },
  "call_graph_analysis": { "attack_chains": [...], "cycles": [...] },
  "decompiled": { "FUN_180001000": "int FUN_180001000(...) { ... }" }
}
```

### 7.2 Radare2 Results

```http
GET /api/analysis/{program_hash}/results/radare2
Authorization: Bearer <token>
```

### 7.3 Qiling Results

```http
GET /api/analysis/{program_hash}/results/qiling
Authorization: Bearer <token>
```

**Response fields:**
```json
{
  "analyzer": "qiling",
  "execution_trace": {},
  "syscalls": { "syscalls": [{ "name": "NtCreateFile", "address": "0x7ff..." }] },
  "api_calls": {},
  "memory_events": {},
  "network_activity": {},
  "evasion_techniques": {},
  "instruction_trace": {},
  "errors": []
}
```

---

## 8. Get Decompiled Files

### 8.1 List Files

```http
GET /api/analysis/{program_hash}/files
Authorization: Bearer <token>
```

**Response:**
```json
{
  "id": "root",
  "name": "malware.exe",
  "type": "folder",
  "children": [
    { "id": "FUN_180001000.c", "name": "FUN_180001000.c", "type": "code" },
    { "id": "FUN_180001b24.c", "name": "FUN_180001b24.c", "type": "code" }
  ]
}
```

### 8.2 Get File Content

```http
GET /api/analysis/{program_hash}/files/{file_id}
Authorization: Bearer <token>
```

**Response:**
```json
{
  "id": "FUN_180001000.c",
  "name": "FUN_180001000.c",
  "language": "c",
  "content": "int FUN_180001000(int param_1) { ... }"
}
```

---

## 9. Get Hex Dump & Disassembly

### 9.1 Hex Dump

```http
GET /api/analysis/{program_hash}/hex?address=0x180001000&size=256
Authorization: Bearer <token>
```

**Response:**
```json
{
  "address": "0x180001000",
  "size": 256,
  "lines": [
    "0x180001000  48 89 5c 24 08 48 89 74 24 10 57 48 83 ec 20 48  H..$.H.t$.WH.. H",
    "0x180001010  8b f1 48 8b fa 48 8b d9 33 d2 41 b8 00 30 00 00  ..H..H..3.A..0..",
    ...
  ]
}
```

### 9.2 Disassembly

```http
GET /api/analysis/{program_hash}/disassembly?address=0x180001000&count=32
Authorization: Bearer <token>
```

**Response:**
```json
{
  "address": "0x180001000",
  "count": 32,
  "instructions": [
    { "address": "0x180001000", "mnemonic": "mov", "operands": "qword [rsp + 8], rbx", "bytes": "48895c2408", "size": 5 },
    { "address": "0x180001005", "mnemonic": "mov", "operands": "qword [rsp + 0x10], rsi", "bytes": "4889742410", "size": 5 },
    ...
  ]
}
```

---

## 10. Query / Ask Follow-Up Questions

After analysis completes, you can ask natural language questions about the binary.

```http
POST /query
Authorization: Bearer <token>
Content-Type: application/json
```

**Request body:**
```json
{
  "session_id": "a1b2c3d4-...",
  "query": "What functions handle network connections?",
  "model": "glm-5"
}
```

**Response:**
```json
{
  "answer": "The binary contains several network-related functions...",
  "reasoning": "I examined the import table and found references to ws2_32.dll..."
}
```

### 10.1 Query with Tool Access (Advanced)

Allows the LLM to invoke Radare2 tools dynamically:

```http
POST /query_with_tools
Authorization: Bearer <token>
Content-Type: application/json
```

**Request body:** same as `/query`.

**Response:**
```json
{
  "answer": "...",
  "reasoning": "...",
  "tool_calls": [...],
  "tool_results": [...]
}
```

---

## 11. Analysis History

### 11.1 List Past Analyses

```http
GET /api/history?limit=20&offset=0
Authorization: Bearer <token>
```

### 11.2 Restore a Past Session

```http
POST /api/history/{session_id}/restore
Authorization: Bearer <token>
```

Restores the session into memory so you can query it again.

### 11.3 Delete an Analysis

```http
DELETE /api/history/{session_id}
Authorization: Bearer <token>
```

---

## 12. Cross-Binary Search

Search across all binaries the user has analyzed:

### 12.1 Search Functions
```http
GET /api/query/functions?q=CreateRemoteThread&limit=20
Authorization: Bearer <token>
```

### 12.2 Search Strings
```http
GET /api/query/strings?q=evil.com&limit=20
Authorization: Bearer <token>
```

### 12.3 Search IOCs
```http
GET /api/query/iocs?type=ip&limit=20
Authorization: Bearer <token>
```

---

## 13. Complete Bot Example (Python)

```python
"""
Gireng Telegram Bot — Minimal Integration Example
Sends a file → waits for analysis → returns PDF report
"""
import os
import time
import asyncio
import requests
import websockets
import json
from pathlib import Path

API_BASE = os.getenv("GIRENG_API", "http://localhost:8080")
TOKEN = os.getenv("GIRENG_TOKEN")  # Or login to get one


def login(email: str, password: str) -> str:
    """Authenticate and return JWT token."""
    resp = requests.post(
        f"{API_BASE}/api/auth/login",
        json={"email": email, "password": password}
    )
    resp.raise_for_status()
    return resp.json()["token"]


def upload_file(filepath: str, model: str = "glm-5") -> str:
    """Upload a binary. Returns session_id."""
    headers = {"Authorization": f"Bearer {TOKEN}"}
    with open(filepath, "rb") as f:
        resp = requests.post(
            f"{API_BASE}/analyze/upload",
            headers=headers,
            files={"file": f},
            data={"model": model}
        )
    resp.raise_for_status()
    return resp.json()["session_id"]


def poll_until_done(session_id: str, timeout: int = 600) -> dict:
    """Poll status until completed or error. Returns final state."""
    headers = {"Authorization": f"Bearer {TOKEN}"}
    start = time.time()
    while time.time() - start < timeout:
        resp = requests.get(
            f"{API_BASE}/status/{session_id}",
            headers=headers
        )
        data = resp.json()
        status = data["status"]

        if status == "completed":
            return data["state"]
        if status == "error":
            raise RuntimeError(f"Analysis failed: {data['state']}")

        time.sleep(5)
    raise TimeoutError("Analysis timed out")


async def ws_wait_for_done(session_id: str) -> dict:
    """WebSocket version — faster notification than polling."""
    uri = f"ws://localhost:8080/stream/{session_id}?token={TOKEN}"
    async with websockets.connect(uri) as ws:
        async for message in ws:
            event = json.loads(message)
            if event["type"] == "analysis:completed":
                return event["payload"]
            if event["type"] == "analysis:error":
                raise RuntimeError(event["payload"]["error"])


def get_summary(program_hash: str) -> dict:
    """Get high-level analysis summary."""
    headers = {"Authorization": f"Bearer {TOKEN}"}
    resp = requests.get(
        f"{API_BASE}/api/analysis/{program_hash}",
        headers=headers
    )
    resp.raise_for_status()
    return resp.json()


def get_text_report(program_hash: str) -> str:
    """Get plain text report."""
    headers = {"Authorization": f"Bearer {TOKEN}"}
    resp = requests.get(
        f"{API_BASE}/api/analysis/{program_hash}/export/text",
        headers=headers
    )
    resp.raise_for_status()
    return resp.text


def get_pdf_report(program_hash: str) -> bytes:
    """Get PDF report as binary."""
    headers = {"Authorization": f"Bearer {TOKEN}"}
    resp = requests.get(
        f"{API_BASE}/api/analysis/{program_hash}/export/pdf",
        headers=headers
    )
    resp.raise_for_status()
    return resp.content


def get_iocs(program_hash: str) -> list:
    """Get extracted IOCs."""
    headers = {"Authorization": f"Bearer {TOKEN}"}
    resp = requests.get(
        f"{API_BASE}/api/binary/{program_hash}/iocs",
        headers=headers
    )
    resp.raise_for_status()
    return resp.json()


# ------------------------------------------------------------------
# Main bot flow
# ------------------------------------------------------------------

def analyze_and_report(filepath: str) -> dict:
    """
    Full flow: upload → poll → return summary + report text.
    Use this inside your Telegram bot's message handler.
    """
    # 1. Upload
    session_id = upload_file(filepath)
    print(f"[+] Session: {session_id}")

    # 2. Wait for completion (polling version)
    state = poll_until_done(session_id)
    program_hash = state["program_hash"]
    print(f"[+] Hash: {program_hash}")

    # 3. Get summary
    summary = get_summary(program_hash)

    # 4. Get text report (good for Telegram messages)
    report_text = get_text_report(program_hash)

    # 5. Get IOCs
    iocs = get_iocs(program_hash)

    return {
        "session_id": session_id,
        "hash": program_hash,
        "verdict": summary.get("verdict", "Unknown"),
        "score": summary.get("threat_score", 0),
        "tags": summary.get("tags", []),
        "report": report_text,
        "iocs": iocs,
    }


# Example: asyncio version with WebSocket notification
async def analyze_async(filepath: str) -> dict:
    """Async version using WebSocket for instant completion notification."""
    session_id = upload_file(filepath)
    print(f"[+] Session: {session_id}")

    # Start WebSocket listener in background
    ws_task = asyncio.create_task(ws_wait_for_done(session_id))

    # Also start polling as fallback
    # (optional — WebSocket alone is usually sufficient)

    # Wait for WebSocket to signal completion
    await ws_task

    # Get results
    state = poll_until_done(session_id)  # one final poll to get full state
    program_hash = state["program_hash"]

    summary = get_summary(program_hash)
    report_text = get_text_report(program_hash)

    return {
        "hash": program_hash,
        "verdict": summary.get("verdict", "Unknown"),
        "score": summary.get("threat_score", 0),
        "report": report_text,
    }


if __name__ == "__main__":
    # Demo: login, analyze, print report
    if not TOKEN:
        TOKEN = login("bot@gireng.local", "secure_password_123")
        print(f"[+] Token: {TOKEN[:20]}...")

    result = analyze_and_report("./sample-binary/chargen")
    print(f"\n[+] Verdict: {result['verdict']} ({result['score']}/100)")
    print(f"[+] Tags: {', '.join(result['tags'])}")
    print(f"\n[+] Report preview:\n{result['report'][:1500]}...")
```

---

## 14. Notification Strategies

Analysis can take **30 seconds to 5+ minutes**. Your bot needs a strategy to notify the user when it's done without blocking.

### Strategy A: Polling (Simplest)

```python
# After upload, reply immediately:
"Analysis started. I'll send results when ready..."

# Then poll in a background thread/task:
def background_poll(chat_id, session_id):
    state = poll_until_done(session_id)
    send_telegram_message(chat_id, "Analysis complete!")
    send_pdf_report(chat_id, state["program_hash"])

threading.Thread(target=background_poll, args=(chat_id, session_id)).start()
```

**Pros:** Simple, no extra libraries, works everywhere.  
**Cons:** 5-second latency between completion and notification.

### Strategy B: WebSocket (Fastest)

```python
async def ws_listener(chat_id, session_id):
    payload = await ws_wait_for_done(session_id)
    send_telegram_message(chat_id, "✅ Analysis complete!")

# Start as asyncio background task
asyncio.create_task(ws_listener(chat_id, session_id))
```

**Pros:** Instant notification (< 1s), live progress updates possible.  
**Cons:** Requires `websockets` library, connection must stay open.

### Strategy C: Hybrid (Recommended for Production)

```python
async def analyze_with_notification(chat_id, filepath):
    session_id = upload_file(filepath)
    send_message(chat_id, f"🔄 Analysis started: `{session_id}`")

    try:
        # Try WebSocket first (fast)
        await asyncio.wait_for(ws_wait_for_done(session_id), timeout=600)
    except asyncio.TimeoutError:
        # Fallback to polling
        pass

    # Final state fetch
    state = poll_until_done(session_id)
    program_hash = state["program_hash"]

    # Build and send summary
    summary = get_summary(program_hash)
    send_message(chat_id, format_summary(summary))

    # Send PDF report as document
    pdf = get_pdf_report(program_hash)
    send_document(chat_id, pdf, filename=f"report_{program_hash[:16]}.pdf")
```

### Strategy D: Internal Webhook (Not Native — Requires Modification)

Gireng **does not** have a native webhook/callback system. If you want the backend to call your bot directly when analysis finishes, you would need to add a `callback_url` field to the upload endpoint and modify `run_with_events()` in `api/main.py` to POST to that URL on completion.

**Quick patch idea:**
```python
# In api/main.py, inside run_with_events(), after analysis:completed broadcast:
if callback_url := state.get("callback_url"):
    async with httpx.AsyncClient() as client:
        await client.post(callback_url, json={
            "session_id": session_id,
            "program_hash": program_hash,
            "status": "completed"
        })
```

---

## Appendix: Error Handling

| HTTP Status | Meaning | Action |
|-------------|---------|--------|
| `200` | Success | Process response |
| `401` | Unauthorized | Token expired or missing — re-login |
| `403` | Forbidden | Insufficient quota or wrong user |
| `404` | Not found | Session not found or analysis not yet complete |
| `413` | Payload too large | File exceeds `MAX_UPLOAD_BYTES` (default 200 MB) |
| `500` | Server error | Check agent logs: `docker compose logs agent` |

---

## Appendix: Rate Limits & Quotas

- Default user quota: **10 analyses** (set via `DEFAULT_USER_QUOTA` env var)
- Admins get unlimited quota (`-1`)
- Polling: recommended interval is **5 seconds**
- WebSocket: one connection per session is sufficient

---

## Appendix: Environment Variables for Bot Deployment

| Variable | Default | Description |
|----------|---------|-------------|
| `API_PORT` | `8080` | Backend port |
| `UI_PORT` | `4173` | Frontend port |
| `MAX_UPLOAD_BYTES` | `209715200` | Max file size (200 MB) |
| `DEFAULT_USER_QUOTA` | `10` | Analyses per user |
| `LLM_TIMEOUT` | `1200` | LLM call timeout (seconds) |
| `DEFAULT_ANALYSIS_TIMEOUT` | `120` | Per-analyzer timeout |
