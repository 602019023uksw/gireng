import asyncio
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, File, Form, HTTPException, UploadFile, WebSocket, WebSocketDisconnect, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from pydantic import BaseModel as PydanticBaseModel, EmailStr, Field as PydanticField

from ghidra_agent import database as db
from ghidra_agent.auth import (
    can_write,
    create_access_token,
    get_current_user,
    get_optional_user,
    hash_password,
    is_admin,
    require_role,
    verify_password,
)
from ghidra_agent.config import settings
from ghidra_agent.ioc_extractor import calculate_verdict, classify_malware_type, build_analysis_tags, extract_iocs_from_state, format_iocs_for_report
from ghidra_agent.langfuse_tracing import create_standalone_trace_metadata
from ghidra_agent.llm import call_llm
from ghidra_agent.context_builder import build_analysis_context
from ghidra_agent.logging import configure_logging, logger
from ghidra_agent.models import (
    QueryRequest,
    SessionCreateRequest,
    SessionCreateResponse,
    StatusResponse,
)
from ghidra_agent.ranking_utils import _function_priority_key
from ghidra_agent.rate_limiter import query_limit, upload_limit
# Updated to import from the new reporting package (ghidra_agent.reporting/)
from ghidra_agent.reporting import (
    build_agent_report_html,
    build_report_html,
    build_report_pdf,
    build_report_text,
)
from ghidra_agent.sessions import run_graph, store
from ghidra_agent.ui_adapter import (
    build_analyzer_response,
    build_code_file,
    build_file_tree,
    build_model_list,
    build_report_content,
    build_reports,
    build_similar_files,
)
from ghidra_agent.utils import ensure_directory, safe_basename


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: validate security configuration
    if settings.jwt_secret in ("changeme-gireng-jwt-secret-key", ""):
        logger.warning("insecure_jwt_secret", hint="Set JWT_SECRET env var to a strong random value")
    if settings.admin_password == "admin":
        logger.warning("insecure_admin_password", hint="Set ADMIN_PASSWORD env var to a strong password")
    if settings.database_url.startswith("postgresql://gireng:gireng_secret@"):
        logger.warning("insecure_database_password", hint="Change default database credentials")
    yield
    # Shutdown: close DB pool
    await db.close_db()


app = FastAPI(title="Ghidra Reverse Engineering Agent", lifespan=lifespan)

# Import and include memory routes
from ghidra_agent.api.memory_routes import router as memory_router
app.include_router(memory_router)

import os as _os

# Build the allowed origins list.
# In production, set CORS_ORIGINS env var (comma-separated).
# In dev, the Vite proxy makes CORS unnecessary, but we still allow common ports.
_cors_env = _os.environ.get("CORS_ORIGINS", "")
_cors_origins: list[str] = [o.strip() for o in _cors_env.split(",") if o.strip()] if _cors_env else []

# Always allow common local dev origins
_DEFAULT_ORIGINS = [
    "http://localhost:5173",   # Vite dev server
    "http://localhost:4173",   # Vite preview / Docker UI
    "http://localhost:3000",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:4173",
    "http://127.0.0.1:3000",
]
for _o in _DEFAULT_ORIGINS:
    if _o not in _cors_origins:
        _cors_origins.append(_o)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

configure_logging()


# ---------------------------------------------------------------------------
# Global exception handler – ensures CORS headers are present even on 500s.
# Without this, unhandled exceptions bypass CORSMiddleware and the browser
# reports a misleading CORS error instead of the real server error.
# ---------------------------------------------------------------------------
@app.exception_handler(Exception)
async def _global_exception_handler(request, exc):
    logger.error("unhandled_exception", path=request.url.path, error=str(exc), exc_info=exc)
    return JSONResponse(
        status_code=500,
        content={"detail": f"Internal server error: {exc}"},
    )


@app.get("/health")
async def health() -> JSONResponse:
    """Health check endpoint. Verifies API and database connectivity."""
    db_ok = False
    try:
        from ghidra_agent import database as db
        await db.get_user_by_id("healthcheck")
        db_ok = True
    except Exception as exc:
        logger.warning("health_db_check_failed", error=str(exc))
    status_code = 200 if db_ok else 503
    return JSONResponse(
        {"status": "ok" if db_ok else "degraded", "db_connected": db_ok, "sessions": len(store.sessions)},
        status_code=status_code,
    )


@app.get("/api/guide", response_class=HTMLResponse)
async def api_guide() -> HTMLResponse:
    """Public API integration guide (docs.md) rendered as HTML."""
    guide_path = Path("/app/docs.md")
    if not guide_path.exists():
        # Fallback for local development where docs.md is at repo root
        guide_path = Path(__file__).resolve().parent.parent.parent.parent.parent / "docs.md"
    if guide_path.exists():
        content = guide_path.read_text(encoding="utf-8")
    else:
        content = "# API Guide\n\nDocumentation not found."
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Gireng API Guide</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; background: #0d1117; color: #c9d1d9; padding: 40px; max-width: 900px; margin: 0 auto; line-height: 1.7; }}
  h1, h2, h3 {{ color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 8px; }}
  h1 {{ font-size: 2rem; }}
  h2 {{ font-size: 1.5rem; margin-top: 40px; }}
  h3 {{ font-size: 1.2rem; margin-top: 30px; }}
  pre {{ background: #161b22; padding: 16px; border-radius: 8px; overflow-x: auto; border: 1px solid #30363d; }}
  code {{ background: #161b22; padding: 2px 6px; border-radius: 4px; font-size: 0.9em; }}
  pre code {{ background: transparent; padding: 0; }}
  table {{ border-collapse: collapse; width: 100%; margin: 16px 0; }}
  th, td {{ border: 1px solid #30363d; padding: 10px; text-align: left; }}
  th {{ background: #161b22; color: #58a6ff; }}
  tr:nth-child(even) {{ background: #161b22; }}
  a {{ color: #58a6ff; }}
  blockquote {{ border-left: 4px solid #30363d; margin: 0; padding-left: 16px; color: #8b949e; }}
  hr {{ border: none; border-top: 1px solid #30363d; margin: 30px 0; }}
</style>
</head>
<body>
<pre>{content}</pre>
</body>
</html>"""
    return HTMLResponse(content=html)


# ---------------------------------------------------------------------------
# Auth request / response models
# ---------------------------------------------------------------------------

class RegisterRequest(PydanticBaseModel):
    email: str
    username: str
    password: str


class LoginRequest(PydanticBaseModel):
    email: str
    password: str


class UpdateProfileRequest(PydanticBaseModel):
    username: str | None = None
    password: str | None = None


class UpdateRoleRequest(PydanticBaseModel):
    role: str


class ResetPasswordRequest(PydanticBaseModel):
    password: str


class UpdateQuotaRequest(PydanticBaseModel):
    quota: int  # -1 = unlimited


# ---------------------------------------------------------------------------
# Auth endpoints
# ---------------------------------------------------------------------------

@app.post("/api/auth/register")
async def register(req: RegisterRequest) -> JSONResponse:
    if not settings.registration_enabled:
        raise HTTPException(status_code=403, detail="Registration is disabled")
    if not req.email or not req.username or not req.password:
        raise HTTPException(status_code=400, detail="All fields required")
    if len(req.password) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters")
    existing = await db.get_user_by_email(req.email)
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")
    existing_name = await db.get_user_by_username(req.username)
    if existing_name:
        raise HTTPException(status_code=409, detail="Username already taken")
    hashed = hash_password(req.password)
    user = await db.create_user(req.email, req.username, hashed, role="user")
    token = create_access_token({"sub": user["id"], "role": user["role"]})
    return JSONResponse({
        "token": token,
        "user": {
            "id": user["id"],
            "email": user["email"],
            "username": user["username"],
            "role": user["role"],
            "quota": user.get("quota", 10),
            "analysis_count": 0,
        },
    })


@app.post("/api/auth/login")
async def login(req: LoginRequest) -> JSONResponse:
    user = await db.get_user_by_email(req.email)
    if not user or not verify_password(req.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not user.get("is_active", True):
        raise HTTPException(status_code=403, detail="Account disabled")
    token = create_access_token({"sub": user["id"], "role": user["role"]})
    return JSONResponse({
        "token": token,
        "user": {
            "id": user["id"],
            "email": user["email"],
            "username": user["username"],
            "role": user["role"],
            "quota": user.get("quota", 10),
            "analysis_count": await db.get_user_analysis_count(user["id"]),
        },
    })


@app.get("/api/auth/me")
async def auth_me(user: Dict[str, Any] = Depends(get_current_user)) -> JSONResponse:
    used = await db.get_user_analysis_count(user["id"])
    return JSONResponse({
        "id": user["id"],
        "email": user["email"],
        "username": user["username"],
        "role": user["role"],
        "is_active": user.get("is_active", True),
        "created_at": user.get("created_at", ""),
        "quota": user.get("quota", 10),
        "analysis_count": used,
    })


@app.put("/api/auth/me")
async def update_profile(
    req: UpdateProfileRequest,
    user: Dict[str, Any] = Depends(get_current_user),
) -> JSONResponse:
    if req.username:
        existing = await db.get_user_by_username(req.username)
        if existing and existing["id"] != user["id"]:
            raise HTTPException(status_code=409, detail="Username already taken")
    if req.password:
        if len(req.password) < 4:
            raise HTTPException(status_code=400, detail="Password must be at least 4 characters")
        await db.update_user_password(user["id"], hash_password(req.password))
    return JSONResponse({"ok": True})


# ---------------------------------------------------------------------------
# Admin endpoints
# ---------------------------------------------------------------------------

@app.get("/api/admin/users")
async def admin_list_users(
    limit: int = 100,
    offset: int = 0,
    user: Dict[str, Any] = Depends(require_role("admin")),
) -> JSONResponse:
    users = await db.list_users(limit=limit, offset=offset)
    total = await db.get_user_count()
    # enrich each user with analysis_count
    for u in users:
        u["analysis_count"] = await db.get_user_analysis_count(u["id"])
    return JSONResponse({"items": users, "total": total})


@app.put("/api/admin/users/{target_user_id}/role")
async def admin_update_role(
    target_user_id: str,
    req: UpdateRoleRequest,
    user: Dict[str, Any] = Depends(require_role("admin")),
) -> JSONResponse:
    if req.role not in ("admin", "user", "guest"):
        raise HTTPException(status_code=400, detail="Invalid role")
    if target_user_id == user["id"] and req.role != "admin":
        raise HTTPException(status_code=400, detail="Cannot demote yourself")
    ok = await db.update_user_role(target_user_id, req.role)
    if not ok:
        raise HTTPException(status_code=404, detail="User not found")
    return JSONResponse({"ok": True})


@app.put("/api/admin/users/{target_user_id}/active")
async def admin_toggle_active(
    target_user_id: str,
    user: Dict[str, Any] = Depends(require_role("admin")),
) -> JSONResponse:
    target = await db.get_user_by_id(target_user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    if target_user_id == user["id"]:
        raise HTTPException(status_code=400, detail="Cannot disable yourself")
    new_active = not target.get("is_active", True)
    await db.update_user_active(target_user_id, new_active)
    return JSONResponse({"ok": True, "is_active": new_active})


@app.delete("/api/admin/users/{target_user_id}")
async def admin_delete_user(
    target_user_id: str,
    user: Dict[str, Any] = Depends(require_role("admin")),
) -> JSONResponse:
    if target_user_id == user["id"]:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
    ok = await db.delete_user(target_user_id)
    if not ok:
        raise HTTPException(status_code=404, detail="User not found")
    return JSONResponse({"ok": True})


@app.put("/api/admin/users/{target_user_id}/password")
async def admin_reset_password(
    target_user_id: str,
    req: ResetPasswordRequest,
    user: Dict[str, Any] = Depends(require_role("admin")),
) -> JSONResponse:
    if not req.password or len(req.password) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters")
    hashed = hash_password(req.password)
    ok = await db.update_user_password(target_user_id, hashed)
    if not ok:
        raise HTTPException(status_code=404, detail="User not found")
    return JSONResponse({"ok": True})


@app.put("/api/admin/users/{target_user_id}/quota")
async def admin_update_quota(
    target_user_id: str,
    req: UpdateQuotaRequest,
    user: Dict[str, Any] = Depends(require_role("admin")),
) -> JSONResponse:
    if req.quota < -1:
        raise HTTPException(status_code=400, detail="Quota must be -1 (unlimited) or >= 0")
    ok = await db.update_user_quota(target_user_id, req.quota)
    if not ok:
        raise HTTPException(status_code=404, detail="User not found")
    return JSONResponse({"ok": True})


# ---------------------------------------------------------------------------
# Auth helper for checking analysis ownership
# ---------------------------------------------------------------------------

async def _check_analysis_access(
    state: Optional[Dict[str, Any]],
    user: Dict[str, Any],
    program_hash: str,
) -> None:
    """Raise 403 if user doesn't own the analysis and isn't admin."""
    if state is None:
        return  # Will be handled as 404 by caller
    if is_admin(user):
        return
    state_user = state.get("user_id")
    if state_user and state_user != user["id"]:
        raise HTTPException(status_code=403, detail="Access denied")


async def _check_quota(user: Dict[str, Any]) -> None:
    """Raise 403 if user has exceeded their analysis quota."""
    if is_admin(user):
        return  # admins are unlimited
    quota = user.get("quota", 10)
    if quota == -1:
        return  # unlimited
    used = await db.get_user_analysis_count(user["id"])
    if used >= quota:
        raise HTTPException(
            status_code=403,
            detail=f"Analysis quota exceeded ({used}/{quota}). Contact admin to increase your quota.",
        )


class ConnectionManager:
    def __init__(self) -> None:
        self.connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, session_id: str, websocket: WebSocket) -> None:
        await websocket.accept()
        self.connections.setdefault(session_id, []).append(websocket)

    def disconnect(self, session_id: str, websocket: WebSocket) -> None:
        if session_id in self.connections:
            self.connections[session_id] = [ws for ws in self.connections[session_id] if ws != websocket]
            if not self.connections[session_id]:
                del self.connections[session_id]

    async def broadcast(self, session_id: str, payload: Dict[str, Any]) -> None:
        dead: List[WebSocket] = []
        for ws in self.connections.get(session_id, []):
            try:
                await ws.send_json(payload)
            except Exception:
                dead.append(ws)
        if dead and session_id in self.connections:
            self.connections[session_id] = [ws for ws in self.connections[session_id] if ws not in dead]


manager = ConnectionManager()


@app.post("/analyze", response_model=SessionCreateResponse)
async def analyze(
    request: SessionCreateRequest,
    user: Dict[str, Any] = Depends(get_current_user),
) -> SessionCreateResponse:
    if not can_write(user):
        raise HTTPException(status_code=403, detail="Guests cannot start analyses")
    await _check_quota(user)
    if not request.binary_path:
        raise HTTPException(status_code=400, detail="binary_path required unless using upload")
    state = store.create_session(request.binary_path)
    state["user_id"] = user["id"]
    if request.model:
        state["llm_model"] = request.model
    _create_tracked_task(_run_with_events(state))
    return SessionCreateResponse(session_id=state["session_id"])


@app.post("/analyze/upload", response_model=SessionCreateResponse)
async def analyze_upload(
    file: UploadFile = File(...),
    model: Optional[str] = Form(None),
    user: Dict[str, Any] = Depends(get_current_user),
    _rate: None = Depends(upload_limit),
) -> SessionCreateResponse:
    if not can_write(user):
        raise HTTPException(status_code=403, detail="Guests cannot upload files")
    await _check_quota(user)
    try:
        shared_root = Path(settings.ghidra_shared_root)
        ensure_directory(shared_root)
        filename = file.filename or "upload"
        target_path = shared_root / safe_basename(filename)
        contents = await file.read()
        if len(contents) == 0:
            raise HTTPException(status_code=400, detail="Uploaded file is empty")
        if len(contents) > settings.max_upload_bytes:
            raise HTTPException(
                status_code=413,
                detail=f"File too large ({len(contents)} bytes). Max allowed: {settings.max_upload_bytes} bytes.",
            )
        target_path.write_bytes(contents)
        logger.info("upload_saved", path=str(target_path), size=len(contents))
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("upload_failed", error=str(exc), exc_info=exc)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to save uploaded file: {exc}",
        )
    state = store.create_session(str(target_path))
    state["user_id"] = user["id"]
    if model:
        state["llm_model"] = model
    _create_tracked_task(_run_with_events(state))
    return SessionCreateResponse(session_id=state["session_id"])


@app.get("/status/{session_id}", response_model=StatusResponse)
async def status(
    session_id: str,
    user: Dict[str, Any] = Depends(get_current_user),
) -> StatusResponse:
    try:
        state = store.get_session(session_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Session not found: {session_id}")
    await _check_analysis_access(state, user, "")
    response_state = dict(state)
    response_state.pop("progress_callback", None)
    # Merge per-analyzer traces so consumers of reasoning_trace see live progress
    merged_trace: list[str] = []
    merged_trace.extend(response_state.get("ghidra_trace", []))
    merged_trace.extend(response_state.get("r2_trace", []))
    merged_trace.extend(response_state.get("qiling_trace", []))
    merged_trace.extend(response_state.get("reasoning_trace", []))
    response_state["reasoning_trace"] = merged_trace
    return StatusResponse(session_id=session_id, status=state["status"], state=response_state)


@app.post("/query")
async def query(
    request: QueryRequest,
    user: Dict[str, Any] = Depends(get_current_user),
    _rate: None = Depends(query_limit),
) -> JSONResponse:
    """Answer follow-up questions using existing analysis context (no re-analysis)."""
    if not can_write(user):
        raise HTTPException(status_code=403, detail="Guests cannot query")
    try:
        state = store.get_session(request.session_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Session not found: {request.session_id}")
    await _check_analysis_access(state, user, "")

    if state.get("status") != "completed":
        return JSONResponse(
            {"ok": False, "error": f"Analysis not yet completed (status: {state.get('status')})"},
            status_code=400,
        )

    # Build context from existing analysis data (tight limits for follow-up query)
    context = build_analysis_context(
        state,
        string_limit=40,
        func_limit=30,
        ghidra_decomp_limit=5,
        r2_decomp_limit=5,
        decomp_chars=1200,
        truncate_decomp=True,
        include_investigation=False,
    )

    # Include previous analysis summary for continuity
    prev_summary = state.get("summary", "")

    # Include memory context (similar previous analyses, patterns)
    try:
        from ghidra_agent.memory import get_memory_manager
        memory = get_memory_manager()
        memory_context = memory.get_context_for_prompt(
            program_hash=state.get("program_hash"),
            max_project_length=2000,
            max_episodic_entries=2,
        )
        if memory_context:
            context += "\n\n=== ANALYSIS PATTERNS & SIMILAR CASES ===\n" + memory_context[:3000]
    except Exception as exc:
        logger.warning("memory_context_fetch_failed", error=str(exc))

    prompt = f"""You are a malware analyst answering a follow-up question about a binary you already analyzed.

PREVIOUS ANALYSIS SUMMARY (for context):
{prev_summary[:8000]}

RAW ANALYSIS DATA:
{context[:16000]}

Binary hash: {state.get('program_hash', 'unknown')}

USER QUESTION: {request.query}

INSTRUCTIONS:
- Answer ONLY the user's specific question. Do NOT repeat the full report.
- Be concise and direct. A few sentences or a short paragraph is ideal.
- Reference specific function names, addresses, and code when relevant.
- If the data doesn't contain enough information to answer, say so clearly.
- Do NOT produce section headers like "Executive Summary" or numbered sections unless the user asks for a report."""

    try:
        logger.info("query_start", session_id=request.session_id, query=request.query[:200])
        lf_meta = create_standalone_trace_metadata(
            session_id=request.session_id,
            trace_name="follow-up-query",
            generation_name="query",
            program_hash=state.get("program_hash", ""),
        )
        result = await call_llm(prompt, metadata=lf_meta or None, model=request.model)
        answer = result.get("content", "")
        reasoning = result.get("reasoning_content", "")
        logger.info("query_complete", session_id=request.session_id, answer_len=len(answer))

        # Store the Q&A in reasoning trace for history
        state.setdefault("qa_history", []).append({
            "question": request.query,
            "answer": answer,
            "reasoning": reasoning,  # Store reasoning for context
        })
        store.update_session(request.session_id, state)
        # Persist Q&A to DB
        try:
            await db.save_qa(request.session_id, request.query, answer)
        except Exception:
            pass

        return JSONResponse({
            "ok": True,
            "session_id": request.session_id,
            "status": "completed",
            "answer": answer,
            "reasoning": reasoning,  # Include reasoning in response
        })
    except Exception as exc:
        logger.error("query_failed", session_id=request.session_id, error=str(exc), exc_info=exc)
        return JSONResponse(
            {"ok": False, "error": str(exc)},
            status_code=500,
        )


@app.post("/query_with_tools")
async def query_with_tools(
    request: QueryRequest,
    user: Dict[str, Any] = Depends(get_current_user),
) -> JSONResponse:
    """Answer follow-up questions with GLM-5 function calling support.

    The LLM can dynamically invoke radare2 tools to perform additional analysis
    beyond the cached data in the session state.
    """
    if not can_write(user):
        raise HTTPException(status_code=403, detail="Guests cannot query")

    try:
        state = store.get_session(request.session_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Session not found: {request.session_id}")
    await _check_analysis_access(state, user, "")

    if state.get("status") != "completed":
        return JSONResponse(
            {"ok": False, "error": f"Analysis not yet completed (status: {state.get('status')})"},
            status_code=400,
        )

    # Build minimal context (lighter than /query since tools can fetch more data)
    context_parts = []
    results = state.get("analysis_results", {})
    binary = results.get("binary", {})
    if binary.get("ok"):
        context_parts.append(f"Architecture: {binary.get('architecture')}, Image base: {binary.get('image_base')}")
        context_parts.append(f"Binary hash: {state.get('program_hash', 'unknown')}")
        context_parts.append(f"Binary path: {state.get('binary_path', 'unknown')}")

    # Build context for tool executor
    program_hash = state.get("program_hash", "")
    binary_path = state.get("binary_path", "")
    session_id = request.session_id

    # Create tool executor that injects session context
    from ghidra_agent.glm_function_tools import get_tool_registry

    registry = get_tool_registry()

    async def tool_executor_with_context(tool_name: str, arguments: Dict[str, Any]) -> Any:
        """Execute tool with session context injected."""
        # Inject common context parameters
        if "session_id" not in arguments:
            arguments["session_id"] = session_id
        if "program_hash" not in arguments and program_hash:
            arguments["program_hash"] = program_hash
        if "binary_path" not in arguments and binary_path:
            arguments["binary_path"] = binary_path

        return await registry.execute_tool(tool_name, arguments)

    # Build prompt
    prev_summary = state.get("summary", "")
    context = "\n".join(context_parts) if context_parts else "No analysis data available."

    prompt = f"""You are a malware analyst with access to binary analysis tools. The user has a question about a binary.

BINARY CONTEXT:
{context}

PREVIOUS ANALYSIS SUMMARY:
{prev_summary[:4000]}

USER QUESTION: {request.query}

AVAILABLE TOOLS:
- r2_analyze_binary: Get binary structure (architecture, sections, imports, exports)
- r2_list_functions: List all functions with addresses and sizes
- r2_build_call_graph: Build inter-procedural call graph
- r2_decompile_function: Decompile a specific function by name or address
- r2_disassemble_at: Disassemble code at a specific address
- r2_find_strings: Find all strings in the binary
- r2_find_xrefs: Find cross-references to an address
- r2_search_bytes: Search for byte patterns
- r2_syscall_analysis: Detect syscalls in the binary
- search_functions: Search previously analyzed functions by name
- get_decompilation: Get cached decompilation for a function

INSTRUCTIONS:
- Use tools when you need specific data that's not in the context
- Be concise and direct in your answers
- Reference specific function names, addresses, and code
- If a tool fails, explain the error and suggest alternatives
- You can chain multiple tool calls to gather comprehensive information"""

    try:
        logger.info("query_with_tools_start", session_id=request.session_id, query=request.query[:200])
        lf_meta = create_standalone_trace_metadata(
            session_id=request.session_id,
            trace_name="follow-up-query-with-tools",
            generation_name="query_with_tools",
            program_hash=program_hash,
        )

        # Get tools and executor
        from ghidra_agent.llm import get_function_calling_tools
        tools = get_function_calling_tools()

        result = await call_llm(
            prompt,
            metadata=lf_meta or None,
            tools=tools,
            tool_executor=tool_executor_with_context,
            model=request.model,
        )

        answer = result.get("content", "")
        reasoning = result.get("reasoning_content", "")
        tool_calls = result.get("tool_calls", [])
        tool_results = result.get("tool_results", [])

        logger.info(
            "query_with_tools_complete",
            session_id=request.session_id,
            answer_len=len(answer),
            tool_calls_count=len(tool_calls),
        )

        # Store the Q&A with tool call information
        state.setdefault("qa_history", []).append({
            "question": request.query,
            "answer": answer,
            "reasoning": reasoning,
            "tool_calls": tool_calls,
            "tool_results": tool_results,
        })
        store.update_session(request.session_id, state)

        # Persist Q&A to DB
        try:
            await db.save_qa(request.session_id, request.query, answer)
        except Exception:
            pass

        return JSONResponse({
            "ok": True,
            "session_id": request.session_id,
            "status": "completed",
            "answer": answer,
            "reasoning": reasoning,
            "tool_calls": tool_calls,
            "tool_results": tool_results,
        })
    except Exception as exc:
        logger.error("query_with_tools_failed", session_id=request.session_id, error=str(exc), exc_info=exc)
        return JSONResponse(
            {"ok": False, "error": str(exc)},
            status_code=500,
        )


@app.websocket("/stream/{session_id}")
async def stream(session_id: str, websocket: WebSocket) -> None:
    # Validate JWT from query param — required for security
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=4001, reason="Token required")
        return
    try:
        from ghidra_agent.auth import decode_token
        decode_token(token)
    except Exception:
        await websocket.close(code=4001, reason="Invalid token")
        return
    await manager.connect(session_id, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(session_id, websocket)


def _task_done_callback(task: asyncio.Task) -> None:
    if task.cancelled():
        return
    exc = task.exception()
    if exc is not None:
        logger.error("background_task_failed", error=str(exc), exc_info=exc)


def _create_tracked_task(coro) -> asyncio.Task:
    task = asyncio.create_task(coro)
    task.add_done_callback(_task_done_callback)
    return task


async def _run_with_events(state: Dict[str, Any]) -> None:
    session_id = state["session_id"]
    try:
        state.setdefault("analyzer_progress", {"ghidra": 0, "radare2": 0, "qiling": 0})
        state.setdefault("analyzer_status", {"ghidra": "pending", "radare2": "pending", "qiling": "pending"})
        state.setdefault("analyzer_step", {"ghidra": "", "radare2": "", "qiling": ""})
        state["started_at"] = time.time()
        state["started_at_iso"] = datetime.now(timezone.utc).isoformat()
        store.update_session(session_id, state)
        await manager.broadcast(
            session_id,
            {
                "type": "analysis:progress",
                "session_id": session_id,
                "payload": {
                    "status": "started",
                    "analyzer_progress": state.get("analyzer_progress", {}),
                    "analyzer_status": state.get("analyzer_status", {}),
                    "analyzer_step": state.get("analyzer_step", {}),
                },
            },
        )
        await manager.broadcast(session_id, {"type": "message:typing", "session_id": session_id, "payload": {"status": "running"}})
        async def on_progress(step: str, pct: int) -> None:
            safe_pct = max(0, min(100, int(pct)))
            state["current_step"] = step
            state["progress"] = safe_pct
            store.update_session(session_id, state)
            await manager.broadcast(
                session_id,
                {
                    "type": "analysis:progress",
                    "session_id": session_id,
                    "payload": {
                        "status": "running",
                        "step": step,
                        "progress": safe_pct,
                        "analyzer_progress": state.get("analyzer_progress", {}),
                        "analyzer_status": state.get("analyzer_status", {}),
                        "analyzer_step": state.get("analyzer_step", {}),
                    },
                },
            )

        result = await run_graph(state, progress_callback=on_progress)
        result["completed_at"] = time.time()
        result["completed_at_iso"] = datetime.now(timezone.utc).isoformat()
        result["duration_seconds"] = round(result["completed_at"] - result.get("started_at", result["completed_at"]), 1)
        store.update_session(session_id, result)
        # Persist verdict to DB
        try:
            iocs = extract_iocs_from_state(result)
            verdict, _, _, score = calculate_verdict(iocs, result)
            await db.save_verdict(session_id, verdict, score)
        except Exception:
            pass
        # Persist normalized data (functions, strings, decompilations, etc.)
        try:
            await db.save_normalized(result)
        except Exception as norm_exc:
            logger.warning("save_normalized_failed", session_id=session_id, error=str(norm_exc))
        # Persist analysis report to QA history so it survives page refreshes
        try:
            summary = result.get("summary", "")
            if summary:
                await db.save_qa(session_id, "Analyze this binary", summary)
        except Exception:
            pass
        await manager.broadcast(
            session_id,
            {
                "type": "analysis:completed",
                "session_id": session_id,
                "payload": {
                    "status": result["status"],
                    "analyzer_progress": result.get("analyzer_progress", {}),
                    "analyzer_status": result.get("analyzer_status", {}),
                    "analyzer_step": result.get("analyzer_step", {}),
                },
            },
        )
    except Exception as exc:
        logger.error("run_with_events_failed", session_id=session_id, error=str(exc), exc_info=exc)
        state["status"] = "error"
        store.update_session(session_id, state)
        await manager.broadcast(
            session_id,
            {
                "type": "analysis:error",
                "session_id": session_id,
                "payload": {
                    "status": "error",
                    "error": str(exc),
                    "analyzer_progress": state.get("analyzer_progress", {}),
                    "analyzer_status": state.get("analyzer_status", {}),
                    "analyzer_step": state.get("analyzer_step", {}),
                },
            },
        )


# ---------------------------------------------------------------------------
# Helper: resolve the best session for a given program_hash
# Prefers the latest completed session; falls back to latest of any status.
# ---------------------------------------------------------------------------

_STATUS_PRIORITY = {"completed": 0, "error": 1, "initialized": 2}


def _pick_best_in_memory(candidates: List[Dict[str, Any]]) -> Dict[str, Any] | None:
    if not candidates:
        return None
    candidates.sort(
        key=lambda s: (
            _STATUS_PRIORITY.get(s.get("status", ""), 9),
            -(s.get("completed_at") or s.get("started_at") or 0),
        )
    )
    return candidates[0]


async def _resolve_by_hash(program_hash: str, user: Optional[Dict[str, Any]] = None) -> Dict[str, Any] | None:
    """Find the best session for a hash, preferring completed DB sessions.
    
    If user is provided and not admin, only return sessions owned by that user.
    """
    candidates = [
        s for s in store.sessions.values()
        if s.get("program_hash") == program_hash
    ]
    # Filter by user ownership (admin sees all)
    if user and not is_admin(user):
        candidates = [s for s in candidates if s.get("user_id") == user["id"]]
    best_in_memory = _pick_best_in_memory(candidates)
    if best_in_memory is not None and best_in_memory.get("status") == "completed":
        return best_in_memory

    try:
        best_db = await db.get_best_analysis_by_hash(program_hash)
    except Exception as exc:
        logger.warning(
            "analysis_hash_lookup_db_failed",
            program_hash=program_hash[:16],
            error=str(exc),
        )
        return best_in_memory

    if best_db is None:
        return best_in_memory

    session_id = str(best_db.get("id", ""))
    if not session_id:
        return best_in_memory
    if session_id in store.sessions:
        return store.sessions[session_id]

    try:
        return await store.load_session_from_db(session_id)
    except Exception as exc:
        logger.warning(
            "analysis_hash_restore_failed",
            session_id=session_id,
            error=str(exc),
        )
        return best_in_memory


@app.get("/api/analysis/{program_hash}")
async def analysis_status(
    program_hash: str,
    user: Dict[str, Any] = Depends(get_current_user),
) -> JSONResponse:
    state = await _resolve_by_hash(program_hash, user)
    if state is None:
        return JSONResponse({"hash": program_hash, "status": "not_found"}, status_code=404)
    duration_secs = state.get("duration_seconds", 0)
    if duration_secs:
        mins = int(duration_secs // 60)
        secs = int(duration_secs % 60)
        duration_str = f"{mins}m {secs}s" if mins else f"{secs}s"
    else:
        duration_str = ""
    started_iso = state.get("started_at_iso", "")
    completed_iso = state.get("completed_at_iso", "")
    active_analyzers: list[str] = []
    if state.get("analysis_results"):
        active_analyzers.append("ghidra")
    if state.get("r2_analysis_results"):
        active_analyzers.append("radare2")
    if state.get("qiling_analysis_results"):
        active_analyzers.append("qiling")
    if not active_analyzers:
        # Backward-compatible default while analysis is still warming up.
        active_analyzers = ["ghidra"]
    analyzer_label = active_analyzers[0] if len(active_analyzers) == 1 else "multi"

    # Compute verdict, malware type, and tags
    iocs = extract_iocs_from_state(state)
    verdict, _, indicators, score = calculate_verdict(iocs, state)
    mtype, mconf, _ = classify_malware_type(state)
    tags = build_analysis_tags(state)

    return JSONResponse({
        "hash": program_hash,
        "status": state["status"],
        "analyzer": analyzer_label,
        "analyzers": active_analyzers,
        "duration": duration_str,
        "started": started_iso,
        "completed": completed_iso,
        "verdict": verdict,
        "threatScore": score,
        "maxScore": 100,
        "malwareType": mtype if mtype != "Unknown" else None,
        "malwareTypeConfidence": mconf,
        "tags": tags,
        "indicators": indicators[:10],
        "summary": state.get("summary", ""),
    })


@app.get("/api/analysis/{program_hash}/analyzers")
async def analysis_analyzers(
    program_hash: str,
    user: Dict[str, Any] = Depends(get_current_user),
) -> JSONResponse:
    state = await _resolve_by_hash(program_hash, user)
    if state is None:
        return JSONResponse([], status_code=404)
    analyzers = [build_analyzer_response(state, "ghidra")]
    if state.get("r2_analysis_results"):
        analyzers.append(build_analyzer_response(state, "radare2"))
    if state.get("qiling_analysis_results"):
        analyzers.append(build_analyzer_response(state, "qiling"))
    return JSONResponse(analyzers)


@app.get("/api/analysis/{program_hash}/analyzers/{analyzer_id}")
async def analysis_analyzer_detail(
    program_hash: str,
    analyzer_id: str,
    user: Dict[str, Any] = Depends(get_current_user),
) -> JSONResponse:
    state = await _resolve_by_hash(program_hash, user)
    if state is None or analyzer_id not in ("ghidra", "radare2", "qiling"):
        return JSONResponse({"error": "not_found"}, status_code=404)
    return JSONResponse(build_analyzer_response(state, analyzer_id))


@app.get("/api/analysis/{program_hash}/files")
async def analysis_files(
    program_hash: str,
    user: Dict[str, Any] = Depends(get_current_user),
) -> JSONResponse:
    state = await _resolve_by_hash(program_hash, user)
    if state is None:
        return JSONResponse({"error": "not_found"}, status_code=404)
    return JSONResponse(build_file_tree(state))


@app.get("/api/analysis/{program_hash}/files/{file_id}")
async def analysis_file_content(
    program_hash: str,
    file_id: str,
    user: Dict[str, Any] = Depends(get_current_user),
) -> JSONResponse:
    state = await _resolve_by_hash(program_hash, user)
    if state is None:
        return JSONResponse({"error": "not_found"}, status_code=404)
    return JSONResponse(build_code_file(state, file_id))


@app.get("/api/analysis/{program_hash}/reports")
async def analysis_reports(
    program_hash: str,
    user: Dict[str, Any] = Depends(get_current_user),
) -> JSONResponse:
    state = await _resolve_by_hash(program_hash, user)
    if state is None:
        return JSONResponse([], status_code=404)
    return JSONResponse(build_reports(state))


@app.get("/api/analysis/{program_hash}/reports/{report_id}")
async def analysis_report_content(
    program_hash: str,
    report_id: str,
    user: Dict[str, Any] = Depends(get_current_user),
) -> JSONResponse:
    state = await _resolve_by_hash(program_hash, user)
    if state is None:
        return JSONResponse({"error": "not_found"}, status_code=404)
    return JSONResponse(build_report_content(state, report_id))


@app.get("/api/analysis/{program_hash}/similar")
async def analysis_similar(
    program_hash: str,
    user: Dict[str, Any] = Depends(get_current_user),
) -> JSONResponse:
    state = await _resolve_by_hash(program_hash, user)
    if state is None:
        return JSONResponse([], status_code=404)
    return JSONResponse(await build_similar_files(state))


@app.get("/api/analysis/{program_hash}/results/ghidra")
async def ghidra_results(
    program_hash: str,
    user: Dict[str, Any] = Depends(get_current_user),
) -> JSONResponse:
    """Return raw Ghidra analysis results (functions, strings, binary info, decompiled code)."""
    state = await _resolve_by_hash(program_hash, user)
    if state is None:
        return JSONResponse({"error": "not_found"}, status_code=404)
    gh = state.get("analysis_results", {})
    return JSONResponse({
        "analyzer": "ghidra",
        "binary": gh.get("binary", {}),
        "functions": gh.get("functions", {}),
        "strings": gh.get("strings", {}),
        "call_graph": gh.get("call_graph", {}),
        "call_graph_analysis": gh.get("call_graph_analysis", {}),
        "decompiled": state.get("decompilation_cache", {}),
    })


@app.get("/api/analysis/{program_hash}/results/radare2")
async def radare2_results(
    program_hash: str,
    user: Dict[str, Any] = Depends(get_current_user),
) -> JSONResponse:
    """Return raw Radare2 analysis results (functions, strings, binary info, decompiled code)."""
    state = await _resolve_by_hash(program_hash, user)
    if state is None:
        return JSONResponse({"error": "not_found"}, status_code=404)
    r2 = state.get("r2_analysis_results", {})
    if not r2:
        return JSONResponse({"error": "radare2 analysis not available"}, status_code=404)
    return JSONResponse({
        "analyzer": "radare2",
        "binary": r2.get("binary", {}),
        "functions": r2.get("functions", {}),
        "strings": r2.get("strings", {}),
        "call_graph": r2.get("call_graph", {}),
        "call_graph_analysis": r2.get("call_graph_analysis", {}),
        "decompiled": state.get("r2_decompilation_cache", {}),
    })


@app.get("/api/analysis/{program_hash}/results/qiling")
async def qiling_results(
    program_hash: str,
    user: Dict[str, Any] = Depends(get_current_user),
) -> JSONResponse:
    """Return raw Qiling dynamic analysis results."""
    state = await _resolve_by_hash(program_hash, user)
    if state is None:
        return JSONResponse({"error": "not_found"}, status_code=404)
    qiling = state.get("qiling_analysis_results", {})
    if not qiling:
        return JSONResponse({"error": "qiling analysis not available"}, status_code=404)
    return JSONResponse({
        "analyzer": "qiling",
        "execution_trace": qiling.get("execution_trace", {}),
        "syscalls": qiling.get("syscalls", {}),
        "api_calls": qiling.get("api_calls", {}),
        "memory_events": qiling.get("memory_events", {}),
        "network_activity": qiling.get("network_activity", {}),
        "evasion_techniques": qiling.get("evasion_techniques", {}),
        "instruction_trace": qiling.get("instruction_trace", {}),
        "errors": qiling.get("errors", []),
    })


@app.get("/api/analysis/{program_hash}/hex")
async def analysis_hex_dump(
    program_hash: str,
    address: str = "0x0",
    size: int = 256,
    user: Dict[str, Any] = Depends(get_current_user),
) -> JSONResponse:
    """Return a hex dump of the binary at the given address."""
    state = await _resolve_by_hash(program_hash, user)
    if state is None:
        return JSONResponse({"error": "not_found"}, status_code=404)
    binary_path = state.get("binary_path", "")
    if not binary_path:
        return JSONResponse({"error": "binary_path_missing"}, status_code=404)
    from ghidra_agent.r2_tools import get_runner
    runner = get_runner()
    safe_size = min(max(size, 16), 4096)
    cmd = f"s {address};px {safe_size}"
    result = await runner.run_command(Path(binary_path), cmd)
    if not result.ok:
        return JSONResponse({"error": result.error}, status_code=500)
    return JSONResponse({
        "address": address,
        "size": safe_size,
        "lines": result.payload.get("raw", "").splitlines(),
    })


@app.get("/api/analysis/{program_hash}/disassembly")
async def analysis_disassembly(
    program_hash: str,
    address: str = "",
    count: int = 32,
    user: Dict[str, Any] = Depends(get_current_user),
) -> JSONResponse:
    """Return disassembled instructions at the given address."""
    state = await _resolve_by_hash(program_hash, user)
    if state is None:
        return JSONResponse({"error": "not_found"}, status_code=404)
    binary_path = state.get("binary_path", "")
    if not binary_path:
        return JSONResponse({"error": "binary_path_missing"}, status_code=404)
    from ghidra_agent.r2_tools import get_runner
    runner = get_runner()
    safe_count = min(max(count, 1), 256)
    addr = address or "entry0"
    cmd = f"aa;s {addr};pdj {safe_count}"
    result = await runner.run_json_command(Path(binary_path), cmd)
    if not result.ok:
        return JSONResponse({"error": result.error}, status_code=500)
    instrs_raw = result.payload.get("json", [])
    instructions = []
    if isinstance(instrs_raw, list):
        for ins in instrs_raw:
            instructions.append({
                "address": hex(ins.get("offset", 0)),
                "mnemonic": ins.get("mnemonic", ""),
                "operands": ins.get("opcode", ""),
                "bytes": ins.get("bytes", ""),
                "size": ins.get("size", 0),
            })
    return JSONResponse({
        "address": addr,
        "count": safe_count,
        "instructions": instructions,
    })


@app.get("/api/models")
async def models() -> JSONResponse:
    return JSONResponse(build_model_list())


@app.get("/api/analysis/{program_hash}/export/html")
async def export_html(
    program_hash: str,
    user: Dict[str, Any] = Depends(get_current_user),
) -> HTMLResponse:
    """Export analysis report as HTML."""
    state = await _resolve_by_hash(program_hash, user)
    if state is None:
        return HTMLResponse("<h1>Report not found</h1>", status_code=404)
    html = build_report_html(state)
    return HTMLResponse(content=html, headers={
        "Content-Disposition": f'attachment; filename="report_{program_hash[:16]}.html"'
    })


@app.get("/api/analysis/{program_hash}/view/html")
async def view_html(
    program_hash: str,
    user: Dict[str, Any] = Depends(get_current_user),
) -> HTMLResponse:
    """Return the HTML report for inline viewing (no attachment disposition)."""
    state = await _resolve_by_hash(program_hash, user)
    if state is None:
        return HTMLResponse("<h1>Report not found</h1>", status_code=404)
    html = build_report_html(state)
    return HTMLResponse(content=html)


@app.get("/api/analysis/{program_hash}/export/text")
async def export_text(
    program_hash: str,
    user: Dict[str, Any] = Depends(get_current_user),
) -> PlainTextResponse:
    """Export analysis report as plain text."""
    state = await _resolve_by_hash(program_hash, user)
    if state is None:
        return PlainTextResponse("Report not found", status_code=404)
    text = build_report_text(state)
    return PlainTextResponse(content=text, headers={
        "Content-Disposition": f'attachment; filename="report_{program_hash[:16]}.txt"'
    })


@app.get("/export/session/{session_id}/html")
async def export_session_html(
    session_id: str,
    user: Dict[str, Any] = Depends(get_current_user),
) -> HTMLResponse:
    """Export session report as HTML (convenience endpoint)."""
    try:
        state = store.get_session(session_id)
        html = build_report_html(state)
        program_hash = state.get("program_hash", "unknown")
        return HTMLResponse(content=html, headers={
            "Content-Disposition": f'attachment; filename="report_{program_hash[:16]}.html"'
        })
    except KeyError:
        return HTMLResponse("<h1>Session not found</h1>", status_code=404)


@app.get("/export/session/{session_id}/agent/{agent}")
async def export_session_agent_html(
    session_id: str,
    agent: str,
    user: Dict[str, Any] = Depends(get_current_user),
) -> HTMLResponse:
    """Export per-agent report (ghidra, r2/radare2, or qiling)."""
    if agent.lower() not in ("ghidra", "r2", "radare2", "qiling"):
        return HTMLResponse("<h1>Invalid agent. Use 'ghidra', 'r2', or 'qiling'.</h1>", status_code=400)
    try:
        state = store.get_session(session_id)
        html = build_agent_report_html(state, agent)
        program_hash = state.get("program_hash", "unknown")
        return HTMLResponse(content=html, headers={
            "Content-Disposition": f'attachment; filename="report_{agent}_{program_hash[:16]}.html"'
        })
    except KeyError:
        return HTMLResponse("<h1>Session not found</h1>", status_code=404)


@app.get("/export/session/{session_id}/text")
async def export_session_text(
    session_id: str,
    user: Dict[str, Any] = Depends(get_current_user),
) -> PlainTextResponse:
    """Export session report as plain text (convenience endpoint)."""
    try:
        state = store.get_session(session_id)
        text = build_report_text(state)
        program_hash = state.get("program_hash", "unknown")
        return PlainTextResponse(content=text, headers={
            "Content-Disposition": f'attachment; filename="report_{program_hash[:16]}.txt"'
        })
    except KeyError:
        return PlainTextResponse("Session not found", status_code=404)


@app.get("/api/analysis/{program_hash}/export/pdf")
async def export_pdf(
    program_hash: str,
    user: Dict[str, Any] = Depends(get_current_user),
) -> Response:
    """Export analysis report as A4 PDF."""
    state = await _resolve_by_hash(program_hash, user)
    if state is None:
        return PlainTextResponse("Report not found", status_code=404)
    try:
        pdf_bytes = await build_report_pdf(state)
    except Exception as e:
        logger.error("PDF generation failed: %s", e)
        return PlainTextResponse(f"PDF generation failed: {e}", status_code=500)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="report_{program_hash[:16]}.pdf"'},
    )


@app.get("/export/session/{session_id}/pdf")
async def export_session_pdf(
    session_id: str,
    user: Dict[str, Any] = Depends(get_current_user),
) -> Response:
    """Export session report as A4 PDF (convenience endpoint)."""
    try:
        state = store.get_session(session_id)
    except KeyError:
        return PlainTextResponse("Session not found", status_code=404)
    try:
        pdf_bytes = await build_report_pdf(state)
    except Exception as e:
        logger.error("PDF generation failed: %s", e)
        return PlainTextResponse(f"PDF generation failed: {e}", status_code=500)
    program_hash = state.get("program_hash", "unknown")
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="report_{program_hash[:16]}.pdf"'},
    )


# ---------------------------------------------------------------------------
# History / Past Analysis Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/history")
async def list_history(
    limit: int = 50,
    offset: int = 0,
    status: str = "",
    search: str = "",
    user: Dict[str, Any] = Depends(get_current_user),
) -> JSONResponse:
    """List past analyses with pagination and optional filters."""
    uid = None if is_admin(user) else user["id"]
    analyses = await db.list_analyses(
        limit=min(limit, 200),
        offset=offset,
        status=status or None,
        search=search or None,
        user_id=uid,
    )
    total = await db.get_analysis_count(
        status=status or None,
        search=search or None,
        user_id=uid,
    )
    return JSONResponse({
        "items": analyses,
        "total": total,
        "limit": limit,
        "offset": offset,
    })


@app.get("/api/history/{session_id}")
async def get_history_item(
    session_id: str,
    user: Dict[str, Any] = Depends(get_current_user),
) -> JSONResponse:
    """Get a single past analysis summary (without full state)."""
    item = await db.get_analysis_by_id(session_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Analysis not found")
    # Don't send the full state blob in the summary endpoint
    item.pop("state_json", None)
    return JSONResponse(item)


@app.get("/api/history/{session_id}/qa")
async def get_history_qa(
    session_id: str,
    user: Dict[str, Any] = Depends(get_current_user),
) -> JSONResponse:
    """Get Q&A history for a past analysis session."""
    qa = await db.get_qa_history(session_id)
    return JSONResponse(qa)


@app.get("/api/history/{session_id}/messages")
async def get_history_messages(
    session_id: str,
    user: Dict[str, Any] = Depends(get_current_user),
) -> JSONResponse:
    """Get full chat message thread for a past analysis session."""
    messages = await db.get_chat_messages(session_id)
    return JSONResponse(messages)


@app.post("/api/history/{session_id}/messages")
async def save_history_message(
    session_id: str,
    role: str,
    content: str,
    msg_type: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    user: Dict[str, Any] = Depends(get_current_user),
) -> JSONResponse:
    """Save a chat message to the conversation thread."""
    await db.save_chat_message(session_id, role, content, msg_type, metadata)
    return JSONResponse({"ok": True})


@app.post("/api/history/{session_id}/restore")
async def restore_session(
    session_id: str,
    user: Dict[str, Any] = Depends(get_current_user),
) -> JSONResponse:
    """Restore a past session into memory so it can be queried again."""
    # Check if already in memory
    if session_id in store.sessions:
        state = store.sessions[session_id]
        return JSONResponse({
            "ok": True,
            "session_id": session_id,
            "program_hash": state.get("program_hash", ""),
            "status": state.get("status", ""),
        })
    try:
        state = await store.load_session_from_db(session_id)
        return JSONResponse({
            "ok": True,
            "session_id": session_id,
            "program_hash": state.get("program_hash", ""),
            "status": state.get("status", ""),
        })
    except KeyError:
        raise HTTPException(status_code=404, detail="Session not found in database")


@app.delete("/api/history/{session_id}")
async def delete_history_item(
    session_id: str,
    user: Dict[str, Any] = Depends(get_current_user),
) -> JSONResponse:
    """Delete a past analysis from the database."""
    if not can_write(user):
        raise HTTPException(status_code=403, detail="Guests cannot delete analyses")
    deleted = await db.delete_analysis(session_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Analysis not found")
    # Also remove from in-memory store if present
    store.sessions.pop(session_id, None)
    return JSONResponse({"ok": True})


# ---------------------------------------------------------------------------
# Cross-analysis query endpoints (normalized tables)
# ---------------------------------------------------------------------------

@app.get("/api/query/functions")
async def query_functions(
    name: str = "",
    analyzer: str = "",
    limit: int = 100,
    user: Dict[str, Any] = Depends(get_current_user),
) -> JSONResponse:
    """Search functions across all analyzed binaries."""
    results = await db.search_functions(
        name_pattern=name or None,
        analyzer=analyzer or None,
        limit=limit,
    )
    return JSONResponse({"items": results, "total": len(results)})


@app.get("/api/query/strings")
async def query_strings(
    pattern: str = "",
    limit: int = 100,
    user: Dict[str, Any] = Depends(get_current_user),
) -> JSONResponse:
    """Full-text search strings across all binaries."""
    if not pattern:
        return JSONResponse({"items": [], "total": 0})
    results = await db.search_strings_across(pattern, limit=limit)
    return JSONResponse({"items": results, "total": len(results)})


@app.get("/api/query/iocs")
async def query_iocs(
    ioc_type: str = "",
    value: str = "",
    limit: int = 100,
    user: Dict[str, Any] = Depends(get_current_user),
) -> JSONResponse:
    """Search IOCs across all binaries."""
    results = await db.search_iocs(
        ioc_type=ioc_type or None,
        value_pattern=value or None,
        limit=limit,
    )
    return JSONResponse({"items": results, "total": len(results)})


@app.get("/api/binary/{program_hash}/functions")
async def binary_functions(
    program_hash: str,
    analyzer: str = "",
    user: Dict[str, Any] = Depends(get_current_user),
) -> JSONResponse:
    """Get all functions for a specific binary."""
    results = await db.get_binary_functions(program_hash, analyzer=analyzer or None)
    return JSONResponse({"items": results, "total": len(results)})


@app.get("/api/binary/{program_hash}/decompilations")
async def binary_decompilations(
    program_hash: str,
    analyzer: str = "",
    user: Dict[str, Any] = Depends(get_current_user),
) -> JSONResponse:
    """Get all decompiled functions for a specific binary."""
    results = await db.get_binary_decompilations(program_hash, analyzer=analyzer or None)
    return JSONResponse({"items": results, "total": len(results)})


@app.get("/api/binary/{program_hash}/iocs")
async def binary_iocs(
    program_hash: str,
    user: Dict[str, Any] = Depends(get_current_user),
) -> JSONResponse:
    """Get IOCs for a specific binary."""
    results = await db.get_binary_iocs(program_hash)
    return JSONResponse({"items": results, "total": len(results)})


@app.get("/api/binary/{program_hash}/attack-chains")
async def binary_attack_chains(
    program_hash: str,
    user: Dict[str, Any] = Depends(get_current_user),
) -> JSONResponse:
    """Get attack chains for a specific binary."""
    results = await db.get_binary_attack_chains(program_hash)
    return JSONResponse({"items": results, "total": len(results)})
