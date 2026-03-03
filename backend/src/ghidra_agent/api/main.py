import asyncio
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from fastapi import FastAPI, File, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response

from ghidra_agent import database as db
from ghidra_agent.config import settings
from ghidra_agent.ioc_extractor import calculate_verdict, classify_malware_type, build_analysis_tags, extract_iocs_from_state, format_iocs_for_report
from ghidra_agent.langfuse_tracing import create_standalone_trace_metadata
from ghidra_agent.llm import call_llm
from ghidra_agent.logging import configure_logging, logger
from ghidra_agent.models import (
    QueryRequest,
    SessionCreateRequest,
    SessionCreateResponse,
    StatusResponse,
    WriteModeRequest,
)
from ghidra_agent.reporting import build_agent_report_html, build_report_html, build_report_pdf, build_report_text
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
    # Startup: nothing needed (pool is lazy)
    yield
    # Shutdown: close DB pool
    await db.close_db()


app = FastAPI(title="Ghidra Reverse Engineering Agent", lifespan=lifespan)

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
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?",  # catch any localhost port
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


def _to_num(value: Any) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return 0.0
    return 0.0


def _function_priority_key(func: Dict[str, Any]) -> tuple[float, float, float, str]:
    score = _to_num(func.get("priority_score"))
    if score <= 0.0:
        score = _to_num(func.get("xrefs")) * 100.0 + _to_num(func.get("size"))
    return (
        score,
        _to_num(func.get("xrefs")),
        _to_num(func.get("size")),
        str(func.get("name", "")),
    )


@app.get("/health")
async def health() -> JSONResponse:
    """Health check endpoint."""
    return JSONResponse({"status": "ok", "sessions": len(store.sessions)})


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
async def analyze(request: SessionCreateRequest) -> SessionCreateResponse:
    if not request.binary_path:
        raise HTTPException(status_code=400, detail="binary_path required unless using upload")
    state = store.create_session(request.binary_path)
    _create_tracked_task(_run_with_events(state))
    return SessionCreateResponse(session_id=state["session_id"])


@app.post("/analyze/upload", response_model=SessionCreateResponse)
async def analyze_upload(file: UploadFile = File(...)) -> SessionCreateResponse:
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
    _create_tracked_task(_run_with_events(state))
    return SessionCreateResponse(session_id=state["session_id"])


@app.get("/status/{session_id}", response_model=StatusResponse)
async def status(session_id: str) -> StatusResponse:
    try:
        state = store.get_session(session_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Session not found: {session_id}")
    response_state = dict(state)
    response_state.pop("progress_callback", None)
    return StatusResponse(session_id=session_id, status=state["status"], state=response_state)


@app.post("/query")
async def query(request: QueryRequest) -> JSONResponse:
    """Answer follow-up questions using existing analysis context (no re-analysis)."""
    try:
        state = store.get_session(request.session_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Session not found: {request.session_id}")

    if state.get("status") != "completed":
        return JSONResponse(
            {"ok": False, "error": f"Analysis not yet completed (status: {state.get('status')})"},
            status_code=400,
        )

    # Build context from existing analysis data (same as synthesize node)
    context_parts = []
    results = state.get("analysis_results", {})
    binary = results.get("binary", {})
    if binary.get("ok"):
        context_parts.append(f"Architecture: {binary.get('architecture')}, Image base: {binary.get('image_base')}")
        if binary.get("entry_points"):
            context_parts.append(f"Entry points: {', '.join(binary.get('entry_points', []))}")
        if binary.get("imports"):
            context_parts.append(f"Ghidra Imports: {', '.join(binary.get('imports', [])[:30])}")
        if binary.get("exports"):
            context_parts.append(f"Ghidra Exports: {', '.join(binary.get('exports', [])[:30])}")

    funcs = results.get("functions", {})
    if funcs.get("ok") and funcs.get("functions"):
        sorted_funcs = sorted(funcs["functions"], key=_function_priority_key, reverse=True)
        func_desc = [
            f"{f.get('name')}(score:{f.get('priority_score', 0)},xrefs:{f.get('xrefs', 0)},size:{f.get('size', 0)})"
            for f in sorted_funcs[:50]
        ]
        context_parts.append(f"Functions ({len(funcs['functions'])} total): {', '.join(func_desc)}")

    gh_call_graph = results.get("call_graph", {})
    gh_call_graph_analysis = results.get("call_graph_analysis", {})
    if gh_call_graph.get("ok"):
        context_parts.append(
            f"Ghidra Call Graph: nodes={len(gh_call_graph.get('nodes', []))}, edges={len(gh_call_graph.get('edges', []))}"
        )
    if gh_call_graph_analysis.get("ok"):
        chains = gh_call_graph_analysis.get("chains", [])
        if chains:
            chain_desc = [
                f"[{c.get('category', 'Unknown')}] {' -> '.join(str(p) for p in c.get('path', []))}"
                for c in chains[:12]
            ]
            context_parts.append(f"Ghidra Attack Chains ({len(chains)}): " + " | ".join(chain_desc))

    strings_data = results.get("strings", {})
    if strings_data.get("ok") and strings_data.get("strings"):
        str_vals = [s.get("value", str(s)) if isinstance(s, dict) else str(s) for s in strings_data["strings"][:50]]
        context_parts.append(f"Strings ({len(strings_data['strings'])} total): {', '.join(str_vals)}")

    decomp_cache = state.get("decompilation_cache", {})
    if decomp_cache:
        context_parts.append(f"\n=== GHIDRA DECOMPILED CODE ({len(decomp_cache)} functions) ===")
        for func_name, c_code in list(decomp_cache.items())[:25]:
            context_parts.append(f"\n--- {func_name} ---\n{c_code[:4000]}")

    r2_results = state.get("r2_analysis_results", {})
    r2_decomp = state.get("r2_decompilation_cache", {})
    if r2_results:
        r2_binary = r2_results.get("binary", {})
        if r2_binary.get("ok"):
            context_parts.append(f"\nR2 Binary: arch={r2_binary.get('architecture')}, bits={r2_binary.get('bits')}, os={r2_binary.get('os')}")
            if r2_binary.get("imports"):
                context_parts.append(f"R2 Imports: {', '.join(r2_binary['imports'][:30])}")
            if r2_binary.get("exports"):
                context_parts.append(f"R2 Exports: {', '.join(r2_binary['exports'][:30])}")
        r2_call_graph = r2_results.get("call_graph", {})
        r2_call_graph_analysis = r2_results.get("call_graph_analysis", {})
        if r2_call_graph.get("ok"):
            context_parts.append(
                f"R2 Call Graph: nodes={len(r2_call_graph.get('nodes', []))}, edges={len(r2_call_graph.get('edges', []))}"
            )
        if r2_call_graph_analysis.get("ok"):
            chains = r2_call_graph_analysis.get("chains", [])
            if chains:
                chain_desc = [
                    f"[{c.get('category', 'Unknown')}] {' -> '.join(str(p) for p in c.get('path', []))}"
                    for c in chains[:12]
                ]
                context_parts.append(f"R2 Attack Chains ({len(chains)}): " + " | ".join(chain_desc))
        r2_syscalls = r2_results.get("syscalls", {})
        if r2_syscalls.get("ok") and r2_syscalls.get("syscalls"):
            syscall_desc = [f"{s.get('name')}#{s.get('number')}" for s in r2_syscalls.get("syscalls", [])[:30]]
            context_parts.append(f"R2 Syscalls ({len(r2_syscalls.get('syscalls', []))} total): {', '.join(syscall_desc)}")
    if r2_decomp:
        context_parts.append(f"\n=== R2 DECOMPILED CODE ({len(r2_decomp)} functions) ===")
        for func_name, c_code in list(r2_decomp.items())[:25]:
            context_parts.append(f"\n--- {func_name} ---\n{c_code[:4000]}")

    qiling_results = state.get("qiling_analysis_results", {})
    if qiling_results:
        context_parts.append("\n=== QILING DYNAMIC ANALYSIS ===")
        execution = qiling_results.get("execution_trace", {})
        if isinstance(execution, dict) and execution:
            context_parts.append(
                "Execution: "
                f"success={execution.get('success')}, os={execution.get('os')}, "
                f"arch={execution.get('arch')}, instructions={execution.get('instructions_executed')}, "
                f"exit={execution.get('exit_reason')}"
            )
        syscalls = qiling_results.get("syscalls", {})
        if isinstance(syscalls, dict) and syscalls:
            context_parts.append(f"Qiling Syscalls: {syscalls.get('summary', {})}")
        network = qiling_results.get("network_activity", {})
        if isinstance(network, dict) and network:
            context_parts.append(f"Qiling Network: {network.get('indicators', network)}")
        evasion = qiling_results.get("evasion_techniques", {})
        if isinstance(evasion, dict) and evasion:
            context_parts.append(f"Qiling Evasion: {evasion.get('summary', evasion)}")
        instr_trace = qiling_results.get("instruction_trace", {})
        if isinstance(instr_trace, dict) and instr_trace:
            summary = instr_trace.get("summary", {})
            if isinstance(summary, dict) and summary.get("total_executed"):
                top = summary.get("top_mnemonics", [])[:10]
                top_str = ", ".join(f"{m.get('mnemonic')}:{m.get('count')}" for m in top if isinstance(m, dict))
                context_parts.append(
                    f"Qiling Instructions: total={summary.get('total_executed')}, "
                    f"unique_mnemonics={summary.get('unique_mnemonics')}, "
                    f"range={summary.get('address_range')}, top=[{top_str}]"
                )

    # Include structured IOC extraction in the follow-up context.
    iocs = extract_iocs_from_state(state)
    verdict, _, indicators, score = calculate_verdict(iocs, state)
    context_parts.append(f"\nIOC Assessment: verdict={verdict}, score={score}, indicators={indicators}")
    if not iocs.is_empty():
        context_parts.append("\n=== EXTRACTED IOCS ===")
        context_parts.append(format_iocs_for_report(iocs))

    # Include previous analysis summary for continuity
    prev_summary = state.get("summary", "")

    context = "\n".join(context_parts) if context_parts else "No analysis data available."

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
        answer = await call_llm(prompt, metadata=lf_meta or None)
        logger.info("query_complete", session_id=request.session_id, answer_len=len(answer))

        # Store the Q&A in reasoning trace for history
        state.setdefault("qa_history", []).append({
            "question": request.query,
            "answer": answer,
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
        })
    except Exception as exc:
        logger.error("query_failed", session_id=request.session_id, error=str(exc), exc_info=exc)
        return JSONResponse(
            {"ok": False, "error": str(exc)},
            status_code=500,
        )


@app.post("/write_mode")
async def write_mode(request: WriteModeRequest) -> JSONResponse:
    try:
        state = store.get_session(request.session_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Session not found: {request.session_id}")
    state["write_mode_enabled"] = request.enabled
    return JSONResponse({"ok": True, "write_mode_enabled": request.enabled})


@app.post("/write_mode/confirm")
async def write_mode_confirm(request: WriteModeRequest) -> JSONResponse:
    try:
        state = store.get_session(request.session_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Session not found: {request.session_id}")
    state["review_approved"] = request.enabled
    return JSONResponse({"ok": True, "review_approved": request.enabled})


@app.websocket("/stream/{session_id}")
async def stream(session_id: str, websocket: WebSocket) -> None:
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


async def _resolve_by_hash(program_hash: str) -> Dict[str, Any] | None:
    """Find the best session for a hash, preferring completed DB sessions."""
    candidates = [
        s for s in store.sessions.values()
        if s.get("program_hash") == program_hash
    ]
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
async def analysis_status(program_hash: str) -> JSONResponse:
    state = await _resolve_by_hash(program_hash)
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
    })


@app.get("/api/analysis/{program_hash}/analyzers")
async def analysis_analyzers(program_hash: str) -> JSONResponse:
    state = await _resolve_by_hash(program_hash)
    if state is None:
        return JSONResponse([], status_code=404)
    analyzers = [build_analyzer_response(state, "ghidra")]
    if state.get("r2_analysis_results"):
        analyzers.append(build_analyzer_response(state, "radare2"))
    if state.get("qiling_analysis_results"):
        analyzers.append(build_analyzer_response(state, "qiling"))
    return JSONResponse(analyzers)


@app.get("/api/analysis/{program_hash}/analyzers/{analyzer_id}")
async def analysis_analyzer_detail(program_hash: str, analyzer_id: str) -> JSONResponse:
    state = await _resolve_by_hash(program_hash)
    if state is None or analyzer_id not in ("ghidra", "radare2", "qiling"):
        return JSONResponse({"error": "not_found"}, status_code=404)
    return JSONResponse(build_analyzer_response(state, analyzer_id))


@app.get("/api/analysis/{program_hash}/files")
async def analysis_files(program_hash: str) -> JSONResponse:
    state = await _resolve_by_hash(program_hash)
    if state is None:
        return JSONResponse({"error": "not_found"}, status_code=404)
    return JSONResponse(build_file_tree(state))


@app.get("/api/analysis/{program_hash}/files/{file_id}")
async def analysis_file_content(program_hash: str, file_id: str) -> JSONResponse:
    state = await _resolve_by_hash(program_hash)
    if state is None:
        return JSONResponse({"error": "not_found"}, status_code=404)
    return JSONResponse(build_code_file(state, file_id))


@app.get("/api/analysis/{program_hash}/reports")
async def analysis_reports(program_hash: str) -> JSONResponse:
    state = await _resolve_by_hash(program_hash)
    if state is None:
        return JSONResponse([], status_code=404)
    return JSONResponse(build_reports(state))


@app.get("/api/analysis/{program_hash}/reports/{report_id}")
async def analysis_report_content(program_hash: str, report_id: str) -> JSONResponse:
    state = await _resolve_by_hash(program_hash)
    if state is None:
        return JSONResponse({"error": "not_found"}, status_code=404)
    return JSONResponse(build_report_content(state, report_id))


@app.get("/api/analysis/{program_hash}/similar")
async def analysis_similar(program_hash: str) -> JSONResponse:
    state = await _resolve_by_hash(program_hash)
    if state is None:
        return JSONResponse([], status_code=404)
    return JSONResponse(build_similar_files(state))


@app.get("/api/analysis/{program_hash}/results/ghidra")
async def ghidra_results(program_hash: str) -> JSONResponse:
    """Return raw Ghidra analysis results (functions, strings, binary info, decompiled code)."""
    state = await _resolve_by_hash(program_hash)
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
async def radare2_results(program_hash: str) -> JSONResponse:
    """Return raw Radare2 analysis results (functions, strings, binary info, decompiled code)."""
    state = await _resolve_by_hash(program_hash)
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
async def qiling_results(program_hash: str) -> JSONResponse:
    """Return raw Qiling dynamic analysis results."""
    state = await _resolve_by_hash(program_hash)
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


@app.get("/api/models")
async def models() -> JSONResponse:
    return JSONResponse(build_model_list())


@app.get("/api/analysis/{program_hash}/export/html")
async def export_html(program_hash: str) -> HTMLResponse:
    """Export analysis report as HTML."""
    state = await _resolve_by_hash(program_hash)
    if state is None:
        return HTMLResponse("<h1>Report not found</h1>", status_code=404)
    html = build_report_html(state)
    return HTMLResponse(content=html, headers={
        "Content-Disposition": f'attachment; filename="report_{program_hash[:16]}.html"'
    })


@app.get("/api/analysis/{program_hash}/export/text")
async def export_text(program_hash: str) -> PlainTextResponse:
    """Export analysis report as plain text."""
    state = await _resolve_by_hash(program_hash)
    if state is None:
        return PlainTextResponse("Report not found", status_code=404)
    text = build_report_text(state)
    return PlainTextResponse(content=text, headers={
        "Content-Disposition": f'attachment; filename="report_{program_hash[:16]}.txt"'
    })


@app.get("/export/session/{session_id}/html")
async def export_session_html(session_id: str) -> HTMLResponse:
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
async def export_session_agent_html(session_id: str, agent: str) -> HTMLResponse:
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
async def export_session_text(session_id: str) -> PlainTextResponse:
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
async def export_pdf(program_hash: str) -> Response:
    """Export analysis report as A4 PDF."""
    state = await _resolve_by_hash(program_hash)
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
async def export_session_pdf(session_id: str) -> Response:
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
) -> JSONResponse:
    """List past analyses with pagination and optional filters."""
    analyses = await db.list_analyses(
        limit=min(limit, 200),
        offset=offset,
        status=status or None,
        search=search or None,
    )
    total = await db.get_analysis_count(
        status=status or None,
        search=search or None,
    )
    return JSONResponse({
        "items": analyses,
        "total": total,
        "limit": limit,
        "offset": offset,
    })


@app.get("/api/history/{session_id}")
async def get_history_item(session_id: str) -> JSONResponse:
    """Get a single past analysis summary (without full state)."""
    item = await db.get_analysis_by_id(session_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Analysis not found")
    # Don't send the full state blob in the summary endpoint
    item.pop("state_json", None)
    return JSONResponse(item)


@app.get("/api/history/{session_id}/qa")
async def get_history_qa(session_id: str) -> JSONResponse:
    """Get Q&A history for a past analysis session."""
    qa = await db.get_qa_history(session_id)
    return JSONResponse(qa)


@app.post("/api/history/{session_id}/restore")
async def restore_session(session_id: str) -> JSONResponse:
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
async def delete_history_item(session_id: str) -> JSONResponse:
    """Delete a past analysis from the database."""
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
async def query_functions(name: str = "", analyzer: str = "", limit: int = 100) -> JSONResponse:
    """Search functions across all analyzed binaries."""
    results = await db.search_functions(
        name_pattern=name or None,
        analyzer=analyzer or None,
        limit=limit,
    )
    return JSONResponse({"items": results, "total": len(results)})


@app.get("/api/query/strings")
async def query_strings(pattern: str = "", limit: int = 100) -> JSONResponse:
    """Full-text search strings across all binaries."""
    if not pattern:
        return JSONResponse({"items": [], "total": 0})
    results = await db.search_strings_across(pattern, limit=limit)
    return JSONResponse({"items": results, "total": len(results)})


@app.get("/api/query/iocs")
async def query_iocs(ioc_type: str = "", value: str = "", limit: int = 100) -> JSONResponse:
    """Search IOCs across all binaries."""
    results = await db.search_iocs(
        ioc_type=ioc_type or None,
        value_pattern=value or None,
        limit=limit,
    )
    return JSONResponse({"items": results, "total": len(results)})


@app.get("/api/binary/{program_hash}/functions")
async def binary_functions(program_hash: str, analyzer: str = "") -> JSONResponse:
    """Get all functions for a specific binary."""
    results = await db.get_binary_functions(program_hash, analyzer=analyzer or None)
    return JSONResponse({"items": results, "total": len(results)})


@app.get("/api/binary/{program_hash}/decompilations")
async def binary_decompilations(program_hash: str, analyzer: str = "") -> JSONResponse:
    """Get all decompiled functions for a specific binary."""
    results = await db.get_binary_decompilations(program_hash, analyzer=analyzer or None)
    return JSONResponse({"items": results, "total": len(results)})


@app.get("/api/binary/{program_hash}/iocs")
async def binary_iocs(program_hash: str) -> JSONResponse:
    """Get IOCs for a specific binary."""
    results = await db.get_binary_iocs(program_hash)
    return JSONResponse({"items": results, "total": len(results)})


@app.get("/api/binary/{program_hash}/attack-chains")
async def binary_attack_chains(program_hash: str) -> JSONResponse:
    """Get attack chains for a specific binary."""
    results = await db.get_binary_attack_chains(program_hash)
    return JSONResponse({"items": results, "total": len(results)})
