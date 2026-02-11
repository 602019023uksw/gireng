import asyncio
from pathlib import Path
from typing import Any, Dict, List

from fastapi import FastAPI, File, UploadFile, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, HTMLResponse
from fastapi.responses import Response as FastAPIResponse

from ghidra_agent.config import settings
from ghidra_agent.logging import configure_logging, logger
from ghidra_agent.models import (
    SessionCreateResponse,
    StatusResponse,
    QueryRequest,
    SessionCreateRequest,
    WriteModeRequest,
)
from ghidra_agent.sessions import store, run_graph
from ghidra_agent.ui_adapter import (
    build_analyzer_response,
    build_code_file,
    build_file_tree,
    build_model_list,
    build_reports,
    build_report_content,
    build_similar_files,
)
from ghidra_agent.reporting import build_report_html, build_report_text, build_agent_report_html
from ghidra_agent.llm import call_llm
from ghidra_agent.ioc_extractor import extract_iocs_from_state, format_iocs_for_report, calculate_verdict
from ghidra_agent.utils import ensure_directory, safe_basename


app = FastAPI(title="Ghidra Reverse Engineering Agent")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

configure_logging()


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
    shared_root = Path(settings.ghidra_shared_root)
    ensure_directory(shared_root)
    filename = file.filename or "upload"
    target_path = shared_root / safe_basename(filename)
    contents = await file.read()
    if len(contents) > settings.max_upload_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"File too large ({len(contents)} bytes). Max allowed: {settings.max_upload_bytes} bytes.",
        )
    target_path.write_bytes(contents)
    state = store.create_session(str(target_path))
    _create_tracked_task(_run_with_events(state))
    return SessionCreateResponse(session_id=state["session_id"])


@app.get("/status/{session_id}", response_model=StatusResponse)
async def status(session_id: str) -> StatusResponse:
    try:
        state = store.get_session(session_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Session not found: {session_id}")
    return StatusResponse(session_id=session_id, status=state["status"], state=state)


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
        for func_name, c_code in list(decomp_cache.items())[:15]:
            context_parts.append(f"\n--- {func_name} ---\n{c_code[:2000]}")

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
        for func_name, c_code in list(r2_decomp.items())[:10]:
            context_parts.append(f"\n--- {func_name} ---\n{c_code[:2000]}")

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
{prev_summary[:4000]}

RAW ANALYSIS DATA:
{context[:8000]}

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
        answer = await call_llm(prompt)
        logger.info("query_complete", session_id=request.session_id, answer_len=len(answer))

        # Store the Q&A in reasoning trace for history
        state.setdefault("qa_history", []).append({
            "question": request.query,
            "answer": answer,
        })
        store.update_session(request.session_id, state)

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
        await manager.broadcast(session_id, {"type": "analysis:progress", "session_id": session_id, "payload": {"status": "started"}})
        await manager.broadcast(session_id, {"type": "message:typing", "session_id": session_id, "payload": {"status": "running"}})
        result = await run_graph(state)
        store.update_session(session_id, result)
        await manager.broadcast(session_id, {"type": "analysis:completed", "session_id": session_id, "payload": {"status": result["status"]}})
    except Exception as exc:
        logger.error("run_with_events_failed", session_id=session_id, error=str(exc), exc_info=exc)
        state["status"] = "error"
        store.update_session(session_id, state)
        await manager.broadcast(session_id, {"type": "analysis:error", "session_id": session_id, "payload": {"status": "error", "error": str(exc)}})


@app.get("/api/analysis/{program_hash}")
async def analysis_status(program_hash: str) -> JSONResponse:
    for state in store.sessions.values():
        if state["program_hash"] == program_hash:
            return JSONResponse({"hash": program_hash, "status": state["status"], "analyzer": "ghidra"})
    return JSONResponse({"hash": program_hash, "status": "not_found"}, status_code=404)


@app.get("/api/analysis/{program_hash}/analyzers")
async def analysis_analyzers(program_hash: str) -> JSONResponse:
    for state in store.sessions.values():
        if state["program_hash"] == program_hash:
            analyzers = [build_analyzer_response(state, "ghidra")]
            # Include radare2 if R2 results exist
            if state.get("r2_analysis_results"):
                analyzers.append(build_analyzer_response(state, "radare2"))
            return JSONResponse(analyzers)
    return JSONResponse([], status_code=404)


@app.get("/api/analysis/{program_hash}/analyzers/{analyzer_id}")
async def analysis_analyzer_detail(program_hash: str, analyzer_id: str) -> JSONResponse:
    for state in store.sessions.values():
        if state["program_hash"] == program_hash and analyzer_id in ("ghidra", "radare2"):
            return JSONResponse(build_analyzer_response(state, analyzer_id))
    return JSONResponse({"error": "not_found"}, status_code=404)


@app.get("/api/analysis/{program_hash}/files")
async def analysis_files(program_hash: str) -> JSONResponse:
    for state in store.sessions.values():
        if state["program_hash"] == program_hash:
            return JSONResponse(build_file_tree(state))
    return JSONResponse({"error": "not_found"}, status_code=404)


@app.get("/api/analysis/{program_hash}/files/{file_id}")
async def analysis_file_content(program_hash: str, file_id: str) -> JSONResponse:
    for state in store.sessions.values():
        if state["program_hash"] == program_hash:
            return JSONResponse(build_code_file(state, file_id))
    return JSONResponse({"error": "not_found"}, status_code=404)


@app.get("/api/analysis/{program_hash}/reports")
async def analysis_reports(program_hash: str) -> JSONResponse:
    for state in store.sessions.values():
        if state["program_hash"] == program_hash:
            return JSONResponse(build_reports(state))
    return JSONResponse([], status_code=404)


@app.get("/api/analysis/{program_hash}/reports/{report_id}")
async def analysis_report_content(program_hash: str, report_id: str) -> JSONResponse:
    for state in store.sessions.values():
        if state["program_hash"] == program_hash:
            return JSONResponse(build_report_content(state, report_id))
    return JSONResponse({"error": "not_found"}, status_code=404)


@app.get("/api/analysis/{program_hash}/similar")
async def analysis_similar(program_hash: str) -> JSONResponse:
    for state in store.sessions.values():
        if state["program_hash"] == program_hash:
            return JSONResponse(build_similar_files(state))
    return JSONResponse([], status_code=404)


@app.get("/api/analysis/{program_hash}/results/ghidra")
async def ghidra_results(program_hash: str) -> JSONResponse:
    """Return raw Ghidra analysis results (functions, strings, binary info, decompiled code)."""
    for state in store.sessions.values():
        if state["program_hash"] == program_hash:
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
    return JSONResponse({"error": "not_found"}, status_code=404)


@app.get("/api/analysis/{program_hash}/results/radare2")
async def radare2_results(program_hash: str) -> JSONResponse:
    """Return raw Radare2 analysis results (functions, strings, binary info, decompiled code)."""
    for state in store.sessions.values():
        if state["program_hash"] == program_hash:
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
    return JSONResponse({"error": "not_found"}, status_code=404)


@app.get("/api/models")
async def models() -> JSONResponse:
    return JSONResponse(build_model_list())


@app.get("/api/analysis/{program_hash}/export/html")
async def export_html(program_hash: str) -> HTMLResponse:
    """Export analysis report as HTML."""
    for state in store.sessions.values():
        if state["program_hash"] == program_hash:
            html = build_report_html(state)
            return HTMLResponse(content=html, headers={
                "Content-Disposition": f'attachment; filename="report_{program_hash[:16]}.html"'
            })
    return HTMLResponse("<h1>Report not found</h1>", status_code=404)


@app.get("/api/analysis/{program_hash}/export/text")
async def export_text(program_hash: str) -> PlainTextResponse:
    """Export analysis report as plain text."""
    for state in store.sessions.values():
        if state["program_hash"] == program_hash:
            text = build_report_text(state)
            return PlainTextResponse(content=text, headers={
                "Content-Disposition": f'attachment; filename="report_{program_hash[:16]}.txt"'
            })
    return PlainTextResponse("Report not found", status_code=404)


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
    """Export per-agent report (ghidra or r2)."""
    if agent.lower() not in ("ghidra", "r2", "radare2"):
        return HTMLResponse("<h1>Invalid agent. Use 'ghidra' or 'r2'.</h1>", status_code=400)
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
