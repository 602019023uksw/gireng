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
from ghidra_agent.reporting import build_report_html, build_report_text
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
    try:
        state = store.get_session(request.session_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Session not found: {request.session_id}")
    state["user_query"] = request.query
    _create_tracked_task(_run_with_events(state))
    return JSONResponse({"ok": True})


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
            return JSONResponse([build_analyzer_response(state)])
    return JSONResponse([], status_code=404)


@app.get("/api/analysis/{program_hash}/analyzers/{analyzer_id}")
async def analysis_analyzer_detail(program_hash: str, analyzer_id: str) -> JSONResponse:
    for state in store.sessions.values():
        if state["program_hash"] == program_hash and analyzer_id == "ghidra":
            return JSONResponse(build_analyzer_response(state))
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
