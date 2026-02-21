from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ToolCall(BaseModel):
    id: str
    name: str
    status: str
    result: Optional[Any] = None
    progress: Optional[int] = None
    max_progress: Optional[int] = Field(default=None, alias="maxProgress")


class Message(BaseModel):
    id: str
    content: str
    is_user: bool = Field(alias="isUser")
    timestamp: str
    tool_calls: Optional[List[ToolCall]] = Field(default=None, alias="toolCalls")
    code_blocks: Optional[List[Dict[str, Any]]] = Field(default=None, alias="codeBlocks")
    show_analysis_completed: Optional[bool] = Field(default=None, alias="showAnalysisCompleted")


class AnalysisResult(BaseModel):
    hash: str
    size: str
    type: str
    status: str
    duration: str
    started: str
    completed: str
    verdict: str
    threat_score: int = Field(alias="threatScore")
    max_score: int = Field(alias="maxScore")
    tags: List[str]


class AnalyzerDetails(BaseModel):
    executive_summary: str = Field(alias="executiveSummary")
    static_analysis: str = Field(alias="staticAnalysis")
    behavioral_analysis: str = Field(alias="behavioralAnalysis")
    iocs: str
    conclusion: str
    execution_logs: List[str] = Field(alias="executionLogs")


class Analyzer(BaseModel):
    id: str
    name: str
    source: str
    source_url: str = Field(alias="sourceUrl")
    verdict: str
    details: Optional[AnalyzerDetails] = None


class FileNode(BaseModel):
    id: str
    name: str
    type: str
    children: Optional[List["FileNode"]] = None


FileNode.model_rebuild()


class CodeFile(BaseModel):
    id: str
    name: str
    language: str
    content: str


class Report(BaseModel):
    id: str
    name: str
    timestamp: int
    content: Optional[str] = None


class SessionCreateRequest(BaseModel):
    binary_path: Optional[str] = None
    upload_name: Optional[str] = None


class SessionCreateResponse(BaseModel):
    session_id: str


class QueryRequest(BaseModel):
    session_id: str
    query: str


class WriteModeRequest(BaseModel):
    session_id: str
    enabled: bool


class StatusResponse(BaseModel):
    session_id: str
    status: str
    state: Dict[str, Any]


class AnalysisResponse(BaseModel):
    hash: str
    status: str
    analyzer_id: str
    details: AnalyzerDetails


class WebSocketEvent(BaseModel):
    type: str
    session_id: str
    payload: Dict[str, Any]
