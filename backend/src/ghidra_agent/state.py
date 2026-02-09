from typing import Any, Dict, List, Optional, TypedDict

from pydantic import BaseModel, Field


class AgentState(TypedDict):
    binary_path: str
    program_hash: str
    current_address: Optional[str]
    current_function: Optional[str]
    analysis_results: Dict[str, Any]
    decompilation_cache: Dict[str, str]
    user_query: str
    reasoning_trace: List[str]
    pending_actions: List[Dict[str, Any]]
    write_mode_enabled: bool
    session_id: str
    intent: Optional[str]
    status: str
    review_approved: bool
    summary: str
    # Radare2 results (parallel to Ghidra)
    r2_analysis_results: Dict[str, Any]
    r2_decompilation_cache: Dict[str, str]


DEFAULT_STATE: AgentState = {
    "binary_path": "",
    "program_hash": "",
    "current_address": None,
    "current_function": None,
    "analysis_results": {},
    "decompilation_cache": {},
    "user_query": "",
    "reasoning_trace": [],
    "pending_actions": [],
    "write_mode_enabled": False,
    "session_id": "",
    "intent": None,
    "status": "initialized",
    "review_approved": False,
    "summary": "",
    "r2_analysis_results": {},
    "r2_decompilation_cache": {},
}


class AgentStateModel(BaseModel):
    binary_path: str
    program_hash: str
    current_address: Optional[str] = None
    current_function: Optional[str] = None
    analysis_results: Dict[str, Any] = Field(default_factory=dict)
    decompilation_cache: Dict[str, str] = Field(default_factory=dict)
    user_query: str = ""
    reasoning_trace: List[str] = Field(default_factory=list)
    pending_actions: List[Dict[str, Any]] = Field(default_factory=list)
    write_mode_enabled: bool = False
    session_id: str
    intent: Optional[str] = None
    status: str = "initialized"
    review_approved: bool = False
    summary: str = ""
    r2_analysis_results: Dict[str, Any] = Field(default_factory=dict)
    r2_decompilation_cache: Dict[str, str] = Field(default_factory=dict)
