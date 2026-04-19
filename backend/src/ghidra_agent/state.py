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
    ghidra_trace: List[str]
    r2_trace: List[str]
    qiling_trace: List[str]
    session_id: str
    intent: Optional[str]
    status: str
    current_step: str
    progress: int
    progress_callback: Any
    summary: str
    analyzer_progress: Dict[str, int]
    analyzer_status: Dict[str, str]
    analyzer_step: Dict[str, str]
    # Radare2 results (parallel to Ghidra)
    r2_analysis_results: Dict[str, Any]
    r2_decompilation_cache: Dict[str, str]
    # Qiling results (dynamic analysis)
    qiling_analysis_results: Dict[str, Any]
    qiling_execution_cache: Dict[str, Any]
    # Optional overrides
    llm_model: Optional[str]
    user_id: Optional[str]
    # Runtime ephemeral fields
    synthesis_reasoning: Optional[str]
    analysis_plan: List[Dict[str, Any]]
    investigation_results: Dict[str, Any]
    investigation_iterations: int
    investigation_trace: Optional[str]
    qa_history: List[Dict[str, Any]]


DEFAULT_STATE: AgentState = {
    "binary_path": "",
    "program_hash": "",
    "current_address": None,
    "current_function": None,
    "analysis_results": {},
    "decompilation_cache": {},
    "user_query": "",
    "reasoning_trace": [],
    "ghidra_trace": [],
    "r2_trace": [],
    "qiling_trace": [],
    "session_id": "",
    "intent": None,
    "status": "initialized",
    "current_step": "",
    "progress": 0,
    "progress_callback": None,
    "summary": "",
    "analyzer_progress": {"ghidra": 0, "radare2": 0, "qiling": 0},
    "analyzer_status": {"ghidra": "pending", "radare2": "pending", "qiling": "pending"},
    "analyzer_step": {"ghidra": "", "radare2": "", "qiling": ""},
    "r2_analysis_results": {},
    "r2_decompilation_cache": {},
    "qiling_analysis_results": {},
    "qiling_execution_cache": {},
    "synthesis_reasoning": None,
    "analysis_plan": [],
    "investigation_results": {},
    "investigation_iterations": 0,
    "investigation_trace": None,
    "qa_history": [],
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
    ghidra_trace: List[str] = Field(default_factory=list)
    r2_trace: List[str] = Field(default_factory=list)
    qiling_trace: List[str] = Field(default_factory=list)
    session_id: str
    intent: Optional[str] = None
    status: str = "initialized"
    current_step: str = ""
    progress: int = 0
    # Runtime-only callback hook; excluded from model serialization.
    progress_callback: Any = Field(default=None, exclude=True)
    summary: str = ""
    analyzer_progress: Dict[str, int] = Field(
        default_factory=lambda: {"ghidra": 0, "radare2": 0, "qiling": 0}
    )
    analyzer_status: Dict[str, str] = Field(
        default_factory=lambda: {"ghidra": "pending", "radare2": "pending", "qiling": "pending"}
    )
    analyzer_step: Dict[str, str] = Field(
        default_factory=lambda: {"ghidra": "", "radare2": "", "qiling": ""}
    )
    r2_analysis_results: Dict[str, Any] = Field(default_factory=dict)
    r2_decompilation_cache: Dict[str, str] = Field(default_factory=dict)
    qiling_analysis_results: Dict[str, Any] = Field(default_factory=dict)
    qiling_execution_cache: Dict[str, Any] = Field(default_factory=dict)
    llm_model: Optional[str] = None
    user_id: Optional[str] = None
    synthesis_reasoning: Optional[str] = None
    analysis_plan: List[Dict[str, Any]] = Field(default_factory=list)
    investigation_results: Dict[str, Any] = Field(default_factory=dict)
    investigation_iterations: int = 0
    investigation_trace: Optional[str] = None
    qa_history: List[Dict[str, Any]] = Field(default_factory=list)
