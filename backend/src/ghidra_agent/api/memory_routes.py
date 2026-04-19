"""Memory API endpoints for the binary analysis agent.

Provides endpoints to:
- View and manage project memory (analysis rules)
- View episodic memory (previous analyses)
- Search for similar analyses
- Get memory statistics
"""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException

from ghidra_agent.auth import get_current_user
from ghidra_agent.memory import (
    EpisodicMemory,
    MemoryManager,
    ProjectMemory,
    get_memory_manager,
)
from ghidra_agent.logging import logger

router = APIRouter(prefix="/api/memory", tags=["memory"])


@router.get("/project/rules")
async def get_project_rules(
    user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """Get all project-level analysis rules."""
    try:
        memory = get_memory_manager()
        rules = memory.get_project_rules()
        return {
            "ok": True,
            "rules": rules,
            "count": len(rules),
        }
    except Exception as exc:
        logger.error("get_project_rules_failed", error=str(exc))
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/project/rules")
async def add_project_rule(
    category: str,
    rule: str,
    user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """Add or update a project-level analysis rule."""
    try:
        memory = get_memory_manager()
        memory.add_project_rule(category, rule)
        return {
            "ok": True,
            "message": f"Rule '{category}' has been added/updated.",
        }
    except Exception as exc:
        logger.error("add_project_rule_failed", error=str(exc))
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/episodic/recent")
async def get_recent_analyses(
    limit: int = 10,
    user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """Get the most recent analysis episodes."""
    try:
        memory = get_memory_manager()
        recent = memory.episodic.get_recent(limit=limit)
        return {
            "ok": True,
            "episodes": recent,
            "count": len(recent),
        }
    except Exception as exc:
        logger.error("get_recent_analyses_failed", error=str(exc))
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/episodic/hash/{program_hash}")
async def get_analysis_by_hash(
    program_hash: str,
    user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """Get analysis episode for a specific binary hash."""
    try:
        memory = get_memory_manager()
        episode = memory.episodic.get_by_hash(program_hash)
        if not episode:
            return {
                "ok": True,
                "episode": None,
                "message": "No analysis found for this hash",
            }
        return {
            "ok": True,
            "episode": episode,
        }
    except Exception as exc:
        logger.error("get_analysis_by_hash_failed", error=str(exc))
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/episodic/similar")
async def find_similar_analyses(
    verdict: Optional[str] = None,
    capability: Optional[str] = None,
    technique: Optional[str] = None,
    limit: int = 5,
    user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """Find similar analysis episodes."""
    try:
        memory = get_memory_manager()
        similar = memory.episodic.find_similar(
            verdict=verdict,
            capability=capability,
            technique=technique,
            limit=limit,
        )
        return {
            "ok": True,
            "episodes": similar,
            "count": len(similar),
        }
    except Exception as exc:
        logger.error("find_similar_analyses_failed", error=str(exc))
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/statistics")
async def get_memory_statistics(
    user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """Get memory statistics."""
    try:
        memory = get_memory_manager()
        stats = memory.get_statistics()
        return {
            "ok": True,
            "statistics": stats,
        }
    except Exception as exc:
        logger.error("get_memory_statistics_failed", error=str(exc))
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/context")
async def get_memory_context(
    program_hash: Optional[str] = None,
    max_length: int = 4000,
    user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """Get formatted memory context for LLM prompts."""
    try:
        memory = get_memory_manager()
        context = memory.get_context_for_prompt(
            program_hash=program_hash,
            max_project_length=max_length,
        )
        return {
            "ok": True,
            "context": context,
            "length": len(context),
        }
    except Exception as exc:
        logger.error("get_memory_context_failed", error=str(exc))
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/record")
async def record_analysis(
    program_hash: str,
    verdict: str,
    capabilities: List[str],
    iocs_count: int,
    techniques: List[str],
    summary: str,
    session_id: Optional[str] = None,
    user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """Record an analysis in episodic memory."""
    try:
        memory = get_memory_manager()
        memory.record_analysis(
            program_hash=program_hash,
            verdict=verdict,
            capabilities=capabilities,
            iocs_count=iocs_count,
            techniques=techniques,
            summary=summary,
            session_id=session_id,
        )
        return {
            "ok": True,
            "message": "Analysis recorded in memory",
        }
    except Exception as exc:
        logger.error("record_analysis_failed", error=str(exc))
        raise HTTPException(status_code=500, detail=str(exc))
