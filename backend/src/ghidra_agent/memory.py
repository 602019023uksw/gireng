"""Memory Mechanism for Binary Analysis Agent

Provides a multi-layered memory system to retain context across analysis sessions:
- Project Memory: Analysis rules, patterns, and conventions
- Episodic Memory: Records of previous analyses and their outcomes
- Semantic Memory: Vector-based similarity search for related analyses (optional)
"""

import asyncio
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from ghidra_agent.config import settings
from ghidra_agent.logging import logger

# Embedding support via LiteLLM (already a project dependency)
try:
    import litellm
    LITELLM_AVAILABLE = True
except ImportError:
    LITELLM_AVAILABLE = False
    logger.warning("litellm_not_available", message="Semantic memory embeddings disabled")

# Memory file locations
MEMORY_DIR = Path(os.environ.get("MEMORY_DIR", "/data/memory"))
PROJECT_MEMORY_FILE = MEMORY_DIR / "project_memory.md"
EPISODIC_MEMORY_FILE = MEMORY_DIR / "episodic_memory.jsonl"
SEMANTIC_INDEX_FILE = MEMORY_DIR / "semantic_index.json"

# Ensure memory directories exist
MEMORY_DIR.mkdir(parents=True, exist_ok=True)


# =============================================================================
# Project Memory - Persistent analysis rules and patterns
# =============================================================================

class ProjectMemory:
    """Project-level memory for analysis rules and conventions.

    Stores long-lived information about how to approach binary analysis,
    including patterns to look for, common techniques, and team conventions.
    """

    def __init__(self, filepath: Path = PROJECT_MEMORY_FILE):
        self.filepath = filepath
        self._rules: Dict[str, str] = {}

    def load(self) -> Dict[str, str]:
        """Load project memory from disk."""
        if not self.filepath.exists():
            # Initialize with default rules
            self._initialize_default_rules()
            return self._rules

        try:
            content = self.filepath.read_text(encoding="utf-8")
            self._parse_markdown(content)
            logger.info("project_memory_loaded", rules_count=len(self._rules))
        except Exception as e:
            logger.warning("project_memory_load_failed", error=str(e))
            self._initialize_default_rules()

        return self._rules

    def save(self) -> None:
        """Save project memory to disk."""
        try:
            content = self._format_markdown()
            self.filepath.write_text(content, encoding="utf-8")
            logger.info("project_memory_saved", filepath=str(self.filepath))
        except Exception as e:
            logger.error("project_memory_save_failed", error=str(e))

    def add_rule(self, category: str, rule: str) -> None:
        """Add or update a rule in project memory."""
        self._rules[category] = rule
        logger.info("project_memory_rule_added", category=category)

    def get_rule(self, category: str) -> Optional[str]:
        """Get a rule by category."""
        return self._rules.get(category)

    def get_all_rules(self) -> Dict[str, str]:
        """Get all rules."""
        return self._rules.copy()

    def format_for_prompt(self, max_length: int = 4000) -> str:
        """Format rules for inclusion in an LLM prompt."""
        if not self._rules:
            self.load()

        sections = []
        current_length = 0

        for category, rule in self._rules.items():
            section = f"## {category}\n{rule}\n\n"
            if current_length + len(section) > max_length:
                break
            sections.append(section)
            current_length += len(section)

        return "".join(sections)

    def _parse_markdown(self, content: str) -> None:
        """Parse markdown content into rules dictionary."""
        self._rules = {}
        current_category = None
        current_content = []

        for line in content.split("\n"):
            if line.startswith("## "):
                # Save previous category
                if current_category:
                    self._rules[current_category] = "\n".join(current_content).strip()

                # Start new category
                current_category = line[3:].strip()
                current_content = []
            elif current_category:
                current_content.append(line)

        # Don't forget the last category
        if current_category:
            self._rules[current_category] = "\n".join(current_content).strip()

    def _format_markdown(self) -> str:
        """Format rules as markdown."""
        sections = []
        for category, rule in self._rules.items():
            sections.append(f"## {category}\n{rule}\n")
        return "\n".join(sections)

    def _initialize_default_rules(self) -> None:
        """Initialize with default binary analysis rules."""
        self._rules = {
            "Malware Analysis Priorities": """
When analyzing binaries, prioritize detecting:
1. **Network Communication**: URLs, IPs, domains, C2 infrastructure
2. **File System Operations**: Creation, deletion, modification of files
3. **Process Manipulation**: Creation, injection, hollowing techniques
4. **Registry/System Changes**: Persistence mechanisms
5. **Anti-Analysis Techniques**: Packing, obfuscation, debugger detection
6. **Data Exfiltration**: How stolen data is transmitted
""",
            "Common Evasion Patterns": """
Look for these evasion techniques:
- API hashing/dynamic resolution
- String obfuscation (XOR, ROT13, custom)
- Anti-VM checks (CPUID, timing, MAC address)
- Debugger detection (IsDebuggerPresent, CheckRemoteDebuggerPresent)
- Process hollowing/thread hijacking
- Direct syscalls (ntdll.dll bypass)
""",
            "Suspicious Import Patterns": """
These import combinations often indicate malicious intent:
- VirtualAlloc/VirtualProtect + WriteProcessMemory = Process injection
- CreateRemoteThread + WriteProcessMemory = DLL injection
- InternetOpen + InternetOpenUrl = Network activity
- CryptAcquireContext + CryptCreateHash = Encryption/obfuscation
- RegCreateKey/RegSetValue = Persistence mechanism
""",
            "Function Naming Conventions": """
When decompiling, use descriptive function names:
- `sub_<addr>` → Rename based on purpose (e.g., `download_payload`, `decrypt_config`)
- Indicate API usage (e.g., `WinHttpOpen_C2_init`)
- Note evasion techniques (e.g., `resolve_api_via_hash`)
- Mark key behavior (e.g., `enum_processes`, `inject_into_browser`)
""",
            "Analysis Report Structure": """
Include in every analysis report:
1. **Executive Summary**: 2-3 sentence overview
2. **Capabilities**: What the malware CAN do (not just might do)
3. **IOC List**: All extracted indicators with confidence scores
4. **Attack Chains**: How capabilities connect into tactics
5. **Attribution Hints**: Code reuse, build timestamps, language hints
""",
        }
        self.save()


# =============================================================================
# Episodic Memory - Records of previous analyses
# =============================================================================

class EpisodicMemory:
    """Episodic memory for storing previous analysis experiences.

    Records specific analysis episodes: what binary was analyzed,
    what was found, what techniques worked, and what the outcome was.
    """

    def __init__(self, filepath: Path = EPISODIC_MEMORY_FILE):
        self.filepath = filepath
        self._episodes: List[Dict[str, Any]] = []

    def load(self) -> List[Dict[str, Any]]:
        """Load episodic memory from disk."""
        if not self.filepath.exists():
            return []

        try:
            self._episodes = []
            with open(self.filepath, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        self._episodes.append(json.loads(line))
            logger.info("episodic_memory_loaded", episodes_count=len(self._episodes))
        except Exception as e:
            logger.warning("episodic_memory_load_failed", error=str(e))
            self._episodes = []

        return self._episodes

    def save(self) -> None:
        """Save episodic memory to disk."""
        try:
            with open(self.filepath, "w", encoding="utf-8") as f:
                for episode in self._episodes:
                    f.write(json.dumps(episode, ensure_ascii=False) + "\n")
            logger.info("episodic_memory_saved", filepath=str(self.filepath))
        except Exception as e:
            logger.error("episodic_memory_save_failed", error=str(e))

    def add_episode(
        self,
        program_hash: str,
        verdict: str,
        capabilities: List[str],
        iocs_count: int,
        techniques_found: List[str],
        summary: str,
        session_id: Optional[str] = None,
    ) -> None:
        """Add a new analysis episode to memory."""
        episode = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "program_hash": program_hash,
            "verdict": verdict,
            "capabilities": capabilities,
            "iocs_count": iocs_count,
            "techniques": techniques_found,
            "summary": summary[:2000],  # Limit summary length
            "session_id": session_id,
        }
        self._episodes.append(episode)
        self.save()
        logger.info("episodic_memory_episode_added", program_hash=program_hash, verdict=verdict)

    def find_similar(
        self,
        program_hash: Optional[str] = None,
        verdict: Optional[str] = None,
        capability: Optional[str] = None,
        technique: Optional[str] = None,
        limit: int = 5,
    ) -> List[Dict[str, Any]]:
        """Find similar analysis episodes."""
        self.load()

        results = []
        for episode in self._episodes:
            # Skip the same binary if looking for similar (not identical)
            if program_hash and episode["program_hash"] == program_hash:
                continue

            # Match verdict if specified
            if verdict and episode["verdict"] != verdict:
                continue

            # Match capability if specified
            if capability and capability not in episode.get("capabilities", []):
                continue

            # Match technique if specified
            if technique and technique not in episode.get("techniques", []):
                continue

            results.append(episode)
            if len(results) >= limit:
                break

        return results

    def get_recent(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get the most recent analysis episodes."""
        self.load()
        return self._episodes[-limit:] if self._episodes else []

    def get_by_hash(self, program_hash: str) -> Optional[Dict[str, Any]]:
        """Get analysis episode for a specific binary hash."""
        self.load()
        for episode in reversed(self._episodes):
            if episode["program_hash"] == program_hash:
                return episode
        return None

    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about analyzed binaries."""
        self.load()

        total = len(self._episodes)
        verdicts: Dict[str, int] = {}
        capabilities: Dict[str, int] = {}

        for episode in self._episodes:
            v = episode.get("verdict", "unknown")
            verdicts[v] = verdicts.get(v, 0) + 1

            for cap in episode.get("capabilities", []):
                capabilities[cap] = capabilities.get(cap, 0) + 1

        return {
            "total_analyzed": total,
            "verdict_distribution": verdicts,
            "common_capabilities": dict(sorted(capabilities.items(), key=lambda x: -x[1])[:20]),
        }


# =============================================================================
# Semantic Memory - Vector-based similarity search
# =============================================================================

class SemanticMemory:
    """Semantic memory for vector-based similarity search.

    Uses LiteLLM embeddings to find semantically similar analyses,
    patterns, or code snippets. Falls back to keyword matching when
    embeddings are unavailable.
    """

    def __init__(
        self,
        index_file: Path = SEMANTIC_INDEX_FILE,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
    ):
        self.index_file = index_file
        self._index: Dict[str, Dict[str, Any]] = {}
        self.embedding_api_key = api_key or os.environ.get("LLM_API_KEY", "")
        self.embedding_base_url = base_url or os.environ.get("LLM_BASE_URL", "")
        self.embedding_model = model or os.environ.get("EMBEDDING_MODEL", "text-embedding-3-small")
        self._embeddings_available = LITELLM_AVAILABLE and bool(self.embedding_api_key)

        if self._embeddings_available:
            logger.info(
                "semantic_memory_initialized",
                model=self.embedding_model,
                has_base_url=bool(self.embedding_base_url),
            )

    def load(self) -> Dict[str, Dict[str, Any]]:
        """Load semantic index from disk."""
        if not self.index_file.exists():
            return {}

        try:
            content = self.index_file.read_text(encoding="utf-8")
            self._index = json.loads(content)
            logger.info("semantic_memory_loaded", entries_count=len(self._index))
        except Exception as e:
            logger.warning("semantic_memory_load_failed", error=str(e))
            self._index = {}

        return self._index

    def save(self) -> None:
        """Save semantic index to disk."""
        try:
            self.index_file.write_text(json.dumps(self._index, ensure_ascii=False), encoding="utf-8")
            logger.info("semantic_memory_saved", filepath=str(self.index_file))
        except Exception as e:
            logger.error("semantic_memory_save_failed", error=str(e))

    def _embed_text(self, text: str) -> Optional[List[float]]:
        """Generate an embedding for a single text via LiteLLM (sync)."""
        if not self._embeddings_available:
            return None
        try:
            response = litellm.embedding(
                model=f"openai/{self.embedding_model}",
                input=[text],
                api_base=self.embedding_base_url or None,
                api_key=self.embedding_api_key or None,
            )
            embedding: List[float] = response.data[0]["embedding"]  # type: ignore
            return embedding
        except Exception as e:
            logger.warning("semantic_memory_embedding_failed", error=str(e))
            return None

    async def _aembed_text(self, text: str) -> Optional[List[float]]:
        """Generate an embedding for a single text via LiteLLM (async)."""
        if not self._embeddings_available:
            return None
        try:
            response = await litellm.aembedding(
                model=f"openai/{self.embedding_model}",
                input=[text],
                api_base=self.embedding_base_url or None,
                api_key=self.embedding_api_key or None,
            )
            embedding: List[float] = response.data[0]["embedding"]  # type: ignore
            return embedding
        except Exception as e:
            logger.warning("semantic_memory_embedding_failed", error=str(e))
            return None

    def add_entry(
        self,
        entry_id: str,
        text: str,
        metadata: Dict[str, Any],
        embedding: Optional[List[float]] = None,
    ) -> None:
        """Add an entry to the semantic index."""
        if embedding is None:
            embedding = self._embed_text(text)

        self._index[entry_id] = {
            "text": text[:1000],  # Limit stored text
            "metadata": metadata,
            "embedding": embedding,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.save()

    async def search(
        self,
        query: str,
        limit: int = 5,
        filters: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """Search for semantically similar entries.

        Uses embedding cosine similarity when available; otherwise falls
        back to keyword matching.
        """
        self.load()

        if not self._index:
            return []

        # Helper to apply filters
        def _matches_filters(entry: Dict[str, Any]) -> bool:
            if not filters:
                return True
            for key, value in filters.items():
                if entry.get("metadata", {}).get(key) != value:
                    return False
            return True

        # Try embedding-based search first
        query_embedding = await self._aembed_text(query)
        if query_embedding:
            results: List[Dict[str, Any]] = []
            for entry_id, entry in self._index.items():
                if not _matches_filters(entry):
                    continue
                entry_embedding = entry.get("embedding")
                if entry_embedding:
                    score = self._cosine_similarity(query_embedding, entry_embedding)
                    if score > 0.0:
                        results.append({
                            "entry_id": entry_id,
                            "text": entry["text"],
                            "metadata": entry.get("metadata", {}),
                            "relevance": round(score, 4),
                        })
            results.sort(key=lambda x: x["relevance"], reverse=True)
            return results[:limit]

        # Fallback to keyword matching
        query_lower = query.lower()
        query_words = set(query_lower.split())
        results = []
        for entry_id, entry in self._index.items():
            if not _matches_filters(entry):
                continue

            text = entry.get("text", "").lower()
            metadata_text = str(entry.get("metadata", {})).lower()
            combined_text = text + " " + metadata_text

            word_matches = sum(1 for word in query_words if word in combined_text)
            phrase_match = 1 if query_lower in combined_text else 0
            relevance_score = word_matches + (phrase_match * 5)

            if relevance_score > 0:
                results.append({
                    "entry_id": entry_id,
                    "text": entry["text"],
                    "metadata": entry.get("metadata", {}),
                    "relevance": relevance_score,
                })

        results.sort(key=lambda x: x["relevance"], reverse=True)
        return results[:limit]

    @staticmethod
    def _cosine_similarity(a: List[float], b: List[float]) -> float:
        """Calculate cosine similarity between two vectors."""
        if len(a) != len(b):
            return 0.0

        dot_product = sum(x * y for x, y in zip(a, b))
        magnitude_a = sum(x * x for x in a) ** 0.5
        magnitude_b = sum(y * y for y in b) ** 0.5

        if magnitude_a == 0 or magnitude_b == 0:
            return 0.0

        return dot_product / (magnitude_a * magnitude_b)


# =============================================================================
# Unified Memory Manager
# =============================================================================

class MemoryManager:
    """Unified manager for all memory layers."""

    def __init__(
        self,
        memory_dir: Optional[Path] = None,
        embedding_api_key: Optional[str] = None,
    ):
        self.memory_dir = memory_dir or MEMORY_DIR
        self.project = ProjectMemory(self.memory_dir / "project_memory.md")
        self.episodic = EpisodicMemory(self.memory_dir / "episodic_memory.jsonl")
        self.semantic = SemanticMemory(
            self.memory_dir / "semantic_index.json",
            api_key=embedding_api_key,
            base_url=os.environ.get("LLM_BASE_URL"),
            model=os.environ.get("EMBEDDING_MODEL"),
        )

        # Load all memories on initialization
        self.project.load()
        self.episodic.load()
        self.semantic.load()

    def get_context_for_prompt(
        self,
        program_hash: Optional[str] = None,
        max_project_length: int = 3000,
        max_episodic_entries: int = 3,
        include_semantic: bool = False,
        semantic_query: Optional[str] = None,
    ) -> str:
        """Gather relevant memory for an LLM prompt."""
        context_parts = []

        # Add project memory (rules and patterns)
        project_rules = self.project.format_for_prompt(max_project_length)
        if project_rules:
            context_parts.append("# Analysis Rules and Patterns\n")
            context_parts.append(project_rules)
            context_parts.append("\n")

        # Add episodic memory (similar previous analyses)
        if program_hash:
            similar = self.episodic.find_similar(limit=max_episodic_entries)
            if similar:
                context_parts.append("# Similar Previous Analyses\n")
                for episode in similar:
                    context_parts.append(f"## Binary: {episode['program_hash']}\n")
                    context_parts.append(f"Verdict: {episode['verdict']}\n")
                    context_parts.append(f"Capabilities: {', '.join(episode['capabilities'][:5])}\n")
                    context_parts.append(f"Summary: {episode['summary'][:500]}\n\n")

        # Add semantic search results if available
        if include_semantic and semantic_query and self.semantic._embeddings_available:
            # Note: This is async, so caller needs to handle it
            pass

        return "".join(context_parts)

    def record_analysis(
        self,
        program_hash: str,
        verdict: str,
        capabilities: List[str],
        iocs_count: int,
        techniques: List[str],
        summary: str,
        session_id: Optional[str] = None,
    ) -> None:
        """Record an analysis in episodic memory."""
        self.episodic.add_episode(
            program_hash=program_hash,
            verdict=verdict,
            capabilities=capabilities,
            iocs_count=iocs_count,
            techniques_found=techniques,
            summary=summary,
            session_id=session_id,
        )

    async def search_similar_analyses(
        self,
        query: str,
        limit: int = 5,
    ) -> List[Dict[str, Any]]:
        """Search for semantically similar analyses."""
        return await self.semantic.search(query, limit=limit)

    def get_statistics(self) -> Dict[str, Any]:
        """Get memory statistics."""
        return {
            "project_rules_count": len(self.project.get_all_rules()),
            "episodic_episodes_count": len(self.episodic._episodes),
            "semantic_entries_count": len(self.semantic._index),
            "episodic_statistics": self.episodic.get_statistics(),
        }

    def add_project_rule(self, category: str, rule: str) -> None:
        """Add or update a project-level analysis rule."""
        self.project.add_rule(category, rule)
        self.project.save()

    def get_project_rules(self) -> Dict[str, str]:
        """Get all project-level rules."""
        return self.project.get_all_rules()


# Global memory manager instance
_global_memory: Optional[MemoryManager] = None


def get_memory_manager() -> MemoryManager:
    """Get the global memory manager instance."""
    global _global_memory
    if _global_memory is None:
        embedding_key = os.environ.get("LLM_API_KEY")
        _global_memory = MemoryManager(embedding_api_key=embedding_key)
    return _global_memory
