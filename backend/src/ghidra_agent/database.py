"""PostgreSQL persistence for analysis sessions and history.

Uses asyncpg for high-performance async access.  Connects to the Postgres
container defined in docker-compose.yml.

Normalized schema stores functions, decompilations, strings, call graphs,
attack chains, and IOCs in dedicated tables for cross-analysis querying.
"""

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import asyncpg

from ghidra_agent.logging import logger

_pool: Optional[asyncpg.Pool] = None


async def get_pool() -> asyncpg.Pool:
    """Return (and lazily create) the connection pool."""
    global _pool
    if _pool is None:
        from ghidra_agent.config import settings
        _pool = await asyncpg.create_pool(
            dsn=settings.database_url,
            min_size=2,
            max_size=10,
        )
        await _init_schema()
        logger.info("database_connected", dsn=settings.database_url.split("@")[-1])
    return _pool


async def close_db() -> None:
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

async def _init_schema() -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS analyses (
                id               TEXT PRIMARY KEY,
                program_hash     TEXT NOT NULL,
                binary_path      TEXT NOT NULL,
                status           TEXT NOT NULL DEFAULT 'initialized',
                intent           TEXT,
                user_query       TEXT,
                summary          TEXT,
                verdict          TEXT,
                threat_score     INTEGER,
                started_at       TIMESTAMPTZ,
                completed_at     TIMESTAMPTZ,
                duration_seconds DOUBLE PRECISION,
                created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
                updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
                state_json       TEXT
            )
        """)
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_analyses_hash ON analyses(program_hash)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_analyses_status ON analyses(status)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_analyses_created ON analyses(created_at DESC)")

        # -- Binaries (deduplicated by hash) --------------------------------
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS binaries (
                program_hash     TEXT PRIMARY KEY,
                file_path        TEXT,
                architecture     TEXT,
                bits             INTEGER,
                os               TEXT,
                image_base       TEXT,
                entry_points     JSONB,
                imports          JSONB,
                exports          JSONB,
                file_size        BIGINT,
                file_type        TEXT,
                created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
            )
        """)

        # -- Functions ------------------------------------------------------
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS functions (
                id               SERIAL PRIMARY KEY,
                program_hash     TEXT NOT NULL REFERENCES binaries(program_hash) ON DELETE CASCADE,
                analyzer         TEXT NOT NULL,
                name             TEXT NOT NULL,
                address          TEXT,
                size             INTEGER,
                xref_count       INTEGER DEFAULT 0,
                priority_score   DOUBLE PRECISION DEFAULT 0,
                created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
                UNIQUE (program_hash, analyzer, name, address)
            )
        """)
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_functions_hash ON functions(program_hash)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_functions_analyzer ON functions(analyzer)")

        # -- Decompilations -------------------------------------------------
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS decompilations (
                id               SERIAL PRIMARY KEY,
                program_hash     TEXT NOT NULL REFERENCES binaries(program_hash) ON DELETE CASCADE,
                analyzer         TEXT NOT NULL,
                function_name    TEXT NOT NULL,
                code             TEXT NOT NULL,
                language         TEXT DEFAULT 'c',
                created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
                UNIQUE (program_hash, analyzer, function_name)
            )
        """)
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_decomp_hash ON decompilations(program_hash)")

        # -- Strings --------------------------------------------------------
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS strings (
                id               SERIAL PRIMARY KEY,
                program_hash     TEXT NOT NULL REFERENCES binaries(program_hash) ON DELETE CASCADE,
                analyzer         TEXT NOT NULL,
                value            TEXT NOT NULL,
                address          TEXT,
                section          TEXT,
                created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
            )
        """)
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_strings_hash ON strings(program_hash)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_strings_value ON strings USING gin(to_tsvector('simple', value))")

        # -- Call Graphs (one row per analyzer per binary) ------------------
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS call_graphs (
                id               SERIAL PRIMARY KEY,
                program_hash     TEXT NOT NULL REFERENCES binaries(program_hash) ON DELETE CASCADE,
                analyzer         TEXT NOT NULL,
                nodes            JSONB,
                edges            JSONB,
                entry_points     JSONB,
                adjacency        JSONB,
                stats            JSONB,
                created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
                UNIQUE (program_hash, analyzer)
            )
        """)
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_callgraph_hash ON call_graphs(program_hash)")

        # -- Attack Chains --------------------------------------------------
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS attack_chains (
                id               SERIAL PRIMARY KEY,
                program_hash     TEXT NOT NULL REFERENCES binaries(program_hash) ON DELETE CASCADE,
                analyzer         TEXT NOT NULL,
                category         TEXT,
                sink             TEXT,
                path             JSONB,
                description      TEXT,
                created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
            )
        """)
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_atchains_hash ON attack_chains(program_hash)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_atchains_cat ON attack_chains(category)")

        # -- IOCs -----------------------------------------------------------
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS iocs (
                id               SERIAL PRIMARY KEY,
                program_hash     TEXT NOT NULL REFERENCES binaries(program_hash) ON DELETE CASCADE,
                ioc_type         TEXT NOT NULL,
                value            TEXT NOT NULL,
                created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
            )
        """)
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_iocs_hash ON iocs(program_hash)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(ioc_type)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value)")

        # -- Q&A History ----------------------------------------------------
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS qa_history (
                id          SERIAL PRIMARY KEY,
                session_id  TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
                question    TEXT NOT NULL,
                answer      TEXT NOT NULL,
                created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
            )
        """)
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_qa_session ON qa_history(session_id)")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _row_to_dict(row: asyncpg.Record) -> Dict[str, Any]:
    d = dict(row)
    for k in ("created_at", "updated_at", "started_at", "completed_at"):
        if k in d and d[k] is not None:
            d[k] = d[k].isoformat()
    return d


def _parse_iso_dt(value) -> "datetime | None":
    """Parse an ISO-8601 string to a datetime, or pass through if already datetime/None."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value))
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Analysis CRUD (blob-level — unchanged)
# ---------------------------------------------------------------------------

async def save_analysis(state: Dict[str, Any]) -> None:
    """Insert or update an analysis session in the database."""
    pool = await get_pool()
    session_id = state.get("session_id", "")
    if not session_id:
        return

    serializable = {k: v for k, v in state.items() if k != "progress_callback"}
    state_json = json.dumps(serializable, default=str)

    async with pool.acquire() as conn:
        await conn.execute("""
            INSERT INTO analyses (
                id, program_hash, binary_path, status, intent, user_query,
                summary, started_at, completed_at, duration_seconds, state_json, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, now())
            ON CONFLICT (id) DO UPDATE SET
                status           = EXCLUDED.status,
                intent           = EXCLUDED.intent,
                user_query       = EXCLUDED.user_query,
                summary          = EXCLUDED.summary,
                started_at       = EXCLUDED.started_at,
                completed_at     = EXCLUDED.completed_at,
                duration_seconds = EXCLUDED.duration_seconds,
                state_json       = EXCLUDED.state_json,
                updated_at       = now()
        """,
            session_id,
            state.get("program_hash", ""),
            state.get("binary_path", ""),
            state.get("status", "initialized"),
            state.get("intent"),
            state.get("user_query"),
            state.get("summary"),
            _parse_iso_dt(state.get("started_at_iso")),
            _parse_iso_dt(state.get("completed_at_iso")),
            state.get("duration_seconds"),
            state_json,
        )


async def save_verdict(session_id: str, verdict: str, threat_score: int) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE analyses SET verdict = $1, threat_score = $2, updated_at = now() WHERE id = $3",
            verdict, threat_score, session_id,
        )


async def save_qa(session_id: str, question: str, answer: str) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO qa_history (session_id, question, answer) VALUES ($1, $2, $3)",
            session_id, question, answer,
        )


async def get_analysis_by_id(session_id: str) -> Optional[Dict[str, Any]]:
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM analyses WHERE id = $1", session_id)
    if row is None:
        return None
    return _row_to_dict(row)


async def get_analysis_by_hash(program_hash: str) -> Optional[Dict[str, Any]]:
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM analyses WHERE program_hash = $1 ORDER BY created_at DESC LIMIT 1",
            program_hash,
        )
    if row is None:
        return None
    return _row_to_dict(row)


async def list_analyses(
    limit: int = 50,
    offset: int = 0,
    status: Optional[str] = None,
    search: Optional[str] = None,
) -> List[Dict[str, Any]]:
    pool = await get_pool()
    conditions: list[str] = []
    params: list[Any] = []
    idx = 1

    if status:
        conditions.append(f"status = ${idx}")
        params.append(status)
        idx += 1
    if search:
        like = f"%{search}%"
        conditions.append(
            f"(program_hash ILIKE ${idx} OR binary_path ILIKE ${idx+1} OR summary ILIKE ${idx+2})"
        )
        params.extend([like, like, like])
        idx += 3

    where = ""
    if conditions:
        where = "WHERE " + " AND ".join(conditions)

    query = (
        f"SELECT id, program_hash, binary_path, status, verdict, threat_score, "
        f"summary, started_at, completed_at, duration_seconds, created_at, updated_at "
        f"FROM analyses {where} ORDER BY created_at DESC LIMIT ${idx} OFFSET ${idx+1}"
    )
    params.extend([limit, offset])

    async with pool.acquire() as conn:
        rows = await conn.fetch(query, *params)
    return [_row_to_dict(r) for r in rows]


async def get_analysis_count(
    status: Optional[str] = None,
    search: Optional[str] = None,
) -> int:
    pool = await get_pool()
    conditions: list[str] = []
    params: list[Any] = []
    idx = 1

    if status:
        conditions.append(f"status = ${idx}")
        params.append(status)
        idx += 1
    if search:
        like = f"%{search}%"
        conditions.append(
            f"(program_hash ILIKE ${idx} OR binary_path ILIKE ${idx+1} OR summary ILIKE ${idx+2})"
        )
        params.extend([like, like, like])
        idx += 3

    where = ""
    if conditions:
        where = "WHERE " + " AND ".join(conditions)

    async with pool.acquire() as conn:
        row = await conn.fetchval(f"SELECT COUNT(*) FROM analyses {where}", *params)
    return row or 0


async def get_qa_history(session_id: str) -> List[Dict[str, Any]]:
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT * FROM qa_history WHERE session_id = $1 ORDER BY created_at ASC",
            session_id,
        )
    return [_row_to_dict(r) for r in rows]


async def load_state_json(session_id: str) -> Optional[Dict[str, Any]]:
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT state_json FROM analyses WHERE id = $1", session_id)
    if row is None or row["state_json"] is None:
        return None
    return json.loads(row["state_json"])


async def delete_analysis(session_id: str) -> bool:
    pool = await get_pool()
    async with pool.acquire() as conn:
        result = await conn.execute("DELETE FROM analyses WHERE id = $1", session_id)
    return result.endswith("1")


# ---------------------------------------------------------------------------
# Normalized data persistence (called once on analysis completion)
# ---------------------------------------------------------------------------

async def save_normalized(state: Dict[str, Any]) -> None:
    """Extract and persist structured data from a completed analysis state.

    Idempotent — uses INSERT ... ON CONFLICT DO NOTHING / DO UPDATE so
    re-running on the same binary+analyzer is safe.
    """
    pool = await get_pool()
    program_hash = state.get("program_hash", "")
    if not program_hash:
        return

    async with pool.acquire() as conn:
        async with conn.transaction():
            # --- Binary info (deduplicated by hash) ---
            await _save_binary(conn, program_hash, state)

            # --- Ghidra data ---
            gh = state.get("analysis_results", {})
            gh_decomp = state.get("decompilation_cache", {})
            await _save_analyzer_data(conn, program_hash, "ghidra", gh, gh_decomp)

            # --- Radare2 data ---
            r2 = state.get("r2_analysis_results", {})
            r2_decomp = state.get("r2_decompilation_cache", {})
            if r2:
                await _save_analyzer_data(conn, program_hash, "radare2", r2, r2_decomp)

            # --- IOCs ---
            await _save_iocs(conn, program_hash, state)

    logger.info("normalized_data_saved", program_hash=program_hash[:16])


async def _save_binary(conn: asyncpg.Connection, program_hash: str, state: Dict[str, Any]) -> None:
    """Upsert the binaries table from Ghidra or R2 binary info."""
    gh_bin = state.get("analysis_results", {}).get("binary", {})
    r2_bin = state.get("r2_analysis_results", {}).get("binary", {})
    # Prefer Ghidra, fall back to R2
    b = gh_bin if gh_bin.get("ok") else r2_bin

    await conn.execute("""
        INSERT INTO binaries (program_hash, file_path, architecture, bits, os,
                              image_base, entry_points, imports, exports, file_type)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        ON CONFLICT (program_hash) DO UPDATE SET
            architecture = COALESCE(EXCLUDED.architecture, binaries.architecture),
            bits         = COALESCE(EXCLUDED.bits, binaries.bits),
            os           = COALESCE(EXCLUDED.os, binaries.os),
            image_base   = COALESCE(EXCLUDED.image_base, binaries.image_base),
            entry_points = COALESCE(EXCLUDED.entry_points, binaries.entry_points),
            imports      = COALESCE(EXCLUDED.imports, binaries.imports),
            exports      = COALESCE(EXCLUDED.exports, binaries.exports),
            file_type    = COALESCE(EXCLUDED.file_type, binaries.file_type)
    """,
        program_hash,
        state.get("binary_path", ""),
        b.get("architecture"),
        int(b["bits"]) if b.get("bits") else None,
        b.get("os"),
        b.get("image_base"),
        json.dumps(b.get("entry_points", [])),
        json.dumps(b.get("imports", [])),
        json.dumps(b.get("exports", [])),
        b.get("type"),
    )


async def _save_analyzer_data(
    conn: asyncpg.Connection,
    program_hash: str,
    analyzer: str,
    results: Dict[str, Any],
    decomp_cache: Dict[str, str],
) -> None:
    """Save functions, decompilations, strings, call graph, and attack chains."""

    # --- Functions ---
    funcs_data = results.get("functions", {})
    if funcs_data.get("ok") and funcs_data.get("functions"):
        rows = []
        for f in funcs_data["functions"]:
            rows.append((
                program_hash,
                analyzer,
                str(f.get("name", "")),
                str(f.get("address", "")),
                int(f["size"]) if f.get("size") else None,
                int(f["xrefs"]) if f.get("xrefs") else 0,
                float(f["priority_score"]) if f.get("priority_score") else 0.0,
            ))
        await conn.executemany("""
            INSERT INTO functions (program_hash, analyzer, name, address, size, xref_count, priority_score)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (program_hash, analyzer, name, address) DO NOTHING
        """, rows)

    # --- Decompilations ---
    if decomp_cache:
        decomp_rows = [
            (program_hash, analyzer, func_name, code)
            for func_name, code in decomp_cache.items()
        ]
        await conn.executemany("""
            INSERT INTO decompilations (program_hash, analyzer, function_name, code)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (program_hash, analyzer, function_name) DO UPDATE SET code = EXCLUDED.code
        """, decomp_rows)

    # --- Strings ---
    strings_data = results.get("strings", {})
    if strings_data.get("ok") and strings_data.get("strings"):
        # Delete existing for idempotent re-insert
        await conn.execute(
            "DELETE FROM strings WHERE program_hash = $1 AND analyzer = $2",
            program_hash, analyzer,
        )
        str_rows = []
        for s in strings_data["strings"]:
            val = s.get("value", str(s)) if isinstance(s, dict) else str(s)
            addr = s.get("address", "") if isinstance(s, dict) else ""
            sec = s.get("section", "") if isinstance(s, dict) else ""
            str_rows.append((program_hash, analyzer, val, str(addr), sec))
        # Batch in chunks of 500
        for i in range(0, len(str_rows), 500):
            await conn.executemany("""
                INSERT INTO strings (program_hash, analyzer, value, address, section)
                VALUES ($1, $2, $3, $4, $5)
            """, str_rows[i:i+500])

    # --- Call Graph ---
    cg = results.get("call_graph", {})
    cga = results.get("call_graph_analysis", {})
    if cg.get("ok") or cga.get("ok"):
        await conn.execute("""
            INSERT INTO call_graphs (program_hash, analyzer, nodes, edges, entry_points, adjacency, stats)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (program_hash, analyzer) DO UPDATE SET
                nodes       = EXCLUDED.nodes,
                edges       = EXCLUDED.edges,
                entry_points= EXCLUDED.entry_points,
                adjacency   = EXCLUDED.adjacency,
                stats       = EXCLUDED.stats
        """,
            program_hash,
            analyzer,
            json.dumps(cg.get("nodes", [])),
            json.dumps(cg.get("edges", [])),
            json.dumps(cg.get("entry_points", [])),
            json.dumps(cga.get("adjacency", [])),
            json.dumps(cga.get("stats", {})),
        )

    # --- Attack Chains ---
    chains = cga.get("chains", [])
    if chains:
        await conn.execute(
            "DELETE FROM attack_chains WHERE program_hash = $1 AND analyzer = $2",
            program_hash, analyzer,
        )
        chain_rows = [
            (
                program_hash,
                analyzer,
                c.get("category", ""),
                c.get("sink", ""),
                json.dumps(c.get("path", [])),
                c.get("description", ""),
            )
            for c in chains
        ]
        await conn.executemany("""
            INSERT INTO attack_chains (program_hash, analyzer, category, sink, path, description)
            VALUES ($1, $2, $3, $4, $5, $6)
        """, chain_rows)


async def _save_iocs(conn: asyncpg.Connection, program_hash: str, state: Dict[str, Any]) -> None:
    """Extract IOCs from state and persist them."""
    try:
        from ghidra_agent.ioc_extractor import extract_iocs_from_state
        iocs = extract_iocs_from_state(state)
    except Exception:
        return

    if iocs.is_empty():
        return

    # Clear previous IOCs for idempotent save
    await conn.execute("DELETE FROM iocs WHERE program_hash = $1", program_hash)

    ioc_rows: list[tuple] = []
    for ioc_type, values in iocs.to_dict().items():
        for v in values:
            ioc_rows.append((program_hash, ioc_type, v))

    if ioc_rows:
        for i in range(0, len(ioc_rows), 500):
            await conn.executemany("""
                INSERT INTO iocs (program_hash, ioc_type, value) VALUES ($1, $2, $3)
            """, ioc_rows[i:i+500])


# ---------------------------------------------------------------------------
# Cross-analysis query helpers
# ---------------------------------------------------------------------------

async def search_functions(
    name_pattern: Optional[str] = None,
    analyzer: Optional[str] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """Search functions across all analyzed binaries."""
    pool = await get_pool()
    conditions: list[str] = []
    params: list[Any] = []
    idx = 1

    if name_pattern:
        conditions.append(f"f.name ILIKE ${idx}")
        params.append(f"%{name_pattern}%")
        idx += 1
    if analyzer:
        conditions.append(f"f.analyzer = ${idx}")
        params.append(analyzer)
        idx += 1

    where = ""
    if conditions:
        where = "WHERE " + " AND ".join(conditions)

    async with pool.acquire() as conn:
        rows = await conn.fetch(f"""
            SELECT f.*, b.architecture, b.file_path
            FROM functions f
            LEFT JOIN binaries b ON f.program_hash = b.program_hash
            {where}
            ORDER BY f.priority_score DESC
            LIMIT ${idx}
        """, *params, limit)
    return [_row_to_dict(r) for r in rows]


async def search_iocs(
    ioc_type: Optional[str] = None,
    value_pattern: Optional[str] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """Search IOCs across all analyzed binaries."""
    pool = await get_pool()
    conditions: list[str] = []
    params: list[Any] = []
    idx = 1

    if ioc_type:
        conditions.append(f"ioc_type = ${idx}")
        params.append(ioc_type)
        idx += 1
    if value_pattern:
        conditions.append(f"value ILIKE ${idx}")
        params.append(f"%{value_pattern}%")
        idx += 1

    where = ""
    if conditions:
        where = "WHERE " + " AND ".join(conditions)

    async with pool.acquire() as conn:
        rows = await conn.fetch(f"""
            SELECT * FROM iocs {where} ORDER BY created_at DESC LIMIT ${idx}
        """, *params, limit)
    return [_row_to_dict(r) for r in rows]


async def search_strings_across(
    pattern: str,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """Full-text search strings across all binaries."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT s.program_hash, s.analyzer, s.value, s.address, b.file_path
            FROM strings s
            LEFT JOIN binaries b ON s.program_hash = b.program_hash
            WHERE s.value ILIKE $1
            ORDER BY s.created_at DESC
            LIMIT $2
        """, f"%{pattern}%", limit)
    return [_row_to_dict(r) for r in rows]


async def get_binary_functions(program_hash: str, analyzer: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get all functions for a specific binary."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        if analyzer:
            rows = await conn.fetch(
                "SELECT * FROM functions WHERE program_hash = $1 AND analyzer = $2 ORDER BY priority_score DESC",
                program_hash, analyzer,
            )
        else:
            rows = await conn.fetch(
                "SELECT * FROM functions WHERE program_hash = $1 ORDER BY priority_score DESC",
                program_hash,
            )
    return [_row_to_dict(r) for r in rows]


async def get_binary_decompilations(program_hash: str, analyzer: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get all decompiled functions for a specific binary."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        if analyzer:
            rows = await conn.fetch(
                "SELECT * FROM decompilations WHERE program_hash = $1 AND analyzer = $2 ORDER BY function_name",
                program_hash, analyzer,
            )
        else:
            rows = await conn.fetch(
                "SELECT * FROM decompilations WHERE program_hash = $1 ORDER BY analyzer, function_name",
                program_hash,
            )
    return [_row_to_dict(r) for r in rows]


async def get_binary_iocs(program_hash: str) -> List[Dict[str, Any]]:
    """Get all IOCs for a specific binary."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT * FROM iocs WHERE program_hash = $1 ORDER BY ioc_type, value",
            program_hash,
        )
    return [_row_to_dict(r) for r in rows]


async def get_binary_attack_chains(program_hash: str) -> List[Dict[str, Any]]:
    """Get attack chains for a specific binary."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT * FROM attack_chains WHERE program_hash = $1 ORDER BY category",
            program_hash,
        )
    return [_row_to_dict(r) for r in rows]
