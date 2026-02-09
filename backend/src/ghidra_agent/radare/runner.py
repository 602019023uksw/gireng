"""Radare2 headless runner — executes r2 commands inside a Docker container."""

import asyncio
import json
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional

from ghidra_agent.config import settings
from ghidra_agent.logging import logger


@dataclass
class R2TaskResult:
    ok: bool
    payload: Dict[str, Any]
    logs: List[str] = field(default_factory=list)
    error: Optional[str] = None


class Radare2Runner:
    """Run r2 commands against a binary inside the radare2 container.

    Pattern:  docker exec radare2 r2 -q -c '<commands>' /data/shared/<binary>

    The binary is already available inside the container because both the
    agent and radare2 containers share the *ghidra_shared* volume mounted
    at ``/data/shared``.
    """

    # How many times to retry a transient failure before giving up.
    MAX_RETRIES = 2
    RETRY_DELAY = 1.5  # seconds

    def __init__(self) -> None:
        self.container = settings.r2_container_name
        self.shared_root = Path(settings.r2_shared_root)
        self._container_verified = False
        self._available_decompilers: Optional[List[str]] = None

    # ------------------------------------------------------------------
    # Container health
    # ------------------------------------------------------------------

    async def verify_container(self) -> bool:
        """Check that the R2 container is running and responsive.

        Caches the result after the first successful check so subsequent
        calls are free.  Call ``reset()`` to force re-verification.
        """
        if self._container_verified:
            return True

        try:
            proc = await asyncio.create_subprocess_exec(
                settings.docker_cli_path, "exec", self.container,
                "r2", "-q", "-v",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            if proc.returncode == 0:
                version = stdout.decode("utf-8", errors="ignore").strip().split("\n")[0]
                logger.info("r2_container_verified", version=version)
                self._container_verified = True
                return True
        except Exception as exc:
            logger.warning("r2_container_verify_failed", error=str(exc))

        return False

    async def detect_decompilers(self) -> List[str]:
        """Probe which decompiler plugins are available in the R2 container.

        Returns a list such as ``["pdg", "pdd", "pdf"]`` in priority order.
        The result is cached for the lifetime of the Runner instance.
        """
        if self._available_decompilers is not None:
            return self._available_decompilers

        available: List[str] = []

        for cmd, label in [("pdg", "r2ghidra"), ("pdd", "r2dec")]:
            try:
                proc = await asyncio.create_subprocess_exec(
                    settings.docker_cli_path, "exec", self.container,
                    "r2", "-q", "-c", f"?e test;{cmd}", "/dev/null",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, stderr = await asyncio.wait_for(proc.communicate(), timeout=15)
                # If stderr contains "unknown command" → not installed
                err_text = stderr.decode("utf-8", errors="ignore").lower()
                if "unknown" not in err_text and "invalid" not in err_text:
                    available.append(cmd)
                    logger.info("r2_decompiler_available", plugin=label, command=cmd)
                else:
                    logger.info("r2_decompiler_missing", plugin=label, command=cmd)
            except Exception:
                logger.info("r2_decompiler_probe_failed", command=cmd)

        # pdf (plain disassembly) is always available
        available.append("pdf")

        self._available_decompilers = available
        logger.info("r2_decompiler_chain", chain=available)
        return available

    def reset(self) -> None:
        """Clear cached state (useful after container restart)."""
        self._container_verified = False
        self._available_decompilers = None

    def _binary_path_in_container(self, binary_path: Path) -> str:
        """Translate the host/agent path into the container-local path."""
        # binary_path is typically /data/shared/<filename>
        name = binary_path.name
        # Always use POSIX paths since the container runs Linux
        return str(PurePosixPath(self.shared_root) / name)

    async def run_command(
        self,
        binary_path: Path,
        r2_commands: str,
        timeout: Optional[int] = None,
    ) -> R2TaskResult:
        """Execute one or more r2 commands and return parsed output.

        Retries up to ``MAX_RETRIES`` times on transient failures
        (timeouts, connection errors).  Permanent errors (non-zero exit
        from r2) are returned immediately.
        """
        container_bin = self._binary_path_in_container(binary_path)
        effective_timeout = timeout or settings.r2_timeout

        args = [
            settings.docker_cli_path,
            "exec",
            "-i",
            self.container,
            "r2",
            "-q",       # quiet mode
            "-e", "bin.cache=true",  # speed up repeated analyses
            "-c", r2_commands,
            container_bin,
        ]

        last_error: Optional[str] = None

        for attempt in range(1, self.MAX_RETRIES + 2):  # 1-based, +1 for initial
            logger.info(
                "r2_task_start",
                commands=r2_commands,
                binary=container_bin,
                attempt=attempt,
            )

            try:
                process = await asyncio.create_subprocess_exec(
                    *args,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=effective_timeout,
                )
            except asyncio.TimeoutError:
                last_error = f"Radare2 command timeout after {effective_timeout}s"
                logger.warning("r2_task_timeout", commands=r2_commands, attempt=attempt)
                if attempt <= self.MAX_RETRIES:
                    await asyncio.sleep(self.RETRY_DELAY)
                    continue
                return R2TaskResult(ok=False, payload={}, error=last_error)
            except Exception as exc:
                last_error = str(exc)
                logger.warning("r2_task_exec_failed", error=last_error, attempt=attempt)
                if attempt <= self.MAX_RETRIES:
                    await asyncio.sleep(self.RETRY_DELAY)
                    continue
                return R2TaskResult(ok=False, payload={}, error=last_error)

            stdout_text = stdout.decode("utf-8", errors="ignore").strip()
            stderr_text = stderr.decode("utf-8", errors="ignore").strip()

            if stderr_text:
                logger.debug("r2_task_stderr", output=stderr_text[:500])

            if process.returncode != 0:
                # Non-zero exit is a permanent error — don't retry
                return R2TaskResult(
                    ok=False,
                    payload={"raw": stdout_text},
                    logs=[stderr_text] if stderr_text else [],
                    error=f"r2 exited with code {process.returncode}",
                )

            return R2TaskResult(
                ok=True,
                payload={"raw": stdout_text},
                logs=[stderr_text] if stderr_text else [],
            )

        # Should not be reached but satisfy the type checker
        return R2TaskResult(ok=False, payload={}, error=last_error or "max retries exceeded")

    async def run_json_command(
        self,
        binary_path: Path,
        r2_commands: str,
        timeout: Optional[int] = None,
    ) -> R2TaskResult:
        """Run r2 commands that produce JSON output (e.g. ``aflj``, ``izj``).

        Attempts to parse the raw stdout as JSON.  Falls back to raw text on failure.
        """
        result = await self.run_command(binary_path, r2_commands, timeout)
        if not result.ok:
            return result

        raw = result.payload.get("raw", "")
        # r2 sometimes prepends log lines before JSON.  Try to find the first
        # '[' or '{' and parse from there.
        json_start = -1
        for i, ch in enumerate(raw):
            if ch in ('[', '{'):
                json_start = i
                break

        if json_start >= 0:
            try:
                parsed = json.loads(raw[json_start:])
                result.payload = {"json": parsed, "raw": raw}
                return result
            except json.JSONDecodeError:
                pass

        # Could not parse — return raw text
        result.payload = {"raw": raw}
        return result
