"""Qiling headless runner — executes Qiling scripts inside a Docker container."""

from __future__ import annotations

import asyncio
import json
import uuid
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional

from ghidra_agent.config import settings
from ghidra_agent.logging import logger


@dataclass
class QilingTaskResult:
    ok: bool
    payload: Dict[str, Any]
    logs: List[str] = field(default_factory=list)
    error: Optional[str] = None


class QilingRunner:
    """Run Qiling scripts against a binary inside the qiling container."""

    MAX_RETRIES = 1
    RETRY_DELAY = 1.0

    def __init__(self) -> None:
        self.container = settings.qiling_container_name
        self.shared_root = Path(settings.qiling_shared_root)
        self.shared_root_in_container = PurePosixPath(settings.qiling_shared_root)
        self.scripts_root = PurePosixPath(settings.qiling_scripts_root)
        self.timeout = settings.qiling_timeout
        self._container_verified = False

    def reset(self) -> None:
        self._container_verified = False

    def _shared_path_in_container(self, host_path: Path) -> str:
        return str(self.shared_root_in_container / host_path.name)

    def _binary_path_in_container(self, binary_path: Path) -> str:
        return str(self.shared_root_in_container / binary_path.name)

    async def verify_container(self) -> bool:
        """Check that the Qiling container is up and can import qiling."""
        if self._container_verified:
            return True

        result = await self._docker_exec(
            ["python3", "-c", "import qiling; print(qiling.__version__)"],
            timeout=45,
        )
        if result.ok:
            version = result.payload.get("raw", "").strip().splitlines()[0] if result.payload.get("raw") else "unknown"
            logger.info("qiling_container_verified", version=version)
            self._container_verified = True
            return True

        logger.warning("qiling_container_verify_failed", error=result.error)
        return False

    async def run_script(
        self,
        script_name: str,
        binary_path: Path,
        payload: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None,
    ) -> QilingTaskResult:
        """Execute a Qiling analysis script and parse JSON output."""
        self.shared_root.mkdir(parents=True, exist_ok=True)

        script_file = Path(script_name).name
        script_path = str(self.scripts_root / script_file)
        effective_timeout = timeout or self.timeout

        task_id = uuid.uuid4().hex[:12]
        input_host = self.shared_root / f"qiling_input_{task_id}.json"
        output_host = self.shared_root / f"qiling_output_{task_id}.json"

        input_container = self._shared_path_in_container(input_host)
        output_container = self._shared_path_in_container(output_host)
        binary_container = self._binary_path_in_container(binary_path)

        request_payload: Dict[str, Any] = {
            "binary_path": binary_container,
            "host_binary_path": str(binary_path),
            "timeout": effective_timeout,
            "rootfs_base": settings.qiling_rootfs_base,
        }
        if payload:
            request_payload.update(payload)

        try:
            input_host.write_text(json.dumps(request_payload), encoding="utf-8")

            last_error: Optional[str] = None
            run_result: Optional[QilingTaskResult] = None

            for attempt in range(1, self.MAX_RETRIES + 2):
                logger.info(
                    "qiling_task_start",
                    script=script_file,
                    binary=binary_container,
                    attempt=attempt,
                )
                run_result = await self._docker_exec(
                    ["python3", script_path, input_container, output_container],
                    timeout=effective_timeout + 30,
                )
                if run_result.ok:
                    break
                last_error = run_result.error
                if attempt <= self.MAX_RETRIES:
                    await asyncio.sleep(self.RETRY_DELAY)

            if run_result is None or not run_result.ok:
                return QilingTaskResult(
                    ok=False,
                    payload={},
                    error=last_error or "Qiling script failed",
                    logs=[] if run_result is None else run_result.logs,
                )

            if output_host.exists():
                raw_output = output_host.read_text(encoding="utf-8", errors="ignore")
            else:
                cat_result = await self._docker_exec(["cat", output_container], timeout=15)
                if not cat_result.ok:
                    return QilingTaskResult(
                        ok=False,
                        payload={},
                        error=cat_result.error or "Qiling output file not found",
                        logs=run_result.logs + cat_result.logs,
                    )
                raw_output = cat_result.payload.get("raw", "")

            try:
                parsed = json.loads(raw_output) if raw_output.strip() else {}
            except json.JSONDecodeError as exc:
                return QilingTaskResult(
                    ok=False,
                    payload={"raw": raw_output},
                    error=f"Invalid JSON output from {script_file}: {exc}",
                    logs=run_result.logs,
                )

            return QilingTaskResult(ok=True, payload=parsed, logs=run_result.logs)
        finally:
            # Best-effort cleanup in both local filesystem and container context.
            try:
                input_host.unlink(missing_ok=True)
            except OSError:
                pass
            try:
                output_host.unlink(missing_ok=True)
            except OSError:
                pass
            await self._docker_exec(["rm", "-f", input_container, output_container], timeout=15)

    async def _docker_exec(self, command: List[str], timeout: int) -> QilingTaskResult:
        args = [settings.docker_cli_path, "exec", "-i", self.container, *command]
        try:
            process = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            return QilingTaskResult(ok=False, payload={}, error=f"Qiling command timeout after {timeout}s")
        except Exception as exc:
            return QilingTaskResult(ok=False, payload={}, error=str(exc))

        stdout_text = stdout.decode("utf-8", errors="ignore").strip()
        stderr_text = stderr.decode("utf-8", errors="ignore").strip()
        logs = [stderr_text] if stderr_text else []

        if process.returncode != 0:
            return QilingTaskResult(
                ok=False,
                payload={"raw": stdout_text},
                error=f"qiling exec exited with code {process.returncode}",
                logs=logs,
            )

        return QilingTaskResult(ok=True, payload={"raw": stdout_text}, logs=logs)

