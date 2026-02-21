import asyncio
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from tenacity import retry, stop_after_attempt, wait_fixed

from ghidra_agent.config import settings
from ghidra_agent.logging import logger
from ghidra_agent.storage import read_json, write_json
from ghidra_agent.utils import ensure_directory, safe_basename


@dataclass
class GhidraTaskResult:
    ok: bool
    payload: Dict[str, Any]
    logs: List[str]
    error: Optional[str] = None


class GhidraHeadlessRunner:
    def __init__(self) -> None:
        self.project_root = Path(settings.ghidra_project_root)
        self.shared_root = Path(settings.ghidra_shared_root)
        ensure_directory(self.project_root)
        ensure_directory(self.shared_root)

    def _project_path(self, program_hash: str, session_id: str) -> Path:
        return self.project_root / f"{program_hash}-{session_id}"

    def _task_root(self, session_id: str) -> Path:
        path = self.shared_root / session_id
        ensure_directory(path)
        return path

    def _project_exists(self, program_hash: str, session_id: str) -> bool:
        """Check if a Ghidra project has already been created for this session."""
        project_path = self._project_path(program_hash, session_id)
        # Ghidra creates {project_location}/{project_name}.gpr at the project root level
        gpr_file = Path(str(project_path) + ".gpr")
        return gpr_file.exists()

    def _container_args(
        self,
        program_hash: str,
        session_id: str,
        task_root: Path,
        binary_path: Optional[Path],
        script_name: str,
        allow_write: bool,
    ) -> List[str]:
        project_path = self._project_path(program_hash, session_id)
        # Do NOT create project_path as a directory -- Ghidra uses it as a
        # project name and creates {name}.gpr + {name}.rep at project_root.
        already_imported = self._project_exists(program_hash, session_id)
        # Use 'docker exec' on the already-running ghidra container which has
        # PyGhidra installed, rather than 'docker run' which would spawn a fresh
        # container that lacks the PyGhidra installation.
        base_args = [
            settings.docker_cli_path,
            "exec",
            "-i",
        ]
        base_args += [
            "-e",
            "XDG_CONFIG_HOME=/data/shared/ghidra-config",
        ]
        base_args.append(settings.ghidra_volume_container)
        if Path(settings.ghidra_headless_script_path).name == "pyghidraRun":
            base_args += [
                settings.ghidra_headless_script_path,
                "-H",
            ]
        else:
            base_args.append(settings.ghidra_headless_script_path)
        base_args += [
            settings.ghidra_project_root,
            project_path.name,
        ]
        if binary_path:
            bp = Path(binary_path) if not isinstance(binary_path, Path) else binary_path
            if str(bp).startswith(str(self.shared_root)):
                import_path = str(bp)
            else:
                import_path = str(self.shared_root / bp.name)
            if already_imported:
                # Project exists: open the already-imported program instead of re-importing
                base_args += ["-process", bp.name]
            else:
                base_args += ["-import", import_path]
        if not allow_write and already_imported:
            # Only use -readOnly when processing an existing project.
            # The first import must NOT be readOnly so the project is persisted.
            base_args.append("-readOnly")

        # I10 FIX: Use -noanalysis for subsequent runs on existing project to save time
        if already_imported:
            base_args.append("-noanalysis")

        base_args += [
            "-scriptPath",
            settings.ghidra_scripts_root,
            "-postScript",
            script_name,
            str(task_root / "input.json"),
            str(task_root / "output.json"),
            str(task_root / "log.txt"),
        ]
        return base_args

    def _sync_scripts(self) -> None:
        source = Path(settings.ghidra_scripts_source)
        target = Path(settings.ghidra_scripts_root)
        ensure_directory(target)
        for script in source.glob("*.py"):
            destination = target / script.name
            if destination.exists() and destination.stat().st_mtime >= script.stat().st_mtime:
                continue
            shutil.copy2(script, destination)

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
    async def run_task(
        self,
        session_id: str,
        program_hash: str,
        script_name: str,
        payload: Dict[str, Any],
        binary_path: Optional[Path] = None,
        allow_write: bool = False,
    ) -> GhidraTaskResult:
        self._sync_scripts()
        task_root = self._task_root(session_id)
        input_path = task_root / "input.json"
        output_path = task_root / "output.json"
        log_path = task_root / "log.txt"
        # Remove stale output from previous script runs in the same session
        if output_path.exists():
            output_path.unlink()
        payload["program_hash"] = program_hash
        payload["binary_path"] = str(binary_path) if binary_path else None
        write_json(input_path, payload)
        args = self._container_args(program_hash, session_id, task_root, binary_path, script_name, allow_write)
        logger.info("ghidra_task_start", script=script_name, args=args)
        process = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            # Send "y\n" responses to auto-accept any PyGhidra prompts, then close stdin
            stdout, stderr = await asyncio.wait_for(
                process.communicate(input=b"y\ny\n"),
                timeout=settings.default_analysis_timeout,
            )
        except asyncio.TimeoutError:
            process.kill()
            return GhidraTaskResult(ok=False, payload={}, logs=[], error="Ghidra task timeout")
        if stdout:
            logger.info("ghidra_task_stdout", output=stdout.decode("utf-8", errors="ignore"))
        if stderr:
            logger.warning("ghidra_task_stderr", output=stderr.decode("utf-8", errors="ignore"))
        output = read_json(output_path)
        ok = process.returncode == 0 and output.get("ok", False)
        error = output.get("error") if not ok else None
        logs = []
        if log_path.exists():
            logs = [line.strip() for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        return GhidraTaskResult(ok=ok, payload=output, logs=logs, error=error)

    def script_path(self, name: str) -> Path:
        return Path(settings.ghidra_scripts_root) / safe_basename(name)
