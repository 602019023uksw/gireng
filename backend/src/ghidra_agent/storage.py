import json
from pathlib import Path
from typing import Any, Dict, List

from ghidra_agent.logging import logger
from ghidra_agent.utils import ensure_directory


def write_json(path: Path, payload: Dict[str, Any]) -> None:
    ensure_directory(path.parent)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def read_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        logger.warning("json_missing", path=str(path))
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        logger.error("json_decode_error", path=str(path), error=str(exc))
        return {"ok": False, "error": f"Malformed JSON in {path.name}"}


def collect_logs(log_path: Path) -> List[str]:
    if not log_path.exists():
        return []
    return [line.strip() for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
