#!/usr/bin/env python3
"""
Gireng Docker Management Script
================================
Convenience wrapper around docker compose for common development tasks.
"""

import subprocess
import sys

COMPOSE_CMD = ["docker", "compose"]

HELP_TEXT = """\
Gireng Docker Management Script
================================
Usage:
    python run.py start           Start all containers (detached)
    python run.py stop            Stop all containers
    python run.py restart         Restart all containers
    python run.py rebuild         Rebuild and restart all containers
    python run.py rebuild agent   Rebuild only the agent container
    python run.py rebuild ui      Rebuild only the ui container
    python run.py logs            Tail live logs (all services)
    python run.py logs agent      Tail live logs for a specific service
    python run.py logs ghidra     Tail live logs for ghidra
    python run.py up              Start with live logs (foreground)
    python run.py status          Show container status
    python run.py db              Open psql shell to the database
    python run.py test            Run backend tests + frontend lint locally
    python run.py lint            Run backend + frontend lint checks locally

Commands:
  start        Start containers in detached mode.
  stop         Stop all containers.
  restart      Restart containers.
  rebuild      Rebuild and restart containers (optionally specify service).
  logs         Tail live logs (optionally specify service).
  up           Start in foreground with live logs (Ctrl+C to stop).
  status       Show container status.
  db           Open psql shell.
  test         Run backend tests + frontend lint checks locally.
  lint         Run backend and frontend lint checks locally.
"""


def run(cmd: list[str], check: bool = True, **kwargs) -> subprocess.CompletedProcess:
    """Run a command, printing it first."""
    print(f"\n> {' '.join(cmd)}\n")
    return subprocess.run(cmd, check=check, **kwargs)


def compose(*args: str, **kwargs) -> subprocess.CompletedProcess:
    """Run a docker compose sub-command."""
    return run([*COMPOSE_CMD, *args], **kwargs)


# ── Commands ────────────────────────────────────────────────────────────────


def cmd_start() -> None:
    compose("up", "-d")


def cmd_stop() -> None:
    compose("down")


def cmd_restart() -> None:
    compose("restart")


def cmd_rebuild(services: list[str]) -> None:
    if services:
        compose("build", "--no-cache", *services)
        compose("up", "-d", *services)
    else:
        compose("build", "--no-cache")
        compose("up", "-d")


def cmd_logs(services: list[str]) -> None:
    compose("logs", "-f", "--tail", "100", *services)


def cmd_up() -> None:
    compose("up")


def cmd_status() -> None:
    compose("ps", "-a")


def cmd_db() -> None:
    interactive = sys.stdin.isatty() and sys.stdout.isatty() and sys.stderr.isatty()
    if interactive:
        run(
            [
                "docker", "exec", "-it", "ireng_postgres",
                "psql", "-U", "ireng", "-d", "ireng",
            ]
        )
    else:
        # Non-interactive: run a single command or just test connectivity
        run(
            [
                "docker", "exec", "ireng_postgres",
                "psql", "-U", "ireng", "-d", "ireng", "-c", "SELECT 1;",
            ]
        )


def cmd_test() -> int:
    """Run tests. Returns non-zero if any step fails."""
    failures = 0

    print("=== Backend tests ===")
    result = run([sys.executable, "-m", "pytest", "backend/tests", "-v"], check=False)
    if result.returncode != 0:
        failures += 1

    print("\n=== Frontend lint (no test suite configured) ===")
    result = run(["npm", "run", "lint", "--prefix", "app"], check=False)
    if result.returncode != 0:
        failures += 1

    if failures:
        print(f"\n[FAIL] {failures} step(s) failed")
    else:
        print("\n[OK] All checks passed")
    return failures


def cmd_lint() -> int:
    """Run linters. Returns non-zero if any step fails."""
    failures = 0

    print("=== Backend lint ===")
    result = run([sys.executable, "-m", "ruff", "check", "backend/"], check=False)
    if result.returncode != 0:
        failures += 1

    print("\n=== Frontend lint ===")
    result = run(["npm", "run", "lint", "--prefix", "app"], check=False)
    if result.returncode != 0:
        failures += 1

    if failures:
        print(f"\n[FAIL] {failures} step(s) failed")
    else:
        print("\n[OK] All checks passed")
    return failures


# ── Dispatch ────────────────────────────────────────────────────────────────

COMMANDS = {
    "start":   (cmd_start,   False),
    "stop":    (cmd_stop,    False),
    "restart": (cmd_restart, False),
    "rebuild": (cmd_rebuild, True),
    "logs":    (cmd_logs,    True),
    "up":      (cmd_up,      False),
    "status":  (cmd_status,  False),
    "db":      (cmd_db,      False),
    "test":    (cmd_test,    False),
    "lint":    (cmd_lint,    False),
}


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help", "help"):
        print(HELP_TEXT)
        sys.exit(0)

    command = sys.argv[1]
    extra = sys.argv[2:]

    if command not in COMMANDS:
        print(f"Unknown command: {command}\n")
        print(HELP_TEXT)
        sys.exit(1)

    handler, accepts_args = COMMANDS[command]

    try:
        if accepts_args:
            rc = handler(extra)
        else:
            rc = handler()
        # test/lint return an int (failure count); exit non-zero if any failed
        if isinstance(rc, int) and rc > 0:
            sys.exit(1)
    except subprocess.CalledProcessError as exc:
        sys.exit(exc.returncode)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(130)


if __name__ == "__main__":
    main()
