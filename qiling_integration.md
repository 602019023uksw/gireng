# Qiling Framework Integration Plan

## Table of Contents

1. [Feasibility Assessment](#feasibility-assessment)
2. [What is Qiling](#what-is-qiling)
3. [Why Qiling for gireng](#why-qiling-for-gireng)
4. [Architecture Fit Analysis](#architecture-fit-analysis)
5. [Integration Plan](#integration-plan)
6. [Data Flow](#data-flow)
7. [Proposed Data Schema](#proposed-data-schema)
8. [Effort Estimate](#effort-estimate)

---

## Feasibility Assessment

### Verdict: Fully Doable

Qiling integrates naturally into gireng's existing multi-analyzer architecture. The codebase already follows a pattern where analyzers (Ghidra, Radare2) run inside dedicated Docker containers and are orchestrated via `asyncio.gather` in the LangGraph `discovery` node. Qiling slots in as a **third analyzer** using the exact same patterns — no architectural redesign required.

### Key Strengths

| Factor | Assessment |
|--------|-----------|
| **Architecture compatibility** | gireng already runs Ghidra + R2 as parallel Docker containers accessed via `docker exec`. Qiling follows the same model. |
| **Data bus** | The shared volume at `/data/shared` already moves binaries between containers. Qiling reads from the same path. |
| **Pipeline pattern** | `r2_graph.py` provides the exact blueprint. A `qiling_graph.py` follows the same async pipeline. |
| **Complementary analysis** | Ghidra/R2 = static. Qiling = dynamic/behavioral. These fill different report sections without overlap. |
| **Python native** | Qiling is a Python framework. No language bridging needed — same as the backend. |
| **Sandboxed execution** | Qiling emulates binaries without executing them natively. Combined with Docker isolation, this is safe for malware analysis. |

### Key Challenge: Rootfs

Qiling requires a **rootfs** (emulated filesystem root) matching the binary's target OS:

- **Linux ELF**: The Qiling Docker container itself provides the rootfs. Qiling's repo ships Linux rootfs templates.
- **Windows PE**: Requires Windows DLLs and registry hive files. These must be pre-bundled in the Docker image or collected from a licensed Windows installation using Qiling's `dllscollector.bat` script.
- **Other platforms** (macOS, UEFI, etc.): Require their own rootfs. Can be added incrementally.

**Strategy**: Start with Linux ELF support (gireng's primary target). Add Windows PE rootfs as a follow-up.

---

## What is Qiling

[Qiling Framework](https://github.com/qilingframework/qiling) (v1.4.7, GPLv2) is an advanced binary emulation framework backed by [Unicorn Engine](https://www.unicorn-engine.org/). It has been presented at Black Hat (USA, EU, Asia, MEA), DEFCON, HITB, and Zeronights.

### Capabilities

| Capability | Description |
|-----------|-------------|
| **Multi-platform** | Windows, macOS, Linux, Android, BSD, UEFI, DOS, MBR |
| **Multi-architecture** | 8086, x86, x86_64, ARM, ARM64, MIPS, RISC-V, PowerPC |
| **File formats** | PE, Mach-O, ELF, COM, MBR |
| **Kernel modules** | `.ko` (Linux), `.sys` (Windows), `.kext` (macOS) via Demigod |
| **Sandboxed execution** | Emulates binary in isolated environment without native execution |
| **Fine-grain instrumentation** | Hooks at instruction, basic-block, memory-access, exception, syscall, and I/O levels |
| **Dynamic hotpatch** | Patch running code on-the-fly, including loaded libraries |
| **Snapshot/restore** | Save and restore execution state |
| **Debugging** | Built-in debugger with reverse debugging, GDB server |

### How It Works

Unlike QEMU (which forwards syscalls to the host OS), Qiling implements its own OS layer. It:

1. Loads the binary using format-specific loaders (PE, ELF, Mach-O)
2. Resolves and relocates shared libraries
3. Implements syscall and API handlers for the target OS
4. Emulates CPU instructions via Unicorn Engine
5. Provides hooks at every level for instrumentation

```python
from qiling import Qiling
from qiling.const import QL_VERBOSE

# Basic emulation
ql = Qiling(["/path/to/binary"], "/path/to/rootfs", verbose=QL_VERBOSE.DEBUG)
ql.run()
```

### Key APIs for gireng Integration

| API | Purpose | Use in gireng |
|-----|---------|---------------|
| `Qiling(argv, rootfs)` | Initialize emulation | Load uploaded binary |
| `ql.run(timeout=N)` | Execute with timeout | Controlled emulation |
| `ql.hook_code(cb)` | Hook every instruction | Instruction tracing |
| `ql.hook_address(cb, addr)` | Hook specific address | Breakpoints |
| `ql.os.set_syscall(name, cb)` | Hook syscall by name | Syscall tracing |
| `ql.os.set_api(name, cb)` | Hook OS API call | API call capture |
| `ql.hook_mem_read(cb)` | Hook memory reads | Memory access tracking |
| `ql.hook_mem_write(cb)` | Hook memory writes | Self-modifying code detection |
| `ql.mem.read(addr, size)` | Read emulated memory | Memory dumps |
| `ql.arch.regs.*` | Read/write registers | Register snapshots |
| `ql.emu_stop()` | Stop emulation | Kill switch on suspicious behavior |
| `ql.save()` / `ql.restore()` | Snapshot state | State preservation |

### Syscall/API Hooking (Critical for Malware Analysis)

Qiling allows intercepting every OS interaction:

```python
from qiling.const import QL_INTERCEPT

# Hook a syscall — captures all file operations
def my_open(ql, pathname, flags, mode):
    path = ql.mem.string(pathname)
    log.append({"syscall": "open", "path": path, "flags": flags})
    # Let original syscall proceed
    return None

ql.os.set_syscall("open", my_open, QL_INTERCEPT.ENTER)

# Hook a Windows API
def my_CreateFileW(ql, address, params):
    log.append({"api": "CreateFileW", "filename": params["lpFileName"]})

ql.os.set_api("CreateFileW", my_CreateFileW)
```

---

## Why Qiling for gireng

### Gap Analysis: What gireng Currently Cannot See

gireng's existing analysis (Ghidra + Radare2) is purely **static** — it examines the binary without executing it. This leaves blind spots:

| Blind Spot | Static Analysis | Qiling Dynamic Analysis |
|-----------|----------------|------------------------|
| **Runtime behavior** | Can only infer from code patterns | Actually observes what the binary does |
| **Packed/obfuscated code** | Sees encrypted/compressed payload | Emulates unpacking, sees decrypted code |
| **Dynamic API resolution** | Cannot resolve `GetProcAddress` targets | Captures actual resolved function pointers |
| **Self-modifying code** | Cannot detect code that rewrites itself | Hooks memory writes to executable regions |
| **C2 communication** | Extracts static strings (URLs, IPs) | Captures actual connection attempts, DNS queries |
| **Anti-analysis evasion** | May not detect environment checks | Observes `IsDebuggerPresent`, timing checks, VM detection |
| **Conditional logic** | Analyzes all paths equally | Shows which path is actually taken at runtime |
| **Shellcode execution** | Identifies shellcode blobs | Emulates shellcode, shows its behavior |
| **File/registry operations** | Infers from imported APIs | Captures actual paths, keys, and data written |

### Value Proposition

Adding Qiling transforms gireng from a **static analysis platform** into a **hybrid static + dynamic analysis platform** — the gold standard for malware analysis. The LLM synthesizer can cross-reference:

- Static disassembly (Ghidra) + runtime traces (Qiling) to confirm malicious intent
- String extraction (R2) + actual network connections (Qiling) to validate C2 indicators
- Call graph (Ghidra) + execution trace (Qiling) to show which code paths are actually reached

---

## Architecture Fit Analysis

### Current Architecture

```
┌───────────────── gireng Analysis Pipeline ─────────────────┐
│                                                            │
│  discovery node (graph.py)                                 │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  asyncio.gather(                                     │  │
│  │    _ghidra_discovery(state),   ← Ghidra container    │  │
│  │    _safe_r2_pipeline(state),   ← Radare2 container   │  │
│  │  )                                                   │  │
│  └──────────────────────────────────────────────────────┘  │
│                         │                                  │
│                         ▼                                  │
│  synthesize node                                           │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Reads:                                              │  │
│  │    state["analysis_results"]        (Ghidra)         │  │
│  │    state["r2_analysis_results"]     (Radare2)        │  │
│  │  → LLM generates report                             │  │
│  └──────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────┘
```

### Proposed Architecture with Qiling

```
┌───────────────── gireng Analysis Pipeline ─────────────────┐
│                                                            │
│  discovery node (graph.py)                                 │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  asyncio.gather(                                     │  │
│  │    _ghidra_discovery(state),     ← Ghidra container  │  │
│  │    _safe_r2_pipeline(state),     ← Radare2 container │  │
│  │    _safe_qiling_pipeline(state), ← Qiling container  │  │
│  │  )                               ▲ NEW               │  │
│  └──────────────────────────────────────────────────────┘  │
│                         │                                  │
│                         ▼                                  │
│  synthesize node                                           │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Reads:                                              │  │
│  │    state["analysis_results"]           (Ghidra)      │  │
│  │    state["r2_analysis_results"]        (Radare2)     │  │
│  │    state["qiling_analysis_results"]    (Qiling) NEW  │  │
│  │  → LLM generates comprehensive report               │  │
│  └──────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────┘
```

### Layer-by-Layer Mapping

| Layer | Existing Pattern | Qiling Equivalent |
|-------|-----------------|-------------------|
| **Docker** | `radare2` service in `docker-compose.yml` — shared volume, idle after setup | `qiling` service — same shared volume, Qiling pre-installed, idle |
| **Config** | `ENABLE_R2`, `R2_CONTAINER_NAME` in `config.py` | `ENABLE_QILING`, `QILING_CONTAINER_NAME` |
| **Runner** | `Radare2Runner` — `docker exec` into R2 container | `QilingRunner` — `docker exec` into Qiling container |
| **Tools** | `r2_tools.py` — `@tool` decorated async functions | `qiling_tools.py` — same `@tool` pattern |
| **Pipeline** | `r2_graph.py` — `run_r2_pipeline(state)` | `qiling_graph.py` — `run_qiling_pipeline(state)` |
| **State** | `r2_analysis_results`, `r2_decompilation_cache` | `qiling_analysis_results`, `qiling_execution_cache` |
| **Graph** | `_safe_r2_pipeline(state)` in `asyncio.gather` | `_safe_qiling_pipeline(state)` added to same gather |
| **Init** | R2 container health check in `initialize_ghidra` | Qiling container health check alongside |
| **Synthesize** | R2 results read into LLM context | Qiling results read into LLM context |
| **Report** | R2 data displayed in report sections | Qiling behavioral data in new "Dynamic Analysis" section |
| **API** | `GET /api/analysis/{hash}/results/radare2` | `GET /api/analysis/{hash}/results/qiling` |

---

## Integration Plan

### Phase 1: Infrastructure (Docker + Config + Runner)

**Goal**: Get a Qiling container running and callable from the agent.

#### 1.1 Create Qiling Dockerfile

```dockerfile
# backend/Dockerfile.qiling
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git gcc g++ cmake pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir qiling==1.4.7

# Clone Qiling rootfs (Linux only for now)
RUN git clone --depth 1 https://github.com/qilingframework/qiling.git /tmp/qiling \
    && mkdir -p /opt/qiling/rootfs \
    && cp -r /tmp/qiling/examples/rootfs/x86_linux /opt/qiling/rootfs/ \
    && cp -r /tmp/qiling/examples/rootfs/x8664_linux /opt/qiling/rootfs/ \
    && rm -rf /tmp/qiling

# Shared data volume mount point
VOLUME ["/data/shared"]

# Analysis scripts directory
COPY qiling_scripts/ /opt/qiling/scripts/

WORKDIR /opt/qiling
CMD ["tail", "-f", "/dev/null"]
```

#### 1.2 Add `qiling` Service to `docker-compose.yml`

```yaml
qiling:
  build:
    context: ./backend
    dockerfile: Dockerfile.qiling
  container_name: qiling_emulator
  volumes:
    - ghidra_shared:/data/shared
  restart: unless-stopped
  healthcheck:
    test: ["CMD", "python3", "-c", "import qiling; print('ok')"]
    interval: 30s
    timeout: 10s
    retries: 3
  deploy:
    resources:
      limits:
        memory: 2G
        cpus: '2.0'
  security_opt:
    - no-new-privileges:true
```

#### 1.3 Add Config Settings

In `config.py`:

```python
ENABLE_QILING: bool = os.getenv("ENABLE_QILING", "true").lower() == "true"
QILING_CONTAINER_NAME: str = os.getenv("QILING_CONTAINER_NAME", "qiling_emulator")
QILING_TIMEOUT: int = int(os.getenv("QILING_TIMEOUT", "60"))  # seconds
QILING_ROOTFS_BASE: str = "/opt/qiling/rootfs"
```

#### 1.4 Create `QilingRunner`

New file: `backend/src/ghidra_agent/qiling/runner.py`

```python
import asyncio
import json
import uuid
from pathlib import Path
from ..config import settings
from ..logging import get_logger

logger = get_logger(__name__)

class QilingRunner:
    """Executes Qiling analysis scripts inside the Qiling Docker container."""

    def __init__(self):
        self.container = settings.QILING_CONTAINER_NAME
        self.timeout = settings.QILING_TIMEOUT
        self.scripts_dir = "/opt/qiling/scripts"

    async def run_script(self, script_name: str, binary_path: str, **kwargs) -> dict:
        """Run a Qiling analysis script in the container."""
        task_id = str(uuid.uuid4())[:8]
        input_path = f"/data/shared/qiling_input_{task_id}.json"
        output_path = f"/data/shared/qiling_output_{task_id}.json"

        # Write input
        input_data = {"binary_path": binary_path, "timeout": self.timeout, **kwargs}
        write_cmd = f"echo '{json.dumps(input_data)}' > {input_path}"
        await self._docker_exec(write_cmd)

        # Execute script
        script_path = f"{self.scripts_dir}/{script_name}"
        run_cmd = f"python3 {script_path} {input_path} {output_path}"
        await self._docker_exec(run_cmd, timeout=self.timeout + 30)

        # Read output
        result = await self._read_json(output_path)

        # Cleanup
        await self._docker_exec(f"rm -f {input_path} {output_path}")

        return result

    async def _docker_exec(self, cmd: str, timeout: int = 30) -> str:
        proc = await asyncio.create_subprocess_exec(
            "docker", "exec", self.container, "bash", "-c", cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        if proc.returncode != 0:
            raise RuntimeError(f"Qiling exec failed: {stderr.decode()}")
        return stdout.decode()

    async def _read_json(self, path: str) -> dict:
        raw = await self._docker_exec(f"cat {path}")
        return json.loads(raw)

    async def health_check(self) -> bool:
        try:
            result = await self._docker_exec("python3 -c 'import qiling; print(\"ok\")'")
            return "ok" in result
        except Exception:
            return False
```

---

### Phase 2: Analysis Scripts

**Goal**: Python scripts that run inside the Qiling container and produce structured JSON output.

All scripts live in `backend/qiling_scripts/` and follow the same I/O pattern as Ghidra scripts: read `input.json`, write `output.json`.

#### 2.1 `emulate_binary.py` — Core Emulation

Loads the binary, runs with timeout, captures basic execution info.

```python
# Inputs: binary_path, timeout, rootfs_path
# Outputs: {
#   "success": bool,
#   "arch": str,
#   "os": str,
#   "entry_point": str,
#   "instructions_executed": int,
#   "duration_ms": float,
#   "exit_reason": "normal"|"timeout"|"crash"|"error",
#   "exit_code": int,
#   "error": str (if any)
# }
```

Key logic:
- Auto-detect arch + OS from binary headers
- Select appropriate rootfs based on detected OS
- Set `ql.run(timeout=N * 1000)` (Qiling timeout is in ms)
- Count instructions via `ql.hook_code`
- Catch crashes and exceptions gracefully

#### 2.2 `trace_syscalls.py` — Syscall Tracing

Hooks all system calls to capture OS interactions.

```python
# Outputs: {
#   "syscalls": [
#     {
#       "name": "open",
#       "args": ["/etc/passwd", 0, 0],
#       "retval": 3,
#       "address": "0x08048a2c",
#       "category": "file_io"
#     }
#   ],
#   "summary": {
#     "total_calls": int,
#     "categories": {"file_io": N, "network": N, "process": N, "memory": N},
#     "unique_syscalls": ["open", "read", "write", "connect", ...],
#     "suspicious_calls": [...]
#   }
# }
```

Syscall categories:
- **file_io**: `open`, `read`, `write`, `close`, `unlink`, `stat`, `chmod`
- **network**: `socket`, `connect`, `bind`, `listen`, `send`, `recv`, `sendto`, `recvfrom`
- **process**: `fork`, `execve`, `clone`, `kill`, `ptrace`, `wait4`
- **memory**: `mmap`, `mprotect`, `brk`, `munmap`
- **system**: `ioctl`, `sysinfo`, `uname`, `getuid`, `getpid`

Suspicious indicators:
- `execve` with shell paths (`/bin/sh`, `/bin/bash`)
- `connect` to external IPs
- `ptrace(PTRACE_TRACEME)` — anti-debugging
- `unlink` on self — self-deleting malware
- `mprotect` with `PROT_EXEC` on heap/stack — shellcode injection

#### 2.3 `trace_api_calls.py` — OS API Tracing (Windows PE)

Hooks Windows API calls for PE32/PE64 binaries.

```python
# Outputs: {
#   "api_calls": [
#     {
#       "name": "CreateFileW",
#       "module": "kernel32.dll",
#       "args": {"lpFileName": "C:\\Windows\\Temp\\payload.exe", ...},
#       "retval": "0x00000024",
#       "address": "0x004012a0"
#     }
#   ],
#   "summary": {
#     "total_calls": int,
#     "modules_used": ["kernel32.dll", "ws2_32.dll", ...],
#     "suspicious_apis": [{"name": str, "reason": str}]
#   }
# }
```

High-value API hooks:
- **File**: `CreateFileW`, `WriteFile`, `DeleteFileW`, `CopyFileW`
- **Registry**: `RegOpenKeyExW`, `RegSetValueExW`, `RegDeleteKeyW`
- **Network**: `connect`, `send`, `recv`, `InternetOpenW`, `HttpSendRequestW`
- **Process**: `CreateProcessW`, `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`
- **Crypto**: `CryptEncrypt`, `CryptDecrypt`, `CryptHashData`
- **Evasion**: `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `GetTickCount`, `QueryPerformanceCounter`

#### 2.4 `memory_analysis.py` — Memory Behavior

Detects self-modifying code, unpacking, and code injection.

```python
# Outputs: {
#   "memory_events": [
#     {
#       "type": "write_to_exec",
#       "source_address": "0x08048b00",
#       "target_address": "0x0804c000",
#       "size": 4096,
#       "description": "Code written to executable memory region"
#     }
#   ],
#   "memory_map": [
#     {"start": "0x08048000", "end": "0x0804a000", "perms": "r-x", "name": ".text"}
#   ],
#   "indicators": {
#     "self_modifying_code": bool,
#     "unpacking_detected": bool,
#     "shellcode_injection": bool,
#     "rwx_segments": int
#   }
# }
```

Detection logic:
- Hook `ql.hook_mem_write` — detect writes to executable regions (self-modifying code)
- Hook `mprotect`/`VirtualProtect` — detect permission changes (W+X = unpacking, code injection)
- Track memory allocations with RWX permissions
- Snapshot memory regions before and after execution for diff analysis

#### 2.5 `network_analysis.py` — Network Behavior

Captures all network-related activity.

```python
# Outputs: {
#   "connections": [
#     {"type": "tcp_connect", "address": "192.168.1.100", "port": 443, "timestamp_ms": 120.5}
#   ],
#   "dns_queries": [
#     {"domain": "evil-c2.example.com", "type": "A"}
#   ],
#   "data_sent": [
#     {"destination": "192.168.1.100:443", "size": 256, "preview_hex": "504f5354..."}
#   ],
#   "indicators": {
#     "c2_candidates": ["192.168.1.100:443"],
#     "dns_domains": ["evil-c2.example.com"],
#     "protocols_used": ["tcp", "udp", "http"]
#   }
# }
```

#### 2.6 `detect_evasion.py` — Anti-Analysis Detection

Identifies techniques the binary uses to evade analysis.

```python
# Outputs: {
#   "techniques": [
#     {
#       "technique": "Debugger Detection",
#       "method": "IsDebuggerPresent",
#       "address": "0x00401230",
#       "mitre_id": "T1622",
#       "description": "Binary checks if a debugger is attached"
#     }
#   ],
#   "summary": {
#     "total_techniques": int,
#     "risk_level": "low"|"medium"|"high",
#     "mitre_tactics": ["Defense Evasion", "Discovery"]
#   }
# }
```

Detections:
- **Debugger checks**: `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `ptrace(PTRACE_TRACEME)`, `NtQueryInformationProcess`
- **Timing checks**: `GetTickCount`, `QueryPerformanceCounter`, `rdtsc` instruction — detects analysis environments via timing discrepancy
- **Environment checks**: `GetComputerNameW`, `GetUserNameW`, `GetSystemInfo` — compares against known sandbox names
- **VM detection**: CPUID checks, registry queries for VMware/VirtualBox artifacts, MAC address prefix checks
- **Anti-disassembly**: Overlapping instructions, opaque predicates (detected via instruction trace anomalies)

---

### Phase 3: LangGraph Integration (Tools + Pipeline + State)

**Goal**: Wire Qiling into the existing analysis pipeline.

#### 3.1 Extend `AgentState` in `state.py`

Add two new fields following the `r2_*` pattern:

```python
# In AgentState TypedDict
qiling_analysis_results: Dict[str, Any]    # Dynamic analysis results
qiling_execution_cache: Dict[str, Any]     # Raw execution data cache
```

Default values:

```python
DEFAULT_STATE = {
    ...
    "qiling_analysis_results": {},
    "qiling_execution_cache": {},
}
```

#### 3.2 Create `qiling_tools.py`

LangChain `@tool` wrappers around `QilingRunner`:

```python
@tool
async def qiling_emulate_binary(session_id: str, program_hash: str, binary_path: str) -> str:
    """Emulate binary execution using Qiling framework. Captures execution trace, instruction count, and exit behavior."""
    runner = get_runner()
    result = await runner.run_script("emulate_binary.py", binary_path)
    return json.dumps(result)

@tool
async def qiling_trace_syscalls(session_id: str, program_hash: str, binary_path: str) -> str:
    """Trace all system calls made during binary emulation. Captures file I/O, network, process, and memory operations."""
    ...

@tool
async def qiling_trace_api_calls(session_id: str, program_hash: str, binary_path: str) -> str:
    """Trace Windows API calls during PE binary emulation. Captures DLL interactions and suspicious API usage."""
    ...

@tool
async def qiling_memory_analysis(session_id: str, program_hash: str, binary_path: str) -> str:
    """Analyze memory behavior during emulation. Detects self-modifying code, unpacking, and code injection."""
    ...

@tool
async def qiling_network_analysis(session_id: str, program_hash: str, binary_path: str) -> str:
    """Capture network activity during emulation. Extracts C2 addresses, DNS queries, and data exfiltration attempts."""
    ...

@tool
async def qiling_detect_evasion(session_id: str, program_hash: str, binary_path: str) -> str:
    """Detect anti-analysis and evasion techniques used by the binary."""
    ...
```

#### 3.3 Create `qiling_graph.py`

Async pipeline following `r2_graph.py` pattern:

```python
async def run_qiling_pipeline(state: AgentState) -> AgentState:
    """Execute the Qiling dynamic analysis pipeline."""
    binary_path = state["binary_path"]
    results = {}

    # Step 1: Emulate binary (must succeed for other steps)
    emulation = await qiling_emulate_binary(...)
    results["execution_trace"] = emulation

    if emulation.get("success"):
        # Step 2-5: Run remaining analyses in parallel
        syscalls, memory, network, evasion = await asyncio.gather(
            qiling_trace_syscalls(...),
            qiling_memory_analysis(...),
            qiling_network_analysis(...),
            qiling_detect_evasion(...),
            return_exceptions=True,
        )
        results["syscalls"] = syscalls
        results["memory_events"] = memory
        results["network_activity"] = network
        results["evasion_techniques"] = evasion

        # Step 6: Windows API tracing (only for PE binaries)
        if emulation.get("os") == "Windows":
            api_calls = await qiling_trace_api_calls(...)
            results["api_calls"] = api_calls

    state["qiling_analysis_results"] = results
    return state
```

#### 3.4 Integrate into `discovery` Node in `graph.py`

```python
async def discovery(state: AgentState) -> AgentState:
    ...
    tasks = [_ghidra_discovery(state)]

    if settings.enable_r2 and r2_available:
        tasks.append(_safe_r2_pipeline(state))

    if settings.enable_qiling and qiling_available:     # NEW
        tasks.append(_safe_qiling_pipeline(state))      # NEW

    await asyncio.gather(*tasks)
    ...
```

#### 3.5 Update `initialize_ghidra` Node

```python
async def initialize_ghidra(state: AgentState) -> AgentState:
    ...
    # Existing R2 check
    if settings.enable_r2:
        r2_ok = await check_r2_container()
        ...

    # NEW: Qiling check
    if settings.enable_qiling:
        qiling_ok = await check_qiling_container()
        state["reasoning_trace"].append(
            "qiling_available" if qiling_ok else "qiling_unavailable"
        )
    ...
```

---

### Phase 4: Report + Prompt Integration

**Goal**: Make the LLM aware of Qiling data and render it in reports.

#### 4.1 Update System Prompt in `prompts.py`

Add to role description:
```
You are an expert malware analyst using Ghidra (static disassembly), Radare2 (static analysis),
and Qiling (dynamic emulation) to analyze binary executables.
```

Add new section:
```
## Dynamic Analysis Data (Qiling)

When Qiling dynamic analysis data is available, you have access to:
- **Execution trace**: How the binary actually runs — instruction count, exit behavior
- **Syscall log**: Every OS interaction — file reads/writes, network connections, process creation
- **API call trace**: Windows API calls with full parameters (PE binaries only)
- **Memory events**: Self-modifying code, unpacking behavior, code injection
- **Network activity**: C2 connections, DNS queries, data exfiltration
- **Evasion techniques**: Anti-debugging, VM detection, timing checks

Cross-reference dynamic findings with static analysis:
- If Ghidra shows a suspicious function, check if Qiling's execution trace reached it
- If R2 finds encrypted strings, check if Qiling captured the decrypted versions at runtime
- If static IOCs (IPs, domains) are found, verify if Qiling observed actual connection attempts
- If the binary has anti-analysis code, note whether Qiling detected the evasion technique
```

#### 4.2 Update `synthesize` Node Context Builder

Add Qiling results to the context string passed to the LLM:

```python
# In synthesize node
if state.get("qiling_analysis_results"):
    qr = state["qiling_analysis_results"]
    context += "\n\n## QILING DYNAMIC ANALYSIS RESULTS\n"

    if "execution_trace" in qr:
        context += f"\n### Execution Trace\n{json.dumps(qr['execution_trace'], indent=2)}"
    if "syscalls" in qr:
        context += f"\n### Syscall Trace ({len(qr['syscalls'].get('syscalls',[]))} calls)\n"
        context += format_syscall_summary(qr['syscalls'])
    if "network_activity" in qr:
        context += f"\n### Network Activity\n{json.dumps(qr['network_activity'], indent=2)}"
    if "memory_events" in qr:
        context += f"\n### Memory Behavior\n{json.dumps(qr['memory_events'], indent=2)}"
    if "evasion_techniques" in qr:
        context += f"\n### Evasion Techniques\n{json.dumps(qr['evasion_techniques'], indent=2)}"
```

#### 4.3 Update `reporting.py`

Add "Dynamic Analysis" section to HTML/PDF reports:

- **Syscall timeline table**: sortable by timestamp, filterable by category
- **API call sequence**: collapsible list with full parameters
- **Network activity cards**: connection attempts with IP/port/protocol
- **Memory event visualization**: address ranges with permission changes highlighted
- **Evasion technique warnings**: cards with MITRE ATT&CK IDs and descriptions
- **Execution summary**: instructions executed, duration, exit reason

#### 4.4 Update Fallback Summary

In `_build_fallback_summary()`, iterate `qiling_analysis_results`:

```python
if state.get("qiling_analysis_results"):
    summary += "\n## Dynamic Analysis (Qiling)\n"
    qr = state["qiling_analysis_results"]
    # Format execution trace, syscalls, network, etc.
```

---

### Phase 5: API + Frontend

**Goal**: Expose Qiling results through the API and display in the UI.

#### 5.1 New API Endpoint

```python
@app.get("/api/analysis/{program_hash}/results/qiling")
async def qiling_results(program_hash: str):
    """Get raw Qiling dynamic analysis results."""
    session = store.find_by_hash(program_hash)
    return session.state.get("qiling_analysis_results", {})
```

#### 5.2 Update Analyzers Endpoint

In `/api/analysis/{hash}/analyzers`, add Qiling as a third analyzer:

```python
analyzers.append({
    "id": "qiling",
    "name": "Qiling Dynamic Analysis",
    "source": "qiling",
    "sourceUrl": "https://qiling.io",
    "verdict": determine_verdict(qiling_results),
    "details": {
        "executiveSummary": qiling_summary,
        "behavioralAnalysis": format_behavioral(qiling_results),
        "iocs": format_dynamic_iocs(qiling_results),
        ...
    }
})
```

#### 5.3 Frontend API Client

In `app/src/lib/api.ts`:

```typescript
export async function getQilingResults(hash: string): Promise<QilingResults> {
  const res = await fetch(`${API_BASE}/api/analysis/${hash}/results/qiling`);
  return res.json();
}
```

#### 5.4 Frontend Components

- **Qiling analyzer card** in `AnalyzerList` — shows execution summary, verdict
- **Syscall trace view** — filterable table with category icons
- **Network activity panel** — connection map with C2 highlights
- **Memory events timeline** — address-range visualization
- **Execution trace overlay** on CallGraphView — highlight actually-executed paths (optional, high-value)

#### 5.5 Update TypeScript Types

```typescript
interface QilingResults {
  execution_trace?: ExecutionTrace;
  syscalls?: SyscallTrace;
  api_calls?: ApiCallTrace;
  network_activity?: NetworkActivity;
  memory_events?: MemoryEvents;
  evasion_techniques?: EvasionTechnique[];
  errors?: string[];
}

interface ExecutionTrace {
  success: boolean;
  arch: string;
  os: string;
  entry_point: string;
  instructions_executed: number;
  duration_ms: number;
  exit_reason: 'normal' | 'timeout' | 'crash' | 'error';
}

interface SyscallEntry {
  name: string;
  args: any[];
  retval: number;
  address: string;
  category: 'file_io' | 'network' | 'process' | 'memory' | 'system';
}

interface NetworkConnection {
  type: 'tcp_connect' | 'udp' | 'dns' | 'http';
  address: string;
  port: number;
  data_preview?: string;
}

interface EvasionTechnique {
  technique: string;
  method: string;
  address: string;
  mitre_id: string;
  description: string;
}
```

---

### Phase 6: Testing + Hardening

#### 6.1 Timeout + Resource Limits

- Emulation timeout: 60 seconds (configurable via `QILING_TIMEOUT`)
- Docker container memory limit: 2GB
- Docker container CPU limit: 2 cores
- Instruction count limit: 100M instructions (prevent infinite loops)

```python
# In emulate_binary.py
instruction_count = 0
MAX_INSTRUCTIONS = 100_000_000

def count_instructions(ql, address, size):
    nonlocal instruction_count
    instruction_count += 1
    if instruction_count >= MAX_INSTRUCTIONS:
        ql.emu_stop()

ql.hook_code(count_instructions)
ql.run(timeout=timeout_ms)
```

#### 6.2 Safety Sandbox

Docker security configuration:

```yaml
qiling:
  security_opt:
    - no-new-privileges:true
  read_only: false  # Qiling needs to write to rootfs for lib loading
  cap_drop:
    - ALL
  cap_add:
    - SYS_PTRACE  # required for Qiling's process emulation
  networks:
    - internal  # no external network access
```

Qiling-level safety:
- `ql.os.stdin` replaced with empty pipe (no real stdin)
- Filesystem mapper restricts access to rootfs only
- Network syscalls hooked to capture but not execute real connections

#### 6.3 Test with Sample Binaries

Test against existing samples in `sample-binary/`:

| Binary | Type | Expected Qiling Behavior |
|--------|------|--------------------------|
| `chargen` | ELF | Basic execution trace, network syscalls |
| `test_binary` | ELF | Simple execution, clean exit |
| `kworofd` | ELF | Malicious behavior: suspicious syscalls, network activity |
| `rop_gently` | ELF | ROP chain execution, memory manipulation |
| `dbus-echo` | ELF | D-Bus communication syscalls |

#### 6.4 Unit + Integration Tests

```
tests/
  test_qiling_runner.py      — QilingRunner health check, script execution
  test_qiling_tools.py       — @tool wrapper input/output validation
  test_qiling_graph.py       — Pipeline flow, error handling, timeout
  test_qiling_integration.py — End-to-end: upload binary → Qiling results in state
```

---

## Data Flow

### Complete Analysis Flow with Qiling

```
User uploads binary
    │
    ▼
POST /analyze/upload
    │
    ▼
Binary copied to /data/shared/{hash}
    │
    ▼
parse_intent → initialize_ghidra (checks Ghidra + R2 + Qiling containers)
    │
    ▼
┌─────────────────────── discovery node ──────────────────────────┐
│                                                                 │
│  asyncio.gather(                                                │
│                                                                 │
│    _ghidra_discovery(state)          _safe_r2_pipeline(state)   │
│    ┌─────────────────────┐           ┌──────────────────────┐   │
│    │ analyze_binary      │           │ r2_analyze_binary     │   │
│    │ list_functions      │           │ r2_list_functions     │   │
│    │ build_call_graph    │           │ r2_build_call_graph   │   │
│    │ find_strings        │           │ r2_find_strings       │   │
│    │ decompile (top N)   │           │ r2_decompile (top N)  │   │
│    │ IOC extraction      │           │ r2_syscall_analysis   │   │
│    └─────────────────────┘           └──────────────────────┘   │
│                                                                 │
│    _safe_qiling_pipeline(state)     ← NEW                       │
│    ┌─────────────────────────────────────────────┐              │
│    │ qiling_emulate_binary                       │              │
│    │   → if success:                             │              │
│    │     qiling_trace_syscalls                   │              │
│    │     qiling_memory_analysis                  │              │
│    │     qiling_network_analysis                 │              │
│    │     qiling_detect_evasion                   │              │
│    │     qiling_trace_api_calls (PE only)        │              │
│    └─────────────────────────────────────────────┘              │
│                                                                 │
│  )  ← all three run concurrently                                │
└─────────────────────────────────────────────────────────────────┘
    │
    ▼
synthesize node
    │  Reads:
    │    state["analysis_results"]           (Ghidra static)
    │    state["decompilation_cache"]        (Ghidra decompiled code)
    │    state["r2_analysis_results"]        (R2 static)
    │    state["r2_decompilation_cache"]     (R2 decompiled code)
    │    state["qiling_analysis_results"]    (Qiling dynamic)  ← NEW
    │
    │  Builds comprehensive context → sends to LLM
    │  → LLM generates report covering static + dynamic findings
    ▼
Report output (HTML / PDF / Text)
    │  Includes new sections:
    │    - Dynamic Analysis summary
    │    - Syscall trace table
    │    - Network activity cards
    │    - Memory behavior indicators
    │    - Evasion technique warnings
    ▼
Frontend displays all three analyzers
```

### Data Flow for a Single Qiling Analysis

```
Agent container                          Qiling container
─────────────────                        ────────────────
QilingRunner.run_script(
  "trace_syscalls.py",
  binary_path
)
    │
    ├─ Write input.json ──────────────→  /data/shared/qiling_input_abc123.json
    │                                      { "binary_path": "/data/shared/deadbeef",
    │                                        "timeout": 60 }
    │
    ├─ docker exec qiling_emulator ───→  python3 /opt/qiling/scripts/trace_syscalls.py
    │   bash -c "python3 ..."                │
    │                                        ├─ Read input.json
    │                                        ├─ ql = Qiling([binary], rootfs)
    │                                        ├─ Hook all syscalls
    │                                        ├─ ql.run(timeout=60000)
    │                                        ├─ Collect traced syscalls
    │                                        └─ Write output.json
    │
    ├─ Read output.json ←────────────── /data/shared/qiling_output_abc123.json
    │                                      { "syscalls": [...], "summary": {...} }
    │
    └─ Return parsed results
```

---

## Proposed Data Schema

### `qiling_analysis_results` (stored in `AgentState`)

```python
qiling_analysis_results = {
    # Core execution info
    "execution_trace": {
        "success": True,
        "arch": "x86_64",
        "os": "Linux",
        "entry_point": "0x00401000",
        "instructions_executed": 1542837,
        "duration_ms": 3240.5,
        "exit_reason": "normal",     # "normal" | "timeout" | "crash" | "error"
        "exit_code": 0,
        "error": None
    },

    # System call trace
    "syscalls": {
        "calls": [
            {
                "name": "open",
                "args": ["/etc/passwd", 0, 0],
                "retval": 3,
                "address": "0x08048a2c",
                "category": "file_io",            # file_io | network | process | memory | system
                "timestamp_ms": 12.5
            },
            {
                "name": "connect",
                "args": [4, {"family": "AF_INET", "addr": "192.168.1.100", "port": 4444}, 16],
                "retval": 0,
                "address": "0x08049100",
                "category": "network",
                "timestamp_ms": 45.2
            }
        ],
        "summary": {
            "total_calls": 247,
            "categories": {
                "file_io": 89,
                "network": 12,
                "process": 3,
                "memory": 134,
                "system": 9
            },
            "unique_syscalls": ["open", "read", "write", "close", "connect", "send", "mmap", "mprotect"],
            "suspicious_calls": [
                {
                    "name": "connect",
                    "reason": "Outbound connection to external IP",
                    "address": "0x08049100",
                    "risk": "high"
                },
                {
                    "name": "execve",
                    "reason": "Shell execution: /bin/sh",
                    "address": "0x08049230",
                    "risk": "critical"
                }
            ]
        }
    },

    # Windows API calls (PE only, empty for ELF)
    "api_calls": {
        "calls": [
            {
                "name": "CreateFileW",
                "module": "kernel32.dll",
                "args": {"lpFileName": "C:\\Windows\\Temp\\payload.exe", "dwDesiredAccess": "GENERIC_WRITE"},
                "retval": "0x00000024",
                "address": "0x004012a0"
            }
        ],
        "summary": {
            "total_calls": 156,
            "modules_used": ["kernel32.dll", "ntdll.dll", "ws2_32.dll", "advapi32.dll"],
            "suspicious_apis": [
                {"name": "VirtualAllocEx", "reason": "Remote memory allocation — possible code injection", "risk": "critical"},
                {"name": "WriteProcessMemory", "reason": "Writing to another process's memory", "risk": "critical"}
            ]
        }
    },

    # Network activity
    "network_activity": {
        "connections": [
            {"type": "tcp_connect", "address": "192.168.1.100", "port": 4444, "timestamp_ms": 45.2},
            {"type": "tcp_connect", "address": "10.0.0.1", "port": 80, "timestamp_ms": 67.8}
        ],
        "dns_queries": [
            {"domain": "evil-c2.example.com", "type": "A", "timestamp_ms": 40.1}
        ],
        "data_sent": [
            {"destination": "192.168.1.100:4444", "size": 256, "preview_hex": "504f535420..."}
        ],
        "indicators": {
            "c2_candidates": ["192.168.1.100:4444"],
            "dns_domains": ["evil-c2.example.com"],
            "protocols_used": ["tcp"]
        }
    },

    # File operations
    "file_operations": [
        {"type": "open", "path": "/etc/passwd", "mode": "read", "timestamp_ms": 12.5},
        {"type": "write", "path": "/tmp/.hidden_payload", "size": 8192, "timestamp_ms": 30.2},
        {"type": "delete", "path": "/tmp/.hidden_payload", "timestamp_ms": 95.0}
    ],

    # Memory behavior
    "memory_events": {
        "events": [
            {
                "type": "write_to_exec",
                "source_address": "0x08048b00",
                "target_address": "0x0804c000",
                "size": 4096,
                "description": "Wrote 4096 bytes to executable .text section"
            },
            {
                "type": "permission_change",
                "address": "0x0804d000",
                "size": 8192,
                "old_perms": "rw-",
                "new_perms": "rwx",
                "description": "Heap region made executable via mprotect"
            }
        ],
        "indicators": {
            "self_modifying_code": true,
            "unpacking_detected": true,
            "shellcode_injection": false,
            "rwx_segments": 2
        }
    },

    # Anti-analysis techniques
    "evasion_techniques": {
        "techniques": [
            {
                "technique": "Debugger Detection",
                "method": "ptrace(PTRACE_TRACEME)",
                "address": "0x08048500",
                "mitre_id": "T1622",
                "mitre_tactic": "Defense Evasion",
                "description": "Uses ptrace to detect if a debugger is attached. If traced, the binary exits."
            },
            {
                "technique": "Timing Check",
                "method": "clock_gettime comparison",
                "address": "0x08048600",
                "mitre_id": "T1497.003",
                "mitre_tactic": "Defense Evasion",
                "description": "Measures execution time between two points to detect emulation/debugging delay."
            }
        ],
        "summary": {
            "total_techniques": 2,
            "risk_level": "medium",
            "mitre_tactics": ["Defense Evasion"]
        }
    },

    # Errors encountered during analysis
    "errors": []
}
```

---

## Effort Estimate

| Phase | Description | Effort | Priority | Dependencies |
|-------|-------------|--------|----------|-------------|
| **Phase 1** | Infrastructure: Docker + Config + Runner | 2–3 days | P0 (must-have) | None |
| **Phase 2** | Analysis Scripts: 6 scripts | 3–4 days | P0 (must-have) | Phase 1 |
| **Phase 3** | LangGraph Integration: State + Tools + Pipeline + Graph | 2–3 days | P0 (must-have) | Phase 1, 2 |
| **Phase 4** | Report + Prompt: LLM context + report sections | 1–2 days | P0 (must-have) | Phase 3 |
| **Phase 5** | API + Frontend: Endpoint + UI components | 2–3 days | P1 (should-have) | Phase 3 |
| **Phase 6** | Testing + Hardening: Tests + security + resource limits | 2–3 days | P0 (must-have) | Phase 1–4 |
| | **Total** | **12–18 days** | | |

### Recommended Implementation Order

```
Week 1:  Phase 1 (Docker image + runner) → Phase 2 (emulate_binary.py + trace_syscalls.py only)
         → Validate end-to-end: upload binary → Qiling runs → results in logs

Week 2:  Phase 2 (remaining 4 scripts) → Phase 3 (state + tools + pipeline + graph integration)
         → Validate: discovery node runs all 3 analyzers in parallel

Week 3:  Phase 4 (prompts + synthesize + reporting) → Phase 5 (API endpoint + frontend)
         → Validate: full report includes dynamic analysis section

Week 4:  Phase 6 (tests + hardening + resource limits) → Polish + documentation
```

### Minimal Viable Integration (MVP)

To prove the concept quickly (3–5 days), implement only:

1. Dockerfile + docker-compose service (Phase 1.1, 1.2)
2. `emulate_binary.py` + `trace_syscalls.py` (Phase 2.1, 2.2)
3. `QilingRunner` (Phase 1.4)
4. State field + one `@tool` wrapper (Phase 3.1, 3.2 partial)
5. Add to `asyncio.gather` in discovery (Phase 3.4)
6. Print results in synthesize context (Phase 4.2 partial)

This gives a working end-to-end flow where Qiling emulates the binary, captures syscalls, and the LLM can reference them in its analysis report.

---

## References

- [Qiling Framework Documentation](https://docs.qiling.io/en/latest/)
- [Qiling GitHub Repository](https://github.com/qilingframework/qiling) — v1.4.7, 5.8k stars, 130 contributors
- [Qiling Installation Guide](https://docs.qiling.io/en/latest/install/)
- [Qiling Hook API](https://docs.qiling.io/en/latest/hook/)
- [Qiling Hijack (Syscall/API Interception)](https://docs.qiling.io/en/latest/hijack/)
- [Qiling Docker Image](https://hub.docker.com/r/qilingframework/qiling)
- [Unicorn Engine](https://www.unicorn-engine.org/) — underlying CPU emulation
- [MITRE ATT&CK — Defense Evasion](https://attack.mitre.org/tactics/TA0005/)
