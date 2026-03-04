"""Trace Windows API calls and dynamic imports during Qiling PE emulation."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

from common import choose_rootfs, detect_binary, fail_payload, load_input, write_output


API_HOOKS = {
    "CreateFileW": "kernel32.dll",
    "WriteFile": "kernel32.dll",
    "DeleteFileW": "kernel32.dll",
    "RegSetValueExW": "advapi32.dll",
    "CreateProcessW": "kernel32.dll",
    "VirtualAllocEx": "kernel32.dll",
    "WriteProcessMemory": "kernel32.dll",
    "CreateRemoteThread": "kernel32.dll",
    "connect": "ws2_32.dll",
    "send": "ws2_32.dll",
    "recv": "ws2_32.dll",
    "IsDebuggerPresent": "kernel32.dll",
}

SUSPICIOUS_DYNAMIC_APIS = {
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "GetAsyncKeyState",
    "SetWindowsHookExA",
    "SetWindowsHookExW",
    "IsDebuggerPresent",
}

MAX_API_CALLS = 250
MAX_DYNAMIC_IMPORTS = 400
MAX_LOADED_LIBRARIES = 128


def _decode_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore").strip("\x00 ")
    if isinstance(value, bytearray):
        return bytes(value).decode("utf-8", errors="ignore").strip("\x00 ")
    return str(value).strip("\x00 ")


def _normalize_proc_name(value: Any) -> str:
    if isinstance(value, int):
        # By Windows convention, integer lpProcName values represent ordinals.
        if 0 <= value <= 0xFFFF:
            return f"ordinal_{value}"
        return hex(value)
    return _decode_text(value)


def _parse_pe_dll_context(binary_path: str) -> Tuple[bool, int, int]:
    """Return (is_dll, image_base, entry_va) for PE binaries."""
    p = Path(binary_path)
    if not p.exists():
        return False, 0, 0

    try:
        data = p.read_bytes()
    except Exception:
        return False, 0, 0

    if len(data) < 0x100 or data[:2] != b"MZ":
        return False, 0, 0

    try:
        pe_off = int.from_bytes(data[0x3C:0x40], "little")
        if pe_off <= 0 or pe_off + 0x60 >= len(data):
            return False, 0, 0
        if data[pe_off: pe_off + 4] != b"PE\x00\x00":
            return False, 0, 0

        file_hdr_off = pe_off + 4
        opt_off = file_hdr_off + 20

        characteristics = int.from_bytes(data[file_hdr_off + 18: file_hdr_off + 20], "little")
        is_dll = bool(characteristics & 0x2000)

        magic = int.from_bytes(data[opt_off: opt_off + 2], "little")
        entry_rva = int.from_bytes(data[opt_off + 16: opt_off + 20], "little")

        image_base = 0
        if magic == 0x20B and opt_off + 32 <= len(data):  # PE32+
            image_base = int.from_bytes(data[opt_off + 24: opt_off + 32], "little")
        elif magic == 0x10B and opt_off + 32 <= len(data):  # PE32
            image_base = int.from_bytes(data[opt_off + 28: opt_off + 32], "little")

        entry_va = image_base + entry_rva if image_base and entry_rva else 0
        return is_dll, image_base, entry_va
    except Exception:
        return False, 0, 0


def _configure_dll_entry_context(ql, binary_path: str, binary_meta: Dict[str, Any], result: Dict[str, Any]) -> int:  # noqa: ANN001
    """Best-effort DllMain argument setup for DLL samples."""
    is_dll, image_base, entry_va = _parse_pe_dll_context(binary_path)
    if not is_dll or entry_va == 0:
        return 0

    arch = str(binary_meta.get("arch", "")).lower()
    result["dll_context"] = {
        "is_dll": True,
        "entry_va": hex(entry_va),
        "image_base": hex(image_base),
        "reason": "dll_entry_override",
    }

    try:
        regs = getattr(ql, "reg", None)
        if regs is None:
            regs = getattr(getattr(ql, "arch", None), "regs", None)

        if arch in {"x86_64", "amd64", "x8664"}:
            # BOOL DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
            # x64 fastcall: RCX, RDX, R8, R9
            if regs is None:
                raise AttributeError("no register interface")
            setattr(regs, "rcx", image_base)
            setattr(regs, "rdx", 0x1)  # DLL_PROCESS_ATTACH
            setattr(regs, "r8", 0x0)
        elif arch in {"x86", "i386", "i686"}:
            # stdcall parameters on stack (right-to-left).
            ql.stack_push(0x0)  # lpReserved
            ql.stack_push(0x1)  # fdwReason = DLL_PROCESS_ATTACH
            ql.stack_push(image_base)  # hinstDLL
    except Exception as exc:
        result["dll_context"]["error"] = f"failed_to_set_dll_args:{exc}"

    return entry_va


def _run(binary_path: str, timeout_sec: int, rootfs_base: str) -> Dict[str, Any]:
    binary_meta = detect_binary(binary_path)
    if binary_meta.get("binary_format") != "pe":
        return {
            "ok": True,
            "success": True,
            "api_calls": [],
            "summary": {"total_calls": 0, "modules_used": [], "suspicious_apis": []},
            "note": "Non-PE binary; API tracing skipped.",
        }

    rootfs, rootfs_name = choose_rootfs(rootfs_base, "windows", binary_meta.get("arch", ""))
    result: Dict[str, Any] = {
        "ok": False,
        "success": False,
        "rootfs": rootfs_name,
        "api_calls": [],
        "dynamic_imports": [],
        "loaded_libraries": [],
        "summary": {"total_calls": 0, "modules_used": [], "suspicious_apis": []},
        "error": None,
    }

    if not Path(binary_path).exists():
        result["error"] = f"Binary not found: {binary_path}"
        return result
    if not rootfs or not Path(rootfs).exists():
        result["error"] = f"Windows rootfs not found for arch={binary_meta.get('arch')}"
        return result

    try:
        from qiling import Qiling
        from qiling.const import QL_VERBOSE
    except Exception as exc:
        result["error"] = f"Qiling import failed: {exc}"
        return result

    calls: List[Dict[str, Any]] = []
    dynamic_imports: List[Dict[str, Any]] = []
    loaded_libraries: List[Dict[str, Any]] = []
    seen_dynamic: set[str] = set()
    seen_libraries: set[str] = set()

    try:
        from qiling.const import QL_INTERCEPT

        ql = Qiling([binary_path], rootfs, verbose=QL_VERBOSE.OFF)

        def _record_call(name: str, module: str, address: Any, params: Any, extra: Dict[str, Any] | None = None) -> None:
            if len(calls) >= MAX_API_CALLS:
                return
            call: Dict[str, Any] = {
                "name": name,
                "module": module,
                "args": params if isinstance(params, dict) else {},
                "retval": None,
                "address": hex(address) if isinstance(address, int) else str(address),
            }
            if extra:
                call.update(extra)
            calls.append(call)

        def _record_dynamic_import(name: str, source: str, address: Any) -> None:
            clean_name = name.strip()
            if not clean_name:
                return
            key = f"{source}:{clean_name}".lower()
            if key in seen_dynamic or len(dynamic_imports) >= MAX_DYNAMIC_IMPORTS:
                return
            seen_dynamic.add(key)
            dynamic_imports.append(
                {
                    "name": clean_name,
                    "source": source,
                    "address": hex(address) if isinstance(address, int) else str(address),
                }
            )

        def _record_loaded_library(name: str, source: str, address: Any) -> None:
            clean_name = name.strip()
            if not clean_name:
                return
            key = clean_name.lower()
            if key in seen_libraries or len(loaded_libraries) >= MAX_LOADED_LIBRARIES:
                return
            seen_libraries.add(key)
            loaded_libraries.append(
                {
                    "name": clean_name,
                    "source": source,
                    "address": hex(address) if isinstance(address, int) else str(address),
                }
            )

        def _hook_get_proc_address(ql_obj, address, params):  # noqa: ANN001
            proc_name = ""
            if isinstance(params, dict):
                proc_name = _normalize_proc_name(params.get("lpProcName"))
            _record_dynamic_import(proc_name, "GetProcAddress", address)
            _record_call(
                "GetProcAddress",
                "kernel32.dll",
                address,
                params,
                {"resolved_name": proc_name or None},
            )
            return None

        def _hook_load_library_a(ql_obj, address, params):  # noqa: ANN001
            lib_name = ""
            if isinstance(params, dict):
                lib_name = _decode_text(params.get("lpLibFileName"))
            _record_loaded_library(lib_name, "LoadLibraryA", address)
            _record_call(
                "LoadLibraryA",
                "kernel32.dll",
                address,
                params,
                {"library_name": lib_name or None},
            )
            return None

        def _hook_load_library_w(ql_obj, address, params):  # noqa: ANN001
            lib_name = ""
            if isinstance(params, dict):
                lib_name = _decode_text(params.get("lpLibFileName"))
            _record_loaded_library(lib_name, "LoadLibraryW", address)
            _record_call(
                "LoadLibraryW",
                "kernel32.dll",
                address,
                params,
                {"library_name": lib_name or None},
            )
            return None

        def _set_api_hook(api_name: str, callback, intercept: Any | None = None) -> bool:
            try:
                if intercept is not None and hasattr(ql, "set_api"):
                    ql.set_api(api_name, callback, intercept)
                    return True
            except Exception:
                pass

            try:
                ql.os.set_api(api_name, callback)
                return True
            except Exception:
                return False

        _set_api_hook("GetProcAddress", _hook_get_proc_address, QL_INTERCEPT.EXIT)
        _set_api_hook("LoadLibraryA", _hook_load_library_a, QL_INTERCEPT.EXIT)
        _set_api_hook("LoadLibraryW", _hook_load_library_w, QL_INTERCEPT.EXIT)

        run_begin = _configure_dll_entry_context(ql, binary_path, binary_meta, result)

        for api_name, module_name in API_HOOKS.items():
            def _make_cb(name: str, module: str):
                def _cb(ql_obj, address, params):  # noqa: ANN001
                    _record_call(name, module, address, params)
                    return None

                return _cb

            try:
                ql.os.set_api(api_name, _make_cb(api_name, module_name))
            except Exception:
                continue

        if run_begin:
            ql.run(begin=run_begin, timeout=timeout_sec * 1000)
        else:
            ql.run(timeout=timeout_sec * 1000)

        suspicious = []
        for call in calls:
            if call["name"] in {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"}:
                suspicious.append(
                    {
                        "name": call["name"],
                        "reason": "Potential process injection primitive",
                        "risk": "critical",
                    }
                )
            elif call["name"] == "IsDebuggerPresent":
                suspicious.append(
                    {
                        "name": call["name"],
                        "reason": "Debugger detection behavior",
                        "risk": "high",
                    }
                )

        for item in dynamic_imports:
            name = str(item.get("name", ""))
            if name in SUSPICIOUS_DYNAMIC_APIS:
                suspicious.append(
                    {
                        "name": name,
                        "reason": "API resolved dynamically via GetProcAddress",
                        "risk": "high",
                    }
                )

        dedup_suspicious: List[Dict[str, Any]] = []
        seen_suspicious: set[str] = set()
        for item in suspicious:
            key = f"{item.get('name')}|{item.get('reason')}"
            if key in seen_suspicious:
                continue
            seen_suspicious.add(key)
            dedup_suspicious.append(item)

        result["ok"] = True
        result["success"] = True
        result["api_calls"] = calls
        result["dynamic_imports"] = dynamic_imports
        result["loaded_libraries"] = loaded_libraries
        result["summary"] = {
            "total_calls": len(calls),
            "modules_used": sorted({c.get("module", "") for c in calls if c.get("module")}),
            "suspicious_apis": dedup_suspicious,
            "dynamic_imports_count": len(dynamic_imports),
            "dynamic_imports_sample": [i.get("name", "") for i in dynamic_imports[:30]],
            "libraries_loaded": [i.get("name", "") for i in loaded_libraries[:30]],
        }
        return result
    except Exception as exc:
        result["api_calls"] = calls
        result["dynamic_imports"] = dynamic_imports
        result["loaded_libraries"] = loaded_libraries
        result["summary"] = {
            "total_calls": len(calls),
            "modules_used": sorted({c.get("module", "") for c in calls if c.get("module")}),
            "suspicious_apis": [],
            "dynamic_imports_count": len(dynamic_imports),
            "dynamic_imports_sample": [i.get("name", "") for i in dynamic_imports[:30]],
            "libraries_loaded": [i.get("name", "") for i in loaded_libraries[:30]],
        }
        result["error"] = str(exc)
        return result


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: trace_api_calls.py <input.json> <output.json>", file=sys.stderr)
        return 2

    input_path, output_path = sys.argv[1], sys.argv[2]
    try:
        payload = load_input(input_path)
        binary_path = str(payload.get("binary_path", "")).strip()
        timeout_sec = int(payload.get("timeout", 60))
        rootfs_base = str(payload.get("rootfs_base", "/opt/qiling/rootfs"))

        if not binary_path:
            write_output(output_path, fail_payload("binary_path missing in input", api_calls=[], summary={}))
            return 0

        result = _run(binary_path, timeout_sec, rootfs_base)
        write_output(output_path, result)
        return 0
    except Exception as exc:
        write_output(output_path, fail_payload(f"trace_api_calls.py failed: {exc}", api_calls=[], summary={}))
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
