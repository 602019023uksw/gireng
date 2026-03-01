from copy import deepcopy

from ghidra_agent.ioc_extractor import IOCs, calculate_verdict
from ghidra_agent.state import DEFAULT_STATE


def test_qiling_evasion_and_suspicious_syscalls_raise_score():
    state = deepcopy(DEFAULT_STATE)
    state["summary"] = ""
    state["qiling_analysis_results"] = {
        "syscalls": {
            "ok": True,
            "syscalls": [
                {"name": "execve", "address": "0x401050", "args": ["/bin/sh", 0, 0], "category": "process"},
                {"name": "ptrace", "address": "0x401070", "args": [0, 0, 0], "category": "process"},
            ],
            "summary": {
                "total_calls": 2,
                "categories": {"process": 2},
                "suspicious_calls": [
                    {"name": "execve", "reason": "Shell execution", "risk": "high"},
                    {"name": "ptrace", "reason": "Debugger detection syscall", "risk": "high"},
                ],
            },
        },
        "evasion_techniques": {
            "ok": True,
            "techniques": [
                {"method": "ptrace", "mitre_id": "T1622"},
                {"method": "clone", "mitre_id": "T1497.001"},
            ],
            "summary": {"total_techniques": 2, "risk_level": "high", "mitre_tactics": ["Defense Evasion"]},
        },
    }

    verdict_name, verdict_class, indicators, score = calculate_verdict(IOCs(), state)

    assert score >= 40
    assert verdict_class in ("suspicious", "malicious")
    assert any("Qiling suspicious syscalls" in item for item in indicators)
    assert any("Qiling high-risk syscalls" in item for item in indicators)
    assert any("Qiling evasion techniques" in item for item in indicators)
    assert verdict_name in ("Suspicious", "Malware")


def test_qiling_high_risk_syscall_names_contribute_without_summary_flags():
    state = deepcopy(DEFAULT_STATE)
    state["summary"] = ""
    state["qiling_analysis_results"] = {
        "syscalls": {
            "ok": True,
            "syscalls": [
                {"name": "process_vm_writev", "address": "0x401100", "args": [], "category": "memory"},
                {"name": "connect", "address": "0x401120", "args": [3, "1.2.3.4:443"], "category": "network"},
            ],
            "summary": {"total_calls": 2, "categories": {"memory": 1, "network": 1}, "suspicious_calls": []},
        }
    }

    _, verdict_class, indicators, score = calculate_verdict(IOCs(), state)

    assert score >= 10
    assert verdict_class in ("suspicious", "malicious")
    assert any("Qiling high-risk syscalls" in item for item in indicators)


def test_qiling_syscall_and_api_names_drive_capability_indicators():
    state = deepcopy(DEFAULT_STATE)
    state["summary"] = ""
    state["qiling_analysis_results"] = {
        "syscalls": {
            "ok": True,
            "syscalls": [
                {"name": "connect", "address": "0x401120", "args": [3, "1.2.3.4:443"], "category": "network"},
                {"name": "execve", "address": "0x401140", "args": ["/bin/sh", "-c", "id"], "category": "process"},
            ],
            "summary": {"total_calls": 2, "categories": {"network": 1, "process": 1}, "suspicious_calls": []},
        },
        "api_calls": {
            "ok": True,
            "api_calls": [
                {"module": "ws2_32.dll", "name": "send", "args": {"buf": "hello"}},
                {"module": "kernel32.dll", "name": "WinExec", "args": {"cmd": "cmd.exe /c whoami"}},
            ],
        },
    }

    _, _, indicators, score = calculate_verdict(IOCs(), state)

    assert score >= 20
    assert "Network capability detected" in indicators
    assert "Command execution capability detected" in indicators
