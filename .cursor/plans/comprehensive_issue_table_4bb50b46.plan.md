---
name: Comprehensive Issue Table
overview: Complete inventory of all remaining issues and improvement points, comparing the current system against the reference report quality bar.
todos: []
isProject: false
---

# All Issues and Improvement Points

Compared against the reference report (`sample_report_fed7ae045bc...html`) and observed behavior during testing.

## Bugs (broken functionality)


| #   | Area          | File                                                                  | Issue                                                                                                                                                                                                                                                         | Impact                                                          |
| --- | ------------- | --------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| B1  | Ghidra Script | [decompile_function.py](backend/ghidra_scripts/decompile_function.py) | `FUN_080d3937` is set as `current_function` name but the iterator `f.getName()` may return a different label (e.g., `FUN_080d3937` vs Ghidra's auto-label). More critically, the name-based search iterates 4,580 functions sequentially -- slow and fragile. | Decompile-by-name rarely finds the function                     |
| B2  | Graph         | [graph.py:37-39](backend/src/ghidra_agent/graph.py)                   | `parse_intent` sets `FUN_080d3937` as `current_function` but does NOT extract `0x080d3937` as `current_address` fallback. The decompile script supports address-based lookup but the address is never passed.                                                 | Query "Decompile FUN_080d3937" fails silently                   |
| B3  | Graph         | [graph.py:88-136](backend/src/ghidra_agent/graph.py)                  | `focus_analysis` only runs when `current_function` or `current_address` is set. On initial upload (no query), neither is set, so entry point is never decompiled.                                                                                             | First analysis has zero decompiled code for the LLM             |
| B4  | Graph         | [graph.py:186-187](backend/src/ghidra_agent/graph.py)                 | `synthesize` sends only the first 30 function names and 20 strings to LLM. For a 4,580-function binary, the LLM misses the important functions deeper in the list.                                                                                            | Shallow analysis, misses key functions like `FUN_080d3937`      |
| B5  | Graph         | [graph.py:196-197](backend/src/ghidra_agent/graph.py)                 | `synthesize` reads `decompilation_cache` but never includes it in the LLM context. The cache data is silently ignored.                                                                                                                                        | Even when decompile succeeds, the C code is not sent to the LLM |
| B6  | Report        | [reporting.py:60](backend/src/ghidra_agent/reporting.py)              | HTML report uses hardcoded "Ghidra analysis completed." and raw JSON dump. Does not include the LLM `summary` or any structured sections.                                                                                                                     | HTML report is useless compared to reference                    |


## Improvement Points (quality gap vs reference report)


| #   | Area                   | What Reference Report Has                                                                                   | What We Have                                                                  | Improvement Needed                                                                          |
| --- | ---------------------- | ----------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| I1  | Auto-decompile         | Entry point + key functions (`sub_80d3937`, `sub_80d3824`, `sub_80c5d6e`) decompiled automatically          | No auto-decompilation during discovery                                        | After `list_functions`, auto-decompile entry point + top 3-5 most-referenced functions      |
| I2  | LLM context: C code    | Full C pseudocode snippets included in analysis                                                             | LLM only sees function names + strings                                        | Feed `decompilation_cache` contents into the synthesize prompt                              |
| I3  | LLM context: depth     | Reference analyzes syscall wrappers, malloc/free, crypto routines by reading the C code                     | Only surface metadata (names, strings, segments)                              | Send more functions (sorted by xref count) and actual decompiled code                       |
| I4  | String selection       | Reference highlights `/proc/self/maps`, `/bin/sh`, crypto strings, C2 IPs                                   | First 20 strings alphabetically (includes section names like `.bss`, `.data`) | Sort strings by relevance: prioritize `/proc`, `/dev`, `/bin`, IP patterns, crypto keywords |
| I5  | Function selection     | Reference picks functions by behavioral role (init, daemonize, mutex, syscall)                              | First 30 functions by address order                                           | Sort by xref count descending; label entry point and high-xref functions                    |
| I6  | IOC extraction         | C2 IP `149.28.130.195:443`, file paths, ClamAV detections                                                   | Nothing                                                                       | Extract IP/URL patterns from strings, flag file paths like `/etc/rc.d/init.d/`              |
| I7  | Malware classification | "Linux/Mirai variant", "Trojan" based on behavioral patterns                                                | Generic "potential RAT/botnet" guessing from string names                     | With decompiled code, the LLM can identify specific malware families                        |
| I8  | Report format          | Structured HTML with Executive Summary, Static Analysis, Behavioral Analysis, IOCs, Conclusion, code blocks | Plain markdown in `summary` field; HTML report is raw JSON dump               | Generate structured report from LLM summary                                                 |
| I9  | Multi-pass analysis    | Reference report appears to analyze multiple functions across multiple passes                               | Single-pass: discovery then synthesize                                        | Support iterative analysis: LLM requests more decompilation, agent fetches it               |
| I10 | Analysis speed         | Each Ghidra script re-runs full auto-analysis (~30s) even with `-process`                                   | Same                                                                          | Cache analysis results or use `-noanalysis` for subsequent script runs on same project      |


## Priority Ranking

- **P0 (must fix -- broken):** B1, B2, B3, B5
- **P1 (high impact on report quality):** I1, I2, I3, I4, I5
- **P2 (medium -- report polish):** B4, B6, I6, I8
- **P3 (nice to have):** I7, I9, I10

