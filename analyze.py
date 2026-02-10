#!/usr/bin/env python3
"""Upload a binary and poll until analysis completes."""
import sys
import time
import requests
from datetime import datetime

API = "http://localhost:8080"


def main():
    if len(sys.argv) < 2:
        print("Usage: python analyze.py <binary-file>")
        print("  e.g. python analyze.py sample-binary/chargen")
        sys.exit(1)

    filepath = sys.argv[1]

    print(f"==> Uploading: {filepath}")
    with open(filepath, "rb") as f:
        resp = requests.post(f"{API}/analyze/upload", files={"file": f})
    resp.raise_for_status()
    sid = resp.json()["session_id"]
    print(f"==> Session: {sid}")

    print("==> Polling status...")
    while True:
        data = requests.get(f"{API}/status/{sid}").json()
        status = data["status"]
        print(f"{datetime.now():%H:%M:%S} {status}")

        if status in ("completed", "error"):
            r = data["state"]
            ar = r.get("analysis_results", {})
            binary = ar.get("binary", {})

            print()
            print("=== GHIDRA RESULTS ===")
            print(f"binary ok:   {bool(binary.get('ok'))}")
            print(f"functions:   {len(ar.get('functions', {}).get('functions', []))}")
            print(f"strings:     {len(ar.get('strings', {}).get('strings', []))}")
            print(f"decompiled:  {len(r.get('decompilation_cache', {}))}")
            print(f"imports:     {len(binary.get('imports', []))}")
            print(f"exports:     {len(binary.get('exports', []))}")

            # R2 results
            r2 = r.get("r2_analysis_results", {})
            r2_bin = r2.get("binary", {})
            r2_funcs = len(r2.get("functions", {}).get("functions", []))
            r2_decomp = len(r.get("r2_decompilation_cache", {}))
            r2_imports = len(r2_bin.get("imports", []))
            r2_exports = len(r2_bin.get("exports", []))
            if r2_funcs:
                print()
                print("=== RADARE2 RESULTS ===")
                print(f"functions:   {r2_funcs}")
                print(f"decompiled:  {r2_decomp}")
                print(f"imports:     {r2_imports}")
                print(f"exports:     {r2_exports}")
                syscalls = r2.get("syscalls", {}).get("syscalls", [])
                if syscalls:
                    print(f"syscalls:    {len(syscalls)}")

            # Byte signatures
            byte_sigs = ar.get("byte_signatures", {}).get("signatures", [])
            sig_hits = sum(1 for s in byte_sigs if s.get("count", 0) > 0)
            print()
            print(f"=== INDICATORS ===")
            print(f"byte sigs:   {len(byte_sigs)} scanned, {sig_hits} hits")

            ioc_data = ar.get("iocs", {}).get("data", {})
            if ioc_data:
                total = sum(len(v) for v in ioc_data.values() if isinstance(v, list))
                print(f"IOCs:        {total}")

            assessment = ar.get("ioc_assessment", {})
            if assessment:
                print(f"verdict:     {assessment.get('verdict', 'N/A')}")
                print(f"score:       {assessment.get('score', 'N/A')}")

            print()
            print("--- SUMMARY ---")
            print(r.get("summary", "")[:800])
            break

        time.sleep(5)


if __name__ == "__main__":
    main()
