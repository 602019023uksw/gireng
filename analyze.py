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
            print("=== RESULTS ===")
            print(f"binary ok:   {bool(binary.get('ok'))}")
            print(f"functions:   {len(ar.get('functions', {}).get('functions', []))}")
            print(f"strings:     {len(ar.get('strings', {}).get('strings', []))}")
            print(f"decompiled:  {len(r.get('decompilation_cache', {}))}")
            print(f"imports:     {len(binary.get('imports', []))}")
            print(f"exports:     {len(binary.get('exports', []))}")
            print(f"byte sigs:   {len(ar.get('byte_signatures', []))}")

            iocs = ar.get("iocs", {})
            if iocs:
                total = sum(len(v) for v in iocs.values() if isinstance(v, list))
                print(f"IOCs:        {total}")

            print()
            print("--- SUMMARY ---")
            print(r.get("summary", "")[:800])
            break

        time.sleep(5)


if __name__ == "__main__":
    main()
