# Replace Unicode special characters in reporting.py with ASCII-safe alternatives
import re

path = 'backend/src/ghidra_agent/reporting.py'

with open(path, 'rb') as f:
    content = f.read()

replacements = [
    (b'\xe2\x80\x94', b' -- '),   # em dash (U+2014) -> ' -- '
    (b'\xe2\x80\x93', b' - '),    # en dash (U+2013) -> ' - '
    (b'\xe2\x80\xa6', b'...'),    # ellipsis (U+2026) -> '...'
    (b'\xe2\x80\x98', b"'"),      # left single quote
    (b'\xe2\x80\x99', b"'"),      # right single quote
    (b'\xe2\x80\x9c', b'"'),      # left double quote
    (b'\xe2\x80\x9d', b'"'),      # right double quote
]

total = 0
for old, new in replacements:
    count = content.count(old)
    if count:
        print(f"Replacing {count}x {repr(old)} -> {repr(new)}")
        content = content.replace(old, new)
        total += count

print(f"\nTotal replacements: {total}")

with open(path, 'wb') as f:
    f.write(content)

print("Done.")

# Verify no more non-ASCII
remaining = [(i, hex(b)) for i, b in enumerate(content) if b > 127]
if remaining:
    print(f"WARNING: {len(remaining)} non-ASCII bytes remaining:")
    for pos, bval in remaining[:10]:
        print(f"  pos={pos} byte={bval}: {repr(content[max(0,pos-40):pos+40])}")
else:
    print("OK: No non-ASCII bytes remaining in file.")
