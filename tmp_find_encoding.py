data = open('backend/src/ghidra_agent/reporting.py', 'rb').read()

# Try to decode as UTF-8 and collect all non-ASCII chars with their line context
lines = data.split(b'\n')
for lineno, line in enumerate(lines, 1):
    has_non_ascii = any(b > 127 for b in line)
    if has_non_ascii:
        try:
            decoded = line.decode('utf-8')
            print(f"Line {lineno} (UTF-8 OK): {repr(decoded[:120])}")
        except UnicodeDecodeError as e:
            print(f"Line {lineno} (UTF-8 FAIL at {e.start}): {repr(line[:120])}")
