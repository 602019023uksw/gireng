"""Create minimal valid Windows NT registry hive files for Qiling emulation.

This generates empty but structurally valid registry hive files (REGF format)
that satisfy Qiling's RegistryManager initialization. The hives are minimal
and contain only the root key node.
"""

from __future__ import annotations

import os
import struct
import sys


def create_minimal_hive(path: str) -> None:
    """Create a minimal valid Windows NT registry hive file."""
    BLOCK_SIZE = 4096

    # --- REGF header (first 4096-byte block) ---
    hdr = bytearray(BLOCK_SIZE)
    hdr[0:4] = b"regf"                            # Signature
    struct.pack_into("<I", hdr, 4, 1)              # Sequence1
    struct.pack_into("<I", hdr, 8, 1)              # Sequence2
    hdr[12:20] = b"\x00" * 8                       # Timestamp
    struct.pack_into("<I", hdr, 20, 1)             # Major version
    struct.pack_into("<I", hdr, 24, 3)             # Minor version
    struct.pack_into("<I", hdr, 28, 0)             # Type (primary)
    struct.pack_into("<I", hdr, 32, 1)             # Format
    struct.pack_into("<I", hdr, 36, 32)            # Root cell offset (from hbin start)
    struct.pack_into("<I", hdr, 40, BLOCK_SIZE)    # Hive bins data size
    struct.pack_into("<I", hdr, 44, 1)             # Cluster

    # Checksum over first 508 bytes
    checksum = 0
    for i in range(0, 508, 4):
        checksum ^= struct.unpack("<I", hdr[i : i + 4])[0]
    checksum &= 0xFFFFFFFF
    struct.pack_into("<I", hdr, 508, checksum)

    # --- hbin block (second 4096-byte block) ---
    hbin = bytearray(BLOCK_SIZE)
    hbin[0:4] = b"hbin"                            # Signature
    struct.pack_into("<I", hbin, 4, 0)             # Offset from data start
    struct.pack_into("<I", hbin, 8, BLOCK_SIZE)    # Size of this hbin
    hbin[12:20] = b"\x00" * 8                      # Timestamp

    # Root key cell at offset 32 inside hbin
    cell_off = 32
    key_name = b"CMI-CreateHive{root}"

    # In a cell: [4 bytes size][record data...]
    # NKRecord offsets are relative to start of record data (cell_off + 4)
    rec_off = cell_off + 4  # Start of NK record data

    # nk record size: 0x4C (fixed header) + key_name length, plus cell size field
    record_data_size = 0x4C + len(key_name)
    cell_total = 4 + record_data_size  # +4 for cell size field
    # Pad to multiple of 8
    cell_total = (cell_total + 7) & ~7
    # Negative cell size = allocated
    struct.pack_into("<i", hbin, cell_off, -cell_total)

    # NK record fields (offsets relative to rec_off)
    hbin[rec_off + 0x00 : rec_off + 0x02] = b"nk"  # Signature
    struct.pack_into("<H", hbin, rec_off + 0x02, 0x0024)  # Flags: KEY_HIVE_ENTRY | KEY_COMP_NAME
    hbin[rec_off + 0x04 : rec_off + 0x0C] = b"\x00" * 8  # Timestamp
    struct.pack_into("<I", hbin, rec_off + 0x0C, 0)  # Access bits / spare
    struct.pack_into("<I", hbin, rec_off + 0x10, 32)  # Parent cell offset (self for root)
    struct.pack_into("<I", hbin, rec_off + 0x14, 0)  # Number of stable subkeys
    struct.pack_into("<I", hbin, rec_off + 0x18, 0)  # Number of volatile subkeys
    struct.pack_into("<i", hbin, rec_off + 0x1C, -1)  # Stable subkeys list offset (none)
    struct.pack_into("<i", hbin, rec_off + 0x20, -1)  # Volatile subkeys list offset (none)
    struct.pack_into("<I", hbin, rec_off + 0x24, 0)  # Number of values
    struct.pack_into("<i", hbin, rec_off + 0x28, -1)  # Values list offset (none)
    struct.pack_into("<i", hbin, rec_off + 0x2C, -1)  # Security descriptor offset (none)
    struct.pack_into("<i", hbin, rec_off + 0x30, -1)  # Class name offset (none)
    struct.pack_into("<I", hbin, rec_off + 0x34, 0)  # Max subkey name length
    struct.pack_into("<I", hbin, rec_off + 0x38, 0)  # Max class name length
    struct.pack_into("<I", hbin, rec_off + 0x3C, 0)  # Max value name length
    struct.pack_into("<I", hbin, rec_off + 0x40, 0)  # Max value data size
    struct.pack_into("<I", hbin, rec_off + 0x44, 0)  # Work variable
    struct.pack_into("<H", hbin, rec_off + 0x48, len(key_name))  # Key name length
    struct.pack_into("<H", hbin, rec_off + 0x4A, 0)  # Class name length
    # Key name data
    hbin[rec_off + 0x4C : rec_off + 0x4C + len(key_name)] = key_name

    # Mark remaining space as a single free cell
    free_off = cell_off + cell_total
    free_size = BLOCK_SIZE - free_off
    if free_size >= 8:
        struct.pack_into("<i", hbin, free_off, free_size)  # positive = free

    with open(path, "wb") as f:
        f.write(hdr)
        f.write(hbin)


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: create_minimal_hives.py <registry_dir>", file=sys.stderr)
        return 2

    registry_dir = sys.argv[1]
    os.makedirs(registry_dir, exist_ok=True)

    hive_names = ["SYSTEM", "SOFTWARE", "SECURITY", "SAM", "HARDWARE", "NTUSER.DAT"]
    for name in hive_names:
        path = os.path.join(registry_dir, name)
        create_minimal_hive(path)
        print(f"  Created {path} ({os.path.getsize(path)} bytes)")

    print(f"Registry hives created in {registry_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
