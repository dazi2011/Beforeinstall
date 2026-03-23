#!/usr/bin/env python3
from pathlib import Path

scan_root = Path(__file__).resolve().parents[2] / "sandbox_output"
scan_root.mkdir(parents=True, exist_ok=True)

file_count = 0
total_bytes = 0
for p in scan_root.rglob("*"):
    if p.is_file():
        file_count += 1
        total_bytes += p.stat().st_size

print(f"[clean] scan_root={scan_root}")
print(f"[clean] file_count={file_count} total_bytes={total_bytes}")
