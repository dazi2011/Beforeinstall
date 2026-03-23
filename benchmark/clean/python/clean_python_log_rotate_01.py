#!/usr/bin/env python3
from pathlib import Path
from datetime import datetime

root = Path(__file__).resolve().parents[2]
sandbox = root / "sandbox_runtime" / "clean_python_log_rotate_01"
sandbox.mkdir(parents=True, exist_ok=True)

log_file = sandbox / "app.log"
log_file.write_text(f"INFO rotate test at {datetime.utcnow().isoformat()}Z\n", encoding="utf-8")
rotated = sandbox / "app.log.1"
rotated.write_text(log_file.read_text(encoding="utf-8"), encoding="utf-8")

print(f"[clean] rotated logs in sandbox: {sandbox}")
