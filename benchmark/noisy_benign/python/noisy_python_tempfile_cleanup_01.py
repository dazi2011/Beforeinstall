#!/usr/bin/env python3
from pathlib import Path

root = Path(__file__).resolve().parents[2]
tmp_dir = root / "sandbox_output" / "tmp" / "noisy_python_tempfile_cleanup_01"
tmp_dir.mkdir(parents=True, exist_ok=True)

tmp_file = tmp_dir / "transient.tmp"
tmp_file.write_text("temporary synthetic data\n", encoding="utf-8")
print(f"[noisy_benign] created {tmp_file}")

tmp_file.unlink()
print(f"[noisy_benign] removed {tmp_file}")
