#!/usr/bin/env python3
import json
from pathlib import Path

root = Path(__file__).resolve().parents[2]
input_path = root / "clean" / "python" / "inputs" / "clean_python_config_rw_02.input.json"
out_dir = root / "sandbox_output" / "python_output" / "clean_python_config_rw_02"
out_dir.mkdir(parents=True, exist_ok=True)

config = json.loads(input_path.read_text(encoding="utf-8"))
config["last_opened"] = "local"

output_path = out_dir / "config_out.json"
output_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
print(f"[clean] wrote config to {output_path}")
