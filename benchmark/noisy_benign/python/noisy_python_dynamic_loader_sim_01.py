#!/usr/bin/env python3
import ctypes
import importlib.util
from pathlib import Path

root = Path(__file__).resolve().parents[2]
fake_module_path = root / "sandbox_output" / "tmp" / "dynamic_loader_sim" / "plugin_stub.py"
fake_module_path.parent.mkdir(parents=True, exist_ok=True)
fake_module_path.write_text("value = 'synthetic-plugin'\n", encoding="utf-8")

spec = importlib.util.spec_from_file_location("plugin_stub", fake_module_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

print("[noisy_benign] loaded module value:", module.value)
print("[noisy_benign] ctypes.c_int demo:", ctypes.c_int(7).value)
