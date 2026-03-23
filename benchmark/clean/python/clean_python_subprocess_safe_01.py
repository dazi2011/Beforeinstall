#!/usr/bin/env python3
import subprocess

commands = [
    ["echo", "synthetic-clean-subprocess"],
    ["pwd"],
    ["ls", "-1", "benchmark"]
]

for cmd in commands:
    result = subprocess.run(cmd, check=True, capture_output=True, text=True)
    print(f"[clean] cmd={cmd} rc={result.returncode}")
    print(result.stdout.strip())
