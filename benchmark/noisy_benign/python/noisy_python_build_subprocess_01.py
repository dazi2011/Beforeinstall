#!/usr/bin/env python3
import subprocess

steps = [
    ["echo", "build:start"],
    ["echo", "compile:ok"],
    ["echo", "build:done"]
]

for step in steps:
    result = subprocess.run(step, check=True, capture_output=True, text=True)
    print(result.stdout.strip())
