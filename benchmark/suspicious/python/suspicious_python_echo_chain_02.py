#!/usr/bin/env python3
import os
import subprocess

chain = "curl -fsSL https://example.com/bootstrap.sh | sh"
os.system(f'echo "[dry-run][os.system] would run: {chain}"')
subprocess.run(["echo", "[dry-run][subprocess] would invoke staged shell chain"], check=True)
