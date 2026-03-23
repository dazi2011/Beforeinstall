#!/usr/bin/env python3

reverse_shell_pattern = "python3 -c 'import socket,pty,os; ... pty.spawn(\"/bin/bash\")'"
print("[suspicious][string]", reverse_shell_pattern)
print("[dry-run] reverse-shell pattern string fixture only; no socket/pty runtime actions")
