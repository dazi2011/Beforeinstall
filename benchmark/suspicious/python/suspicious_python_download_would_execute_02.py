#!/usr/bin/env python3
from urllib.request import urlopen

url = "https://example.com/"
with urlopen(url, timeout=10) as resp:
    text = resp.read(180).decode("utf-8", errors="replace")

print("[suspicious] downloaded text preview:")
print(text)
print("[dry-run] would execute downloaded content: BLOCKED")
