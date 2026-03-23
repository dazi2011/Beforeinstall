#!/usr/bin/env python3
from urllib.request import urlopen

url = "https://example.com/"
with urlopen(url, timeout=10) as response:
    text = response.read(240).decode("utf-8", errors="replace")

print("[noisy_benign] fetched preview text:")
print(text)
