#!/usr/bin/env python3
from pathlib import Path

root = Path(__file__).resolve().parents[2]
sandbox = root / "sandbox_runtime" / "noisy_python_updater_01"
sandbox.mkdir(parents=True, exist_ok=True)

candidate_urls = [
    "https://updates.example.invalid/app/latest.pkg",
    "https://cdn.example.invalid/signatures/latest.sig",
]

print("[dry-run] updater candidate URLs (not fetched):")
for url in candidate_urls:
    print(" -", url)

(sandbox / "updater_report.txt").write_text(
    "No network calls were made. URLs listed for detection testing only.\n",
    encoding="utf-8",
)
