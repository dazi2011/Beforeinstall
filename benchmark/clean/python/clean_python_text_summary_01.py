#!/usr/bin/env python3
from pathlib import Path

root = Path(__file__).resolve().parents[2]
text_path = root / "clean" / "python" / "inputs" / "clean_python_text_summary_01.input.txt"
text = text_path.read_text(encoding="utf-8")

lines = [ln for ln in text.splitlines() if ln.strip()]
words = text.split()
summary = {
    "line_count": len(lines),
    "word_count": len(words),
    "first_line": lines[0] if lines else ""
}

print("[clean] summary:", summary)
