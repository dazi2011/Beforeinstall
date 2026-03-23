#!/usr/bin/env python3
from pathlib import Path

root = Path(__file__).resolve().parents[2]
mirror = root / "sandbox_sensitive_mirror" / "Library" / "LaunchAgents"
mirror.mkdir(parents=True, exist_ok=True)
plist_path = mirror / "com.synthetic.python.mirror.plist"

plist_content = """<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
<plist version=\"1.0\"><dict><key>Label</key><string>com.synthetic.python.mirror</string></dict></plist>
"""
plist_path.write_text(plist_content, encoding="utf-8")
print(f"[dry-run] wrote plist to mirror only: {plist_path}")
print("[dry-run] no launchctl commands executed")
