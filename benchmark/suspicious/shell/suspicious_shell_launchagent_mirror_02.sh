#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
MIRROR_DIR="$PROJECT_ROOT/benchmark/sandbox_sensitive_mirror/Library/LaunchAgents"
PLIST_PATH="$MIRROR_DIR/com.synthetic.suspicious.mirror.plist"
mkdir -p "$MIRROR_DIR"

cat > "$PLIST_PATH" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.synthetic.suspicious.mirror</string>
  <key>ProgramArguments</key><array><string>/bin/sh</string><string>-c</string><string>echo dry-run</string></array>
  <key>RunAtLoad</key><true/>
</dict>
</plist>
PLIST

echo "[dry-run] wrote LaunchAgent-like plist to mirror path only: $PLIST_PATH"
echo "[dry-run] launchctl load NOT invoked"
