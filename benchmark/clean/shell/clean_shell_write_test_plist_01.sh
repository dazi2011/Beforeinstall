#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
PLIST_DIR="$PROJECT_ROOT/benchmark/sandbox_output/plist_tests"
PLIST_PATH="$PLIST_DIR/com.synthetic.clean.test.plist"
mkdir -p "$PLIST_DIR"

cat > "$PLIST_PATH" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.synthetic.clean.test</string>
  <key>RunAtLoad</key>
  <false/>
</dict>
</plist>
PLIST

echo "[clean] wrote test plist to sandbox only: $PLIST_PATH"
