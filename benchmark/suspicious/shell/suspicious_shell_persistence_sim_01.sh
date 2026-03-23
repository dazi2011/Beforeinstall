#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"
SANDBOX_DIR="$ROOT_DIR/sandbox_runtime/suspicious_shell_persistence_sim_01"
mkdir -p "$SANDBOX_DIR"

PERSIST_CMD='launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.fake.agent.plist'
PLIST_PATH="$SANDBOX_DIR/com.fake.agent.plist"

echo "[string-only] simulated persistence command: $PERSIST_CMD"
cat > "$PLIST_PATH" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>Label</key><string>com.fake.agent</string></dict></plist>
PLIST

echo "[dry-run] fake plist written to sandbox only: $PLIST_PATH"
