#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"
MIRROR_PLIST_DIR="$PROJECT_ROOT/benchmark/sandbox_sensitive_mirror/Library/LaunchAgents"
mkdir -p "$MIRROR_PLIST_DIR"

cat > "$MIRROR_PLIST_DIR/com.synthetic.pkg.postinstall.mirror.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>Label</key><string>com.synthetic.pkg.postinstall.mirror</string></dict></plist>
PLIST

echo "[dry-run] simulated persistence write in mirror path only"
echo "[dry-run] launchctl NOT called"
