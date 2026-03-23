#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
APP_SUPPORT_STYLE_DIR="$PROJECT_ROOT/benchmark/sandbox_output/app_support_style/ExampleVendor/ExampleApp"
mkdir -p "$APP_SUPPORT_STYLE_DIR"

cat > "$APP_SUPPORT_STYLE_DIR/settings.json" <<'JSON'
{
  "last_launch": "synthetic",
  "telemetry": false,
  "channel": "stable"
}
JSON

echo "[noisy_benign] wrote Application Support-style data in project sandbox only"
