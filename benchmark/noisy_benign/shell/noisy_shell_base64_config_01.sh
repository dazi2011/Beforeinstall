#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
OUT_DIR="$PROJECT_ROOT/benchmark/sandbox_output/cache/noisy_shell_base64_config_01"
mkdir -p "$OUT_DIR"

CONFIG_PAYLOAD='{"feature":"safe-mode","retry":3}'
ENCODED="$(printf '%s' "$CONFIG_PAYLOAD" | base64)"
printf '%s\n' "$ENCODED" > "$OUT_DIR/config.b64"
printf '%s\n' "$ENCODED" | base64 --decode > "$OUT_DIR/config.decoded.json"

echo "[noisy_benign] base64 config generated at $OUT_DIR"
