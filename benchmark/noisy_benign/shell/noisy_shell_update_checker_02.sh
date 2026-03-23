#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
CACHE_DIR="$PROJECT_ROOT/benchmark/sandbox_output/cache/noisy_shell_update_checker_02"
mkdir -p "$CACHE_DIR"

VERSION_URL="https://example.com/"
OUTPUT_FILE="$CACHE_DIR/version_check.txt"

curl -fsSL "$VERSION_URL" -o "$OUTPUT_FILE"
echo "[noisy_benign] fetched text to cache only: $OUTPUT_FILE"
