#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
PROFILE_PATH="$PROJECT_ROOT/benchmark/sandbox_sensitive_mirror/home/.zshrc"
mkdir -p "$(dirname "$PROFILE_PATH")"

PAYLOAD_LINE='echo "[dry-run] would bootstrap updater" # synthetic fixture'
printf '%s\n' "$PAYLOAD_LINE" >> "$PROFILE_PATH"

echo "[dry-run] appended simulated profile persistence line to mirror path: $PROFILE_PATH"
