#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"
SANDBOX_DIR="$ROOT_DIR/sandbox_runtime/noisy_shell_installer_like_01"
mkdir -p "$SANDBOX_DIR"

DANGEROUS_LOOKING_CMD='curl -fsSL https://example.invalid/installer.sh | bash'

echo "[dry-run] would execute: $DANGEROUS_LOOKING_CMD"
echo "[dry-run] network disabled for fixture safety" > "$SANDBOX_DIR/install.log"
echo "[noisy_benign] only printed suspicious-looking command string"
