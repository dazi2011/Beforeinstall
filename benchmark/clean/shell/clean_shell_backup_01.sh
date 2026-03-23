#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"
SANDBOX_DIR="$ROOT_DIR/sandbox_runtime/clean_shell_backup_01"
mkdir -p "$SANDBOX_DIR"

echo "user notes $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$SANDBOX_DIR/notes.txt"
cp "$SANDBOX_DIR/notes.txt" "$SANDBOX_DIR/notes.txt.bak"

echo "[clean] sandbox backup completed: $SANDBOX_DIR"
