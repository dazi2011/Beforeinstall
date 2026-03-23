#!/usr/bin/env bash
set -euo pipefail

SAFE_URL="https://www.apple.com/macos/"
open "$SAFE_URL"
echo "[clean] opened fixed safe URL: $SAFE_URL"
