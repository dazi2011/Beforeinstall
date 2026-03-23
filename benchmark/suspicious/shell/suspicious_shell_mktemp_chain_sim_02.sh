#!/usr/bin/env bash
set -euo pipefail

TMP_FILE="$(mktemp "${TMPDIR:-/tmp}/synthetic_fixture.XXXXXX")"
SIM_URL='https://example.com/payload.sh'

echo "[dry-run] would download $SIM_URL to $TMP_FILE"
echo "[dry-run] would chmod +x $TMP_FILE"
echo "[dry-run] would execute $TMP_FILE"

rm -f "$TMP_FILE"
echo "[suspicious] temp filename chain simulated; temp file cleaned"
