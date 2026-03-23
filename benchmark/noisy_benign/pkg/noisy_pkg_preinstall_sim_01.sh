#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"
SANDBOX_DIR="$ROOT_DIR/sandbox_runtime/noisy_pkg_preinstall_sim_01"
mkdir -p "$SANDBOX_DIR"

echo "[dry-run] would copy app to /Applications (simulation only)"
echo "[dry-run] would run chown root:wheel (simulation only)"

echo "No system changes were made." > "$SANDBOX_DIR/preinstall_sim.log"
