#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"
TARGET="$PROJECT_ROOT/benchmark/sandbox_output/pkg_install_target"
mkdir -p "$TARGET"
printf 'preinstall check\n' > "$TARGET/preinstall.log"
echo "[noisy_benign pkg] preinstall wrote sandbox log"
