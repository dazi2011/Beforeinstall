#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"
TARGET="$PROJECT_ROOT/benchmark/sandbox_output/pkg_install_target"
mkdir -p "$TARGET"
printf 'postinstall complete\n' > "$TARGET/postinstall.log"
echo "[noisy_benign pkg] postinstall wrote sandbox log"
