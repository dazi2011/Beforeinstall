#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
LOG_SRC="$PROJECT_ROOT/benchmark/sandbox_output/logs_input"
ARCHIVE_DIR="$PROJECT_ROOT/benchmark/sandbox_output/tmp/clean_shell_log_archive_01"
mkdir -p "$LOG_SRC" "$ARCHIVE_DIR"

if [[ -z "$(find "$LOG_SRC" -maxdepth 1 -type f -name '*.log' 2>/dev/null)" ]]; then
  printf "INFO sample log A\n" > "$LOG_SRC/app_a.log"
  printf "WARN sample log B\n" > "$LOG_SRC/app_b.log"
fi

tar -czf "$ARCHIVE_DIR/logs_archive.tgz" -C "$LOG_SRC" .

echo "archived_from=$LOG_SRC" > "$ARCHIVE_DIR/archive_report.txt"
echo "[clean] logs archived to: $ARCHIVE_DIR/logs_archive.tgz"
