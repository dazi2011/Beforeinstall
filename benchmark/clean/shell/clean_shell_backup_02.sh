#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
OUT_DIR="$PROJECT_ROOT/benchmark/sandbox_output/backup/clean_shell_backup_02"
mkdir -p "$OUT_DIR"

copied=0
for dir in "$HOME/Documents" "$HOME/Desktop"; do
  if [[ -d "$dir" ]]; then
    while IFS= read -r f; do
      cp "$f" "$OUT_DIR/$(basename "$f")"
      copied=$((copied + 1))
      [[ $copied -ge 10 ]] && break
    done < <(find "$dir" -maxdepth 1 -type f \( -name '*.txt' -o -name '*.md' -o -name '*.pdf' \) 2>/dev/null)
  fi
  [[ $copied -ge 10 ]] && break

done

echo "copied_files=$copied" > "$OUT_DIR/backup_report.txt"
echo "[clean] backup complete in sandbox: $OUT_DIR"
