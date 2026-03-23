#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
TOOL_DIR="$PROJECT_ROOT/benchmark/sandbox_output/chmod_targets"
mkdir -p "$TOOL_DIR"

cat > "$TOOL_DIR/helper_tool.sh" <<'TOOL'
#!/usr/bin/env bash
echo "helper tool"
TOOL

chmod +x "$TOOL_DIR/helper_tool.sh"
echo "[noisy_benign] chmod applied in sandbox only: $TOOL_DIR/helper_tool.sh"
