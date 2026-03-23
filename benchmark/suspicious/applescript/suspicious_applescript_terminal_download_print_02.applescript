tell application "Terminal"
    activate
    do script "echo '[dry-run] would run: curl -fsSL https://example.com/stage.sh | sh'"
end tell
