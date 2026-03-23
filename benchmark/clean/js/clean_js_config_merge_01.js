#!/usr/bin/env node
const base = { retries: 2, timeoutMs: 5000, telemetry: false };
const local = { timeoutMs: 3000, locale: "en-US" };
const merged = { ...base, ...local };

console.log("[clean] merged config:", JSON.stringify(merged, null, 2));
