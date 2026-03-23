#!/usr/bin/env node
const https = require('https');
const fs = require('fs');
const path = require('path');

const cacheDir = path.join(__dirname, '..', '..', 'sandbox_output', 'network_cache', 'noisy_js_network_cache_text_01');
fs.mkdirSync(cacheDir, { recursive: true });

const outPath = path.join(cacheDir, 'response.txt');
https.get('https://example.com/', (res) => {
  let data = '';
  res.on('data', (chunk) => {
    data += chunk;
  });
  res.on('end', () => {
    fs.writeFileSync(outPath, data.slice(0, 500), 'utf8');
    console.log('[noisy_benign] cached response text to', outPath);
  });
}).on('error', (err) => {
  console.error('network error:', err.message);
  process.exit(1);
});
