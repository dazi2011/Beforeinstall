#!/usr/bin/env node
const { execFile } = require('child_process');

execFile('ls', ['-la', 'benchmark'], (err, stdout, stderr) => {
  if (err) {
    console.error(err.message);
    process.exit(1);
  }
  if (stderr) {
    console.error(stderr);
  }
  console.log('[noisy_benign] ls output:');
  console.log(stdout);
});
