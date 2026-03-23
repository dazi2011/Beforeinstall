#!/usr/bin/env node
const { execFile } = require('child_process');

execFile('echo', ['node-safe-echo'], (err, stdout, stderr) => {
  if (err) {
    console.error(err.message);
    process.exit(1);
  }
  if (stderr) {
    console.error(stderr);
  }
  console.log('[clean] child_process output:', stdout.trim());
});
