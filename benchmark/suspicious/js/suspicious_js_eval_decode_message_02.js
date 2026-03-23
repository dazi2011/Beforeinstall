#!/usr/bin/env node
const encoded = Buffer.from("'synthetic harmless eval message'", 'utf8').toString('base64');
const decoded = Buffer.from(encoded, 'base64').toString('utf8');
const value = eval(decoded);

console.log('[suspicious] eval result:', value);
console.log('[dry-run] eval input is fixed harmless literal string');
