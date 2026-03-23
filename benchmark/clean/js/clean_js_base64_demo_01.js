#!/usr/bin/env node
const source = 'benchmark-config-token';
const encoded = Buffer.from(source, 'utf8').toString('base64');
const decoded = Buffer.from(encoded, 'base64').toString('utf8');

console.log('[clean] encoded:', encoded);
console.log('[clean] decoded:', decoded);
