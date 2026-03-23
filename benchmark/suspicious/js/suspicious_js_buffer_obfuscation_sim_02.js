#!/usr/bin/env node
const payload = 'launchctl bootstrap gui/501 ~/Library/LaunchAgents/com.fake.plist';
const encoded = Buffer.from(payload, 'utf8').toString('base64');
const decoded = Buffer.from(encoded, 'base64').toString('utf8');

console.log('[suspicious] encoded snippet:', encoded);
console.log('[suspicious] decoded snippet:', decoded);
console.log('[dry-run] no system modification commands are executed');
