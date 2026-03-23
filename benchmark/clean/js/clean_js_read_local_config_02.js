#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

const configPath = path.join(__dirname, 'inputs', 'clean_js_read_local_config_02.input.json');
const raw = fs.readFileSync(configPath, 'utf8');
const config = JSON.parse(raw);

console.log('[clean] loaded local config:', config);
