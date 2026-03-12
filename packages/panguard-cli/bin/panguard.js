#!/usr/bin/env node
// Thin wrapper: delegates to @panguard-ai/panguard CLI
const { join, dirname } = require('path');
const { createRequire } = require('module');

// resolve the installed @panguard-ai/panguard package directory
const r = createRequire(__filename);
let pkgDir;
try {
  // package.json is always resolvable regardless of ESM/CJS
  const pkgJson = r.resolve('@panguard-ai/panguard/package.json');
  pkgDir = dirname(pkgJson);
} catch {
  console.error('Error: @panguard-ai/panguard is not installed.');
  console.error('Run: npm install -g @panguard-ai/panguard');
  process.exit(1);
}

const cli = join(pkgDir, 'dist', 'cli', 'index.js');
import(cli).catch(e => { console.error(e.message); process.exit(1); });
