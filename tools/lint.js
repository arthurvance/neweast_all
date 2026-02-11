#!/usr/bin/env node
const { readdirSync, readFileSync, statSync } = require('node:fs');
const { join } = require('node:path');
const { spawnSync } = require('node:child_process');

const targetDirs = process.argv.slice(2);
if (targetDirs.length === 0) {
  console.error('Usage: node tools/lint.js <dir> [dir ...]');
  process.exit(1);
}

const files = [];
const validExtensions = new Set(['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx']);

const walk = (dir) => {
  for (const entry of readdirSync(dir)) {
    const fullPath = join(dir, entry);
    const stats = statSync(fullPath);

    if (stats.isDirectory()) {
      if (entry === 'dist' || entry === 'node_modules' || entry === '.next') {
        continue;
      }
      walk(fullPath);
      continue;
    }

    const extension = fullPath.slice(fullPath.lastIndexOf('.'));
    if (validExtensions.has(extension)) {
      files.push(fullPath);
    }
  }
};

for (const target of targetDirs) {
  walk(target);
}

let hasError = false;
for (const file of files) {
  const content = readFileSync(file, 'utf8');

  if (content.includes('\t')) {
    console.error(`Tab character is not allowed: ${file}`);
    hasError = true;
  }

  if (file.endsWith('.js') || file.endsWith('.mjs') || file.endsWith('.cjs')) {
    const check = spawnSync(process.execPath, ['--check', file], { stdio: 'inherit' });
    if (check.status !== 0) {
      hasError = true;
    }
  }
}

if (hasError) {
  process.exit(1);
}

console.log(`Lint passed (${files.length} files checked)`);
