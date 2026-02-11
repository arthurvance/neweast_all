#!/usr/bin/env node
const { cpSync, mkdirSync, rmSync } = require('node:fs');
const { spawnSync } = require('node:child_process');
const { resolve } = require('node:path');

const root = resolve(__dirname, '..');
const output = resolve(root, 'dist/apps/web');

rmSync(output, { recursive: true, force: true });
mkdirSync(output, { recursive: true });

const viteBuild = spawnSync('pnpm', ['--dir', 'apps/web', 'run', 'build'], {
  cwd: root,
  stdio: 'inherit',
  env: process.env
});

if (viteBuild.status !== 0) {
  process.exit(viteBuild.status || 1);
}

cpSync(resolve(root, 'apps/web/server.js'), resolve(output, 'server.js'));
cpSync(resolve(root, 'apps/web/src/server.js'), resolve(output, 'src/server.js'), {
  recursive: true
});

console.log('Built dist/apps/web');
