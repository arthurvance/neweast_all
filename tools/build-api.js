#!/usr/bin/env node
const { cpSync, mkdirSync, rmSync, writeFileSync } = require('node:fs');
const { resolve } = require('node:path');

const root = resolve(__dirname, '..');
const output = resolve(root, 'dist/apps/api');

rmSync(output, { recursive: true, force: true });
mkdirSync(output, { recursive: true });
cpSync(resolve(root, 'apps/api/src'), resolve(output, 'src'), { recursive: true });
cpSync(resolve(root, 'apps/api/migrations'), resolve(output, 'migrations'), { recursive: true });
cpSync(resolve(root, 'apps/api/scripts'), resolve(output, 'scripts'), { recursive: true });
cpSync(resolve(root, 'apps/api/typeorm.config.js'), resolve(output, 'typeorm.config.js'));
writeFileSync(resolve(output, 'README.txt'), 'API build artifact generated for Story 1.1 baseline.\n');
console.log('Built dist/apps/api');
