#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');

const repoRoot = path.resolve(__dirname, '../../..');
const joinModulePath = (...segments) => segments.join('/');

const REPLACEMENTS = [
  {
    from: joinModulePath('modules', 'auth', 'auth.service'),
    to: 'shared-kernel/auth/create-auth-service',
    bridge: joinModulePath('modules', 'auth', 'auth.service')
  },
  {
    from: joinModulePath('modules', 'auth', 'auth.store.memory'),
    to: 'shared-kernel/auth/store/create-in-memory-auth-store',
    bridge: joinModulePath('modules', 'auth', 'auth.store.memory')
  },
  {
    from: joinModulePath('modules', 'auth', 'auth.store.mysql'),
    to: 'shared-kernel/auth/store/create-mysql-auth-store',
    bridge: joinModulePath('modules', 'auth', 'auth.store.mysql')
  },
  {
    from: joinModulePath('store-methods', 'auth-store-memory-capabilities'),
    to: 'shared-kernel/auth/store/memory/shared-memory-auth-store-repository-method-map.service',
    bridge: joinModulePath('store-methods', 'auth-store-memory-capabilities')
  },
  {
    from: joinModulePath('store-methods', 'auth-store-mysql-capabilities'),
    to: 'shared-kernel/auth/store/mysql/shared-mysql-auth-store-repository-method-map.service',
    bridge: joinModulePath('store-methods', 'auth-store-mysql-capabilities')
  }
];

const SCAN_DIRECTORIES = ['apps', 'tools'];
const SOURCE_FILE_RE = /\.(?:[mc]?js|ts|tsx|jsx|md)$/;

const args = new Set(process.argv.slice(2));
const checkOnly = args.has('--check');
const restoreBridge = args.has('--restore-bridge');

function walk(directoryPath, files) {
  let entries = [];
  try {
    entries = fs.readdirSync(directoryPath, { withFileTypes: true });
  } catch (_error) {
    return;
  }

  for (const entry of entries) {
    if (entry.name === 'node_modules' || entry.name === '.git' || entry.name === 'dist') {
      continue;
    }
    const absolutePath = path.join(directoryPath, entry.name);
    if (entry.isDirectory()) {
      walk(absolutePath, files);
      continue;
    }
    if (entry.isFile() && SOURCE_FILE_RE.test(entry.name)) {
      files.push(absolutePath);
    }
  }
}

function getTargetFiles() {
  const files = [];
  for (const directoryName of SCAN_DIRECTORIES) {
    walk(path.join(repoRoot, directoryName), files);
  }
  return files;
}

function run() {
  const targetFiles = getTargetFiles();
  const findings = [];
  let updatedCount = 0;

  for (const filePath of targetFiles) {
    if (path.resolve(filePath) === path.resolve(__filename)) {
      continue;
    }
    const original = fs.readFileSync(filePath, 'utf8');
    let next = original;

    for (const replacement of REPLACEMENTS) {
      const source = restoreBridge ? replacement.to : replacement.from;
      const target = restoreBridge ? replacement.bridge : replacement.to;
      if (next.includes(source)) {
        findings.push(`${path.relative(repoRoot, filePath)}: ${source}`);
        if (!checkOnly) {
          next = next.split(source).join(target);
        }
      }
    }

    if (!checkOnly && next !== original) {
      fs.writeFileSync(filePath, next, 'utf8');
      updatedCount += 1;
    }
  }

  if (checkOnly) {
    if (findings.length > 0) {
      process.stderr.write(
        `Legacy auth import references found (${findings.length}):\n${findings.join('\n')}\n`
      );
      process.exit(1);
    }
    process.stdout.write('OK: no legacy auth import references found.\n');
    return;
  }

  process.stdout.write(
    `${restoreBridge ? 'Restored' : 'Updated'} auth import paths in ${updatedCount} files.\n`
  );
}

run();
