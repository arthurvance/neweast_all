'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const REPO_ROOT = path.resolve(__dirname, '../../..');
const joinSegment = (...segments) => segments.join('/');
const LEGACY_FILES = [
  joinSegment('apps', 'api', 'src', 'modules', 'auth', 'auth.service.js'),
  joinSegment('apps', 'api', 'src', 'modules', 'auth', 'auth.store.memory.js'),
  joinSegment('apps', 'api', 'src', 'modules', 'auth', 'auth.store.mysql.js'),
  joinSegment('apps', 'api', 'src', 'modules', 'auth', 'store-methods', 'auth-store-memory-capabilities.js'),
  joinSegment('apps', 'api', 'src', 'modules', 'auth', 'store-methods', 'auth-store-mysql-capabilities.js')
];
const LEGACY_IMPORT_SEGMENTS = [
  joinSegment('modules', 'auth', 'auth.service'),
  joinSegment('modules', 'auth', 'auth.store.memory'),
  joinSegment('modules', 'auth', 'auth.store.mysql'),
  joinSegment('store-methods', 'auth-store-memory-capabilities'),
  joinSegment('store-methods', 'auth-store-mysql-capabilities')
];

function walk(directoryPath, output) {
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
      walk(absolutePath, output);
      continue;
    }
    if (entry.isFile() && /\.(?:[mc]?js|ts|tsx|jsx|md)$/.test(entry.name)) {
      output.push(absolutePath);
    }
  }
}

test('legacy auth aggregate files are removed in closure stage', () => {
  for (const relativePath of LEGACY_FILES) {
    const absolutePath = path.join(REPO_ROOT, relativePath);
    assert.equal(fs.existsSync(absolutePath), false, `legacy file still exists: ${relativePath}`);
  }
});

test('workspace source no longer imports legacy auth aggregate paths', () => {
  const files = [];
  walk(path.join(REPO_ROOT, 'apps'), files);
  walk(path.join(REPO_ROOT, 'tools'), files);

  const findings = [];
  for (const filePath of files) {
    const content = fs.readFileSync(filePath, 'utf8');
    for (const segment of LEGACY_IMPORT_SEGMENTS) {
      if (content.includes(segment)) {
        findings.push(`${path.relative(REPO_ROOT, filePath)} -> ${segment}`);
      }
    }
  }

  assert.deepEqual(findings, []);
});
