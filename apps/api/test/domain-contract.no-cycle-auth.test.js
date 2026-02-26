'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  runAuthImportCycleCheck
} = require('../../../tools/domain-contract/check-auth-import-cycles');

const REPO_ROOT = require('node:path').resolve(__dirname, '../../..');

test('auth import graph has no cycles', () => {
  const result = runAuthImportCycleCheck({ repoRoot: REPO_ROOT });
  assert.equal(result.ok, true, result.errors.join('\n'));
});
