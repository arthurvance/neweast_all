'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const {
  runCapabilityBoundaryCheck
} = require('../../../tools/domain-contract/check-capability-boundaries');

const REPO_ROOT = path.resolve(__dirname, '../../..');

test('auth capability boundaries satisfy C1-C10 guard assertions', () => {
  const result = runCapabilityBoundaryCheck({ repoRoot: REPO_ROOT });
  assert.equal(result.ok, true, result.errors.join('\n'));
});
