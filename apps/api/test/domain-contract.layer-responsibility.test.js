'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const {
  runLayerResponsibilityCheck
} = require('../../../tools/domain-contract/check-layer-responsibilities');

const REPO_ROOT = path.resolve(__dirname, '../../..');

test('route/service/store layer responsibilities are preserved', () => {
  const result = runLayerResponsibilityCheck({ repoRoot: REPO_ROOT });
  assert.equal(result.ok, true, result.errors.join('\n'));
});
