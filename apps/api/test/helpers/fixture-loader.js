'use strict';

const { readFileSync } = require('node:fs');
const { resolve } = require('node:path');

const FIXTURE_ROOT = resolve(__dirname, '..', 'fixtures');

const deepFreeze = (value) => {
  if (!value || typeof value !== 'object') {
    return value;
  }
  if (Object.isFrozen(value)) {
    return value;
  }
  Object.freeze(value);
  if (Array.isArray(value)) {
    value.forEach((entry) => deepFreeze(entry));
    return value;
  }
  for (const key of Object.keys(value)) {
    deepFreeze(value[key]);
  }
  return value;
};

const loadJsonFixture = (relativePath) => {
  const normalizedRelativePath = String(relativePath || '').trim();
  if (!normalizedRelativePath) {
    throw new TypeError('relativePath is required');
  }
  const absolutePath = resolve(FIXTURE_ROOT, normalizedRelativePath);
  const content = readFileSync(absolutePath, 'utf8');
  return deepFreeze(JSON.parse(content));
};

const stableSortObjectKeys = (value) => {
  if (Array.isArray(value)) {
    return value.map((entry) => stableSortObjectKeys(entry));
  }
  if (!value || typeof value !== 'object') {
    return value;
  }
  const sorted = {};
  for (const key of Object.keys(value).sort()) {
    sorted[key] = stableSortObjectKeys(value[key]);
  }
  return sorted;
};

const stableStringify = (value) =>
  JSON.stringify(stableSortObjectKeys(value), null, 2);

module.exports = {
  FIXTURE_ROOT,
  loadJsonFixture,
  stableStringify
};
