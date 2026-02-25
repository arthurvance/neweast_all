const test = require('node:test');
const assert = require('node:assert/strict');
const {
  transformDomainFileByBoundary
} = require('../../../tools/codemods/split-domain-file-by-boundary');

const SAMPLE_CONTENT = `
const { log } = require('../../common/logger');

const MAX_NAME_LENGTH = 64;
const VALID_STATUSES = new Set(['active', 'disabled']);

const userErrors = {
  invalidPayload: () => new Error('USR-400-INVALID-PAYLOAD'),
  invalidStatus: () => new Error('USR-400-INVALID-STATUS')
};

const isPlainObject = (candidate) =>
  candidate !== null
  && typeof candidate === 'object'
  && !Array.isArray(candidate);

const normalizeName = (value) => {
  if (typeof value !== 'string') {
    return '';
  }
  const normalized = value.trim();
  if (!normalized || normalized.length > MAX_NAME_LENGTH) {
    throw userErrors.invalidPayload();
  }
  return normalized;
};

const parsePayload = (payload) => {
  if (!isPlainObject(payload)) {
    throw userErrors.invalidPayload();
  }
  const name = normalizeName(payload.name);
  const status = String(payload.status || '').trim().toLowerCase();
  if (!VALID_STATUSES.has(status)) {
    throw userErrors.invalidStatus();
  }
  return { name, status };
};

const createDemoService = () => {
  const createUser = (payload) => parsePayload(payload);
  return { createUser };
};

module.exports = {
  createDemoService
};
`;

test('split-domain-file-by-boundary extracts semantic boundary files and rewrites main import surface', () => {
  const result = transformDomainFileByBoundary({
    filePath: '/repo/apps/api/src/domains/platform/settings/user/service/index.js',
    content: SAMPLE_CONTENT,
    maxLoc: 30,
    minBoundaryLoc: 1
  });

  assert.equal(result.changed, true);
  assert.ok(result.boundaryOutputs.length >= 1);
  assert.match(result.mainContent, /require\('\.\/service\.[a-z]+'\)/);
  assert.doesNotMatch(result.mainContent, /const parsePayload =/);
  assert.doesNotMatch(result.mainContent, /const normalizeName =/);

  const mergedBoundary = result.boundaryOutputs[0];
  assert.ok(mergedBoundary);
  assert.match(mergedBoundary.content, /module\.exports = \{/);
  assert.match(mergedBoundary.content, /parsePayload/);
  assert.match(mergedBoundary.content, /normalizeName/);
});

test('split-domain-file-by-boundary keeps require declarations as imports instead of extracted exports', () => {
  const mergeSampleContent = `
const {
  USER_TABLE,
  USER_FIELDS
} = require('./constants');

const normalizeName = (value) => String(value || '').trim();

const parsePayload = (payload = {}) => ({
  name: normalizeName(payload.name),
  table: USER_TABLE,
  fields: USER_FIELDS
});

const createDemoService = () => ({ parsePayload });

module.exports = {
  createDemoService
};
`;

  const result = transformDomainFileByBoundary({
    filePath: '/repo/apps/api/src/domains/platform/settings/user/service/index.js',
    content: mergeSampleContent,
    maxLoc: 8,
    minBoundaryLoc: 1
  });

  assert.equal(result.changed, true);
  assert.ok(result.boundaryOutputs.length >= 1);

  const mergedBoundary = result.boundaryOutputs[0];
  const dedupedRequireMatches = mergedBoundary.content.match(/require\('\.\/constants'\)/g) || [];
  assert.equal(dedupedRequireMatches.length, 1);
  assert.match(mergedBoundary.content, /normalizeName/);
  assert.match(mergedBoundary.content, /parsePayload/);
  assert.equal(mergedBoundary.exportedNames.includes('USER_TABLE'), false);
  assert.equal(mergedBoundary.exportedNames.includes('USER_FIELDS'), false);
});

test('split-domain-file-by-boundary reports best-practice issues when min boundary LOC is too strict', () => {
  const result = transformDomainFileByBoundary({
    filePath: '/repo/apps/api/src/domains/platform/settings/user/service/index.js',
    content: SAMPLE_CONTENT,
    maxLoc: 20,
    minBoundaryLoc: 80
  });

  assert.equal(result.changed, true);
  assert.ok(result.bestPracticeIssues.length > 0);
  assert.match(
    result.bestPracticeIssues.join('\n'),
    /too small|main file still oversized|did not decrease/
  );
});

test('split-domain-file-by-boundary does not truncate exported declaration prefix after extraction', () => {
  const overlapSampleContent = `
const A = 1;

const normalizeA = () => A;

const normalizeB = () => normalizeA();

const parsePayload = (payload = {}) => ({
  value: normalizeB(),
  payload
});

const createStableService = () => ({
  parsePayload
});

module.exports = {
  createStableService
};
`;

  const result = transformDomainFileByBoundary({
    filePath: '/repo/apps/api/src/domains/platform/settings/user/service/index.js',
    content: overlapSampleContent,
    maxLoc: 5,
    minBoundaryLoc: 1
  });

  assert.equal(result.changed, true);
  assert.match(result.mainContent, /const createStableService =/);
  assert.doesNotMatch(result.mainContent, /\nt createStableService =/);
});
