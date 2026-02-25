const test = require('node:test');
const assert = require('node:assert/strict');
const {
  PROTECTED_PLATFORM_ROLE_IDS
} = require('../../src/domains/platform/settings/role/constants');
const {
  PROTECTED_TENANT_ROLE_IDS
} = require('../../src/domains/tenant/settings/role/constants');
const {
  PLATFORM_INTEGRATION_LIFECYCLE_STATUSES
} = require('../../src/domains/platform/config/integration/constants');
const {
  PLATFORM_INTEGRATION_CONTRACT_STATUS_ENUM
} = require('../../src/domains/platform/config/integration-contract/constants');
const {
  PLATFORM_INTEGRATION_RECOVERY_STATUS_ENUM
} = require('../../src/domains/platform/config/integration-recovery/constants');
const {
  PLATFORM_INTEGRATION_FREEZE_STATUS_ENUM
} = require('../../src/domains/platform/config/integration-freeze/constants');

const assertUniqueStringEnum = (values = [], label = '') => {
  assert.ok(Array.isArray(values), `${label} must be an array`);
  assert.ok(values.length > 0, `${label} must not be empty`);
  const normalizedValues = values.map((value) => String(value || '').trim());
  normalizedValues.forEach((value) => {
    assert.ok(value.length > 0, `${label} must not contain empty values`);
  });
  assert.equal(
    new Set(normalizedValues).size,
    normalizedValues.length,
    `${label} must not contain duplicate values`
  );
};

test('platform protected role ids stay immutable and complete', () => {
  assert.deepEqual(PROTECTED_PLATFORM_ROLE_IDS, ['sys_admin']);
});

test('tenant protected role ids stay immutable and complete', () => {
  assert.deepEqual(PROTECTED_TENANT_ROLE_IDS, [
    'tenant_owner',
    'tenant_admin',
    'tenant_member'
  ]);
});

test('platform integration lifecycle statuses stay stable', () => {
  assert.deepEqual(PLATFORM_INTEGRATION_LIFECYCLE_STATUSES, [
    'draft',
    'active',
    'paused',
    'retired'
  ]);
  assertUniqueStringEnum(
    PLATFORM_INTEGRATION_LIFECYCLE_STATUSES,
    'PLATFORM_INTEGRATION_LIFECYCLE_STATUSES'
  );
});

test('platform integration contract statuses stay stable', () => {
  assert.deepEqual(PLATFORM_INTEGRATION_CONTRACT_STATUS_ENUM, [
    'candidate',
    'active',
    'deprecated',
    'retired'
  ]);
  assertUniqueStringEnum(
    PLATFORM_INTEGRATION_CONTRACT_STATUS_ENUM,
    'PLATFORM_INTEGRATION_CONTRACT_STATUS_ENUM'
  );
});

test('platform integration recovery statuses stay stable', () => {
  assert.deepEqual(PLATFORM_INTEGRATION_RECOVERY_STATUS_ENUM, [
    'pending',
    'retrying',
    'succeeded',
    'failed',
    'dlq',
    'replayed'
  ]);
  assertUniqueStringEnum(
    PLATFORM_INTEGRATION_RECOVERY_STATUS_ENUM,
    'PLATFORM_INTEGRATION_RECOVERY_STATUS_ENUM'
  );
});

test('platform integration freeze statuses stay stable', () => {
  assert.deepEqual(PLATFORM_INTEGRATION_FREEZE_STATUS_ENUM, [
    'active',
    'released'
  ]);
  assertUniqueStringEnum(
    PLATFORM_INTEGRATION_FREEZE_STATUS_ENUM,
    'PLATFORM_INTEGRATION_FREEZE_STATUS_ENUM'
  );
});
