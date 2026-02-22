const test = require('node:test');
const assert = require('node:assert/strict');
const {
  resolveContractVersionForInvocation,
  resolveVersionByStrategy
} = require('../src/modules/integration');

test('resolveContractVersionForInvocation resolves active contract with default strategy', () => {
  const resolved = resolveContractVersionForInvocation({
    integration: {
      lifecycle_status: 'active'
    },
    activeContract: {
      contract_version: 'v2026.02.22',
      status: 'active'
    },
    direction: 'outbound'
  });

  assert.deepEqual(resolved, {
    contract_version: 'v2026.02.22',
    resolved_by: 'strategy:active',
    direction: 'outbound',
    lifecycle_status: 'active',
    invocation_allowed: true
  });
});

test('resolveContractVersionForInvocation blocks production invocation when lifecycle is not active', () => {
  assert.throws(
    () =>
      resolveContractVersionForInvocation({
        integration: {
          lifecycle_status: 'paused'
        },
        activeContract: {
          contract_version: 'v2026.02.22',
          status: 'active'
        },
        direction: 'outbound'
      }),
    (error) =>
      error?.code === 'ERR_INTEGRATION_INVOCATION_BLOCKED'
      && error?.reason === 'lifecycle_not_active'
      && error?.lifecycleStatus === 'paused'
  );
});

test('resolveContractVersionForInvocation fails closed on strategy resolved contract mismatch', () => {
  assert.throws(
    () =>
      resolveContractVersionForInvocation({
        integration: {
          lifecycle_status: 'active',
          version_strategy: 'header:x-contract-version'
        },
        activeContract: {
          contract_version: 'v2026.02.22',
          status: 'active'
        },
        requestHeaders: {
          'x-contract-version': 'v2026.03.01'
        },
        direction: 'inbound'
      }),
    (error) =>
      error?.code === 'ERR_INTEGRATION_CONTRACT_VERSION_MISMATCH'
      && error?.expectedContractVersion === 'v2026.02.22'
      && error?.resolvedContractVersion === 'v2026.03.01'
      && error?.resolvedBy === 'strategy:header'
  );
});

test('resolveVersionByStrategy prefers explicit requested contract version over strategy', () => {
  const resolved = resolveVersionByStrategy({
    versionStrategy: 'query:contract_version',
    requestedContractVersion: 'v2026.03.15',
    requestQuery: {
      contract_version: 'v2026.04.01'
    },
    activeContractVersion: 'v2026.02.22'
  });

  assert.deepEqual(resolved, {
    resolvedContractVersion: 'v2026.03.15',
    resolvedBy: 'request:explicit'
  });
});

test('resolveVersionByStrategy fails closed when explicit requested contract version is malformed', () => {
  assert.throws(
    () =>
      resolveVersionByStrategy({
        requestedContractVersion: ' v2026.03.15',
        activeContractVersion: 'v2026.02.22'
      }),
    (error) =>
      error?.code === 'ERR_INTEGRATION_CONTRACT_STRATEGY_INVALID'
      && error?.reason === 'requested_version_invalid'
  );
});

test('resolveContractVersionForInvocation fails closed when version_strategy is malformed', () => {
  assert.throws(
    () =>
      resolveContractVersionForInvocation({
        integration: {
          lifecycle_status: 'active',
          version_strategy: 'header'
        },
        activeContract: {
          contract_version: 'v2026.02.22',
          status: 'active'
        },
        requestHeaders: {
          'x-contract-version': 'v2026.02.22'
        },
        direction: 'outbound'
      }),
    (error) =>
      error?.code === 'ERR_INTEGRATION_CONTRACT_STRATEGY_INVALID'
      && error?.reason === 'strategy_malformed'
  );
});

test('resolveContractVersionForInvocation fails closed when header strategy value is missing', () => {
  assert.throws(
    () =>
      resolveContractVersionForInvocation({
        integration: {
          lifecycle_status: 'active',
          version_strategy: 'header:x-contract-version'
        },
        activeContract: {
          contract_version: 'v2026.02.22',
          status: 'active'
        },
        requestHeaders: {},
        direction: 'outbound'
      }),
    (error) =>
      error?.code === 'ERR_INTEGRATION_CONTRACT_STRATEGY_INVALID'
      && error?.reason === 'strategy_header_missing'
  );
});

test('resolveVersionByStrategy fails closed when strategy type is unsupported', () => {
  assert.throws(
    () =>
      resolveVersionByStrategy({
        versionStrategy: 'cookie:x-contract-version',
        activeContractVersion: 'v2026.02.22'
      }),
    (error) =>
      error?.code === 'ERR_INTEGRATION_CONTRACT_STRATEGY_INVALID'
      && error?.reason === 'strategy_unsupported'
  );
});
