const test = require('node:test');
const assert = require('node:assert/strict');
const { createRouteHandlers } = require('../src/http-routes');
const { readConfig } = require('../src/config/env');

const dependencyProbe = async () => ({
  db: { ok: true, detail: 'db ok' },
  redis: { ok: true, detail: 'redis ok' }
});

test('createRouteHandlers exposes authIdempotencyStore when store contract is complete', () => {
  const store = {
    claimOrRead: async () => ({ action: 'retry' }),
    read: async () => null,
    resolve: async () => true,
    releasePending: async () => true
  };

  const handlers = createRouteHandlers(
    readConfig({ ALLOW_MOCK_BACKENDS: 'true' }),
    {
      dependencyProbe: async () => ({
        db: { ok: true, detail: 'db ok' },
        redis: { ok: true, detail: 'redis ok' }
      }),
      authService: {},
      authIdempotencyStore: store
    }
  );

  assert.equal(handlers.authIdempotencyStore, store);
});

test('createRouteHandlers uses default dependency probe when dependencyProbe is omitted', async () => {
  const handlers = createRouteHandlers(
    readConfig({ ALLOW_MOCK_BACKENDS: 'true' }),
    {
      authService: {}
    }
  );

  const health = await handlers.health('req-default-probe');
  assert.equal(health.ok, true);
  assert.equal(health.dependencies.db.ok, true);
  assert.equal(health.dependencies.redis.ok, true);

  const smoke = await handlers.smoke('req-default-probe');
  assert.equal(smoke.ok, true);
  assert.equal(smoke.dependencies.db.ok, true);
  assert.equal(smoke.dependencies.redis.ok, true);
});

test('createRouteHandlers degrades health response when dependencyProbe throws', async () => {
  const handlers = createRouteHandlers(
    readConfig({ ALLOW_MOCK_BACKENDS: 'true' }),
    {
      dependencyProbe: async () => {
        throw new Error('probe boom');
      },
      authService: {}
    }
  );

  const health = await handlers.health('req-probe-throws');
  assert.equal(health.ok, false);
  assert.equal(health.dependencies.db.ok, false);
  assert.equal(health.dependencies.redis.ok, false);
  assert.equal(health.dependencies.db.mode, 'probe-error');
  assert.equal(health.dependencies.redis.mode, 'probe-error');
  assert.equal(health.dependencies.db.detail, 'dependency probe failed');
  assert.equal(health.dependencies.redis.detail, 'dependency probe failed');
});

test('createRouteHandlers normalizes malformed dependencyProbe payloads as degraded', async () => {
  const handlers = createRouteHandlers(
    readConfig({ ALLOW_MOCK_BACKENDS: 'true' }),
    {
      dependencyProbe: async () => ({
        db: {
          ok: true,
          mode: 'custom',
          detail: 'db ok'
        }
      }),
      authService: {}
    }
  );

  const health = await handlers.health('req-probe-malformed');
  assert.equal(health.ok, false);
  assert.equal(health.dependencies.db.ok, true);
  assert.equal(health.dependencies.redis.ok, false);
  assert.equal(health.dependencies.redis.mode, 'redis-probe');
  assert.equal(
    health.dependencies.redis.detail,
    'dependency probe result missing'
  );
});

test('createRouteHandlers wires platform integration handlers with provided service', async () => {
  const integrationCalls = [];
  const platformIntegrationService = {
    listIntegrations: async (payload) => {
      integrationCalls.push({ method: 'list', payload });
      return { request_id: payload.requestId, integrations: [] };
    },
    getIntegration: async (payload) => {
      integrationCalls.push({ method: 'get', payload });
      return {
        integration_id: payload.integrationId,
        request_id: payload.requestId
      };
    },
    createIntegration: async (payload) => {
      integrationCalls.push({ method: 'create', payload });
      return {
        integration_id: 'integration-created',
        request_id: payload.requestId
      };
    },
    updateIntegration: async (payload) => {
      integrationCalls.push({ method: 'update', payload });
      return {
        integration_id: payload.integrationId,
        request_id: payload.requestId
      };
    },
    changeIntegrationLifecycle: async (payload) => {
      integrationCalls.push({ method: 'lifecycle', payload });
      return {
        integration_id: payload.integrationId,
        previous_status: 'draft',
        current_status: payload.payload.status,
        request_id: payload.requestId
      };
    }
  };

  const handlers = createRouteHandlers(
    readConfig({ ALLOW_MOCK_BACKENDS: 'true' }),
    {
      dependencyProbe,
      authService: {},
      platformIntegrationService
    }
  );

  const listed = await handlers.platformListIntegrations(
    'req-http-routes-platform-integration-list',
    'Bearer fake-token',
    { page: '1', page_size: '20' },
    null
  );
  assert.deepEqual(listed, {
    request_id: 'req-http-routes-platform-integration-list',
    integrations: []
  });

  const created = await handlers.platformCreateIntegration(
    'req-http-routes-platform-integration-create',
    'Bearer fake-token',
    {
      code: 'HTTP_ROUTES_INTEGRATION',
      name: 'HTTP Routes Integration',
      direction: 'outbound',
      protocol: 'https',
      auth_mode: 'hmac'
    },
    null,
    '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'
  );
  assert.equal(created.integration_id, 'integration-created');
  assert.equal(created.request_id, 'req-http-routes-platform-integration-create');
  assert.equal(integrationCalls.length, 2);
  assert.equal(integrationCalls[0].method, 'list');
  assert.equal(integrationCalls[1].method, 'create');
  assert.equal(handlers._internals.platformIntegrationService, platformIntegrationService);
});

test('createRouteHandlers enforces shared auth service identity for platformIntegrationService', () => {
  assert.throws(
    () =>
      createRouteHandlers(
        readConfig({ ALLOW_MOCK_BACKENDS: 'true' }),
        {
          authService: { serviceName: 'primary-auth' },
          platformIntegrationService: {
            listIntegrations: async () => ({}),
            getIntegration: async () => ({}),
            createIntegration: async () => ({}),
            updateIntegration: async () => ({}),
            changeIntegrationLifecycle: async () => ({}),
            _internals: {
              authService: { serviceName: 'other-auth' }
            }
          }
        }
      ),
    /authService and platformIntegrationService to share the same authService instance/
  );
});

test('createRouteHandlers wires platform integration contract handlers with provided service', async () => {
  const contractCalls = [];
  const platformIntegrationContractService = {
    listContracts: async (payload) => {
      contractCalls.push({ method: 'list', payload });
      return {
        integration_id: payload.integrationId,
        contracts: [],
        active_contracts: [],
        request_id: payload.requestId
      };
    },
    createContract: async (payload) => {
      contractCalls.push({ method: 'create', payload });
      return {
        integration_id: payload.integrationId,
        contract_type: payload.payload.contract_type,
        contract_version: payload.payload.contract_version,
        request_id: payload.requestId
      };
    },
    evaluateCompatibility: async (payload) => {
      contractCalls.push({ method: 'compatibility', payload });
      return {
        integration_id: payload.integrationId,
        contract_type: payload.payload.contract_type,
        baseline_version: payload.payload.baseline_version,
        candidate_version: payload.payload.candidate_version,
        evaluation_result: 'compatible',
        breaking_change_count: 0,
        request_id: payload.requestId,
        checked_at: '2026-02-22T00:00:00.000Z'
      };
    },
    checkConsistency: async (payload) => {
      contractCalls.push({ method: 'consistency', payload });
      return {
        integration_id: payload.integrationId,
        contract_type: payload.payload.contract_type,
        baseline_version: payload.payload.baseline_version,
        candidate_version: payload.payload.candidate_version,
        check_result: 'passed',
        blocking: false,
        failure_reason: null,
        breaking_change_count: 0,
        diff_summary: {
          breaking_changes: []
        },
        request_id: payload.requestId,
        checked_at: '2026-02-22T00:00:00.000Z'
      };
    },
    activateContract: async (payload) => {
      contractCalls.push({ method: 'activate', payload });
      return {
        integration_id: payload.integrationId,
        contract_type: payload.payload.contract_type,
        contract_version: payload.contractVersion,
        status: 'active',
        previous_status: 'candidate',
        current_status: 'active',
        request_id: payload.requestId
      };
    }
  };

  const handlers = createRouteHandlers(
    readConfig({ ALLOW_MOCK_BACKENDS: 'true' }),
    {
      dependencyProbe,
      authService: {},
      platformIntegrationContractService
    }
  );

  const listed = await handlers.platformListIntegrationContracts(
    'req-http-routes-platform-integration-contract-list',
    'Bearer fake-token',
    { integration_id: 'erp-outbound-main' },
    {},
    null
  );
  assert.equal(listed.integration_id, 'erp-outbound-main');
  assert.equal(contractCalls[0].method, 'list');

  const created = await handlers.platformCreateIntegrationContract(
    'req-http-routes-platform-integration-contract-create',
    'Bearer fake-token',
    { integration_id: 'erp-outbound-main' },
    {
      contract_type: 'openapi',
      contract_version: 'v2026.02.22',
      schema_ref: 's3://contracts/erp/v2026.02.22/openapi.json',
      schema_checksum: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    },
    null,
    '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'
  );
  assert.equal(created.contract_version, 'v2026.02.22');
  assert.equal(contractCalls[1].method, 'create');

  const checked = await handlers.platformEvaluateIntegrationContractCompatibility(
    'req-http-routes-platform-integration-contract-compatibility',
    'Bearer fake-token',
    { integration_id: 'erp-outbound-main' },
    {
      contract_type: 'openapi',
      baseline_version: 'v2026.01.15',
      candidate_version: 'v2026.02.22'
    },
    null,
    '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'
  );
  assert.equal(checked.evaluation_result, 'compatible');
  assert.equal(contractCalls[2].method, 'compatibility');

  const consistency = await handlers.platformCheckIntegrationContractConsistency(
    'req-http-routes-platform-integration-contract-consistency',
    'Bearer fake-token',
    { integration_id: 'erp-outbound-main' },
    {
      contract_type: 'openapi',
      baseline_version: 'v2026.01.15',
      candidate_version: 'v2026.02.22'
    },
    null,
    '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'
  );
  assert.equal(consistency.check_result, 'passed');
  assert.equal(contractCalls[3].method, 'consistency');

  const activated = await handlers.platformActivateIntegrationContract(
    'req-http-routes-platform-integration-contract-activate',
    'Bearer fake-token',
    {
      integration_id: 'erp-outbound-main',
      contract_version: 'v2026.02.22'
    },
    {
      contract_type: 'openapi'
    },
    null,
    '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'
  );
  assert.equal(activated.current_status, 'active');
  assert.equal(contractCalls[4].method, 'activate');
  assert.equal(
    handlers._internals.platformIntegrationContractService,
    platformIntegrationContractService
  );
});

test('createRouteHandlers enforces shared auth service identity for platformIntegrationContractService', () => {
  assert.throws(
    () =>
      createRouteHandlers(
        readConfig({ ALLOW_MOCK_BACKENDS: 'true' }),
        {
          authService: { serviceName: 'primary-auth' },
          platformIntegrationContractService: {
            listContracts: async () => ({}),
            createContract: async () => ({}),
            evaluateCompatibility: async () => ({}),
            checkConsistency: async () => ({}),
            activateContract: async () => ({}),
            _internals: {
              authService: { serviceName: 'other-auth' }
            }
          }
        }
      ),
    /authService and platformIntegrationContractService to share the same authService instance/
  );
});

test('createRouteHandlers wires platform integration freeze handlers with auth-backed service', async () => {
  const freezeCalls = [];
  const now = '2026-02-22T00:00:00.000Z';
  let activeFreeze = null;
  let latestFreeze = null;
  const authService = {
    authorizeRoute: async ({
      requestId,
      permissionCode,
      scope
    }) => {
      freezeCalls.push({
        method: 'authorizeRoute',
        requestId,
        permissionCode,
        scope
      });
      return {
        user_id: 'platform-freeze-operator',
        session_id: 'session-freeze-operator'
      };
    },
    _internals: {
      authStore: {
        findActivePlatformIntegrationFreeze: async () => {
          freezeCalls.push({ method: 'findActive' });
          return activeFreeze;
        },
        findLatestPlatformIntegrationFreeze: async () => {
          freezeCalls.push({ method: 'findLatest' });
          return latestFreeze;
        },
        activatePlatformIntegrationFreeze: async (payload) => {
          freezeCalls.push({ method: 'activate', payload });
          const freezeRecord = {
            freeze_id: 'release-window-http-routes-001',
            status: 'active',
            freeze_reason: payload.freezeReason,
            rollback_reason: null,
            frozen_at: now,
            released_at: null,
            frozen_by_user_id: payload.operatorUserId,
            released_by_user_id: null,
            request_id: payload.requestId,
            traceparent: payload.traceparent || null,
            created_at: now,
            updated_at: now
          };
          activeFreeze = freezeRecord;
          latestFreeze = freezeRecord;
          return freezeRecord;
        },
        releasePlatformIntegrationFreeze: async (payload) => {
          freezeCalls.push({ method: 'release', payload });
          const releasedRecord = {
            freeze_id: activeFreeze?.freeze_id || 'release-window-http-routes-001',
            status: 'released',
            freeze_reason: activeFreeze?.freeze_reason || 'release window opened',
            rollback_reason: payload.rollbackReason,
            frozen_at: activeFreeze?.frozen_at || now,
            released_at: now,
            frozen_by_user_id: activeFreeze?.frozen_by_user_id || payload.operatorUserId,
            released_by_user_id: payload.operatorUserId,
            request_id: payload.requestId,
            traceparent: payload.traceparent || null,
            created_at: activeFreeze?.created_at || now,
            updated_at: now,
            previous_status: 'active',
            current_status: 'released'
          };
          activeFreeze = null;
          latestFreeze = releasedRecord;
          return releasedRecord;
        }
      }
    }
  };

  const handlers = createRouteHandlers(
    readConfig({ ALLOW_MOCK_BACKENDS: 'true' }),
    {
      dependencyProbe,
      authService
    }
  );

  const initialStatus = await handlers.platformGetIntegrationFreezeStatus(
    'req-http-routes-platform-integration-freeze-status-initial',
    'Bearer fake-token',
    null
  );
  assert.equal(initialStatus.frozen, false);
  assert.equal(initialStatus.active_freeze, null);
  assert.equal(initialStatus.latest_freeze, null);

  const activated = await handlers.platformActivateIntegrationFreeze(
    'req-http-routes-platform-integration-freeze-activate',
    'Bearer fake-token',
    {
      freeze_reason: 'release window opened'
    },
    null,
    '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'
  );
  assert.equal(activated.freeze_id, 'release-window-http-routes-001');
  assert.equal(activated.status, 'active');

  const released = await handlers.platformReleaseIntegrationFreeze(
    'req-http-routes-platform-integration-freeze-release',
    'Bearer fake-token',
    {
      rollback_reason: 'release completed'
    },
    null,
    '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'
  );
  assert.equal(released.freeze_id, 'release-window-http-routes-001');
  assert.equal(released.status, 'released');
  assert.equal(released.released, true);

  assert.ok(freezeCalls.some((entry) => entry.method === 'findActive'));
  assert.ok(freezeCalls.some((entry) => entry.method === 'findLatest'));
  assert.ok(
    freezeCalls.some(
      (entry) =>
        entry.method === 'activate'
        && entry.payload.requestId === 'req-http-routes-platform-integration-freeze-activate'
        && entry.payload.traceparent
    )
  );
  assert.ok(
    freezeCalls.some(
      (entry) =>
        entry.method === 'release'
        && entry.payload.rollbackReason === 'release completed'
        && entry.payload.requestId === 'req-http-routes-platform-integration-freeze-release'
    )
  );
  assert.equal(typeof handlers._internals.platformIntegrationFreezeService, 'object');
});

test('createRouteHandlers wires platform integration recovery handlers with provided service', async () => {
  const recoveryCalls = [];
  const platformIntegrationRecoveryService = {
    listRecoveryQueue: async (payload) => {
      recoveryCalls.push({ method: 'list', payload });
      return {
        integration_id: payload.integrationId,
        lifecycle_status: 'active',
        status: payload.query.status || null,
        limit: Number(payload.query.limit || 50),
        queue: [],
        request_id: payload.requestId
      };
    },
    replayRecoveryQueueItem: async (payload) => {
      recoveryCalls.push({ method: 'replay', payload });
      return {
        recovery: {
          recovery_id: payload.recoveryId,
          integration_id: payload.integrationId,
          contract_type: 'openapi',
          contract_version: 'v2026.02.22',
          request_id: 'req-source',
          traceparent: null,
          idempotency_key: null,
          attempt_count: 1,
          max_attempts: 5,
          next_retry_at: '2026-02-22T00:00:00.000Z',
          last_attempt_at: '2026-02-22T00:00:00.000Z',
          status: 'replayed',
          failure_code: null,
          failure_detail: null,
          last_http_status: null,
          retryable: true,
          payload_snapshot: { ok: true },
          response_snapshot: null,
          created_by_user_id: null,
          updated_by_user_id: 'operator',
          created_at: '2026-02-22T00:00:00.000Z',
          updated_at: '2026-02-22T00:00:00.000Z'
        },
        previous_status: 'dlq',
        current_status: 'replayed',
        replayed: true,
        request_id: payload.requestId
      };
    }
  };

  const handlers = createRouteHandlers(
    readConfig({ ALLOW_MOCK_BACKENDS: 'true' }),
    {
      dependencyProbe,
      authService: {},
      platformIntegrationRecoveryService
    }
  );

  const listed = await handlers.platformListIntegrationRecoveryQueue(
    'req-http-routes-platform-integration-recovery-list',
    'Bearer fake-token',
    { integration_id: 'erp-outbound-main' },
    { status: 'dlq', limit: '20' },
    null
  );
  assert.equal(listed.integration_id, 'erp-outbound-main');
  assert.equal(recoveryCalls[0].method, 'list');

  const replayed = await handlers.platformReplayIntegrationRecoveryQueueItem(
    'req-http-routes-platform-integration-recovery-replay',
    'Bearer fake-token',
    {
      integration_id: 'erp-outbound-main',
      recovery_id: 'recovery-001'
    },
    {
      reason: 'manual replay'
    },
    null,
    '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'
  );
  assert.equal(replayed.current_status, 'replayed');
  assert.equal(recoveryCalls[1].method, 'replay');
  assert.equal(
    handlers._internals.platformIntegrationRecoveryService,
    platformIntegrationRecoveryService
  );
});

test('createRouteHandlers enforces shared auth service identity for platformIntegrationRecoveryService', () => {
  assert.throws(
    () =>
      createRouteHandlers(
        readConfig({ ALLOW_MOCK_BACKENDS: 'true' }),
        {
          authService: { serviceName: 'primary-auth' },
          platformIntegrationRecoveryService: {
            listRecoveryQueue: async () => ({}),
            replayRecoveryQueueItem: async () => ({}),
            _internals: {
              authService: { serviceName: 'other-auth' }
            }
          }
        }
      ),
    /authService and platformIntegrationRecoveryService to share the same authService instance/
  );
});
