const test = require('node:test');
const assert = require('node:assert/strict');
const { createRouteHandlers } = require('../src/http-routes');
const { createAuthService } = require('../src/shared-kernel/auth/create-auth-service');
const { dispatchApiRoute } = require('../src/server');
const { readConfig } = require('../src/config/env');

const config = readConfig({ ALLOW_MOCK_BACKENDS: 'true' });
const dependencyProbe = async () => ({
  db: { ok: true },
  redis: { ok: true }
});

const OPERATOR_PHONE = '13835550131';
const VIEWER_PHONE = '13835550132';

const createHarness = () => {
  const authService = createAuthService({
    seedUsers: [
      {
        id: 'platform-integration-recovery-operator',
        phone: OPERATOR_PHONE,
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: [
          {
            roleId: 'platform-integration-recovery-admin',
            status: 'active',
            permission: {
              canViewUserManagement: true,
              canOperateUserManagement: true,
              canViewTenantManagement: false,
              canOperateTenantManagement: false
            }
          }
        ]
      },
      {
        id: 'platform-integration-recovery-viewer',
        phone: VIEWER_PHONE,
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: [
          {
            roleId: 'platform-integration-recovery-read-only',
            status: 'active',
            permission: {
              canViewUserManagement: true,
              canOperateUserManagement: false,
              canViewTenantManagement: false,
              canOperateTenantManagement: false
            }
          }
        ]
      }
    ]
  });

  const handlers = createRouteHandlers(config, {
    dependencyProbe,
    authService
  });

  return {
    authService,
    handlers
  };
};

const loginByPhone = async ({ authService, phone, requestId }) =>
  authService.login({
    requestId,
    phone,
    password: 'Passw0rd!',
    entryDomain: 'platform'
  });

const createIntegration = async ({
  handlers,
  accessToken,
  integrationId,
  requestId
}) =>
  dispatchApiRoute({
    pathname: '/platform/integrations',
    method: 'POST',
    requestId,
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: {
      integration_id: integrationId,
      code: integrationId.toUpperCase(),
      name: '集成恢复治理测试集成',
      direction: 'outbound',
      protocol: 'https',
      auth_mode: 'hmac',
      lifecycle_status: 'active',
      lifecycle_reason: '用于恢复治理联调'
    },
    handlers
  });

const seedRecoveryQueueEntry = async ({
  authService,
  integrationId,
  recoveryId,
  requestId,
  status,
  attemptCount,
  maxAttempts = 5
}) => {
  const authStore = authService._internals.authStore;
  return authStore.upsertPlatformIntegrationRecoveryQueueEntry({
    recoveryId,
    integrationId,
    contractType: 'openapi',
    contractVersion: 'v2026.02.22',
    requestId,
    traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01',
    idempotencyKey: `idem-${recoveryId}`,
    attemptCount,
    maxAttempts,
    nextRetryAt: status === 'pending' ? '2026-02-22T00:00:00.000Z' : null,
    lastAttemptAt: status === 'pending' ? null : '2026-02-22T00:00:00.000Z',
    status,
    failureCode: status === 'dlq' || status === 'failed' ? 'HTTP_500' : null,
    failureDetail: status === 'dlq' || status === 'failed' ? 'downstream timeout' : null,
    lastHttpStatus: status === 'dlq' || status === 'failed' ? 500 : null,
    retryable: status !== 'succeeded',
    payloadSnapshot: {
      order_id: 'ORDER-001'
    },
    responseSnapshot: status === 'dlq' || status === 'failed'
      ? {
        message: 'timeout'
      }
      : null,
    operatorUserId: 'platform-integration-recovery-operator'
  });
};

test('integration recovery queue list and replay succeed with audit trail', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-recovery-login-success'
  });
  const integrationId = 'integration-recovery-main';

  const integrationRoute = await createIntegration({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId,
    requestId: 'req-platform-integration-recovery-create-integration-success'
  });
  assert.equal(integrationRoute.status, 200);

  await seedRecoveryQueueEntry({
    authService: harness.authService,
    integrationId,
    recoveryId: 'recovery-dlq-001',
    requestId: 'req-source-recovery-dlq-001',
    status: 'dlq',
    attemptCount: 5
  });
  await seedRecoveryQueueEntry({
    authService: harness.authService,
    integrationId,
    recoveryId: 'recovery-pending-001',
    requestId: 'req-source-recovery-pending-001',
    status: 'pending',
    attemptCount: 1
  });

  const listRoute = await dispatchApiRoute({
    pathname: `/platform/integrations/${integrationId}/recovery/queue?status=dlq&limit=10`,
    method: 'GET',
    requestId: 'req-platform-integration-recovery-list-success',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers: harness.handlers
  });
  assert.equal(listRoute.status, 200);
  const listPayload = JSON.parse(listRoute.body);
  assert.equal(listPayload.integration_id, integrationId);
  assert.equal(listPayload.status, 'dlq');
  assert.equal(listPayload.limit, 10);
  assert.equal(listPayload.queue.length, 1);
  assert.equal(listPayload.queue[0].recovery_id, 'recovery-dlq-001');

  const replayRoute = await dispatchApiRoute({
    pathname: `/platform/integrations/${integrationId}/recovery/queue/recovery-dlq-001/replay`,
    method: 'POST',
    requestId: 'req-platform-integration-recovery-replay-success',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      reason: 'manual replay after downstream fix'
    },
    handlers: harness.handlers
  });
  assert.equal(replayRoute.status, 200);
  const replayPayload = JSON.parse(replayRoute.body);
  assert.equal(replayPayload.current_status, 'replayed');
  assert.equal(replayPayload.previous_status, 'dlq');
  assert.equal(replayPayload.replayed, true);
  assert.equal(replayPayload.recovery.recovery_id, 'recovery-dlq-001');

  const replayAuditRoute = await dispatchApiRoute({
    pathname: '/platform/audit/events?request_id=req-platform-integration-recovery-replay-success&event_type=platform.integration.recovery.replayed',
    method: 'GET',
    requestId: 'req-platform-integration-recovery-replay-audit-query',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers: harness.handlers
  });
  assert.equal(replayAuditRoute.status, 200);
  const replayAuditPayload = JSON.parse(replayAuditRoute.body);
  assert.equal(replayAuditPayload.total, 1);
});

test('integration recovery replay supports idempotent result replay for same key and payload', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-recovery-login-idempotency'
  });
  const integrationId = 'integration-recovery-idempotency';

  const integrationRoute = await createIntegration({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId,
    requestId: 'req-platform-integration-recovery-create-integration-idempotency'
  });
  assert.equal(integrationRoute.status, 200);

  await seedRecoveryQueueEntry({
    authService: harness.authService,
    integrationId,
    recoveryId: 'recovery-dlq-idem-001',
    requestId: 'req-source-recovery-dlq-idem-001',
    status: 'dlq',
    attemptCount: 5
  });

  const first = await dispatchApiRoute({
    pathname: `/platform/integrations/${integrationId}/recovery/queue/recovery-dlq-idem-001/replay`,
    method: 'POST',
    requestId: 'req-platform-integration-recovery-replay-idem-1',
    headers: {
      authorization: `Bearer ${login.access_token}`,
      'idempotency-key': 'idem-platform-integration-recovery-replay-001'
    },
    body: {
      reason: 'idempotent replay'
    },
    handlers: harness.handlers
  });
  const second = await dispatchApiRoute({
    pathname: `/platform/integrations/${integrationId}/recovery/queue/recovery-dlq-idem-001/replay`,
    method: 'POST',
    requestId: 'req-platform-integration-recovery-replay-idem-2',
    headers: {
      authorization: `Bearer ${login.access_token}`,
      'idempotency-key': 'idem-platform-integration-recovery-replay-001'
    },
    body: {
      reason: 'idempotent replay'
    },
    handlers: harness.handlers
  });
  assert.equal(first.status, 200);
  assert.equal(second.status, 200);
  const firstPayload = JSON.parse(first.body);
  const secondPayload = JSON.parse(second.body);
  assert.equal(firstPayload.current_status, 'replayed');
  assert.equal(secondPayload.current_status, firstPayload.current_status);
  assert.equal(
    secondPayload.recovery.recovery_id,
    firstPayload.recovery.recovery_id
  );
  assert.equal(
    secondPayload.request_id,
    'req-platform-integration-recovery-replay-idem-2'
  );

  const replayAuditRoute = await dispatchApiRoute({
    pathname: '/platform/audit/events?request_id=req-platform-integration-recovery-replay-idem-2&event_type=platform.integration.recovery.replayed',
    method: 'GET',
    requestId: 'req-platform-integration-recovery-replay-idem-audit-query',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers: harness.handlers
  });
  assert.equal(replayAuditRoute.status, 200);
  const replayAuditPayload = JSON.parse(replayAuditRoute.body);
  assert.equal(replayAuditPayload.total, 0);
});

test('integration recovery replay requires operate permission while list allows view permission', async () => {
  const harness = createHarness();
  const operatorLogin = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-recovery-login-operator-for-seed'
  });
  const viewerLogin = await loginByPhone({
    authService: harness.authService,
    phone: VIEWER_PHONE,
    requestId: 'req-platform-integration-recovery-login-viewer'
  });
  const integrationId = 'integration-recovery-permission';

  const integrationRoute = await createIntegration({
    handlers: harness.handlers,
    accessToken: operatorLogin.access_token,
    integrationId,
    requestId: 'req-platform-integration-recovery-create-integration-permission'
  });
  assert.equal(integrationRoute.status, 200);

  await seedRecoveryQueueEntry({
    authService: harness.authService,
    integrationId,
    recoveryId: 'recovery-dlq-002',
    requestId: 'req-source-recovery-dlq-002',
    status: 'dlq',
    attemptCount: 5
  });

  const viewerListRoute = await dispatchApiRoute({
    pathname: `/platform/integrations/${integrationId}/recovery/queue`,
    method: 'GET',
    requestId: 'req-platform-integration-recovery-viewer-list',
    headers: {
      authorization: `Bearer ${viewerLogin.access_token}`
    },
    handlers: harness.handlers
  });
  assert.equal(viewerListRoute.status, 200);

  const viewerReplayRoute = await dispatchApiRoute({
    pathname: `/platform/integrations/${integrationId}/recovery/queue/recovery-dlq-002/replay`,
    method: 'POST',
    requestId: 'req-platform-integration-recovery-viewer-replay-forbidden',
    headers: {
      authorization: `Bearer ${viewerLogin.access_token}`
    },
    body: {
      reason: 'viewer should not replay'
    },
    handlers: harness.handlers
  });
  assert.equal(viewerReplayRoute.status, 403);
  const payload = JSON.parse(viewerReplayRoute.body);
  assert.equal(payload.error_code, 'AUTH-403-FORBIDDEN');
});

test('integration recovery replay returns 409 for non-failed status', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-recovery-login-conflict'
  });
  const integrationId = 'integration-recovery-conflict';

  const integrationRoute = await createIntegration({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId,
    requestId: 'req-platform-integration-recovery-create-integration-conflict'
  });
  assert.equal(integrationRoute.status, 200);

  await seedRecoveryQueueEntry({
    authService: harness.authService,
    integrationId,
    recoveryId: 'recovery-pending-002',
    requestId: 'req-source-recovery-pending-002',
    status: 'pending',
    attemptCount: 1
  });

  const replayRoute = await dispatchApiRoute({
    pathname: `/platform/integrations/${integrationId}/recovery/queue/recovery-pending-002/replay`,
    method: 'POST',
    requestId: 'req-platform-integration-recovery-replay-conflict',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      reason: 'should conflict'
    },
    handlers: harness.handlers
  });
  assert.equal(replayRoute.status, 409);
  const payload = JSON.parse(replayRoute.body);
  assert.equal(payload.error_code, 'INT-409-RECOVERY-REPLAY-CONFLICT');
  assert.equal(payload.previous_status, 'pending');
  assert.equal(payload.requested_status, 'replayed');
});

test('integration recovery list fails closed when store returns malformed queue record', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-recovery-login-fail-closed'
  });
  const integrationId = 'integration-recovery-fail-closed';

  const integrationRoute = await createIntegration({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId,
    requestId: 'req-platform-integration-recovery-create-integration-fail-closed'
  });
  assert.equal(integrationRoute.status, 200);

  const authStore = harness.authService._internals.authStore;
  const originalList = authStore.listPlatformIntegrationRecoveryQueueEntries;
  authStore.listPlatformIntegrationRecoveryQueueEntries = async () => ([
    {
      recoveryId: 'recovery-bad-001',
      integrationId,
      contractType: 'openapi',
      contractVersion: 'v2026.02.22',
      requestId: 'req-source-bad',
      attemptCount: 1,
      maxAttempts: 5,
      status: 'unknown',
      retryable: true,
      payloadSnapshot: {
        ok: true
      },
      createdAt: '2026-02-22T00:00:00.000Z',
      updatedAt: '2026-02-22T00:00:00.000Z'
    }
  ]);

  try {
    const route = await dispatchApiRoute({
      pathname: `/platform/integrations/${integrationId}/recovery/queue`,
      method: 'GET',
      requestId: 'req-platform-integration-recovery-list-fail-closed',
      headers: {
        authorization: `Bearer ${login.access_token}`
      },
      handlers: harness.handlers
    });
    assert.equal(route.status, 503);
    const payload = JSON.parse(route.body);
    assert.equal(payload.error_code, 'INT-503-DEPENDENCY-UNAVAILABLE');
    assert.equal(
      payload.degradation_reason,
      'integration-recovery-list-result-malformed'
    );
  } finally {
    authStore.listPlatformIntegrationRecoveryQueueEntries = originalList;
  }
});

test('integration recovery replay fails closed when store replay result is malformed', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-recovery-login-replay-fail-closed'
  });
  const integrationId = 'integration-recovery-replay-fail-closed';

  const integrationRoute = await createIntegration({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId,
    requestId: 'req-platform-integration-recovery-create-integration-replay-fail-closed'
  });
  assert.equal(integrationRoute.status, 200);

  const authStore = harness.authService._internals.authStore;
  const originalReplay = authStore.replayPlatformIntegrationRecoveryQueueEntry;
  authStore.replayPlatformIntegrationRecoveryQueueEntry = async () => ({
    recoveryId: 'recovery-dlq-raw-001',
    integrationId,
    contractType: 'openapi',
    contractVersion: 'v2026.02.22',
    requestId: 'req-source-recovery-dlq-raw-001',
    traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01',
    idempotencyKey: 'idem-recovery-dlq-raw-001',
    attemptCount: 5,
    maxAttempts: 5,
    nextRetryAt: null,
    lastAttemptAt: '2026-02-22T00:00:00.000Z',
    status: 'dlq',
    failureCode: 'HTTP_500',
    failureDetail: 'timeout',
    lastHttpStatus: 500,
    retryable: true,
    payloadSnapshot: {
      order_id: 'ORDER-001'
    },
    responseSnapshot: {
      message: 'timeout'
    },
    createdAt: '2026-02-22T00:00:00.000Z',
    updatedAt: '2026-02-22T00:00:00.000Z',
    previousStatus: 'dlq',
    currentStatus: 'dlq'
  });

  try {
    const route = await dispatchApiRoute({
      pathname: `/platform/integrations/${integrationId}/recovery/queue/recovery-dlq-raw-001/replay`,
      method: 'POST',
      requestId: 'req-platform-integration-recovery-replay-fail-closed',
      headers: {
        authorization: `Bearer ${login.access_token}`
      },
      body: {
        reason: 'should fail closed'
      },
      handlers: harness.handlers
    });
    assert.equal(route.status, 503);
    const payload = JSON.parse(route.body);
    assert.equal(payload.error_code, 'INT-503-DEPENDENCY-UNAVAILABLE');
    assert.equal(
      payload.degradation_reason,
      'integration-recovery-replay-result-malformed'
    );
  } finally {
    authStore.replayPlatformIntegrationRecoveryQueueEntry = originalReplay;
  }
});

test('recovery queue upsert keeps terminal replayed record immutable on dedup re-delivery', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-recovery-login-terminal-upsert'
  });
  const integrationId = 'integration-recovery-terminal-main';
  const integrationRoute = await createIntegration({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId,
    requestId: 'req-platform-integration-recovery-create-integration-terminal-upsert'
  });
  assert.equal(integrationRoute.status, 200);
  const authStore = harness.authService._internals.authStore;

  const first = await authStore.upsertPlatformIntegrationRecoveryQueueEntry({
    recoveryId: 'recovery-terminal-main',
    integrationId,
    contractType: 'openapi',
    contractVersion: 'v2026.02.22',
    requestId: 'req-source-terminal-main',
    idempotencyKey: 'idem-terminal-main',
    attemptCount: 5,
    maxAttempts: 5,
    nextRetryAt: null,
    lastAttemptAt: '2026-02-22T00:00:00.000Z',
    status: 'replayed',
    retryable: true,
    payloadSnapshot: {
      order_id: 'ORDER-001'
    },
    responseSnapshot: null,
    operatorUserId: 'platform-integration-recovery-operator'
  });
  assert.equal(first.status, 'replayed');
  assert.equal(first.attemptCount, 5);
  assert.equal(first.nextRetryAt, null);

  const second = await authStore.upsertPlatformIntegrationRecoveryQueueEntry({
    recoveryId: 'recovery-terminal-new-id',
    integrationId,
    contractType: 'openapi',
    contractVersion: 'v2026.02.22',
    requestId: 'req-source-terminal-main',
    idempotencyKey: 'idem-terminal-main',
    attemptCount: 0,
    maxAttempts: 5,
    nextRetryAt: '2026-02-22T00:10:00.000Z',
    status: 'pending',
    retryable: true,
    payloadSnapshot: {
      order_id: 'ORDER-001'
    },
    responseSnapshot: null,
    operatorUserId: 'platform-integration-recovery-operator'
  });

  assert.equal(second.recoveryId, 'recovery-terminal-main');
  assert.equal(second.status, 'replayed');
  assert.equal(second.attemptCount, 5);
  assert.equal(second.nextRetryAt, null);
  assert.equal(second.inserted, false);
  assert.equal(second.auditRecorded, false);
});

test('recovery queue upsert fails closed for duplicate recovery_id with mismatched dedup identity', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-recovery-login-dup-recovery-id'
  });
  const integrationId = 'integration-recovery-dup-recovery-id';
  const integrationRoute = await createIntegration({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId,
    requestId: 'req-platform-integration-recovery-create-integration-dup-recovery-id'
  });
  assert.equal(integrationRoute.status, 200);
  const authStore = harness.authService._internals.authStore;

  await authStore.upsertPlatformIntegrationRecoveryQueueEntry({
    recoveryId: 'recovery-duplicate-identity-001',
    integrationId,
    contractType: 'openapi',
    contractVersion: 'v2026.02.22',
    requestId: 'req-source-dup-identity-001',
    idempotencyKey: 'idem-dup-identity-001',
    attemptCount: 0,
    maxAttempts: 5,
    status: 'pending',
    retryable: true,
    payloadSnapshot: {
      order_id: 'ORDER-001'
    },
    responseSnapshot: null,
    operatorUserId: 'platform-integration-recovery-operator'
  });

  await assert.rejects(
    () =>
      authStore.upsertPlatformIntegrationRecoveryQueueEntry({
        recoveryId: 'recovery-duplicate-identity-001',
        integrationId,
        contractType: 'openapi',
        contractVersion: 'v2026.02.22',
        requestId: 'req-source-dup-identity-002',
        idempotencyKey: 'idem-dup-identity-002',
        attemptCount: 0,
        maxAttempts: 5,
        status: 'pending',
        retryable: true,
        payloadSnapshot: {
          order_id: 'ORDER-001'
        },
        responseSnapshot: null,
        operatorUserId: 'platform-integration-recovery-operator'
      }),
    /duplicate platform integration recovery queue entry/
  );
});

test('recovery queue upsert fails closed when integration does not exist in memory store', async () => {
  const harness = createHarness();
  const authStore = harness.authService._internals.authStore;

  await assert.rejects(
    () =>
      authStore.upsertPlatformIntegrationRecoveryQueueEntry({
        recoveryId: 'recovery-missing-integration-001',
        integrationId: 'integration-recovery-missing',
        contractType: 'openapi',
        contractVersion: 'v2026.02.22',
        requestId: 'req-source-missing-integration-001',
        idempotencyKey: 'idem-missing-integration-001',
        attemptCount: 0,
        maxAttempts: 5,
        status: 'pending',
        retryable: true,
        payloadSnapshot: {
          order_id: 'ORDER-001'
        },
        responseSnapshot: null,
        operatorUserId: 'platform-integration-recovery-operator'
      }),
    /upsertPlatformIntegrationRecoveryQueueEntry received invalid input/
  );
});

test('recovery queue claim uses lease to prevent immediate duplicate retrying claims', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-recovery-login-claim-lease'
  });
  const integrationId = 'integration-recovery-claim-lease';
  const integrationRoute = await createIntegration({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId,
    requestId: 'req-platform-integration-recovery-create-integration-claim-lease'
  });
  assert.equal(integrationRoute.status, 200);
  const authStore = harness.authService._internals.authStore;
  const nowIso = '2026-02-22T00:00:00.000Z';

  await authStore.upsertPlatformIntegrationRecoveryQueueEntry({
    recoveryId: 'recovery-claim-lease-001',
    integrationId,
    contractType: 'openapi',
    contractVersion: 'v2026.02.22',
    requestId: 'req-source-claim-lease-001',
    idempotencyKey: 'idem-claim-lease-001',
    attemptCount: 0,
    maxAttempts: 5,
    nextRetryAt: null,
    status: 'pending',
    retryable: true,
    payloadSnapshot: {
      order_id: 'ORDER-001'
    },
    responseSnapshot: null,
    operatorUserId: 'platform-integration-recovery-operator'
  });

  const firstClaim = await authStore.claimNextDuePlatformIntegrationRecoveryQueueEntry({
    integrationId,
    now: nowIso,
    operatorUserId: 'platform-integration-recovery-operator'
  });
  const secondClaim = await authStore.claimNextDuePlatformIntegrationRecoveryQueueEntry({
    integrationId,
    now: nowIso,
    operatorUserId: 'platform-integration-recovery-operator'
  });

  assert.equal(firstClaim?.status, 'retrying');
  assert.equal(firstClaim?.attemptCount, 1);
  assert.equal(firstClaim?.nextRetryAt, '2026-02-22T00:05:00.000Z');
  assert.equal(secondClaim, null);
});

test('recovery queue claim settles stale exhausted retrying entry to dlq and allows replay', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-recovery-login-claim-stale-dlq'
  });
  const integrationId = 'integration-recovery-claim-stale-dlq';
  const integrationRoute = await createIntegration({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId,
    requestId: 'req-platform-integration-recovery-create-integration-claim-stale-dlq'
  });
  assert.equal(integrationRoute.status, 200);
  const authStore = harness.authService._internals.authStore;

  await authStore.upsertPlatformIntegrationRecoveryQueueEntry({
    recoveryId: 'recovery-claim-stale-dlq-001',
    integrationId,
    contractType: 'openapi',
    contractVersion: 'v2026.02.22',
    requestId: 'req-source-claim-stale-dlq-001',
    idempotencyKey: 'idem-claim-stale-dlq-001',
    attemptCount: 5,
    maxAttempts: 5,
    nextRetryAt: '2026-02-22T00:05:00.000Z',
    lastAttemptAt: '2026-02-22T00:00:00.000Z',
    status: 'retrying',
    retryable: true,
    payloadSnapshot: {
      order_id: 'ORDER-001'
    },
    responseSnapshot: {
      message: 'timeout'
    },
    operatorUserId: 'platform-integration-recovery-operator'
  });

  const claimResult = await authStore.claimNextDuePlatformIntegrationRecoveryQueueEntry({
    integrationId,
    now: '2026-02-22T00:10:00.000Z',
    operatorUserId: 'platform-integration-recovery-operator'
  });
  assert.equal(claimResult, null);

  const settledRecord = await authStore.findPlatformIntegrationRecoveryQueueEntryByRecoveryId({
    integrationId,
    recoveryId: 'recovery-claim-stale-dlq-001'
  });
  assert.equal(settledRecord?.status, 'dlq');
  assert.equal(settledRecord?.nextRetryAt, null);
  const staleSweepAudit = await authStore.listAuditEvents({
    domain: 'platform',
    requestId: 'request_id_unset',
    eventType: 'platform.integration.recovery.retry_exhausted',
    targetId: 'recovery-claim-stale-dlq-001'
  });
  assert.equal(staleSweepAudit.total, 1);
  assert.equal(staleSweepAudit.events[0]?.target_id, 'recovery-claim-stale-dlq-001');
  assert.equal(
    staleSweepAudit.events[0]?.metadata?.exhausted_by,
    'stale-retrying-claim-sweep'
  );

  const replayed = await authStore.replayPlatformIntegrationRecoveryQueueEntry({
    integrationId,
    recoveryId: 'recovery-claim-stale-dlq-001',
    reason: 'manual replay after stale retrying lease'
  });
  assert.equal(replayed?.previousStatus, 'dlq');
  assert.equal(replayed?.currentStatus, 'replayed');
});
