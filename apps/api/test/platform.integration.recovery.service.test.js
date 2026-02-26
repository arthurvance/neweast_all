const test = require('node:test');
const assert = require('node:assert/strict');
const { createAuthService } = require('../src/shared-kernel/auth/create-auth-service');
const {
  createPlatformIntegrationRecoveryService
} = require('../src/domains/platform/config/integration-recovery/service');

const seedIntegration = async ({
  authStore,
  integrationId
}) =>
  authStore.createPlatformIntegrationCatalogEntry({
    integrationId,
    code: integrationId.toUpperCase(),
    name: '集成恢复服务测试集成',
    direction: 'outbound',
    protocol: 'https',
    authMode: 'hmac',
    lifecycleStatus: 'active'
  });

const seedRecoveryQueueEntry = async ({
  authStore,
  integrationId,
  recoveryId,
  requestId
}) =>
  authStore.upsertPlatformIntegrationRecoveryQueueEntry({
    recoveryId,
    integrationId,
    contractType: 'openapi',
    contractVersion: 'v2026.02.22',
    requestId,
    traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01',
    idempotencyKey: `idem-${recoveryId}`,
    attemptCount: 0,
    maxAttempts: 5,
    nextRetryAt: '2026-02-22T00:00:00.000Z',
    status: 'pending',
    retryable: true,
    payloadSnapshot: {
      order_id: 'ORDER-001'
    },
    responseSnapshot: null
  });

test('processNextRecoveryQueueItem executes claimed entry and completes to succeeded', async () => {
  const authService = createAuthService();
  const authStore = authService._internals.authStore;
  const integrationId = 'integration-recovery-worker-success';
  const recoveryId = 'recovery-worker-success-001';
  await seedIntegration({ authStore, integrationId });
  await seedRecoveryQueueEntry({
    authStore,
    integrationId,
    recoveryId,
    requestId: 'req-source-worker-success-001'
  });

  let executorCallCount = 0;
  const service = createPlatformIntegrationRecoveryService({
    authService,
    deliveryExecutor: async ({ recovery }) => {
      executorCallCount += 1;
      assert.equal(recovery.integration_id, integrationId);
      assert.equal(recovery.recovery_id, recoveryId);
      return {
        succeeded: true,
        responseSnapshot: {
          delivered: true
        }
      };
    }
  });

  const processed = await service.processNextRecoveryQueueItem({
    requestId: 'req-recovery-worker-success',
    integrationId,
    now: '2026-02-22T00:00:00.000Z',
    operatorUserId: 'platform-integration-recovery-operator',
    operatorSessionId: 'platform-integration-recovery-session'
  });

  assert.equal(executorCallCount, 1);
  assert.equal(processed.processed, true);
  assert.equal(processed.current_status, 'succeeded');

  const stored = await authStore.findPlatformIntegrationRecoveryQueueEntryByRecoveryId({
    integrationId,
    recoveryId
  });
  assert.equal(stored?.status, 'succeeded');
  assert.equal(stored?.attemptCount, 1);
  assert.equal(stored?.retryable, false);

  const auditEvents = await authStore.listAuditEvents({
    domain: 'platform',
    requestId: 'req-recovery-worker-success',
    eventType: 'platform.integration.recovery.reprocess_succeeded'
  });
  assert.equal(auditEvents.total, 1);
});

test('processNextRecoveryQueueItem routes non-retryable failure to dlq via orchestrator-backed completion', async () => {
  const authService = createAuthService();
  const authStore = authService._internals.authStore;
  const integrationId = 'integration-recovery-worker-non-retryable';
  const recoveryId = 'recovery-worker-non-retryable-001';
  await seedIntegration({ authStore, integrationId });
  await seedRecoveryQueueEntry({
    authStore,
    integrationId,
    recoveryId,
    requestId: 'req-source-worker-non-retryable-001'
  });

  const service = createPlatformIntegrationRecoveryService({
    authService,
    deliveryExecutor: async () => ({
      succeeded: false,
      retryable: true,
      failureCode: 'HTTP_400',
      failureDetail: 'downstream validation failed',
      lastHttpStatus: 400,
      responseSnapshot: {
        error_code: 'VALIDATION_ERROR'
      }
    })
  });

  const processed = await service.processNextRecoveryQueueItem({
    requestId: 'req-recovery-worker-non-retryable',
    integrationId,
    now: '2026-02-22T00:00:00.000Z',
    operatorUserId: 'platform-integration-recovery-operator',
    operatorSessionId: 'platform-integration-recovery-session'
  });
  assert.equal(processed.processed, true);
  assert.equal(processed.current_status, 'dlq');

  const stored = await authStore.findPlatformIntegrationRecoveryQueueEntryByRecoveryId({
    integrationId,
    recoveryId
  });
  assert.equal(stored?.status, 'dlq');
  assert.equal(stored?.retryable, false);

  const exhaustedAuditEvents = await authStore.listAuditEvents({
    domain: 'platform',
    requestId: 'req-recovery-worker-non-retryable',
    eventType: 'platform.integration.recovery.retry_exhausted'
  });
  assert.equal(exhaustedAuditEvents.total, 1);
});

test('processNextRecoveryQueueItem can claim replayed entry and reprocess it', async () => {
  const authService = createAuthService();
  const authStore = authService._internals.authStore;
  const integrationId = 'integration-recovery-worker-replayed';
  const recoveryId = 'recovery-worker-replayed-001';
  await seedIntegration({ authStore, integrationId });
  await authStore.upsertPlatformIntegrationRecoveryQueueEntry({
    recoveryId,
    integrationId,
    contractType: 'openapi',
    contractVersion: 'v2026.02.22',
    requestId: 'req-source-worker-replayed-001',
    traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01',
    idempotencyKey: `idem-${recoveryId}`,
    attemptCount: 5,
    maxAttempts: 5,
    nextRetryAt: null,
    lastAttemptAt: '2026-02-22T00:00:00.000Z',
    status: 'dlq',
    retryable: true,
    failureCode: 'HTTP_500',
    failureDetail: 'timeout',
    lastHttpStatus: 500,
    payloadSnapshot: {
      order_id: 'ORDER-001'
    },
    responseSnapshot: {
      message: 'timeout'
    }
  });
  await authStore.replayPlatformIntegrationRecoveryQueueEntry({
    integrationId,
    recoveryId,
    reason: 'manual replay'
  });

  let executorCallCount = 0;
  const service = createPlatformIntegrationRecoveryService({
    authService,
    deliveryExecutor: async ({ recovery }) => {
      executorCallCount += 1;
      assert.equal(recovery.status, 'retrying');
      return {
        succeeded: true,
        responseSnapshot: {
          delivered: true
        }
      };
    }
  });

  const processed = await service.processNextRecoveryQueueItem({
    requestId: 'req-recovery-worker-replayed',
    integrationId,
    now: '2099-01-01T00:00:00.000Z',
    operatorUserId: 'platform-integration-recovery-operator',
    operatorSessionId: 'platform-integration-recovery-session'
  });

  assert.equal(executorCallCount, 1);
  assert.equal(processed.processed, true);
  assert.equal(processed.previous_status, 'replayed');
  assert.equal(processed.current_status, 'succeeded');

  const stored = await authStore.findPlatformIntegrationRecoveryQueueEntryByRecoveryId({
    integrationId,
    recoveryId
  });
  assert.equal(stored?.status, 'succeeded');
  assert.equal(stored?.attemptCount, 1);
});

test('processNextRecoveryQueueItem fails closed when no delivery executor is configured', async () => {
  const authService = createAuthService();
  const service = createPlatformIntegrationRecoveryService({
    authService
  });

  await assert.rejects(
    () =>
      service.processNextRecoveryQueueItem({
        requestId: 'req-recovery-worker-no-executor'
      }),
    (error) => {
      assert.equal(error?.status, 503);
      assert.equal(error?.errorCode, 'INT-503-DEPENDENCY-UNAVAILABLE');
      assert.equal(
        error?.extensions?.degradation_reason,
        'integration-recovery-delivery-executor-unavailable'
      );
      return true;
    }
  );
});
