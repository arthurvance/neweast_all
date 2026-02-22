const test = require('node:test');
const assert = require('node:assert/strict');

const { createInMemoryAuthStore } = require('../src/modules/auth/auth.store.memory');

test('in-memory integration catalog write is rejected when freeze window is active', async () => {
  const store = createInMemoryAuthStore();

  await store.activatePlatformIntegrationFreeze({
    freezeId: 'memory-freeze-gate-001',
    freezeReason: 'release window active',
    requestId: 'req-memory-freeze-gate-activate'
  });

  await assert.rejects(
    () =>
      store.createPlatformIntegrationCatalogEntry({
        integrationId: 'memory-freeze-gate-target',
        code: 'MEMORY_FREEZE_GATE_TARGET',
        name: 'Memory freeze gate target',
        direction: 'outbound',
        protocol: 'https',
        authMode: 'hmac'
      }),
    (error) => {
      assert.equal(error?.code, 'ERR_PLATFORM_INTEGRATION_FREEZE_ACTIVE_CONFLICT');
      assert.equal(error?.freezeId, 'memory-freeze-gate-001');
      return true;
    }
  );
});

test('activatePlatformIntegrationFreeze rolls back in-memory state when audit write fails', async () => {
  const store = createInMemoryAuthStore({
    faultInjector: {
      beforePlatformIntegrationFreezeActivateAuditWrite: () => {
        throw new Error('injected-freeze-activate-audit-failure');
      }
    }
  });

  await assert.rejects(
    () =>
      store.activatePlatformIntegrationFreeze({
        freezeId: 'memory-freeze-activate-rollback-001',
        freezeReason: 'rollback verification',
        requestId: 'req-memory-freeze-activate-rollback',
        auditContext: {
          requestId: 'req-memory-freeze-activate-rollback',
          actorUserId: 'platform-operator',
          actorSessionId: 'platform-session'
        }
      }),
    (error) => {
      assert.equal(error?.code, 'ERR_AUDIT_WRITE_FAILED');
      return true;
    }
  );

  const activeFreeze = await store.findActivePlatformIntegrationFreeze();
  const latestFreeze = await store.findLatestPlatformIntegrationFreeze();
  assert.equal(activeFreeze, null);
  assert.equal(latestFreeze, null);

  const auditEvents = await store.listAuditEvents({
    domain: 'platform',
    requestId: 'req-memory-freeze-activate-rollback'
  });
  assert.equal(auditEvents.total, 0);
});

test('releasePlatformIntegrationFreeze rolls back in-memory state when audit write fails', async () => {
  const store = createInMemoryAuthStore({
    faultInjector: {
      beforePlatformIntegrationFreezeReleaseAuditWrite: () => {
        throw new Error('injected-freeze-release-audit-failure');
      }
    }
  });

  const activated = await store.activatePlatformIntegrationFreeze({
    freezeId: 'memory-freeze-release-rollback-001',
    freezeReason: 'prepare release rollback',
    requestId: 'req-memory-freeze-release-rollback-activate'
  });
  assert.equal(activated.status, 'active');

  await assert.rejects(
    () =>
      store.releasePlatformIntegrationFreeze({
        rollbackReason: 'release rollback verification',
        requestId: 'req-memory-freeze-release-rollback',
        auditContext: {
          requestId: 'req-memory-freeze-release-rollback',
          actorUserId: 'platform-operator',
          actorSessionId: 'platform-session'
        }
      }),
    (error) => {
      assert.equal(error?.code, 'ERR_AUDIT_WRITE_FAILED');
      return true;
    }
  );

  const activeFreeze = await store.findActivePlatformIntegrationFreeze();
  const latestFreeze = await store.findLatestPlatformIntegrationFreeze();
  assert.equal(activeFreeze?.freezeId, 'memory-freeze-release-rollback-001');
  assert.equal(activeFreeze?.status, 'active');
  assert.equal(activeFreeze?.releasedAt, null);
  assert.equal(latestFreeze?.freezeId, 'memory-freeze-release-rollback-001');
  assert.equal(latestFreeze?.status, 'active');

  const auditEvents = await store.listAuditEvents({
    domain: 'platform',
    requestId: 'req-memory-freeze-release-rollback'
  });
  assert.equal(auditEvents.total, 0);
});
