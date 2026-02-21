const test = require('node:test');
const assert = require('node:assert/strict');

const { createAuditService } = require('../src/modules/audit/audit.service');
const { AuthProblemError } = require('../src/modules/auth/auth.service');

const VALID_EVENT = {
  event_id: 'audit-event-1',
  domain: 'tenant',
  tenant_id: 'tenant-a',
  request_id: 'req-audit-1',
  traceparent: null,
  event_type: 'auth.tenant_membership_roles.updated',
  actor_user_id: 'operator-1',
  actor_session_id: 'session-1',
  target_type: 'membership_role_bindings',
  target_id: 'membership-1',
  result: 'success',
  before_state: { role_ids: ['r1'] },
  after_state: { role_ids: ['r1', 'r2'] },
  metadata: { affected_user_count: 1 },
  occurred_at: '2026-02-20T00:00:00.000Z'
};

test('listTenantAuditEvents fails closed when dependency returns cross-domain event', async () => {
  const service = createAuditService({
    authService: {
      authorizeRoute: async () => ({
        user_id: 'tenant-auditor',
        session_id: 'tenant-session',
        active_tenant_id: 'tenant-a'
      }),
      listAuditEvents: async () => ({
        total: 1,
        events: [
          {
            ...VALID_EVENT,
            domain: 'platform',
            tenant_id: 'tenant-b'
          }
        ]
      })
    }
  });

  await assert.rejects(
    () =>
      service.listTenantAuditEvents({
        requestId: 'req-tenant-audit-read',
        accessToken: 'token'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-AUDIT-DEPENDENCY-UNAVAILABLE');
      assert.equal(error.extensions?.degradation_reason, 'audit-query-result-invalid');
      return true;
    }
  );
});

test('listPlatformAuditEvents fails closed when tenant filter is violated by dependency payload', async () => {
  const service = createAuditService({
    authService: {
      authorizeRoute: async () => ({
        user_id: 'platform-auditor',
        session_id: 'platform-session'
      }),
      listAuditEvents: async () => ({
        total: 1,
        events: [
          {
            ...VALID_EVENT,
            domain: 'platform',
            tenant_id: 'tenant-b'
          }
        ]
      })
    }
  });

  await assert.rejects(
    () =>
      service.listPlatformAuditEvents({
        requestId: 'req-platform-audit-read',
        accessToken: 'token',
        query: {
          tenant_id: 'tenant-a'
        }
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-AUDIT-DEPENDENCY-UNAVAILABLE');
      assert.equal(error.extensions?.degradation_reason, 'audit-query-result-invalid');
      return true;
    }
  );
});

test('audit service fails closed when dependency returns invalid traceparent', async () => {
  const service = createAuditService({
    authService: {
      authorizeRoute: async () => ({
        user_id: 'platform-auditor',
        session_id: 'platform-session'
      }),
      listAuditEvents: async () => ({
        total: 1,
        events: [
          {
            ...VALID_EVENT,
            domain: 'platform',
            tenant_id: null,
            traceparent: 'not-a-valid-traceparent'
          }
        ]
      })
    }
  });

  await assert.rejects(
    () =>
      service.listPlatformAuditEvents({
        requestId: 'req-audit-service-test',
        accessToken: 'token'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-AUDIT-DEPENDENCY-UNAVAILABLE');
      assert.equal(error.extensions?.degradation_reason, 'audit-query-result-invalid');
      return true;
    }
  );
});
