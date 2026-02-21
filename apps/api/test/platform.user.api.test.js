const test = require('node:test');
const assert = require('node:assert/strict');
const { createRouteHandlers } = require('../src/http-routes');
const { createPlatformUserHandlers } = require('../src/modules/platform/user.routes');
const { createPlatformUserService } = require('../src/modules/platform/user.service');
const { dispatchApiRoute } = require('../src/server');
const { readConfig } = require('../src/config/env');
const { AuthProblemError } = require('../src/modules/auth/auth.routes');

const config = readConfig({ ALLOW_MOCK_BACKENDS: 'true' });
const dependencyProbe = async () => ({
  db: { ok: true },
  redis: { ok: true }
});

const createHarness = ({
  authorizeRoute = async () => ({
    user_id: 'platform-operator',
    session_id: 'platform-session',
    entry_domain: 'platform',
    active_tenant_id: null
  }),
  provisionPlatformUserByPhone = async () => ({
    user_id: 'platform-user-default',
    created_user: false,
    reused_existing_user: true,
    request_id: 'request_id_unset'
  }),
  updatePlatformUserStatus = async ({ userId, nextStatus }) => ({
    user_id: userId,
    previous_status: nextStatus === 'disabled' ? 'active' : 'disabled',
    current_status: nextStatus
  }),
  recordIdempotencyEvent = async () => {},
  authIdempotencyStore = null
} = {}) => {
  const authorizeCalls = [];
  const provisionCalls = [];
  const statusCalls = [];
  const idempotencyEvents = [];
  const authService = {
    authorizeRoute: async (payload) => {
      authorizeCalls.push(payload);
      return authorizeRoute(payload);
    },
    provisionPlatformUserByPhone: async (payload) => {
      provisionCalls.push(payload);
      return provisionPlatformUserByPhone(payload);
    },
    updatePlatformUserStatus: async (payload) => {
      statusCalls.push(payload);
      return updatePlatformUserStatus(payload);
    },
    recordIdempotencyEvent: async (payload) => {
      idempotencyEvents.push(payload);
      return recordIdempotencyEvent(payload);
    },
    _internals: {
      auditTrail: []
    }
  };

  const platformUserService = createPlatformUserService({
    authService
  });
  const handlers = createRouteHandlers(config, {
    dependencyProbe,
    authService,
    platformUserService,
    authIdempotencyStore
  });
  return {
    handlers,
    platformUserService,
    authorizeCalls,
    provisionCalls,
    statusCalls,
    idempotencyEvents
  };
};

test('createPlatformUserHandlers fails fast when platform user service capability is missing', () => {
  assert.throws(
    () => createPlatformUserHandlers(),
    /requires a platformUserService with createUser and updateUserStatus/
  );
  assert.throws(
    () => createPlatformUserHandlers({}),
    /requires a platformUserService with createUser and updateUserStatus/
  );
});

test('createPlatformUser maps non-auth operator authorization failures to USR-503-DEPENDENCY-UNAVAILABLE', async () => {
  const service = createPlatformUserService({
    authService: {
      authorizeRoute: async () => {
        throw new Error('auth dependency temporarily unavailable');
      },
      provisionPlatformUserByPhone: async () => ({
        user_id: 'platform-user-created',
        created_user: true,
        reused_existing_user: false
      })
    }
  });

  await assert.rejects(
    () =>
      service.createUser({
        requestId: 'req-platform-user-operator-auth-upstream-failure',
        accessToken: 'fake-access-token',
        payload: {
          phone: '13800000040'
        }
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'USR-503-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
});

test('createPlatformUser emits rejected audit event when upstream payload misses user_id', async () => {
  const service = createPlatformUserService({
    authService: {
      authorizeRoute: async () => ({
        user_id: 'platform-operator',
        session_id: 'platform-session',
        entry_domain: 'platform',
        active_tenant_id: null
      }),
      provisionPlatformUserByPhone: async () => ({
        created_user: true,
        reused_existing_user: false
      })
    }
  });

  await assert.rejects(
    () =>
      service.createUser({
        requestId: 'req-platform-user-missing-upstream-user-id',
        accessToken: 'fake-access-token',
        payload: {
          phone: '13800000048'
        }
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'USR-503-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );

  const lastAuditEvent = service._internals.auditTrail.at(-1);
  assert.equal(lastAuditEvent.type, 'platform.user.create.rejected');
  assert.equal(lastAuditEvent.error_code, 'USR-503-DEPENDENCY-UNAVAILABLE');
  assert.equal(
    lastAuditEvent.upstream_error_code,
    'PLATFORM-USER-PROVISION-RESULT-MISSING-USER-ID'
  );
});

test('POST /platform/users creates platform user and returns governance response fields', async () => {
  const harness = createHarness({
    provisionPlatformUserByPhone: async ({ requestId }) => ({
      user_id: 'platform-user-created',
      created_user: true,
      reused_existing_user: false,
      request_id: requestId
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/users',
    method: 'POST',
    requestId: 'req-platform-user-create',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      phone: '13800000041'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 200);
  const payload = JSON.parse(route.body);
  assert.deepEqual(payload, {
    user_id: 'platform-user-created',
    created_user: true,
    reused_existing_user: false,
    request_id: 'req-platform-user-create'
  });
  assert.equal(harness.provisionCalls.length, 1);
  const lastAuditEvent = harness.platformUserService._internals.auditTrail.at(-1);
  assert.equal(lastAuditEvent.phone, '138****0041');
});

test('POST /platform/users reuses existing user identity when phone already exists', async () => {
  const harness = createHarness({
    provisionPlatformUserByPhone: async ({ requestId }) => ({
      user_id: 'platform-user-existing',
      created_user: false,
      reused_existing_user: true,
      request_id: requestId
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/users',
    method: 'POST',
    requestId: 'req-platform-user-reuse',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      phone: '13800000042'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 200);
  const payload = JSON.parse(route.body);
  assert.equal(payload.user_id, 'platform-user-existing');
  assert.equal(payload.created_user, false);
  assert.equal(payload.reused_existing_user, true);
  assert.equal(payload.request_id, 'req-platform-user-reuse');
});

test('POST /platform/users returns AUTH-403-FORBIDDEN when operator lacks permission', async () => {
  const harness = createHarness({
    authorizeRoute: async () => {
      throw new AuthProblemError({
        status: 403,
        title: 'Forbidden',
        detail: '当前操作无权限',
        errorCode: 'AUTH-403-FORBIDDEN'
      });
    }
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/users',
    method: 'POST',
    requestId: 'req-platform-user-forbidden',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      phone: '13800000047'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 403);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-403-FORBIDDEN');
  assert.equal(payload.request_id, 'req-platform-user-forbidden');
  assert.equal(harness.provisionCalls.length, 0);
});

test('POST /platform/users keeps problem+json contract on payload validation failure', async () => {
  const harness = createHarness({
    provisionPlatformUserByPhone: async () => {
      throw new AuthProblemError({
        status: 400,
        title: 'Bad Request',
        detail: '请求参数不完整或格式错误',
        errorCode: 'AUTH-400-INVALID-PAYLOAD'
      });
    }
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/users',
    method: 'POST',
    requestId: 'req-platform-user-invalid-payload',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      phone: '13800000043',
      unexpected_field: true
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 400);
  assert.equal(route.headers['content-type'], 'application/problem+json');
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-400-INVALID-PAYLOAD');
  assert.equal(payload.request_id, 'req-platform-user-invalid-payload');
  const lastAuditEvent = harness.platformUserService._internals.auditTrail.at(-1);
  assert.equal(lastAuditEvent.phone, '138****0043');
});

test('POST /platform/users replays first success response for same Idempotency-Key and payload', async () => {
  const harness = createHarness({
    provisionPlatformUserByPhone: async ({ requestId }) => ({
      user_id: 'platform-user-idem-replay',
      created_user: true,
      reused_existing_user: false,
      request_id: requestId
    })
  });

  const requestBody = {
    phone: '13800000044'
  };
  const first = await dispatchApiRoute({
    pathname: '/platform/users',
    method: 'POST',
    requestId: 'req-platform-user-idem-replay-1',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-platform-user-replay-001'
    },
    body: requestBody,
    handlers: harness.handlers
  });
  const second = await dispatchApiRoute({
    pathname: '/platform/users',
    method: 'POST',
    requestId: 'req-platform-user-idem-replay-2',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-platform-user-replay-001'
    },
    body: requestBody,
    handlers: harness.handlers
  });

  assert.equal(first.status, 200);
  assert.equal(second.status, 200);
  assert.equal(harness.provisionCalls.length, 1);
  const firstPayload = JSON.parse(first.body);
  const secondPayload = JSON.parse(second.body);
  assert.equal(secondPayload.user_id, firstPayload.user_id);
  assert.equal(secondPayload.created_user, firstPayload.created_user);
  assert.equal(secondPayload.request_id, 'req-platform-user-idem-replay-2');
});

test('POST /platform/users rejects same Idempotency-Key with different payloads', async () => {
  const harness = createHarness({
    provisionPlatformUserByPhone: async ({ requestId }) => ({
      user_id: 'platform-user-idem-conflict',
      created_user: true,
      reused_existing_user: false,
      request_id: requestId
    })
  });

  const first = await dispatchApiRoute({
    pathname: '/platform/users',
    method: 'POST',
    requestId: 'req-platform-user-idem-conflict-1',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-platform-user-conflict-001'
    },
    body: {
      phone: '13800000045'
    },
    handlers: harness.handlers
  });
  const second = await dispatchApiRoute({
    pathname: '/platform/users',
    method: 'POST',
    requestId: 'req-platform-user-idem-conflict-2',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-platform-user-conflict-001'
    },
    body: {
      phone: '13800000046'
    },
    handlers: harness.handlers
  });

  assert.equal(first.status, 200);
  assert.equal(second.status, 409);
  const payload = JSON.parse(second.body);
  assert.equal(payload.error_code, 'AUTH-409-IDEMPOTENCY-CONFLICT');
  assert.equal(payload.request_id, 'req-platform-user-idem-conflict-2');
  assert.equal(harness.provisionCalls.length, 1);
});

test('POST /platform/users/status updates user status and records governance audit fields', async () => {
  const harness = createHarness({
    updatePlatformUserStatus: async ({ userId, nextStatus }) => ({
      user_id: userId,
      previous_status: 'active',
      current_status: nextStatus
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/users/status',
    method: 'POST',
    requestId: 'req-platform-user-status-disable',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      user_id: 'platform-user-target-1',
      status: 'disabled',
      reason: 'manual-governance'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 200);
  const payload = JSON.parse(route.body);
  assert.deepEqual(payload, {
    user_id: 'platform-user-target-1',
    previous_status: 'active',
    current_status: 'disabled',
    request_id: 'req-platform-user-status-disable'
  });
  assert.equal(harness.statusCalls.length, 1);
  assert.equal(harness.statusCalls[0].userId, 'platform-user-target-1');
  assert.equal(harness.statusCalls[0].nextStatus, 'disabled');
  assert.equal(harness.statusCalls[0].operatorUserId, 'platform-operator');
  assert.equal(harness.statusCalls[0].operatorSessionId, 'platform-session');
  assert.equal(harness.statusCalls[0].reason, 'manual-governance');
  const lastAuditEvent = harness.platformUserService._internals.auditTrail.at(-1);
  assert.equal(lastAuditEvent.type, 'platform.user.status.updated');
  assert.equal(lastAuditEvent.target_user_id, 'platform-user-target-1');
  assert.equal(lastAuditEvent.previous_status, 'active');
  assert.equal(lastAuditEvent.next_status, 'disabled');
});

test('POST /platform/users/status forwards traceparent to auth domain write call', async () => {
  const harness = createHarness();
  const traceparent = '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01';

  const route = await dispatchApiRoute({
    pathname: '/platform/users/status',
    method: 'POST',
    requestId: 'req-platform-user-status-traceparent',
    headers: {
      authorization: 'Bearer fake-access-token',
      traceparent
    },
    body: {
      user_id: 'platform-user-target-trace',
      status: 'disabled'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 200);
  assert.equal(harness.statusCalls.length, 1);
  assert.equal(
    harness.statusCalls[0].traceparent,
    traceparent
  );
});

test('POST /platform/users/status accepts status=enabled and normalizes to active', async () => {
  const harness = createHarness({
    updatePlatformUserStatus: async ({ userId, nextStatus }) => ({
      user_id: userId,
      previous_status: 'disabled',
      current_status: nextStatus
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/users/status',
    method: 'POST',
    requestId: 'req-platform-user-status-enable-normalized',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      user_id: 'platform-user-target-2',
      status: 'enabled'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 200);
  const payload = JSON.parse(route.body);
  assert.equal(payload.current_status, 'active');
  assert.equal(harness.statusCalls.length, 1);
  assert.equal(harness.statusCalls[0].nextStatus, 'active');
});

test('POST /platform/users/status returns USER-404 when target user is missing or has no platform-domain access', async () => {
  const harness = createHarness({
    updatePlatformUserStatus: async () => {
      throw new AuthProblemError({
        status: 404,
        title: 'Not Found',
        detail: 'user missing',
        errorCode: 'AUTH-404-USER-NOT-FOUND'
      });
    }
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/users/status',
    method: 'POST',
    requestId: 'req-platform-user-status-not-found',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      user_id: 'platform-user-missing',
      status: 'disabled'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 404);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'USR-404-USER-NOT-FOUND');
  assert.equal(payload.detail, '目标平台用户不存在或无 platform 域访问');
  assert.equal(payload.request_id, 'req-platform-user-status-not-found');
});

test('POST /platform/users/status preserves non-404 auth domain errors', async () => {
  const harness = createHarness({
    updatePlatformUserStatus: async () => {
      throw new AuthProblemError({
        status: 503,
        title: 'Service Unavailable',
        detail: 'platform permission snapshot temporarily degraded',
        errorCode: 'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED',
        extensions: {
          retryable: true,
          degradation_reason: 'db-deadlock'
        }
      });
    }
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/users/status',
    method: 'POST',
    requestId: 'req-platform-user-status-upstream-degraded',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      user_id: 'platform-user-upstream-error',
      status: 'disabled'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 503);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED');
  assert.equal(payload.request_id, 'req-platform-user-status-upstream-degraded');
  assert.equal(payload.retryable, true);
  assert.equal(payload.degradation_reason, 'db-deadlock');
  const lastAuditEvent = harness.platformUserService._internals.auditTrail.at(-1);
  assert.equal(lastAuditEvent.type, 'platform.user.status.rejected');
  assert.equal(lastAuditEvent.error_code, 'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED');
  assert.equal(lastAuditEvent.upstream_error_code, 'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED');
});

test('POST /platform/users/status maps invalid upstream status result to AUTH-503-PLATFORM-SNAPSHOT-DEGRADED', async () => {
  const harness = createHarness({
    updatePlatformUserStatus: async ({ userId }) => ({
      user_id: userId,
      previous_status: 'active',
      current_status: 'archived'
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/users/status',
    method: 'POST',
    requestId: 'req-platform-user-status-invalid-upstream-status',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      user_id: 'platform-user-target-invalid-status',
      status: 'disabled'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 503);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED');
  assert.equal(payload.degradation_reason, 'platform-user-status-result-invalid');
  assert.equal(payload.request_id, 'req-platform-user-status-invalid-upstream-status');
  const lastAuditEvent = harness.platformUserService._internals.auditTrail.at(-1);
  assert.equal(lastAuditEvent.type, 'platform.user.status.rejected');
  assert.equal(lastAuditEvent.error_code, 'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED');
  assert.equal(lastAuditEvent.upstream_error_code, 'PLATFORM-USER-STATUS-RESULT-INVALID');
});

test('POST /platform/users/status maps upstream target mismatch to AUTH-503-PLATFORM-SNAPSHOT-DEGRADED', async () => {
  const harness = createHarness({
    updatePlatformUserStatus: async () => ({
      user_id: 'platform-user-target-mismatched',
      previous_status: 'active',
      current_status: 'disabled'
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/users/status',
    method: 'POST',
    requestId: 'req-platform-user-status-upstream-target-mismatch',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      user_id: 'platform-user-target-requested',
      status: 'disabled'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 503);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED');
  assert.equal(payload.degradation_reason, 'platform-user-status-target-mismatch');
  assert.equal(payload.request_id, 'req-platform-user-status-upstream-target-mismatch');
  const lastAuditEvent = harness.platformUserService._internals.auditTrail.at(-1);
  assert.equal(lastAuditEvent.type, 'platform.user.status.rejected');
  assert.equal(lastAuditEvent.error_code, 'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED');
  assert.equal(
    lastAuditEvent.upstream_error_code,
    'PLATFORM-USER-STATUS-RESULT-TARGET-MISMATCH'
  );
  assert.equal(lastAuditEvent.upstream_target_user_id, 'platform-user-target-mismatched');
});

test('POST /platform/users/status rejects invalid payload with USER problem details', async () => {
  const harness = createHarness();

  const route = await dispatchApiRoute({
    pathname: '/platform/users/status',
    method: 'POST',
    requestId: 'req-platform-user-status-invalid-payload',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      user_id: 'platform-user-target-3',
      status: 'archived'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 400);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'USR-400-INVALID-PAYLOAD');
  assert.match(payload.detail, /active 或 disabled/);
  assert.equal(harness.statusCalls.length, 0);
  const lastAuditEvent = harness.platformUserService._internals.auditTrail.at(-1);
  assert.equal(lastAuditEvent.type, 'platform.user.status.rejected');
  assert.equal(lastAuditEvent.previous_status, null);
  assert.equal(lastAuditEvent.next_status, 'archived');
});

test('POST /platform/users/status returns AUTH-403-FORBIDDEN when operator lacks permission', async () => {
  const harness = createHarness({
    authorizeRoute: async () => {
      throw new AuthProblemError({
        status: 403,
        title: 'Forbidden',
        detail: '当前操作无权限',
        errorCode: 'AUTH-403-FORBIDDEN'
      });
    }
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/users/status',
    method: 'POST',
    requestId: 'req-platform-user-status-forbidden',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      user_id: 'platform-user-target-forbidden',
      status: 'disabled'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 403);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-403-FORBIDDEN');
  assert.equal(payload.request_id, 'req-platform-user-status-forbidden');
  assert.equal(harness.statusCalls.length, 0);
});

test('POST /platform/users/status replays first success response for same Idempotency-Key and payload', async () => {
  const harness = createHarness();
  const requestBody = {
    user_id: 'platform-user-target-4',
    status: 'disabled'
  };

  const first = await dispatchApiRoute({
    pathname: '/platform/users/status',
    method: 'POST',
    requestId: 'req-platform-user-status-idem-replay-1',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-platform-user-status-replay-001'
    },
    body: requestBody,
    handlers: harness.handlers
  });
  const second = await dispatchApiRoute({
    pathname: '/platform/users/status',
    method: 'POST',
    requestId: 'req-platform-user-status-idem-replay-2',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-platform-user-status-replay-001'
    },
    body: requestBody,
    handlers: harness.handlers
  });

  assert.equal(first.status, 200);
  assert.equal(second.status, 200);
  assert.equal(harness.statusCalls.length, 1);
  const firstPayload = JSON.parse(first.body);
  const secondPayload = JSON.parse(second.body);
  assert.equal(secondPayload.user_id, firstPayload.user_id);
  assert.equal(secondPayload.current_status, firstPayload.current_status);
  assert.equal(secondPayload.request_id, 'req-platform-user-status-idem-replay-2');
});

test('POST /platform/users/status rejects same Idempotency-Key with different payloads', async () => {
  const harness = createHarness();
  const first = await dispatchApiRoute({
    pathname: '/platform/users/status',
    method: 'POST',
    requestId: 'req-platform-user-status-idem-conflict-1',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-platform-user-status-conflict-001'
    },
    body: {
      user_id: 'platform-user-target-5',
      status: 'disabled'
    },
    handlers: harness.handlers
  });
  const second = await dispatchApiRoute({
    pathname: '/platform/users/status',
    method: 'POST',
    requestId: 'req-platform-user-status-idem-conflict-2',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-platform-user-status-conflict-001'
    },
    body: {
      user_id: 'platform-user-target-5',
      status: 'active'
    },
    handlers: harness.handlers
  });

  assert.equal(first.status, 200);
  assert.equal(second.status, 409);
  const payload = JSON.parse(second.body);
  assert.equal(payload.error_code, 'AUTH-409-IDEMPOTENCY-CONFLICT');
  assert.equal(payload.request_id, 'req-platform-user-status-idem-conflict-2');
  assert.equal(harness.statusCalls.length, 1);
});
