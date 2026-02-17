const test = require('node:test');
const assert = require('node:assert/strict');
const { createRouteHandlers } = require('../src/http-routes');
const { createPlatformOrgHandlers } = require('../src/modules/platform/org.routes');
const { createPlatformOrgService } = require('../src/modules/platform/org.service');
const { dispatchApiRoute } = require('../src/server');
const { readConfig } = require('../src/config/env');
const { AuthProblemError } = require('../src/modules/auth/auth.routes');
const {
  markRoutePreauthorizedContext
} = require('../src/modules/auth/route-preauthorization');

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
  getOrCreateUserIdentityByPhone = async ({ phone }) => ({
    user_id: 'owner-user-existing',
    phone,
    created_user: false,
    reused_existing_user: true,
    credential_initialized: false,
    first_login_force_password_change: false
  }),
  rollbackProvisionedUserIdentity = async () => {},
  includeRollbackProvisionedUserIdentity = true,
  createOrganizationWithOwner = async ({ orgId, ownerUserId }) => ({
    org_id: orgId,
    owner_user_id: ownerUserId
  }),
  recordIdempotencyEvent = async () => {},
  authIdempotencyStore = null
} = {}) => {
  const storeCalls = [];
  const rollbackCalls = [];
  const authorizeCalls = [];
  const idempotencyEvents = [];
  const authService = {
    authorizeRoute: async (payload) => {
      authorizeCalls.push(payload);
      return authorizeRoute(payload);
    },
    getOrCreateUserIdentityByPhone,
    createOrganizationWithOwner: async (payload) => {
      storeCalls.push(payload);
      return createOrganizationWithOwner(payload);
    },
    recordIdempotencyEvent: async (payload) => {
      idempotencyEvents.push(payload);
      return recordIdempotencyEvent(payload);
    },
    _internals: {
      auditTrail: []
    }
  };
  if (includeRollbackProvisionedUserIdentity) {
    authService.rollbackProvisionedUserIdentity = async (payload) => {
      rollbackCalls.push(payload);
      return rollbackProvisionedUserIdentity(payload);
    };
  }
  const platformOrgService = createPlatformOrgService({
    authService
  });
  const handlers = createRouteHandlers(config, {
    dependencyProbe,
    authService,
    platformOrgService,
    authIdempotencyStore
  });
  return {
    handlers,
    platformOrgService,
    storeCalls,
    rollbackCalls,
    authorizeCalls,
    idempotencyEvents
  };
};

test('createPlatformOrgHandlers fails fast when platform org service capability is missing', () => {
  assert.throws(
    () => createPlatformOrgHandlers(),
    /requires a platformOrgService with createOrg/
  );
  assert.throws(
    () => createPlatformOrgHandlers({}),
    /requires a platformOrgService with createOrg/
  );
});

test('POST /platform/orgs rejects missing initial_owner_phone with standard problem details', async () => {
  const harness = createHarness();
  const route = await dispatchApiRoute({
    pathname: '/platform/orgs',
    method: 'POST',
    requestId: 'req-platform-org-missing-owner-phone',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      org_name: '组织 A'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 400);
  assert.equal(route.headers['content-type'], 'application/problem+json');
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'ORG-400-INITIAL-OWNER-PHONE-REQUIRED');
  assert.equal(payload.retryable, false);
  assert.equal(payload.request_id, 'req-platform-org-missing-owner-phone');
  assert.equal(harness.storeCalls.length, 0);
});

test('POST /platform/orgs rejects missing org_name with standard problem details', async () => {
  const harness = createHarness();
  const route = await dispatchApiRoute({
    pathname: '/platform/orgs',
    method: 'POST',
    requestId: 'req-platform-org-missing-org-name',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      initial_owner_phone: '13800000011'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 400);
  assert.equal(route.headers['content-type'], 'application/problem+json');
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'ORG-400-INVALID-PAYLOAD');
  assert.match(payload.detail, /org_name/);
  assert.equal(payload.request_id, 'req-platform-org-missing-org-name');
  assert.equal(harness.storeCalls.length, 0);
});

test('POST /platform/orgs rejects invalid initial_owner_phone format', async () => {
  const harness = createHarness();
  const route = await dispatchApiRoute({
    pathname: '/platform/orgs',
    method: 'POST',
    requestId: 'req-platform-org-invalid-owner-phone-format',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      org_name: '组织 Invalid Phone',
      initial_owner_phone: '2380000000'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 400);
  assert.equal(route.headers['content-type'], 'application/problem+json');
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'ORG-400-INVALID-PAYLOAD');
  assert.match(payload.detail, /initial_owner_phone/);
  assert.equal(payload.request_id, 'req-platform-org-invalid-owner-phone-format');
  assert.equal(harness.storeCalls.length, 0);
});

test('POST /platform/orgs rejects initial_owner_phone with surrounding whitespace', async () => {
  const harness = createHarness();
  const route = await dispatchApiRoute({
    pathname: '/platform/orgs',
    method: 'POST',
    requestId: 'req-platform-org-invalid-owner-phone-whitespace',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      org_name: '组织 Invalid Phone Whitespace',
      initial_owner_phone: ' 13800000011 '
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 400);
  assert.equal(route.headers['content-type'], 'application/problem+json');
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'ORG-400-INVALID-PAYLOAD');
  assert.match(payload.detail, /initial_owner_phone/);
  assert.equal(payload.request_id, 'req-platform-org-invalid-owner-phone-whitespace');
  assert.equal(harness.storeCalls.length, 0);
});

test('POST /platform/orgs rejects non-string initial_owner_phone as invalid payload', async () => {
  const harness = createHarness();
  const route = await dispatchApiRoute({
    pathname: '/platform/orgs',
    method: 'POST',
    requestId: 'req-platform-org-invalid-owner-phone-type',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      org_name: '组织 Invalid Phone Type',
      initial_owner_phone: 13800000011
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 400);
  assert.equal(route.headers['content-type'], 'application/problem+json');
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'ORG-400-INVALID-PAYLOAD');
  assert.match(payload.detail, /initial_owner_phone/);
  assert.equal(payload.request_id, 'req-platform-org-invalid-owner-phone-type');
  assert.equal(harness.storeCalls.length, 0);
});

test('POST /platform/orgs rejects non-string org_name as invalid payload', async () => {
  const harness = createHarness();
  const route = await dispatchApiRoute({
    pathname: '/platform/orgs',
    method: 'POST',
    requestId: 'req-platform-org-invalid-org-name-type',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      org_name: 12345,
      initial_owner_phone: '13800000011'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 400);
  assert.equal(route.headers['content-type'], 'application/problem+json');
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'ORG-400-INVALID-PAYLOAD');
  assert.match(payload.detail, /org_name/);
  assert.equal(payload.request_id, 'req-platform-org-invalid-org-name-type');
  assert.equal(harness.storeCalls.length, 0);
});

test('POST /platform/orgs rejects org_name containing control characters', async () => {
  const harness = createHarness();
  const route = await dispatchApiRoute({
    pathname: '/platform/orgs',
    method: 'POST',
    requestId: 'req-platform-org-invalid-org-name-control-char',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      org_name: '组织\nInvalid Name',
      initial_owner_phone: '13800000011'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 400);
  assert.equal(route.headers['content-type'], 'application/problem+json');
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'ORG-400-INVALID-PAYLOAD');
  assert.match(payload.detail, /org_name/);
  assert.equal(payload.request_id, 'req-platform-org-invalid-org-name-control-char');
  assert.equal(harness.storeCalls.length, 0);
});

test('POST /platform/orgs rejects unknown payload fields to keep request contract strict', async () => {
  const harness = createHarness();
  const route = await dispatchApiRoute({
    pathname: '/platform/orgs',
    method: 'POST',
    requestId: 'req-platform-org-unknown-fields',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      org_name: '组织 Unknown',
      initial_owner_phone: '13800000009',
      unexpected_field: 'should-not-pass'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 400);
  assert.equal(route.headers['content-type'], 'application/problem+json');
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'ORG-400-INVALID-PAYLOAD');
  assert.match(payload.detail, /unexpected_field/);
  assert.equal(payload.request_id, 'req-platform-org-unknown-fields');
  assert.equal(harness.storeCalls.length, 0);
});

test('POST /platform/orgs bounds unknown-field detail length for oversized payloads', async () => {
  const harness = createHarness();
  const oversizedPayload = {
    org_name: '组织 Unknown Oversized',
    initial_owner_phone: '13800000009'
  };
  for (let index = 0; index < 20; index += 1) {
    oversizedPayload[`unexpected_field_${index}`] = `value_${index}`;
  }

  const route = await dispatchApiRoute({
    pathname: '/platform/orgs',
    method: 'POST',
    requestId: 'req-platform-org-unknown-fields-oversized',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: oversizedPayload,
    handlers: harness.handlers
  });

  assert.equal(route.status, 400);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'ORG-400-INVALID-PAYLOAD');
  assert.match(payload.detail, /包含未支持字段/);
  assert.match(payload.detail, /等 20 个字段/);
  assert.ok(payload.detail.length < 300);
});

test('POST /platform/orgs sanitizes unknown-field names in validation detail for oversized keys', async () => {
  const harness = createHarness();
  const oversizedUnknownKey = `unexpected_field_${'x'.repeat(600)}`;
  const route = await dispatchApiRoute({
    pathname: '/platform/orgs',
    method: 'POST',
    requestId: 'req-platform-org-unknown-field-oversized-key',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      org_name: '组织 Unknown Key Oversized',
      initial_owner_phone: '13800000029',
      [oversizedUnknownKey]: true
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 400);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'ORG-400-INVALID-PAYLOAD');
  assert.match(payload.detail, /包含未支持字段/);
  assert.ok(payload.detail.includes('unexpected_field_'));
  assert.ok(payload.detail.includes('...'));
  assert.equal(payload.detail.includes(oversizedUnknownKey), false);
  assert.ok(payload.detail.length <= 280);
});

test('POST /platform/orgs does not reserve Idempotency-Key on payload validation failure', async () => {
  const harness = createHarness();

  const first = await dispatchApiRoute({
    pathname: '/platform/orgs',
    method: 'POST',
    requestId: 'req-platform-org-idem-invalid-1',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-platform-org-invalid-001'
    },
    body: {
      org_name: '组织 幂等 无效载荷'
    },
    handlers: harness.handlers
  });
  const second = await dispatchApiRoute({
    pathname: '/platform/orgs',
    method: 'POST',
    requestId: 'req-platform-org-idem-invalid-2',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-platform-org-invalid-001'
    },
    body: {
      org_name: '组织 幂等 无效载荷',
      initial_owner_phone: '13800000010'
    },
    handlers: harness.handlers
  });

  assert.equal(first.status, 400);
  const firstPayload = JSON.parse(first.body);
  assert.equal(firstPayload.error_code, 'ORG-400-INITIAL-OWNER-PHONE-REQUIRED');

  assert.equal(second.status, 200);
  const secondPayload = JSON.parse(second.body);
  assert.equal(secondPayload.request_id, 'req-platform-org-idem-invalid-2');
  assert.equal(harness.storeCalls.length, 1);
});

test('POST /platform/orgs succeeds and reuses existing owner user identity', async () => {
  const harness = createHarness({
    getOrCreateUserIdentityByPhone: async ({ phone }) => ({
      user_id: 'owner-user-existing',
      phone,
      created_user: false,
      reused_existing_user: true,
      credential_initialized: false,
      first_login_force_password_change: false
    }),
    createOrganizationWithOwner: async ({ orgId, ownerUserId }) => ({
      org_id: orgId,
      owner_user_id: ownerUserId
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/orgs',
    method: 'POST',
    requestId: 'req-platform-org-reuse-owner',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      org_name: '组织 B',
      initial_owner_phone: '13800000001'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 200);
  const payload = JSON.parse(route.body);
  assert.equal(payload.org_id, harness.storeCalls[0].orgId);
  assert.equal(payload.owner_user_id, 'owner-user-existing');
  assert.equal(payload.reused_existing_user, true);
  assert.equal(payload.created_owner_user, false);
  assert.equal(payload.request_id, 'req-platform-org-reuse-owner');
  assert.equal(harness.storeCalls[0].ownerUserId, 'owner-user-existing');
  assert.equal(harness.authorizeCalls.length, 1);
});

test('POST /platform/orgs succeeds and creates owner user identity when phone is new', async () => {
  const harness = createHarness({
    getOrCreateUserIdentityByPhone: async ({ phone }) => ({
      user_id: 'owner-user-created',
      phone,
      created_user: true,
      reused_existing_user: false,
      credential_initialized: true,
      first_login_force_password_change: false
    }),
    createOrganizationWithOwner: async ({ orgId, ownerUserId }) => ({
      org_id: orgId,
      owner_user_id: ownerUserId
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/orgs',
    method: 'POST',
    requestId: 'req-platform-org-create-owner',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      org_name: '组织 C',
      initial_owner_phone: '13800000002'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 200);
  const payload = JSON.parse(route.body);
  assert.equal(payload.owner_user_id, 'owner-user-created');
  assert.equal(payload.created_owner_user, true);
  assert.equal(payload.reused_existing_user, false);
  assert.equal(payload.request_id, 'req-platform-org-create-owner');
});

test('POST /platform/orgs is blocked when current session lacks platform permission context', async () => {
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
    pathname: '/platform/orgs',
    method: 'POST',
    requestId: 'req-platform-org-forbidden',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      org_name: '组织 D',
      initial_owner_phone: '13800000003'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 403);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-403-FORBIDDEN');
});

test('POST /platform/orgs fails closed when authorizeRoute does not resolve operator identifiers', async () => {
  const harness = createHarness({
    authorizeRoute: async () => ({
      user_id: '',
      session_id: '',
      entry_domain: 'platform',
      active_tenant_id: null
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/orgs',
    method: 'POST',
    requestId: 'req-platform-org-missing-operator-context',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      org_name: '组织 Missing Operator Context',
      initial_owner_phone: '13800000033'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 403);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-403-FORBIDDEN');
  assert.equal(harness.storeCalls.length, 0);
  const lastAuditEvent = harness.platformOrgService._internals.auditTrail.at(-1);
  assert.equal(lastAuditEvent.type, 'org.create.rejected');
  assert.equal(lastAuditEvent.request_id, 'req-platform-org-missing-operator-context');
  assert.equal(lastAuditEvent.error_code, 'AUTH-403-FORBIDDEN');
});

test('POST /platform/orgs maps duplicate organization conflict to ORG-409-ORG-CONFLICT', async () => {
  const harness = createHarness({
    createOrganizationWithOwner: async () => {
      const duplicateError = new Error('duplicate org');
      duplicateError.code = 'ER_DUP_ENTRY';
      duplicateError.errno = 1062;
      throw duplicateError;
    }
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/orgs',
    method: 'POST',
    requestId: 'req-platform-org-duplicate',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      org_name: '组织 E',
      initial_owner_phone: '13800000005'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 409);
  assert.equal(route.headers['content-type'], 'application/problem+json');
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'ORG-409-ORG-CONFLICT');
  assert.equal(payload.retryable, false);
  assert.equal(payload.request_id, 'req-platform-org-duplicate');
});

test('POST /platform/orgs replays first success response for same Idempotency-Key and payload', async () => {
  const harness = createHarness();
  const requestBody = {
    org_name: '组织 幂等 Replay',
    initial_owner_phone: '13800000015'
  };

  const first = await dispatchApiRoute({
    pathname: '/platform/orgs',
    method: 'POST',
    requestId: 'req-platform-org-idem-replay-1',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-platform-org-replay-001'
    },
    body: requestBody,
    handlers: harness.handlers
  });
  const second = await dispatchApiRoute({
    pathname: '/platform/orgs',
    method: 'POST',
    requestId: 'req-platform-org-idem-replay-2',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-platform-org-replay-001'
    },
    body: requestBody,
    handlers: harness.handlers
  });

  assert.equal(first.status, 200);
  assert.equal(second.status, 200);
  assert.equal(harness.storeCalls.length, 1);

  const firstPayload = JSON.parse(first.body);
  const secondPayload = JSON.parse(second.body);
  assert.equal(secondPayload.org_id, firstPayload.org_id);
  assert.equal(secondPayload.owner_user_id, firstPayload.owner_user_id);
  assert.equal(secondPayload.request_id, 'req-platform-org-idem-replay-2');
});

test('POST /platform/orgs replays first success response across sessions even when tenant context changes', async () => {
  let sessionSequence = 0;
  const harness = createHarness({
    authorizeRoute: async () => {
      sessionSequence += 1;
      return {
        user_id: 'platform-operator',
        session_id: `platform-session-${sessionSequence}`,
        entry_domain: 'platform',
        active_tenant_id: sessionSequence === 1 ? 'tenant-a' : 'tenant-b'
      };
    }
  });
  const requestBody = {
    org_name: '组织 幂等 跨会话',
    initial_owner_phone: '13800000017'
  };

  const first = await dispatchApiRoute({
    pathname: '/platform/orgs',
    method: 'POST',
    requestId: 'req-platform-org-idem-cross-session-1',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-platform-org-cross-session-001'
    },
    body: requestBody,
    handlers: harness.handlers
  });
  const second = await dispatchApiRoute({
    pathname: '/platform/orgs',
    method: 'POST',
    requestId: 'req-platform-org-idem-cross-session-2',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-platform-org-cross-session-001'
    },
    body: requestBody,
    handlers: harness.handlers
  });

  assert.equal(first.status, 200);
  assert.equal(second.status, 200);
  assert.equal(harness.storeCalls.length, 1);
  assert.equal(harness.authorizeCalls.length, 2);

  const firstPayload = JSON.parse(first.body);
  const secondPayload = JSON.parse(second.body);
  assert.equal(secondPayload.org_id, firstPayload.org_id);
  assert.equal(secondPayload.owner_user_id, firstPayload.owner_user_id);
  assert.equal(secondPayload.request_id, 'req-platform-org-idem-cross-session-2');
});

test('POST /platform/orgs rejects same Idempotency-Key with different payloads', async () => {
  const harness = createHarness();

  const first = await dispatchApiRoute({
    pathname: '/platform/orgs',
    method: 'POST',
    requestId: 'req-platform-org-idem-conflict-1',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-platform-org-conflict-001'
    },
    body: {
      org_name: '组织 幂等 冲突 A',
      initial_owner_phone: '13800000016'
    },
    handlers: harness.handlers
  });
  const second = await dispatchApiRoute({
    pathname: '/platform/orgs',
    method: 'POST',
    requestId: 'req-platform-org-idem-conflict-2',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-platform-org-conflict-001'
    },
    body: {
      org_name: '组织 幂等 冲突 B',
      initial_owner_phone: '13800000016'
    },
    handlers: harness.handlers
  });

  assert.equal(first.status, 200);
  assert.equal(second.status, 409);
  assert.equal(harness.storeCalls.length, 1);
  const payload = JSON.parse(second.body);
  assert.equal(payload.error_code, 'AUTH-409-IDEMPOTENCY-CONFLICT');
  assert.equal(payload.request_id, 'req-platform-org-idem-conflict-2');
  assert.equal(payload.retryable, false);
});

test('POST /platform/orgs returns AUTH-503-IDEMPOTENCY-STORE-UNAVAILABLE when idempotency store is unavailable', async () => {
  const harness = createHarness({
    authIdempotencyStore: {
      claimOrRead: async () => {
        throw new Error('idempotency-store-down');
      },
      read: async () => null,
      resolve: async () => {},
      releasePending: async () => {}
    }
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/orgs',
    method: 'POST',
    requestId: 'req-platform-org-idem-store-unavailable',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-platform-org-store-unavailable-001'
    },
    body: {
      org_name: '组织 幂等 存储不可用',
      initial_owner_phone: '13800000036'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 503);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-503-IDEMPOTENCY-STORE-UNAVAILABLE');
  assert.equal(payload.degradation_reason, 'idempotency-store-unavailable');
  assert.equal(harness.storeCalls.length, 0);
  assert.equal(harness.idempotencyEvents.length, 1);
  assert.equal(harness.idempotencyEvents[0].outcome, 'store_unavailable');
  assert.equal(harness.idempotencyEvents[0].routeKey, 'POST /platform/orgs');
});

test('POST /platform/orgs returns AUTH-503-IDEMPOTENCY-STORE-UNAVAILABLE when existing replay entry is corrupted', async () => {
  const harness = createHarness({
    authIdempotencyStore: {
      claimOrRead: async () => ({
        action: 'existing',
        entry: null
      }),
      read: async () => null,
      resolve: async () => {},
      releasePending: async () => {}
    }
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/orgs',
    method: 'POST',
    requestId: 'req-platform-org-idem-corrupted-entry',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-platform-org-corrupted-entry-001'
    },
    body: {
      org_name: '组织 幂等 异常缓存',
      initial_owner_phone: '13800000039'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 503);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-503-IDEMPOTENCY-STORE-UNAVAILABLE');
  assert.equal(payload.degradation_reason, 'idempotency-store-unavailable');
  assert.equal(harness.storeCalls.length, 0);
  assert.equal(harness.idempotencyEvents.length, 1);
  assert.equal(harness.idempotencyEvents[0].outcome, 'store_unavailable');
  assert.equal(
    harness.idempotencyEvents[0].metadata?.degradation_reason,
    'idempotency-store-corrupted-entry'
  );
  assert.equal(
    harness.idempotencyEvents[0].metadata?.idempotency_stage,
    'claim-or-read'
  );
  assert.equal(harness.idempotencyEvents[0].routeKey, 'POST /platform/orgs');
});

test('POST /platform/orgs returns AUTH-503-IDEMPOTENCY-STORE-UNAVAILABLE when existing replay entry has invalid request hash', async () => {
  const harness = createHarness({
    authIdempotencyStore: {
      claimOrRead: async () => ({
        action: 'existing',
        entry: {
          state: 'pending',
          requestHash: ''
        }
      }),
      read: async () => null,
      resolve: async () => {},
      releasePending: async () => {}
    }
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/orgs',
    method: 'POST',
    requestId: 'req-platform-org-idem-corrupted-entry-request-hash',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-platform-org-corrupted-entry-request-hash-001'
    },
    body: {
      org_name: '组织 幂等 异常 hash',
      initial_owner_phone: '13800000078'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 503);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-503-IDEMPOTENCY-STORE-UNAVAILABLE');
  assert.equal(payload.degradation_reason, 'idempotency-store-unavailable');
  assert.equal(harness.storeCalls.length, 0);
  assert.equal(harness.idempotencyEvents.length, 1);
  assert.equal(harness.idempotencyEvents[0].outcome, 'store_unavailable');
  assert.equal(
    harness.idempotencyEvents[0].metadata?.degradation_reason,
    'idempotency-store-corrupted-entry'
  );
  assert.equal(
    harness.idempotencyEvents[0].metadata?.idempotency_stage,
    'claim-or-read'
  );
  assert.equal(harness.idempotencyEvents[0].routeKey, 'POST /platform/orgs');
});

test('POST /platform/orgs returns AUTH-503-IDEMPOTENCY-STORE-UNAVAILABLE when pending replay entry disappears', async () => {
  let claimCalls = 0;
  let readCalls = 0;
  const harness = createHarness({
    authIdempotencyStore: {
      claimOrRead: async ({ requestHash }) => {
        claimCalls += 1;
        return {
          action: 'existing',
          entry: {
            state: 'pending',
            requestHash
          }
        };
      },
      read: async () => {
        readCalls += 1;
        return null;
      },
      resolve: async () => {},
      releasePending: async () => {}
    }
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/orgs',
    method: 'POST',
    requestId: 'req-platform-org-idem-pending-timeout',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-platform-org-pending-timeout-001'
    },
    body: {
      org_name: '组织 幂等 超时',
      initial_owner_phone: '13800000037'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 503);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-503-IDEMPOTENCY-STORE-UNAVAILABLE');
  assert.equal(payload.degradation_reason, 'idempotency-store-unavailable');
  assert.equal(claimCalls, 1);
  assert.equal(readCalls, 1);
  assert.equal(harness.storeCalls.length, 0);
  assert.equal(harness.idempotencyEvents.length, 1);
  assert.equal(harness.idempotencyEvents[0].outcome, 'store_unavailable');
  assert.equal(
    harness.idempotencyEvents[0].metadata?.degradation_reason,
    'idempotency-store-entry-missing'
  );
  assert.equal(
    harness.idempotencyEvents[0].metadata?.idempotency_stage,
    'wait-for-resolved'
  );
  assert.equal(harness.idempotencyEvents[0].routeKey, 'POST /platform/orgs');
});

test('POST /platform/orgs returns AUTH-503-IDEMPOTENCY-PENDING-TIMEOUT when replay stays pending until timeout', async () => {
  let claimCalls = 0;
  let readCalls = 0;
  let pendingRequestHash = '';
  const originalDateNow = Date.now;
  let dateNowCalls = 0;

  try {
    Date.now = () => {
      dateNowCalls += 1;
      if (dateNowCalls <= 2) {
        return 0;
      }
      return 6001;
    };

    const harness = createHarness({
      authIdempotencyStore: {
        claimOrRead: async ({ requestHash }) => {
          claimCalls += 1;
          pendingRequestHash = requestHash;
          return {
            action: 'existing',
            entry: {
              state: 'pending',
              requestHash
            }
          };
        },
        read: async () => {
          readCalls += 1;
          return {
            state: 'pending',
            requestHash: pendingRequestHash
          };
        },
        resolve: async () => {},
        releasePending: async () => {}
      }
    });

    const route = await dispatchApiRoute({
      pathname: '/platform/orgs',
      method: 'POST',
      requestId: 'req-platform-org-idem-pending-timeout',
      headers: {
        authorization: 'Bearer fake-access-token',
        'idempotency-key': 'idem-platform-org-pending-timeout-001'
      },
      body: {
        org_name: '组织 幂等 超时',
        initial_owner_phone: '13800000037'
      },
      handlers: harness.handlers
    });

    assert.equal(route.status, 503);
    const payload = JSON.parse(route.body);
    assert.equal(payload.error_code, 'AUTH-503-IDEMPOTENCY-PENDING-TIMEOUT');
    assert.equal(payload.degradation_reason, 'idempotency-pending-timeout');
    assert.equal(claimCalls, 1);
    assert.equal(readCalls, 1);
    assert.equal(harness.storeCalls.length, 0);
    assert.equal(harness.idempotencyEvents.length, 1);
    assert.equal(harness.idempotencyEvents[0].outcome, 'pending_timeout');
    assert.equal(harness.idempotencyEvents[0].routeKey, 'POST /platform/orgs');
  } finally {
    Date.now = originalDateNow;
  }
});

test('POST /platform/orgs maps unexpected org-store failure to ORG-503-DEPENDENCY-UNAVAILABLE', async () => {
  const harness = createHarness({
    createOrganizationWithOwner: async () => {
      throw new Error('mysql-connection-lost');
    }
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/orgs',
    method: 'POST',
    requestId: 'req-platform-org-store-dependency-failure',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      org_name: '组织 F',
      initial_owner_phone: '13800000006'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 503);
  assert.equal(route.headers['content-type'], 'application/problem+json');
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'ORG-503-DEPENDENCY-UNAVAILABLE');
  assert.equal(payload.retryable, true);
  assert.equal(payload.request_id, 'req-platform-org-store-dependency-failure');
  assert.equal(harness.rollbackCalls.length, 0);
});

test('POST /platform/orgs rolls back newly created owner identity when org creation fails after owner bootstrap', async () => {
  const harness = createHarness({
    getOrCreateUserIdentityByPhone: async ({ phone }) => ({
      user_id: 'owner-user-created-for-rollback',
      phone,
      created_user: true,
      reused_existing_user: false,
      credential_initialized: true,
      first_login_force_password_change: false
    }),
    createOrganizationWithOwner: async () => {
      const duplicateError = new Error('duplicate org');
      duplicateError.code = 'ER_DUP_ENTRY';
      duplicateError.errno = 1062;
      throw duplicateError;
    }
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/orgs',
    method: 'POST',
    requestId: 'req-platform-org-rollback-owner-identity',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      org_name: '组织 G',
      initial_owner_phone: '13800000007'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 409);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'ORG-409-ORG-CONFLICT');
  assert.equal(harness.rollbackCalls.length, 1);
  assert.deepEqual(harness.rollbackCalls[0], {
    requestId: 'req-platform-org-rollback-owner-identity',
    userId: 'owner-user-created-for-rollback'
  });
});

test('POST /platform/orgs rolls back newly created owner identity on storage length errors and returns ORG-400-INVALID-PAYLOAD', async () => {
  const harness = createHarness({
    getOrCreateUserIdentityByPhone: async ({ phone }) => ({
      user_id: 'owner-user-created-data-too-long',
      phone,
      created_user: true,
      reused_existing_user: false,
      credential_initialized: true,
      first_login_force_password_change: false
    }),
    createOrganizationWithOwner: async () => {
      const tooLongError = new Error('Data too long for column');
      tooLongError.code = 'ER_DATA_TOO_LONG';
      tooLongError.errno = 1406;
      throw tooLongError;
    }
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/orgs',
    method: 'POST',
    requestId: 'req-platform-org-rollback-owner-data-too-long',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      org_name: '组织长度异常',
      initial_owner_phone: '13800000019'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 400);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'ORG-400-INVALID-PAYLOAD');
  assert.equal(harness.rollbackCalls.length, 1);
  assert.deepEqual(harness.rollbackCalls[0], {
    requestId: 'req-platform-org-rollback-owner-data-too-long',
    userId: 'owner-user-created-data-too-long'
  });
});

test('POST /platform/orgs fails closed when rollback capability is unavailable', async () => {
  const harness = createHarness({
    includeRollbackProvisionedUserIdentity: false
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/orgs',
    method: 'POST',
    requestId: 'req-platform-org-rollback-capability-missing',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      org_name: '组织 缺少回滚能力',
      initial_owner_phone: '13800000041'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 503);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'ORG-503-DEPENDENCY-UNAVAILABLE');
  assert.equal(harness.authorizeCalls.length, 1);
  assert.equal(harness.storeCalls.length, 0);
  assert.equal(harness.rollbackCalls.length, 0);
});

test('POST /platform/orgs fails closed when owner rollback fails after org storage failure', async () => {
  const harness = createHarness({
    getOrCreateUserIdentityByPhone: async ({ phone }) => ({
      user_id: 'owner-user-created-rollback-failure',
      phone,
      created_user: true,
      reused_existing_user: false,
      credential_initialized: true,
      first_login_force_password_change: false
    }),
    createOrganizationWithOwner: async () => {
      const duplicateError = new Error('duplicate org with rollback failure');
      duplicateError.code = 'ER_DUP_ENTRY';
      duplicateError.errno = 1062;
      throw duplicateError;
    },
    rollbackProvisionedUserIdentity: async () => {
      throw new Error('rollback-failed');
    }
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/orgs',
    method: 'POST',
    requestId: 'req-platform-org-rollback-failure',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      org_name: '组织 回滚失败',
      initial_owner_phone: '13800000042'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 503);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'ORG-503-DEPENDENCY-UNAVAILABLE');
  assert.equal(harness.storeCalls.length, 1);
  assert.equal(harness.rollbackCalls.length, 1);
  const lastAuditEvent = harness.platformOrgService._internals.auditTrail.at(-1);
  assert.equal(lastAuditEvent.type, 'org.create.rejected');
  assert.match(lastAuditEvent.detail, /rollback failed/);
});

test('platformCreateOrg maps owner bootstrap 503 errors to ORG-503-DEPENDENCY-UNAVAILABLE', async () => {
  const harness = createHarness({
    getOrCreateUserIdentityByPhone: async () => {
      throw new AuthProblemError({
        status: 503,
        title: 'Service Unavailable',
        detail: 'default password config unavailable',
        errorCode: 'AUTH-503-PROVISION-CONFIG-UNAVAILABLE',
        extensions: { retryable: true }
      });
    }
  });

  await assert.rejects(
    () =>
      harness.handlers.platformCreateOrg(
        'req-platform-org-owner-bootstrap-503',
        'Bearer fake-access-token',
        {
          org_name: '组织 H',
          initial_owner_phone: '13800000008'
        }
      ),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'ORG-503-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
  assert.equal(harness.authorizeCalls.length, 1);
  assert.equal(harness.storeCalls.length, 0);
});

test('platformCreateOrg maps owner bootstrap non-409 auth problems to ORG-503-DEPENDENCY-UNAVAILABLE', async () => {
  const harness = createHarness({
    getOrCreateUserIdentityByPhone: async () => {
      throw new AuthProblemError({
        status: 400,
        title: 'Bad Request',
        detail: 'downstream payload rejected',
        errorCode: 'AUTH-400-INVALID-PAYLOAD'
      });
    }
  });

  await assert.rejects(
    () =>
      harness.handlers.platformCreateOrg(
        'req-platform-org-owner-bootstrap-400',
        'Bearer fake-access-token',
        {
          org_name: '组织 H-400',
          initial_owner_phone: '13800000012'
        }
      ),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'ORG-503-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
  assert.equal(harness.authorizeCalls.length, 1);
  assert.equal(harness.storeCalls.length, 0);
});

test('platformCreateOrg maps owner bootstrap 409 conflicts to ORG-409-ORG-CONFLICT', async () => {
  const harness = createHarness({
    getOrCreateUserIdentityByPhone: async () => {
      throw new AuthProblemError({
        status: 409,
        title: 'Conflict',
        detail: 'user provisioning conflict',
        errorCode: 'AUTH-409-PROVISION-CONFLICT'
      });
    }
  });

  await assert.rejects(
    () =>
      harness.handlers.platformCreateOrg(
        'req-platform-org-owner-bootstrap-409',
        'Bearer fake-access-token',
        {
          org_name: '组织 I',
          initial_owner_phone: '13800000018'
        }
      ),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 409);
      assert.equal(error.errorCode, 'ORG-409-ORG-CONFLICT');
      return true;
    }
  );
  assert.equal(harness.authorizeCalls.length, 1);
  assert.equal(harness.storeCalls.length, 0);
});

test('platformCreateOrg records rejection audit when owner bootstrap auth problem is normalized to dependency unavailable', async () => {
  const harness = createHarness({
    getOrCreateUserIdentityByPhone: async () => {
      throw new AuthProblemError({
        status: 400,
        title: 'Bad Request',
        detail: 'upstream invalid payload',
        errorCode: 'AUTH-400-INVALID-PAYLOAD'
      });
    }
  });

  await assert.rejects(
    () =>
      harness.handlers.platformCreateOrg(
        'req-platform-org-owner-bootstrap-authproblem-normalized',
        'Bearer fake-access-token',
        {
          org_name: '组织 I-1',
          initial_owner_phone: '13800000042'
        }
      ),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'ORG-503-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );

  assert.equal(harness.authorizeCalls.length, 1);
  assert.equal(harness.storeCalls.length, 0);
  const lastAuditEvent = harness.platformOrgService._internals.auditTrail.at(-1);
  assert.equal(lastAuditEvent.type, 'org.create.rejected');
  assert.equal(lastAuditEvent.request_id, 'req-platform-org-owner-bootstrap-authproblem-normalized');
  assert.equal(lastAuditEvent.error_code, 'ORG-503-DEPENDENCY-UNAVAILABLE');
  assert.equal(lastAuditEvent.upstream_error_code, 'AUTH-400-INVALID-PAYLOAD');
});

test('platformCreateOrg resolves operator context before payload validation when no preauthorized context is provided', async () => {
  const harness = createHarness();

  await assert.rejects(
    () =>
      harness.handlers.platformCreateOrg(
        'req-platform-org-direct-invalid-payload',
        'Bearer fake-access-token',
        {
          org_name: '组织 J'
        }
      ),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 400);
      assert.equal(error.errorCode, 'ORG-400-INITIAL-OWNER-PHONE-REQUIRED');
      return true;
    }
  );

  assert.equal(harness.authorizeCalls.length, 1);
  const lastAuditEvent = harness.platformOrgService._internals.auditTrail.at(-1);
  assert.equal(lastAuditEvent.type, 'org.create.rejected');
  assert.equal(lastAuditEvent.request_id, 'req-platform-org-direct-invalid-payload');
  assert.equal(lastAuditEvent.operator_user_id, 'platform-operator');
});

test('platformCreateOrg does not trust forged preauthorized context without internal marker', async () => {
  const harness = createHarness({
    authorizeRoute: async () => ({
      user_id: 'trusted-platform-operator',
      session_id: 'trusted-platform-session',
      entry_domain: 'platform',
      active_tenant_id: null
    })
  });

  const response = await harness.handlers.platformCreateOrg(
    'req-platform-org-forged-preauth-context',
    'Bearer fake-access-token',
    {
      org_name: '组织 K',
      initial_owner_phone: '13800000021'
    },
    {
      entry_domain: 'platform',
      user_id: 'forged-operator',
      session_id: 'forged-session'
    }
  );

  assert.equal(response.request_id, 'req-platform-org-forged-preauth-context');
  assert.equal(harness.authorizeCalls.length, 1);
  assert.equal(harness.storeCalls.length, 1);
  assert.equal(harness.storeCalls[0].operatorUserId, 'trusted-platform-operator');
});

test('platformCreateOrg falls back to bearer authorization when preauthorized context marker is incomplete', async () => {
  const harness = createHarness({
    authorizeRoute: async () => ({
      user_id: 'trusted-platform-operator',
      session_id: 'trusted-platform-session',
      entry_domain: 'platform',
      active_tenant_id: null
    })
  });

  const response = await harness.handlers.platformCreateOrg(
    'req-platform-org-incomplete-preauth-context',
    'Bearer fake-access-token',
    {
      org_name: '组织 K-1',
      initial_owner_phone: '13800000032'
    },
    {
      ...markRoutePreauthorizedContext({
        authorizationContext: {
          entry_domain: 'platform',
          user_id: 'forged-operator',
          session_id: 'forged-session'
        },
        permissionCode: 'platform.member_admin.view',
        scope: 'platform'
      })
    }
  );

  assert.equal(response.request_id, 'req-platform-org-incomplete-preauth-context');
  assert.equal(harness.authorizeCalls.length, 1);
  assert.equal(harness.storeCalls.length, 1);
  assert.equal(harness.storeCalls[0].operatorUserId, 'trusted-platform-operator');
});

test('platformCreateOrg accepts marked preauthorized context without Authorization header', async () => {
  const harness = createHarness();
  const response = await harness.handlers.platformCreateOrg(
    'req-platform-org-marked-preauth-no-auth-header',
    undefined,
    {
      org_name: '组织 Preauth No Header',
      initial_owner_phone: '13800000023'
    },
    {
      ...markRoutePreauthorizedContext({
        authorizationContext: {
          entry_domain: 'platform',
          user_id: 'platform-operator',
          session_id: 'platform-session'
        },
        permissionCode: 'platform.member_admin.operate',
        scope: 'platform'
      })
    }
  );

  assert.equal(response.request_id, 'req-platform-org-marked-preauth-no-auth-header');
  assert.equal(harness.authorizeCalls.length, 0);
  assert.equal(harness.storeCalls.length, 1);
});

test('platformCreateOrg accepts marked preauthorized context even when Authorization header is malformed', async () => {
  const harness = createHarness();
  const response = await harness.handlers.platformCreateOrg(
    'req-platform-org-marked-preauth-bad-auth-header',
    'Basic malformed-header',
    {
      org_name: '组织 Preauth Bad Header',
      initial_owner_phone: '13800000024'
    },
    {
      ...markRoutePreauthorizedContext({
        authorizationContext: {
          entry_domain: 'platform',
          user_id: 'platform-operator',
          session_id: 'platform-session'
        },
        permissionCode: 'platform.member_admin.operate',
        scope: 'platform'
      })
    }
  );

  assert.equal(response.request_id, 'req-platform-org-marked-preauth-bad-auth-header');
  assert.equal(harness.authorizeCalls.length, 0);
  assert.equal(harness.storeCalls.length, 1);
});

test('platformCreateOrg does not trust forged Symbol.for preauthorization marker', async () => {
  const harness = createHarness({
    authorizeRoute: async () => ({
      user_id: 'trusted-platform-operator',
      session_id: 'trusted-platform-session',
      entry_domain: 'platform',
      active_tenant_id: null
    })
  });

  const response = await harness.handlers.platformCreateOrg(
    'req-platform-org-forged-symbolfor-preauth-context',
    'Bearer fake-access-token',
    {
      org_name: '组织 K-2',
      initial_owner_phone: '13800000031'
    },
    {
      [Symbol.for('neweast.auth.route.preauthorized')]: true,
      [Symbol.for('neweast.auth.route.permission_code')]: 'platform.member_admin.operate',
      [Symbol.for('neweast.auth.route.scope')]: 'platform',
      entry_domain: 'platform',
      user_id: 'forged-operator',
      session_id: 'forged-session'
    }
  );

  assert.equal(response.request_id, 'req-platform-org-forged-symbolfor-preauth-context');
  assert.equal(harness.authorizeCalls.length, 1);
  assert.equal(harness.storeCalls.length, 1);
  assert.equal(harness.storeCalls[0].operatorUserId, 'trusted-platform-operator');
});

test('platformCreateOrg keeps audit trail bounded to avoid unbounded memory growth', async () => {
  const harness = createHarness();
  const totalAttempts = 230;
  const auditTrailLimit = 200;

  for (let index = 0; index < totalAttempts; index += 1) {
    const response = await dispatchApiRoute({
      pathname: '/platform/orgs',
      method: 'POST',
      requestId: `req-platform-org-audit-cap-${index}`,
      headers: {
        authorization: 'Bearer fake-access-token'
      },
      body: {
        org_name: `组织审计容量-${index}`
      },
      handlers: harness.handlers
    });
    assert.equal(response.status, 400);
  }

  const auditTrail = harness.platformOrgService._internals.auditTrail;
  assert.equal(auditTrail.length, auditTrailLimit);
  assert.equal(
    auditTrail[0].request_id,
    `req-platform-org-audit-cap-${totalAttempts - auditTrailLimit}`
  );
  assert.equal(auditTrail.at(-1).request_id, `req-platform-org-audit-cap-${totalAttempts - 1}`);
});
