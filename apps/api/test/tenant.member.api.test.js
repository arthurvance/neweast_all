const test = require('node:test');
const assert = require('node:assert/strict');
const { createRouteHandlers } = require('../src/http-routes');
const { createTenantMemberHandlers } = require('../src/modules/tenant/member.routes');
const { createTenantMemberService } = require('../src/modules/tenant/member.service');
const { dispatchApiRoute } = require('../src/server');
const { readConfig } = require('../src/config/env');
const { AuthProblemError } = require('../src/modules/auth/auth.routes');

const config = readConfig({ ALLOW_MOCK_BACKENDS: 'true' });
const dependencyProbe = async () => ({
  db: { ok: true },
  redis: { ok: true }
});

const assertSamePayloadWithFreshRequestId = (actualPayload, expectedPayload) => {
  assert.ok(actualPayload.request_id);
  assert.ok(expectedPayload.request_id);
  assert.notEqual(actualPayload.request_id, expectedPayload.request_id);
  const { request_id: _actualRequestId, ...actualWithoutRequestId } = actualPayload;
  const { request_id: _expectedRequestId, ...expectedWithoutRequestId } = expectedPayload;
  assert.deepEqual(actualWithoutRequestId, expectedWithoutRequestId);
};

const createHarness = ({
  authorizeRoute = async () => ({
    user_id: 'tenant-operator',
    session_id: 'tenant-session',
    entry_domain: 'tenant',
    active_tenant_id: 'tenant-a'
  }),
  listTenantMembers = async ({ tenantId }) => [
    {
      membership_id: 'membership-a1',
      user_id: 'tenant-user-a1',
      tenant_id: tenantId,
      tenant_name: 'Tenant A',
      phone: '13800000001',
      status: 'active',
      joined_at: '2026-02-18T00:00:00.000Z',
      left_at: null
    }
  ],
  provisionTenantUserByPhone = async ({ requestId }) => ({
    user_id: 'tenant-user-created',
    created_user: true,
    reused_existing_user: false,
    request_id: requestId
  }),
  findTenantMembershipByUserAndTenantId = async ({ userId, tenantId }) => ({
    membership_id: 'membership-created',
    user_id: userId,
    tenant_id: tenantId,
    tenant_name: 'Tenant A',
    phone: '13800000022',
    status: 'active',
    joined_at: '2026-02-18T00:00:00.000Z',
    left_at: null
  }),
  updateTenantMemberStatus = async ({ membershipId, nextStatus }) => ({
    membership_id: membershipId,
    user_id: 'tenant-user-target',
    tenant_id: 'tenant-a',
    previous_status: nextStatus === 'active' ? 'disabled' : 'active',
    current_status: nextStatus
  }),
  listTenantMemberRoleBindings = async ({ membershipId }) => ({
    membership_id: membershipId,
    role_ids: ['tenant_member']
  }),
  replaceTenantMemberRoleBindings = async ({ membershipId, roleIds }) => ({
    membership_id: membershipId,
    role_ids: roleIds
  }),
  recordIdempotencyEvent = async () => {},
  authIdempotencyStore = null
} = {}) => {
  const authorizeCalls = [];
  const listCalls = [];
  const provisionCalls = [];
  const findMembershipCalls = [];
  const statusCalls = [];
  const roleBindingReadCalls = [];
  const roleBindingWriteCalls = [];
  const idempotencyEvents = [];

  const authService = {
    authorizeRoute: async (payload) => {
      authorizeCalls.push(payload);
      return authorizeRoute(payload);
    },
    listTenantMembers: async (payload) => {
      listCalls.push(payload);
      return listTenantMembers(payload);
    },
    provisionTenantUserByPhone: async (payload) => {
      provisionCalls.push(payload);
      return provisionTenantUserByPhone(payload);
    },
    findTenantMembershipByUserAndTenantId: async (payload) => {
      findMembershipCalls.push(payload);
      return findTenantMembershipByUserAndTenantId(payload);
    },
    updateTenantMemberStatus: async (payload) => {
      statusCalls.push(payload);
      return updateTenantMemberStatus(payload);
    },
    listTenantMemberRoleBindings: async (payload) => {
      roleBindingReadCalls.push(payload);
      return listTenantMemberRoleBindings(payload);
    },
    replaceTenantMemberRoleBindings: async (payload) => {
      roleBindingWriteCalls.push(payload);
      return replaceTenantMemberRoleBindings(payload);
    },
    recordIdempotencyEvent: async (payload) => {
      idempotencyEvents.push(payload);
      return recordIdempotencyEvent(payload);
    },
    _internals: {
      auditTrail: []
    }
  };

  const tenantMemberService = createTenantMemberService({
    authService
  });
  const handlers = createRouteHandlers(config, {
    dependencyProbe,
    authService,
    tenantMemberService,
    authIdempotencyStore
  });

  return {
    handlers,
    tenantMemberService,
    authorizeCalls,
    listCalls,
    provisionCalls,
    findMembershipCalls,
    statusCalls,
    roleBindingReadCalls,
    roleBindingWriteCalls,
    idempotencyEvents
  };
};

test('createTenantMemberHandlers fails fast when tenant member service capability is missing', () => {
  assert.throws(
    () => createTenantMemberHandlers(),
    /requires a tenantMemberService with listMembers, createMember, updateMemberStatus, getMemberRoles and replaceMemberRoles/
  );
  assert.throws(
    () => createTenantMemberHandlers({}),
    /requires a tenantMemberService with listMembers, createMember, updateMemberStatus, getMemberRoles and replaceMemberRoles/
  );
});

test('GET /tenant/members lists members in active tenant scope', async () => {
  const harness = createHarness();

  const route = await dispatchApiRoute({
    pathname: '/tenant/members',
    method: 'GET',
    requestId: 'req-tenant-member-list',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 200);
  const payload = JSON.parse(route.body);
  assert.equal(payload.tenant_id, 'tenant-a');
  assert.equal(payload.page, 1);
  assert.equal(payload.page_size, 50);
  assert.equal(payload.request_id, 'req-tenant-member-list');
  assert.equal(payload.members.length, 1);
  assert.equal(payload.members[0].membership_id, 'membership-a1');
  assert.equal(payload.members[0].tenant_id, 'tenant-a');
  assert.equal(harness.authorizeCalls.length, 1);
  assert.equal(harness.authorizeCalls[0].permissionCode, 'tenant.member_admin.view');
  assert.equal(harness.authorizeCalls[0].scope, 'tenant');
  assert.equal(harness.listCalls.length, 1);
  assert.equal(harness.listCalls[0].tenantId, 'tenant-a');
  assert.equal(harness.listCalls[0].page, 1);
  assert.equal(harness.listCalls[0].pageSize, 50);
});

test('GET /tenant/members accepts camelCase authorization context and avoids duplicate authorizeRoute calls', async () => {
  const harness = createHarness({
    authorizeRoute: async () => ({
      userId: 'tenant-operator-camel',
      sessionId: 'tenant-session-camel',
      entryDomain: 'tenant',
      activeTenantId: 'tenant-a'
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/tenant/members',
    method: 'GET',
    requestId: 'req-tenant-member-list-camel-context',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 200);
  const payload = JSON.parse(route.body);
  assert.equal(payload.tenant_id, 'tenant-a');
  assert.equal(harness.authorizeCalls.length, 1);
  assert.equal(harness.listCalls.length, 1);
  assert.equal(harness.listCalls[0].tenantId, 'tenant-a');
});

test('GET /tenant/members accepts snake_case payload when camelCase shadow keys are undefined', async () => {
  const harness = createHarness({
    listTenantMembers: async () => [
      {
        membershipId: undefined,
        membership_id: 'membership-shadow-fallback',
        userId: undefined,
        user_id: 'tenant-user-shadow-fallback',
        tenantId: undefined,
        tenant_id: 'tenant-a',
        tenantName: undefined,
        tenant_name: 'Tenant A',
        phone: '13800000066',
        status: 'active',
        joinedAt: undefined,
        joined_at: '2026-02-18T00:00:00.000Z',
        leftAt: undefined,
        left_at: null
      }
    ]
  });

  const route = await dispatchApiRoute({
    pathname: '/tenant/members',
    method: 'GET',
    requestId: 'req-tenant-member-list-shadow-fallback',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 200);
  const payload = JSON.parse(route.body);
  assert.equal(payload.members.length, 1);
  assert.equal(payload.members[0].membership_id, 'membership-shadow-fallback');
  assert.equal(payload.members[0].user_id, 'tenant-user-shadow-fallback');
  assert.equal(payload.members[0].tenant_id, 'tenant-a');
});

test('GET /tenant/members accepts page and page_size query params', async () => {
  const harness = createHarness();

  const route = await dispatchApiRoute({
    pathname: '/tenant/members?page=3&page_size=20',
    method: 'GET',
    requestId: 'req-tenant-member-list-paged',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 200);
  const payload = JSON.parse(route.body);
  assert.equal(payload.tenant_id, 'tenant-a');
  assert.equal(payload.page, 3);
  assert.equal(payload.page_size, 20);
  assert.equal(payload.request_id, 'req-tenant-member-list-paged');
  assert.equal(harness.listCalls.length, 1);
  assert.equal(harness.listCalls[0].tenantId, 'tenant-a');
  assert.equal(harness.listCalls[0].page, 3);
  assert.equal(harness.listCalls[0].pageSize, 20);
});

test('GET /tenant/members fails closed when downstream returns cross-tenant members', async () => {
  const harness = createHarness({
    listTenantMembers: async () => [
      {
        membership_id: 'membership-cross-tenant',
        user_id: 'tenant-user-cross',
        tenant_id: 'tenant-b',
        tenant_name: 'Tenant B',
        phone: '13800000088',
        status: 'active',
        joined_at: '2026-02-18T00:00:00.000Z',
        left_at: null
      }
    ]
  });

  const route = await dispatchApiRoute({
    pathname: '/tenant/members',
    method: 'GET',
    requestId: 'req-tenant-member-list-cross-tenant',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 503);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
  assert.equal(payload.request_id, 'req-tenant-member-list-cross-tenant');
  const lastAuditEvent = harness.tenantMemberService._internals.auditTrail.at(-1);
  assert.equal(lastAuditEvent.type, 'tenant.member.list.rejected');
  assert.equal(lastAuditEvent.error_code, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
});

test('GET /tenant/members fails closed when downstream returns malformed member records', async () => {
  const harness = createHarness({
    listTenantMembers: async () => [
      {
        membership_id: '',
        user_id: 'tenant-user-cross',
        tenant_id: 'tenant-a',
        tenant_name: 'Tenant A',
        phone: '13800000088',
        status: 'active',
        joined_at: '2026-02-18T00:00:00.000Z',
        left_at: null
      }
    ]
  });

  const route = await dispatchApiRoute({
    pathname: '/tenant/members',
    method: 'GET',
    requestId: 'req-tenant-member-list-malformed-record',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 503);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
  assert.equal(payload.request_id, 'req-tenant-member-list-malformed-record');
  const lastAuditEvent = harness.tenantMemberService._internals.auditTrail.at(-1);
  assert.equal(lastAuditEvent.type, 'tenant.member.list.rejected');
  assert.equal(lastAuditEvent.error_code, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
});

test('GET /tenant/members fails closed when downstream returns invalid phone format', async () => {
  const harness = createHarness({
    listTenantMembers: async () => [
      {
        membership_id: 'membership-invalid-phone',
        user_id: 'tenant-user-cross',
        tenant_id: 'tenant-a',
        tenant_name: 'Tenant A',
        phone: 'invalid-phone',
        status: 'active',
        joined_at: '2026-02-18T00:00:00.000Z',
        left_at: null
      }
    ]
  });

  const route = await dispatchApiRoute({
    pathname: '/tenant/members',
    method: 'GET',
    requestId: 'req-tenant-member-list-invalid-phone',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 503);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
  assert.equal(payload.request_id, 'req-tenant-member-list-invalid-phone');
  const lastAuditEvent = harness.tenantMemberService._internals.auditTrail.at(-1);
  assert.equal(lastAuditEvent.type, 'tenant.member.list.rejected');
  assert.equal(lastAuditEvent.error_code, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
});

test('GET /tenant/members fails closed when downstream returns non-string tenant_name', async () => {
  const harness = createHarness({
    listTenantMembers: async () => [
      {
        membership_id: 'membership-invalid-tenant-name',
        user_id: 'tenant-user-cross',
        tenant_id: 'tenant-a',
        tenant_name: { bad: true },
        phone: '13800000088',
        status: 'active',
        joined_at: '2026-02-18T00:00:00.000Z',
        left_at: null
      }
    ]
  });

  const route = await dispatchApiRoute({
    pathname: '/tenant/members',
    method: 'GET',
    requestId: 'req-tenant-member-list-invalid-tenant-name',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 503);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
  assert.equal(payload.request_id, 'req-tenant-member-list-invalid-tenant-name');
  const lastAuditEvent = harness.tenantMemberService._internals.auditTrail.at(-1);
  assert.equal(lastAuditEvent.type, 'tenant.member.list.rejected');
  assert.equal(lastAuditEvent.error_code, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
});

test('GET /tenant/members fails closed when downstream returns invalid joined_at', async () => {
  const harness = createHarness({
    listTenantMembers: async () => [
      {
        membership_id: 'membership-invalid-joined-at',
        user_id: 'tenant-user-cross',
        tenant_id: 'tenant-a',
        tenant_name: 'Tenant A',
        phone: '13800000088',
        status: 'active',
        joined_at: 'not-a-datetime',
        left_at: null
      }
    ]
  });

  const route = await dispatchApiRoute({
    pathname: '/tenant/members',
    method: 'GET',
    requestId: 'req-tenant-member-list-invalid-joined-at',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 503);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
  assert.equal(payload.request_id, 'req-tenant-member-list-invalid-joined-at');
  const lastAuditEvent = harness.tenantMemberService._internals.auditTrail.at(-1);
  assert.equal(lastAuditEvent.type, 'tenant.member.list.rejected');
  assert.equal(lastAuditEvent.error_code, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
});

test('GET /tenant/members fails closed when downstream membership_id contains surrounding whitespace', async () => {
  const harness = createHarness({
    listTenantMembers: async () => [
      {
        membership_id: ' membership-whitespace ',
        user_id: 'tenant-user-cross',
        tenant_id: 'tenant-a',
        tenant_name: 'Tenant A',
        phone: '13800000088',
        status: 'active',
        joined_at: '2026-02-18T00:00:00.000Z',
        left_at: null
      }
    ]
  });

  const route = await dispatchApiRoute({
    pathname: '/tenant/members',
    method: 'GET',
    requestId: 'req-tenant-member-list-membership-whitespace',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 503);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
  assert.equal(payload.request_id, 'req-tenant-member-list-membership-whitespace');
  const lastAuditEvent = harness.tenantMemberService._internals.auditTrail.at(-1);
  assert.equal(lastAuditEvent.type, 'tenant.member.list.rejected');
  assert.equal(lastAuditEvent.error_code, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
});

test('GET /tenant/members fails closed when downstream returns non-array payload', async () => {
  const harness = createHarness({
    listTenantMembers: async () => ({
      members: []
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/tenant/members',
    method: 'GET',
    requestId: 'req-tenant-member-list-malformed-payload-shape',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 503);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
  assert.equal(payload.request_id, 'req-tenant-member-list-malformed-payload-shape');
  const lastAuditEvent = harness.tenantMemberService._internals.auditTrail.at(-1);
  assert.equal(lastAuditEvent.type, 'tenant.member.list.rejected');
  assert.equal(lastAuditEvent.error_code, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
});

test('GET /tenant/members rejects duplicate query parameter values', async () => {
  const harness = createHarness();

  const route = await dispatchApiRoute({
    pathname: '/tenant/members?page=1&page=2',
    method: 'GET',
    requestId: 'req-tenant-member-list-duplicate-query',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 400);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-400-INVALID-PAYLOAD');
  assert.equal(payload.request_id, 'req-tenant-member-list-duplicate-query');
  assert.equal(harness.listCalls.length, 0);
});

test('GET /tenant/members rejects __proto__ query parameter', async () => {
  const harness = createHarness();

  const route = await dispatchApiRoute({
    pathname: '/tenant/members?__proto__=polluted',
    method: 'GET',
    requestId: 'req-tenant-member-list-proto-query',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 400);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-400-INVALID-PAYLOAD');
  assert.equal(payload.request_id, 'req-tenant-member-list-proto-query');
  assert.equal(harness.listCalls.length, 0);
});

test('GET /tenant/members rejects invalid query parameters', async () => {
  const harness = createHarness();

  const route = await dispatchApiRoute({
    pathname: '/tenant/members?page=0',
    method: 'GET',
    requestId: 'req-tenant-member-list-invalid-query',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 400);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-400-INVALID-PAYLOAD');
  assert.equal(payload.request_id, 'req-tenant-member-list-invalid-query');
  assert.equal(harness.listCalls.length, 0);
});

test('GET /tenant/members rejects empty page query parameter', async () => {
  const harness = createHarness();

  const route = await dispatchApiRoute({
    pathname: '/tenant/members?page=',
    method: 'GET',
    requestId: 'req-tenant-member-list-empty-page',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 400);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-400-INVALID-PAYLOAD');
  assert.equal(payload.request_id, 'req-tenant-member-list-empty-page');
  assert.equal(harness.listCalls.length, 0);
});

test('GET /tenant/members rejects empty page_size query parameter', async () => {
  const harness = createHarness();

  const route = await dispatchApiRoute({
    pathname: '/tenant/members?page_size=',
    method: 'GET',
    requestId: 'req-tenant-member-list-empty-page-size',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 400);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-400-INVALID-PAYLOAD');
  assert.equal(payload.request_id, 'req-tenant-member-list-empty-page-size');
  assert.equal(harness.listCalls.length, 0);
});

test('GET /tenant/members returns AUTH-403-NO-DOMAIN when active tenant is unavailable', async () => {
  const harness = createHarness({
    authorizeRoute: async () => ({
      user_id: 'tenant-operator',
      session_id: 'tenant-session',
      entry_domain: 'tenant',
      active_tenant_id: null
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/tenant/members',
    method: 'GET',
    requestId: 'req-tenant-member-list-no-domain',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 403);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-403-NO-DOMAIN');
  assert.equal(payload.request_id, 'req-tenant-member-list-no-domain');
  assert.equal(harness.listCalls.length, 0);
});

test('POST /tenant/members creates member and returns membership fields', async () => {
  const harness = createHarness();

  const route = await dispatchApiRoute({
    pathname: '/tenant/members',
    method: 'POST',
    requestId: 'req-tenant-member-create',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      phone: '13800000022'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 200);
  const payload = JSON.parse(route.body);
  assert.deepEqual(payload, {
    membership_id: 'membership-created',
    user_id: 'tenant-user-created',
    tenant_id: 'tenant-a',
    status: 'active',
    created_user: true,
    reused_existing_user: false,
    request_id: 'req-tenant-member-create'
  });
  assert.equal(harness.authorizeCalls.length, 1);
  assert.equal(harness.authorizeCalls[0].permissionCode, 'tenant.member_admin.operate');
  assert.equal(harness.provisionCalls.length, 1);
  assert.equal(harness.provisionCalls[0].payload.phone, '13800000022');
  assert.equal(harness.provisionCalls[0].authorizedRoute.active_tenant_id, 'tenant-a');
  assert.equal(harness.findMembershipCalls.length, 1);
  assert.equal(harness.findMembershipCalls[0].userId, 'tenant-user-created');
  assert.equal(harness.findMembershipCalls[0].tenantId, 'tenant-a');
  const lastAuditEvent = harness.tenantMemberService._internals.auditTrail.at(-1);
  assert.equal(lastAuditEvent.type, 'tenant.member.created');
  assert.equal(lastAuditEvent.membership_id, 'membership-created');
});

test('POST /tenant/members reports identity reuse when target user already exists', async () => {
  const harness = createHarness({
    provisionTenantUserByPhone: async ({ requestId }) => ({
      user_id: 'tenant-user-existing',
      created_user: false,
      reused_existing_user: true,
      request_id: requestId
    }),
    findTenantMembershipByUserAndTenantId: async ({ userId, tenantId }) => ({
      membership_id: 'membership-existing',
      user_id: userId,
      tenant_id: tenantId,
      tenant_name: 'Tenant A',
      phone: '13800000023',
      status: 'active',
      joined_at: '2026-02-18T00:00:00.000Z',
      left_at: null
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/tenant/members',
    method: 'POST',
    requestId: 'req-tenant-member-create-reuse',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      phone: '13800000023'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 200);
  const payload = JSON.parse(route.body);
  assert.equal(payload.membership_id, 'membership-existing');
  assert.equal(payload.user_id, 'tenant-user-existing');
  assert.equal(payload.created_user, false);
  assert.equal(payload.reused_existing_user, true);
  const lastAuditEvent = harness.tenantMemberService._internals.auditTrail.at(-1);
  assert.equal(lastAuditEvent.type, 'tenant.member.identity_reused');
});

test('POST /tenant/members rejects forged tenant context fields from payload', async () => {
  const harness = createHarness();

  const route = await dispatchApiRoute({
    pathname: '/tenant/members',
    method: 'POST',
    requestId: 'req-tenant-member-create-forged-tenant-context',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      phone: '13800000024',
      tenant_id: 'tenant-forged'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 400);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-400-INVALID-PAYLOAD');
  assert.equal(harness.provisionCalls.length, 0);
});

test('POST /tenant/members maps membership lookup dependency failures to stable 503 error', async () => {
  const harness = createHarness({
    findTenantMembershipByUserAndTenantId: async () => {
      throw new Error('membership lookup failed');
    }
  });

  const route = await dispatchApiRoute({
    pathname: '/tenant/members',
    method: 'POST',
    requestId: 'req-tenant-member-create-lookup-failed',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      phone: '13800000028'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 503);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
  assert.equal(payload.request_id, 'req-tenant-member-create-lookup-failed');
});

test('POST /tenant/members maps malformed provision result to stable 503 and audits rejection', async () => {
  const harness = createHarness({
    provisionTenantUserByPhone: async ({ requestId }) => ({
      created_user: true,
      reused_existing_user: false,
      request_id: requestId
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/tenant/members',
    method: 'POST',
    requestId: 'req-tenant-member-create-incomplete-user-id',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      phone: '13800000030'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 503);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
  assert.equal(payload.request_id, 'req-tenant-member-create-incomplete-user-id');
  assert.equal(harness.findMembershipCalls.length, 0);
  const lastAuditEvent = harness.tenantMemberService._internals.auditTrail.at(-1);
  assert.equal(lastAuditEvent.type, 'tenant.member.create.rejected');
  assert.equal(lastAuditEvent.error_code, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
});

test('POST /tenant/members fails closed when provision result identity flags are inconsistent', async () => {
  const harness = createHarness({
    provisionTenantUserByPhone: async ({ requestId }) => ({
      user_id: 'tenant-user-created',
      created_user: false,
      reused_existing_user: false,
      request_id: requestId
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/tenant/members',
    method: 'POST',
    requestId: 'req-tenant-member-create-inconsistent-flags',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      phone: '13800000030'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 503);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
  assert.equal(payload.request_id, 'req-tenant-member-create-inconsistent-flags');
  assert.equal(harness.findMembershipCalls.length, 0);
  const lastAuditEvent = harness.tenantMemberService._internals.auditTrail.at(-1);
  assert.equal(lastAuditEvent.type, 'tenant.member.create.rejected');
  assert.equal(lastAuditEvent.error_code, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
});

test('POST /tenant/members fails closed when provision result omits identity reuse flag', async () => {
  const harness = createHarness({
    provisionTenantUserByPhone: async ({ requestId }) => ({
      user_id: 'tenant-user-created',
      created_user: true,
      request_id: requestId
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/tenant/members',
    method: 'POST',
    requestId: 'req-tenant-member-create-missing-identity-flag',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      phone: '13800000030'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 503);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
  assert.equal(payload.request_id, 'req-tenant-member-create-missing-identity-flag');
  assert.equal(harness.findMembershipCalls.length, 0);
  const lastAuditEvent = harness.tenantMemberService._internals.auditTrail.at(-1);
  assert.equal(lastAuditEvent.type, 'tenant.member.create.rejected');
  assert.equal(lastAuditEvent.error_code, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
});

test('POST /tenant/members maps inconsistent membership lookup result to stable 503', async () => {
  const harness = createHarness({
    findTenantMembershipByUserAndTenantId: async () => ({
      membership_id: 'membership-cross-tenant',
      user_id: 'tenant-user-other',
      tenant_id: 'tenant-b',
      tenant_name: 'Tenant B',
      phone: '13800000031',
      status: 'active',
      joined_at: '2026-02-18T00:00:00.000Z',
      left_at: null
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/tenant/members',
    method: 'POST',
    requestId: 'req-tenant-member-create-cross-tenant',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      phone: '13800000031'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 503);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
  assert.equal(payload.request_id, 'req-tenant-member-create-cross-tenant');
  const lastAuditEvent = harness.tenantMemberService._internals.auditTrail.at(-1);
  assert.equal(lastAuditEvent.type, 'tenant.member.create.rejected');
  assert.equal(lastAuditEvent.error_code, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
});

test('POST /tenant/members fails closed when membership lookup phone mismatches requested phone', async () => {
  const harness = createHarness({
    findTenantMembershipByUserAndTenantId: async () => ({
      membership_id: 'membership-created',
      user_id: 'tenant-user-created',
      tenant_id: 'tenant-a',
      tenant_name: 'Tenant A',
      phone: '13800000032',
      status: 'active',
      joined_at: '2026-02-18T00:00:00.000Z',
      left_at: null
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/tenant/members',
    method: 'POST',
    requestId: 'req-tenant-member-create-phone-mismatch',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      phone: '13800000031'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 503);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
  assert.equal(payload.request_id, 'req-tenant-member-create-phone-mismatch');
  const lastAuditEvent = harness.tenantMemberService._internals.auditTrail.at(-1);
  assert.equal(lastAuditEvent.type, 'tenant.member.create.rejected');
  assert.equal(lastAuditEvent.error_code, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
});

test('POST /tenant/members fails closed when membership lookup omits status', async () => {
  const harness = createHarness({
    findTenantMembershipByUserAndTenantId: async () => ({
      membership_id: 'membership-created',
      user_id: 'tenant-user-created',
      tenant_id: 'tenant-a',
      tenant_name: 'Tenant A',
      phone: '13800000031',
      joined_at: '2026-02-18T00:00:00.000Z',
      left_at: null
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/tenant/members',
    method: 'POST',
    requestId: 'req-tenant-member-create-missing-status',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      phone: '13800000031'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 503);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
  assert.equal(payload.request_id, 'req-tenant-member-create-missing-status');
  const lastAuditEvent = harness.tenantMemberService._internals.auditTrail.at(-1);
  assert.equal(lastAuditEvent.type, 'tenant.member.create.rejected');
  assert.equal(lastAuditEvent.error_code, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
});

test('POST /tenant/members fails closed when membership lookup returns non-active status', async () => {
  const harness = createHarness({
    findTenantMembershipByUserAndTenantId: async () => ({
      membership_id: 'membership-created',
      user_id: 'tenant-user-created',
      tenant_id: 'tenant-a',
      tenant_name: 'Tenant A',
      phone: '13800000031',
      status: 'left',
      joined_at: '2026-02-18T00:00:00.000Z',
      left_at: '2026-02-19T00:00:00.000Z'
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/tenant/members',
    method: 'POST',
    requestId: 'req-tenant-member-create-left-status',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      phone: '13800000031'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 503);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
  assert.equal(payload.request_id, 'req-tenant-member-create-left-status');
  const lastAuditEvent = harness.tenantMemberService._internals.auditTrail.at(-1);
  assert.equal(lastAuditEvent.type, 'tenant.member.create.rejected');
  assert.equal(lastAuditEvent.error_code, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
});

test('POST /tenant/members fails closed when membership lookup tenant_id contains surrounding whitespace', async () => {
  const harness = createHarness({
    findTenantMembershipByUserAndTenantId: async () => ({
      membership_id: 'membership-created',
      user_id: 'tenant-user-created',
      tenant_id: ' tenant-a',
      tenant_name: 'Tenant A',
      phone: '13800000031',
      status: 'active',
      joined_at: '2026-02-18T00:00:00.000Z',
      left_at: null
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/tenant/members',
    method: 'POST',
    requestId: 'req-tenant-member-create-tenant-id-whitespace',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      phone: '13800000031'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 503);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
  assert.equal(payload.request_id, 'req-tenant-member-create-tenant-id-whitespace');
  const lastAuditEvent = harness.tenantMemberService._internals.auditTrail.at(-1);
  assert.equal(lastAuditEvent.type, 'tenant.member.create.rejected');
  assert.equal(lastAuditEvent.error_code, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
});

test('POST /tenant/members replays first success response for same Idempotency-Key and payload', async () => {
  const harness = createHarness();
  const requestBody = {
    phone: '13800000022'
  };

  const first = await dispatchApiRoute({
    pathname: '/tenant/members',
    method: 'POST',
    requestId: 'req-tenant-member-create-idem-replay-1',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-tenant-member-create-replay-001'
    },
    body: requestBody,
    handlers: harness.handlers
  });
  const replay = await dispatchApiRoute({
    pathname: '/tenant/members',
    method: 'POST',
    requestId: 'req-tenant-member-create-idem-replay-2',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-tenant-member-create-replay-001'
    },
    body: requestBody,
    handlers: harness.handlers
  });

  assert.equal(first.status, 200);
  assert.equal(replay.status, 200);
  assert.equal(harness.provisionCalls.length, 1);
  const firstPayload = JSON.parse(first.body);
  const replayPayload = JSON.parse(replay.body);
  assertSamePayloadWithFreshRequestId(replayPayload, firstPayload);
  assert.ok(
    harness.idempotencyEvents.some(
      (event) =>
        event.routeKey === 'POST /tenant/members'
        && event.outcome === 'hit'
    )
  );
});

test('POST /tenant/members replays first success response across different sessions for same user', async () => {
  let authorizeCallCount = 0;
  const harness = createHarness({
    authorizeRoute: async () => {
      authorizeCallCount += 1;
      return {
        user_id: 'tenant-operator',
        session_id: `tenant-session-${authorizeCallCount}`,
        entry_domain: 'tenant',
        active_tenant_id: 'tenant-a'
      };
    }
  });
  const requestBody = {
    phone: '13800000022'
  };

  const first = await dispatchApiRoute({
    pathname: '/tenant/members',
    method: 'POST',
    requestId: 'req-tenant-member-create-idem-cross-session-1',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-tenant-member-create-cross-session-001'
    },
    body: requestBody,
    handlers: harness.handlers
  });
  const replay = await dispatchApiRoute({
    pathname: '/tenant/members',
    method: 'POST',
    requestId: 'req-tenant-member-create-idem-cross-session-2',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-tenant-member-create-cross-session-001'
    },
    body: requestBody,
    handlers: harness.handlers
  });

  assert.equal(first.status, 200);
  assert.equal(replay.status, 200);
  assert.equal(harness.provisionCalls.length, 1);
  const firstPayload = JSON.parse(first.body);
  const replayPayload = JSON.parse(replay.body);
  assertSamePayloadWithFreshRequestId(replayPayload, firstPayload);
  assert.ok(
    harness.idempotencyEvents.some(
      (event) =>
        event.routeKey === 'POST /tenant/members'
        && event.outcome === 'hit'
    )
  );
});

test('POST /tenant/members does not replay same Idempotency-Key across tenant switch when authorization context uses activeTenantId alias', async () => {
  let authorizeCallCount = 0;
  const harness = createHarness({
    authorizeRoute: async () => {
      authorizeCallCount += 1;
      return {
        user_id: 'tenant-operator',
        session_id: `tenant-session-${authorizeCallCount}`,
        entry_domain: 'tenant',
        activeTenantId: authorizeCallCount === 1 ? 'tenant-a' : 'tenant-b'
      };
    },
    findTenantMembershipByUserAndTenantId: async ({ userId, tenantId }) => ({
      membership_id: `membership-${tenantId}`,
      user_id: userId,
      tenant_id: tenantId,
      tenant_name: tenantId === 'tenant-a' ? 'Tenant A' : 'Tenant B',
      phone: '13800000022',
      status: 'active',
      joined_at: '2026-02-18T00:00:00.000Z',
      left_at: null
    })
  });
  const requestBody = {
    phone: '13800000022'
  };

  const first = await dispatchApiRoute({
    pathname: '/tenant/members',
    method: 'POST',
    requestId: 'req-tenant-member-create-idem-cross-tenant-alias-1',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-tenant-member-create-cross-tenant-alias-001'
    },
    body: requestBody,
    handlers: harness.handlers
  });
  const second = await dispatchApiRoute({
    pathname: '/tenant/members',
    method: 'POST',
    requestId: 'req-tenant-member-create-idem-cross-tenant-alias-2',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-tenant-member-create-cross-tenant-alias-001'
    },
    body: requestBody,
    handlers: harness.handlers
  });

  assert.equal(first.status, 200);
  assert.equal(second.status, 200);
  assert.equal(harness.provisionCalls.length, 2);
  const firstPayload = JSON.parse(first.body);
  const secondPayload = JSON.parse(second.body);
  assert.equal(firstPayload.tenant_id, 'tenant-a');
  assert.equal(secondPayload.tenant_id, 'tenant-b');
  assert.equal(firstPayload.membership_id, 'membership-tenant-a');
  assert.equal(secondPayload.membership_id, 'membership-tenant-b');
  assert.equal(
    harness.idempotencyEvents.some(
      (event) =>
        event.routeKey === 'POST /tenant/members'
        && event.outcome === 'hit'
    ),
    false
  );
});

test('POST /tenant/members rejects same Idempotency-Key with different payloads', async () => {
  const harness = createHarness();

  const first = await dispatchApiRoute({
    pathname: '/tenant/members',
    method: 'POST',
    requestId: 'req-tenant-member-create-idem-conflict-1',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-tenant-member-create-conflict-001'
    },
    body: {
      phone: '13800000022'
    },
    handlers: harness.handlers
  });
  const second = await dispatchApiRoute({
    pathname: '/tenant/members',
    method: 'POST',
    requestId: 'req-tenant-member-create-idem-conflict-2',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-tenant-member-create-conflict-001'
    },
    body: {
      phone: '13800000027'
    },
    handlers: harness.handlers
  });

  assert.equal(first.status, 200);
  assert.equal(second.status, 409);
  const payload = JSON.parse(second.body);
  assert.equal(payload.error_code, 'AUTH-409-IDEMPOTENCY-CONFLICT');
  assert.equal(payload.request_id, 'req-tenant-member-create-idem-conflict-2');
  assert.equal(harness.provisionCalls.length, 1);
});

test('POST /tenant/members does not cache retryable 409 responses for same Idempotency-Key', async () => {
  let attempt = 0;
  const harness = createHarness({
    provisionTenantUserByPhone: async ({ requestId }) => {
      attempt += 1;
      if (attempt === 1) {
        throw new AuthProblemError({
          status: 409,
          title: 'Conflict',
          detail: 'tenant member create conflict',
          errorCode: 'AUTH-409-PROVISION-CONFLICT',
          extensions: {
            retryable: true
          }
        });
      }
      return {
        user_id: 'tenant-user-created-after-retry',
        created_user: true,
        reused_existing_user: false,
        request_id: requestId
      };
    },
    findTenantMembershipByUserAndTenantId: async ({ userId, tenantId }) => ({
      membership_id: 'membership-created-after-retry',
      user_id: userId,
      tenant_id: tenantId,
      tenant_name: 'Tenant A',
      phone: '13800000029',
      status: 'active',
      joined_at: '2026-02-18T00:00:00.000Z',
      left_at: null
    })
  });

  const requestBody = { phone: '13800000029' };
  const first = await dispatchApiRoute({
    pathname: '/tenant/members',
    method: 'POST',
    requestId: 'req-tenant-member-create-idem-retryable-409-1',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-tenant-member-create-retryable-409-001'
    },
    body: requestBody,
    handlers: harness.handlers
  });
  const second = await dispatchApiRoute({
    pathname: '/tenant/members',
    method: 'POST',
    requestId: 'req-tenant-member-create-idem-retryable-409-2',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-tenant-member-create-retryable-409-001'
    },
    body: requestBody,
    handlers: harness.handlers
  });

  assert.equal(first.status, 409);
  assert.equal(second.status, 200);
  assert.equal(harness.provisionCalls.length, 2);
  const firstPayload = JSON.parse(first.body);
  assert.equal(firstPayload.error_code, 'AUTH-409-PROVISION-CONFLICT');
  const secondPayload = JSON.parse(second.body);
  assert.equal(secondPayload.membership_id, 'membership-created-after-retry');
  assert.equal(
    secondPayload.request_id,
    'req-tenant-member-create-idem-retryable-409-2'
  );
});

test('POST /tenant/members caches non-retryable 409 responses for same Idempotency-Key', async () => {
  const harness = createHarness({
    provisionTenantUserByPhone: async () => {
      throw new AuthProblemError({
        status: 409,
        title: 'Conflict',
        detail: 'tenant member create conflict',
        errorCode: 'AUTH-409-PROVISION-CONFLICT',
        extensions: {
          retryable: false
        }
      });
    }
  });

  const requestBody = { phone: '13800000029' };
  const first = await dispatchApiRoute({
    pathname: '/tenant/members',
    method: 'POST',
    requestId: 'req-tenant-member-create-idem-nonretryable-409-1',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-tenant-member-create-nonretryable-409-001'
    },
    body: requestBody,
    handlers: harness.handlers
  });
  const second = await dispatchApiRoute({
    pathname: '/tenant/members',
    method: 'POST',
    requestId: 'req-tenant-member-create-idem-nonretryable-409-2',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-tenant-member-create-nonretryable-409-001'
    },
    body: requestBody,
    handlers: harness.handlers
  });

  assert.equal(first.status, 409);
  assert.equal(second.status, 409);
  assert.equal(harness.provisionCalls.length, 1);
  const firstPayload = JSON.parse(first.body);
  assert.equal(firstPayload.error_code, 'AUTH-409-PROVISION-CONFLICT');
  const secondPayload = JSON.parse(second.body);
  assert.equal(secondPayload.error_code, 'AUTH-409-PROVISION-CONFLICT');
});

test('PATCH /tenant/members/:membership_id/status updates status and forwards route params', async () => {
  const harness = createHarness();

  const route = await dispatchApiRoute({
    pathname: '/tenant/members/membership-target-1/status',
    method: 'PATCH',
    requestId: 'req-tenant-member-status-disable',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      status: 'disabled',
      reason: 'manual-governance'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 200);
  const payload = JSON.parse(route.body);
  assert.deepEqual(payload, {
    membership_id: 'membership-target-1',
    user_id: 'tenant-user-target',
    tenant_id: 'tenant-a',
    previous_status: 'active',
    current_status: 'disabled',
    request_id: 'req-tenant-member-status-disable'
  });
  assert.equal(harness.statusCalls.length, 1);
  assert.equal(harness.statusCalls[0].membershipId, 'membership-target-1');
  assert.equal(harness.statusCalls[0].nextStatus, 'disabled');
  assert.equal(harness.statusCalls[0].reason, 'manual-governance');
  assert.equal(harness.statusCalls[0].authorizedRoute.active_tenant_id, 'tenant-a');
});

test('PATCH /tenant/members/:membership_id/status allows left-to-active rejoin result with new membership_id', async () => {
  const harness = createHarness({
    updateTenantMemberStatus: async ({ nextStatus }) => ({
      membership_id: 'membership-target-rejoin-new',
      user_id: 'tenant-user-target',
      tenant_id: 'tenant-a',
      previous_status: 'left',
      current_status: nextStatus
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/tenant/members/membership-target-rejoin-old/status',
    method: 'PATCH',
    requestId: 'req-tenant-member-status-rejoin',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      status: 'active',
      reason: 'manual-rejoin'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 200);
  const payload = JSON.parse(route.body);
  assert.equal(payload.membership_id, 'membership-target-rejoin-new');
  assert.equal(payload.previous_status, 'left');
  assert.equal(payload.current_status, 'active');
  assert.equal(harness.statusCalls.length, 1);
  assert.equal(harness.statusCalls[0].membershipId, 'membership-target-rejoin-old');
});

test('PATCH /tenant/members/:membership_id/status fails closed when left-to-active rejoin reuses old membership_id', async () => {
  const harness = createHarness({
    updateTenantMemberStatus: async ({ membershipId, nextStatus }) => ({
      membership_id: membershipId,
      user_id: 'tenant-user-target',
      tenant_id: 'tenant-a',
      previous_status: 'left',
      current_status: nextStatus
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/tenant/members/membership-target-rejoin-old/status',
    method: 'PATCH',
    requestId: 'req-tenant-member-status-rejoin-same-membership-id',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      status: 'active',
      reason: 'manual-rejoin'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 503);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
  assert.equal(
    payload.request_id,
    'req-tenant-member-status-rejoin-same-membership-id'
  );
  const lastAuditEvent = harness.tenantMemberService._internals.auditTrail.at(-1);
  assert.equal(lastAuditEvent.type, 'tenant.member.status.rejected');
  assert.equal(lastAuditEvent.error_code, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
});

test('PATCH /tenant/members/:membership_id/status maps inconsistent downstream result to stable 503', async () => {
  const harness = createHarness({
    updateTenantMemberStatus: async ({ membershipId, nextStatus }) => ({
      membership_id: membershipId,
      user_id: 'tenant-user-target',
      tenant_id: 'tenant-b',
      previous_status: 'active',
      current_status: nextStatus
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/tenant/members/membership-target-cross-tenant/status',
    method: 'PATCH',
    requestId: 'req-tenant-member-status-cross-tenant',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      status: 'disabled'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 503);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
  assert.equal(payload.request_id, 'req-tenant-member-status-cross-tenant');
  const lastAuditEvent = harness.tenantMemberService._internals.auditTrail.at(-1);
  assert.equal(lastAuditEvent.type, 'tenant.member.status.rejected');
  assert.equal(lastAuditEvent.error_code, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
});

test('PATCH /tenant/members/:membership_id/status fails closed when downstream omits tenant_id', async () => {
  const harness = createHarness({
    updateTenantMemberStatus: async ({ membershipId, nextStatus }) => ({
      membership_id: membershipId,
      user_id: 'tenant-user-target',
      previous_status: 'active',
      current_status: nextStatus
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/tenant/members/membership-target-missing-tenant/status',
    method: 'PATCH',
    requestId: 'req-tenant-member-status-missing-tenant-id',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      status: 'disabled'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 503);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
  assert.equal(payload.request_id, 'req-tenant-member-status-missing-tenant-id');
  const lastAuditEvent = harness.tenantMemberService._internals.auditTrail.at(-1);
  assert.equal(lastAuditEvent.type, 'tenant.member.status.rejected');
  assert.equal(lastAuditEvent.error_code, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
});

test('PATCH /tenant/members/:membership_id/status fails closed when downstream returns unsupported status value', async () => {
  const harness = createHarness({
    updateTenantMemberStatus: async ({ membershipId }) => ({
      membership_id: membershipId,
      user_id: 'tenant-user-target',
      tenant_id: 'tenant-a',
      previous_status: 'active',
      current_status: 'archived'
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/tenant/members/membership-target-invalid-status/status',
    method: 'PATCH',
    requestId: 'req-tenant-member-status-invalid-status',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      status: 'disabled'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 503);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
  assert.equal(payload.request_id, 'req-tenant-member-status-invalid-status');
  const lastAuditEvent = harness.tenantMemberService._internals.auditTrail.at(-1);
  assert.equal(lastAuditEvent.type, 'tenant.member.status.rejected');
  assert.equal(lastAuditEvent.error_code, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
});

test('PATCH /tenant/members/:membership_id/status fails closed when downstream result status mismatches requested status', async () => {
  const harness = createHarness({
    updateTenantMemberStatus: async ({ membershipId }) => ({
      membership_id: membershipId,
      user_id: 'tenant-user-target',
      tenant_id: 'tenant-a',
      previous_status: 'active',
      current_status: 'active'
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/tenant/members/membership-target-status-mismatch/status',
    method: 'PATCH',
    requestId: 'req-tenant-member-status-mismatch',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      status: 'disabled'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 503);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
  assert.equal(payload.request_id, 'req-tenant-member-status-mismatch');
  const lastAuditEvent = harness.tenantMemberService._internals.auditTrail.at(-1);
  assert.equal(lastAuditEvent.type, 'tenant.member.status.rejected');
  assert.equal(lastAuditEvent.error_code, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
});

test('PATCH /tenant/members/:membership_id/status fails closed when downstream current_status contains surrounding whitespace', async () => {
  const harness = createHarness({
    updateTenantMemberStatus: async ({ membershipId }) => ({
      membership_id: membershipId,
      user_id: 'tenant-user-target',
      tenant_id: 'tenant-a',
      previous_status: 'active',
      current_status: ' disabled'
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/tenant/members/membership-target-status-whitespace/status',
    method: 'PATCH',
    requestId: 'req-tenant-member-status-whitespace',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      status: 'disabled'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 503);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
  assert.equal(payload.request_id, 'req-tenant-member-status-whitespace');
  const lastAuditEvent = harness.tenantMemberService._internals.auditTrail.at(-1);
  assert.equal(lastAuditEvent.type, 'tenant.member.status.rejected');
  assert.equal(lastAuditEvent.error_code, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
});

test('PATCH /tenant/members/:membership_id/status fails closed when downstream returns mismatched membership_id', async () => {
  const harness = createHarness({
    updateTenantMemberStatus: async ({ nextStatus }) => ({
      membership_id: 'membership-target-other',
      user_id: 'tenant-user-target',
      tenant_id: 'tenant-a',
      previous_status: 'active',
      current_status: nextStatus
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/tenant/members/membership-target-status-id-mismatch/status',
    method: 'PATCH',
    requestId: 'req-tenant-member-status-id-mismatch',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      status: 'disabled'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 503);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
  assert.equal(payload.request_id, 'req-tenant-member-status-id-mismatch');
  const lastAuditEvent = harness.tenantMemberService._internals.auditTrail.at(-1);
  assert.equal(lastAuditEvent.type, 'tenant.member.status.rejected');
  assert.equal(lastAuditEvent.error_code, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
});

test('PATCH /tenant/members/:membership_id/status accepts membership_id at max length boundary', async () => {
  const harness = createHarness();
  const maxMembershipId = `m${'a'.repeat(63)}`;

  const route = await dispatchApiRoute({
    pathname: `/tenant/members/${maxMembershipId}/status`,
    method: 'PATCH',
    requestId: 'req-tenant-member-status-membership-id-max-length',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      status: 'disabled',
      reason: 'manual-governance'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 200);
  assert.equal(harness.statusCalls.length, 1);
  assert.equal(harness.statusCalls[0].membershipId, maxMembershipId);
});

test('PATCH /tenant/members/:membership_id/status rejects overlong membership_id', async () => {
  const harness = createHarness();
  const longMembershipId = `m${'a'.repeat(64)}`;

  const route = await dispatchApiRoute({
    pathname: `/tenant/members/${longMembershipId}/status`,
    method: 'PATCH',
    requestId: 'req-tenant-member-status-membership-id-too-long',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      status: 'disabled',
      reason: 'manual-governance'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 400);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-400-INVALID-PAYLOAD');
  assert.equal(payload.request_id, 'req-tenant-member-status-membership-id-too-long');
  assert.equal(harness.statusCalls.length, 0);
});

test('PATCH /tenant/members/:membership_id/status normalizes membership_id path to lowercase', async () => {
  const harness = createHarness();

  const route = await dispatchApiRoute({
    pathname: '/tenant/members/MEMBERSHIP-STATUS-LOWERCASE/status',
    method: 'PATCH',
    requestId: 'req-tenant-member-status-membership-id-lowercase',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      status: 'disabled'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 200);
  assert.equal(harness.statusCalls.length, 1);
  assert.equal(
    harness.statusCalls[0].membershipId,
    'membership-status-lowercase'
  );
});

test('PATCH /tenant/members/:membership_id/status replays first success response for same Idempotency-Key and payload', async () => {
  const harness = createHarness();
  const requestBody = {
    status: 'disabled',
    reason: 'manual-governance'
  };

  const first = await dispatchApiRoute({
    pathname: '/tenant/members/membership-target-2/status',
    method: 'PATCH',
    requestId: 'req-tenant-member-status-idem-replay-1',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-tenant-member-status-replay-001'
    },
    body: requestBody,
    handlers: harness.handlers
  });
  const replay = await dispatchApiRoute({
    pathname: '/tenant/members/membership-target-2/status',
    method: 'PATCH',
    requestId: 'req-tenant-member-status-idem-replay-2',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-tenant-member-status-replay-001'
    },
    body: requestBody,
    handlers: harness.handlers
  });

  assert.equal(first.status, 200);
  assert.equal(replay.status, 200);
  assert.equal(harness.statusCalls.length, 1);
  const firstPayload = JSON.parse(first.body);
  const replayPayload = JSON.parse(replay.body);
  assertSamePayloadWithFreshRequestId(replayPayload, firstPayload);
});

test('PATCH /tenant/members/:membership_id/status enforces idempotency across canonicalized membership_id path variants', async () => {
  const harness = createHarness();
  const first = await dispatchApiRoute({
    pathname: '/tenant/members/Membership_Status_Idem/status',
    method: 'PATCH',
    requestId: 'req-tenant-member-status-idem-canonicalized-1',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-tenant-member-status-canonicalized'
    },
    body: {
      status: 'disabled'
    },
    handlers: harness.handlers
  });
  const second = await dispatchApiRoute({
    pathname: '/tenant/members/membership_status_idem/status',
    method: 'PATCH',
    requestId: 'req-tenant-member-status-idem-canonicalized-2',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-tenant-member-status-canonicalized'
    },
    body: {
      status: 'left'
    },
    handlers: harness.handlers
  });

  assert.equal(first.status, 200);
  assert.equal(second.status, 409);
  const payload = JSON.parse(second.body);
  assert.equal(payload.error_code, 'AUTH-409-IDEMPOTENCY-CONFLICT');
  assert.equal(payload.request_id, 'req-tenant-member-status-idem-canonicalized-2');
  assert.equal(harness.statusCalls.length, 1);
});

test('PATCH /tenant/members/:membership_id/status does not cache retryable 409 responses for same Idempotency-Key', async () => {
  let attempt = 0;
  const harness = createHarness({
    updateTenantMemberStatus: async ({ membershipId, nextStatus }) => {
      attempt += 1;
      if (attempt === 1) {
        throw new AuthProblemError({
          status: 409,
          title: 'Conflict',
          detail: 'tenant membership update conflict',
          errorCode: 'AUTH-409-PROVISION-CONFLICT',
          extensions: {
            retryable: true
          }
        });
      }
      return {
        membership_id: membershipId,
        user_id: 'tenant-user-target',
        tenant_id: 'tenant-a',
        previous_status: 'disabled',
        current_status: nextStatus
      };
    }
  });

  const requestBody = {
    status: 'active'
  };
  const first = await dispatchApiRoute({
    pathname: '/tenant/members/membership-target-3/status',
    method: 'PATCH',
    requestId: 'req-tenant-member-status-idem-retryable-409-1',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-tenant-member-status-retryable-409-001'
    },
    body: requestBody,
    handlers: harness.handlers
  });
  const second = await dispatchApiRoute({
    pathname: '/tenant/members/membership-target-3/status',
    method: 'PATCH',
    requestId: 'req-tenant-member-status-idem-retryable-409-2',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-tenant-member-status-retryable-409-001'
    },
    body: requestBody,
    handlers: harness.handlers
  });

  assert.equal(first.status, 409);
  assert.equal(second.status, 200);
  assert.equal(harness.statusCalls.length, 2);
  const firstPayload = JSON.parse(first.body);
  assert.equal(firstPayload.error_code, 'AUTH-409-PROVISION-CONFLICT');
  const secondPayload = JSON.parse(second.body);
  assert.equal(secondPayload.current_status, 'active');
  assert.equal(
    secondPayload.request_id,
    'req-tenant-member-status-idem-retryable-409-2'
  );
});

test('PATCH /tenant/members/:membership_id/status caches non-retryable 409 responses for same Idempotency-Key', async () => {
  const harness = createHarness({
    updateTenantMemberStatus: async () => {
      throw new AuthProblemError({
        status: 409,
        title: 'Conflict',
        detail: 'tenant membership update conflict',
        errorCode: 'AUTH-409-PROVISION-CONFLICT',
        extensions: {
          retryable: false
        }
      });
    }
  });

  const requestBody = {
    status: 'active'
  };
  const first = await dispatchApiRoute({
    pathname: '/tenant/members/membership-target-3/status',
    method: 'PATCH',
    requestId: 'req-tenant-member-status-idem-nonretryable-409-1',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-tenant-member-status-nonretryable-409-001'
    },
    body: requestBody,
    handlers: harness.handlers
  });
  const second = await dispatchApiRoute({
    pathname: '/tenant/members/membership-target-3/status',
    method: 'PATCH',
    requestId: 'req-tenant-member-status-idem-nonretryable-409-2',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-tenant-member-status-nonretryable-409-001'
    },
    body: requestBody,
    handlers: harness.handlers
  });

  assert.equal(first.status, 409);
  assert.equal(second.status, 409);
  assert.equal(harness.statusCalls.length, 1);
  const firstPayload = JSON.parse(first.body);
  assert.equal(firstPayload.error_code, 'AUTH-409-PROVISION-CONFLICT');
  const secondPayload = JSON.parse(second.body);
  assert.equal(secondPayload.error_code, 'AUTH-409-PROVISION-CONFLICT');
});

test('GET /tenant/members/:membership_id/roles lists role bindings under active tenant scope', async () => {
  const harness = createHarness({
    listTenantMemberRoleBindings: async ({ membershipId }) => ({
      membership_id: membershipId,
      role_ids: ['tenant_ops_admin', 'tenant_billing_viewer']
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/tenant/members/membership-role-read-1/roles',
    method: 'GET',
    requestId: 'req-tenant-member-role-read-1',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 200);
  const payload = JSON.parse(route.body);
  assert.equal(payload.membership_id, 'membership-role-read-1');
  assert.deepEqual(payload.role_ids, ['tenant_ops_admin', 'tenant_billing_viewer']);
  assert.equal(payload.request_id, 'req-tenant-member-role-read-1');
  assert.equal(harness.authorizeCalls.length, 1);
  assert.equal(harness.authorizeCalls[0].permissionCode, 'tenant.member_admin.view');
  assert.equal(harness.roleBindingReadCalls.length, 1);
  assert.equal(harness.roleBindingReadCalls[0].tenantId, 'tenant-a');
  assert.equal(harness.roleBindingReadCalls[0].membershipId, 'membership-role-read-1');
});

test('GET /tenant/members/:membership_id/roles normalizes membership_id path to lowercase', async () => {
  const harness = createHarness({
    listTenantMemberRoleBindings: async ({ membershipId }) => ({
      membership_id: membershipId,
      role_ids: ['tenant_ops_admin']
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/tenant/members/MEMBERSHIP-ROLE-READ-LOWERCASE/roles',
    method: 'GET',
    requestId: 'req-tenant-member-role-read-lowercase',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 200);
  const payload = JSON.parse(route.body);
  assert.equal(payload.membership_id, 'membership-role-read-lowercase');
  assert.equal(harness.roleBindingReadCalls.length, 1);
  assert.equal(
    harness.roleBindingReadCalls[0].membershipId,
    'membership-role-read-lowercase'
  );
});

test('GET /tenant/members/:membership_id/roles maps membership-not-found to stable 404', async () => {
  const harness = createHarness({
    listTenantMemberRoleBindings: async () => {
      throw new AuthProblemError({
        status: 404,
        title: 'Not Found',
        detail: '目标成员关系不存在',
        errorCode: 'AUTH-404-TENANT-MEMBERSHIP-NOT-FOUND',
        extensions: {
          retryable: false
        }
      });
    }
  });

  const route = await dispatchApiRoute({
    pathname: '/tenant/members/membership-role-read-not-found/roles',
    method: 'GET',
    requestId: 'req-tenant-member-role-read-not-found',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 404);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-404-TENANT-MEMBERSHIP-NOT-FOUND');
  assert.equal(payload.request_id, 'req-tenant-member-role-read-not-found');
});

test('PUT /tenant/members/:membership_id/roles replaces role bindings with normalized role_ids', async () => {
  const harness = createHarness({
    replaceTenantMemberRoleBindings: async ({ membershipId, roleIds }) => ({
      membership_id: membershipId,
      role_ids: roleIds
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/tenant/members/membership-role-write-1/roles',
    method: 'PUT',
    requestId: 'req-tenant-member-role-write-1',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      role_ids: ['Tenant_Ops_Admin', 'tenant.billing_viewer']
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 200);
  const payload = JSON.parse(route.body);
  assert.equal(payload.membership_id, 'membership-role-write-1');
  assert.deepEqual(payload.role_ids, ['tenant_ops_admin', 'tenant.billing_viewer']);
  assert.equal(payload.request_id, 'req-tenant-member-role-write-1');
  assert.equal(harness.authorizeCalls.length, 1);
  assert.equal(harness.authorizeCalls[0].permissionCode, 'tenant.member_admin.operate');
  assert.equal(harness.roleBindingWriteCalls.length, 1);
  assert.equal(harness.roleBindingWriteCalls[0].tenantId, 'tenant-a');
  assert.equal(harness.roleBindingWriteCalls[0].membershipId, 'membership-role-write-1');
  assert.deepEqual(
    harness.roleBindingWriteCalls[0].roleIds,
    ['tenant_ops_admin', 'tenant.billing_viewer']
  );
});

test('PUT /tenant/members/:membership_id/roles normalizes membership_id path to lowercase', async () => {
  const harness = createHarness({
    replaceTenantMemberRoleBindings: async ({ membershipId, roleIds }) => ({
      membership_id: membershipId,
      role_ids: roleIds
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/tenant/members/MEMBERSHIP-ROLE-WRITE-LOWERCASE/roles',
    method: 'PUT',
    requestId: 'req-tenant-member-role-write-lowercase',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      role_ids: ['tenant_role_a']
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 200);
  const payload = JSON.parse(route.body);
  assert.equal(payload.membership_id, 'membership-role-write-lowercase');
  assert.equal(harness.roleBindingWriteCalls.length, 1);
  assert.equal(
    harness.roleBindingWriteCalls[0].membershipId,
    'membership-role-write-lowercase'
  );
});

test('PUT /tenant/members/:membership_id/roles enforces idempotency conflict on same key with different payload', async () => {
  const harness = createHarness();
  const first = await dispatchApiRoute({
    pathname: '/tenant/members/membership-role-idem-1/roles',
    method: 'PUT',
    requestId: 'req-tenant-member-role-idem-conflict-1',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-tenant-member-role-conflict-001'
    },
    body: {
      role_ids: ['tenant_role_a']
    },
    handlers: harness.handlers
  });
  const second = await dispatchApiRoute({
    pathname: '/tenant/members/membership-role-idem-1/roles',
    method: 'PUT',
    requestId: 'req-tenant-member-role-idem-conflict-2',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-tenant-member-role-conflict-001'
    },
    body: {
      role_ids: ['tenant_role_b']
    },
    handlers: harness.handlers
  });

  assert.equal(first.status, 200);
  assert.equal(second.status, 409);
  const payload = JSON.parse(second.body);
  assert.equal(payload.error_code, 'AUTH-409-IDEMPOTENCY-CONFLICT');
  assert.equal(payload.request_id, 'req-tenant-member-role-idem-conflict-2');
  assert.equal(harness.roleBindingWriteCalls.length, 1);
});

test('PUT /tenant/members/:membership_id/roles enforces idempotency across canonicalized membership_id path variants', async () => {
  const harness = createHarness();
  const first = await dispatchApiRoute({
    pathname: '/tenant/members/Membership_Role_Idem_Canonical/roles',
    method: 'PUT',
    requestId: 'req-tenant-member-role-idem-canonicalized-1',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-tenant-member-role-canonicalized'
    },
    body: {
      role_ids: ['tenant_role_a']
    },
    handlers: harness.handlers
  });
  const second = await dispatchApiRoute({
    pathname: '/tenant/members/membership_role_idem_canonical/roles',
    method: 'PUT',
    requestId: 'req-tenant-member-role-idem-canonicalized-2',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-tenant-member-role-canonicalized'
    },
    body: {
      role_ids: ['tenant_role_b']
    },
    handlers: harness.handlers
  });

  assert.equal(first.status, 200);
  assert.equal(second.status, 409);
  const payload = JSON.parse(second.body);
  assert.equal(payload.error_code, 'AUTH-409-IDEMPOTENCY-CONFLICT');
  assert.equal(payload.request_id, 'req-tenant-member-role-idem-canonicalized-2');
  assert.equal(harness.roleBindingWriteCalls.length, 1);
});

test('PUT /tenant/members/:membership_id/roles does not cache retryable 409 responses for same Idempotency-Key', async () => {
  const harness = createHarness();
  let writeCalls = 0;
  harness.handlers.tenantReplaceMemberRoles = async () => {
    writeCalls += 1;
    throw new AuthProblemError({
      status: 409,
      title: 'Conflict',
      detail: '可重试成员角色绑定冲突',
      errorCode: 'AUTH-409-TENANT-MEMBER-ROLE-RETRYABLE-CONFLICT',
      extensions: {
        retryable: true
      }
    });
  };

  const request = (requestId) =>
    dispatchApiRoute({
      pathname: '/tenant/members/membership-role-idem-retryable/roles',
      method: 'PUT',
      requestId,
      headers: {
        authorization: 'Bearer fake-access-token',
        'idempotency-key': 'idem-tenant-member-role-retryable-conflict'
      },
      body: {
        role_ids: ['tenant_role_a']
      },
      handlers: harness.handlers
    });

  const first = await request('req-tenant-member-role-idem-retryable-1');
  const second = await request('req-tenant-member-role-idem-retryable-2');

  assert.equal(first.status, 409);
  assert.equal(second.status, 409);
  assert.equal(writeCalls, 2);
  const secondPayload = JSON.parse(second.body);
  assert.equal(secondPayload.error_code, 'AUTH-409-TENANT-MEMBER-ROLE-RETRYABLE-CONFLICT');
  assert.equal(secondPayload.request_id, 'req-tenant-member-role-idem-retryable-2');
});

test('PUT /tenant/members/:membership_id/roles caches non-retryable 409 responses for same Idempotency-Key', async () => {
  const harness = createHarness();
  let writeCalls = 0;
  harness.handlers.tenantReplaceMemberRoles = async () => {
    writeCalls += 1;
    throw new AuthProblemError({
      status: 409,
      title: 'Conflict',
      detail: '不可重试成员角色绑定冲突',
      errorCode: 'AUTH-409-TENANT-MEMBER-ROLE-NON-RETRYABLE-CONFLICT',
      extensions: {
        retryable: false
      }
    });
  };

  const request = (requestId) =>
    dispatchApiRoute({
      pathname: '/tenant/members/membership-role-idem-non-retryable/roles',
      method: 'PUT',
      requestId,
      headers: {
        authorization: 'Bearer fake-access-token',
        'idempotency-key': 'idem-tenant-member-role-non-retryable-conflict'
      },
      body: {
        role_ids: ['tenant_role_a']
      },
      handlers: harness.handlers
    });

  const first = await request('req-tenant-member-role-idem-non-retryable-1');
  const second = await request('req-tenant-member-role-idem-non-retryable-2');

  assert.equal(first.status, 409);
  assert.equal(second.status, 409);
  assert.equal(writeCalls, 1);
  const secondPayload = JSON.parse(second.body);
  assert.equal(
    secondPayload.error_code,
    'AUTH-409-TENANT-MEMBER-ROLE-NON-RETRYABLE-CONFLICT'
  );
  assert.equal(secondPayload.request_id, 'req-tenant-member-role-idem-non-retryable-2');
});

test('GET /tenant/members/:membership_id/roles fails closed when downstream role_ids is malformed', async () => {
  const harness = createHarness({
    listTenantMemberRoleBindings: async ({ membershipId }) => ({
      membership_id: membershipId,
      role_ids: 'tenant_member_admin'
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/tenant/members/membership-role-read-malformed/roles',
    method: 'GET',
    requestId: 'req-tenant-member-role-read-malformed',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 503);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
  assert.equal(payload.request_id, 'req-tenant-member-role-read-malformed');
});

test('GET /tenant/members/:membership_id/roles fails closed when downstream role_ids contains surrounding whitespace', async () => {
  const harness = createHarness({
    listTenantMemberRoleBindings: async ({ membershipId }) => ({
      membership_id: membershipId,
      role_ids: [' tenant_member_admin']
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/tenant/members/membership-role-read-whitespace/roles',
    method: 'GET',
    requestId: 'req-tenant-member-role-read-whitespace',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 503);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
  assert.equal(payload.request_id, 'req-tenant-member-role-read-whitespace');
});

test('GET /tenant/members/:membership_id/roles fails closed when downstream membership_id contains surrounding whitespace', async () => {
  const harness = createHarness({
    listTenantMemberRoleBindings: async ({ membershipId }) => ({
      membership_id: ` ${membershipId} `,
      role_ids: ['tenant_member_admin']
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/tenant/members/membership-role-read-membership-whitespace/roles',
    method: 'GET',
    requestId: 'req-tenant-member-role-read-membership-whitespace',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 503);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
  assert.equal(payload.request_id, 'req-tenant-member-role-read-membership-whitespace');
});

test('PUT /tenant/members/:membership_id/roles fails closed when downstream returns mismatched role set', async () => {
  const harness = createHarness({
    replaceTenantMemberRoleBindings: async ({ membershipId }) => ({
      membership_id: membershipId,
      role_ids: ['tenant_role_a', 'tenant_role_a']
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/tenant/members/membership-role-write-malformed/roles',
    method: 'PUT',
    requestId: 'req-tenant-member-role-write-malformed',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      role_ids: ['tenant_role_a']
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 503);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
  assert.equal(payload.request_id, 'req-tenant-member-role-write-malformed');
});

test('PUT /tenant/members/:membership_id/roles fails closed when downstream membership_id contains surrounding whitespace', async () => {
  const harness = createHarness({
    replaceTenantMemberRoleBindings: async ({ membershipId }) => ({
      membership_id: ` ${membershipId} `,
      role_ids: ['tenant_role_a']
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/tenant/members/membership-role-write-membership-whitespace/roles',
    method: 'PUT',
    requestId: 'req-tenant-member-role-write-membership-whitespace',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      role_ids: ['tenant_role_a']
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 503);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
  assert.equal(payload.request_id, 'req-tenant-member-role-write-membership-whitespace');
});
