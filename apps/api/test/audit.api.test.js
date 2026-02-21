const test = require('node:test');
const assert = require('node:assert/strict');
const { createRouteHandlers } = require('../src/http-routes');
const { createAuthService } = require('../src/modules/auth/auth.service');
const { dispatchApiRoute } = require('../src/server');
const { readConfig } = require('../src/config/env');

const config = readConfig({ ALLOW_MOCK_BACKENDS: 'true' });
const dependencyProbe = async () => ({
  db: { ok: true },
  redis: { ok: true }
});

const PLATFORM_AUDITOR_PHONE = '13832000001';
const TENANT_AUDITOR_PHONE = '13832000002';

const createHarness = () => {
  const authService = createAuthService({
    seedUsers: [
      {
        id: 'platform-auditor',
        phone: PLATFORM_AUDITOR_PHONE,
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: [
          {
            roleId: 'platform-audit-viewer',
            status: 'active',
            permission: {
              canViewMemberAdmin: true,
              canOperateMemberAdmin: false,
              canViewBilling: false,
              canOperateBilling: false
            }
          }
        ]
      },
      {
        id: 'tenant-auditor',
        phone: TENANT_AUDITOR_PHONE,
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant'],
        tenants: [
          {
            membershipId: 'membership-tenant-auditor',
            tenantId: 'tenant-a',
            tenantName: 'Tenant A',
            status: 'active',
            permission: {
              scopeLabel: '组织权限（Tenant A）',
              canViewMemberAdmin: true,
              canOperateMemberAdmin: false,
              canViewBilling: false,
              canOperateBilling: false
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

const loginByPhone = async ({ authService, requestId, phone, entryDomain }) =>
  authService.login({
    requestId,
    phone,
    password: 'Passw0rd!',
    entryDomain
  });

const seedAuditEvent = async (authService, payload) =>
  authService._internals.authStore.recordAuditEvent(payload);

test('GET /platform/audit/events supports pagination and returns occurred_at DESC order', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    requestId: 'req-platform-audit-login',
    phone: PLATFORM_AUDITOR_PHONE,
    entryDomain: 'platform'
  });

  await seedAuditEvent(harness.authService, {
    domain: 'platform',
    requestId: 'audit-platform-1',
    eventType: 'auth.role.catalog.updated',
    actorUserId: 'platform-auditor',
    targetType: 'role',
    targetId: 'platform_ops_admin',
    result: 'success',
    occurredAt: '2026-02-20T09:00:00.000Z'
  });
  await seedAuditEvent(harness.authService, {
    domain: 'platform',
    requestId: 'audit-platform-2',
    eventType: 'auth.platform_role_permission_grants.updated',
    actorUserId: 'platform-auditor',
    targetType: 'role_permission_grants',
    targetId: 'platform_ops_admin',
    result: 'success',
    occurredAt: '2026-02-20T09:05:00.000Z'
  });
  await seedAuditEvent(harness.authService, {
    domain: 'platform',
    requestId: 'audit-platform-3',
    eventType: 'auth.org.status.updated',
    actorUserId: 'platform-auditor',
    targetType: 'org',
    targetId: 'tenant-a',
    result: 'rejected',
    occurredAt: '2026-02-20T08:55:00.000Z'
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/audit/events?page=1&page_size=2',
    method: 'GET',
    requestId: 'req-platform-audit-list',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 200);
  const payload = JSON.parse(route.body);
  assert.equal(payload.domain, 'platform');
  assert.equal(payload.page, 1);
  assert.equal(payload.page_size, 2);
  assert.equal(payload.total, 3);
  assert.equal(payload.request_id, 'req-platform-audit-list');
  assert.equal(payload.events.length, 2);
  assert.equal(payload.events[0].request_id, 'audit-platform-2');
  assert.equal(payload.events[1].request_id, 'audit-platform-1');
});

test('GET /platform/audit/events supports tenant_id and result filters', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    requestId: 'req-platform-audit-filter-login',
    phone: PLATFORM_AUDITOR_PHONE,
    entryDomain: 'platform'
  });

  await seedAuditEvent(harness.authService, {
    domain: 'platform',
    tenantId: 'tenant-a',
    requestId: 'audit-platform-filter-1',
    eventType: 'auth.org.status.updated',
    actorUserId: 'platform-auditor',
    targetType: 'org',
    targetId: 'tenant-a',
    result: 'success',
    occurredAt: '2026-02-20T09:10:00.000Z'
  });
  await seedAuditEvent(harness.authService, {
    domain: 'platform',
    tenantId: 'tenant-b',
    requestId: 'audit-platform-filter-2',
    eventType: 'auth.org.status.updated',
    actorUserId: 'platform-auditor',
    targetType: 'org',
    targetId: 'tenant-b',
    result: 'failed',
    occurredAt: '2026-02-20T09:11:00.000Z'
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/audit/events?tenant_id=tenant-a&result=success&event_type=auth.org.status.updated',
    method: 'GET',
    requestId: 'req-platform-audit-filter',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 200);
  const payload = JSON.parse(route.body);
  assert.equal(payload.total, 1);
  assert.equal(payload.events.length, 1);
  assert.equal(payload.events[0].tenant_id, 'tenant-a');
  assert.equal(payload.events[0].result, 'success');
  assert.equal(payload.events[0].event_type, 'auth.org.status.updated');
});

test('GET /platform/audit/events supports traceparent filter with pagination', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    requestId: 'req-platform-audit-trace-filter-login',
    phone: PLATFORM_AUDITOR_PHONE,
    entryDomain: 'platform'
  });
  const traceparentA = '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01';
  const traceparentB = '00-11111111111111111111111111111111-2222222222222222-01';

  await seedAuditEvent(harness.authService, {
    domain: 'platform',
    requestId: 'audit-platform-trace-1',
    traceparent: traceparentA,
    eventType: 'auth.org.status.updated',
    actorUserId: 'platform-auditor',
    targetType: 'org',
    targetId: 'tenant-a',
    result: 'success',
    occurredAt: '2026-02-20T10:10:00.000Z'
  });
  await seedAuditEvent(harness.authService, {
    domain: 'platform',
    requestId: 'audit-platform-trace-2',
    traceparent: traceparentA,
    eventType: 'auth.org.status.updated',
    actorUserId: 'platform-auditor',
    targetType: 'org',
    targetId: 'tenant-b',
    result: 'success',
    occurredAt: '2026-02-20T10:11:00.000Z'
  });
  await seedAuditEvent(harness.authService, {
    domain: 'platform',
    requestId: 'audit-platform-trace-3',
    traceparent: traceparentB,
    eventType: 'auth.org.status.updated',
    actorUserId: 'platform-auditor',
    targetType: 'org',
    targetId: 'tenant-c',
    result: 'success',
    occurredAt: '2026-02-20T10:12:00.000Z'
  });

  const route = await dispatchApiRoute({
    pathname: `/platform/audit/events?traceparent=${encodeURIComponent(traceparentA)}&page=1&page_size=1`,
    method: 'GET',
    requestId: 'req-platform-audit-trace-filter',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 200);
  const payload = JSON.parse(route.body);
  assert.equal(payload.total, 2);
  assert.equal(payload.events.length, 1);
  assert.equal(payload.events[0].traceparent, traceparentA);
});

test('GET /tenant/audit/events is forced to active_tenant_id and blocks cross-tenant reads', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    requestId: 'req-tenant-audit-login',
    phone: TENANT_AUDITOR_PHONE,
    entryDomain: 'tenant'
  });

  await seedAuditEvent(harness.authService, {
    domain: 'tenant',
    tenantId: 'tenant-a',
    requestId: 'audit-tenant-a-1',
    eventType: 'auth.tenant_role_permission_grants.updated',
    actorUserId: 'tenant-auditor',
    targetType: 'role_permission_grants',
    targetId: 'tenant_role_a',
    result: 'success',
    occurredAt: '2026-02-20T09:20:00.000Z'
  });
  await seedAuditEvent(harness.authService, {
    domain: 'tenant',
    tenantId: 'tenant-b',
    requestId: 'audit-tenant-b-1',
    eventType: 'auth.tenant_role_permission_grants.updated',
    actorUserId: 'tenant-auditor',
    targetType: 'role_permission_grants',
    targetId: 'tenant_role_b',
    result: 'success',
    occurredAt: '2026-02-20T09:21:00.000Z'
  });

  const route = await dispatchApiRoute({
    pathname: '/tenant/audit/events?page=1&page_size=20',
    method: 'GET',
    requestId: 'req-tenant-audit-list',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 200);
  const payload = JSON.parse(route.body);
  assert.equal(payload.domain, 'tenant');
  assert.equal(payload.total, 1);
  assert.equal(payload.events.length, 1);
  assert.equal(payload.events[0].tenant_id, 'tenant-a');
  assert.equal(payload.events[0].request_id, 'audit-tenant-a-1');
});

test('GET /tenant/audit/events supports traceparent filter and keeps tenant isolation', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    requestId: 'req-tenant-audit-trace-login',
    phone: TENANT_AUDITOR_PHONE,
    entryDomain: 'tenant'
  });
  const traceparentA = '00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01';
  const traceparentB = '00-cccccccccccccccccccccccccccccccc-dddddddddddddddd-01';

  await seedAuditEvent(harness.authService, {
    domain: 'tenant',
    tenantId: 'tenant-a',
    requestId: 'audit-tenant-trace-a1',
    traceparent: traceparentA,
    eventType: 'auth.tenant_role_permission_grants.updated',
    actorUserId: 'tenant-auditor',
    targetType: 'role_permission_grants',
    targetId: 'tenant_role_a',
    result: 'success',
    occurredAt: '2026-02-20T11:20:00.000Z'
  });
  await seedAuditEvent(harness.authService, {
    domain: 'tenant',
    tenantId: 'tenant-a',
    requestId: 'audit-tenant-trace-a2',
    traceparent: traceparentB,
    eventType: 'auth.tenant_role_permission_grants.updated',
    actorUserId: 'tenant-auditor',
    targetType: 'role_permission_grants',
    targetId: 'tenant_role_a',
    result: 'success',
    occurredAt: '2026-02-20T11:21:00.000Z'
  });
  await seedAuditEvent(harness.authService, {
    domain: 'tenant',
    tenantId: 'tenant-b',
    requestId: 'audit-tenant-trace-b1',
    traceparent: traceparentA,
    eventType: 'auth.tenant_role_permission_grants.updated',
    actorUserId: 'tenant-auditor',
    targetType: 'role_permission_grants',
    targetId: 'tenant_role_b',
    result: 'success',
    occurredAt: '2026-02-20T11:22:00.000Z'
  });

  const route = await dispatchApiRoute({
    pathname: `/tenant/audit/events?traceparent=${encodeURIComponent(traceparentA)}`,
    method: 'GET',
    requestId: 'req-tenant-audit-trace-filter',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 200);
  const payload = JSON.parse(route.body);
  assert.equal(payload.total, 1);
  assert.equal(payload.events.length, 1);
  assert.equal(payload.events[0].tenant_id, 'tenant-a');
  assert.equal(payload.events[0].traceparent, traceparentA);
});

test('GET /tenant/audit/events rejects unsupported tenant_id query override', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    requestId: 'req-tenant-audit-invalid-query-login',
    phone: TENANT_AUDITOR_PHONE,
    entryDomain: 'tenant'
  });

  const route = await dispatchApiRoute({
    pathname: '/tenant/audit/events?tenant_id=tenant-b',
    method: 'GET',
    requestId: 'req-tenant-audit-invalid-query',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 400);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-400-INVALID-PAYLOAD');
  assert.equal(payload.request_id, 'req-tenant-audit-invalid-query');
});

test('GET /platform/audit/events returns 503 when audit query capability is unavailable', async () => {
  const authService = createAuthService({
    seedUsers: [
      {
        id: 'platform-auditor',
        phone: PLATFORM_AUDITOR_PHONE,
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: [
          {
            roleId: 'platform-audit-viewer',
            status: 'active',
            permission: {
              canViewMemberAdmin: true,
              canOperateMemberAdmin: false,
              canViewBilling: false,
              canOperateBilling: false
            }
          }
        ]
      }
    ]
  });
  authService.listAuditEvents = undefined;
  const handlers = createRouteHandlers(config, {
    dependencyProbe,
    authService
  });
  const login = await loginByPhone({
    authService,
    requestId: 'req-platform-audit-capability-missing-login',
    phone: PLATFORM_AUDITOR_PHONE,
    entryDomain: 'platform'
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/audit/events?page=1&page_size=20',
    method: 'GET',
    requestId: 'req-platform-audit-capability-missing',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers
  });

  assert.equal(route.status, 503);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-503-AUDIT-DEPENDENCY-UNAVAILABLE');
  assert.equal(payload.request_id, 'req-platform-audit-capability-missing');
});
