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

const OPERATOR_PHONE = '13835550001';
const VIEWER_PHONE = '13835550002';

const createHarness = () => {
  const authService = createAuthService({
    seedUsers: [
      {
        id: 'platform-integration-operator',
        phone: OPERATOR_PHONE,
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: [
          {
            roleId: 'platform-integration-admin',
            status: 'active',
            permission: {
              canViewMemberAdmin: true,
              canOperateMemberAdmin: true,
              canViewBilling: false,
              canOperateBilling: false
            }
          }
        ]
      },
      {
        id: 'platform-integration-viewer',
        phone: VIEWER_PHONE,
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: [
          {
            roleId: 'platform-integration-read-only',
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

test('platform integrations support create/get/list/update/lifecycle and emit traceable audit events', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-login-success'
  });
  const traceparent = '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01';

  const createRoute = await dispatchApiRoute({
    pathname: '/platform/integrations',
    method: 'POST',
    requestId: 'req-platform-integration-create-success',
    headers: {
      authorization: `Bearer ${login.access_token}`,
      traceparent
    },
    body: {
      integration_id: 'ERP_OUTBOUND_MAIN',
      code: 'ERP_OUTBOUND_MAIN',
      name: 'ERP 出站主通道',
      direction: 'outbound',
      protocol: 'https',
      auth_mode: 'hmac',
      endpoint: '/orders/sync',
      base_url: 'https://erp.example.com/api',
      timeout_ms: 8000,
      retry_policy: {
        max_attempts: 3,
        backoff_ms: 500
      },
      idempotency_policy: {
        key_from: 'order_id'
      },
      version_strategy: 'header:x-api-version',
      runbook_url: 'https://runbook.example.com/integration/erp',
      lifecycle_status: 'draft',
      lifecycle_reason: '首次接入'
    },
    handlers: harness.handlers
  });

  assert.equal(createRoute.status, 200);
  const created = JSON.parse(createRoute.body);
  assert.equal(created.integration_id, 'erp_outbound_main');
  assert.equal(created.code, 'ERP_OUTBOUND_MAIN');
  assert.equal(created.direction, 'outbound');
  assert.equal(created.protocol, 'https');
  assert.equal(created.auth_mode, 'hmac');
  assert.equal(created.lifecycle_status, 'draft');
  assert.equal(created.effective_invocation_enabled, false);
  assert.equal(created.request_id, 'req-platform-integration-create-success');

  const getRoute = await dispatchApiRoute({
    pathname: `/platform/integrations/${created.integration_id}`,
    method: 'GET',
    requestId: 'req-platform-integration-get-success',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers: harness.handlers
  });

  assert.equal(getRoute.status, 200);
  const loaded = JSON.parse(getRoute.body);
  assert.equal(loaded.integration_id, created.integration_id);
  assert.equal(loaded.code, 'ERP_OUTBOUND_MAIN');
  assert.equal(loaded.request_id, 'req-platform-integration-get-success');

  const listRoute = await dispatchApiRoute({
    pathname: '/platform/integrations?page=1&page_size=20&lifecycle_status=draft&keyword=ERP_OUTBOUND_MAIN',
    method: 'GET',
    requestId: 'req-platform-integration-list-success',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers: harness.handlers
  });

  assert.equal(listRoute.status, 200);
  const listPayload = JSON.parse(listRoute.body);
  assert.equal(listPayload.page, 1);
  assert.equal(listPayload.page_size, 20);
  assert.ok(listPayload.total >= 1);
  const listed = listPayload.integrations.find(
    (entry) => entry.integration_id === created.integration_id
  );
  assert.ok(listed);

  const updateRoute = await dispatchApiRoute({
    pathname: `/platform/integrations/${created.integration_id}`,
    method: 'PATCH',
    requestId: 'req-platform-integration-update-success',
    headers: {
      authorization: `Bearer ${login.access_token}`,
      traceparent
    },
    body: {
      name: 'ERP 出站主通道 V2',
      timeout_ms: 6000,
      lifecycle_reason: '压测后降时延'
    },
    handlers: harness.handlers
  });

  assert.equal(updateRoute.status, 200);
  const updated = JSON.parse(updateRoute.body);
  assert.equal(updated.integration_id, created.integration_id);
  assert.equal(updated.name, 'ERP 出站主通道 V2');
  assert.equal(updated.timeout_ms, 6000);
  assert.equal(updated.lifecycle_reason, '压测后降时延');

  const lifecycleRoute = await dispatchApiRoute({
    pathname: `/platform/integrations/${created.integration_id}/lifecycle`,
    method: 'POST',
    requestId: 'req-platform-integration-lifecycle-success',
    headers: {
      authorization: `Bearer ${login.access_token}`,
      traceparent
    },
    body: {
      status: 'active',
      reason: '联调完成，开启调用'
    },
    handlers: harness.handlers
  });

  assert.equal(lifecycleRoute.status, 200);
  const lifecyclePayload = JSON.parse(lifecycleRoute.body);
  assert.equal(lifecyclePayload.integration_id, created.integration_id);
  assert.equal(lifecyclePayload.previous_status, 'draft');
  assert.equal(lifecyclePayload.current_status, 'active');
  assert.equal(lifecyclePayload.lifecycle_status, 'active');
  assert.equal(lifecyclePayload.effective_invocation_enabled, true);

  const createAuditRoute = await dispatchApiRoute({
    pathname: '/platform/audit/events?request_id=req-platform-integration-create-success&event_type=platform.integration.created',
    method: 'GET',
    requestId: 'req-platform-integration-audit-create-query',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers: harness.handlers
  });
  assert.equal(createAuditRoute.status, 200);
  const createAudit = JSON.parse(createAuditRoute.body);
  assert.equal(createAudit.total, 1);
  assert.equal(createAudit.events[0].event_type, 'platform.integration.created');
  assert.equal(createAudit.events[0].request_id, 'req-platform-integration-create-success');
  assert.equal(createAudit.events[0].traceparent, traceparent);
  assert.equal(createAudit.events[0].target_id, created.integration_id);

  const updateAuditRoute = await dispatchApiRoute({
    pathname: '/platform/audit/events?request_id=req-platform-integration-update-success&event_type=platform.integration.updated',
    method: 'GET',
    requestId: 'req-platform-integration-audit-update-query',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers: harness.handlers
  });
  assert.equal(updateAuditRoute.status, 200);
  const updateAudit = JSON.parse(updateAuditRoute.body);
  assert.equal(updateAudit.total, 1);
  assert.equal(updateAudit.events[0].event_type, 'platform.integration.updated');

  const lifecycleAuditRoute = await dispatchApiRoute({
    pathname: '/platform/audit/events?request_id=req-platform-integration-lifecycle-success&event_type=platform.integration.lifecycle_changed',
    method: 'GET',
    requestId: 'req-platform-integration-audit-lifecycle-query',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers: harness.handlers
  });
  assert.equal(lifecycleAuditRoute.status, 200);
  const lifecycleAudit = JSON.parse(lifecycleAuditRoute.body);
  assert.equal(lifecycleAudit.total, 1);
  assert.equal(
    lifecycleAudit.events[0].event_type,
    'platform.integration.lifecycle_changed'
  );
});

test('POST /platform/integrations replays first result for same Idempotency-Key and payload', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-login-idempotency'
  });

  const requestBody = {
    integration_id: 'integration-idem-replay',
    code: 'INTEGRATION_IDEM_REPLAY',
    name: '幂等重放测试',
    direction: 'inbound',
    protocol: 'https',
    auth_mode: 'signature'
  };

  const first = await dispatchApiRoute({
    pathname: '/platform/integrations',
    method: 'POST',
    requestId: 'req-platform-integration-idem-1',
    headers: {
      authorization: `Bearer ${login.access_token}`,
      'idempotency-key': 'idem-platform-integration-create-001'
    },
    body: requestBody,
    handlers: harness.handlers
  });
  const second = await dispatchApiRoute({
    pathname: '/platform/integrations',
    method: 'POST',
    requestId: 'req-platform-integration-idem-2',
    headers: {
      authorization: `Bearer ${login.access_token}`,
      'idempotency-key': 'idem-platform-integration-create-001'
    },
    body: requestBody,
    handlers: harness.handlers
  });

  assert.equal(first.status, 200);
  assert.equal(second.status, 200);
  const firstPayload = JSON.parse(first.body);
  const secondPayload = JSON.parse(second.body);
  assert.equal(secondPayload.integration_id, firstPayload.integration_id);
  assert.equal(secondPayload.code, firstPayload.code);
  assert.equal(secondPayload.request_id, 'req-platform-integration-idem-2');

  const replayAuditRoute = await dispatchApiRoute({
    pathname: '/platform/audit/events?request_id=req-platform-integration-idem-2&event_type=platform.integration.created',
    method: 'GET',
    requestId: 'req-platform-integration-idem-audit-replay-query',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers: harness.handlers
  });
  assert.equal(replayAuditRoute.status, 200);
  const replayAuditPayload = JSON.parse(replayAuditRoute.body);
  assert.equal(replayAuditPayload.total, 0);
});

test('POST /platform/integrations/:integration_id/lifecycle rejects illegal transition with stable 409 semantics', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-login-lifecycle-conflict'
  });

  const createRoute = await dispatchApiRoute({
    pathname: '/platform/integrations',
    method: 'POST',
    requestId: 'req-platform-integration-lifecycle-conflict-create',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      integration_id: 'integration-retired-terminal',
      code: 'INTEGRATION_RETIRED_TERMINAL',
      name: '终态冲突测试',
      direction: 'outbound',
      protocol: 'https',
      auth_mode: 'hmac',
      lifecycle_status: 'retired',
      lifecycle_reason: '已下线'
    },
    handlers: harness.handlers
  });
  assert.equal(createRoute.status, 200);

  const transitionRoute = await dispatchApiRoute({
    pathname: '/platform/integrations/integration-retired-terminal/lifecycle',
    method: 'POST',
    requestId: 'req-platform-integration-lifecycle-conflict',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      status: 'active',
      reason: '尝试恢复'
    },
    handlers: harness.handlers
  });

  assert.equal(transitionRoute.status, 409);
  assert.equal(transitionRoute.headers['content-type'], 'application/problem+json');
  const payload = JSON.parse(transitionRoute.body);
  assert.equal(payload.error_code, 'INT-409-LIFECYCLE-CONFLICT');
  assert.equal(payload.previous_status, 'retired');
  assert.equal(payload.requested_status, 'active');
  assert.equal(payload.retryable, false);
});

test('POST /platform/integrations rejects unknown payload fields with INT-400-INVALID-PAYLOAD', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-login-invalid-payload'
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/integrations',
    method: 'POST',
    requestId: 'req-platform-integration-invalid-payload',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      code: 'INTEGRATION_INVALID_PAYLOAD',
      name: '非法载荷测试',
      direction: 'outbound',
      protocol: 'https',
      auth_mode: 'hmac',
      unexpected_field: true
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 400);
  assert.equal(route.headers['content-type'], 'application/problem+json');
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'INT-400-INVALID-PAYLOAD');
  assert.equal(payload.request_id, 'req-platform-integration-invalid-payload');
});

test('GET /platform/integrations rejects protocol/auth_mode/keyword that exceed contract max length', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-login-list-filter-too-long'
  });

  const route = await dispatchApiRoute({
    pathname: `/platform/integrations?protocol=${'x'.repeat(65)}`,
    method: 'GET',
    requestId: 'req-platform-integration-list-filter-too-long',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 400);
  assert.equal(route.headers['content-type'], 'application/problem+json');
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'INT-400-INVALID-PAYLOAD');
  assert.equal(payload.request_id, 'req-platform-integration-list-filter-too-long');
});

test('GET /platform/integrations rejects page_size greater than 100', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-login-list-page-size-too-large'
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/integrations?page=1&page_size=101',
    method: 'GET',
    requestId: 'req-platform-integration-list-page-size-too-large',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 400);
  assert.equal(route.headers['content-type'], 'application/problem+json');
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'INT-400-INVALID-PAYLOAD');
  assert.equal(payload.request_id, 'req-platform-integration-list-page-size-too-large');
});

test('POST /platform/integrations rejects integration_id longer than 64 chars', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-login-id-too-long'
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/integrations',
    method: 'POST',
    requestId: 'req-platform-integration-id-too-long',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      integration_id: 'x'.repeat(65),
      code: 'INTEGRATION_ID_TOO_LONG',
      name: '超长标识测试',
      direction: 'outbound',
      protocol: 'https',
      auth_mode: 'hmac'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 400);
  assert.equal(route.headers['content-type'], 'application/problem+json');
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'INT-400-INVALID-PAYLOAD');
  assert.equal(payload.request_id, 'req-platform-integration-id-too-long');
});

test('POST /platform/integrations/:integration_id/lifecycle fails closed when store returns malformed transition metadata', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-login-lifecycle-malformed'
  });

  harness.authService._internals.authStore.transitionPlatformIntegrationLifecycle = async () => ({
    integrationId: 'integration-malformed-lifecycle',
    code: 'INTEGRATION_MALFORMED_LIFECYCLE',
    name: '生命周期元数据异常',
    direction: 'outbound',
    protocol: 'https',
    authMode: 'hmac',
    endpoint: null,
    baseUrl: null,
    timeoutMs: 3000,
    retryPolicy: null,
    idempotencyPolicy: null,
    versionStrategy: null,
    runbookUrl: null,
    lifecycleStatus: 'active',
    lifecycleReason: null,
    createdByUserId: 'platform-integration-operator',
    updatedByUserId: 'platform-integration-operator',
    createdAt: '2026-02-22T00:00:00.000Z',
    updatedAt: '2026-02-22T00:00:00.000Z',
    previousStatus: 'unknown',
    currentStatus: 'active',
    effectiveInvocationEnabled: true
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/integrations/integration-malformed-lifecycle/lifecycle',
    method: 'POST',
    requestId: 'req-platform-integration-lifecycle-malformed',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      status: 'active',
      reason: '尝试变更'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 503);
  assert.equal(route.headers['content-type'], 'application/problem+json');
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'INT-503-DEPENDENCY-UNAVAILABLE');
  assert.equal(payload.request_id, 'req-platform-integration-lifecycle-malformed');
});

test('POST /platform/integrations/:integration_id/lifecycle fails closed when effective_invocation_enabled conflicts with lifecycle status', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-login-lifecycle-effective-mismatch'
  });

  harness.authService._internals.authStore.transitionPlatformIntegrationLifecycle = async () => ({
    integrationId: 'integration-effective-mismatch',
    code: 'INTEGRATION_EFFECTIVE_MISMATCH',
    name: '有效调用标识冲突',
    direction: 'outbound',
    protocol: 'https',
    authMode: 'hmac',
    endpoint: null,
    baseUrl: null,
    timeoutMs: 3000,
    retryPolicy: null,
    idempotencyPolicy: null,
    versionStrategy: null,
    runbookUrl: null,
    lifecycleStatus: 'paused',
    lifecycleReason: null,
    createdByUserId: 'platform-integration-operator',
    updatedByUserId: 'platform-integration-operator',
    createdAt: '2026-02-22T00:00:00.000Z',
    updatedAt: '2026-02-22T00:00:00.000Z',
    previousStatus: 'active',
    currentStatus: 'paused',
    effectiveInvocationEnabled: true
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/integrations/integration-effective-mismatch/lifecycle',
    method: 'POST',
    requestId: 'req-platform-integration-lifecycle-effective-mismatch',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      status: 'paused',
      reason: '尝试变更'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 503);
  assert.equal(route.headers['content-type'], 'application/problem+json');
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'INT-503-DEPENDENCY-UNAVAILABLE');
  assert.equal(
    payload.request_id,
    'req-platform-integration-lifecycle-effective-mismatch'
  );
});

test('GET /platform/integrations/:integration_id fails closed when store returns invalid timestamp fields', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-login-get-invalid-timestamp'
  });

  harness.authService._internals.authStore.findPlatformIntegrationCatalogEntryByIntegrationId =
    async () => ({
      integrationId: 'integration-invalid-timestamp',
      code: 'INTEGRATION_INVALID_TIMESTAMP',
      name: '时间戳异常',
      direction: 'outbound',
      protocol: 'https',
      authMode: 'hmac',
      endpoint: null,
      baseUrl: null,
      timeoutMs: 3000,
      retryPolicy: null,
      idempotencyPolicy: null,
      versionStrategy: null,
      runbookUrl: null,
      lifecycleStatus: 'draft',
      lifecycleReason: null,
      createdByUserId: 'platform-integration-operator',
      updatedByUserId: 'platform-integration-operator',
      createdAt: 'not-a-valid-timestamp',
      updatedAt: '2026-02-22T00:00:00.000Z'
    });

  const route = await dispatchApiRoute({
    pathname: '/platform/integrations/integration-invalid-timestamp',
    method: 'GET',
    requestId: 'req-platform-integration-get-invalid-timestamp',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 503);
  assert.equal(route.headers['content-type'], 'application/problem+json');
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'INT-503-DEPENDENCY-UNAVAILABLE');
  assert.equal(payload.request_id, 'req-platform-integration-get-invalid-timestamp');
});

test('GET /platform/integrations/:integration_id fails closed when store returns overlong contract fields', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-login-get-overlong-field'
  });

  harness.authService._internals.authStore.findPlatformIntegrationCatalogEntryByIntegrationId =
    async () => ({
      integrationId: 'integration-overlong-field',
      code: 'X'.repeat(65),
      name: '字段越界',
      direction: 'outbound',
      protocol: 'https',
      authMode: 'hmac',
      endpoint: null,
      baseUrl: null,
      timeoutMs: 3000,
      retryPolicy: null,
      idempotencyPolicy: null,
      versionStrategy: null,
      runbookUrl: null,
      lifecycleStatus: 'draft',
      lifecycleReason: null,
      createdByUserId: 'platform-integration-operator',
      updatedByUserId: 'platform-integration-operator',
      createdAt: '2026-02-22T00:00:00.000Z',
      updatedAt: '2026-02-22T00:00:00.000Z'
    });

  const route = await dispatchApiRoute({
    pathname: '/platform/integrations/integration-overlong-field',
    method: 'GET',
    requestId: 'req-platform-integration-get-overlong-field',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 503);
  assert.equal(route.headers['content-type'], 'application/problem+json');
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'INT-503-DEPENDENCY-UNAVAILABLE');
  assert.equal(payload.request_id, 'req-platform-integration-get-overlong-field');
});

test('POST /platform/integrations requires platform.member_admin.operate permission', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: VIEWER_PHONE,
    requestId: 'req-platform-integration-login-viewer'
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/integrations',
    method: 'POST',
    requestId: 'req-platform-integration-viewer-forbidden',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      code: 'INTEGRATION_VIEWER_FORBIDDEN',
      name: '权限拒绝测试',
      direction: 'inbound',
      protocol: 'https',
      auth_mode: 'signature'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 403);
  assert.equal(route.headers['content-type'], 'application/problem+json');
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-403-FORBIDDEN');
  assert.equal(payload.request_id, 'req-platform-integration-viewer-forbidden');
});
