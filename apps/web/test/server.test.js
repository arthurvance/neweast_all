const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { mkdirSync, rmSync, writeFileSync } = require('node:fs');
const { dirname, resolve } = require('node:path');
const { handleWebRoute } = require('../src/server');

const WORKSPACE_ROOT = resolve(__dirname, '../../..');

test('web smoke endpoint validates web->api chain', async () => {
  const route = await handleWebRoute(
    { pathname: '/smoke', method: 'GET', headers: { 'x-request-id': 'web-test' } },
    {
      apiBaseUrl: 'http://api',
      apiClient: async () => ({
        status: 200,
        payload: {
          ok: true,
          dependencies: {
            db: { ok: true },
            redis: { ok: true }
          }
        }
      })
    }
  );
  const body = JSON.parse(route.body);
  assert.equal(route.status, 200);
  assert.equal(body.ok, true);
  assert.equal(body.request_id, 'web-test');
});

test('web /api proxy forwards request to upstream API', async () => {
  const route = await handleWebRoute(
    {
      pathname: '/api/auth/otp/send?channel=sms',
      method: 'POST',
      headers: {
        'x-request-id': 'proxy-test',
        'content-type': 'application/json'
      },
      body: JSON.stringify({ phone: '13800000000' })
    },
    {
      apiBaseUrl: 'http://api',
      apiClient: async (path, headers, request) => {
        assert.equal(path, '/auth/otp/send?channel=sms');
        assert.equal(headers['x-request-id'], 'proxy-test');
        assert.equal(headers['content-type'], 'application/json');
        assert.equal(request.method, 'POST');
        assert.equal(request.body, JSON.stringify({ phone: '13800000000' }));
        return {
          status: 429,
          headers: { 'content-type': 'application/problem+json' },
          payload: {
            status: 429,
            error_code: 'AUTH-429-RATE-LIMITED',
            retry_after_seconds: 31
          }
        };
      }
    }
  );

  assert.equal(route.status, 429);
  assert.equal(route.headers['content-type'], 'application/problem+json');
  const body = JSON.parse(route.body);
  assert.equal(body.error_code, 'AUTH-429-RATE-LIMITED');
  assert.equal(body.retry_after_seconds, 31);
});

test('web root route accepts query string for invite/deeplink flows', async () => {
  const route = await handleWebRoute(
    {
      pathname: '/?from=invite',
      method: 'GET',
      headers: {
        'x-request-id': 'query-test'
      }
    },
    { apiBaseUrl: 'http://api' }
  );

  assert.equal(route.status, 200);
  assert.equal(route.headers['content-type'], 'text/html; charset=utf-8');
  assert.match(String(route.body), /<!doctype html>/i);
});

test('web serves built static assets with immutable cache headers', async () => {
  const relativeAssetPath = `assets/unit-test-asset-${randomUUID()}-abcdefgh.js`;
  const absoluteAssetPath = resolve(WORKSPACE_ROOT, 'dist/apps/web/client', relativeAssetPath);
  const payload = 'console.log("asset-ok");';

  mkdirSync(dirname(absoluteAssetPath), { recursive: true });
  writeFileSync(absoluteAssetPath, payload, 'utf8');

  try {
    const route = await handleWebRoute(
      {
        pathname: `/${relativeAssetPath}`,
        method: 'GET',
        headers: { accept: '*/*' }
      },
      { apiBaseUrl: 'http://api' }
    );

    assert.equal(route.status, 200);
    assert.equal(route.headers['content-type'], 'text/javascript; charset=utf-8');
    assert.equal(route.headers['cache-control'], 'public, max-age=31536000, immutable');
    assert.match(String(route.headers.etag || ''), /^W\/".+"$/);
    assert.equal(typeof route.headers['last-modified'], 'string');
    assert.equal(String(route.body), payload);
  } finally {
    rmSync(absoluteAssetPath, { force: true });
  }
});

test('web supports SPA history fallback for html navigation', async () => {
  const route = await handleWebRoute(
    {
      pathname: '/login',
      method: 'GET',
      headers: { accept: 'text/html,application/xhtml+xml' }
    },
    { apiBaseUrl: 'http://api' }
  );

  assert.equal(route.status, 200);
  assert.equal(route.headers['content-type'], 'text/html; charset=utf-8');
  assert.match(String(route.body), /<!doctype html>/i);
});

test('web does not apply SPA fallback for non-html requests', async () => {
  const route = await handleWebRoute(
    {
      pathname: '/login',
      method: 'GET',
      headers: { accept: 'application/json' }
    },
    { apiBaseUrl: 'http://api' }
  );

  assert.equal(route.status, 404);
  const body = JSON.parse(route.body);
  assert.equal(body.status, 404);
});

test('web static route rejects path traversal attempts', async () => {
  const route = await handleWebRoute(
    {
      pathname: '/assets/../secrets.txt',
      method: 'GET',
      headers: { accept: '*/*' }
    },
    { apiBaseUrl: 'http://api' }
  );

  assert.equal(route.status, 404);
  const body = JSON.parse(route.body);
  assert.equal(body.status, 404);
});

test('web static route rejects encoded path traversal attempts', async () => {
  const route = await handleWebRoute(
    {
      pathname: '/assets/%2e%2e/secrets.txt',
      method: 'GET',
      headers: { accept: '*/*' }
    },
    { apiBaseUrl: 'http://api' }
  );

  assert.equal(route.status, 404);
  const body = JSON.parse(route.body);
  assert.equal(body.status, 404);
});

test('tenant mutation resolver differentiates missing tenant_options vs explicit empty list', async () => {
  const { resolveTenantMutationUiState } = await import('../src/tenant-mutation.mjs');

  const partialPayloadState = resolveTenantMutationUiState({
    nextTenantOptions: [],
    nextActiveTenantId: 'tenant-b',
    hasTenantOptions: false,
    previousTenantSwitchValue: 'tenant-a',
    previousTenantOptions: [{ tenant_id: 'tenant-a', tenant_name: 'A' }]
  });
  assert.equal(partialPayloadState.tenantSwitchValue, 'tenant-a');
  assert.equal(partialPayloadState.tenantOptionsUpdate, undefined);

  const partialPayloadKnownActiveState = resolveTenantMutationUiState({
    nextTenantOptions: [],
    nextActiveTenantId: 'tenant-b',
    hasTenantOptions: false,
    previousTenantSwitchValue: 'tenant-a',
    previousTenantOptions: [
      { tenant_id: 'tenant-a', tenant_name: 'A' },
      { tenant_id: 'tenant-b', tenant_name: 'B' }
    ]
  });
  assert.equal(partialPayloadKnownActiveState.tenantSwitchValue, 'tenant-b');
  assert.equal(partialPayloadKnownActiveState.tenantOptionsUpdate, undefined);

  const partialPayloadWithoutKnownOptionsState = resolveTenantMutationUiState({
    nextTenantOptions: [],
    nextActiveTenantId: 'tenant-z',
    hasTenantOptions: false,
    previousTenantSwitchValue: '',
    previousTenantOptions: []
  });
  assert.equal(partialPayloadWithoutKnownOptionsState.tenantSwitchValue, '');
  assert.equal(partialPayloadWithoutKnownOptionsState.tenantOptionsUpdate, undefined);

  const explicitEmptyOptionsState = resolveTenantMutationUiState({
    nextTenantOptions: [],
    nextActiveTenantId: 'tenant-b',
    hasTenantOptions: true,
    previousTenantSwitchValue: 'tenant-a'
  });
  assert.equal(explicitEmptyOptionsState.tenantSwitchValue, '');
  assert.deepEqual(explicitEmptyOptionsState.tenantOptionsUpdate, []);

  const activeTenantPreferredState = resolveTenantMutationUiState({
    nextTenantOptions: [
      { tenant_id: 'tenant-a', tenant_name: 'A' },
      { tenant_id: 'tenant-b', tenant_name: 'B' }
    ],
    nextActiveTenantId: 'tenant-b',
    hasTenantOptions: true,
    previousTenantSwitchValue: 'tenant-a'
  });
  assert.equal(activeTenantPreferredState.tenantSwitchValue, 'tenant-b');

  const activeTenantOutOfOptionsState = resolveTenantMutationUiState({
    nextTenantOptions: [
      { tenant_id: 'tenant-a', tenant_name: 'A' },
      { tenant_id: 'tenant-b', tenant_name: 'B' }
    ],
    nextActiveTenantId: 'tenant-c',
    hasTenantOptions: true,
    previousTenantSwitchValue: 'tenant-a'
  });
  assert.equal(activeTenantOutOfOptionsState.tenantSwitchValue, 'tenant-a');

  const missingActiveFallsBackToPreviousState = resolveTenantMutationUiState({
    nextTenantOptions: [
      { tenant_id: 'tenant-a', tenant_name: 'A' },
      { tenant_id: 'tenant-b', tenant_name: 'B' }
    ],
    nextActiveTenantId: '',
    hasTenantOptions: true,
    previousTenantSwitchValue: 'tenant-b'
  });
  assert.equal(missingActiveFallsBackToPreviousState.tenantSwitchValue, 'tenant-b');
});

test('tenant mutation permission context is fail-closed when payload omits tenant_permission_context', async () => {
  const { resolveTenantMutationPermissionContext } = await import('../src/tenant-mutation.mjs');

  const withContext = resolveTenantMutationPermissionContext({
    hasTenantPermissionContext: true,
    nextTenantPermissionContext: {
      scope_label: '组织权限（Tenant B）',
      can_view_user_management: true
    }
  });
  assert.deepEqual(withContext, {
    scope_label: '组织权限（Tenant B）',
    can_view_user_management: true
  });

  const missingContext = resolveTenantMutationPermissionContext({
    hasTenantPermissionContext: false,
    nextTenantPermissionContext: {
      scope_label: 'stale-context',
      can_view_user_management: true
    }
  });
  assert.equal(missingContext, null);
});

test('tenant mutation session state consumes rotated session fields from mutation payload', async () => {
  const { resolveTenantMutationSessionState } = await import('../src/tenant-mutation.mjs');

  const withRotatedSession = resolveTenantMutationSessionState({
    previousSessionState: {
      access_token: 'old-access-token',
      session_id: 'old-session-id',
      entry_domain: 'tenant',
      active_tenant_id: 'tenant-a',
      tenant_selection_required: false,
      tenant_permission_context: { scope_label: 'old' }
    },
    payload: {
      access_token: 'new-access-token',
      session_id: 'new-session-id',
      entry_domain: 'tenant',
      tenant_selection_required: false
    },
    nextActiveTenantId: 'tenant-b',
    nextTenantPermissionContext: { scope_label: 'new' }
  });
  assert.equal(withRotatedSession.access_token, 'new-access-token');
  assert.equal(withRotatedSession.session_id, 'new-session-id');
  assert.equal(withRotatedSession.active_tenant_id, 'tenant-b');
  assert.deepEqual(withRotatedSession.tenant_permission_context, { scope_label: 'new' });

  const withMissingSessionFields = resolveTenantMutationSessionState({
    previousSessionState: {
      access_token: 'kept-access-token',
      session_id: 'kept-session-id',
      entry_domain: 'tenant',
      active_tenant_id: 'tenant-a',
      tenant_selection_required: false,
      tenant_permission_context: { scope_label: 'kept' }
    },
    payload: {
      entry_domain: 'tenant',
      tenant_selection_required: true
    },
    nextActiveTenantId: 'tenant-c',
    nextTenantPermissionContext: null
  });
  assert.equal(withMissingSessionFields.access_token, 'kept-access-token');
  assert.equal(withMissingSessionFields.session_id, 'kept-session-id');
  assert.equal(withMissingSessionFields.active_tenant_id, 'tenant-c');
  assert.equal(withMissingSessionFields.tenant_selection_required, true);
  assert.equal(withMissingSessionFields.tenant_permission_context, null);
});

test('tenant refresh session binding uses expected session context to avoid stale-drop after mutation rotation', async () => {
  const { isTenantRefreshResultBoundToCurrentSession } = await import(
    '../src/tenant-mutation.mjs'
  );

  const staleCurrentSession = {
    access_token: 'old-access-token',
    session_id: 'old-session-id'
  };
  const expectedSession = {
    access_token: 'new-access-token',
    session_id: 'new-session-id'
  };

  const rejectedWithoutExpectedSession = isTenantRefreshResultBoundToCurrentSession({
    currentSession: staleCurrentSession,
    requestAccessToken: 'new-access-token',
    requestSessionId: 'new-session-id',
    responsePayload: {
      session_id: 'new-session-id'
    }
  });
  assert.equal(rejectedWithoutExpectedSession, false);

  const acceptedWithExpectedSession = isTenantRefreshResultBoundToCurrentSession({
    currentSession: staleCurrentSession,
    expectedSession,
    requestAccessToken: 'new-access-token',
    requestSessionId: 'new-session-id',
    responsePayload: {
      session_id: 'new-session-id'
    }
  });
  assert.equal(acceptedWithExpectedSession, true);
});

test('tenant refresh ui resolver keeps switch value aligned after tenant list shrink', async () => {
  const { resolveTenantRefreshUiState } = await import('../src/tenant-mutation.mjs');

  const refreshState = resolveTenantRefreshUiState({
    tenantOptions: [
      { tenant_id: 'tenant-a', tenant_name: 'A' },
      { tenant_id: 'tenant-b', tenant_name: 'B' }
    ],
    activeTenantId: '',
    previousTenantSwitchValue: 'tenant-stale'
  });

  assert.deepEqual(refreshState.tenantOptionsUpdate, [
    { tenant_id: 'tenant-a', tenant_name: 'A' },
    { tenant_id: 'tenant-b', tenant_name: 'B' }
  ]);
  assert.equal(refreshState.tenantSwitchValue, 'tenant-a');
});

test('latest request executor ignores stale tenant refresh success payloads', async () => {
  const { createLatestRequestExecutor } = await import('../src/latest-request.mjs');
  const executor = createLatestRequestExecutor();
  const applied = [];

  let resolveFirst;
  let resolveSecond;
  const firstRequest = new Promise((resolve) => {
    resolveFirst = resolve;
  });
  const secondRequest = new Promise((resolve) => {
    resolveSecond = resolve;
  });

  const firstRun = executor.run(
    () => firstRequest,
    (payload) => applied.push(payload)
  );
  const secondRun = executor.run(
    () => secondRequest,
    (payload) => applied.push(payload)
  );

  resolveSecond({ active_tenant_id: 'tenant-new' });
  const secondResult = await secondRun;
  resolveFirst({ active_tenant_id: 'tenant-old' });
  const firstResult = await firstRun;

  assert.deepEqual(secondResult, { active_tenant_id: 'tenant-new' });
  assert.equal(firstResult, undefined);
  assert.deepEqual(applied, [{ active_tenant_id: 'tenant-new' }]);
});

test('latest request executor suppresses stale tenant refresh failures', async () => {
  const { createLatestRequestExecutor } = await import('../src/latest-request.mjs');
  const executor = createLatestRequestExecutor();
  const applied = [];

  let rejectFirst;
  const firstRequest = new Promise((_resolve, reject) => {
    rejectFirst = reject;
  });

  const firstRun = executor.run(
    () => firstRequest,
    (payload) => applied.push(payload)
  );
  const secondRun = executor.run(
    () => Promise.resolve({ active_tenant_id: 'tenant-new' }),
    (payload) => applied.push(payload)
  );

  const secondResult = await secondRun;
  rejectFirst(new Error('stale refresh failed'));
  const firstResult = await firstRun;

  assert.deepEqual(secondResult, { active_tenant_id: 'tenant-new' });
  assert.equal(firstResult, undefined);
  assert.deepEqual(applied, [{ active_tenant_id: 'tenant-new' }]);
});

test('latest request executor drops result when session binding check fails', async () => {
  const { createLatestRequestExecutor } = await import('../src/latest-request.mjs');
  const executor = createLatestRequestExecutor();
  const applied = [];

  let resolveRequest;
  const pendingRequest = new Promise((resolve) => {
    resolveRequest = resolve;
  });

  let currentSessionId = 'session-new';
  const runPromise = executor.run(
    () => pendingRequest,
    (payload) => applied.push(payload),
    {
      isResultCurrent: (payload) => payload.session_id === currentSessionId
    }
  );

  resolveRequest({ session_id: 'session-old', active_tenant_id: 'tenant-old' });
  const result = await runPromise;

  assert.equal(result, undefined);
  assert.deepEqual(applied, []);
});
