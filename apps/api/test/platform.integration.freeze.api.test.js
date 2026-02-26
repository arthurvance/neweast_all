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

const OPERATOR_PHONE = '13835550331';
const VIEWER_PHONE = '13835550332';

const createHarness = () => {
  const authService = createAuthService({
    seedUsers: [
      {
        id: 'platform-integration-freeze-operator',
        phone: OPERATOR_PHONE,
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: [
          {
            roleId: 'platform-integration-freeze-admin',
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
        id: 'platform-integration-freeze-viewer',
        phone: VIEWER_PHONE,
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: [
          {
            roleId: 'platform-integration-freeze-read-only',
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

test('platform integration freeze APIs support status/activate/release with audit traceability', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-freeze-login-success'
  });
  const traceparent = '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01';

  const statusInitialRoute = await dispatchApiRoute({
    pathname: '/platform/integrations/freeze',
    method: 'GET',
    requestId: 'req-platform-integration-freeze-status-initial',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers: harness.handlers
  });
  assert.equal(statusInitialRoute.status, 200);
  const statusInitialPayload = JSON.parse(statusInitialRoute.body);
  assert.equal(statusInitialPayload.frozen, false);
  assert.equal(statusInitialPayload.active_freeze, null);
  assert.equal(statusInitialPayload.latest_freeze, null);
  assert.equal(statusInitialPayload.request_id, 'req-platform-integration-freeze-status-initial');

  const activateRoute = await dispatchApiRoute({
    pathname: '/platform/integrations/freeze',
    method: 'POST',
    requestId: 'req-platform-integration-freeze-activate-success',
    headers: {
      authorization: `Bearer ${login.access_token}`,
      traceparent,
      'idempotency-key': 'idem-platform-integration-freeze-activate-success'
    },
    body: {
      freeze_id: 'release-window-2026-02-22',
      freeze_reason: 'production release window opened'
    },
    handlers: harness.handlers
  });
  assert.equal(activateRoute.status, 200);
  const activated = JSON.parse(activateRoute.body);
  assert.equal(activated.freeze_id, 'release-window-2026-02-22');
  assert.equal(activated.status, 'active');
  assert.equal(activated.freeze_reason, 'production release window opened');
  assert.equal(activated.request_id, 'req-platform-integration-freeze-activate-success');

  const statusActiveRoute = await dispatchApiRoute({
    pathname: '/platform/integrations/freeze',
    method: 'GET',
    requestId: 'req-platform-integration-freeze-status-active',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers: harness.handlers
  });
  assert.equal(statusActiveRoute.status, 200);
  const statusActivePayload = JSON.parse(statusActiveRoute.body);
  assert.equal(statusActivePayload.frozen, true);
  assert.equal(statusActivePayload.active_freeze.freeze_id, activated.freeze_id);
  assert.equal(statusActivePayload.latest_freeze.freeze_id, activated.freeze_id);

  const releaseRoute = await dispatchApiRoute({
    pathname: '/platform/integrations/freeze/release',
    method: 'POST',
    requestId: 'req-platform-integration-freeze-release-success',
    headers: {
      authorization: `Bearer ${login.access_token}`,
      traceparent,
      'idempotency-key': 'idem-platform-integration-freeze-release-success'
    },
    body: {
      rollback_reason: 'release completed'
    },
    handlers: harness.handlers
  });
  assert.equal(releaseRoute.status, 200);
  const released = JSON.parse(releaseRoute.body);
  assert.equal(released.freeze_id, activated.freeze_id);
  assert.equal(released.status, 'released');
  assert.equal(released.previous_status, 'active');
  assert.equal(released.current_status, 'released');
  assert.equal(released.released, true);

  const statusReleasedRoute = await dispatchApiRoute({
    pathname: '/platform/integrations/freeze',
    method: 'GET',
    requestId: 'req-platform-integration-freeze-status-released',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers: harness.handlers
  });
  assert.equal(statusReleasedRoute.status, 200);
  const statusReleasedPayload = JSON.parse(statusReleasedRoute.body);
  assert.equal(statusReleasedPayload.frozen, false);
  assert.equal(statusReleasedPayload.active_freeze, null);
  assert.equal(statusReleasedPayload.latest_freeze.freeze_id, activated.freeze_id);
  assert.equal(statusReleasedPayload.latest_freeze.status, 'released');
  assert.equal(statusReleasedPayload.latest_freeze.rollback_reason, 'release completed');

  const activateAuditRoute = await dispatchApiRoute({
    pathname: '/platform/audit/events?request_id=req-platform-integration-freeze-activate-success&event_type=platform.integration.freeze.activated',
    method: 'GET',
    requestId: 'req-platform-integration-freeze-audit-activate-query',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers: harness.handlers
  });
  assert.equal(activateAuditRoute.status, 200);
  const activateAuditPayload = JSON.parse(activateAuditRoute.body);
  assert.equal(activateAuditPayload.total, 1);
  assert.equal(activateAuditPayload.events[0].event_type, 'platform.integration.freeze.activated');
  assert.equal(activateAuditPayload.events[0].traceparent, traceparent);

  const releaseAuditRoute = await dispatchApiRoute({
    pathname: '/platform/audit/events?request_id=req-platform-integration-freeze-release-success&event_type=platform.integration.freeze.released',
    method: 'GET',
    requestId: 'req-platform-integration-freeze-audit-release-query',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers: harness.handlers
  });
  assert.equal(releaseAuditRoute.status, 200);
  const releaseAuditPayload = JSON.parse(releaseAuditRoute.body);
  assert.equal(releaseAuditPayload.total, 1);
  assert.equal(releaseAuditPayload.events[0].event_type, 'platform.integration.freeze.released');
  assert.equal(releaseAuditPayload.events[0].traceparent, traceparent);
});

test('platform integration freeze APIs keep conflict semantics stable', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-freeze-login-conflict'
  });

  const firstActivateRoute = await dispatchApiRoute({
    pathname: '/platform/integrations/freeze',
    method: 'POST',
    requestId: 'req-platform-integration-freeze-conflict-first-activate',
    headers: {
      authorization: `Bearer ${login.access_token}`,
      'idempotency-key': 'idem-platform-integration-freeze-conflict-first-activate'
    },
    body: {
      freeze_id: 'release-window-conflict-01',
      freeze_reason: 'first freeze'
    },
    handlers: harness.handlers
  });
  assert.equal(firstActivateRoute.status, 200);

  const secondActivateRoute = await dispatchApiRoute({
    pathname: '/platform/integrations/freeze',
    method: 'POST',
    requestId: 'req-platform-integration-freeze-conflict-second-activate',
    headers: {
      authorization: `Bearer ${login.access_token}`,
      'idempotency-key': 'idem-platform-integration-freeze-conflict-second-activate'
    },
    body: {
      freeze_reason: 'second freeze should conflict'
    },
    handlers: harness.handlers
  });
  assert.equal(secondActivateRoute.status, 409);
  assert.equal(secondActivateRoute.headers['content-type'], 'application/problem+json');
  const secondActivatePayload = JSON.parse(secondActivateRoute.body);
  assert.equal(secondActivatePayload.error_code, 'INT-409-INTEGRATION-FREEZE-ACTIVE');
  assert.equal(secondActivatePayload.freeze_id, 'release-window-conflict-01');
  assert.equal(
    secondActivatePayload.request_id,
    'req-platform-integration-freeze-conflict-second-activate'
  );

  const firstReleaseRoute = await dispatchApiRoute({
    pathname: '/platform/integrations/freeze/release',
    method: 'POST',
    requestId: 'req-platform-integration-freeze-conflict-first-release',
    headers: {
      authorization: `Bearer ${login.access_token}`,
      'idempotency-key': 'idem-platform-integration-freeze-conflict-first-release'
    },
    body: {
      rollback_reason: 'resolve conflict'
    },
    handlers: harness.handlers
  });
  assert.equal(firstReleaseRoute.status, 200);

  const secondReleaseRoute = await dispatchApiRoute({
    pathname: '/platform/integrations/freeze/release',
    method: 'POST',
    requestId: 'req-platform-integration-freeze-conflict-second-release',
    headers: {
      authorization: `Bearer ${login.access_token}`,
      'idempotency-key': 'idem-platform-integration-freeze-conflict-second-release'
    },
    body: {
      rollback_reason: 'second release should conflict'
    },
    handlers: harness.handlers
  });
  assert.equal(secondReleaseRoute.status, 409);
  assert.equal(secondReleaseRoute.headers['content-type'], 'application/problem+json');
  const secondReleasePayload = JSON.parse(secondReleaseRoute.body);
  assert.equal(secondReleasePayload.error_code, 'INT-409-INTEGRATION-FREEZE-RELEASE-CONFLICT');
  assert.equal(
    secondReleasePayload.request_id,
    'req-platform-integration-freeze-conflict-second-release'
  );
});

test('platform integration freeze write routes require platform.user_management.operate permission', async () => {
  const harness = createHarness();
  const operatorLogin = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-freeze-login-permission-operator'
  });
  const viewerLogin = await loginByPhone({
    authService: harness.authService,
    phone: VIEWER_PHONE,
    requestId: 'req-platform-integration-freeze-login-permission-viewer'
  });

  const viewerReadRoute = await dispatchApiRoute({
    pathname: '/platform/integrations/freeze',
    method: 'GET',
    requestId: 'req-platform-integration-freeze-permission-viewer-read',
    headers: {
      authorization: `Bearer ${viewerLogin.access_token}`
    },
    handlers: harness.handlers
  });
  assert.equal(viewerReadRoute.status, 200);

  const viewerActivateRoute = await dispatchApiRoute({
    pathname: '/platform/integrations/freeze',
    method: 'POST',
    requestId: 'req-platform-integration-freeze-permission-viewer-activate',
    headers: {
      authorization: `Bearer ${viewerLogin.access_token}`,
      'idempotency-key': 'idem-platform-integration-freeze-permission-viewer-activate'
    },
    body: {
      freeze_reason: 'viewer should be rejected'
    },
    handlers: harness.handlers
  });
  assert.equal(viewerActivateRoute.status, 403);
  const viewerActivatePayload = JSON.parse(viewerActivateRoute.body);
  assert.equal(viewerActivatePayload.error_code, 'AUTH-403-FORBIDDEN');

  const operatorActivateRoute = await dispatchApiRoute({
    pathname: '/platform/integrations/freeze',
    method: 'POST',
    requestId: 'req-platform-integration-freeze-permission-operator-activate',
    headers: {
      authorization: `Bearer ${operatorLogin.access_token}`,
      'idempotency-key': 'idem-platform-integration-freeze-permission-operator-activate'
    },
    body: {
      freeze_reason: 'operator setup freeze'
    },
    handlers: harness.handlers
  });
  assert.equal(operatorActivateRoute.status, 200);

  const viewerReleaseRoute = await dispatchApiRoute({
    pathname: '/platform/integrations/freeze/release',
    method: 'POST',
    requestId: 'req-platform-integration-freeze-permission-viewer-release',
    headers: {
      authorization: `Bearer ${viewerLogin.access_token}`,
      'idempotency-key': 'idem-platform-integration-freeze-permission-viewer-release'
    },
    body: {
      rollback_reason: 'viewer should be rejected'
    },
    handlers: harness.handlers
  });
  assert.equal(viewerReleaseRoute.status, 403);
  const viewerReleasePayload = JSON.parse(viewerReleaseRoute.body);
  assert.equal(viewerReleasePayload.error_code, 'AUTH-403-FORBIDDEN');
});
