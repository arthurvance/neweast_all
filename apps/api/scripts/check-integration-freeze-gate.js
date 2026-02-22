#!/usr/bin/env node

const { createRouteHandlers } = require('../src/http-routes');
const { createAuthService } = require('../src/modules/auth/auth.service');
const { dispatchApiRoute } = require('../src/server');
const { readConfig } = require('../src/config/env');

const OPERATOR_PHONE = '13835550441';
const OPERATOR_PASSWORD = 'Passw0rd!';

const createHarness = () => {
  const authService = createAuthService({
    seedUsers: [
      {
        id: 'platform-integration-release-window-gate-operator',
        phone: OPERATOR_PHONE,
        password: OPERATOR_PASSWORD,
        status: 'active',
        domains: ['platform'],
        platformRoles: [
          {
            roleId: 'platform-integration-release-window-gate-admin',
            status: 'active',
            permission: {
              canViewMemberAdmin: true,
              canOperateMemberAdmin: true,
              canViewBilling: false,
              canOperateBilling: false
            }
          }
        ]
      }
    ]
  });
  const handlers = createRouteHandlers(readConfig({ ALLOW_MOCK_BACKENDS: 'true' }), {
    dependencyProbe: async () => ({
      db: { ok: true },
      redis: { ok: true }
    }),
    authService
  });
  return {
    authService,
    handlers
  };
};

const parseJsonBodySafely = (route) => {
  if (!route || typeof route.body !== 'string' || route.body.trim().length === 0) {
    return null;
  }
  try {
    return JSON.parse(route.body);
  } catch (_error) {
    return null;
  }
};

const resolveRouteRequestId = (route, payload) => {
  if (route && typeof route.requestId === 'string' && route.requestId.trim().length > 0) {
    return route.requestId.trim();
  }
  if (
    payload
    && typeof payload.request_id === 'string'
    && payload.request_id.trim().length > 0
  ) {
    return payload.request_id.trim();
  }
  return null;
};

const assertRoute = (checks, route, {
  id,
  expectedStatus,
  validate = null
}) => {
  const payload = parseJsonBodySafely(route);
  let validationResult = true;
  if (typeof validate === 'function') {
    try {
      validationResult = validate(route, payload);
    } catch (error) {
      validationResult = `validation exception: ${String(error && error.message ? error.message : error)}`;
    }
  }
  const validationPassed = validationResult === true;
  const passed = route.status === expectedStatus && validationPassed;
  let detail = null;
  if (!passed) {
    if (route.status !== expectedStatus) {
      detail = `Expected status=${expectedStatus}, received status=${route.status}`;
    } else if (typeof validationResult === 'string' && validationResult.trim().length > 0) {
      detail = validationResult.trim();
    } else {
      detail = `Response validation failed for status=${route.status}`;
    }
  }
  checks.push({
    id,
    passed,
    status: route.status,
    request_id: resolveRouteRequestId(route, payload),
    detail
  });
  return passed;
};

const runIntegrationReleaseWindowCheck = async () => {
  const checks = [];
  const requestIds = [];
  const now = new Date().toISOString();
  const integrationId = 'integration-release-window-gate-check';
  const harness = createHarness();
  let activeFreezeId = null;

  const loginRequestId = 'req-integration-release-window-gate-login';
  const loginRoute = await harness.authService.login({
    requestId: loginRequestId,
    phone: OPERATOR_PHONE,
    password: OPERATOR_PASSWORD,
    entryDomain: 'platform'
  });
  const accessToken = loginRoute.access_token;
  requestIds.push(loginRequestId);

  const createIntegrationRequestId = 'req-integration-release-window-gate-setup-integration-create';
  const createIntegrationRoute = await dispatchApiRoute({
    pathname: '/platform/integrations',
    method: 'POST',
    requestId: createIntegrationRequestId,
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: {
      integration_id: integrationId,
      code: 'INTEGRATION_RELEASE_WINDOW_GATE',
      name: 'Integration release window gate check',
      direction: 'outbound',
      protocol: 'https',
      auth_mode: 'hmac',
      lifecycle_status: 'draft'
    },
    handlers: harness.handlers
  });
  requestIds.push(createIntegrationRequestId);
  assertRoute(checks, createIntegrationRoute, {
    id: 'setup.integration.create',
    expectedStatus: 200
  });

  const createContractRequestId = 'req-integration-release-window-gate-setup-contract-create-v1';
  const createContractRoute = await dispatchApiRoute({
    pathname: `/platform/integrations/${integrationId}/contracts`,
    method: 'POST',
    requestId: createContractRequestId,
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: 'v1',
      schema_ref: `s3://contracts/${integrationId}/v1/openapi.json`,
      schema_checksum: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      status: 'candidate',
      is_backward_compatible: true
    },
    handlers: harness.handlers
  });
  requestIds.push(createContractRequestId);
  assertRoute(checks, createContractRoute, {
    id: 'setup.contract.create_candidate',
    expectedStatus: 200
  });

  const activateFreezeRequestId = 'req-integration-release-window-gate-freeze-activate';
  const activateFreezeRoute = await dispatchApiRoute({
    pathname: '/platform/integrations/freeze',
    method: 'POST',
    requestId: activateFreezeRequestId,
    headers: {
      authorization: `Bearer ${accessToken}`,
      'idempotency-key': 'idem-integration-release-window-gate-freeze-activate'
    },
    body: {
      freeze_id: 'release-window-gate-check-001',
      freeze_reason: 'release window gate check active'
    },
    handlers: harness.handlers
  });
  requestIds.push(activateFreezeRequestId);
  const activatePayload = parseJsonBodySafely(activateFreezeRoute);
  if (activatePayload && typeof activatePayload.freeze_id === 'string') {
    activeFreezeId = activatePayload.freeze_id;
  }
  assertRoute(checks, activateFreezeRoute, {
    id: 'freeze.activate',
    expectedStatus: 200,
    validate: (_route, payload) => {
      if (!payload || typeof payload !== 'object') {
        return 'response body must be valid JSON object';
      }
      return payload.status === 'active'
        && typeof payload.freeze_id === 'string'
        && payload.freeze_id.length > 0;
    }
  });

  const integrationCreateBlockedRequestId =
    'req-integration-release-window-gate-integration-create-blocked';
  const integrationCreateBlockedRoute = await dispatchApiRoute({
    pathname: '/platform/integrations',
    method: 'POST',
    requestId: integrationCreateBlockedRequestId,
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: {
      integration_id: `${integrationId}-blocked`,
      code: 'INTEGRATION_RELEASE_WINDOW_GATE_BLOCKED_CREATE',
      name: 'Blocked create during freeze',
      direction: 'outbound',
      protocol: 'https',
      auth_mode: 'hmac'
    },
    handlers: harness.handlers
  });
  requestIds.push(integrationCreateBlockedRequestId);
  assertRoute(checks, integrationCreateBlockedRoute, {
    id: 'freeze.block.integration_create',
    expectedStatus: 409,
    validate: (_route, payload) => {
      if (!payload || typeof payload !== 'object') {
        return 'response body must be valid JSON object';
      }
      if (payload.error_code !== 'INT-409-INTEGRATION-FREEZE-BLOCKED') {
        return `unexpected error_code=${String(payload.error_code || '')}`;
      }
      if (activeFreezeId && payload.freeze_id !== activeFreezeId) {
        return `unexpected freeze_id=${String(payload.freeze_id || '')}`;
      }
      return true;
    }
  });

  const integrationUpdateBlockedRequestId =
    'req-integration-release-window-gate-integration-update-blocked';
  const integrationUpdateBlockedRoute = await dispatchApiRoute({
    pathname: `/platform/integrations/${integrationId}`,
    method: 'PATCH',
    requestId: integrationUpdateBlockedRequestId,
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: {
      name: 'Blocked update during freeze'
    },
    handlers: harness.handlers
  });
  requestIds.push(integrationUpdateBlockedRequestId);
  assertRoute(checks, integrationUpdateBlockedRoute, {
    id: 'freeze.block.integration_update',
    expectedStatus: 409,
    validate: (_route, payload) =>
      payload
      && payload.error_code === 'INT-409-INTEGRATION-FREEZE-BLOCKED'
      && (!activeFreezeId || payload.freeze_id === activeFreezeId)
  });

  const lifecycleBlockedRequestId =
    'req-integration-release-window-gate-integration-lifecycle-blocked';
  const lifecycleBlockedRoute = await dispatchApiRoute({
    pathname: `/platform/integrations/${integrationId}/lifecycle`,
    method: 'POST',
    requestId: lifecycleBlockedRequestId,
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: {
      status: 'active',
      reason: 'freeze gate check'
    },
    handlers: harness.handlers
  });
  requestIds.push(lifecycleBlockedRequestId);
  assertRoute(checks, lifecycleBlockedRoute, {
    id: 'freeze.block.integration_lifecycle',
    expectedStatus: 409,
    validate: (_route, payload) =>
      payload
      && payload.error_code === 'INT-409-INTEGRATION-FREEZE-BLOCKED'
      && (!activeFreezeId || payload.freeze_id === activeFreezeId)
  });

  const contractCreateBlockedRequestId =
    'req-integration-release-window-gate-contract-create-blocked';
  const contractCreateBlockedRoute = await dispatchApiRoute({
    pathname: `/platform/integrations/${integrationId}/contracts`,
    method: 'POST',
    requestId: contractCreateBlockedRequestId,
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: 'v2',
      schema_ref: `s3://contracts/${integrationId}/v2/openapi.json`,
      schema_checksum: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      status: 'candidate',
      is_backward_compatible: true
    },
    handlers: harness.handlers
  });
  requestIds.push(contractCreateBlockedRequestId);
  assertRoute(checks, contractCreateBlockedRoute, {
    id: 'freeze.block.contract_create',
    expectedStatus: 409,
    validate: (_route, payload) =>
      payload
      && payload.error_code === 'INT-409-INTEGRATION-FREEZE-BLOCKED'
      && (!activeFreezeId || payload.freeze_id === activeFreezeId)
  });

  const contractActivateBlockedRequestId =
    'req-integration-release-window-gate-contract-activate-blocked';
  const contractActivateBlockedRoute = await dispatchApiRoute({
    pathname: `/platform/integrations/${integrationId}/contracts/v1/activate`,
    method: 'POST',
    requestId: contractActivateBlockedRequestId,
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: {
      contract_type: 'openapi'
    },
    handlers: harness.handlers
  });
  requestIds.push(contractActivateBlockedRequestId);
  assertRoute(checks, contractActivateBlockedRoute, {
    id: 'freeze.block.contract_activate',
    expectedStatus: 409,
    validate: (_route, payload) =>
      payload
      && payload.error_code === 'INT-409-INTEGRATION-FREEZE-BLOCKED'
      && (!activeFreezeId || payload.freeze_id === activeFreezeId)
  });

  const releaseFreezeRequestId = 'req-integration-release-window-gate-freeze-release';
  const releaseFreezeRoute = await dispatchApiRoute({
    pathname: '/platform/integrations/freeze/release',
    method: 'POST',
    requestId: releaseFreezeRequestId,
    headers: {
      authorization: `Bearer ${accessToken}`,
      'idempotency-key': 'idem-integration-release-window-gate-freeze-release'
    },
    body: {
      rollback_reason: 'release window gate check completed'
    },
    handlers: harness.handlers
  });
  requestIds.push(releaseFreezeRequestId);
  assertRoute(checks, releaseFreezeRoute, {
    id: 'freeze.release',
    expectedStatus: 200,
    validate: (_route, payload) =>
      payload
      && payload.status === 'released'
      && payload.current_status === 'released'
      && payload.released === true
  });

  const statusAfterReleaseRequestId = 'req-integration-release-window-gate-freeze-status-after';
  const statusAfterReleaseRoute = await dispatchApiRoute({
    pathname: '/platform/integrations/freeze',
    method: 'GET',
    requestId: statusAfterReleaseRequestId,
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    handlers: harness.handlers
  });
  requestIds.push(statusAfterReleaseRequestId);
  assertRoute(checks, statusAfterReleaseRoute, {
    id: 'freeze.status.after_release',
    expectedStatus: 200,
    validate: (_route, payload) =>
      payload
      && payload.frozen === false
      && payload.active_freeze === null
      && payload.latest_freeze
      && payload.latest_freeze.status === 'released'
  });

  const blockedAuditRequestId = 'req-integration-release-window-gate-blocked-audit-query';
  const blockedAuditRoute = await dispatchApiRoute({
    pathname: `/platform/audit/events?request_id=${integrationCreateBlockedRequestId}&event_type=platform.integration.freeze.change_blocked`,
    method: 'GET',
    requestId: blockedAuditRequestId,
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    handlers: harness.handlers
  });
  requestIds.push(blockedAuditRequestId);
  assertRoute(checks, blockedAuditRoute, {
    id: 'freeze.block.audit_event',
    expectedStatus: 200,
    validate: (_route, payload) => {
      if (!payload || typeof payload !== 'object') {
        return 'response body must be valid JSON object';
      }
      return Number(payload.total || 0) >= 1;
    }
  });

  const passed = checks.every((check) => check.passed === true);
  return {
    gate: 'integration-release-window',
    generated_at: now,
    passed,
    blocking: !passed,
    checks,
    evidence: {
      integration_id: integrationId,
      freeze_id: activeFreezeId,
      request_ids: requestIds
    }
  };
};

const main = async () => {
  try {
    const report = await runIntegrationReleaseWindowCheck();
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    process.exit(report.passed ? 0 : 1);
  } catch (error) {
    const report = {
      gate: 'integration-release-window',
      generated_at: new Date().toISOString(),
      passed: false,
      blocking: true,
      checks: [
        {
          id: 'release-window.runtime',
          passed: false,
          detail: String(error && error.message ? error.message : error)
        }
      ],
      evidence: {
        integration_id: null,
        freeze_id: null,
        request_ids: []
      }
    };
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    process.exit(1);
  }
};

if (require.main === module) {
  void main();
}

module.exports = {
  runIntegrationReleaseWindowCheck,
  _internals: {
    parseJsonBodySafely,
    resolveRouteRequestId,
    assertRoute
  }
};
