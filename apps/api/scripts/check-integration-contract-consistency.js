#!/usr/bin/env node

const { createRouteHandlers } = require('../src/http-routes');
const { createAuthService } = require('../src/modules/auth/auth.service');
const { dispatchApiRoute } = require('../src/server');
const { readConfig } = require('../src/config/env');

const OPERATOR_PHONE = '13835550111';
const OPERATOR_PASSWORD = 'Passw0rd!';

const createHarness = () => {
  const authService = createAuthService({
    seedUsers: [
      {
        id: 'platform-integration-contract-consistency-gate-operator',
        phone: OPERATOR_PHONE,
        password: OPERATOR_PASSWORD,
        status: 'active',
        domains: ['platform'],
        platformRoles: [
          {
            roleId: 'platform-integration-contract-consistency-gate-admin',
            status: 'active',
            permission: {
              canViewUserManagement: true,
              canOperateUserManagement: true,
              canViewOrganizationManagement: false,
              canOperateOrganizationManagement: false
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

const runIntegrationContractConsistencyCheck = async () => {
  const checks = [];
  const requestIds = [];
  const now = new Date().toISOString();
  const integrationId = 'integration-contract-release-gate-check';
  const harness = createHarness();

  const loginRoute = await harness.authService.login({
    requestId: 'req-integration-contract-consistency-gate-login',
    phone: OPERATOR_PHONE,
    password: OPERATOR_PASSWORD,
    entryDomain: 'platform'
  });
  const accessToken = loginRoute.access_token;
  requestIds.push('req-integration-contract-consistency-gate-login');

  const createIntegrationRoute = await dispatchApiRoute({
    pathname: '/platform/integrations',
    method: 'POST',
    requestId: 'req-integration-contract-consistency-gate-create-integration',
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: {
      integration_id: integrationId,
      code: 'INTEGRATION_CONSISTENCY_GATE',
      name: '集成契约一致性发布门禁校验',
      direction: 'outbound',
      protocol: 'https',
      auth_mode: 'hmac',
      lifecycle_status: 'active',
      lifecycle_reason: 'release gate consistency check'
    },
    handlers: harness.handlers
  });
  requestIds.push('req-integration-contract-consistency-gate-create-integration');
  assertRoute(checks, createIntegrationRoute, {
    id: 'setup.integration.create',
    expectedStatus: 200
  });

  const createBaselineRoute = await dispatchApiRoute({
    pathname: `/platform/integrations/${integrationId}/contracts`,
    method: 'POST',
    requestId: 'req-integration-contract-consistency-gate-create-baseline',
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
  requestIds.push('req-integration-contract-consistency-gate-create-baseline');
  assertRoute(checks, createBaselineRoute, {
    id: 'setup.contract.create_baseline',
    expectedStatus: 200
  });

  const activateBaselineRoute = await dispatchApiRoute({
    pathname: `/platform/integrations/${integrationId}/contracts/v1/activate`,
    method: 'POST',
    requestId: 'req-integration-contract-consistency-gate-activate-baseline',
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: {
      contract_type: 'openapi'
    },
    handlers: harness.handlers
  });
  requestIds.push('req-integration-contract-consistency-gate-activate-baseline');
  assertRoute(checks, activateBaselineRoute, {
    id: 'setup.contract.activate_baseline',
    expectedStatus: 200
  });

  const createCandidateRoute = await dispatchApiRoute({
    pathname: `/platform/integrations/${integrationId}/contracts`,
    method: 'POST',
    requestId: 'req-integration-contract-consistency-gate-create-candidate',
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
  requestIds.push('req-integration-contract-consistency-gate-create-candidate');
  assertRoute(checks, createCandidateRoute, {
    id: 'setup.contract.create_candidate',
    expectedStatus: 200
  });

  const beforeRoute = await dispatchApiRoute({
    pathname: `/platform/integrations/${integrationId}/contracts/consistency-check`,
    method: 'POST',
    requestId: 'req-integration-contract-consistency-gate-before',
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: {
      contract_type: 'openapi',
      baseline_version: 'v1',
      candidate_version: 'v2'
    },
    handlers: harness.handlers
  });
  requestIds.push('req-integration-contract-consistency-gate-before');
  assertRoute(checks, beforeRoute, {
    id: 'consistency.before_compatibility',
    expectedStatus: 409,
    validate: (_route, payload) => {
      if (!payload || typeof payload !== 'object') {
        return 'response body must be valid JSON object';
      }
      return payload.error_code === 'integration_contract_consistency_blocked'
        && payload.failure_reason === 'missing_latest_compatibility_check'
        && payload.blocking === true;
    }
  });

  const evaluateRoute = await dispatchApiRoute({
    pathname: `/platform/integrations/${integrationId}/contracts/compatibility-check`,
    method: 'POST',
    requestId: 'req-integration-contract-consistency-gate-evaluate',
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: {
      contract_type: 'openapi',
      baseline_version: 'v1',
      candidate_version: 'v2',
      diff_summary: {
        breaking_changes: []
      }
    },
    handlers: harness.handlers
  });
  requestIds.push('req-integration-contract-consistency-gate-evaluate');
  assertRoute(checks, evaluateRoute, {
    id: 'compatibility.evaluate',
    expectedStatus: 200,
    validate: (_route, payload) => {
      if (!payload || typeof payload !== 'object') {
        return 'response body must be valid JSON object';
      }
      return payload.evaluation_result === 'compatible'
        && payload.breaking_change_count === 0;
    }
  });

  const afterRoute = await dispatchApiRoute({
    pathname: `/platform/integrations/${integrationId}/contracts/consistency-check`,
    method: 'POST',
    requestId: 'req-integration-contract-consistency-gate-after',
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: {
      contract_type: 'openapi',
      baseline_version: 'v1',
      candidate_version: 'v2'
    },
    handlers: harness.handlers
  });
  requestIds.push('req-integration-contract-consistency-gate-after');
  assertRoute(checks, afterRoute, {
    id: 'consistency.after_compatibility',
    expectedStatus: 200,
    validate: (_route, payload) => {
      if (!payload || typeof payload !== 'object') {
        return 'response body must be valid JSON object';
      }
      return payload.check_result === 'passed'
        && payload.blocking === false
        && payload.failure_reason === null;
    }
  });

  const auditRoute = await dispatchApiRoute({
    pathname: '/platform/audit/events?request_id=req-integration-contract-consistency-gate-after&event_type=platform.integration.contract.consistency_checked',
    method: 'GET',
    requestId: 'req-integration-contract-consistency-gate-audit-query',
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    handlers: harness.handlers
  });
  requestIds.push('req-integration-contract-consistency-gate-audit-query');
  assertRoute(checks, auditRoute, {
    id: 'consistency.audit_event',
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
    gate: 'integration-contract-consistency',
    generated_at: now,
    passed,
    blocking: !passed,
    checks,
    evidence: {
      integration_id: integrationId,
      request_ids: requestIds
    }
  };
};

const main = async () => {
  try {
    const report = await runIntegrationContractConsistencyCheck();
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    process.exit(report.passed ? 0 : 1);
  } catch (error) {
    const report = {
      gate: 'integration-contract-consistency',
      generated_at: new Date().toISOString(),
      passed: false,
      blocking: true,
      checks: [
        {
          id: 'consistency.runtime',
          passed: false,
          detail: String(error && error.message ? error.message : error)
        }
      ],
      evidence: {
        integration_id: null,
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
  runIntegrationContractConsistencyCheck,
  _internals: {
    parseJsonBodySafely,
    resolveRouteRequestId,
    assertRoute
  }
};
