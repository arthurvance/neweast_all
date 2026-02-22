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

const OPERATOR_PHONE = '13835550111';
const VIEWER_PHONE = '13835550112';

const createHarness = () => {
  const authService = createAuthService({
    seedUsers: [
      {
        id: 'platform-integration-contract-operator',
        phone: OPERATOR_PHONE,
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: [
          {
            roleId: 'platform-integration-contract-admin',
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
        id: 'platform-integration-contract-viewer',
        phone: VIEWER_PHONE,
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: [
          {
            roleId: 'platform-integration-contract-read-only',
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

const createIntegration = async ({
  handlers,
  accessToken,
  integrationId = 'integration-contract-main',
  requestId = 'req-platform-integration-contract-create-integration'
}) =>
  dispatchApiRoute({
    pathname: '/platform/integrations',
    method: 'POST',
    requestId,
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: {
      integration_id: integrationId,
      code: integrationId.toUpperCase(),
      name: '集成契约治理测试集成',
      direction: 'outbound',
      protocol: 'https',
      auth_mode: 'hmac',
      lifecycle_status: 'active',
      lifecycle_reason: '用于契约治理联调'
    },
    handlers
  });

const createContractVersion = async ({
  handlers,
  accessToken,
  integrationId,
  contractVersion,
  requestId,
  schemaChecksum,
  status = 'candidate',
  isBackwardCompatible = true
}) =>
  dispatchApiRoute({
    pathname: `/platform/integrations/${integrationId}/contracts`,
    method: 'POST',
    requestId,
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: contractVersion,
      schema_ref: `s3://contracts/${integrationId}/${contractVersion}/openapi.json`,
      schema_checksum: schemaChecksum,
      status,
      is_backward_compatible: isBackwardCompatible
    },
    handlers
  });

const activateContractVersion = async ({
  handlers,
  accessToken,
  integrationId,
  contractVersion,
  requestId,
  baselineVersion = null
}) =>
  dispatchApiRoute({
    pathname: `/platform/integrations/${integrationId}/contracts/${contractVersion}/activate`,
    method: 'POST',
    requestId,
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body: baselineVersion
      ? {
        contract_type: 'openapi',
        baseline_version: baselineVersion
      }
      : {
        contract_type: 'openapi'
      },
    handlers
  });

const evaluateContractCompatibility = async ({
  handlers,
  accessToken,
  integrationId,
  requestId,
  baselineVersion,
  candidateVersion,
  diffSummary,
  breakingChangeCount
}) => {
  const body = {
    contract_type: 'openapi',
    baseline_version: baselineVersion,
    candidate_version: candidateVersion
  };
  if (diffSummary !== undefined) {
    body.diff_summary = diffSummary;
  }
  if (breakingChangeCount !== undefined) {
    body.breaking_change_count = breakingChangeCount;
  }
  return dispatchApiRoute({
    pathname: `/platform/integrations/${integrationId}/contracts/compatibility-check`,
    method: 'POST',
    requestId,
    headers: {
      authorization: `Bearer ${accessToken}`
    },
    body,
    handlers
  });
};

const checkContractConsistency = async ({
  handlers,
  accessToken,
  integrationId,
  requestId,
  baselineVersion,
  candidateVersion,
  idempotencyKey = null
}) => {
  const headers = {
    authorization: `Bearer ${accessToken}`
  };
  if (idempotencyKey) {
    headers['idempotency-key'] = idempotencyKey;
  }
  return dispatchApiRoute({
    pathname: `/platform/integrations/${integrationId}/contracts/consistency-check`,
    method: 'POST',
    requestId,
    headers,
    body: {
      contract_type: 'openapi',
      baseline_version: baselineVersion,
      candidate_version: candidateVersion
    },
    handlers
  });
};

test('platform integration contract APIs support create/list/compatibility/activate with audit traceability', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-contract-login-success'
  });

  const integrationRoute = await createIntegration({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId: 'integration-contract-main',
    requestId: 'req-platform-integration-contract-create-integration-success'
  });
  assert.equal(integrationRoute.status, 200);

  const createBaselineRoute = await dispatchApiRoute({
    pathname: '/platform/integrations/integration-contract-main/contracts',
    method: 'POST',
    requestId: 'req-platform-integration-contract-create-v1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: 'v2026.01.15',
      schema_ref: 's3://contracts/erp/v2026.01.15/openapi.json',
      schema_checksum: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      status: 'candidate',
      is_backward_compatible: true
    },
    handlers: harness.handlers
  });
  assert.equal(createBaselineRoute.status, 200);

  const activateBaselineRoute = await dispatchApiRoute({
    pathname: '/platform/integrations/integration-contract-main/contracts/v2026.01.15/activate',
    method: 'POST',
    requestId: 'req-platform-integration-contract-activate-v1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi'
    },
    handlers: harness.handlers
  });
  assert.equal(activateBaselineRoute.status, 200);

  const createCandidateRoute = await dispatchApiRoute({
    pathname: '/platform/integrations/integration-contract-main/contracts',
    method: 'POST',
    requestId: 'req-platform-integration-contract-create-v2',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: 'v2026.02.22',
      schema_ref: 's3://contracts/erp/v2026.02.22/openapi.json',
      schema_checksum: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      status: 'candidate',
      is_backward_compatible: true,
      compatibility_notes: '新增可选字段，向后兼容'
    },
    handlers: harness.handlers
  });
  assert.equal(createCandidateRoute.status, 200);

  const evaluateRoute = await dispatchApiRoute({
    pathname: '/platform/integrations/integration-contract-main/contracts/compatibility-check',
    method: 'POST',
    requestId: 'req-platform-integration-contract-compatibility-v1-v2',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      baseline_version: 'v2026.01.15',
      candidate_version: 'v2026.02.22',
      diff_summary: {
        breaking_changes: []
      }
    },
    handlers: harness.handlers
  });
  assert.equal(evaluateRoute.status, 200);
  const evaluatePayload = JSON.parse(evaluateRoute.body);
  assert.equal(evaluatePayload.evaluation_result, 'compatible');
  assert.equal(evaluatePayload.breaking_change_count, 0);

  const activateCandidateRoute = await dispatchApiRoute({
    pathname: '/platform/integrations/integration-contract-main/contracts/v2026.02.22/activate',
    method: 'POST',
    requestId: 'req-platform-integration-contract-activate-v2',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      baseline_version: 'v2026.01.15'
    },
    handlers: harness.handlers
  });
  assert.equal(activateCandidateRoute.status, 200);
  const activatedPayload = JSON.parse(activateCandidateRoute.body);
  assert.equal(activatedPayload.contract_version, 'v2026.02.22');
  assert.equal(activatedPayload.current_status, 'active');

  const listRoute = await dispatchApiRoute({
    pathname: '/platform/integrations/integration-contract-main/contracts?contract_type=openapi',
    method: 'GET',
    requestId: 'req-platform-integration-contract-list-success',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers: harness.handlers
  });
  assert.equal(listRoute.status, 200);
  const listPayload = JSON.parse(listRoute.body);
  assert.equal(listPayload.integration_id, 'integration-contract-main');
  assert.ok(Array.isArray(listPayload.contracts));
  assert.ok(Array.isArray(listPayload.active_contracts));
  assert.equal(
    listPayload.active_contracts.some(
      (item) => item.contract_version === 'v2026.02.22' && item.status === 'active'
    ),
    true
  );

  const createAuditRoute = await dispatchApiRoute({
    pathname: '/platform/audit/events?request_id=req-platform-integration-contract-create-v2&event_type=platform.integration.contract.created',
    method: 'GET',
    requestId: 'req-platform-integration-contract-create-audit-query',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers: harness.handlers
  });
  assert.equal(createAuditRoute.status, 200);
  const createAuditPayload = JSON.parse(createAuditRoute.body);
  assert.equal(createAuditPayload.total, 1);

  const compatibilityAuditRoute = await dispatchApiRoute({
    pathname: '/platform/audit/events?request_id=req-platform-integration-contract-compatibility-v1-v2&event_type=platform.integration.contract.compatibility_evaluated',
    method: 'GET',
    requestId: 'req-platform-integration-contract-compatibility-audit-query',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers: harness.handlers
  });
  assert.equal(compatibilityAuditRoute.status, 200);
  const compatibilityAuditPayload = JSON.parse(compatibilityAuditRoute.body);
  assert.equal(compatibilityAuditPayload.total, 1);

  const activateAuditRoute = await dispatchApiRoute({
    pathname: '/platform/audit/events?request_id=req-platform-integration-contract-activate-v2&event_type=platform.integration.contract.activated',
    method: 'GET',
    requestId: 'req-platform-integration-contract-activate-audit-query',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers: harness.handlers
  });
  assert.equal(activateAuditRoute.status, 200);
  const activateAuditPayload = JSON.parse(activateAuditRoute.body);
  assert.equal(activateAuditPayload.total, 1);
});

test('contract create accepts uppercase schema_checksum and normalizes persistence output', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-contract-login-uppercase-checksum'
  });

  const integrationRoute = await createIntegration({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId: 'integration-contract-uppercase-checksum',
    requestId: 'req-platform-integration-contract-create-integration-uppercase-checksum'
  });
  assert.equal(integrationRoute.status, 200);

  const createContractRoute = await dispatchApiRoute({
    pathname: '/platform/integrations/integration-contract-uppercase-checksum/contracts',
    method: 'POST',
    requestId: 'req-platform-integration-contract-create-uppercase-checksum',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: 'v1',
      schema_ref: 's3://contracts/uppercase-checksum/v1/openapi.json',
      schema_checksum: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      status: 'candidate',
      is_backward_compatible: true
    },
    handlers: harness.handlers
  });
  assert.equal(createContractRoute.status, 200);
  const payload = JSON.parse(createContractRoute.body);
  assert.equal(
    payload.schema_checksum,
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
  );
});

test('contract create fails closed when store create result status mismatches requested status', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-contract-login-create-status-mismatch'
  });

  const integrationRoute = await createIntegration({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId: 'integration-contract-create-status-mismatch',
    requestId:
      'req-platform-integration-contract-create-integration-create-status-mismatch'
  });
  assert.equal(integrationRoute.status, 200);

  const authStore = harness.authService._internals.authStore;
  const originalCreateContract = authStore.createPlatformIntegrationContractVersion;
  authStore.createPlatformIntegrationContractVersion = async (...args) => {
    const created = await originalCreateContract(...args);
    return {
      ...created,
      status: 'active'
    };
  };
  try {
    const route = await dispatchApiRoute({
      pathname:
        '/platform/integrations/integration-contract-create-status-mismatch/contracts',
      method: 'POST',
      requestId: 'req-platform-integration-contract-create-status-mismatch-create-v1',
      headers: {
        authorization: `Bearer ${login.access_token}`
      },
      body: {
        contract_type: 'openapi',
        contract_version: 'v1',
        schema_ref: 's3://contracts/create-status-mismatch/v1/openapi.json',
        schema_checksum: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        status: 'candidate',
        is_backward_compatible: true
      },
      handlers: harness.handlers
    });
    assert.equal(route.status, 503);
    const payload = JSON.parse(route.body);
    assert.equal(payload.error_code, 'INT-503-DEPENDENCY-UNAVAILABLE');
    assert.equal(payload.degradation_reason, 'integration-contract-create-result-invalid');
    assert.equal(
      payload.request_id,
      'req-platform-integration-contract-create-status-mismatch-create-v1'
    );
  } finally {
    authStore.createPlatformIntegrationContractVersion = originalCreateContract;
  }
});

test('contract create fails closed when store create result schema_checksum mismatches requested payload', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-contract-login-create-checksum-mismatch'
  });

  const integrationRoute = await createIntegration({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId: 'integration-contract-create-checksum-mismatch',
    requestId:
      'req-platform-integration-contract-create-integration-create-checksum-mismatch'
  });
  assert.equal(integrationRoute.status, 200);

  const authStore = harness.authService._internals.authStore;
  const originalCreateContract = authStore.createPlatformIntegrationContractVersion;
  authStore.createPlatformIntegrationContractVersion = async (...args) => {
    const created = await originalCreateContract(...args);
    return {
      ...created,
      schemaChecksum: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
    };
  };
  try {
    const route = await dispatchApiRoute({
      pathname:
        '/platform/integrations/integration-contract-create-checksum-mismatch/contracts',
      method: 'POST',
      requestId: 'req-platform-integration-contract-create-checksum-mismatch-create-v1',
      headers: {
        authorization: `Bearer ${login.access_token}`
      },
      body: {
        contract_type: 'openapi',
        contract_version: 'v1',
        schema_ref: 's3://contracts/create-checksum-mismatch/v1/openapi.json',
        schema_checksum: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        status: 'candidate',
        is_backward_compatible: true
      },
      handlers: harness.handlers
    });
    assert.equal(route.status, 503);
    const payload = JSON.parse(route.body);
    assert.equal(payload.error_code, 'INT-503-DEPENDENCY-UNAVAILABLE');
    assert.equal(payload.degradation_reason, 'integration-contract-create-result-invalid');
    assert.equal(
      payload.request_id,
      'req-platform-integration-contract-create-checksum-mismatch-create-v1'
    );
  } finally {
    authStore.createPlatformIntegrationContractVersion = originalCreateContract;
  }
});

test('contract compatibility fails closed when store result breaking_change_count mismatches requested payload', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-contract-login-check-count-mismatch'
  });

  const integrationRoute = await createIntegration({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId: 'integration-contract-check-count-mismatch',
    requestId:
      'req-platform-integration-contract-create-integration-check-count-mismatch'
  });
  assert.equal(integrationRoute.status, 200);

  const createV1Route = await dispatchApiRoute({
    pathname: '/platform/integrations/integration-contract-check-count-mismatch/contracts',
    method: 'POST',
    requestId: 'req-platform-integration-contract-check-count-mismatch-create-v1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: 'v1',
      schema_ref: 's3://contracts/check-count-mismatch/v1/openapi.json',
      schema_checksum: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      status: 'candidate',
      is_backward_compatible: true
    },
    handlers: harness.handlers
  });
  assert.equal(createV1Route.status, 200);

  const createV2Route = await dispatchApiRoute({
    pathname: '/platform/integrations/integration-contract-check-count-mismatch/contracts',
    method: 'POST',
    requestId: 'req-platform-integration-contract-check-count-mismatch-create-v2',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: 'v2',
      schema_ref: 's3://contracts/check-count-mismatch/v2/openapi.json',
      schema_checksum: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      status: 'candidate',
      is_backward_compatible: true
    },
    handlers: harness.handlers
  });
  assert.equal(createV2Route.status, 200);

  const authStore = harness.authService._internals.authStore;
  const originalCreateCheck =
    authStore.createPlatformIntegrationContractCompatibilityCheck;
  authStore.createPlatformIntegrationContractCompatibilityCheck = async (...args) => {
    const created = await originalCreateCheck(...args);
    return {
      ...created,
      breakingChangeCount: Number(created.breakingChangeCount || 0) + 1
    };
  };
  try {
    const route = await dispatchApiRoute({
      pathname:
        '/platform/integrations/integration-contract-check-count-mismatch/contracts/compatibility-check',
      method: 'POST',
      requestId: 'req-platform-integration-contract-check-count-mismatch-compatibility',
      headers: {
        authorization: `Bearer ${login.access_token}`
      },
      body: {
        contract_type: 'openapi',
        baseline_version: 'v1',
        candidate_version: 'v2',
        breaking_change_count: 0,
        diff_summary: {
          breaking_changes: []
        }
      },
      handlers: harness.handlers
    });
    assert.equal(route.status, 503);
    const payload = JSON.parse(route.body);
    assert.equal(payload.error_code, 'INT-503-DEPENDENCY-UNAVAILABLE');
    assert.equal(
      payload.degradation_reason,
      'integration-contract-compatibility-result-invalid'
    );
    assert.equal(
      payload.request_id,
      'req-platform-integration-contract-check-count-mismatch-compatibility'
    );
  } finally {
    authStore.createPlatformIntegrationContractCompatibilityCheck =
      originalCreateCheck;
  }
});

test('contract compatibility fails closed when store result request_id mismatches current request', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-contract-login-check-request-id-mismatch'
  });

  const integrationRoute = await createIntegration({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId: 'integration-contract-check-request-id-mismatch',
    requestId:
      'req-platform-integration-contract-create-integration-check-request-id-mismatch'
  });
  assert.equal(integrationRoute.status, 200);

  const createV1Route = await dispatchApiRoute({
    pathname:
      '/platform/integrations/integration-contract-check-request-id-mismatch/contracts',
    method: 'POST',
    requestId:
      'req-platform-integration-contract-check-request-id-mismatch-create-v1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: 'v1',
      schema_ref: 's3://contracts/check-request-id-mismatch/v1/openapi.json',
      schema_checksum: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      status: 'candidate',
      is_backward_compatible: true
    },
    handlers: harness.handlers
  });
  assert.equal(createV1Route.status, 200);

  const createV2Route = await dispatchApiRoute({
    pathname:
      '/platform/integrations/integration-contract-check-request-id-mismatch/contracts',
    method: 'POST',
    requestId:
      'req-platform-integration-contract-check-request-id-mismatch-create-v2',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: 'v2',
      schema_ref: 's3://contracts/check-request-id-mismatch/v2/openapi.json',
      schema_checksum: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      status: 'candidate',
      is_backward_compatible: true
    },
    handlers: harness.handlers
  });
  assert.equal(createV2Route.status, 200);

  const authStore = harness.authService._internals.authStore;
  const originalCreateCheck =
    authStore.createPlatformIntegrationContractCompatibilityCheck;
  authStore.createPlatformIntegrationContractCompatibilityCheck = async (...args) => {
    const created = await originalCreateCheck(...args);
    return {
      ...created,
      requestId: 'req-platform-integration-contract-forged-request-id'
    };
  };
  try {
    const route = await dispatchApiRoute({
      pathname:
        '/platform/integrations/integration-contract-check-request-id-mismatch/contracts/compatibility-check',
      method: 'POST',
      requestId:
        'req-platform-integration-contract-check-request-id-mismatch-compatibility',
      headers: {
        authorization: `Bearer ${login.access_token}`
      },
      body: {
        contract_type: 'openapi',
        baseline_version: 'v1',
        candidate_version: 'v2',
        breaking_change_count: 0,
        diff_summary: {
          breaking_changes: []
        }
      },
      handlers: harness.handlers
    });
    assert.equal(route.status, 503);
    const payload = JSON.parse(route.body);
    assert.equal(payload.error_code, 'INT-503-DEPENDENCY-UNAVAILABLE');
    assert.equal(
      payload.degradation_reason,
      'integration-contract-compatibility-result-invalid'
    );
    assert.equal(
      payload.request_id,
      'req-platform-integration-contract-check-request-id-mismatch-compatibility'
    );
  } finally {
    authStore.createPlatformIntegrationContractCompatibilityCheck =
      originalCreateCheck;
  }
});

test('contract compatibility accepts semantically equivalent diff_summary when store reorders object keys', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-contract-login-check-summary-key-order'
  });

  const integrationRoute = await createIntegration({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId: 'integration-contract-check-summary-key-order',
    requestId:
      'req-platform-integration-contract-create-integration-check-summary-key-order'
  });
  assert.equal(integrationRoute.status, 200);

  const createV1Route = await dispatchApiRoute({
    pathname:
      '/platform/integrations/integration-contract-check-summary-key-order/contracts',
    method: 'POST',
    requestId:
      'req-platform-integration-contract-check-summary-key-order-create-v1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: 'v1',
      schema_ref: 's3://contracts/check-summary-key-order/v1/openapi.json',
      schema_checksum: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      status: 'candidate',
      is_backward_compatible: true
    },
    handlers: harness.handlers
  });
  assert.equal(createV1Route.status, 200);

  const createV2Route = await dispatchApiRoute({
    pathname:
      '/platform/integrations/integration-contract-check-summary-key-order/contracts',
    method: 'POST',
    requestId:
      'req-platform-integration-contract-check-summary-key-order-create-v2',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: 'v2',
      schema_ref: 's3://contracts/check-summary-key-order/v2/openapi.json',
      schema_checksum: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      status: 'candidate',
      is_backward_compatible: true
    },
    handlers: harness.handlers
  });
  assert.equal(createV2Route.status, 200);

  const authStore = harness.authService._internals.authStore;
  const originalCreateCheck =
    authStore.createPlatformIntegrationContractCompatibilityCheck;
  authStore.createPlatformIntegrationContractCompatibilityCheck = async (...args) => {
    const created = await originalCreateCheck(...args);
    return {
      ...created,
      diffSummary: {
        breaking_changes: [],
        metadata: {
          alpha: 1,
          zeta: 2
        }
      }
    };
  };
  try {
    const route = await dispatchApiRoute({
      pathname:
        '/platform/integrations/integration-contract-check-summary-key-order/contracts/compatibility-check',
      method: 'POST',
      requestId:
        'req-platform-integration-contract-check-summary-key-order-compatibility',
      headers: {
        authorization: `Bearer ${login.access_token}`
      },
      body: {
        contract_type: 'openapi',
        baseline_version: 'v1',
        candidate_version: 'v2',
        breaking_change_count: 0,
        diff_summary: {
          metadata: {
            zeta: 2,
            alpha: 1
          },
          breaking_changes: []
        }
      },
      handlers: harness.handlers
    });
    assert.equal(route.status, 200);
    const payload = JSON.parse(route.body);
    assert.equal(payload.evaluation_result, 'compatible');
    assert.equal(payload.breaking_change_count, 0);
  } finally {
    authStore.createPlatformIntegrationContractCompatibilityCheck =
      originalCreateCheck;
  }
});

test('contract compatibility fails closed when store result diff_summary is non-serializable', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-contract-login-check-summary-circular'
  });

  const integrationRoute = await createIntegration({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId: 'integration-contract-check-summary-circular',
    requestId:
      'req-platform-integration-contract-create-integration-check-summary-circular'
  });
  assert.equal(integrationRoute.status, 200);

  const createV1Route = await dispatchApiRoute({
    pathname:
      '/platform/integrations/integration-contract-check-summary-circular/contracts',
    method: 'POST',
    requestId:
      'req-platform-integration-contract-check-summary-circular-create-v1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: 'v1',
      schema_ref: 's3://contracts/check-summary-circular/v1/openapi.json',
      schema_checksum: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      status: 'candidate',
      is_backward_compatible: true
    },
    handlers: harness.handlers
  });
  assert.equal(createV1Route.status, 200);

  const createV2Route = await dispatchApiRoute({
    pathname:
      '/platform/integrations/integration-contract-check-summary-circular/contracts',
    method: 'POST',
    requestId:
      'req-platform-integration-contract-check-summary-circular-create-v2',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: 'v2',
      schema_ref: 's3://contracts/check-summary-circular/v2/openapi.json',
      schema_checksum: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      status: 'candidate',
      is_backward_compatible: true
    },
    handlers: harness.handlers
  });
  assert.equal(createV2Route.status, 200);

  const authStore = harness.authService._internals.authStore;
  const originalCreateCheck =
    authStore.createPlatformIntegrationContractCompatibilityCheck;
  authStore.createPlatformIntegrationContractCompatibilityCheck = async (...args) => {
    const created = await originalCreateCheck(...args);
    const circularDiffSummary = {
      breaking_changes: []
    };
    circularDiffSummary.self = circularDiffSummary;
    return {
      ...created,
      diffSummary: circularDiffSummary
    };
  };
  try {
    const route = await dispatchApiRoute({
      pathname:
        '/platform/integrations/integration-contract-check-summary-circular/contracts/compatibility-check',
      method: 'POST',
      requestId:
        'req-platform-integration-contract-check-summary-circular-compatibility',
      headers: {
        authorization: `Bearer ${login.access_token}`
      },
      body: {
        contract_type: 'openapi',
        baseline_version: 'v1',
        candidate_version: 'v2',
        breaking_change_count: 0,
        diff_summary: {
          breaking_changes: []
        }
      },
      handlers: harness.handlers
    });
    assert.equal(route.status, 503);
    const payload = JSON.parse(route.body);
    assert.equal(payload.error_code, 'INT-503-DEPENDENCY-UNAVAILABLE');
    assert.equal(
      payload.degradation_reason,
      'integration-contract-compatibility-result-invalid'
    );
    assert.equal(
      payload.request_id,
      'req-platform-integration-contract-check-summary-circular-compatibility'
    );
  } finally {
    authStore.createPlatformIntegrationContractCompatibilityCheck =
      originalCreateCheck;
  }
});

test('contract compatibility rejects null breaking_change_count instead of coercing to zero', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-contract-login-breaking-count-null'
  });

  const integrationRoute = await createIntegration({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId: 'integration-contract-breaking-count-null',
    requestId:
      'req-platform-integration-contract-create-integration-breaking-count-null'
  });
  assert.equal(integrationRoute.status, 200);

  const createV1Route = await dispatchApiRoute({
    pathname: '/platform/integrations/integration-contract-breaking-count-null/contracts',
    method: 'POST',
    requestId: 'req-platform-integration-contract-breaking-count-null-create-v1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: 'v1',
      schema_ref: 's3://contracts/breaking-count-null/v1/openapi.json',
      schema_checksum: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      status: 'candidate',
      is_backward_compatible: true
    },
    handlers: harness.handlers
  });
  assert.equal(createV1Route.status, 200);

  const createV2Route = await dispatchApiRoute({
    pathname: '/platform/integrations/integration-contract-breaking-count-null/contracts',
    method: 'POST',
    requestId: 'req-platform-integration-contract-breaking-count-null-create-v2',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: 'v2',
      schema_ref: 's3://contracts/breaking-count-null/v2/openapi.json',
      schema_checksum: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      status: 'candidate',
      is_backward_compatible: true
    },
    handlers: harness.handlers
  });
  assert.equal(createV2Route.status, 200);

  const route = await dispatchApiRoute({
    pathname:
      '/platform/integrations/integration-contract-breaking-count-null/contracts/compatibility-check',
    method: 'POST',
    requestId: 'req-platform-integration-contract-breaking-count-null-compatibility',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      baseline_version: 'v1',
      candidate_version: 'v2',
      breaking_change_count: null
    },
    handlers: harness.handlers
  });
  assert.equal(route.status, 400);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'integration_contract_invalid_payload');
  assert.equal(
    payload.request_id,
    'req-platform-integration-contract-breaking-count-null-compatibility'
  );
});

test('contract activation follows compatibility check result even when candidate is_backward_compatible is false', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-contract-login-compatible-flag-false'
  });

  const integrationRoute = await createIntegration({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId: 'integration-contract-compatible-flag-false',
    requestId: 'req-platform-integration-contract-create-integration-compatible-flag-false'
  });
  assert.equal(integrationRoute.status, 200);

  const createV1Route = await dispatchApiRoute({
    pathname: '/platform/integrations/integration-contract-compatible-flag-false/contracts',
    method: 'POST',
    requestId: 'req-platform-integration-contract-compatible-flag-false-create-v1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: 'v1',
      schema_ref: 's3://contracts/compatible-flag-false/v1/openapi.json',
      schema_checksum: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      status: 'candidate',
      is_backward_compatible: true
    },
    handlers: harness.handlers
  });
  assert.equal(createV1Route.status, 200);

  const activateV1Route = await dispatchApiRoute({
    pathname: '/platform/integrations/integration-contract-compatible-flag-false/contracts/v1/activate',
    method: 'POST',
    requestId: 'req-platform-integration-contract-compatible-flag-false-activate-v1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi'
    },
    handlers: harness.handlers
  });
  assert.equal(activateV1Route.status, 200);

  const createV2Route = await dispatchApiRoute({
    pathname: '/platform/integrations/integration-contract-compatible-flag-false/contracts',
    method: 'POST',
    requestId: 'req-platform-integration-contract-compatible-flag-false-create-v2',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: 'v2',
      schema_ref: 's3://contracts/compatible-flag-false/v2/openapi.json',
      schema_checksum: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      status: 'candidate',
      is_backward_compatible: false
    },
    handlers: harness.handlers
  });
  assert.equal(createV2Route.status, 200);

  const evaluateRoute = await dispatchApiRoute({
    pathname: '/platform/integrations/integration-contract-compatible-flag-false/contracts/compatibility-check',
    method: 'POST',
    requestId: 'req-platform-integration-contract-compatible-flag-false-compatibility-v1-v2',
    headers: {
      authorization: `Bearer ${login.access_token}`
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
  assert.equal(evaluateRoute.status, 200);
  const evaluatePayload = JSON.parse(evaluateRoute.body);
  assert.equal(evaluatePayload.evaluation_result, 'compatible');

  const activateV2Route = await dispatchApiRoute({
    pathname: '/platform/integrations/integration-contract-compatible-flag-false/contracts/v2/activate',
    method: 'POST',
    requestId: 'req-platform-integration-contract-compatible-flag-false-activate-v2',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      baseline_version: 'v1'
    },
    handlers: harness.handlers
  });
  assert.equal(activateV2Route.status, 200);
  const payload = JSON.parse(activateV2Route.body);
  assert.equal(payload.contract_version, 'v2');
  assert.equal(payload.current_status, 'active');
});

test('contract activation is blocked when compatibility check is missing', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-contract-login-missing-check'
  });

  const integrationRoute = await createIntegration({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId: 'integration-contract-missing-check',
    requestId: 'req-platform-integration-contract-create-integration-missing-check'
  });
  assert.equal(integrationRoute.status, 200);

  const createV1Route = await dispatchApiRoute({
    pathname: '/platform/integrations/integration-contract-missing-check/contracts',
    method: 'POST',
    requestId: 'req-platform-integration-contract-missing-check-create-v1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: 'v1',
      schema_ref: 's3://contracts/missing-check/v1/openapi.json',
      schema_checksum: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      status: 'candidate',
      is_backward_compatible: true
    },
    handlers: harness.handlers
  });
  assert.equal(createV1Route.status, 200);

  const activateV1Route = await dispatchApiRoute({
    pathname: '/platform/integrations/integration-contract-missing-check/contracts/v1/activate',
    method: 'POST',
    requestId: 'req-platform-integration-contract-missing-check-activate-v1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi'
    },
    handlers: harness.handlers
  });
  assert.equal(activateV1Route.status, 200);

  const createV2Route = await dispatchApiRoute({
    pathname: '/platform/integrations/integration-contract-missing-check/contracts',
    method: 'POST',
    requestId: 'req-platform-integration-contract-missing-check-create-v2',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: 'v2',
      schema_ref: 's3://contracts/missing-check/v2/openapi.json',
      schema_checksum: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      status: 'candidate',
      is_backward_compatible: true
    },
    handlers: harness.handlers
  });
  assert.equal(createV2Route.status, 200);

  const activateV2Route = await dispatchApiRoute({
    pathname: '/platform/integrations/integration-contract-missing-check/contracts/v2/activate',
    method: 'POST',
    requestId: 'req-platform-integration-contract-missing-check-activate-v2',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      baseline_version: 'v1'
    },
    handlers: harness.handlers
  });
  assert.equal(activateV2Route.status, 409);
  const payload = JSON.parse(activateV2Route.body);
  assert.equal(payload.error_code, 'integration_contract_activation_blocked');
  assert.equal(payload.request_id, 'req-platform-integration-contract-missing-check-activate-v2');
});

test('contract activation is blocked when compatibility evaluation is incompatible', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-contract-login-incompatible'
  });

  const integrationRoute = await createIntegration({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId: 'integration-contract-incompatible',
    requestId: 'req-platform-integration-contract-create-integration-incompatible'
  });
  assert.equal(integrationRoute.status, 200);

  const createV1Route = await dispatchApiRoute({
    pathname: '/platform/integrations/integration-contract-incompatible/contracts',
    method: 'POST',
    requestId: 'req-platform-integration-contract-incompatible-create-v1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: 'v1',
      schema_ref: 's3://contracts/incompatible/v1/openapi.json',
      schema_checksum: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      status: 'candidate',
      is_backward_compatible: true
    },
    handlers: harness.handlers
  });
  assert.equal(createV1Route.status, 200);

  const activateV1Route = await dispatchApiRoute({
    pathname: '/platform/integrations/integration-contract-incompatible/contracts/v1/activate',
    method: 'POST',
    requestId: 'req-platform-integration-contract-incompatible-activate-v1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi'
    },
    handlers: harness.handlers
  });
  assert.equal(activateV1Route.status, 200);

  const createV2Route = await dispatchApiRoute({
    pathname: '/platform/integrations/integration-contract-incompatible/contracts',
    method: 'POST',
    requestId: 'req-platform-integration-contract-incompatible-create-v2',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: 'v2',
      schema_ref: 's3://contracts/incompatible/v2/openapi.json',
      schema_checksum: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      status: 'candidate',
      is_backward_compatible: true
    },
    handlers: harness.handlers
  });
  assert.equal(createV2Route.status, 200);

  const evaluateIncompatibleRoute = await dispatchApiRoute({
    pathname: '/platform/integrations/integration-contract-incompatible/contracts/compatibility-check',
    method: 'POST',
    requestId: 'req-platform-integration-contract-incompatible-compatibility-v1-v2',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      baseline_version: 'v1',
      candidate_version: 'v2',
      breaking_change_count: 2,
      diff_summary: {
        breaking_changes: [
          'remove field customer_id',
          'rename field total_amount'
        ]
      }
    },
    handlers: harness.handlers
  });
  assert.equal(evaluateIncompatibleRoute.status, 200);
  const evaluatePayload = JSON.parse(evaluateIncompatibleRoute.body);
  assert.equal(evaluatePayload.evaluation_result, 'incompatible');
  assert.equal(evaluatePayload.breaking_change_count, 2);

  const activateV2Route = await dispatchApiRoute({
    pathname: '/platform/integrations/integration-contract-incompatible/contracts/v2/activate',
    method: 'POST',
    requestId: 'req-platform-integration-contract-incompatible-activate-v2',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      baseline_version: 'v1'
    },
    handlers: harness.handlers
  });
  assert.equal(activateV2Route.status, 409);
  const payload = JSON.parse(activateV2Route.body);
  assert.equal(payload.error_code, 'integration_contract_incompatible');
  assert.equal(payload.request_id, 'req-platform-integration-contract-incompatible-activate-v2');
});

test('contract activation blocks retired candidate before compatibility check lookup', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-contract-login-retired-candidate'
  });

  const integrationRoute = await createIntegration({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId: 'integration-contract-retired-candidate',
    requestId: 'req-platform-integration-contract-create-integration-retired-candidate'
  });
  assert.equal(integrationRoute.status, 200);

  const createV1Route = await dispatchApiRoute({
    pathname: '/platform/integrations/integration-contract-retired-candidate/contracts',
    method: 'POST',
    requestId: 'req-platform-integration-contract-retired-candidate-create-v1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: 'v1',
      schema_ref: 's3://contracts/retired-candidate/v1/openapi.json',
      schema_checksum: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      status: 'candidate',
      is_backward_compatible: true
    },
    handlers: harness.handlers
  });
  assert.equal(createV1Route.status, 200);

  const activateV1Route = await dispatchApiRoute({
    pathname: '/platform/integrations/integration-contract-retired-candidate/contracts/v1/activate',
    method: 'POST',
    requestId: 'req-platform-integration-contract-retired-candidate-activate-v1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi'
    },
    handlers: harness.handlers
  });
  assert.equal(activateV1Route.status, 200);

  const createRetiredRoute = await dispatchApiRoute({
    pathname: '/platform/integrations/integration-contract-retired-candidate/contracts',
    method: 'POST',
    requestId: 'req-platform-integration-contract-retired-candidate-create-v2',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: 'v2',
      schema_ref: 's3://contracts/retired-candidate/v2/openapi.json',
      schema_checksum: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      status: 'retired',
      is_backward_compatible: false
    },
    handlers: harness.handlers
  });
  assert.equal(createRetiredRoute.status, 200);

  const authStore = harness.authService._internals.authStore;
  const originalFindLatestCheck =
    authStore.findLatestPlatformIntegrationContractCompatibilityCheck;
  let latestCheckLookupCalled = false;
  authStore.findLatestPlatformIntegrationContractCompatibilityCheck = async () => {
    latestCheckLookupCalled = true;
    const error = new Error('compatibility check store unavailable');
    error.code = 'ERR_COMPATIBILITY_CHECK_STORE_UNAVAILABLE';
    throw error;
  };
  try {
    const activateRetiredRoute = await dispatchApiRoute({
      pathname: '/platform/integrations/integration-contract-retired-candidate/contracts/v2/activate',
      method: 'POST',
      requestId: 'req-platform-integration-contract-retired-candidate-activate-v2',
      headers: {
        authorization: `Bearer ${login.access_token}`
      },
      body: {
        contract_type: 'openapi',
        baseline_version: 'v1'
      },
      handlers: harness.handlers
    });
    assert.equal(activateRetiredRoute.status, 409);
    const payload = JSON.parse(activateRetiredRoute.body);
    assert.equal(payload.error_code, 'integration_contract_activation_blocked');
    assert.equal(payload.reason, 'retired_version');
    assert.equal(payload.baseline_version, 'v1');
    assert.equal(payload.candidate_version, 'v2');
    assert.equal(payload.request_id, 'req-platform-integration-contract-retired-candidate-activate-v2');
    assert.equal(latestCheckLookupCalled, false);
  } finally {
    authStore.findLatestPlatformIntegrationContractCompatibilityCheck =
      originalFindLatestCheck;
  }
});

test('contract activation normalizes store activation_blocked reason to snake_case', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-contract-login-activation-reason-normalize'
  });

  const integrationRoute = await createIntegration({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId: 'integration-contract-activation-reason-normalize',
    requestId:
      'req-platform-integration-contract-create-integration-activation-reason-normalize'
  });
  assert.equal(integrationRoute.status, 200);

  const createV1Route = await dispatchApiRoute({
    pathname:
      '/platform/integrations/integration-contract-activation-reason-normalize/contracts',
    method: 'POST',
    requestId:
      'req-platform-integration-contract-activation-reason-normalize-create-v1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: 'v1',
      schema_ref: 's3://contracts/activation-reason-normalize/v1/openapi.json',
      schema_checksum: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      status: 'candidate',
      is_backward_compatible: true
    },
    handlers: harness.handlers
  });
  assert.equal(createV1Route.status, 200);

  const activateV1Route = await dispatchApiRoute({
    pathname:
      '/platform/integrations/integration-contract-activation-reason-normalize/contracts/v1/activate',
    method: 'POST',
    requestId:
      'req-platform-integration-contract-activation-reason-normalize-activate-v1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi'
    },
    handlers: harness.handlers
  });
  assert.equal(activateV1Route.status, 200);

  const createV2Route = await dispatchApiRoute({
    pathname:
      '/platform/integrations/integration-contract-activation-reason-normalize/contracts',
    method: 'POST',
    requestId:
      'req-platform-integration-contract-activation-reason-normalize-create-v2',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: 'v2',
      schema_ref: 's3://contracts/activation-reason-normalize/v2/openapi.json',
      schema_checksum: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      status: 'candidate',
      is_backward_compatible: true
    },
    handlers: harness.handlers
  });
  assert.equal(createV2Route.status, 200);

  const evaluateRoute = await dispatchApiRoute({
    pathname:
      '/platform/integrations/integration-contract-activation-reason-normalize/contracts/compatibility-check',
    method: 'POST',
    requestId:
      'req-platform-integration-contract-activation-reason-normalize-compatibility',
    headers: {
      authorization: `Bearer ${login.access_token}`
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
  assert.equal(evaluateRoute.status, 200);

  const authStore = harness.authService._internals.authStore;
  const originalActivate = authStore.activatePlatformIntegrationContractVersion;
  authStore.activatePlatformIntegrationContractVersion = async () => {
    const error = new Error('activation blocked by store');
    error.code = 'ERR_PLATFORM_INTEGRATION_CONTRACT_ACTIVATION_BLOCKED';
    error.reason = 'retired-version';
    throw error;
  };
  try {
    const route = await dispatchApiRoute({
      pathname:
        '/platform/integrations/integration-contract-activation-reason-normalize/contracts/v2/activate',
      method: 'POST',
      requestId:
        'req-platform-integration-contract-activation-reason-normalize-activate-v2',
      headers: {
        authorization: `Bearer ${login.access_token}`
      },
      body: {
        contract_type: 'openapi',
        baseline_version: 'v1'
      },
      handlers: harness.handlers
    });
    assert.equal(route.status, 409);
    const payload = JSON.parse(route.body);
    assert.equal(payload.error_code, 'integration_contract_activation_blocked');
    assert.equal(payload.reason, 'retired_version');
    assert.equal(
      payload.request_id,
      'req-platform-integration-contract-activation-reason-normalize-activate-v2'
    );
  } finally {
    authStore.activatePlatformIntegrationContractVersion = originalActivate;
  }
});

test('contract activation blocks baseline_version mismatch to prevent compatibility bypass', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-contract-login-baseline-mismatch'
  });

  const integrationRoute = await createIntegration({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId: 'integration-contract-baseline-mismatch',
    requestId: 'req-platform-integration-contract-create-integration-baseline-mismatch'
  });
  assert.equal(integrationRoute.status, 200);

  const createV1Route = await dispatchApiRoute({
    pathname: '/platform/integrations/integration-contract-baseline-mismatch/contracts',
    method: 'POST',
    requestId: 'req-platform-integration-contract-baseline-mismatch-create-v1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: 'v1',
      schema_ref: 's3://contracts/baseline-mismatch/v1/openapi.json',
      schema_checksum: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      status: 'candidate',
      is_backward_compatible: true
    },
    handlers: harness.handlers
  });
  assert.equal(createV1Route.status, 200);

  const activateV1Route = await dispatchApiRoute({
    pathname: '/platform/integrations/integration-contract-baseline-mismatch/contracts/v1/activate',
    method: 'POST',
    requestId: 'req-platform-integration-contract-baseline-mismatch-activate-v1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi'
    },
    handlers: harness.handlers
  });
  assert.equal(activateV1Route.status, 200);

  const createV2Route = await dispatchApiRoute({
    pathname: '/platform/integrations/integration-contract-baseline-mismatch/contracts',
    method: 'POST',
    requestId: 'req-platform-integration-contract-baseline-mismatch-create-v2',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: 'v2',
      schema_ref: 's3://contracts/baseline-mismatch/v2/openapi.json',
      schema_checksum: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      status: 'candidate',
      is_backward_compatible: true
    },
    handlers: harness.handlers
  });
  assert.equal(createV2Route.status, 200);

  const bypassAttemptRoute = await dispatchApiRoute({
    pathname: '/platform/integrations/integration-contract-baseline-mismatch/contracts/v2/activate',
    method: 'POST',
    requestId: 'req-platform-integration-contract-baseline-mismatch-activate-bypass',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      baseline_version: 'v2'
    },
    handlers: harness.handlers
  });
  assert.equal(bypassAttemptRoute.status, 409);
  const payload = JSON.parse(bypassAttemptRoute.body);
  assert.equal(payload.error_code, 'integration_contract_activation_blocked');
  assert.equal(payload.reason, 'baseline_version_mismatch');
  assert.equal(payload.baseline_version, 'v1');
  assert.equal(payload.candidate_version, 'v2');
});

test('contract compatibility maps store lookup failures to stable 503 problem details', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-contract-login-store-failure'
  });

  const integrationRoute = await createIntegration({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId: 'integration-contract-store-failure',
    requestId: 'req-platform-integration-contract-create-integration-store-failure'
  });
  assert.equal(integrationRoute.status, 200);

  const createV1Route = await dispatchApiRoute({
    pathname: '/platform/integrations/integration-contract-store-failure/contracts',
    method: 'POST',
    requestId: 'req-platform-integration-contract-store-failure-create-v1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: 'v1',
      schema_ref: 's3://contracts/store-failure/v1/openapi.json',
      schema_checksum: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      status: 'candidate',
      is_backward_compatible: true
    },
    handlers: harness.handlers
  });
  assert.equal(createV1Route.status, 200);

  const authStore = harness.authService._internals.authStore;
  const originalFindContract = authStore.findPlatformIntegrationContractVersion;
  authStore.findPlatformIntegrationContractVersion = async () => {
    const error = new Error('lookup failure');
    error.code = 'ERR_STORE_LOOKUP_FAILED';
    throw error;
  };
  try {
    const route = await dispatchApiRoute({
      pathname: '/platform/integrations/integration-contract-store-failure/contracts/compatibility-check',
      method: 'POST',
      requestId: 'req-platform-integration-contract-store-failure-compatibility',
      headers: {
        authorization: `Bearer ${login.access_token}`
      },
      body: {
        contract_type: 'openapi',
        baseline_version: 'v1',
        candidate_version: 'v2'
      },
      handlers: harness.handlers
    });
    assert.equal(route.status, 503);
    const payload = JSON.parse(route.body);
    assert.equal(payload.error_code, 'INT-503-DEPENDENCY-UNAVAILABLE');
    assert.equal(payload.request_id, 'req-platform-integration-contract-store-failure-compatibility');
    assert.equal(payload.retryable, true);
  } finally {
    authStore.findPlatformIntegrationContractVersion = originalFindContract;
  }
});

test('contract governance fails closed when integration catalog lookup result mismatches requested integration_id', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-contract-login-catalog-mismatch'
  });

  const createSourceIntegrationRoute = await createIntegration({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId: 'integration-contract-catalog-mismatch-source',
    requestId:
      'req-platform-integration-contract-create-integration-catalog-mismatch-source'
  });
  assert.equal(createSourceIntegrationRoute.status, 200);

  const authStore = harness.authService._internals.authStore;
  const originalFindIntegration =
    authStore.findPlatformIntegrationCatalogEntryByIntegrationId;
  authStore.findPlatformIntegrationCatalogEntryByIntegrationId = async () => ({
    integration_id: 'integration-contract-catalog-mismatch-source',
    lifecycle_status: 'active'
  });
  try {
    const route = await dispatchApiRoute({
      pathname: '/platform/integrations/integration-contract-catalog-mismatch-target/contracts',
      method: 'GET',
      requestId: 'req-platform-integration-contract-catalog-mismatch-list',
      headers: {
        authorization: `Bearer ${login.access_token}`
      },
      handlers: harness.handlers
    });
    assert.equal(route.status, 503);
    const payload = JSON.parse(route.body);
    assert.equal(payload.error_code, 'INT-503-DEPENDENCY-UNAVAILABLE');
    assert.equal(payload.degradation_reason, 'integration-catalog-record-invalid');
    assert.equal(
      payload.request_id,
      'req-platform-integration-contract-catalog-mismatch-list'
    );
  } finally {
    authStore.findPlatformIntegrationCatalogEntryByIntegrationId =
      originalFindIntegration;
  }
});

test('contract compatibility fails closed when baseline/candidate lookup result is malformed', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-contract-login-malformed-lookup'
  });

  const integrationRoute = await createIntegration({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId: 'integration-contract-malformed-lookup',
    requestId: 'req-platform-integration-contract-create-integration-malformed-lookup'
  });
  assert.equal(integrationRoute.status, 200);

  for (const [contractVersion, checksum] of [
    [
      'v1',
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    ],
    [
      'v2',
      'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
    ]
  ]) {
    const createRoute = await dispatchApiRoute({
      pathname: '/platform/integrations/integration-contract-malformed-lookup/contracts',
      method: 'POST',
      requestId: `req-platform-integration-contract-malformed-lookup-create-${contractVersion}`,
      headers: {
        authorization: `Bearer ${login.access_token}`
      },
      body: {
        contract_type: 'openapi',
        contract_version: contractVersion,
        schema_ref: `s3://contracts/malformed-lookup/${contractVersion}/openapi.json`,
        schema_checksum: checksum,
        status: 'candidate',
        is_backward_compatible: true
      },
      handlers: harness.handlers
    });
    assert.equal(createRoute.status, 200);
  }

  const authStore = harness.authService._internals.authStore;
  const originalFindContract = authStore.findPlatformIntegrationContractVersion;
  authStore.findPlatformIntegrationContractVersion = async () => ({
    integration_id: 'integration-contract-malformed-lookup',
    contract_type: 'openapi',
    contract_version: 'v1'
  });
  try {
    const route = await dispatchApiRoute({
      pathname: '/platform/integrations/integration-contract-malformed-lookup/contracts/compatibility-check',
      method: 'POST',
      requestId: 'req-platform-integration-contract-malformed-lookup-compatibility',
      headers: {
        authorization: `Bearer ${login.access_token}`
      },
      body: {
        contract_type: 'openapi',
        baseline_version: 'v1',
        candidate_version: 'v2'
      },
      handlers: harness.handlers
    });
    assert.equal(route.status, 503);
    const payload = JSON.parse(route.body);
    assert.equal(payload.error_code, 'INT-503-DEPENDENCY-UNAVAILABLE');
    assert.equal(
      payload.request_id,
      'req-platform-integration-contract-malformed-lookup-compatibility'
    );
    assert.equal(
      payload.degradation_reason,
      'integration-contract-baseline-read-result-malformed'
    );
  } finally {
    authStore.findPlatformIntegrationContractVersion = originalFindContract;
  }
});

test('contract activation fails closed when candidate lookup result mismatches requested contract_version', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-contract-login-activate-candidate-mismatch'
  });

  const integrationRoute = await createIntegration({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId: 'integration-contract-activate-candidate-mismatch',
    requestId: 'req-platform-integration-contract-create-integration-activate-candidate-mismatch'
  });
  assert.equal(integrationRoute.status, 200);

  for (const [contractVersion, checksum] of [
    [
      'v1',
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    ],
    [
      'v2',
      'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
    ]
  ]) {
    const createRoute = await dispatchApiRoute({
      pathname:
        '/platform/integrations/integration-contract-activate-candidate-mismatch/contracts',
      method: 'POST',
      requestId:
        `req-platform-integration-contract-activate-candidate-mismatch-create-${contractVersion}`,
      headers: {
        authorization: `Bearer ${login.access_token}`
      },
      body: {
        contract_type: 'openapi',
        contract_version: contractVersion,
        schema_ref: `s3://contracts/activate-candidate-mismatch/${contractVersion}/openapi.json`,
        schema_checksum: checksum,
        status: 'candidate',
        is_backward_compatible: true
      },
      handlers: harness.handlers
    });
    assert.equal(createRoute.status, 200);
  }

  const authStore = harness.authService._internals.authStore;
  const originalFindContract = authStore.findPlatformIntegrationContractVersion;
  authStore.findPlatformIntegrationContractVersion = async (lookup = {}) =>
    originalFindContract({
      ...lookup,
      contractVersion: 'v2'
    });
  try {
    const route = await dispatchApiRoute({
      pathname:
        '/platform/integrations/integration-contract-activate-candidate-mismatch/contracts/v1/activate',
      method: 'POST',
      requestId: 'req-platform-integration-contract-activate-candidate-mismatch-activate',
      headers: {
        authorization: `Bearer ${login.access_token}`
      },
      body: {
        contract_type: 'openapi'
      },
      handlers: harness.handlers
    });
    assert.equal(route.status, 503);
    const payload = JSON.parse(route.body);
    assert.equal(payload.error_code, 'INT-503-DEPENDENCY-UNAVAILABLE');
    assert.equal(
      payload.degradation_reason,
      'integration-contract-candidate-read-result-malformed'
    );
    assert.equal(
      payload.request_id,
      'req-platform-integration-contract-activate-candidate-mismatch-activate'
    );
  } finally {
    authStore.findPlatformIntegrationContractVersion = originalFindContract;
  }
});

test('contract activation fails closed when candidate lookup result is malformed', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-contract-login-activate-candidate-malformed'
  });

  const integrationRoute = await createIntegration({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId: 'integration-contract-activate-candidate-malformed',
    requestId:
      'req-platform-integration-contract-create-integration-activate-candidate-malformed'
  });
  assert.equal(integrationRoute.status, 200);

  const createRoute = await dispatchApiRoute({
    pathname:
      '/platform/integrations/integration-contract-activate-candidate-malformed/contracts',
    method: 'POST',
    requestId: 'req-platform-integration-contract-activate-candidate-malformed-create-v1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: 'v1',
      schema_ref: 's3://contracts/activate-candidate-malformed/v1/openapi.json',
      schema_checksum: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      status: 'candidate',
      is_backward_compatible: true
    },
    handlers: harness.handlers
  });
  assert.equal(createRoute.status, 200);

  const authStore = harness.authService._internals.authStore;
  const originalFindContract = authStore.findPlatformIntegrationContractVersion;
  authStore.findPlatformIntegrationContractVersion = async () => ({
    integration_id: 'integration-contract-activate-candidate-malformed',
    contract_type: 'openapi',
    contract_version: 'v1'
  });
  try {
    const route = await dispatchApiRoute({
      pathname:
        '/platform/integrations/integration-contract-activate-candidate-malformed/contracts/v1/activate',
      method: 'POST',
      requestId: 'req-platform-integration-contract-activate-candidate-malformed-activate',
      headers: {
        authorization: `Bearer ${login.access_token}`
      },
      body: {
        contract_type: 'openapi'
      },
      handlers: harness.handlers
    });
    assert.equal(route.status, 503);
    const payload = JSON.parse(route.body);
    assert.equal(payload.error_code, 'INT-503-DEPENDENCY-UNAVAILABLE');
    assert.equal(
      payload.request_id,
      'req-platform-integration-contract-activate-candidate-malformed-activate'
    );
    assert.equal(
      payload.degradation_reason,
      'integration-contract-candidate-read-result-malformed'
    );
  } finally {
    authStore.findPlatformIntegrationContractVersion = originalFindContract;
  }
});

test('contract activation fails closed when active contract lookup result is malformed', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-contract-login-activate-active-malformed'
  });

  const integrationRoute = await createIntegration({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId: 'integration-contract-activate-active-malformed',
    requestId:
      'req-platform-integration-contract-create-integration-activate-active-malformed'
  });
  assert.equal(integrationRoute.status, 200);

  const createV1Route = await dispatchApiRoute({
    pathname: '/platform/integrations/integration-contract-activate-active-malformed/contracts',
    method: 'POST',
    requestId: 'req-platform-integration-contract-activate-active-malformed-create-v1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: 'v1',
      schema_ref: 's3://contracts/activate-active-malformed/v1/openapi.json',
      schema_checksum: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      status: 'candidate',
      is_backward_compatible: true
    },
    handlers: harness.handlers
  });
  assert.equal(createV1Route.status, 200);

  const activateV1Route = await dispatchApiRoute({
    pathname:
      '/platform/integrations/integration-contract-activate-active-malformed/contracts/v1/activate',
    method: 'POST',
    requestId: 'req-platform-integration-contract-activate-active-malformed-activate-v1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi'
    },
    handlers: harness.handlers
  });
  assert.equal(activateV1Route.status, 200);

  const createV2Route = await dispatchApiRoute({
    pathname: '/platform/integrations/integration-contract-activate-active-malformed/contracts',
    method: 'POST',
    requestId: 'req-platform-integration-contract-activate-active-malformed-create-v2',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: 'v2',
      schema_ref: 's3://contracts/activate-active-malformed/v2/openapi.json',
      schema_checksum: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      status: 'candidate',
      is_backward_compatible: true
    },
    handlers: harness.handlers
  });
  assert.equal(createV2Route.status, 200);

  const authStore = harness.authService._internals.authStore;
  const originalFindLatestActive =
    authStore.findLatestActivePlatformIntegrationContractVersion;
  authStore.findLatestActivePlatformIntegrationContractVersion = async () => ({
    integration_id: 'integration-contract-activate-active-malformed',
    contract_type: 'openapi',
    contract_version: 'v1',
    status: 'active'
  });
  try {
    const route = await dispatchApiRoute({
      pathname:
        '/platform/integrations/integration-contract-activate-active-malformed/contracts/v2/activate',
      method: 'POST',
      requestId: 'req-platform-integration-contract-activate-active-malformed-activate-v2',
      headers: {
        authorization: `Bearer ${login.access_token}`
      },
      body: {
        contract_type: 'openapi'
      },
      handlers: harness.handlers
    });
    assert.equal(route.status, 503);
    const payload = JSON.parse(route.body);
    assert.equal(payload.error_code, 'INT-503-DEPENDENCY-UNAVAILABLE');
    assert.equal(
      payload.request_id,
      'req-platform-integration-contract-activate-active-malformed-activate-v2'
    );
    assert.equal(
      payload.degradation_reason,
      'integration-contract-active-read-result-malformed'
    );
  } finally {
    authStore.findLatestActivePlatformIntegrationContractVersion =
      originalFindLatestActive;
  }
});

test('contract compatibility rejects oversized diff_summary with stable 400 problem details', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-contract-login-diff-summary-oversize'
  });

  const integrationRoute = await createIntegration({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId: 'integration-contract-diff-summary-oversize',
    requestId: 'req-platform-integration-contract-create-integration-diff-summary-oversize'
  });
  assert.equal(integrationRoute.status, 200);

  const createV1Route = await dispatchApiRoute({
    pathname: '/platform/integrations/integration-contract-diff-summary-oversize/contracts',
    method: 'POST',
    requestId: 'req-platform-integration-contract-diff-summary-oversize-create-v1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: 'v1',
      schema_ref: 's3://contracts/diff-summary-oversize/v1/openapi.json',
      schema_checksum: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      status: 'candidate',
      is_backward_compatible: true
    },
    handlers: harness.handlers
  });
  assert.equal(createV1Route.status, 200);

  const createV2Route = await dispatchApiRoute({
    pathname: '/platform/integrations/integration-contract-diff-summary-oversize/contracts',
    method: 'POST',
    requestId: 'req-platform-integration-contract-diff-summary-oversize-create-v2',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: 'v2',
      schema_ref: 's3://contracts/diff-summary-oversize/v2/openapi.json',
      schema_checksum: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      status: 'candidate',
      is_backward_compatible: true
    },
    handlers: harness.handlers
  });
  assert.equal(createV2Route.status, 200);

  const route = await dispatchApiRoute({
    pathname: '/platform/integrations/integration-contract-diff-summary-oversize/contracts/compatibility-check',
    method: 'POST',
    requestId: 'req-platform-integration-contract-diff-summary-oversize-compatibility',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      baseline_version: 'v1',
      candidate_version: 'v2',
      diff_summary: {
        raw_diff: 'x'.repeat(70000)
      }
    },
    handlers: harness.handlers
  });
  assert.equal(route.status, 400);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'integration_contract_invalid_payload');
  assert.equal(
    payload.request_id,
    'req-platform-integration-contract-diff-summary-oversize-compatibility'
  );
});

test('contract compatibility infers incompatible when diff_summary is a non-empty array', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-contract-login-diff-summary-array'
  });

  const integrationRoute = await createIntegration({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId: 'integration-contract-diff-summary-array',
    requestId: 'req-platform-integration-contract-create-integration-diff-summary-array'
  });
  assert.equal(integrationRoute.status, 200);

  const createV1Route = await dispatchApiRoute({
    pathname: '/platform/integrations/integration-contract-diff-summary-array/contracts',
    method: 'POST',
    requestId: 'req-platform-integration-contract-diff-summary-array-create-v1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: 'v1',
      schema_ref: 's3://contracts/diff-summary-array/v1/openapi.json',
      schema_checksum: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      status: 'candidate',
      is_backward_compatible: true
    },
    handlers: harness.handlers
  });
  assert.equal(createV1Route.status, 200);

  const createV2Route = await dispatchApiRoute({
    pathname: '/platform/integrations/integration-contract-diff-summary-array/contracts',
    method: 'POST',
    requestId: 'req-platform-integration-contract-diff-summary-array-create-v2',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: 'v2',
      schema_ref: 's3://contracts/diff-summary-array/v2/openapi.json',
      schema_checksum: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      status: 'candidate',
      is_backward_compatible: true
    },
    handlers: harness.handlers
  });
  assert.equal(createV2Route.status, 200);

  const route = await dispatchApiRoute({
    pathname: '/platform/integrations/integration-contract-diff-summary-array/contracts/compatibility-check',
    method: 'POST',
    requestId: 'req-platform-integration-contract-diff-summary-array-compatibility',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      baseline_version: 'v1',
      candidate_version: 'v2',
      diff_summary: ['remove required field order_id']
    },
    handlers: harness.handlers
  });
  assert.equal(route.status, 200);
  const payload = JSON.parse(route.body);
  assert.equal(payload.evaluation_result, 'incompatible');
  assert.equal(payload.breaking_change_count, 1);
});

test('contract compatibility rejects mismatched breaking_change_count and diff_summary inference', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId:
      'req-platform-integration-contract-login-diff-summary-count-mismatch'
  });

  const integrationRoute = await createIntegration({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId: 'integration-contract-diff-summary-count-mismatch',
    requestId:
      'req-platform-integration-contract-create-integration-diff-summary-count-mismatch'
  });
  assert.equal(integrationRoute.status, 200);

  const createV1Route = await dispatchApiRoute({
    pathname:
      '/platform/integrations/integration-contract-diff-summary-count-mismatch/contracts',
    method: 'POST',
    requestId:
      'req-platform-integration-contract-diff-summary-count-mismatch-create-v1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: 'v1',
      schema_ref: 's3://contracts/diff-summary-count-mismatch/v1/openapi.json',
      schema_checksum:
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      status: 'candidate',
      is_backward_compatible: true
    },
    handlers: harness.handlers
  });
  assert.equal(createV1Route.status, 200);

  const createV2Route = await dispatchApiRoute({
    pathname:
      '/platform/integrations/integration-contract-diff-summary-count-mismatch/contracts',
    method: 'POST',
    requestId:
      'req-platform-integration-contract-diff-summary-count-mismatch-create-v2',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: 'v2',
      schema_ref: 's3://contracts/diff-summary-count-mismatch/v2/openapi.json',
      schema_checksum:
        'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      status: 'candidate',
      is_backward_compatible: true
    },
    handlers: harness.handlers
  });
  assert.equal(createV2Route.status, 200);

  const route = await dispatchApiRoute({
    pathname:
      '/platform/integrations/integration-contract-diff-summary-count-mismatch/contracts/compatibility-check',
    method: 'POST',
    requestId:
      'req-platform-integration-contract-diff-summary-count-mismatch-compatibility',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      baseline_version: 'v1',
      candidate_version: 'v2',
      breaking_change_count: 0,
      diff_summary: ['remove required field order_id']
    },
    handlers: harness.handlers
  });
  assert.equal(route.status, 400);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'integration_contract_invalid_payload');
  assert.equal(
    payload.request_id,
    'req-platform-integration-contract-diff-summary-count-mismatch-compatibility'
  );
});

test('contract compatibility rejects negative diff_summary.breaking_change_count', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-contract-login-diff-summary-negative'
  });

  const integrationRoute = await createIntegration({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId: 'integration-contract-diff-summary-negative',
    requestId:
      'req-platform-integration-contract-create-integration-diff-summary-negative'
  });
  assert.equal(integrationRoute.status, 200);

  const createV1Route = await dispatchApiRoute({
    pathname:
      '/platform/integrations/integration-contract-diff-summary-negative/contracts',
    method: 'POST',
    requestId:
      'req-platform-integration-contract-diff-summary-negative-create-v1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: 'v1',
      schema_ref: 's3://contracts/diff-summary-negative/v1/openapi.json',
      schema_checksum:
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      status: 'candidate',
      is_backward_compatible: true
    },
    handlers: harness.handlers
  });
  assert.equal(createV1Route.status, 200);

  const createV2Route = await dispatchApiRoute({
    pathname:
      '/platform/integrations/integration-contract-diff-summary-negative/contracts',
    method: 'POST',
    requestId:
      'req-platform-integration-contract-diff-summary-negative-create-v2',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: 'v2',
      schema_ref: 's3://contracts/diff-summary-negative/v2/openapi.json',
      schema_checksum:
        'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      status: 'candidate',
      is_backward_compatible: true
    },
    handlers: harness.handlers
  });
  assert.equal(createV2Route.status, 200);

  const route = await dispatchApiRoute({
    pathname:
      '/platform/integrations/integration-contract-diff-summary-negative/contracts/compatibility-check',
    method: 'POST',
    requestId:
      'req-platform-integration-contract-diff-summary-negative-compatibility',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      baseline_version: 'v1',
      candidate_version: 'v2',
      diff_summary: {
        breaking_change_count: -1
      }
    },
    handlers: harness.handlers
  });
  assert.equal(route.status, 400);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'integration_contract_invalid_payload');
  assert.equal(
    payload.request_id,
    'req-platform-integration-contract-diff-summary-negative-compatibility'
  );
});

test('contract compatibility rejects breaking_change_count overflow beyond unsigned int range', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-contract-login-breaking-count-overflow'
  });

  const integrationRoute = await createIntegration({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId: 'integration-contract-breaking-count-overflow',
    requestId:
      'req-platform-integration-contract-create-integration-breaking-count-overflow'
  });
  assert.equal(integrationRoute.status, 200);

  const createV1Route = await dispatchApiRoute({
    pathname:
      '/platform/integrations/integration-contract-breaking-count-overflow/contracts',
    method: 'POST',
    requestId:
      'req-platform-integration-contract-breaking-count-overflow-create-v1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: 'v1',
      schema_ref: 's3://contracts/breaking-count-overflow/v1/openapi.json',
      schema_checksum:
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      status: 'candidate',
      is_backward_compatible: true
    },
    handlers: harness.handlers
  });
  assert.equal(createV1Route.status, 200);

  const createV2Route = await dispatchApiRoute({
    pathname:
      '/platform/integrations/integration-contract-breaking-count-overflow/contracts',
    method: 'POST',
    requestId:
      'req-platform-integration-contract-breaking-count-overflow-create-v2',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: 'v2',
      schema_ref: 's3://contracts/breaking-count-overflow/v2/openapi.json',
      schema_checksum:
        'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      status: 'candidate',
      is_backward_compatible: true
    },
    handlers: harness.handlers
  });
  assert.equal(createV2Route.status, 200);

  const route = await dispatchApiRoute({
    pathname:
      '/platform/integrations/integration-contract-breaking-count-overflow/contracts/compatibility-check',
    method: 'POST',
    requestId:
      'req-platform-integration-contract-breaking-count-overflow-compatibility',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      baseline_version: 'v1',
      candidate_version: 'v2',
      breaking_change_count: 4294967296
    },
    handlers: harness.handlers
  });
  assert.equal(route.status, 400);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'integration_contract_invalid_payload');
  assert.equal(
    payload.request_id,
    'req-platform-integration-contract-breaking-count-overflow-compatibility'
  );
});

test('contract activation fails closed when latest compatibility check read result is malformed', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-contract-login-malformed-latest-check'
  });

  const integrationRoute = await createIntegration({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId: 'integration-contract-malformed-latest-check',
    requestId: 'req-platform-integration-contract-create-integration-malformed-latest-check'
  });
  assert.equal(integrationRoute.status, 200);

  const createV1Route = await dispatchApiRoute({
    pathname: '/platform/integrations/integration-contract-malformed-latest-check/contracts',
    method: 'POST',
    requestId: 'req-platform-integration-contract-malformed-latest-check-create-v1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: 'v1',
      schema_ref: 's3://contracts/malformed-latest-check/v1/openapi.json',
      schema_checksum: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      status: 'candidate',
      is_backward_compatible: true
    },
    handlers: harness.handlers
  });
  assert.equal(createV1Route.status, 200);

  const activateV1Route = await dispatchApiRoute({
    pathname:
      '/platform/integrations/integration-contract-malformed-latest-check/contracts/v1/activate',
    method: 'POST',
    requestId: 'req-platform-integration-contract-malformed-latest-check-activate-v1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi'
    },
    handlers: harness.handlers
  });
  assert.equal(activateV1Route.status, 200);

  const createV2Route = await dispatchApiRoute({
    pathname: '/platform/integrations/integration-contract-malformed-latest-check/contracts',
    method: 'POST',
    requestId: 'req-platform-integration-contract-malformed-latest-check-create-v2',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: 'v2',
      schema_ref: 's3://contracts/malformed-latest-check/v2/openapi.json',
      schema_checksum: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      status: 'candidate',
      is_backward_compatible: true
    },
    handlers: harness.handlers
  });
  assert.equal(createV2Route.status, 200);

  const authStore = harness.authService._internals.authStore;
  const originalFindLatestCheck =
    authStore.findLatestPlatformIntegrationContractCompatibilityCheck;
  authStore.findLatestPlatformIntegrationContractCompatibilityCheck = async () => ({
    integration_id: 'integration-contract-malformed-latest-check',
    contract_type: 'openapi',
    baseline_version: 'v1',
    candidate_version: 'v2',
    evaluation_result: 'compatible',
    breaking_change_count: 0
  });
  try {
    const route = await dispatchApiRoute({
      pathname:
        '/platform/integrations/integration-contract-malformed-latest-check/contracts/v2/activate',
      method: 'POST',
      requestId: 'req-platform-integration-contract-malformed-latest-check-activate-v2',
      headers: {
        authorization: `Bearer ${login.access_token}`
      },
      body: {
        contract_type: 'openapi',
        baseline_version: 'v1'
      },
      handlers: harness.handlers
    });
    assert.equal(route.status, 503);
    const payload = JSON.parse(route.body);
    assert.equal(payload.error_code, 'INT-503-DEPENDENCY-UNAVAILABLE');
    assert.equal(
      payload.degradation_reason,
      'integration-contract-compatibility-check-read-result-malformed'
    );
    assert.equal(
      payload.request_id,
      'req-platform-integration-contract-malformed-latest-check-activate-v2'
    );
  } finally {
    authStore.findLatestPlatformIntegrationContractCompatibilityCheck =
      originalFindLatestCheck;
  }
});

test('contract activation fails closed when latest compatibility check marks compatible with non-zero breaking_change_count', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-contract-login-latest-check-compatible-nonzero'
  });

  const integrationRoute = await createIntegration({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId: 'integration-contract-latest-check-compatible-nonzero',
    requestId:
      'req-platform-integration-contract-create-integration-latest-check-compatible-nonzero'
  });
  assert.equal(integrationRoute.status, 200);

  const createV1Route = await dispatchApiRoute({
    pathname:
      '/platform/integrations/integration-contract-latest-check-compatible-nonzero/contracts',
    method: 'POST',
    requestId:
      'req-platform-integration-contract-latest-check-compatible-nonzero-create-v1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: 'v1',
      schema_ref: 's3://contracts/latest-check-compatible-nonzero/v1/openapi.json',
      schema_checksum: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      status: 'candidate',
      is_backward_compatible: true
    },
    handlers: harness.handlers
  });
  assert.equal(createV1Route.status, 200);

  const activateV1Route = await dispatchApiRoute({
    pathname:
      '/platform/integrations/integration-contract-latest-check-compatible-nonzero/contracts/v1/activate',
    method: 'POST',
    requestId:
      'req-platform-integration-contract-latest-check-compatible-nonzero-activate-v1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi'
    },
    handlers: harness.handlers
  });
  assert.equal(activateV1Route.status, 200);

  const createV2Route = await dispatchApiRoute({
    pathname:
      '/platform/integrations/integration-contract-latest-check-compatible-nonzero/contracts',
    method: 'POST',
    requestId:
      'req-platform-integration-contract-latest-check-compatible-nonzero-create-v2',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: 'v2',
      schema_ref: 's3://contracts/latest-check-compatible-nonzero/v2/openapi.json',
      schema_checksum: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      status: 'candidate',
      is_backward_compatible: true
    },
    handlers: harness.handlers
  });
  assert.equal(createV2Route.status, 200);

  const authStore = harness.authService._internals.authStore;
  const originalFindLatestCheck =
    authStore.findLatestPlatformIntegrationContractCompatibilityCheck;
  authStore.findLatestPlatformIntegrationContractCompatibilityCheck = async () => ({
    integration_id: 'integration-contract-latest-check-compatible-nonzero',
    contract_type: 'openapi',
    baseline_version: 'v1',
    candidate_version: 'v2',
    evaluation_result: 'compatible',
    breaking_change_count: 1,
    diff_summary: {
      breaking_changes: ['remove required field order_id']
    },
    request_id: 'req-platform-integration-contract-latest-check-compatible-nonzero-forged',
    checked_by_user_id: 'platform-integration-contract-operator',
    checked_at: new Date().toISOString()
  });
  try {
    const route = await dispatchApiRoute({
      pathname:
        '/platform/integrations/integration-contract-latest-check-compatible-nonzero/contracts/v2/activate',
      method: 'POST',
      requestId:
        'req-platform-integration-contract-latest-check-compatible-nonzero-activate-v2',
      headers: {
        authorization: `Bearer ${login.access_token}`
      },
      body: {
        contract_type: 'openapi',
        baseline_version: 'v1'
      },
      handlers: harness.handlers
    });
    assert.equal(route.status, 503);
    const payload = JSON.parse(route.body);
    assert.equal(payload.error_code, 'INT-503-DEPENDENCY-UNAVAILABLE');
    assert.equal(
      payload.degradation_reason,
      'integration-contract-compatibility-check-read-result-malformed'
    );
    assert.equal(
      payload.request_id,
      'req-platform-integration-contract-latest-check-compatible-nonzero-activate-v2'
    );
  } finally {
    authStore.findLatestPlatformIntegrationContractCompatibilityCheck =
      originalFindLatestCheck;
  }
});

test('contract activation fails closed when latest compatibility check breaking_change_count overflows unsigned int range', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-contract-login-latest-check-count-overflow'
  });

  const integrationRoute = await createIntegration({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId: 'integration-contract-latest-check-count-overflow',
    requestId:
      'req-platform-integration-contract-create-integration-latest-check-count-overflow'
  });
  assert.equal(integrationRoute.status, 200);

  const createV1Route = await dispatchApiRoute({
    pathname:
      '/platform/integrations/integration-contract-latest-check-count-overflow/contracts',
    method: 'POST',
    requestId:
      'req-platform-integration-contract-latest-check-count-overflow-create-v1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: 'v1',
      schema_ref: 's3://contracts/latest-check-count-overflow/v1/openapi.json',
      schema_checksum: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      status: 'candidate',
      is_backward_compatible: true
    },
    handlers: harness.handlers
  });
  assert.equal(createV1Route.status, 200);

  const activateV1Route = await dispatchApiRoute({
    pathname:
      '/platform/integrations/integration-contract-latest-check-count-overflow/contracts/v1/activate',
    method: 'POST',
    requestId:
      'req-platform-integration-contract-latest-check-count-overflow-activate-v1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi'
    },
    handlers: harness.handlers
  });
  assert.equal(activateV1Route.status, 200);

  const createV2Route = await dispatchApiRoute({
    pathname:
      '/platform/integrations/integration-contract-latest-check-count-overflow/contracts',
    method: 'POST',
    requestId:
      'req-platform-integration-contract-latest-check-count-overflow-create-v2',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: 'v2',
      schema_ref: 's3://contracts/latest-check-count-overflow/v2/openapi.json',
      schema_checksum: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      status: 'candidate',
      is_backward_compatible: true
    },
    handlers: harness.handlers
  });
  assert.equal(createV2Route.status, 200);

  const authStore = harness.authService._internals.authStore;
  const originalFindLatestCheck =
    authStore.findLatestPlatformIntegrationContractCompatibilityCheck;
  authStore.findLatestPlatformIntegrationContractCompatibilityCheck = async () => ({
    integration_id: 'integration-contract-latest-check-count-overflow',
    contract_type: 'openapi',
    baseline_version: 'v1',
    candidate_version: 'v2',
    evaluation_result: 'compatible',
    breaking_change_count: 4294967296,
    diff_summary: null,
    request_id: 'req-platform-integration-contract-latest-check-count-overflow-forged',
    checked_by_user_id: 'platform-integration-contract-operator',
    checked_at: new Date().toISOString()
  });
  try {
    const route = await dispatchApiRoute({
      pathname:
        '/platform/integrations/integration-contract-latest-check-count-overflow/contracts/v2/activate',
      method: 'POST',
      requestId:
        'req-platform-integration-contract-latest-check-count-overflow-activate-v2',
      headers: {
        authorization: `Bearer ${login.access_token}`
      },
      body: {
        contract_type: 'openapi',
        baseline_version: 'v1'
      },
      handlers: harness.handlers
    });
    assert.equal(route.status, 503);
    const payload = JSON.parse(route.body);
    assert.equal(payload.error_code, 'INT-503-DEPENDENCY-UNAVAILABLE');
    assert.equal(
      payload.degradation_reason,
      'integration-contract-compatibility-check-read-result-malformed'
    );
    assert.equal(
      payload.request_id,
      'req-platform-integration-contract-latest-check-count-overflow-activate-v2'
    );
  } finally {
    authStore.findLatestPlatformIntegrationContractCompatibilityCheck =
      originalFindLatestCheck;
  }
});

test('contract activation fails closed when latest compatibility check diff_summary inference mismatches breaking_change_count', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-contract-login-latest-check-summary-mismatch'
  });

  const integrationRoute = await createIntegration({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId: 'integration-contract-latest-check-summary-mismatch',
    requestId:
      'req-platform-integration-contract-create-integration-latest-check-summary-mismatch'
  });
  assert.equal(integrationRoute.status, 200);

  const createV1Route = await dispatchApiRoute({
    pathname:
      '/platform/integrations/integration-contract-latest-check-summary-mismatch/contracts',
    method: 'POST',
    requestId:
      'req-platform-integration-contract-latest-check-summary-mismatch-create-v1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: 'v1',
      schema_ref: 's3://contracts/latest-check-summary-mismatch/v1/openapi.json',
      schema_checksum: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      status: 'candidate',
      is_backward_compatible: true
    },
    handlers: harness.handlers
  });
  assert.equal(createV1Route.status, 200);

  const activateV1Route = await dispatchApiRoute({
    pathname:
      '/platform/integrations/integration-contract-latest-check-summary-mismatch/contracts/v1/activate',
    method: 'POST',
    requestId:
      'req-platform-integration-contract-latest-check-summary-mismatch-activate-v1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi'
    },
    handlers: harness.handlers
  });
  assert.equal(activateV1Route.status, 200);

  const createV2Route = await dispatchApiRoute({
    pathname:
      '/platform/integrations/integration-contract-latest-check-summary-mismatch/contracts',
    method: 'POST',
    requestId:
      'req-platform-integration-contract-latest-check-summary-mismatch-create-v2',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: 'v2',
      schema_ref: 's3://contracts/latest-check-summary-mismatch/v2/openapi.json',
      schema_checksum: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      status: 'candidate',
      is_backward_compatible: true
    },
    handlers: harness.handlers
  });
  assert.equal(createV2Route.status, 200);

  const authStore = harness.authService._internals.authStore;
  const originalFindLatestCheck =
    authStore.findLatestPlatformIntegrationContractCompatibilityCheck;
  authStore.findLatestPlatformIntegrationContractCompatibilityCheck = async () => ({
    integration_id: 'integration-contract-latest-check-summary-mismatch',
    contract_type: 'openapi',
    baseline_version: 'v1',
    candidate_version: 'v2',
    evaluation_result: 'compatible',
    breaking_change_count: 0,
    diff_summary: ['remove required field order_id'],
    request_id: 'req-platform-integration-contract-latest-check-summary-mismatch-forged',
    checked_by_user_id: 'platform-integration-contract-operator',
    checked_at: new Date().toISOString()
  });
  try {
    const route = await dispatchApiRoute({
      pathname:
        '/platform/integrations/integration-contract-latest-check-summary-mismatch/contracts/v2/activate',
      method: 'POST',
      requestId:
        'req-platform-integration-contract-latest-check-summary-mismatch-activate-v2',
      headers: {
        authorization: `Bearer ${login.access_token}`
      },
      body: {
        contract_type: 'openapi',
        baseline_version: 'v1'
      },
      handlers: harness.handlers
    });
    assert.equal(route.status, 503);
    const payload = JSON.parse(route.body);
    assert.equal(payload.error_code, 'INT-503-DEPENDENCY-UNAVAILABLE');
    assert.equal(
      payload.degradation_reason,
      'integration-contract-compatibility-check-read-result-malformed'
    );
    assert.equal(
      payload.request_id,
      'req-platform-integration-contract-latest-check-summary-mismatch-activate-v2'
    );
  } finally {
    authStore.findLatestPlatformIntegrationContractCompatibilityCheck =
      originalFindLatestCheck;
  }
});

test('contract activation fails closed when latest compatibility check diff_summary exceeds max length', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-contract-login-latest-check-summary-oversized'
  });

  const integrationRoute = await createIntegration({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId: 'integration-contract-latest-check-summary-oversized',
    requestId:
      'req-platform-integration-contract-create-integration-latest-check-summary-oversized'
  });
  assert.equal(integrationRoute.status, 200);

  const createV1Route = await dispatchApiRoute({
    pathname:
      '/platform/integrations/integration-contract-latest-check-summary-oversized/contracts',
    method: 'POST',
    requestId:
      'req-platform-integration-contract-latest-check-summary-oversized-create-v1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: 'v1',
      schema_ref: 's3://contracts/latest-check-summary-oversized/v1/openapi.json',
      schema_checksum: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      status: 'candidate',
      is_backward_compatible: true
    },
    handlers: harness.handlers
  });
  assert.equal(createV1Route.status, 200);

  const activateV1Route = await dispatchApiRoute({
    pathname:
      '/platform/integrations/integration-contract-latest-check-summary-oversized/contracts/v1/activate',
    method: 'POST',
    requestId:
      'req-platform-integration-contract-latest-check-summary-oversized-activate-v1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi'
    },
    handlers: harness.handlers
  });
  assert.equal(activateV1Route.status, 200);

  const createV2Route = await dispatchApiRoute({
    pathname:
      '/platform/integrations/integration-contract-latest-check-summary-oversized/contracts',
    method: 'POST',
    requestId:
      'req-platform-integration-contract-latest-check-summary-oversized-create-v2',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: 'v2',
      schema_ref: 's3://contracts/latest-check-summary-oversized/v2/openapi.json',
      schema_checksum: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      status: 'candidate',
      is_backward_compatible: true
    },
    handlers: harness.handlers
  });
  assert.equal(createV2Route.status, 200);

  const authStore = harness.authService._internals.authStore;
  const originalFindLatestCheck =
    authStore.findLatestPlatformIntegrationContractCompatibilityCheck;
  authStore.findLatestPlatformIntegrationContractCompatibilityCheck = async () => ({
    integration_id: 'integration-contract-latest-check-summary-oversized',
    contract_type: 'openapi',
    baseline_version: 'v1',
    candidate_version: 'v2',
    evaluation_result: 'compatible',
    breaking_change_count: 0,
    diff_summary: {
      breaking_changes: [],
      notes: 'x'.repeat(70000)
    },
    request_id: 'req-platform-integration-contract-latest-check-summary-oversized-forged',
    checked_by_user_id: 'platform-integration-contract-operator',
    checked_at: new Date().toISOString()
  });
  try {
    const route = await dispatchApiRoute({
      pathname:
        '/platform/integrations/integration-contract-latest-check-summary-oversized/contracts/v2/activate',
      method: 'POST',
      requestId:
        'req-platform-integration-contract-latest-check-summary-oversized-activate-v2',
      headers: {
        authorization: `Bearer ${login.access_token}`
      },
      body: {
        contract_type: 'openapi',
        baseline_version: 'v1'
      },
      handlers: harness.handlers
    });
    assert.equal(route.status, 503);
    const payload = JSON.parse(route.body);
    assert.equal(payload.error_code, 'INT-503-DEPENDENCY-UNAVAILABLE');
    assert.equal(
      payload.degradation_reason,
      'integration-contract-compatibility-check-read-result-malformed'
    );
    assert.equal(
      payload.request_id,
      'req-platform-integration-contract-latest-check-summary-oversized-activate-v2'
    );
  } finally {
    authStore.findLatestPlatformIntegrationContractCompatibilityCheck =
      originalFindLatestCheck;
  }
});

test('contract compatibility returns integration_contract_not_found when integration is missing', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-contract-login-integration-missing'
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/integrations/integration-contract-does-not-exist/contracts/compatibility-check',
    method: 'POST',
    requestId: 'req-platform-integration-contract-integration-missing-compatibility',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      contract_type: 'openapi',
      baseline_version: 'v1',
      candidate_version: 'v2'
    },
    handlers: harness.handlers
  });
  assert.equal(route.status, 404);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'integration_contract_not_found');
  assert.equal(payload.integration_id, 'integration-contract-does-not-exist');
  assert.equal(
    payload.request_id,
    'req-platform-integration-contract-integration-missing-compatibility'
  );
});

test('contract consistency check blocks release when latest compatibility check is missing', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-contract-login-consistency-missing-check'
  });
  const integrationId = 'integration-contract-consistency-missing-check';

  const integrationRoute = await createIntegration({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId,
    requestId:
      'req-platform-integration-contract-create-integration-consistency-missing-check'
  });
  assert.equal(integrationRoute.status, 200);

  const createV1Route = await createContractVersion({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId,
    contractVersion: 'v1',
    requestId: 'req-platform-integration-contract-consistency-missing-check-create-v1',
    schemaChecksum: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
  });
  assert.equal(createV1Route.status, 200);

  const activateV1Route = await activateContractVersion({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId,
    contractVersion: 'v1',
    requestId: 'req-platform-integration-contract-consistency-missing-check-activate-v1'
  });
  assert.equal(activateV1Route.status, 200);

  const createV2Route = await createContractVersion({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId,
    contractVersion: 'v2',
    requestId: 'req-platform-integration-contract-consistency-missing-check-create-v2',
    schemaChecksum: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
  });
  assert.equal(createV2Route.status, 200);

  const consistencyRoute = await checkContractConsistency({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId,
    requestId: 'req-platform-integration-contract-consistency-missing-check-run',
    baselineVersion: 'v1',
    candidateVersion: 'v2'
  });
  assert.equal(consistencyRoute.status, 409);
  const payload = JSON.parse(consistencyRoute.body);
  assert.equal(payload.error_code, 'integration_contract_consistency_blocked');
  assert.equal(payload.blocking, true);
  assert.equal(payload.check_result, 'blocked');
  assert.equal(payload.failure_reason, 'missing_latest_compatibility_check');
  assert.equal(payload.baseline_version, 'v1');
  assert.equal(payload.candidate_version, 'v2');
  assert.equal(
    payload.request_id,
    'req-platform-integration-contract-consistency-missing-check-run'
  );
});

test('contract consistency check blocks release and returns breaking summary when latest evaluation is incompatible', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-contract-login-consistency-incompatible'
  });
  const integrationId = 'integration-contract-consistency-incompatible';

  const integrationRoute = await createIntegration({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId,
    requestId:
      'req-platform-integration-contract-create-integration-consistency-incompatible'
  });
  assert.equal(integrationRoute.status, 200);

  const createV1Route = await createContractVersion({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId,
    contractVersion: 'v1',
    requestId: 'req-platform-integration-contract-consistency-incompatible-create-v1',
    schemaChecksum: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
  });
  assert.equal(createV1Route.status, 200);

  const activateV1Route = await activateContractVersion({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId,
    contractVersion: 'v1',
    requestId: 'req-platform-integration-contract-consistency-incompatible-activate-v1'
  });
  assert.equal(activateV1Route.status, 200);

  const createV2Route = await createContractVersion({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId,
    contractVersion: 'v2',
    requestId: 'req-platform-integration-contract-consistency-incompatible-create-v2',
    schemaChecksum: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
  });
  assert.equal(createV2Route.status, 200);

  const evaluateRoute = await evaluateContractCompatibility({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId,
    requestId: 'req-platform-integration-contract-consistency-incompatible-evaluate',
    baselineVersion: 'v1',
    candidateVersion: 'v2',
    breakingChangeCount: 2,
    diffSummary: {
      breaking_changes: [
        'remove field customer_id',
        'rename field total_amount'
      ]
    }
  });
  assert.equal(evaluateRoute.status, 200);

  const consistencyRoute = await checkContractConsistency({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId,
    requestId: 'req-platform-integration-contract-consistency-incompatible-run',
    baselineVersion: 'v1',
    candidateVersion: 'v2'
  });
  assert.equal(consistencyRoute.status, 409);
  const payload = JSON.parse(consistencyRoute.body);
  assert.equal(payload.error_code, 'integration_contract_consistency_blocked');
  assert.equal(payload.blocking, true);
  assert.equal(payload.check_result, 'blocked');
  assert.equal(payload.failure_reason, 'latest_compatibility_incompatible');
  assert.equal(payload.breaking_change_count, 2);
  assert.deepEqual(payload.diff_summary, {
    breaking_changes: [
      'remove field customer_id',
      'rename field total_amount'
    ]
  });
});

test('contract consistency check blocks release when requested baseline_version mismatches latest active version', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-contract-login-consistency-baseline-mismatch'
  });
  const integrationId = 'integration-contract-consistency-baseline-mismatch';

  const integrationRoute = await createIntegration({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId,
    requestId:
      'req-platform-integration-contract-create-integration-consistency-baseline-mismatch'
  });
  assert.equal(integrationRoute.status, 200);

  const createV1Route = await createContractVersion({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId,
    contractVersion: 'v1',
    requestId: 'req-platform-integration-contract-consistency-baseline-mismatch-create-v1',
    schemaChecksum: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
  });
  assert.equal(createV1Route.status, 200);

  const activateV1Route = await activateContractVersion({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId,
    contractVersion: 'v1',
    requestId:
      'req-platform-integration-contract-consistency-baseline-mismatch-activate-v1'
  });
  assert.equal(activateV1Route.status, 200);

  const createV2Route = await createContractVersion({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId,
    contractVersion: 'v2',
    requestId: 'req-platform-integration-contract-consistency-baseline-mismatch-create-v2',
    schemaChecksum: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
  });
  assert.equal(createV2Route.status, 200);

  const evaluateV1ToV2Route = await evaluateContractCompatibility({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId,
    requestId:
      'req-platform-integration-contract-consistency-baseline-mismatch-evaluate-v1-v2',
    baselineVersion: 'v1',
    candidateVersion: 'v2',
    diffSummary: {
      breaking_changes: []
    }
  });
  assert.equal(evaluateV1ToV2Route.status, 200);

  const activateV2Route = await activateContractVersion({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId,
    contractVersion: 'v2',
    requestId:
      'req-platform-integration-contract-consistency-baseline-mismatch-activate-v2',
    baselineVersion: 'v1'
  });
  assert.equal(activateV2Route.status, 200);

  const createV3Route = await createContractVersion({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId,
    contractVersion: 'v3',
    requestId: 'req-platform-integration-contract-consistency-baseline-mismatch-create-v3',
    schemaChecksum: 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc'
  });
  assert.equal(createV3Route.status, 200);

  const evaluateV1ToV3Route = await evaluateContractCompatibility({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId,
    requestId:
      'req-platform-integration-contract-consistency-baseline-mismatch-evaluate-v1-v3',
    baselineVersion: 'v1',
    candidateVersion: 'v3',
    diffSummary: {
      breaking_changes: []
    }
  });
  assert.equal(evaluateV1ToV3Route.status, 200);

  const consistencyRoute = await checkContractConsistency({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId,
    requestId: 'req-platform-integration-contract-consistency-baseline-mismatch-run',
    baselineVersion: 'v1',
    candidateVersion: 'v3'
  });
  assert.equal(consistencyRoute.status, 409);
  const payload = JSON.parse(consistencyRoute.body);
  assert.equal(payload.error_code, 'integration_contract_consistency_blocked');
  assert.equal(payload.blocking, true);
  assert.equal(payload.check_result, 'blocked');
  assert.equal(payload.failure_reason, 'baseline_version_mismatch');
  assert.equal(payload.baseline_version, 'v1');
  assert.equal(payload.candidate_version, 'v3');
  assert.deepEqual(payload.diff_summary, {
    expected_active_baseline_version: 'v2',
    requested_baseline_version: 'v1'
  });
});

test('contract consistency check returns passed result and writes queryable audit event', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-contract-login-consistency-pass'
  });
  const integrationId = 'integration-contract-consistency-pass';

  const integrationRoute = await createIntegration({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId,
    requestId: 'req-platform-integration-contract-create-integration-consistency-pass'
  });
  assert.equal(integrationRoute.status, 200);

  const createV1Route = await createContractVersion({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId,
    contractVersion: 'v1',
    requestId: 'req-platform-integration-contract-consistency-pass-create-v1',
    schemaChecksum: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
  });
  assert.equal(createV1Route.status, 200);

  const activateV1Route = await activateContractVersion({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId,
    contractVersion: 'v1',
    requestId: 'req-platform-integration-contract-consistency-pass-activate-v1'
  });
  assert.equal(activateV1Route.status, 200);

  const createV2Route = await createContractVersion({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId,
    contractVersion: 'v2',
    requestId: 'req-platform-integration-contract-consistency-pass-create-v2',
    schemaChecksum: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
  });
  assert.equal(createV2Route.status, 200);

  const evaluateRoute = await evaluateContractCompatibility({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId,
    requestId: 'req-platform-integration-contract-consistency-pass-evaluate',
    baselineVersion: 'v1',
    candidateVersion: 'v2',
    diffSummary: {
      breaking_changes: []
    }
  });
  assert.equal(evaluateRoute.status, 200);

  const consistencyRoute = await checkContractConsistency({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId,
    requestId: 'req-platform-integration-contract-consistency-pass-run',
    baselineVersion: 'v1',
    candidateVersion: 'v2'
  });
  assert.equal(consistencyRoute.status, 200);
  const payload = JSON.parse(consistencyRoute.body);
  assert.equal(payload.check_result, 'passed');
  assert.equal(payload.blocking, false);
  assert.equal(payload.failure_reason, null);
  assert.equal(payload.breaking_change_count, 0);
  assert.deepEqual(payload.diff_summary, {
    breaking_changes: []
  });
  assert.equal(payload.request_id, 'req-platform-integration-contract-consistency-pass-run');

  const auditRoute = await dispatchApiRoute({
    pathname: '/platform/audit/events?request_id=req-platform-integration-contract-consistency-pass-run&event_type=platform.integration.contract.consistency_checked',
    method: 'GET',
    requestId: 'req-platform-integration-contract-consistency-pass-audit-query',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers: harness.handlers
  });
  assert.equal(auditRoute.status, 200);
  const auditPayload = JSON.parse(auditRoute.body);
  assert.equal(auditPayload.total, 1);
  assert.equal(
    auditPayload.events[0].event_type,
    'platform.integration.contract.consistency_checked'
  );
});

test('contract consistency check fails closed when latest compatibility check read result is malformed', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-contract-login-consistency-malformed-check'
  });
  const integrationId = 'integration-contract-consistency-malformed-check';

  const integrationRoute = await createIntegration({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId,
    requestId:
      'req-platform-integration-contract-create-integration-consistency-malformed-check'
  });
  assert.equal(integrationRoute.status, 200);

  const createV1Route = await createContractVersion({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId,
    contractVersion: 'v1',
    requestId: 'req-platform-integration-contract-consistency-malformed-check-create-v1',
    schemaChecksum: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
  });
  assert.equal(createV1Route.status, 200);

  const activateV1Route = await activateContractVersion({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId,
    contractVersion: 'v1',
    requestId: 'req-platform-integration-contract-consistency-malformed-check-activate-v1'
  });
  assert.equal(activateV1Route.status, 200);

  const createV2Route = await createContractVersion({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId,
    contractVersion: 'v2',
    requestId: 'req-platform-integration-contract-consistency-malformed-check-create-v2',
    schemaChecksum: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
  });
  assert.equal(createV2Route.status, 200);

  const authStore = harness.authService._internals.authStore;
  const originalFindLatestCheck =
    authStore.findLatestPlatformIntegrationContractCompatibilityCheck;
  authStore.findLatestPlatformIntegrationContractCompatibilityCheck = async () => ({
    integration_id: integrationId,
    contract_type: 'openapi',
    baseline_version: 'v1',
    candidate_version: 'v2',
    evaluation_result: 'compatible',
    breaking_change_count: 0,
    diff_summary: {
      breaking_changes: []
    },
    request_id: 'req-platform-integration-contract-consistency-malformed-check-forged'
  });
  try {
    const consistencyRoute = await checkContractConsistency({
      handlers: harness.handlers,
      accessToken: login.access_token,
      integrationId,
      requestId: 'req-platform-integration-contract-consistency-malformed-check-run',
      baselineVersion: 'v1',
      candidateVersion: 'v2'
    });
    assert.equal(consistencyRoute.status, 503);
    const payload = JSON.parse(consistencyRoute.body);
    assert.equal(payload.error_code, 'INT-503-DEPENDENCY-UNAVAILABLE');
    assert.equal(
      payload.degradation_reason,
      'integration-contract-consistency-check-read-result-malformed'
    );
    assert.equal(
      payload.request_id,
      'req-platform-integration-contract-consistency-malformed-check-run'
    );
  } finally {
    authStore.findLatestPlatformIntegrationContractCompatibilityCheck =
      originalFindLatestCheck;
  }
});

test('contract consistency check fails closed when latest active baseline read result is malformed', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-contract-login-consistency-malformed-active'
  });
  const integrationId = 'integration-contract-consistency-malformed-active';

  const integrationRoute = await createIntegration({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId,
    requestId:
      'req-platform-integration-contract-create-integration-consistency-malformed-active'
  });
  assert.equal(integrationRoute.status, 200);

  const createV1Route = await createContractVersion({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId,
    contractVersion: 'v1',
    requestId: 'req-platform-integration-contract-consistency-malformed-active-create-v1',
    schemaChecksum: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
  });
  assert.equal(createV1Route.status, 200);

  const activateV1Route = await activateContractVersion({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId,
    contractVersion: 'v1',
    requestId:
      'req-platform-integration-contract-consistency-malformed-active-activate-v1'
  });
  assert.equal(activateV1Route.status, 200);

  const createV2Route = await createContractVersion({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId,
    contractVersion: 'v2',
    requestId: 'req-platform-integration-contract-consistency-malformed-active-create-v2',
    schemaChecksum: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
  });
  assert.equal(createV2Route.status, 200);

  const evaluateRoute = await evaluateContractCompatibility({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId,
    requestId: 'req-platform-integration-contract-consistency-malformed-active-evaluate',
    baselineVersion: 'v1',
    candidateVersion: 'v2',
    diffSummary: {
      breaking_changes: []
    }
  });
  assert.equal(evaluateRoute.status, 200);

  const authStore = harness.authService._internals.authStore;
  const originalFindLatestActive =
    authStore.findLatestActivePlatformIntegrationContractVersion;
  authStore.findLatestActivePlatformIntegrationContractVersion = async () => ({
    integration_id: integrationId,
    contract_type: 'openapi',
    contract_version: 'v1',
    schema_ref: `s3://contracts/${integrationId}/v1/openapi.json`,
    schema_checksum: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    status: 'candidate',
    is_backward_compatible: true,
    created_by_user_id: 'platform-integration-contract-operator',
    updated_by_user_id: 'platform-integration-contract-operator',
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString()
  });
  try {
    const consistencyRoute = await checkContractConsistency({
      handlers: harness.handlers,
      accessToken: login.access_token,
      integrationId,
      requestId: 'req-platform-integration-contract-consistency-malformed-active-run',
      baselineVersion: 'v1',
      candidateVersion: 'v2'
    });
    assert.equal(consistencyRoute.status, 503);
    const payload = JSON.parse(consistencyRoute.body);
    assert.equal(payload.error_code, 'INT-503-DEPENDENCY-UNAVAILABLE');
    assert.equal(
      payload.degradation_reason,
      'integration-contract-active-read-result-malformed'
    );
  } finally {
    authStore.findLatestActivePlatformIntegrationContractVersion =
      originalFindLatestActive;
  }
});

test('contract consistency check keeps idempotency replay semantics stable', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-contract-login-consistency-idem'
  });
  const integrationId = 'integration-contract-consistency-idem';

  const integrationRoute = await createIntegration({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId,
    requestId: 'req-platform-integration-contract-create-integration-consistency-idem'
  });
  assert.equal(integrationRoute.status, 200);

  const createV1Route = await createContractVersion({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId,
    contractVersion: 'v1',
    requestId: 'req-platform-integration-contract-consistency-idem-create-v1',
    schemaChecksum: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
  });
  assert.equal(createV1Route.status, 200);

  const activateV1Route = await activateContractVersion({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId,
    contractVersion: 'v1',
    requestId: 'req-platform-integration-contract-consistency-idem-activate-v1'
  });
  assert.equal(activateV1Route.status, 200);

  const createV2Route = await createContractVersion({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId,
    contractVersion: 'v2',
    requestId: 'req-platform-integration-contract-consistency-idem-create-v2',
    schemaChecksum: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
  });
  assert.equal(createV2Route.status, 200);

  const evaluateRoute = await evaluateContractCompatibility({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId,
    requestId: 'req-platform-integration-contract-consistency-idem-evaluate',
    baselineVersion: 'v1',
    candidateVersion: 'v2',
    diffSummary: {
      breaking_changes: []
    }
  });
  assert.equal(evaluateRoute.status, 200);

  const first = await checkContractConsistency({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId,
    requestId: 'req-platform-integration-contract-consistency-idem-1',
    baselineVersion: 'v1',
    candidateVersion: 'v2',
    idempotencyKey: 'idem-platform-integration-contract-consistency-001'
  });
  const second = await checkContractConsistency({
    handlers: harness.handlers,
    accessToken: login.access_token,
    integrationId,
    requestId: 'req-platform-integration-contract-consistency-idem-2',
    baselineVersion: 'v1',
    candidateVersion: 'v2',
    idempotencyKey: 'idem-platform-integration-contract-consistency-001'
  });
  assert.equal(first.status, 200);
  assert.equal(second.status, 200);
  const firstPayload = JSON.parse(first.body);
  const secondPayload = JSON.parse(second.body);
  assert.equal(firstPayload.check_result, 'passed');
  assert.equal(secondPayload.check_result, 'passed');
  assert.equal(secondPayload.blocking, false);
  assert.equal(
    secondPayload.request_id,
    'req-platform-integration-contract-consistency-idem-2'
  );

  const replayAuditRoute = await dispatchApiRoute({
    pathname: '/platform/audit/events?request_id=req-platform-integration-contract-consistency-idem-2&event_type=platform.integration.contract.consistency_checked',
    method: 'GET',
    requestId: 'req-platform-integration-contract-consistency-idem-audit-replay-query',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers: harness.handlers
  });
  assert.equal(replayAuditRoute.status, 200);
  const replayAuditPayload = JSON.parse(replayAuditRoute.body);
  assert.equal(replayAuditPayload.total, 0);
});

test('contract governance write routes require platform.member_admin.operate permission', async () => {
  const harness = createHarness();
  const operatorLogin = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-platform-integration-contract-login-viewer-prep'
  });
  const viewerLogin = await loginByPhone({
    authService: harness.authService,
    phone: VIEWER_PHONE,
    requestId: 'req-platform-integration-contract-login-viewer'
  });

  const integrationRoute = await createIntegration({
    handlers: harness.handlers,
    accessToken: operatorLogin.access_token,
    integrationId: 'integration-contract-viewer-forbidden',
    requestId: 'req-platform-integration-contract-create-integration-viewer-forbidden'
  });
  assert.equal(integrationRoute.status, 200);

  const route = await dispatchApiRoute({
    pathname: '/platform/integrations/integration-contract-viewer-forbidden/contracts',
    method: 'POST',
    requestId: 'req-platform-integration-contract-viewer-create-forbidden',
    headers: {
      authorization: `Bearer ${viewerLogin.access_token}`
    },
    body: {
      contract_type: 'openapi',
      contract_version: 'v-viewer',
      schema_ref: 's3://contracts/viewer/v/openapi.json',
      schema_checksum: 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
      status: 'candidate',
      is_backward_compatible: true
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 403);
  assert.equal(route.headers['content-type'], 'application/problem+json');
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-403-FORBIDDEN');
  assert.equal(payload.request_id, 'req-platform-integration-contract-viewer-create-forbidden');
});
