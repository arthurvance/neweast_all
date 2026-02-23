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

const OPERATOR_PHONE = '13830000001';
const TARGET_PHONE = '13830000002';

const createHarness = () => {
  const authService = createAuthService({
    seedUsers: [
      {
        id: 'platform-role-operator',
        phone: OPERATOR_PHONE,
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: [
          {
            roleId: 'platform-role-operator-admin',
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
        id: 'platform-role-target-user',
        phone: TARGET_PHONE,
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: []
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

const loginOperator = async (authService, requestId) =>
  authService.login({
    requestId,
    phone: OPERATOR_PHONE,
    password: 'Passw0rd!',
    entryDomain: 'platform'
  });

const loginByPhone = async (authService, requestId, phone) =>
  authService.login({
    requestId,
    phone,
    password: 'Passw0rd!',
    entryDomain: 'platform'
  });

test('POST /platform/roles creates role and GET /platform/roles returns traceable fields', async () => {
  const harness = createHarness();
  const login = await loginOperator(harness.authService, 'req-platform-role-login-1');

  const createRoute = await dispatchApiRoute({
    pathname: '/platform/roles',
    method: 'POST',
    requestId: 'req-platform-role-create-1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      role_id: 'platform_ops_admin',
      code: 'OPS_ADMIN',
      name: '平台运维管理员',
      status: 'active'
    },
    handlers: harness.handlers
  });

  assert.equal(createRoute.status, 200);
  const createPayload = JSON.parse(createRoute.body);
  assert.equal(createPayload.role_id, 'platform_ops_admin');
  assert.equal(createPayload.code, 'OPS_ADMIN');
  assert.equal(createPayload.name, '平台运维管理员');
  assert.equal(createPayload.status, 'active');
  assert.equal(createPayload.is_system, false);
  assert.equal(createPayload.request_id, 'req-platform-role-create-1');
  assert.ok(typeof createPayload.created_at === 'string' && createPayload.created_at.length > 0);
  assert.ok(typeof createPayload.updated_at === 'string' && createPayload.updated_at.length > 0);

  const listRoute = await dispatchApiRoute({
    pathname: '/platform/roles',
    method: 'GET',
    requestId: 'req-platform-role-list-1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers: harness.handlers
  });

  assert.equal(listRoute.status, 200);
  const listPayload = JSON.parse(listRoute.body);
  assert.equal(listPayload.request_id, 'req-platform-role-list-1');
  assert.ok(Array.isArray(listPayload.roles));
  assert.ok(listPayload.roles.length >= 1);
  const role = listPayload.roles.find((item) => item.role_id === 'platform_ops_admin');
  assert.ok(role);
  assert.equal(role.code, 'OPS_ADMIN');
  assert.equal(role.name, '平台运维管理员');
  assert.equal(role.status, 'active');
  assert.equal(role.request_id, 'req-platform-role-list-1');
  assert.ok(typeof role.created_at === 'string' && role.created_at.length > 0);
});

test('POST /platform/roles auto-generates role_id when omitted from payload', async () => {
  const harness = createHarness();
  const login = await loginOperator(harness.authService, 'req-platform-role-login-auto-role-id');

  const createRoute = await dispatchApiRoute({
    pathname: '/platform/roles',
    method: 'POST',
    requestId: 'req-platform-role-create-auto-role-id',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      code: 'AUTO_ROLE_ID',
      name: '自动生成角色ID'
    },
    handlers: harness.handlers
  });

  assert.equal(createRoute.status, 200);
  const createPayload = JSON.parse(createRoute.body);
  assert.ok(typeof createPayload.role_id === 'string' && createPayload.role_id.length > 0);
  assert.equal(createPayload.code, 'AUTO_ROLE_ID');
  assert.equal(createPayload.name, '自动生成角色ID');
  assert.equal(createPayload.status, 'active');
  assert.equal(createPayload.is_system, false);
});

test('POST /platform/roles persists audit event with request_id and traceparent', async () => {
  const harness = createHarness();
  const login = await loginOperator(harness.authService, 'req-platform-role-login-audit');
  const traceparent = '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01';

  const createRoute = await dispatchApiRoute({
    pathname: '/platform/roles',
    method: 'POST',
    requestId: 'req-platform-role-create-audit',
    headers: {
      authorization: `Bearer ${login.access_token}`,
      traceparent
    },
    body: {
      role_id: 'platform_role_audit_trace',
      code: 'ROLE_AUDIT_TRACE',
      name: '审计透传验证角色',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRoute.status, 200);

  const auditRoute = await dispatchApiRoute({
    pathname: '/platform/audit/events?request_id=req-platform-role-create-audit&event_type=auth.role.catalog.created',
    method: 'GET',
    requestId: 'req-platform-role-audit-query',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers: harness.handlers
  });
  assert.equal(auditRoute.status, 200);
  const auditPayload = JSON.parse(auditRoute.body);
  assert.equal(auditPayload.total, 1);
  assert.equal(auditPayload.events[0].event_type, 'auth.role.catalog.created');
  assert.equal(auditPayload.events[0].request_id, 'req-platform-role-create-audit');
  assert.equal(auditPayload.events[0].traceparent, traceparent);
  assert.equal(auditPayload.events[0].target_type, 'role');
});

test('POST /auth/platform/role-facts/replace persists audit event with request_id and traceparent', async () => {
  const harness = createHarness();
  const login = await loginOperator(harness.authService, 'req-platform-role-login-role-facts-audit');
  const traceparent = '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01';

  const createRoleRoute = await dispatchApiRoute({
    pathname: '/platform/roles',
    method: 'POST',
    requestId: 'req-platform-role-facts-audit-create-role',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      role_id: 'platform_role_facts_audit_trace',
      code: 'PLATFORM_ROLE_FACTS_AUDIT_TRACE',
      name: '平台角色事实审计透传验证角色',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRoleRoute.status, 200);

  const replaceFactsRoute = await dispatchApiRoute({
    pathname: '/auth/platform/role-facts/replace',
    method: 'POST',
    requestId: 'req-platform-role-facts-audit',
    headers: {
      authorization: `Bearer ${login.access_token}`,
      traceparent
    },
    body: {
      user_id: 'platform-role-target-user',
      roles: [{ role_id: 'platform_role_facts_audit_trace' }]
    },
    handlers: harness.handlers
  });
  assert.equal(replaceFactsRoute.status, 200);

  const auditRoute = await dispatchApiRoute({
    pathname: '/platform/audit/events?request_id=req-platform-role-facts-audit&event_type=auth.platform_role_facts.updated',
    method: 'GET',
    requestId: 'req-platform-role-facts-audit-query',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers: harness.handlers
  });
  assert.equal(auditRoute.status, 200);
  const auditPayload = JSON.parse(auditRoute.body);
  assert.equal(auditPayload.total, 1);
  assert.equal(auditPayload.events[0].event_type, 'auth.platform_role_facts.updated');
  assert.equal(auditPayload.events[0].request_id, 'req-platform-role-facts-audit');
  assert.equal(auditPayload.events[0].traceparent, traceparent);
  assert.equal(auditPayload.events[0].target_type, 'user');
  assert.equal(auditPayload.events[0].target_id, 'platform-role-target-user');
});

test('POST /platform/roles rejects case-insensitive duplicate code with stable 409 semantics', async () => {
  const harness = createHarness();
  const login = await loginOperator(harness.authService, 'req-platform-role-login-2');

  const first = await dispatchApiRoute({
    pathname: '/platform/roles',
    method: 'POST',
    requestId: 'req-platform-role-create-2-1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      role_id: 'platform_finance_admin',
      code: 'FINANCE_ADMIN',
      name: '财务管理员',
      status: 'active'
    },
    handlers: harness.handlers
  });
  const second = await dispatchApiRoute({
    pathname: '/platform/roles',
    method: 'POST',
    requestId: 'req-platform-role-create-2-2',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      role_id: 'platform_finance_admin_2',
      code: 'finance_admin',
      name: '财务管理员-2',
      status: 'active'
    },
    handlers: harness.handlers
  });

  assert.equal(first.status, 200);
  assert.equal(second.status, 409);
  assert.equal(second.headers['content-type'], 'application/problem+json');
  const payload = JSON.parse(second.body);
  assert.equal(payload.error_code, 'ROLE-409-CODE-CONFLICT');
  assert.equal(payload.request_id, 'req-platform-role-create-2-2');
  assert.equal(payload.retryable, false);
});

test('POST /platform/roles rejects case-insensitive duplicate role_id to keep memory/mysql semantics aligned', async () => {
  const harness = createHarness();
  const login = await loginOperator(harness.authService, 'req-platform-role-login-2-role-id');

  const first = await dispatchApiRoute({
    pathname: '/platform/roles',
    method: 'POST',
    requestId: 'req-platform-role-create-role-id-1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      role_id: 'RoleCase',
      code: 'ROLE_CASE_A',
      name: '角色大小写A',
      status: 'active'
    },
    handlers: harness.handlers
  });
  const second = await dispatchApiRoute({
    pathname: '/platform/roles',
    method: 'POST',
    requestId: 'req-platform-role-create-role-id-2',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      role_id: 'rolecase',
      code: 'ROLE_CASE_B',
      name: '角色大小写B',
      status: 'active'
    },
    handlers: harness.handlers
  });

  assert.equal(first.status, 200);
  assert.equal(second.status, 409);
  assert.equal(second.headers['content-type'], 'application/problem+json');
  const payload = JSON.parse(second.body);
  assert.equal(payload.error_code, 'ROLE-409-ROLE-ID-CONFLICT');
});

test('POST /platform/roles rejects non-addressable role_id characters', async () => {
  const harness = createHarness();
  const login = await loginOperator(harness.authService, 'req-platform-role-login-invalid-role-id');
  const headers = {
    authorization: `Bearer ${login.access_token}`
  };

  const roleWithSpace = await dispatchApiRoute({
    pathname: '/platform/roles',
    method: 'POST',
    requestId: 'req-platform-role-create-invalid-space',
    headers,
    body: {
      role_id: 'role with space',
      code: 'ROLE_INVALID_SPACE',
      name: '非法角色-空格',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(roleWithSpace.status, 400);
  const roleWithSpacePayload = JSON.parse(roleWithSpace.body);
  assert.equal(roleWithSpacePayload.error_code, 'ROLE-400-INVALID-PAYLOAD');

  const roleWithSlash = await dispatchApiRoute({
    pathname: '/platform/roles',
    method: 'POST',
    requestId: 'req-platform-role-create-invalid-slash',
    headers,
    body: {
      role_id: 'role/with/slash',
      code: 'ROLE_INVALID_SLASH',
      name: '非法角色-斜杠',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(roleWithSlash.status, 400);
  const roleWithSlashPayload = JSON.parse(roleWithSlash.body);
  assert.equal(roleWithSlashPayload.error_code, 'ROLE-400-INVALID-PAYLOAD');
});

test('POST/PATCH /platform/roles reject undocumented status alias enabled', async () => {
  const harness = createHarness();
  const login = await loginOperator(harness.authService, 'req-platform-role-login-enabled-status');
  const headers = {
    authorization: `Bearer ${login.access_token}`
  };

  const createWithEnabledStatus = await dispatchApiRoute({
    pathname: '/platform/roles',
    method: 'POST',
    requestId: 'req-platform-role-create-enabled-status',
    headers,
    body: {
      role_id: 'enabled_status_input',
      code: 'ENABLED_STATUS_INPUT',
      name: '状态别名校验',
      status: 'enabled'
    },
    handlers: harness.handlers
  });
  assert.equal(createWithEnabledStatus.status, 400);
  assert.equal(
    JSON.parse(createWithEnabledStatus.body).error_code,
    'ROLE-400-INVALID-PAYLOAD'
  );

  const createBaselineRole = await dispatchApiRoute({
    pathname: '/platform/roles',
    method: 'POST',
    requestId: 'req-platform-role-create-baseline-for-enabled-status',
    headers,
    body: {
      role_id: 'baseline_for_enabled_status',
      code: 'BASELINE_FOR_ENABLED_STATUS',
      name: '状态更新基线角色',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createBaselineRole.status, 200);

  const patchWithEnabledStatus = await dispatchApiRoute({
    pathname: '/platform/roles/baseline_for_enabled_status',
    method: 'PATCH',
    requestId: 'req-platform-role-patch-enabled-status',
    headers,
    body: {
      status: 'enabled'
    },
    handlers: harness.handlers
  });
  assert.equal(patchWithEnabledStatus.status, 400);
  assert.equal(
    JSON.parse(patchWithEnabledStatus.body).error_code,
    'ROLE-400-INVALID-PAYLOAD'
  );
});

test('GET /platform/roles rejects non-canonical paths with trailing or duplicate slashes', async () => {
  const harness = createHarness();
  const login = await loginOperator(harness.authService, 'req-platform-role-login-path-canonical');
  const headers = {
    authorization: `Bearer ${login.access_token}`
  };

  const trailingSlash = await dispatchApiRoute({
    pathname: '/platform/roles/',
    method: 'GET',
    requestId: 'req-platform-role-list-trailing-slash',
    headers,
    handlers: harness.handlers
  });
  assert.equal(trailingSlash.status, 404);
  assert.equal(
    JSON.parse(trailingSlash.body).error_code,
    'AUTH-404-NOT-FOUND'
  );

  const duplicateSlash = await dispatchApiRoute({
    pathname: '/platform/roles//',
    method: 'GET',
    requestId: 'req-platform-role-list-duplicate-slash',
    headers,
    handlers: harness.handlers
  });
  assert.equal(duplicateSlash.status, 404);
  assert.equal(
    JSON.parse(duplicateSlash.body).error_code,
    'AUTH-404-NOT-FOUND'
  );
});

test('PATCH/DELETE /platform/roles/:role_id decode URL-encoded path params before service lookup', async () => {
  const harness = createHarness();
  const login = await loginOperator(harness.authService, 'req-platform-role-login-encoded-param');
  const authHeaders = {
    authorization: `Bearer ${login.access_token}`
  };
  const createRole = await dispatchApiRoute({
    pathname: '/platform/roles',
    method: 'POST',
    requestId: 'req-platform-role-create-encoded-param',
    headers: authHeaders,
    body: {
      role_id: 'platform.route_encoded',
      code: 'ROLE_ENCODED_PARAM',
      name: '编码路径参数角色',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRole.status, 200);

  const encodedRolePath = '/platform/roles/platform%2Eroute_encoded';
  const patchRoute = await dispatchApiRoute({
    pathname: encodedRolePath,
    method: 'PATCH',
    requestId: 'req-platform-role-patch-encoded-param',
    headers: authHeaders,
    body: {
      name: '编码路径参数角色-已更新'
    },
    handlers: harness.handlers
  });
  assert.equal(patchRoute.status, 200);
  const patchPayload = JSON.parse(patchRoute.body);
  assert.equal(patchPayload.role_id, 'platform.route_encoded');
  assert.equal(patchPayload.name, '编码路径参数角色-已更新');

  const deleteRoute = await dispatchApiRoute({
    pathname: encodedRolePath,
    method: 'DELETE',
    requestId: 'req-platform-role-delete-encoded-param',
    headers: authHeaders,
    handlers: harness.handlers
  });
  assert.equal(deleteRoute.status, 200);
  const deletePayload = JSON.parse(deleteRoute.body);
  assert.equal(deletePayload.role_id, 'platform.route_encoded');
});

test('PATCH/DELETE /platform/roles/:role_id reject protected sys_admin role mutation', async () => {
  const harness = createHarness();
  const login = await loginOperator(harness.authService, 'req-platform-role-login-3');

  const patchRoute = await dispatchApiRoute({
    pathname: '/platform/roles/sys_admin',
    method: 'PATCH',
    requestId: 'req-platform-role-protected-patch',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      name: '系统管理员(非法修改)'
    },
    handlers: harness.handlers
  });

  assert.equal(patchRoute.status, 403);
  const patchPayload = JSON.parse(patchRoute.body);
  assert.equal(patchPayload.error_code, 'ROLE-403-SYSTEM-ROLE-PROTECTED');
  assert.equal(patchPayload.request_id, 'req-platform-role-protected-patch');

  const deleteRoute = await dispatchApiRoute({
    pathname: '/platform/roles/sys_admin',
    method: 'DELETE',
    requestId: 'req-platform-role-protected-delete',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers: harness.handlers
  });

  assert.equal(deleteRoute.status, 403);
  const deletePayload = JSON.parse(deleteRoute.body);
  assert.equal(deletePayload.error_code, 'ROLE-403-SYSTEM-ROLE-PROTECTED');
  assert.equal(deletePayload.request_id, 'req-platform-role-protected-delete');
});

test('GET /platform/roles fails closed when role catalog returns malformed records', async () => {
  const harness = createHarness();
  const login = await loginOperator(harness.authService, 'req-platform-role-login-list-malformed');
  const originalListPlatformRoleCatalogEntries = harness.authService.listPlatformRoleCatalogEntries;
  harness.authService.listPlatformRoleCatalogEntries = async () => ([
    {
      role_id: 'platform_role_malformed_list_target',
      code: 'ROLE_MALFORMED_LIST_TARGET',
      name: '平台角色目录脏记录',
      status: 'active',
      scope: 'platform',
      is_system: false,
      updated_at: new Date().toISOString()
    }
  ]);
  try {
    const listRoute = await dispatchApiRoute({
      pathname: '/platform/roles',
      method: 'GET',
      requestId: 'req-platform-role-list-malformed',
      headers: {
        authorization: `Bearer ${login.access_token}`
      },
      handlers: harness.handlers
    });
    assert.equal(listRoute.status, 503);
    const payload = JSON.parse(listRoute.body);
    assert.equal(payload.error_code, 'ROLE-503-DEPENDENCY-UNAVAILABLE');
    assert.equal(payload.request_id, 'req-platform-role-list-malformed');
  } finally {
    harness.authService.listPlatformRoleCatalogEntries = originalListPlatformRoleCatalogEntries;
  }
});

test('GET /platform/roles fails closed when role catalog payload is not an array', async () => {
  const harness = createHarness();
  const login = await loginOperator(harness.authService, 'req-platform-role-login-list-non-array');
  const originalListPlatformRoleCatalogEntries = harness.authService.listPlatformRoleCatalogEntries;
  harness.authService.listPlatformRoleCatalogEntries = async () => ({
    role_id: 'platform_role_non_array_payload'
  });
  try {
    const listRoute = await dispatchApiRoute({
      pathname: '/platform/roles',
      method: 'GET',
      requestId: 'req-platform-role-list-non-array',
      headers: {
        authorization: `Bearer ${login.access_token}`
      },
      handlers: harness.handlers
    });
    assert.equal(listRoute.status, 503);
    const payload = JSON.parse(listRoute.body);
    assert.equal(payload.error_code, 'ROLE-503-DEPENDENCY-UNAVAILABLE');
    assert.equal(payload.request_id, 'req-platform-role-list-non-array');
  } finally {
    harness.authService.listPlatformRoleCatalogEntries = originalListPlatformRoleCatalogEntries;
  }
});

test('POST /platform/roles fails closed when create returns malformed catalog record', async () => {
  const harness = createHarness();
  const login = await loginOperator(harness.authService, 'req-platform-role-login-create-malformed');
  const originalCreatePlatformRoleCatalogEntry = harness.authService.createPlatformRoleCatalogEntry;
  harness.authService.createPlatformRoleCatalogEntry = async () => ({
    role_id: 'platform_role_create_malformed_target',
    code: 'ROLE_CREATE_MALFORMED_TARGET',
    name: '平台角色创建脏记录目标',
    status: 'active',
    scope: 'platform',
    is_system: false,
    updated_at: new Date().toISOString()
  });
  try {
    const createRoute = await dispatchApiRoute({
      pathname: '/platform/roles',
      method: 'POST',
      requestId: 'req-platform-role-create-malformed',
      headers: {
        authorization: `Bearer ${login.access_token}`
      },
      body: {
        role_id: 'platform_role_create_malformed_target',
        code: 'ROLE_CREATE_MALFORMED_TARGET',
        name: '平台角色创建脏记录目标',
        status: 'active'
      },
      handlers: harness.handlers
    });
    assert.equal(createRoute.status, 503);
    const payload = JSON.parse(createRoute.body);
    assert.equal(payload.error_code, 'ROLE-503-DEPENDENCY-UNAVAILABLE');
    assert.equal(payload.request_id, 'req-platform-role-create-malformed');
  } finally {
    harness.authService.createPlatformRoleCatalogEntry = originalCreatePlatformRoleCatalogEntry;
  }
});

test('PATCH /platform/roles/:role_id fails closed when update returns malformed catalog record', async () => {
  const harness = createHarness();
  const login = await loginOperator(harness.authService, 'req-platform-role-login-update-malformed');
  const authHeaders = {
    authorization: `Bearer ${login.access_token}`
  };

  const createRole = await dispatchApiRoute({
    pathname: '/platform/roles',
    method: 'POST',
    requestId: 'req-platform-role-create-update-malformed-target',
    headers: authHeaders,
    body: {
      role_id: 'platform_role_update_malformed_target',
      code: 'ROLE_UPDATE_MALFORMED_TARGET',
      name: '平台角色更新脏记录目标',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRole.status, 200);

  const originalUpdatePlatformRoleCatalogEntry = harness.authService.updatePlatformRoleCatalogEntry;
  harness.authService.updatePlatformRoleCatalogEntry = async () => ({
    role_id: 'platform_role_update_malformed_target',
    code: 'ROLE_UPDATE_MALFORMED_TARGET',
    name: '平台角色更新脏记录目标-已更新',
    status: 'active',
    scope: 'platform',
    is_system: false,
    updated_at: new Date().toISOString()
  });
  try {
    const updateRoute = await dispatchApiRoute({
      pathname: '/platform/roles/platform_role_update_malformed_target',
      method: 'PATCH',
      requestId: 'req-platform-role-update-malformed',
      headers: authHeaders,
      body: {
        name: '平台角色更新脏记录目标-已更新'
      },
      handlers: harness.handlers
    });
    assert.equal(updateRoute.status, 503);
    const payload = JSON.parse(updateRoute.body);
    assert.equal(payload.error_code, 'ROLE-503-DEPENDENCY-UNAVAILABLE');
    assert.equal(payload.request_id, 'req-platform-role-update-malformed');
  } finally {
    harness.authService.updatePlatformRoleCatalogEntry = originalUpdatePlatformRoleCatalogEntry;
  }
});

test('DELETE /platform/roles/:role_id fails closed when delete result is not soft-deleted', async () => {
  const harness = createHarness();
  const login = await loginOperator(harness.authService, 'req-platform-role-login-delete-malformed');
  const authHeaders = {
    authorization: `Bearer ${login.access_token}`
  };

  const createRole = await dispatchApiRoute({
    pathname: '/platform/roles',
    method: 'POST',
    requestId: 'req-platform-role-create-delete-malformed-target',
    headers: authHeaders,
    body: {
      role_id: 'platform_role_delete_malformed_target',
      code: 'ROLE_DELETE_MALFORMED_TARGET',
      name: '平台角色删除脏记录目标',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRole.status, 200);

  const originalDeletePlatformRoleCatalogEntry = harness.authService.deletePlatformRoleCatalogEntry;
  harness.authService.deletePlatformRoleCatalogEntry = async () => ({
    role_id: 'platform_role_delete_malformed_target',
    code: 'ROLE_DELETE_MALFORMED_TARGET',
    name: '平台角色删除脏记录目标',
    status: 'active',
    scope: 'platform',
    is_system: false,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString()
  });
  try {
    const deleteRoute = await dispatchApiRoute({
      pathname: '/platform/roles/platform_role_delete_malformed_target',
      method: 'DELETE',
      requestId: 'req-platform-role-delete-malformed',
      headers: authHeaders,
      handlers: harness.handlers
    });
    assert.equal(deleteRoute.status, 503);
    const payload = JSON.parse(deleteRoute.body);
    assert.equal(payload.error_code, 'ROLE-503-DEPENDENCY-UNAVAILABLE');
    assert.equal(payload.request_id, 'req-platform-role-delete-malformed');
  } finally {
    harness.authService.deletePlatformRoleCatalogEntry = originalDeletePlatformRoleCatalogEntry;
  }
});

test('DELETE /platform/roles/:role_id keeps idempotency scope isolated by route params', async () => {
  const harness = createHarness();
  const login = await loginOperator(harness.authService, 'req-platform-role-login-iso');
  const authHeaders = {
    authorization: `Bearer ${login.access_token}`
  };
  const createRoleA = await dispatchApiRoute({
    pathname: '/platform/roles',
    method: 'POST',
    requestId: 'req-platform-role-iso-create-a',
    headers: authHeaders,
    body: {
      role_id: 'platform_role_iso_a',
      code: 'ROLE_ISO_A',
      name: '幂等隔离A',
      status: 'active'
    },
    handlers: harness.handlers
  });
  const createRoleB = await dispatchApiRoute({
    pathname: '/platform/roles',
    method: 'POST',
    requestId: 'req-platform-role-iso-create-b',
    headers: authHeaders,
    body: {
      role_id: 'platform_role_iso_b',
      code: 'ROLE_ISO_B',
      name: '幂等隔离B',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRoleA.status, 200);
  assert.equal(createRoleB.status, 200);

  const deleteA = await dispatchApiRoute({
    pathname: '/platform/roles/platform_role_iso_a',
    method: 'DELETE',
    requestId: 'req-platform-role-iso-delete-a',
    headers: {
      ...authHeaders,
      'idempotency-key': 'idem-platform-role-delete-isolation'
    },
    handlers: harness.handlers
  });
  const deleteB = await dispatchApiRoute({
    pathname: '/platform/roles/platform_role_iso_b',
    method: 'DELETE',
    requestId: 'req-platform-role-iso-delete-b',
    headers: {
      ...authHeaders,
      'idempotency-key': 'idem-platform-role-delete-isolation'
    },
    handlers: harness.handlers
  });

  assert.equal(deleteA.status, 200);
  assert.equal(deleteB.status, 200);
  const deleteAPayload = JSON.parse(deleteA.body);
  const deleteBPayload = JSON.parse(deleteB.body);
  assert.equal(deleteAPayload.role_id, 'platform_role_iso_a');
  assert.equal(deleteBPayload.role_id, 'platform_role_iso_b');
  assert.equal(deleteBPayload.request_id, 'req-platform-role-iso-delete-b');
});

test('PATCH /platform/roles/:role_id rejects malformed paths with consecutive slashes', async () => {
  const harness = createHarness();
  const login = await loginOperator(harness.authService, 'req-platform-role-login-double-slash');
  const authHeaders = {
    authorization: `Bearer ${login.access_token}`
  };
  const createRole = await dispatchApiRoute({
    pathname: '/platform/roles',
    method: 'POST',
    requestId: 'req-platform-role-create-double-slash',
    headers: authHeaders,
    body: {
      role_id: 'double_slash_target',
      code: 'DOUBLE_SLASH_TARGET',
      name: '双斜杠目标角色',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRole.status, 200);

  const malformedPatch = await dispatchApiRoute({
    pathname: '/platform/roles//double_slash_target',
    method: 'PATCH',
    requestId: 'req-platform-role-patch-double-slash',
    headers: authHeaders,
    body: {
      name: '不应命中'
    },
    handlers: harness.handlers
  });

  assert.equal(malformedPatch.status, 404);
  const payload = JSON.parse(malformedPatch.body);
  assert.equal(payload.error_code, 'AUTH-404-NOT-FOUND');
});

test('PATCH /platform/roles/:role_id rejects malformed URL-encoded path segments', async () => {
  const harness = createHarness();
  const login = await loginOperator(harness.authService, 'req-platform-role-login-malformed-encoded');
  const malformedPatch = await dispatchApiRoute({
    pathname: '/platform/roles/%E0%A4%A',
    method: 'PATCH',
    requestId: 'req-platform-role-patch-malformed-encoded',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      name: '不应命中'
    },
    handlers: harness.handlers
  });

  assert.equal(malformedPatch.status, 404);
  const payload = JSON.parse(malformedPatch.body);
  assert.equal(payload.error_code, 'AUTH-404-NOT-FOUND');
});

test('PATCH /platform/roles/:role_id rejects URL-encoded leading/trailing whitespace path segments', async () => {
  const harness = createHarness();
  const login = await loginOperator(harness.authService, 'req-platform-role-login-whitespace-encoded');
  const authHeaders = {
    authorization: `Bearer ${login.access_token}`
  };
  const createRole = await dispatchApiRoute({
    pathname: '/platform/roles',
    method: 'POST',
    requestId: 'req-platform-role-create-whitespace-encoded',
    headers: authHeaders,
    body: {
      role_id: 'whitespace_path_target',
      code: 'WHITESPACE_PATH_TARGET',
      name: '空白路径参数目标角色',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRole.status, 200);

  const encodedLeadingWhitespacePatch = await dispatchApiRoute({
    pathname: '/platform/roles/%20whitespace_path_target',
    method: 'PATCH',
    requestId: 'req-platform-role-patch-whitespace-encoded-leading',
    headers: authHeaders,
    body: {
      name: '不应命中'
    },
    handlers: harness.handlers
  });
  assert.equal(encodedLeadingWhitespacePatch.status, 404);
  assert.equal(
    JSON.parse(encodedLeadingWhitespacePatch.body).error_code,
    'AUTH-404-NOT-FOUND'
  );

  const encodedTrailingWhitespacePatch = await dispatchApiRoute({
    pathname: '/platform/roles/whitespace_path_target%20',
    method: 'PATCH',
    requestId: 'req-platform-role-patch-whitespace-encoded-trailing',
    headers: authHeaders,
    body: {
      name: '不应命中'
    },
    handlers: harness.handlers
  });
  assert.equal(encodedTrailingWhitespacePatch.status, 404);
  assert.equal(
    JSON.parse(encodedTrailingWhitespacePatch.body).error_code,
    'AUTH-404-NOT-FOUND'
  );
});

test('PATCH /platform/roles/:role_id enforces idempotency across canonicalized role_id path variants', async () => {
  const harness = createHarness();
  const login = await loginOperator(harness.authService, 'req-platform-role-login-idem-canonicalized');
  const authHeaders = {
    authorization: `Bearer ${login.access_token}`
  };
  const createRole = await dispatchApiRoute({
    pathname: '/platform/roles',
    method: 'POST',
    requestId: 'req-platform-role-create-idem-canonicalized',
    headers: authHeaders,
    body: {
      role_id: 'idem_canonicalized',
      code: 'IDEM_CANONICALIZED',
      name: '幂等规范化角色',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRole.status, 200);

  const firstPatch = await dispatchApiRoute({
    pathname: '/platform/roles/Idem_Canonicalized',
    method: 'PATCH',
    requestId: 'req-platform-role-patch-idem-canonicalized-1',
    headers: {
      ...authHeaders,
      'idempotency-key': 'idem-platform-role-canonicalized-path'
    },
    body: {
      name: '版本A'
    },
    handlers: harness.handlers
  });
  assert.equal(firstPatch.status, 200);

  const secondPatch = await dispatchApiRoute({
    pathname: '/platform/roles/IDEM_CANONICALIZED',
    method: 'PATCH',
    requestId: 'req-platform-role-patch-idem-canonicalized-2',
    headers: {
      ...authHeaders,
      'idempotency-key': 'idem-platform-role-canonicalized-path'
    },
    body: {
      name: '版本B'
    },
    handlers: harness.handlers
  });

  assert.equal(secondPatch.status, 409);
  const secondPayload = JSON.parse(secondPatch.body);
  assert.equal(secondPayload.error_code, 'AUTH-409-IDEMPOTENCY-CONFLICT');
});

test('PUT /platform/roles/:role_id/permissions enforces idempotency across canonicalized role_id path variants', async () => {
  const harness = createHarness();
  const login = await loginOperator(
    harness.authService,
    'req-platform-role-login-permission-idem-canonicalized'
  );
  const authHeaders = {
    authorization: `Bearer ${login.access_token}`
  };
  const createRole = await dispatchApiRoute({
    pathname: '/platform/roles',
    method: 'POST',
    requestId: 'req-platform-role-create-permission-idem-canonicalized',
    headers: authHeaders,
    body: {
      role_id: 'idem_permission_canonicalized',
      code: 'IDEM_PERMISSION_CANONICALIZED',
      name: '权限幂等规范化角色',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRole.status, 200);

  const firstReplace = await dispatchApiRoute({
    pathname: '/platform/roles/Idem_Permission_Canonicalized/permissions',
    method: 'PUT',
    requestId: 'req-platform-role-permission-idem-canonicalized-1',
    headers: {
      ...authHeaders,
      'idempotency-key': 'idem-platform-role-permission-canonicalized-path'
    },
    body: {
      permission_codes: ['platform.member_admin.view']
    },
    handlers: harness.handlers
  });
  assert.equal(firstReplace.status, 200);

  const secondReplace = await dispatchApiRoute({
    pathname: '/platform/roles/IDEM_PERMISSION_CANONICALIZED/permissions',
    method: 'PUT',
    requestId: 'req-platform-role-permission-idem-canonicalized-2',
    headers: {
      ...authHeaders,
      'idempotency-key': 'idem-platform-role-permission-canonicalized-path'
    },
    body: {
      permission_codes: ['platform.billing.view']
    },
    handlers: harness.handlers
  });
  assert.equal(secondReplace.status, 409);
  const secondPayload = JSON.parse(secondReplace.body);
  assert.equal(secondPayload.error_code, 'AUTH-409-IDEMPOTENCY-CONFLICT');
});

test('DELETE /platform/roles/:role_id idempotency hash ignores request body drift', async () => {
  const harness = createHarness();
  const login = await loginOperator(harness.authService, 'req-platform-role-login-delete-body-drift');
  const authHeaders = {
    authorization: `Bearer ${login.access_token}`
  };
  const createRole = await dispatchApiRoute({
    pathname: '/platform/roles',
    method: 'POST',
    requestId: 'req-platform-role-create-delete-body-drift',
    headers: authHeaders,
    body: {
      role_id: 'delete_body_drift_target',
      code: 'DELETE_BODY_DRIFT_TARGET',
      name: '删除幂等请求体漂移目标角色',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRole.status, 200);

  const firstDelete = await dispatchApiRoute({
    pathname: '/platform/roles/delete_body_drift_target',
    method: 'DELETE',
    requestId: 'req-platform-role-delete-body-drift-1',
    headers: {
      ...authHeaders,
      'idempotency-key': 'idem-platform-role-delete-body-drift'
    },
    body: {
      payload: 'A'
    },
    handlers: harness.handlers
  });
  assert.equal(firstDelete.status, 200);

  const secondDelete = await dispatchApiRoute({
    pathname: '/platform/roles/delete_body_drift_target',
    method: 'DELETE',
    requestId: 'req-platform-role-delete-body-drift-2',
    headers: {
      ...authHeaders,
      'idempotency-key': 'idem-platform-role-delete-body-drift'
    },
    body: {
      payload: 'B'
    },
    handlers: harness.handlers
  });
  assert.equal(secondDelete.status, 200);
  const secondDeletePayload = JSON.parse(secondDelete.body);
  assert.equal(secondDeletePayload.role_id, 'delete_body_drift_target');
  assert.equal(secondDeletePayload.status, 'disabled');
  assert.equal(secondDeletePayload.request_id, 'req-platform-role-delete-body-drift-2');
});

test('PUT/GET /platform/roles/:role_id/permissions persists final grant codes and can be read back', async () => {
  const harness = createHarness();
  const login = await loginOperator(harness.authService, 'req-platform-role-login-permission-1');

  const createRole = await dispatchApiRoute({
    pathname: '/platform/roles',
    method: 'POST',
    requestId: 'req-platform-role-create-permission-1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      role_id: 'platform_permission_editor',
      code: 'PERMISSION_EDITOR',
      name: '权限配置员',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRole.status, 200);

  const replacePermissions = await dispatchApiRoute({
    pathname: '/platform/roles/platform_permission_editor/permissions',
    method: 'PUT',
    requestId: 'req-platform-role-permission-replace-1',
    headers: {
      authorization: `Bearer ${login.access_token}`,
      'idempotency-key': 'idem-platform-role-permission-replace-1'
    },
    body: {
      permission_codes: [
        'platform.member_admin.view',
        'platform.member_admin.operate'
      ]
    },
    handlers: harness.handlers
  });
  assert.equal(replacePermissions.status, 200);
  const replacePayload = JSON.parse(replacePermissions.body);
  assert.equal(replacePayload.role_id, 'platform_permission_editor');
  assert.deepEqual(
    replacePayload.permission_codes,
    ['platform.member_admin.operate', 'platform.member_admin.view']
  );
  assert.equal(replacePayload.request_id, 'req-platform-role-permission-replace-1');
  assert.ok(Array.isArray(replacePayload.available_permission_codes));
  assert.ok(replacePayload.available_permission_codes.includes('platform.member_admin.view'));

  const getPermissions = await dispatchApiRoute({
    pathname: '/platform/roles/platform_permission_editor/permissions',
    method: 'GET',
    requestId: 'req-platform-role-permission-read-1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers: harness.handlers
  });
  assert.equal(getPermissions.status, 200);
  const getPayload = JSON.parse(getPermissions.body);
  assert.equal(getPayload.role_id, 'platform_permission_editor');
  assert.deepEqual(
    getPayload.permission_codes,
    ['platform.member_admin.operate', 'platform.member_admin.view']
  );
  assert.equal(getPayload.request_id, 'req-platform-role-permission-read-1');
});

test('GET /platform/roles/:role_id/permissions fails closed when downstream payload is malformed', async () => {
  const harness = createHarness();
  const login = await loginOperator(harness.authService, 'req-platform-role-login-permission-read-malformed');

  const createRole = await dispatchApiRoute({
    pathname: '/platform/roles',
    method: 'POST',
    requestId: 'req-platform-role-create-permission-read-malformed',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      role_id: 'platform_permission_read_malformed',
      code: 'PERMISSION_READ_MALFORMED',
      name: '权限读取脏载荷角色',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRole.status, 200);

  const originalListPlatformRolePermissionGrants =
    harness.authService.listPlatformRolePermissionGrants;
  harness.authService.listPlatformRolePermissionGrants = async ({ roleId }) => {
    if (String(roleId || '').trim().toLowerCase() === 'platform_permission_read_malformed') {
      return {
        role_id: 'platform_permission_read_malformed',
        permission_codes: [' platform.member_admin.view'],
        available_permission_codes: ['platform.member_admin.view']
      };
    }
    return originalListPlatformRolePermissionGrants({ roleId });
  };

  try {
    const getPermissions = await dispatchApiRoute({
      pathname: '/platform/roles/platform_permission_read_malformed/permissions',
      method: 'GET',
      requestId: 'req-platform-role-permission-read-malformed',
      headers: {
        authorization: `Bearer ${login.access_token}`
      },
      handlers: harness.handlers
    });
    assert.equal(getPermissions.status, 503);
    const payload = JSON.parse(getPermissions.body);
    assert.equal(payload.error_code, 'ROLE-503-DEPENDENCY-UNAVAILABLE');
    assert.equal(payload.request_id, 'req-platform-role-permission-read-malformed');
  } finally {
    harness.authService.listPlatformRolePermissionGrants =
      originalListPlatformRolePermissionGrants;
  }
});

test('GET /platform/roles/:role_id/permissions returns deterministically sorted permission arrays', async () => {
  const harness = createHarness();
  const login = await loginOperator(harness.authService, 'req-platform-role-login-permission-read-sort-stability');

  const createRole = await dispatchApiRoute({
    pathname: '/platform/roles',
    method: 'POST',
    requestId: 'req-platform-role-create-permission-read-sort-stability',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      role_id: 'platform_permission_read_sort_stability',
      code: 'PERMISSION_READ_SORT_STABILITY',
      name: '权限读取稳定排序角色',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRole.status, 200);

  const originalListPlatformRolePermissionGrants =
    harness.authService.listPlatformRolePermissionGrants;
  harness.authService.listPlatformRolePermissionGrants = async ({ roleId }) => {
    if (String(roleId || '').trim().toLowerCase() === 'platform_permission_read_sort_stability') {
      return {
        role_id: 'platform_permission_read_sort_stability',
        permission_codes: [
          'platform.member_admin.view',
          'platform.member_admin.operate'
        ],
        available_permission_codes: [
          'platform.system_config.view',
          'platform.member_admin.view',
          'platform.billing.view',
          'platform.member_admin.operate'
        ]
      };
    }
    return originalListPlatformRolePermissionGrants({ roleId });
  };

  try {
    const getPermissions = await dispatchApiRoute({
      pathname: '/platform/roles/platform_permission_read_sort_stability/permissions',
      method: 'GET',
      requestId: 'req-platform-role-permission-read-sort-stability',
      headers: {
        authorization: `Bearer ${login.access_token}`
      },
      handlers: harness.handlers
    });
    assert.equal(getPermissions.status, 200);
    const payload = JSON.parse(getPermissions.body);
    assert.deepEqual(payload.permission_codes, [
      'platform.member_admin.operate',
      'platform.member_admin.view'
    ]);
    assert.deepEqual(payload.available_permission_codes, [
      'platform.billing.view',
      'platform.member_admin.operate',
      'platform.member_admin.view',
      'platform.system_config.view'
    ]);
  } finally {
    harness.authService.listPlatformRolePermissionGrants =
      originalListPlatformRolePermissionGrants;
  }
});

test('GET /platform/roles/:role_id/permissions fails closed when downstream payload includes unknown catalog permissions', async () => {
  const harness = createHarness();
  const login = await loginOperator(harness.authService, 'req-platform-role-login-permission-read-unknown-catalog');

  const createRole = await dispatchApiRoute({
    pathname: '/platform/roles',
    method: 'POST',
    requestId: 'req-platform-role-create-permission-read-unknown-catalog',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      role_id: 'platform_permission_read_unknown_catalog',
      code: 'PERMISSION_READ_UNKNOWN_CATALOG',
      name: '权限读取未知目录项角色',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRole.status, 200);

  const originalListPlatformRolePermissionGrants =
    harness.authService.listPlatformRolePermissionGrants;
  harness.authService.listPlatformRolePermissionGrants = async ({ roleId }) => {
    if (String(roleId || '').trim().toLowerCase() === 'platform_permission_read_unknown_catalog') {
      return {
        role_id: 'platform_permission_read_unknown_catalog',
        permission_codes: ['platform.permission.unknown'],
        available_permission_codes: ['platform.permission.unknown']
      };
    }
    return originalListPlatformRolePermissionGrants({ roleId });
  };

  try {
    const getPermissions = await dispatchApiRoute({
      pathname: '/platform/roles/platform_permission_read_unknown_catalog/permissions',
      method: 'GET',
      requestId: 'req-platform-role-permission-read-unknown-catalog',
      headers: {
        authorization: `Bearer ${login.access_token}`
      },
      handlers: harness.handlers
    });
    assert.equal(getPermissions.status, 503);
    const payload = JSON.parse(getPermissions.body);
    assert.equal(payload.error_code, 'ROLE-503-DEPENDENCY-UNAVAILABLE');
    assert.equal(payload.request_id, 'req-platform-role-permission-read-unknown-catalog');
  } finally {
    harness.authService.listPlatformRolePermissionGrants =
      originalListPlatformRolePermissionGrants;
  }
});

test('PUT /platform/roles/:role_id/permissions fails closed when downstream write result role_id mismatches target', async () => {
  const harness = createHarness();
  const login = await loginOperator(harness.authService, 'req-platform-role-login-permission-write-roleid-mismatch');

  const createRole = await dispatchApiRoute({
    pathname: '/platform/roles',
    method: 'POST',
    requestId: 'req-platform-role-create-permission-write-roleid-mismatch',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      role_id: 'platform_permission_write_roleid_mismatch',
      code: 'PERMISSION_WRITE_ROLEID_MISMATCH',
      name: '权限写入角色标识不匹配角色',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRole.status, 200);

  const originalReplacePlatformRolePermissionGrants =
    harness.authService.replacePlatformRolePermissionGrants;
  harness.authService.replacePlatformRolePermissionGrants = async () => ({
    role_id: 'platform_permission_write_roleid_mismatch_other',
    permission_codes: ['platform.member_admin.view'],
    affected_user_count: 0
  });
  try {
    const replacePermissions = await dispatchApiRoute({
      pathname: '/platform/roles/platform_permission_write_roleid_mismatch/permissions',
      method: 'PUT',
      requestId: 'req-platform-role-permission-write-roleid-mismatch',
      headers: {
        authorization: `Bearer ${login.access_token}`
      },
      body: {
        permission_codes: ['platform.member_admin.view']
      },
      handlers: harness.handlers
    });
    assert.equal(replacePermissions.status, 503);
    const payload = JSON.parse(replacePermissions.body);
    assert.equal(payload.error_code, 'ROLE-503-DEPENDENCY-UNAVAILABLE');
    assert.equal(payload.request_id, 'req-platform-role-permission-write-roleid-mismatch');
  } finally {
    harness.authService.replacePlatformRolePermissionGrants =
      originalReplacePlatformRolePermissionGrants;
  }
});

test('PUT /platform/roles/:role_id/permissions fails closed when downstream write affected_user_count is malformed', async () => {
  const harness = createHarness();
  const login = await loginOperator(harness.authService, 'req-platform-role-login-permission-write-affected-user-count-string');

  const createRole = await dispatchApiRoute({
    pathname: '/platform/roles',
    method: 'POST',
    requestId: 'req-platform-role-create-permission-write-affected-user-count-string',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      role_id: 'platform_permission_write_affected_user_count_string',
      code: 'PERMISSION_WRITE_AFFECTED_USER_COUNT_STRING',
      name: '权限写入影响用户数异常角色',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRole.status, 200);

  const originalReplacePlatformRolePermissionGrants =
    harness.authService.replacePlatformRolePermissionGrants;
  harness.authService.replacePlatformRolePermissionGrants = async () => ({
    role_id: 'platform_permission_write_affected_user_count_string',
    permission_codes: ['platform.member_admin.view'],
    affected_user_count: '1'
  });
  try {
    const replacePermissions = await dispatchApiRoute({
      pathname: '/platform/roles/platform_permission_write_affected_user_count_string/permissions',
      method: 'PUT',
      requestId: 'req-platform-role-permission-write-affected-user-count-string',
      headers: {
        authorization: `Bearer ${login.access_token}`
      },
      body: {
        permission_codes: ['platform.member_admin.view']
      },
      handlers: harness.handlers
    });
    assert.equal(replacePermissions.status, 503);
    const payload = JSON.parse(replacePermissions.body);
    assert.equal(payload.error_code, 'ROLE-503-DEPENDENCY-UNAVAILABLE');
    assert.equal(payload.request_id, 'req-platform-role-permission-write-affected-user-count-string');
  } finally {
    harness.authService.replacePlatformRolePermissionGrants =
      originalReplacePlatformRolePermissionGrants;
  }
});

test('PUT /platform/roles/:role_id/permissions fails closed when permission catalog dependency is unavailable', async () => {
  const harness = createHarness();
  const login = await loginOperator(harness.authService, 'req-platform-role-login-permission-write-catalog-dependency');

  const createRole = await dispatchApiRoute({
    pathname: '/platform/roles',
    method: 'POST',
    requestId: 'req-platform-role-create-permission-write-catalog-dependency',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      role_id: 'platform_permission_write_catalog_dependency',
      code: 'PERMISSION_WRITE_CATALOG_DEPENDENCY',
      name: '权限写入目录依赖异常角色',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRole.status, 200);

  const originalListPlatformPermissionCatalog = harness.authService.listPlatformPermissionCatalog;
  harness.authService.listPlatformPermissionCatalog = () => {
    throw new Error('catalog dependency unavailable');
  };

  try {
    const replacePermissions = await dispatchApiRoute({
      pathname: '/platform/roles/platform_permission_write_catalog_dependency/permissions',
      method: 'PUT',
      requestId: 'req-platform-role-permission-write-catalog-dependency',
      headers: {
        authorization: `Bearer ${login.access_token}`
      },
      body: {
        permission_codes: ['platform.member_admin.view']
      },
      handlers: harness.handlers
    });
    assert.equal(replacePermissions.status, 503);
    const payload = JSON.parse(replacePermissions.body);
    assert.equal(payload.error_code, 'ROLE-503-DEPENDENCY-UNAVAILABLE');
    assert.equal(payload.request_id, 'req-platform-role-permission-write-catalog-dependency');
  } finally {
    harness.authService.listPlatformPermissionCatalog = originalListPlatformPermissionCatalog;
  }
});

test('PUT /platform/roles/:role_id/permissions fails closed before write when permission catalog payload is malformed', async () => {
  const harness = createHarness();
  const login = await loginOperator(harness.authService, 'req-platform-role-login-permission-write-catalog-malformed');

  const createRole = await dispatchApiRoute({
    pathname: '/platform/roles',
    method: 'POST',
    requestId: 'req-platform-role-create-permission-write-catalog-malformed',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      role_id: 'platform_permission_write_catalog_malformed',
      code: 'PERMISSION_WRITE_CATALOG_MALFORMED',
      name: '权限写入目录畸形回包角色',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRole.status, 200);

  const originalListPlatformPermissionCatalog = harness.authService.listPlatformPermissionCatalog;
  const originalReplacePlatformRolePermissionGrants =
    harness.authService.replacePlatformRolePermissionGrants;
  let replacePlatformRolePermissionGrantsCalls = 0;
  harness.authService.listPlatformPermissionCatalog = () => ({
    malformed: true
  });
  harness.authService.replacePlatformRolePermissionGrants = async ({ roleId }) => {
    replacePlatformRolePermissionGrantsCalls += 1;
    return {
      role_id: roleId,
      permission_codes: [],
      affected_user_count: 0
    };
  };

  try {
    const replacePermissions = await dispatchApiRoute({
      pathname: '/platform/roles/platform_permission_write_catalog_malformed/permissions',
      method: 'PUT',
      requestId: 'req-platform-role-permission-write-catalog-malformed',
      headers: {
        authorization: `Bearer ${login.access_token}`
      },
      body: {
        permission_codes: []
      },
      handlers: harness.handlers
    });
    assert.equal(replacePermissions.status, 503);
    const payload = JSON.parse(replacePermissions.body);
    assert.equal(payload.error_code, 'ROLE-503-DEPENDENCY-UNAVAILABLE');
    assert.equal(payload.request_id, 'req-platform-role-permission-write-catalog-malformed');
    assert.equal(replacePlatformRolePermissionGrantsCalls, 0);
  } finally {
    harness.authService.listPlatformPermissionCatalog = originalListPlatformPermissionCatalog;
    harness.authService.replacePlatformRolePermissionGrants =
      originalReplacePlatformRolePermissionGrants;
  }
});

test('PUT /platform/roles/:role_id/permissions allows disabled role definitions to be configured', async () => {
  const harness = createHarness();
  const login = await loginOperator(harness.authService, 'req-platform-role-login-permission-disabled-1');

  const createRole = await dispatchApiRoute({
    pathname: '/platform/roles',
    method: 'POST',
    requestId: 'req-platform-role-create-permission-disabled-1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      role_id: 'platform_permission_disabled_role',
      code: 'PERMISSION_DISABLED_ROLE',
      name: '禁用状态权限配置角色',
      status: 'disabled'
    },
    handlers: harness.handlers
  });
  assert.equal(createRole.status, 200);

  const replacePermissions = await dispatchApiRoute({
    pathname: '/platform/roles/platform_permission_disabled_role/permissions',
    method: 'PUT',
    requestId: 'req-platform-role-permission-disabled-replace-1',
    headers: {
      authorization: `Bearer ${login.access_token}`,
      'idempotency-key': 'idem-platform-role-permission-disabled-replace-1'
    },
    body: {
      permission_codes: ['platform.member_admin.view']
    },
    handlers: harness.handlers
  });
  assert.equal(replacePermissions.status, 200);
  const replacePayload = JSON.parse(replacePermissions.body);
  assert.equal(replacePayload.role_id, 'platform_permission_disabled_role');
  assert.deepEqual(replacePayload.permission_codes, ['platform.member_admin.view']);

  const getPermissions = await dispatchApiRoute({
    pathname: '/platform/roles/platform_permission_disabled_role/permissions',
    method: 'GET',
    requestId: 'req-platform-role-permission-disabled-read-1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers: harness.handlers
  });
  assert.equal(getPermissions.status, 200);
  const getPayload = JSON.parse(getPermissions.body);
  assert.equal(getPayload.role_id, 'platform_permission_disabled_role');
  assert.deepEqual(getPayload.permission_codes, ['platform.member_admin.view']);
});

test('PUT /platform/roles/:role_id/permissions rejects non-platform or unknown permission code', async () => {
  const harness = createHarness();
  const login = await loginOperator(harness.authService, 'req-platform-role-login-permission-2');

  const createRole = await dispatchApiRoute({
    pathname: '/platform/roles',
    method: 'POST',
    requestId: 'req-platform-role-create-permission-2',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      role_id: 'platform_permission_reject',
      code: 'PERMISSION_REJECT',
      name: '非法权限码测试角色',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRole.status, 200);

  const replacePermissions = await dispatchApiRoute({
    pathname: '/platform/roles/platform_permission_reject/permissions',
    method: 'PUT',
    requestId: 'req-platform-role-permission-reject-1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      permission_codes: ['tenant.member_admin.view']
    },
    handlers: harness.handlers
  });
  assert.equal(replacePermissions.status, 400);
  const payload = JSON.parse(replacePermissions.body);
  assert.equal(payload.error_code, 'ROLE-400-INVALID-PAYLOAD');
});

test('PUT /platform/roles/:role_id/permissions rejects permission codes with leading or trailing whitespace', async () => {
  const harness = createHarness();
  const login = await loginOperator(harness.authService, 'req-platform-role-login-permission-whitespace-1');

  const createRole = await dispatchApiRoute({
    pathname: '/platform/roles',
    method: 'POST',
    requestId: 'req-platform-role-create-permission-whitespace-1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      role_id: 'platform_permission_whitespace_role',
      code: 'PERMISSION_WHITESPACE_ROLE',
      name: '权限码空白校验角色',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRole.status, 200);

  const replacePermissions = await dispatchApiRoute({
    pathname: '/platform/roles/platform_permission_whitespace_role/permissions',
    method: 'PUT',
    requestId: 'req-platform-role-permission-whitespace-replace-1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      permission_codes: [' platform.member_admin.view']
    },
    handlers: harness.handlers
  });
  assert.equal(replacePermissions.status, 400);
  const payload = JSON.parse(replacePermissions.body);
  assert.equal(payload.error_code, 'ROLE-400-INVALID-PAYLOAD');
});

test('PUT /platform/roles/:role_id/permissions canonicalizes duplicated permission codes (case-insensitive)', async () => {
  const harness = createHarness();
  const login = await loginOperator(harness.authService, 'req-platform-role-login-permission-dup-1');

  const createRole = await dispatchApiRoute({
    pathname: '/platform/roles',
    method: 'POST',
    requestId: 'req-platform-role-create-permission-dup-1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      role_id: 'platform_permission_duplicate_role',
      code: 'PERMISSION_DUPLICATE_ROLE',
      name: '重复权限码测试角色',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRole.status, 200);

  const replacePermissions = await dispatchApiRoute({
    pathname: '/platform/roles/platform_permission_duplicate_role/permissions',
    method: 'PUT',
    requestId: 'req-platform-role-permission-dup-replace-1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      permission_codes: [
        'platform.member_admin.view',
        'platform.Member_Admin.View'
      ]
    },
    handlers: harness.handlers
  });
  assert.equal(replacePermissions.status, 200);
  const payload = JSON.parse(replacePermissions.body);
  assert.deepEqual(payload.permission_codes, ['platform.member_admin.view']);
});

test('PUT /platform/roles/:role_id/permissions rejects oversized permission_codes payload', async () => {
  const harness = createHarness();
  const login = await loginOperator(harness.authService, 'req-platform-role-login-permission-oversize-1');

  const createRole = await dispatchApiRoute({
    pathname: '/platform/roles',
    method: 'POST',
    requestId: 'req-platform-role-create-permission-oversize-1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      role_id: 'platform_permission_oversize_role',
      code: 'PERMISSION_OVERSIZE_ROLE',
      name: '超大权限列表测试角色',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRole.status, 200);

  const oversizedPermissionCodes = Array.from(
    { length: 65 },
    () => 'platform.member_admin.view'
  );
  const replacePermissions = await dispatchApiRoute({
    pathname: '/platform/roles/platform_permission_oversize_role/permissions',
    method: 'PUT',
    requestId: 'req-platform-role-permission-oversize-replace-1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      permission_codes: oversizedPermissionCodes
    },
    handlers: harness.handlers
  });
  assert.equal(replacePermissions.status, 400);
  const payload = JSON.parse(replacePermissions.body);
  assert.equal(payload.error_code, 'ROLE-400-INVALID-PAYLOAD');
});

test('PUT /platform/roles/:role_id/permissions normalizes accepted permission codes to lowercase canonical form', async () => {
  const harness = createHarness();
  const login = await loginOperator(harness.authService, 'req-platform-role-login-permission-case-1');

  const createRole = await dispatchApiRoute({
    pathname: '/platform/roles',
    method: 'POST',
    requestId: 'req-platform-role-create-permission-case-1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      role_id: 'platform_permission_case_role',
      code: 'PERMISSION_CASE_ROLE',
      name: '权限码大小写规范化测试角色',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRole.status, 200);

  const replacePermissions = await dispatchApiRoute({
    pathname: '/platform/roles/platform_permission_case_role/permissions',
    method: 'PUT',
    requestId: 'req-platform-role-permission-case-replace-1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      permission_codes: [
        'platform.Member_Admin.View',
        'platform.MEMBER_admin.operate'
      ]
    },
    handlers: harness.handlers
  });
  assert.equal(replacePermissions.status, 200);
  const replacePayload = JSON.parse(replacePermissions.body);
  assert.deepEqual(
    replacePayload.permission_codes,
    ['platform.member_admin.operate', 'platform.member_admin.view']
  );

  const getPermissions = await dispatchApiRoute({
    pathname: '/platform/roles/platform_permission_case_role/permissions',
    method: 'GET',
    requestId: 'req-platform-role-permission-case-read-1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers: harness.handlers
  });
  assert.equal(getPermissions.status, 200);
  assert.deepEqual(
    JSON.parse(getPermissions.body).permission_codes,
    ['platform.member_admin.operate', 'platform.member_admin.view']
  );
});

test('PUT /platform/roles/:role_id/permissions fails closed before write when resync capability is unavailable', async () => {
  const harness = createHarness();
  const login = await loginOperator(harness.authService, 'req-platform-role-login-permission-preflight-1');

  const createRole = await dispatchApiRoute({
    pathname: '/platform/roles',
    method: 'POST',
    requestId: 'req-platform-role-create-permission-preflight-1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      role_id: 'platform_permission_preflight_role',
      code: 'PERMISSION_PREFLIGHT_ROLE',
      name: '权限预检测试角色',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRole.status, 200);

  const baselineRead = await dispatchApiRoute({
    pathname: '/platform/roles/platform_permission_preflight_role/permissions',
    method: 'GET',
    requestId: 'req-platform-role-permission-preflight-read-baseline',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers: harness.handlers
  });
  assert.equal(baselineRead.status, 200);
  assert.deepEqual(JSON.parse(baselineRead.body).permission_codes, []);

  const authStore = harness.authService._internals.authStore;
  const originalListUserIdsByPlatformRoleId = authStore.listUserIdsByPlatformRoleId;
  authStore.listUserIdsByPlatformRoleId = undefined;
  try {
    const replacePermissions = await dispatchApiRoute({
      pathname: '/platform/roles/platform_permission_preflight_role/permissions',
      method: 'PUT',
      requestId: 'req-platform-role-permission-preflight-replace-1',
      headers: {
        authorization: `Bearer ${login.access_token}`
      },
      body: {
        permission_codes: ['platform.member_admin.view']
      },
      handlers: harness.handlers
    });
    assert.equal(replacePermissions.status, 503);
    assert.equal(JSON.parse(replacePermissions.body).error_code, 'ROLE-503-DEPENDENCY-UNAVAILABLE');
  } finally {
    authStore.listUserIdsByPlatformRoleId = originalListUserIdsByPlatformRoleId;
  }

  const readAfterFailedWrite = await dispatchApiRoute({
    pathname: '/platform/roles/platform_permission_preflight_role/permissions',
    method: 'GET',
    requestId: 'req-platform-role-permission-preflight-read-after-failure',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers: harness.handlers
  });
  assert.equal(readAfterFailedWrite.status, 200);
  assert.deepEqual(JSON.parse(readAfterFailedWrite.body).permission_codes, []);
});

test('PUT /platform/roles/:role_id/permissions maps delete-race write miss to ROLE-404-ROLE-NOT-FOUND', async () => {
  const harness = createHarness();
  const login = await loginOperator(harness.authService, 'req-platform-role-login-permission-race-delete');

  const createRole = await dispatchApiRoute({
    pathname: '/platform/roles',
    method: 'POST',
    requestId: 'req-platform-role-create-permission-race-delete',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      role_id: 'platform_permission_race_deleted_role',
      code: 'PERMISSION_RACE_DELETED_ROLE',
      name: '权限删除竞争角色',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRole.status, 200);

  const authStore = harness.authService._internals.authStore;
  const originalReplacePlatformRolePermissionGrants =
    authStore.replacePlatformRolePermissionGrants;
  authStore.replacePlatformRolePermissionGrants = async () => null;
  try {
    const replacePermissions = await dispatchApiRoute({
      pathname: '/platform/roles/platform_permission_race_deleted_role/permissions',
      method: 'PUT',
      requestId: 'req-platform-role-permission-race-delete',
      headers: {
        authorization: `Bearer ${login.access_token}`
      },
      body: {
        permission_codes: ['platform.member_admin.view']
      },
      handlers: harness.handlers
    });
    assert.equal(replacePermissions.status, 404);
    assert.equal(JSON.parse(replacePermissions.body).error_code, 'ROLE-404-ROLE-NOT-FOUND');
  } finally {
    authStore.replacePlatformRolePermissionGrants = originalReplacePlatformRolePermissionGrants;
  }
});

test('role permission grants update converges affected sessions and takes effect immediately for authorization', async () => {
  const harness = createHarness();
  const operatorLogin = await loginOperator(harness.authService, 'req-platform-role-login-permission-3-operator');

  const createRole = await dispatchApiRoute({
    pathname: '/platform/roles',
    method: 'POST',
    requestId: 'req-platform-role-create-permission-3',
    headers: {
      authorization: `Bearer ${operatorLogin.access_token}`
    },
    body: {
      role_id: 'platform_scope_probe_role',
      code: 'SCOPE_PROBE_ROLE',
      name: '权限收敛验证角色',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRole.status, 200);

  const grantPermission = await dispatchApiRoute({
    pathname: '/platform/roles/platform_scope_probe_role/permissions',
    method: 'PUT',
    requestId: 'req-platform-role-permission-replace-3-1',
    headers: {
      authorization: `Bearer ${operatorLogin.access_token}`
    },
    body: {
      permission_codes: ['platform.member_admin.view']
    },
    handlers: harness.handlers
  });
  assert.equal(grantPermission.status, 200);

  const assignRole = await dispatchApiRoute({
    pathname: '/auth/platform/role-facts/replace',
    method: 'POST',
    requestId: 'req-platform-role-assign-permission-3',
    headers: {
      authorization: `Bearer ${operatorLogin.access_token}`
    },
    body: {
      user_id: 'platform-role-target-user',
      roles: [{ role_id: 'platform_scope_probe_role' }]
    },
    handlers: harness.handlers
  });
  assert.equal(assignRole.status, 200);

  const targetLogin = await loginByPhone(
    harness.authService,
    'req-platform-role-login-permission-3-target',
    TARGET_PHONE
  );
  const targetProbeAllowed = await dispatchApiRoute({
    pathname: '/auth/platform/member-admin/probe',
    method: 'GET',
    requestId: 'req-platform-role-probe-permission-3-allowed',
    headers: {
      authorization: `Bearer ${targetLogin.access_token}`
    },
    handlers: harness.handlers
  });
  assert.equal(targetProbeAllowed.status, 200);

  const revokePermission = await dispatchApiRoute({
    pathname: '/platform/roles/platform_scope_probe_role/permissions',
    method: 'PUT',
    requestId: 'req-platform-role-permission-replace-3-2',
    headers: {
      authorization: `Bearer ${operatorLogin.access_token}`
    },
    body: {
      permission_codes: []
    },
    handlers: harness.handlers
  });
  assert.equal(revokePermission.status, 200);

  const targetProbeWithOldToken = await dispatchApiRoute({
    pathname: '/auth/platform/member-admin/probe',
    method: 'GET',
    requestId: 'req-platform-role-probe-permission-3-old-token',
    headers: {
      authorization: `Bearer ${targetLogin.access_token}`
    },
    handlers: harness.handlers
  });
  assert.equal(targetProbeWithOldToken.status, 401);
  assert.equal(JSON.parse(targetProbeWithOldToken.body).error_code, 'AUTH-401-INVALID-ACCESS');

  const targetRelogin = await loginByPhone(
    harness.authService,
    'req-platform-role-login-permission-3-target-relogin',
    TARGET_PHONE
  );
  const targetProbeDenied = await dispatchApiRoute({
    pathname: '/auth/platform/member-admin/probe',
    method: 'GET',
    requestId: 'req-platform-role-probe-permission-3-denied',
    headers: {
      authorization: `Bearer ${targetRelogin.access_token}`
    },
    handlers: harness.handlers
  });
  assert.equal(targetProbeDenied.status, 403);
  assert.equal(JSON.parse(targetProbeDenied.body).error_code, 'AUTH-403-FORBIDDEN');
});

test('PATCH /platform/roles/:role_id disabling role converges affected sessions and denies protected access immediately', async () => {
  const harness = createHarness();
  const operatorLogin = await loginOperator(
    harness.authService,
    'req-platform-role-login-disable-operator'
  );

  const createRole = await dispatchApiRoute({
    pathname: '/platform/roles',
    method: 'POST',
    requestId: 'req-platform-role-create-disable-target',
    headers: {
      authorization: `Bearer ${operatorLogin.access_token}`
    },
    body: {
      role_id: 'platform_scope_disable_role',
      code: 'SCOPE_DISABLE_ROLE',
      name: '平台角色禁用即时收敛验证',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRole.status, 200);

  const grantPermission = await dispatchApiRoute({
    pathname: '/platform/roles/platform_scope_disable_role/permissions',
    method: 'PUT',
    requestId: 'req-platform-role-disable-permission-replace-1',
    headers: {
      authorization: `Bearer ${operatorLogin.access_token}`
    },
    body: {
      permission_codes: ['platform.member_admin.view']
    },
    handlers: harness.handlers
  });
  assert.equal(grantPermission.status, 200);

  const assignRole = await dispatchApiRoute({
    pathname: '/auth/platform/role-facts/replace',
    method: 'POST',
    requestId: 'req-platform-role-disable-assign-target',
    headers: {
      authorization: `Bearer ${operatorLogin.access_token}`
    },
    body: {
      user_id: 'platform-role-target-user',
      roles: [{ role_id: 'platform_scope_disable_role' }]
    },
    handlers: harness.handlers
  });
  assert.equal(assignRole.status, 200);

  const targetLogin = await loginByPhone(
    harness.authService,
    'req-platform-role-disable-login-target',
    TARGET_PHONE
  );
  const targetProbeAllowed = await dispatchApiRoute({
    pathname: '/auth/platform/member-admin/probe',
    method: 'GET',
    requestId: 'req-platform-role-disable-probe-allowed',
    headers: {
      authorization: `Bearer ${targetLogin.access_token}`
    },
    handlers: harness.handlers
  });
  assert.equal(targetProbeAllowed.status, 200);

  const disableRole = await dispatchApiRoute({
    pathname: '/platform/roles/platform_scope_disable_role',
    method: 'PATCH',
    requestId: 'req-platform-role-disable-status-patch',
    headers: {
      authorization: `Bearer ${operatorLogin.access_token}`
    },
    body: {
      status: 'disabled'
    },
    handlers: harness.handlers
  });
  assert.equal(disableRole.status, 200);
  assert.equal(JSON.parse(disableRole.body).status, 'disabled');

  const probeWithOldToken = await dispatchApiRoute({
    pathname: '/auth/platform/member-admin/probe',
    method: 'GET',
    requestId: 'req-platform-role-disable-probe-old-token',
    headers: {
      authorization: `Bearer ${targetLogin.access_token}`
    },
    handlers: harness.handlers
  });
  assert.equal(probeWithOldToken.status, 401);
  assert.equal(JSON.parse(probeWithOldToken.body).error_code, 'AUTH-401-INVALID-ACCESS');

  const targetRelogin = await loginByPhone(
    harness.authService,
    'req-platform-role-disable-login-target-relogin',
    TARGET_PHONE
  );
  const targetProbeDenied = await dispatchApiRoute({
    pathname: '/auth/platform/member-admin/probe',
    method: 'GET',
    requestId: 'req-platform-role-disable-probe-denied',
    headers: {
      authorization: `Bearer ${targetRelogin.access_token}`
    },
    handlers: harness.handlers
  });
  assert.equal(targetProbeDenied.status, 403);
  assert.equal(JSON.parse(targetProbeDenied.body).error_code, 'AUTH-403-FORBIDDEN');

  const boundUserIds = await harness.authService._internals.authStore.listUserIdsByPlatformRoleId({
    roleId: 'platform_scope_disable_role'
  });
  assert.ok(boundUserIds.includes('platform-role-target-user'));
});

test('POST /auth/platform/role-facts/replace rejects empty role list with AUTH-400-INVALID-PAYLOAD', async () => {
  const harness = createHarness();
  const login = await loginOperator(harness.authService, 'req-platform-role-login-empty-roles');

  const assignEmptyRoles = await dispatchApiRoute({
    pathname: '/auth/platform/role-facts/replace',
    method: 'POST',
    requestId: 'req-platform-role-assign-empty-roles',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      user_id: 'platform-role-target-user',
      roles: []
    },
    handlers: harness.handlers
  });

  assert.equal(assignEmptyRoles.status, 400);
  const payload = JSON.parse(assignEmptyRoles.body);
  assert.equal(payload.error_code, 'AUTH-400-INVALID-PAYLOAD');
});

test('POST /auth/platform/role-facts/replace rejects unknown role when only system role catalog exists', async () => {
  const harness = createHarness();
  const login = await loginOperator(harness.authService, 'req-platform-role-login-unknown-only-system');

  const assignUnknownRole = await dispatchApiRoute({
    pathname: '/auth/platform/role-facts/replace',
    method: 'POST',
    requestId: 'req-platform-role-assign-unknown-only-system',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      user_id: 'platform-role-target-user',
      roles: [
        {
          role_id: 'platform_role_missing_in_catalog_before_custom',
          status: 'active'
        }
      ]
    },
    handlers: harness.handlers
  });

  assert.equal(assignUnknownRole.status, 400);
  const payload = JSON.parse(assignUnknownRole.body);
  assert.equal(payload.error_code, 'AUTH-400-INVALID-PAYLOAD');
  assert.equal(payload.request_id, 'req-platform-role-assign-unknown-only-system');
});

test('POST /auth/platform/role-facts/replace validates role catalog existence/status/scope once custom roles exist', async () => {
  const harness = createHarness();
  const login = await loginOperator(harness.authService, 'req-platform-role-login-4');

  const createCustomRole = await dispatchApiRoute({
    pathname: '/platform/roles',
    method: 'POST',
    requestId: 'req-platform-role-create-custom',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      role_id: 'platform_policy_admin',
      code: 'POLICY_ADMIN',
      name: '策略管理员',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createCustomRole.status, 200);

  const assignKnownRole = await dispatchApiRoute({
    pathname: '/auth/platform/role-facts/replace',
    method: 'POST',
    requestId: 'req-platform-role-assign-known',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      user_id: 'platform-role-target-user',
      roles: [
        {
          role_id: 'platform_policy_admin',
          status: 'active'
        }
      ]
    },
    handlers: harness.handlers
  });

  assert.equal(assignKnownRole.status, 200);
  const assignKnownPayload = JSON.parse(assignKnownRole.body);
  assert.equal(assignKnownPayload.synced, true);
  assert.equal(assignKnownPayload.request_id, 'req-platform-role-assign-known');

  const createDisabledRole = await dispatchApiRoute({
    pathname: '/platform/roles',
    method: 'POST',
    requestId: 'req-platform-role-create-disabled',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      role_id: 'platform_disabled_role',
      code: 'DISABLED_ROLE',
      name: '已禁用角色',
      status: 'disabled'
    },
    handlers: harness.handlers
  });
  assert.equal(createDisabledRole.status, 200);

  const assignDisabledRole = await dispatchApiRoute({
    pathname: '/auth/platform/role-facts/replace',
    method: 'POST',
    requestId: 'req-platform-role-assign-disabled',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      user_id: 'platform-role-target-user',
      roles: [
        {
          role_id: 'platform_disabled_role',
          status: 'active'
        }
      ]
    },
    handlers: harness.handlers
  });
  assert.equal(assignDisabledRole.status, 400);
  assert.equal(
    JSON.parse(assignDisabledRole.body).error_code,
    'AUTH-400-INVALID-PAYLOAD'
  );

  const assignUnknownRole = await dispatchApiRoute({
    pathname: '/auth/platform/role-facts/replace',
    method: 'POST',
    requestId: 'req-platform-role-assign-unknown',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      user_id: 'platform-role-target-user',
      roles: [
        {
          role_id: 'platform_role_missing_in_catalog',
          status: 'active'
        }
      ]
    },
    handlers: harness.handlers
  });

  assert.equal(assignUnknownRole.status, 400);
  const unknownPayload = JSON.parse(assignUnknownRole.body);
  assert.equal(unknownPayload.error_code, 'AUTH-400-INVALID-PAYLOAD');
  assert.equal(unknownPayload.request_id, 'req-platform-role-assign-unknown');
});
