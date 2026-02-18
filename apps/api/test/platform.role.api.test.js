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

test('PUT /platform/roles/:role_id/permissions rejects duplicated permission codes (case-insensitive)', async () => {
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
  assert.equal(replacePermissions.status, 400);
  const payload = JSON.parse(replacePermissions.body);
  assert.equal(payload.error_code, 'ROLE-400-INVALID-PAYLOAD');
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
