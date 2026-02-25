const test = require('node:test');
const assert = require('node:assert/strict');
const { createRouteHandlers } = require('../src/http-routes');
const { createAuthService } = require('../src/modules/auth/auth.service');
const { AuthProblemError } = require('../src/modules/auth/auth.routes');
const { dispatchApiRoute } = require('../src/server');
const { readConfig } = require('../src/config/env');

const config = readConfig({ ALLOW_MOCK_BACKENDS: 'true' });
const dependencyProbe = async () => ({
  db: { ok: true },
  redis: { ok: true }
});

const TENANT_OPERATOR_A_PHONE = '13831000001';
const TENANT_OPERATOR_B_PHONE = '13831000002';

const createHarness = () => {
  const authService = createAuthService({
    seedUsers: [
      {
        id: 'tenant-role-operator-a',
        phone: TENANT_OPERATOR_A_PHONE,
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant'],
        tenants: [
          {
            membershipId: 'membership-tenant-role-a',
            tenantId: 'tenant-a',
            tenantName: 'Tenant A',
            status: 'active',
            permission: {
              scopeLabel: '组织权限（Tenant A）',
              canViewUserManagement: true,
              canOperateUserManagement: true,
              canViewRoleManagement: true,
              canOperateRoleManagement: true
            }
          }
        ]
      },
      {
        id: 'tenant-role-operator-b',
        phone: TENANT_OPERATOR_B_PHONE,
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant'],
        tenants: [
          {
            membershipId: 'membership-tenant-role-b',
            tenantId: 'tenant-b',
            tenantName: 'Tenant B',
            status: 'active',
            permission: {
              scopeLabel: '组织权限（Tenant B）',
              canViewUserManagement: true,
              canOperateUserManagement: true,
              canViewRoleManagement: true,
              canOperateRoleManagement: true
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

const loginByPhone = async (authService, requestId, phone) =>
  authService.login({
    requestId,
    phone,
    password: 'Passw0rd!',
    entryDomain: 'tenant'
  });

const resolveMembershipIdByUserAndTenant = async ({
  authService,
  requestId,
  operatorUserId,
  targetUserId,
  tenantId
}) => {
  const users = await authService.listTenantUsers({
    requestId,
    operatorUserId,
    tenantId,
    page: 1,
    pageSize: 100,
    entryDomain: 'tenant'
  });
  assert.ok(Array.isArray(users));
  const target = users.find((user) => String(user?.user_id || '') === String(targetUserId || ''));
  assert.ok(target);
  const membershipId = String(target?.membership_id || '').trim();
  assert.ok(membershipId.length > 0);
  return membershipId;
};

test('POST /tenant/roles creates role and GET /tenant/roles returns tenant-scoped catalog entries', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-create-list',
    TENANT_OPERATOR_A_PHONE
  );

  const createRoute = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      role_id: 'tenant_a_ops_admin',
      code: 'OPS_ADMIN',
      name: '租户A运维管理员',
      status: 'active'
    },
    handlers: harness.handlers
  });

  assert.equal(createRoute.status, 200);
  const createPayload = JSON.parse(createRoute.body);
  assert.equal(createPayload.role_id, 'tenant_a_ops_admin');
  assert.equal(createPayload.tenant_id, 'tenant-a');
  assert.equal(createPayload.code, 'OPS_ADMIN');
  assert.equal(createPayload.name, '租户A运维管理员');
  assert.equal(createPayload.status, 'active');
  assert.equal(createPayload.is_system, false);
  assert.equal(createPayload.request_id, 'req-tenant-role-create-1');
  assert.ok(typeof createPayload.created_at === 'string' && createPayload.created_at.length > 0);
  assert.ok(typeof createPayload.updated_at === 'string' && createPayload.updated_at.length > 0);

  const listRoute = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'GET',
    requestId: 'req-tenant-role-list-1',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers: harness.handlers
  });

  assert.equal(listRoute.status, 200);
  const listPayload = JSON.parse(listRoute.body);
  assert.equal(listPayload.request_id, 'req-tenant-role-list-1');
  assert.equal(listPayload.tenant_id, 'tenant-a');
  assert.ok(Array.isArray(listPayload.roles));
  const role = listPayload.roles.find((item) => item.role_id === 'tenant_a_ops_admin');
  assert.ok(role);
  assert.equal(role.tenant_id, 'tenant-a');
  assert.equal(role.code, 'OPS_ADMIN');
});

test('POST /tenant/roles auto-generates role_id when omitted and does not reuse code', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-create-auto-role-id',
    TENANT_OPERATOR_A_PHONE
  );

  const createRoute = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-auto-role-id',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      code: 'TENANT_AUTO_GENERATED_ROLE',
      name: '租户自动生成角色ID',
      status: 'active'
    },
    handlers: harness.handlers
  });

  assert.equal(createRoute.status, 200);
  const createPayload = JSON.parse(createRoute.body);
  assert.ok(typeof createPayload.role_id === 'string' && createPayload.role_id.length > 0);
  assert.match(createPayload.role_id, /^[a-z0-9][a-z0-9._-]{0,63}$/);
  assert.notEqual(createPayload.role_id, 'tenant_auto_generated_role');
  assert.equal(createPayload.code, 'TENANT_AUTO_GENERATED_ROLE');
  assert.equal(createPayload.name, '租户自动生成角色ID');
  assert.equal(createPayload.status, 'active');
});

test('POST /tenant/roles persists tenant audit event with request_id and traceparent', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-audit',
    TENANT_OPERATOR_A_PHONE
  );
  const traceparent = '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01';

  const createRoute = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-audit',
    headers: {
      authorization: `Bearer ${login.access_token}`,
      traceparent
    },
    body: {
      role_id: 'tenant_a_role_audit_trace',
      code: 'TENANT_ROLE_AUDIT_TRACE',
      name: '租户角色审计透传验证',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRoute.status, 200);

  const auditRoute = await dispatchApiRoute({
    pathname: '/tenant/audit/events?request_id=req-tenant-role-create-audit&event_type=auth.role.catalog.created',
    method: 'GET',
    requestId: 'req-tenant-role-audit-query',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers: harness.handlers
  });
  assert.equal(auditRoute.status, 200);
  const auditPayload = JSON.parse(auditRoute.body);
  assert.equal(auditPayload.total, 1);
  assert.equal(auditPayload.events[0].event_type, 'auth.role.catalog.created');
  assert.equal(auditPayload.events[0].request_id, 'req-tenant-role-create-audit');
  assert.equal(auditPayload.events[0].traceparent, traceparent);
  assert.equal(auditPayload.events[0].tenant_id, 'tenant-a');
});

test('GET /tenant/roles accepts snake_case catalog fields when camelCase shadow keys are undefined', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-shadow-fallback',
    TENANT_OPERATOR_A_PHONE
  );
  const now = new Date().toISOString();
  harness.authService.listPlatformRoleCatalogEntries = async () => ([
    {
      roleId: undefined,
      role_id: 'tenant_role_shadow_fallback',
      tenantId: undefined,
      tenant_id: 'tenant-a',
      code: 'ROLE_SHADOW_FALLBACK',
      name: '影子字段回退角色',
      status: 'active',
      scope: 'tenant',
      isSystem: false,
      createdAt: undefined,
      created_at: now,
      updatedAt: undefined,
      updated_at: now
    }
  ]);

  const listRoute = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'GET',
    requestId: 'req-tenant-role-list-shadow-fallback',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers: harness.handlers
  });

  assert.equal(listRoute.status, 200);
  const payload = JSON.parse(listRoute.body);
  assert.equal(payload.tenant_id, 'tenant-a');
  assert.equal(payload.roles.length, 1);
  assert.equal(payload.roles[0].role_id, 'tenant_role_shadow_fallback');
});

test('GET /tenant/roles fails closed when downstream catalog entry omits status', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-list-missing-status',
    TENANT_OPERATOR_A_PHONE
  );
  const now = new Date().toISOString();
  harness.authService.listPlatformRoleCatalogEntries = async () => ([
    {
      roleId: 'tenant_role_missing_status',
      tenantId: 'tenant-a',
      code: 'ROLE_MISSING_STATUS',
      name: '缺失状态字段角色',
      isSystem: false,
      createdAt: now,
      updatedAt: now
    }
  ]);

  const listRoute = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'GET',
    requestId: 'req-tenant-role-list-missing-status',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers: harness.handlers
  });

  assert.equal(listRoute.status, 503);
  const payload = JSON.parse(listRoute.body);
  assert.equal(payload.error_code, 'TROLE-503-DEPENDENCY-UNAVAILABLE');
});

test('GET /tenant/roles fails closed when downstream catalog entry omits is_system', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-list-missing-is-system',
    TENANT_OPERATOR_A_PHONE
  );
  const now = new Date().toISOString();
  harness.authService.listPlatformRoleCatalogEntries = async () => ([
    {
      roleId: 'tenant_role_missing_is_system',
      tenantId: 'tenant-a',
      code: 'ROLE_MISSING_IS_SYSTEM',
      name: '缺失系统标记字段角色',
      status: 'active',
      createdAt: now,
      updatedAt: now
    }
  ]);

  const listRoute = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'GET',
    requestId: 'req-tenant-role-list-missing-is-system',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers: harness.handlers
  });

  assert.equal(listRoute.status, 503);
  const payload = JSON.parse(listRoute.body);
  assert.equal(payload.error_code, 'TROLE-503-DEPENDENCY-UNAVAILABLE');
});

test('GET /tenant/roles fails closed when downstream catalog entry scope is not tenant', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-list-invalid-scope',
    TENANT_OPERATOR_A_PHONE
  );
  const now = new Date().toISOString();
  harness.authService.listPlatformRoleCatalogEntries = async () => ([
    {
      roleId: 'tenant_role_invalid_scope',
      tenantId: 'tenant-a',
      code: 'ROLE_INVALID_SCOPE',
      name: '非法作用域角色',
      status: 'active',
      scope: 'platform',
      isSystem: false,
      createdAt: now,
      updatedAt: now
    }
  ]);

  const listRoute = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'GET',
    requestId: 'req-tenant-role-list-invalid-scope',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers: harness.handlers
  });

  assert.equal(listRoute.status, 503);
  const payload = JSON.parse(listRoute.body);
  assert.equal(payload.error_code, 'TROLE-503-DEPENDENCY-UNAVAILABLE');
});

test('GET /tenant/roles fails closed when downstream catalog entry role_id contains surrounding whitespace', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-list-roleid-whitespace',
    TENANT_OPERATOR_A_PHONE
  );
  const now = new Date().toISOString();
  harness.authService.listPlatformRoleCatalogEntries = async () => ([
    {
      roleId: ' tenant_role_roleid_whitespace',
      tenantId: 'tenant-a',
      code: 'ROLE_ID_WHITESPACE',
      name: '角色标识前后空白',
      status: 'active',
      scope: 'tenant',
      isSystem: false,
      createdAt: now,
      updatedAt: now
    }
  ]);

  const listRoute = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'GET',
    requestId: 'req-tenant-role-list-roleid-whitespace',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers: harness.handlers
  });

  assert.equal(listRoute.status, 503);
  const payload = JSON.parse(listRoute.body);
  assert.equal(payload.error_code, 'TROLE-503-DEPENDENCY-UNAVAILABLE');
});

test('GET /tenant/roles fails closed when downstream catalog entry code contains control chars', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-list-control-char-code',
    TENANT_OPERATOR_A_PHONE
  );
  const now = new Date().toISOString();
  harness.authService.listPlatformRoleCatalogEntries = async () => ([
    {
      roleId: 'tenant_role_control_char_code',
      tenantId: 'tenant-a',
      code: 'ROLE_CONTROL_\u0007_CHAR',
      name: '控制字符编码角色',
      status: 'active',
      scope: 'tenant',
      isSystem: false,
      createdAt: now,
      updatedAt: now
    }
  ]);

  const listRoute = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'GET',
    requestId: 'req-tenant-role-list-control-char-code',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers: harness.handlers
  });

  assert.equal(listRoute.status, 503);
  const payload = JSON.parse(listRoute.body);
  assert.equal(payload.error_code, 'TROLE-503-DEPENDENCY-UNAVAILABLE');
});

test('POST /tenant/roles rejects case-insensitive duplicate code inside the same tenant', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-code-duplicate',
    TENANT_OPERATOR_A_PHONE
  );
  const headers = {
    authorization: `Bearer ${login.access_token}`
  };

  const first = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-dup-1',
    headers,
    body: {
      role_id: 'tenant_a_finance_admin',
      code: 'FINANCE_ADMIN',
      name: '财务管理员A',
      status: 'active'
    },
    handlers: harness.handlers
  });
  const second = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-dup-2',
    headers,
    body: {
      role_id: 'tenant_a_finance_admin_2',
      code: 'finance_admin',
      name: '财务管理员A-2',
      status: 'active'
    },
    handlers: harness.handlers
  });

  assert.equal(first.status, 200);
  assert.equal(second.status, 409);
  assert.equal(second.headers['content-type'], 'application/problem+json');
  const payload = JSON.parse(second.body);
  assert.equal(payload.error_code, 'TROLE-409-CODE-CONFLICT');
  assert.equal(payload.retryable, false);
});

test('POST /tenant/roles rejects duplicate role_id inside the same tenant', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-role-id-duplicate',
    TENANT_OPERATOR_A_PHONE
  );
  const headers = {
    authorization: `Bearer ${login.access_token}`
  };

  const first = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-role-id-dup-1',
    headers,
    body: {
      role_id: 'tenant_a_same_role_id',
      code: 'TENANT_A_SAME_ROLE_ID_A',
      name: '角色标识冲突-A',
      status: 'active'
    },
    handlers: harness.handlers
  });
  const second = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-role-id-dup-2',
    headers,
    body: {
      role_id: 'tenant_a_same_role_id',
      code: 'TENANT_A_SAME_ROLE_ID_B',
      name: '角色标识冲突-B',
      status: 'active'
    },
    handlers: harness.handlers
  });

  assert.equal(first.status, 200);
  assert.equal(second.status, 409);
  assert.equal(second.headers['content-type'], 'application/problem+json');
  const payload = JSON.parse(second.body);
  assert.equal(payload.error_code, 'TROLE-409-ROLE-ID-CONFLICT');
  assert.equal(payload.retryable, false);
});

test('POST /tenant/roles rejects duplicate role_id across different tenants (shared catalog key guard)', async () => {
  const harness = createHarness();
  const loginA = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-cross-tenant-role-id-a',
    TENANT_OPERATOR_A_PHONE
  );
  const loginB = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-cross-tenant-role-id-b',
    TENANT_OPERATOR_B_PHONE
  );

  const createInTenantA = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-cross-tenant-role-id-a',
    headers: {
      authorization: `Bearer ${loginA.access_token}`
    },
    body: {
      role_id: 'tenant_shared_role_id',
      code: 'TENANT_A_SHARED_ROLE_ID',
      name: '租户A共享 role_id',
      status: 'active'
    },
    handlers: harness.handlers
  });
  const createInTenantB = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-cross-tenant-role-id-b',
    headers: {
      authorization: `Bearer ${loginB.access_token}`
    },
    body: {
      role_id: 'tenant_shared_role_id',
      code: 'TENANT_B_SHARED_ROLE_ID',
      name: '租户B共享 role_id',
      status: 'active'
    },
    handlers: harness.handlers
  });

  assert.equal(createInTenantA.status, 200);
  assert.equal(createInTenantB.status, 409);
  const payload = JSON.parse(createInTenantB.body);
  assert.equal(payload.error_code, 'TROLE-409-ROLE-ID-CONFLICT');
  assert.equal(payload.retryable, false);
});

test('POST /tenant/roles allows same code across different tenants', async () => {
  const harness = createHarness();
  const loginA = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-cross-tenant-a',
    TENANT_OPERATOR_A_PHONE
  );
  const loginB = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-cross-tenant-b',
    TENANT_OPERATOR_B_PHONE
  );

  const createInTenantA = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-cross-tenant-a',
    headers: {
      authorization: `Bearer ${loginA.access_token}`
    },
    body: {
      role_id: 'tenant_a_shared_code',
      code: 'SHARED_ROLE',
      name: '租户A共享编码角色',
      status: 'active'
    },
    handlers: harness.handlers
  });
  const createInTenantB = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-cross-tenant-b',
    headers: {
      authorization: `Bearer ${loginB.access_token}`
    },
    body: {
      role_id: 'tenant_b_shared_code',
      code: 'shared_role',
      name: '租户B共享编码角色',
      status: 'active'
    },
    handlers: harness.handlers
  });

  assert.equal(createInTenantA.status, 200);
  assert.equal(createInTenantB.status, 200);
  assert.equal(JSON.parse(createInTenantA.body).tenant_id, 'tenant-a');
  assert.equal(JSON.parse(createInTenantB.body).tenant_id, 'tenant-b');
});

test('PATCH/DELETE /tenant/roles/:role_id keep tenant isolation and reject cross-tenant mutation', async () => {
  const harness = createHarness();
  const loginA = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-cross-tenant-mutation-a',
    TENANT_OPERATOR_A_PHONE
  );
  const loginB = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-cross-tenant-mutation-b',
    TENANT_OPERATOR_B_PHONE
  );

  const createInTenantB = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-cross-tenant-mutation-b',
    headers: {
      authorization: `Bearer ${loginB.access_token}`
    },
    body: {
      role_id: 'tenant_b_mutation_target',
      code: 'TENANT_B_MUTATION_TARGET',
      name: '租户B变更目标',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createInTenantB.status, 200);

  const patchFromTenantA = await dispatchApiRoute({
    pathname: '/tenant/roles/tenant_b_mutation_target',
    method: 'PATCH',
    requestId: 'req-tenant-role-cross-tenant-patch-forbidden',
    headers: {
      authorization: `Bearer ${loginA.access_token}`
    },
    body: {
      name: '租户A非法改租户B角色'
    },
    handlers: harness.handlers
  });
  assert.equal(patchFromTenantA.status, 404);
  assert.equal(
    JSON.parse(patchFromTenantA.body).error_code,
    'TROLE-404-ROLE-NOT-FOUND'
  );

  const deleteFromTenantA = await dispatchApiRoute({
    pathname: '/tenant/roles/tenant_b_mutation_target',
    method: 'DELETE',
    requestId: 'req-tenant-role-cross-tenant-delete-forbidden',
    headers: {
      authorization: `Bearer ${loginA.access_token}`
    },
    handlers: harness.handlers
  });
  assert.equal(deleteFromTenantA.status, 404);
  assert.equal(
    JSON.parse(deleteFromTenantA.body).error_code,
    'TROLE-404-ROLE-NOT-FOUND'
  );
});

test('POST /tenant/roles fails closed when client payload includes forged tenant_id', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-forged-tenant',
    TENANT_OPERATOR_A_PHONE
  );

  const createRoute = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-forged-tenant',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      tenant_id: 'tenant-b',
      role_id: 'tenant_context_forged',
      code: 'TENANT_CONTEXT_FORGED',
      name: '伪造租户上下文',
      status: 'active'
    },
    handlers: harness.handlers
  });

  assert.equal(createRoute.status, 400);
  assert.equal(
    JSON.parse(createRoute.body).error_code,
    'TROLE-400-INVALID-PAYLOAD'
  );
});

test('POST /tenant/roles rejects forged system role marker is_system=true', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-forged-system-marker',
    TENANT_OPERATOR_A_PHONE
  );

  const createRoute = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-forged-system-marker',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      role_id: 'tenant_a_illegal_system_marker',
      code: 'TENANT_A_ILLEGAL_SYSTEM_MARKER',
      name: '伪造系统角色标记',
      status: 'active',
      is_system: true
    },
    handlers: harness.handlers
  });

  assert.equal(createRoute.status, 400);
  const payload = JSON.parse(createRoute.body);
  assert.equal(payload.error_code, 'TROLE-400-INVALID-PAYLOAD');
});

test('POST /tenant/roles rejects forged system role marker is_system=false', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-forged-system-marker-false',
    TENANT_OPERATOR_A_PHONE
  );

  const createRoute = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-forged-system-marker-false',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      role_id: 'tenant_a_illegal_system_marker_false',
      code: 'TENANT_A_ILLEGAL_SYSTEM_MARKER_FALSE',
      name: '伪造系统角色标记-布尔假',
      status: 'active',
      is_system: false
    },
    handlers: harness.handlers
  });

  assert.equal(createRoute.status, 400);
  const payload = JSON.parse(createRoute.body);
  assert.equal(payload.error_code, 'TROLE-400-INVALID-PAYLOAD');
});

test('PATCH/DELETE /tenant/roles/:role_id reject protected tenant role mutation', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-protected',
    TENANT_OPERATOR_A_PHONE
  );
  const headers = {
    authorization: `Bearer ${login.access_token}`
  };

  const patchRoute = await dispatchApiRoute({
    pathname: '/tenant/roles/tenant_owner',
    method: 'PATCH',
    requestId: 'req-tenant-role-protected-patch',
    headers,
    body: {
      name: '租户负责人(非法修改)'
    },
    handlers: harness.handlers
  });
  assert.equal(patchRoute.status, 403);
  const patchPayload = JSON.parse(patchRoute.body);
  assert.equal(patchPayload.error_code, 'TROLE-403-SYSTEM-ROLE-PROTECTED');
  assert.equal(patchPayload.retryable, false);

  const deleteRoute = await dispatchApiRoute({
    pathname: '/tenant/roles/tenant_owner',
    method: 'DELETE',
    requestId: 'req-tenant-role-protected-delete',
    headers,
    handlers: harness.handlers
  });
  assert.equal(deleteRoute.status, 403);
  const deletePayload = JSON.parse(deleteRoute.body);
  assert.equal(deletePayload.error_code, 'TROLE-403-SYSTEM-ROLE-PROTECTED');
  assert.equal(deletePayload.retryable, false);
});

test('POST /tenant/roles rejects protected tenant role creation by reserved role_id', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-protected-create',
    TENANT_OPERATOR_A_PHONE
  );

  const createRoute = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-protected-create',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      role_id: 'tenant_owner',
      code: 'TENANT_OWNER_RESERVED',
      name: '非法创建受保护角色',
      status: 'active'
    },
    handlers: harness.handlers
  });

  assert.equal(createRoute.status, 403);
  const payload = JSON.parse(createRoute.body);
  assert.equal(payload.error_code, 'TROLE-403-SYSTEM-ROLE-PROTECTED');
  assert.equal(payload.retryable, false);
});

test('POST /tenant/roles fails closed when downstream created role omits timestamps', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-create-missing-timestamp',
    TENANT_OPERATOR_A_PHONE
  );

  harness.authService.createPlatformRoleCatalogEntry = async (payload = {}) => ({
    roleId: payload.roleId,
    tenantId: payload.tenantId,
    code: payload.code,
    name: payload.name,
    status: payload.status,
    scope: payload.scope,
    isSystem: false
  });

  const createRoute = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-missing-timestamp',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      role_id: 'tenant_a_missing_timestamp',
      code: 'TENANT_A_MISSING_TIMESTAMP',
      name: '缺失时间戳下游返回',
      status: 'active'
    },
    handlers: harness.handlers
  });

  assert.equal(createRoute.status, 503);
  const payload = JSON.parse(createRoute.body);
  assert.equal(payload.error_code, 'TROLE-503-DEPENDENCY-UNAVAILABLE');
});

test('POST /tenant/roles fails closed when downstream created role mismatches requested role_id', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-create-mismatch-role-id',
    TENANT_OPERATOR_A_PHONE
  );
  const originalCreate = harness.authService.createPlatformRoleCatalogEntry.bind(
    harness.authService
  );
  harness.authService.createPlatformRoleCatalogEntry = async (payload = {}) => {
    await originalCreate(payload);
    return originalCreate({
      roleId: 'tenant_a_create_mismatch_actual',
      code: 'TENANT_A_CREATE_MISMATCH_ACTUAL',
      name: '创建返回错配角色',
      status: payload.status,
      scope: payload.scope,
      tenantId: payload.tenantId,
      isSystem: false,
      operatorUserId: payload.operatorUserId,
      operatorSessionId: payload.operatorSessionId
    });
  };

  const createRoute = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-mismatch-role-id',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      role_id: 'tenant_a_create_mismatch_expected',
      code: 'TENANT_A_CREATE_MISMATCH_EXPECTED',
      name: '创建返回错配目标角色',
      status: 'active'
    },
    handlers: harness.handlers
  });

  assert.equal(createRoute.status, 503);
  const payload = JSON.parse(createRoute.body);
  assert.equal(payload.error_code, 'TROLE-503-DEPENDENCY-UNAVAILABLE');
});

test('POST /tenant/roles fails closed when downstream created role tenant_id contains surrounding whitespace', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-create-tenantid-whitespace',
    TENANT_OPERATOR_A_PHONE
  );
  const now = new Date().toISOString();
  harness.authService.createPlatformRoleCatalogEntry = async (payload = {}) => ({
    roleId: payload.roleId,
    tenantId: ` ${payload.tenantId}`,
    code: payload.code,
    name: payload.name,
    status: payload.status,
    scope: payload.scope,
    isSystem: false,
    createdAt: now,
    updatedAt: now
  });

  const createRoute = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-tenantid-whitespace',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      role_id: 'tenant_a_create_tenantid_whitespace',
      code: 'TENANT_A_CREATE_TENANTID_WHITESPACE',
      name: '创建返回租户标识前后空白',
      status: 'active'
    },
    handlers: harness.handlers
  });

  assert.equal(createRoute.status, 503);
  const payload = JSON.parse(createRoute.body);
  assert.equal(payload.error_code, 'TROLE-503-DEPENDENCY-UNAVAILABLE');
});

test('POST /tenant/roles fails closed when downstream created role returns control-char code', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-create-control-char-code',
    TENANT_OPERATOR_A_PHONE
  );
  const now = new Date().toISOString();
  harness.authService.createPlatformRoleCatalogEntry = async (payload = {}) => ({
    roleId: payload.roleId,
    tenantId: payload.tenantId,
    code: 'CREATE_\u0007_CONTROL_CHAR',
    name: payload.name,
    status: payload.status,
    scope: payload.scope,
    isSystem: false,
    createdAt: now,
    updatedAt: now
  });

  const createRoute = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-control-char-code',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      role_id: 'tenant_a_create_control_char_code',
      code: 'TENANT_A_CREATE_CONTROL_CHAR_CODE',
      name: '创建返回控制字符编码',
      status: 'active'
    },
    handlers: harness.handlers
  });

  assert.equal(createRoute.status, 503);
  const payload = JSON.parse(createRoute.body);
  assert.equal(payload.error_code, 'TROLE-503-DEPENDENCY-UNAVAILABLE');
});

test('POST /tenant/roles fails closed when downstream created role is marked is_system=true', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-create-downstream-system-role',
    TENANT_OPERATOR_A_PHONE
  );
  const now = new Date().toISOString();
  harness.authService.createPlatformRoleCatalogEntry = async (payload = {}) => ({
    roleId: payload.roleId,
    tenantId: payload.tenantId,
    code: payload.code,
    name: payload.name,
    status: payload.status,
    scope: payload.scope,
    isSystem: true,
    createdAt: now,
    updatedAt: now
  });

  const createRoute = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-downstream-system-role',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      role_id: 'tenant_a_create_downstream_system_role',
      code: 'TENANT_A_CREATE_DOWNSTREAM_SYSTEM_ROLE',
      name: '下游错误回传系统角色',
      status: 'active'
    },
    handlers: harness.handlers
  });

  assert.equal(createRoute.status, 503);
  const payload = JSON.parse(createRoute.body);
  assert.equal(payload.error_code, 'TROLE-503-DEPENDENCY-UNAVAILABLE');
});

test('PATCH /tenant/roles/:role_id rejects is_system role even when role_id is outside protected constant list', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-protected-by-is-system',
    TENANT_OPERATOR_A_PHONE
  );
  await harness.authService.createPlatformRoleCatalogEntry({
    roleId: 'tenant_a_custom_system_role',
    code: 'TENANT_A_CUSTOM_SYSTEM_ROLE',
    name: '租户A自定义系统角色',
    status: 'active',
    scope: 'tenant',
    tenantId: 'tenant-a',
    isSystem: true,
    operatorUserId: 'seed-user',
    operatorSessionId: 'seed-session'
  });

  const patchRoute = await dispatchApiRoute({
    pathname: '/tenant/roles/tenant_a_custom_system_role',
    method: 'PATCH',
    requestId: 'req-tenant-role-protected-by-is-system-patch',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      name: '非法修改系统角色'
    },
    handlers: harness.handlers
  });

  assert.equal(patchRoute.status, 403);
  const payload = JSON.parse(patchRoute.body);
  assert.equal(payload.error_code, 'TROLE-403-SYSTEM-ROLE-PROTECTED');
  assert.equal(payload.retryable, false);
});

test('PATCH /tenant/roles/:role_id fails closed when downstream update returns mismatched role identity', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-update-mismatch',
    TENANT_OPERATOR_A_PHONE
  );
  const headers = {
    authorization: `Bearer ${login.access_token}`
  };
  const createA = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-update-mismatch-a',
    headers,
    body: {
      role_id: 'tenant_a_update_mismatch_a',
      code: 'TENANT_A_UPDATE_MISMATCH_A',
      name: '更新错配A',
      status: 'active'
    },
    handlers: harness.handlers
  });
  const createB = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-update-mismatch-b',
    headers,
    body: {
      role_id: 'tenant_a_update_mismatch_b',
      code: 'TENANT_A_UPDATE_MISMATCH_B',
      name: '更新错配B',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createA.status, 200);
  assert.equal(createB.status, 200);

  const originalUpdate = harness.authService.updatePlatformRoleCatalogEntry.bind(
    harness.authService
  );
  harness.authService.updatePlatformRoleCatalogEntry = async (payload = {}) => {
    if (String(payload.roleId || '').trim() === 'tenant_a_update_mismatch_a') {
      return harness.authService.findPlatformRoleCatalogEntryByRoleId({
        roleId: 'tenant_a_update_mismatch_b',
        scope: 'tenant',
        tenantId: 'tenant-a'
      });
    }
    return originalUpdate(payload);
  };

  const patchRoute = await dispatchApiRoute({
    pathname: '/tenant/roles/tenant_a_update_mismatch_a',
    method: 'PATCH',
    requestId: 'req-tenant-role-update-mismatch',
    headers,
    body: {
      name: '非法错配更新'
    },
    handlers: harness.handlers
  });

  assert.equal(patchRoute.status, 503);
  const payload = JSON.parse(patchRoute.body);
  assert.equal(payload.error_code, 'TROLE-503-DEPENDENCY-UNAVAILABLE');
});

test('PATCH /tenant/roles/:role_id fails closed when downstream update result is marked is_system=true', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-update-downstream-system-role',
    TENANT_OPERATOR_A_PHONE
  );
  const headers = {
    authorization: `Bearer ${login.access_token}`
  };
  const createRoute = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-update-downstream-system-role',
    headers,
    body: {
      role_id: 'tenant_a_update_downstream_system_role',
      code: 'TENANT_A_UPDATE_DOWNSTREAM_SYSTEM_ROLE',
      name: '更新下游系统角色结果',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRoute.status, 200);

  const originalUpdate = harness.authService.updatePlatformRoleCatalogEntry.bind(
    harness.authService
  );
  harness.authService.updatePlatformRoleCatalogEntry = async (payload = {}) => {
    const updated = await originalUpdate(payload);
    if (!updated) {
      return updated;
    }
    return {
      ...updated,
      isSystem: true,
      updatedAt: new Date().toISOString()
    };
  };

  const patchRoute = await dispatchApiRoute({
    pathname: '/tenant/roles/tenant_a_update_downstream_system_role',
    method: 'PATCH',
    requestId: 'req-tenant-role-update-downstream-system-role',
    headers,
    body: {
      name: '非法下游系统角色回传'
    },
    handlers: harness.handlers
  });

  assert.equal(patchRoute.status, 503);
  const payload = JSON.parse(patchRoute.body);
  assert.equal(payload.error_code, 'TROLE-503-DEPENDENCY-UNAVAILABLE');
});

test('PATCH /tenant/roles/:role_id fails closed when downstream lookup scope is not tenant', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-update-invalid-scope',
    TENANT_OPERATOR_A_PHONE
  );
  const headers = {
    authorization: `Bearer ${login.access_token}`
  };
  const createRoute = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-update-invalid-scope',
    headers,
    body: {
      role_id: 'tenant_a_update_invalid_scope',
      code: 'TENANT_A_UPDATE_INVALID_SCOPE',
      name: '更新作用域错配目标',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRoute.status, 200);

  const originalFindByRoleId = harness.authService.findPlatformRoleCatalogEntryByRoleId.bind(
    harness.authService
  );
  harness.authService.findPlatformRoleCatalogEntryByRoleId = async (payload = {}) => {
    const found = await originalFindByRoleId(payload);
    if (!found) {
      return found;
    }
    if (String(payload.roleId || '').trim() !== 'tenant_a_update_invalid_scope') {
      return found;
    }
    return {
      ...found,
      scope: 'platform'
    };
  };

  const patchRoute = await dispatchApiRoute({
    pathname: '/tenant/roles/tenant_a_update_invalid_scope',
    method: 'PATCH',
    requestId: 'req-tenant-role-update-invalid-scope',
    headers,
    body: {
      name: '非法作用域更新'
    },
    handlers: harness.handlers
  });

  assert.equal(patchRoute.status, 503);
  const payload = JSON.parse(patchRoute.body);
  assert.equal(payload.error_code, 'TROLE-503-DEPENDENCY-UNAVAILABLE');
});

test('PATCH /tenant/roles/:role_id fails closed when downstream lookup status contains surrounding whitespace', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-update-status-whitespace',
    TENANT_OPERATOR_A_PHONE
  );
  const headers = {
    authorization: `Bearer ${login.access_token}`
  };
  const createRoute = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-update-status-whitespace',
    headers,
    body: {
      role_id: 'tenant_a_update_status_whitespace',
      code: 'TENANT_A_UPDATE_STATUS_WHITESPACE',
      name: '更新状态空白目标',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRoute.status, 200);

  const originalFindByRoleId = harness.authService.findPlatformRoleCatalogEntryByRoleId.bind(
    harness.authService
  );
  harness.authService.findPlatformRoleCatalogEntryByRoleId = async (payload = {}) => {
    const found = await originalFindByRoleId(payload);
    if (!found) {
      return found;
    }
    if (String(payload.roleId || '').trim() !== 'tenant_a_update_status_whitespace') {
      return found;
    }
    return {
      ...found,
      status: ' active'
    };
  };

  const patchRoute = await dispatchApiRoute({
    pathname: '/tenant/roles/tenant_a_update_status_whitespace',
    method: 'PATCH',
    requestId: 'req-tenant-role-update-status-whitespace',
    headers,
    body: {
      name: '非法状态空白更新'
    },
    handlers: harness.handlers
  });

  assert.equal(patchRoute.status, 503);
  const payload = JSON.parse(patchRoute.body);
  assert.equal(payload.error_code, 'TROLE-503-DEPENDENCY-UNAVAILABLE');
});

test('POST /tenant/roles rejects malformed active_tenant_id from authorization context', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-invalid-tenant-context',
    TENANT_OPERATOR_A_PHONE
  );
  const originalAuthorizeRoute = harness.handlers.authorizeRoute.bind(harness.handlers);
  harness.handlers.authorizeRoute = async (payload = {}) => {
    const authorized = await originalAuthorizeRoute(payload);
    const activeTenantId = String(
      authorized?.active_tenant_id
      || authorized?.activeTenantId
      || authorized?.session_context?.active_tenant_id
      || 'tenant-a'
    ).trim() || 'tenant-a';
    return {
      ...(authorized || {}),
      active_tenant_id: `${activeTenantId}\u0007`
    };
  };

  const createRoute = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-invalid-tenant-context',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      role_id: 'tenant_a_invalid_tenant_context',
      code: 'TENANT_A_INVALID_TENANT_CONTEXT',
      name: '非法租户上下文',
      status: 'active'
    },
    handlers: harness.handlers
  });

  assert.equal(createRoute.status, 403);
  assert.equal(
    JSON.parse(createRoute.body).error_code,
    'AUTH-403-NO-DOMAIN'
  );
});

test('POST /tenant/roles rejects preauthorized context with unresolved operator identifiers', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-unknown-operator-create',
    TENANT_OPERATOR_A_PHONE
  );
  harness.handlers.authorizeRoute = async () => ({
    user_id: 'unknown',
    session_id: 'unknown',
    active_tenant_id: 'tenant-a',
    entry_domain: 'tenant'
  });

  const createRoute = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-unknown-operator',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      role_id: 'tenant_a_unknown_operator_create',
      code: 'TENANT_A_UNKNOWN_OPERATOR_CREATE',
      name: '未知操作者创建',
      status: 'active'
    },
    handlers: harness.handlers
  });

  assert.equal(createRoute.status, 403);
  assert.equal(
    JSON.parse(createRoute.body).error_code,
    'AUTH-403-FORBIDDEN'
  );
});

test('PATCH /tenant/roles/:role_id rejects preauthorized context with unresolved operator identifiers', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-unknown-operator-patch',
    TENANT_OPERATOR_A_PHONE
  );
  const headers = {
    authorization: `Bearer ${login.access_token}`
  };

  const createRoute = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-for-unknown-operator-patch',
    headers,
    body: {
      role_id: 'tenant_a_unknown_operator_patch',
      code: 'TENANT_A_UNKNOWN_OPERATOR_PATCH',
      name: '未知操作者更新',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRoute.status, 200);

  harness.handlers.authorizeRoute = async () => ({
    user_id: 'unknown',
    session_id: 'unknown',
    active_tenant_id: 'tenant-a',
    entry_domain: 'tenant'
  });

  const patchRoute = await dispatchApiRoute({
    pathname: '/tenant/roles/tenant_a_unknown_operator_patch',
    method: 'PATCH',
    requestId: 'req-tenant-role-patch-unknown-operator',
    headers,
    body: {
      name: '未知操作者更新-非法'
    },
    handlers: harness.handlers
  });

  assert.equal(patchRoute.status, 403);
  assert.equal(
    JSON.parse(patchRoute.body).error_code,
    'AUTH-403-FORBIDDEN'
  );
});

test('DELETE /tenant/roles/:role_id rejects preauthorized context with unresolved operator identifiers', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-unknown-operator-delete',
    TENANT_OPERATOR_A_PHONE
  );
  const headers = {
    authorization: `Bearer ${login.access_token}`
  };

  const createRoute = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-for-unknown-operator-delete',
    headers,
    body: {
      role_id: 'tenant_a_unknown_operator_delete',
      code: 'TENANT_A_UNKNOWN_OPERATOR_DELETE',
      name: '未知操作者删除',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRoute.status, 200);

  harness.handlers.authorizeRoute = async () => ({
    user_id: 'unknown',
    session_id: 'unknown',
    active_tenant_id: 'tenant-a',
    entry_domain: 'tenant'
  });

  const deleteRoute = await dispatchApiRoute({
    pathname: '/tenant/roles/tenant_a_unknown_operator_delete',
    method: 'DELETE',
    requestId: 'req-tenant-role-delete-unknown-operator',
    headers,
    handlers: harness.handlers
  });

  assert.equal(deleteRoute.status, 403);
  assert.equal(
    JSON.parse(deleteRoute.body).error_code,
    'AUTH-403-FORBIDDEN'
  );
});

test('DELETE /tenant/roles/:role_id fails closed when downstream delete result is not target disabled role', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-delete-mismatch',
    TENANT_OPERATOR_A_PHONE
  );
  const headers = {
    authorization: `Bearer ${login.access_token}`
  };
  const createA = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-delete-mismatch-a',
    headers,
    body: {
      role_id: 'tenant_a_delete_mismatch_a',
      code: 'TENANT_A_DELETE_MISMATCH_A',
      name: '删除错配A',
      status: 'active'
    },
    handlers: harness.handlers
  });
  const createB = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-delete-mismatch-b',
    headers,
    body: {
      role_id: 'tenant_a_delete_mismatch_b',
      code: 'TENANT_A_DELETE_MISMATCH_B',
      name: '删除错配B',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createA.status, 200);
  assert.equal(createB.status, 200);

  const originalDelete = harness.authService.deletePlatformRoleCatalogEntry.bind(
    harness.authService
  );
  harness.authService.deletePlatformRoleCatalogEntry = async (payload = {}) => {
    if (String(payload.roleId || '').trim() === 'tenant_a_delete_mismatch_a') {
      return harness.authService.findPlatformRoleCatalogEntryByRoleId({
        roleId: 'tenant_a_delete_mismatch_b',
        scope: 'tenant',
        tenantId: 'tenant-a'
      });
    }
    return originalDelete(payload);
  };

  const deleteRoute = await dispatchApiRoute({
    pathname: '/tenant/roles/tenant_a_delete_mismatch_a',
    method: 'DELETE',
    requestId: 'req-tenant-role-delete-mismatch',
    headers,
    handlers: harness.handlers
  });

  assert.equal(deleteRoute.status, 503);
  const payload = JSON.parse(deleteRoute.body);
  assert.equal(payload.error_code, 'TROLE-503-DEPENDENCY-UNAVAILABLE');
});

test('DELETE /tenant/roles/:role_id fails closed when downstream delete result is marked is_system=true', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-delete-downstream-system-role',
    TENANT_OPERATOR_A_PHONE
  );
  const headers = {
    authorization: `Bearer ${login.access_token}`
  };
  const createRoute = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-delete-downstream-system-role',
    headers,
    body: {
      role_id: 'tenant_a_delete_downstream_system_role',
      code: 'TENANT_A_DELETE_DOWNSTREAM_SYSTEM_ROLE',
      name: '删除下游系统角色结果',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRoute.status, 200);

  const originalDelete = harness.authService.deletePlatformRoleCatalogEntry.bind(
    harness.authService
  );
  harness.authService.deletePlatformRoleCatalogEntry = async (payload = {}) => {
    const deleted = await originalDelete(payload);
    if (!deleted) {
      return deleted;
    }
    return {
      ...deleted,
      isSystem: true,
      status: 'disabled',
      updatedAt: new Date().toISOString()
    };
  };

  const deleteRoute = await dispatchApiRoute({
    pathname: '/tenant/roles/tenant_a_delete_downstream_system_role',
    method: 'DELETE',
    requestId: 'req-tenant-role-delete-downstream-system-role',
    headers,
    handlers: harness.handlers
  });

  assert.equal(deleteRoute.status, 503);
  const payload = JSON.parse(deleteRoute.body);
  assert.equal(payload.error_code, 'TROLE-503-DEPENDENCY-UNAVAILABLE');
});

test('DELETE /tenant/roles/:role_id rejects disabled role deletion precondition', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-delete-disabled',
    TENANT_OPERATOR_A_PHONE
  );
  const headers = {
    authorization: `Bearer ${login.access_token}`
  };

  const createRoute = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-disabled-for-delete',
    headers,
    body: {
      role_id: 'tenant_a_disabled_for_delete',
      code: 'DISABLED_FOR_DELETE',
      name: '禁用删除前置校验',
      status: 'disabled'
    },
    handlers: harness.handlers
  });
  assert.equal(createRoute.status, 200);

  const deleteRoute = await dispatchApiRoute({
    pathname: '/tenant/roles/tenant_a_disabled_for_delete',
    method: 'DELETE',
    requestId: 'req-tenant-role-delete-disabled',
    headers,
    handlers: harness.handlers
  });
  assert.equal(deleteRoute.status, 409);
  const payload = JSON.parse(deleteRoute.body);
  assert.equal(payload.error_code, 'TROLE-409-DELETE-CONDITION-NOT-MET');
  assert.equal(payload.retryable, false);
});

test('PATCH /tenant/roles/:role_id disabling role converges affected sessions and denies protected access immediately', async () => {
  const harness = createHarness();
  const operatorLogin = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-disable-operator',
    TENANT_OPERATOR_A_PHONE
  );
  const operatorHeaders = {
    authorization: `Bearer ${operatorLogin.access_token}`
  };

  const createRole = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-disable-target',
    headers: operatorHeaders,
    body: {
      role_id: 'tenant_a_scope_disable_role',
      code: 'TENANT_A_SCOPE_DISABLE_ROLE',
      name: '租户角色禁用即时收敛验证',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRole.status, 200);

  const replacePermission = await dispatchApiRoute({
    pathname: '/tenant/roles/tenant_a_scope_disable_role/permissions',
    method: 'PUT',
    requestId: 'req-tenant-role-disable-permission-replace-1',
    headers: operatorHeaders,
    body: {
      permission_codes: ['tenant.role_management.operate']
    },
    handlers: harness.handlers
  });
  assert.equal(replacePermission.status, 200);

  const targetMembershipId = await resolveMembershipIdByUserAndTenant({
    authService: harness.authService,
    requestId: 'req-tenant-role-disable-target-membership-resolve',
    operatorUserId: 'tenant-role-operator-a',
    targetUserId: 'tenant-role-operator-a',
    tenantId: 'tenant-a'
  });

  const replaceRoleBindings = await dispatchApiRoute({
    pathname: `/tenant/users/${targetMembershipId}/roles`,
    method: 'PUT',
    requestId: 'req-tenant-role-disable-bindings-replace',
    headers: operatorHeaders,
    body: {
      role_ids: ['tenant_a_scope_disable_role']
    },
    handlers: harness.handlers
  });
  assert.equal(replaceRoleBindings.status, 200);

  const targetLogin = await loginByPhone(
    harness.authService,
    'req-tenant-role-disable-login-target',
    TENANT_OPERATOR_A_PHONE
  );
  const targetProbeAllowed = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'GET',
    requestId: 'req-tenant-role-disable-probe-allowed',
    headers: {
      authorization: `Bearer ${targetLogin.access_token}`
    },
    handlers: harness.handlers
  });
  assert.equal(targetProbeAllowed.status, 200);

  const disableRole = await dispatchApiRoute({
    pathname: '/tenant/roles/tenant_a_scope_disable_role',
    method: 'PATCH',
    requestId: 'req-tenant-role-disable-status-patch',
    headers: {
      authorization: `Bearer ${targetLogin.access_token}`
    },
    body: {
      status: 'disabled'
    },
    handlers: harness.handlers
  });
  assert.equal(disableRole.status, 200);
  assert.equal(JSON.parse(disableRole.body).status, 'disabled');

  const probeWithOldToken = await dispatchApiRoute({
    pathname: '/auth/tenant/user-management/probe',
    method: 'GET',
    requestId: 'req-tenant-role-disable-probe-old-token',
    headers: {
      authorization: `Bearer ${targetLogin.access_token}`
    },
    handlers: harness.handlers
  });
  assert.equal(probeWithOldToken.status, 401);
  assert.equal(JSON.parse(probeWithOldToken.body).error_code, 'AUTH-401-INVALID-ACCESS');

  const targetRelogin = await loginByPhone(
    harness.authService,
    'req-tenant-role-disable-login-target-relogin',
    TENANT_OPERATOR_A_PHONE
  );
  const targetProbeDenied = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'GET',
    requestId: 'req-tenant-role-disable-probe-denied',
    headers: {
      authorization: `Bearer ${targetRelogin.access_token}`
    },
    handlers: harness.handlers
  });
  assert.equal(targetProbeDenied.status, 403);
  assert.equal(JSON.parse(targetProbeDenied.body).error_code, 'AUTH-403-FORBIDDEN');

  const roleBindings = await harness.authService._internals.authStore.listTenantUsershipRoleBindings({
    membershipId: targetMembershipId,
    tenantId: 'tenant-a'
  });
  assert.ok(Array.isArray(roleBindings));
  assert.ok(roleBindings.includes('tenant_a_scope_disable_role'));
});

test('PATCH/DELETE /tenant/roles/:role_id decode URL-encoded path params before service lookup', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-url-encoded',
    TENANT_OPERATOR_A_PHONE
  );
  const headers = {
    authorization: `Bearer ${login.access_token}`
  };

  const createRoute = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-url-encoded',
    headers,
    body: {
      role_id: 'tenant.role.encoded',
      code: 'TENANT_ROLE_ENCODED',
      name: '租户编码路径参数角色',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRoute.status, 200);

  const encodedPath = '/tenant/roles/tenant%2Erole%2Eencoded';
  const patchRoute = await dispatchApiRoute({
    pathname: encodedPath,
    method: 'PATCH',
    requestId: 'req-tenant-role-patch-url-encoded',
    headers,
    body: {
      name: '租户编码路径参数角色-更新'
    },
    handlers: harness.handlers
  });
  assert.equal(patchRoute.status, 200);
  assert.equal(JSON.parse(patchRoute.body).role_id, 'tenant.role.encoded');

  const deleteRoute = await dispatchApiRoute({
    pathname: encodedPath,
    method: 'DELETE',
    requestId: 'req-tenant-role-delete-url-encoded',
    headers,
    handlers: harness.handlers
  });
  assert.equal(deleteRoute.status, 200);
  assert.equal(JSON.parse(deleteRoute.body).role_id, 'tenant.role.encoded');
});

test('PATCH /tenant/roles/:role_id enforces idempotency across canonicalized role_id path variants', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-idem-canonicalized',
    TENANT_OPERATOR_A_PHONE
  );
  const headers = {
    authorization: `Bearer ${login.access_token}`
  };

  const createRoute = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-idem-canonicalized',
    headers,
    body: {
      role_id: 'tenant_idem_target',
      code: 'TENANT_IDEM_TARGET',
      name: '租户幂等规范化目标角色',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRoute.status, 200);

  const firstPatch = await dispatchApiRoute({
    pathname: '/tenant/roles/Tenant_Idem_Target',
    method: 'PATCH',
    requestId: 'req-tenant-role-patch-idem-canonicalized-1',
    headers: {
      ...headers,
      'idempotency-key': 'idem-tenant-role-canonicalized-path'
    },
    body: {
      name: '版本A'
    },
    handlers: harness.handlers
  });
  assert.equal(firstPatch.status, 200);

  const secondPatch = await dispatchApiRoute({
    pathname: '/tenant/roles/TENANT_IDEM_TARGET',
    method: 'PATCH',
    requestId: 'req-tenant-role-patch-idem-canonicalized-2',
    headers: {
      ...headers,
      'idempotency-key': 'idem-tenant-role-canonicalized-path'
    },
    body: {
      name: '版本B'
    },
    handlers: harness.handlers
  });
  assert.equal(secondPatch.status, 409);
  assert.equal(
    JSON.parse(secondPatch.body).error_code,
    'AUTH-409-IDEMPOTENCY-CONFLICT'
  );
});

test('PATCH /tenant/roles/:role_id does not cache retryable 409 responses under idempotency key', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-idem-retryable-conflict',
    TENANT_OPERATOR_A_PHONE
  );
  let updateCalls = 0;
  harness.handlers.tenantUpdateRole = async () => {
    updateCalls += 1;
    throw new AuthProblemError({
      status: 409,
      title: 'Conflict',
      detail: '可重试冲突',
      errorCode: 'TROLE-409-RETRYABLE-CONFLICT',
      extensions: {
        retryable: true
      }
    });
  };

  const request = (requestId) =>
    dispatchApiRoute({
      pathname: '/tenant/roles/tenant_idem_retryable_conflict',
      method: 'PATCH',
      requestId,
      headers: {
        authorization: `Bearer ${login.access_token}`,
        'idempotency-key': 'idem-tenant-role-retryable-conflict'
      },
      body: {
        name: '可重试冲突'
      },
      handlers: harness.handlers
    });

  const firstPatch = await request('req-tenant-role-patch-idem-retryable-conflict-1');
  const secondPatch = await request('req-tenant-role-patch-idem-retryable-conflict-2');

  assert.equal(firstPatch.status, 409);
  assert.equal(secondPatch.status, 409);
  assert.equal(updateCalls, 2);
  assert.equal(
    JSON.parse(secondPatch.body).error_code,
    'TROLE-409-RETRYABLE-CONFLICT'
  );
});

test('PATCH /tenant/roles/:role_id caches non-retryable 409 responses under idempotency key', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-idem-non-retryable-conflict',
    TENANT_OPERATOR_A_PHONE
  );
  let updateCalls = 0;
  harness.handlers.tenantUpdateRole = async () => {
    updateCalls += 1;
    throw new AuthProblemError({
      status: 409,
      title: 'Conflict',
      detail: '不可重试冲突',
      errorCode: 'TROLE-409-NON-RETRYABLE-CONFLICT',
      extensions: {
        retryable: false
      }
    });
  };

  const request = (requestId) =>
    dispatchApiRoute({
      pathname: '/tenant/roles/tenant_idem_non_retryable_conflict',
      method: 'PATCH',
      requestId,
      headers: {
        authorization: `Bearer ${login.access_token}`,
        'idempotency-key': 'idem-tenant-role-non-retryable-conflict'
      },
      body: {
        name: '不可重试冲突'
      },
      handlers: harness.handlers
    });

  const firstPatch = await request('req-tenant-role-patch-idem-non-retryable-conflict-1');
  const secondPatch = await request('req-tenant-role-patch-idem-non-retryable-conflict-2');

  assert.equal(firstPatch.status, 409);
  assert.equal(secondPatch.status, 409);
  assert.equal(updateCalls, 1);
  assert.equal(
    JSON.parse(secondPatch.body).error_code,
    'TROLE-409-NON-RETRYABLE-CONFLICT'
  );
});

test('DELETE /tenant/roles/:role_id keeps idempotency scope isolated by route params', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-idem-isolated',
    TENANT_OPERATOR_A_PHONE
  );
  const headers = {
    authorization: `Bearer ${login.access_token}`
  };

  const createA = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-idem-isolated-a',
    headers,
    body: {
      role_id: 'tenant_idem_isolated_a',
      code: 'TENANT_IDEM_ISOLATED_A',
      name: '租户幂等隔离A',
      status: 'active'
    },
    handlers: harness.handlers
  });
  const createB = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-idem-isolated-b',
    headers,
    body: {
      role_id: 'tenant_idem_isolated_b',
      code: 'TENANT_IDEM_ISOLATED_B',
      name: '租户幂等隔离B',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createA.status, 200);
  assert.equal(createB.status, 200);

  const deleteA = await dispatchApiRoute({
    pathname: '/tenant/roles/tenant_idem_isolated_a',
    method: 'DELETE',
    requestId: 'req-tenant-role-delete-idem-isolated-a',
    headers: {
      ...headers,
      'idempotency-key': 'idem-tenant-role-delete-isolated'
    },
    handlers: harness.handlers
  });
  const deleteB = await dispatchApiRoute({
    pathname: '/tenant/roles/tenant_idem_isolated_b',
    method: 'DELETE',
    requestId: 'req-tenant-role-delete-idem-isolated-b',
    headers: {
      ...headers,
      'idempotency-key': 'idem-tenant-role-delete-isolated'
    },
    handlers: harness.handlers
  });

  assert.equal(deleteA.status, 200);
  assert.equal(deleteB.status, 200);
  assert.equal(JSON.parse(deleteA.body).role_id, 'tenant_idem_isolated_a');
  assert.equal(JSON.parse(deleteB.body).role_id, 'tenant_idem_isolated_b');
});

test('GET/PUT /tenant/roles/:role_id/permissions manages tenant role permission grants', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-permission-read-write',
    TENANT_OPERATOR_A_PHONE
  );
  const headers = {
    authorization: `Bearer ${login.access_token}`
  };

  const createRoute = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-permission-target',
    headers,
    body: {
      role_id: 'tenant_permission_target',
      code: 'TENANT_PERMISSION_TARGET',
      name: '租户权限授予目标角色',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRoute.status, 200);

  const readBefore = await dispatchApiRoute({
    pathname: '/tenant/roles/tenant_permission_target/permissions',
    method: 'GET',
    requestId: 'req-tenant-role-permission-read-before',
    headers,
    handlers: harness.handlers
  });
  assert.equal(readBefore.status, 200);
  const readBeforePayload = JSON.parse(readBefore.body);
  assert.equal(readBeforePayload.role_id, 'tenant_permission_target');
  assert.deepEqual(readBeforePayload.permission_codes, []);
  assert.ok(Array.isArray(readBeforePayload.available_permission_codes));

  const replaceRoute = await dispatchApiRoute({
    pathname: '/tenant/roles/tenant_permission_target/permissions',
    method: 'PUT',
    requestId: 'req-tenant-role-permission-write',
    headers,
    body: {
      permission_codes: ['tenant.user_management.view', 'tenant.role_management.view']
    },
    handlers: harness.handlers
  });
  assert.equal(replaceRoute.status, 200);
  const replacePayload = JSON.parse(replaceRoute.body);
  assert.equal(replacePayload.role_id, 'tenant_permission_target');
  assert.deepEqual(
    [...replacePayload.permission_codes].sort(),
    ['tenant.role_management.view', 'tenant.user_management.view']
  );
  assert.equal(Number.isInteger(replacePayload.affected_user_count), true);
  assert.ok(replacePayload.affected_user_count >= 0);

  const readAfter = await dispatchApiRoute({
    pathname: '/tenant/roles/tenant_permission_target/permissions',
    method: 'GET',
    requestId: 'req-tenant-role-permission-read-after',
    headers,
    handlers: harness.handlers
  });
  assert.equal(readAfter.status, 200);
  const readAfterPayload = JSON.parse(readAfter.body);
  assert.deepEqual(
    [...readAfterPayload.permission_codes].sort(),
    ['tenant.role_management.view', 'tenant.user_management.view']
  );
});

test('GET /tenant/roles/:role_id/permissions keeps tenant isolation and rejects cross-tenant lookup', async () => {
  const harness = createHarness();
  const loginA = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-permission-cross-tenant-a',
    TENANT_OPERATOR_A_PHONE
  );
  const loginB = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-permission-cross-tenant-b',
    TENANT_OPERATOR_B_PHONE
  );

  const createInTenantB = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-permission-cross-tenant-b',
    headers: {
      authorization: `Bearer ${loginB.access_token}`
    },
    body: {
      role_id: 'tenant_b_permission_target',
      code: 'TENANT_B_PERMISSION_TARGET',
      name: '租户B权限目标角色',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createInTenantB.status, 200);

  const readByTenantA = await dispatchApiRoute({
    pathname: '/tenant/roles/tenant_b_permission_target/permissions',
    method: 'GET',
    requestId: 'req-tenant-role-permission-cross-tenant-read',
    headers: {
      authorization: `Bearer ${loginA.access_token}`
    },
    handlers: harness.handlers
  });
  assert.equal(readByTenantA.status, 404);
  assert.equal(
    JSON.parse(readByTenantA.body).error_code,
    'TROLE-404-ROLE-NOT-FOUND'
  );
});

test('PUT /tenant/roles/:role_id/permissions rejects non-tenant permission codes', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-permission-invalid-code',
    TENANT_OPERATOR_A_PHONE
  );
  const headers = {
    authorization: `Bearer ${login.access_token}`
  };

  const createRoute = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-permission-invalid-code',
    headers,
    body: {
      role_id: 'tenant_permission_invalid_code_target',
      code: 'TENANT_PERMISSION_INVALID_CODE_TARGET',
      name: '租户权限码校验目标角色',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRoute.status, 200);

  const replaceRoute = await dispatchApiRoute({
    pathname: '/tenant/roles/tenant_permission_invalid_code_target/permissions',
    method: 'PUT',
    requestId: 'req-tenant-role-permission-invalid-code',
    headers,
    body: {
      permission_codes: ['platform.user_management.view']
    },
    handlers: harness.handlers
  });
  assert.equal(replaceRoute.status, 400);
  assert.equal(
    JSON.parse(replaceRoute.body).error_code,
    'TROLE-400-INVALID-PAYLOAD'
  );
});

test('PUT /tenant/roles/:role_id/permissions rejects permission codes with leading or trailing whitespace', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-permission-whitespace-code',
    TENANT_OPERATOR_A_PHONE
  );
  const headers = {
    authorization: `Bearer ${login.access_token}`
  };

  const createRoute = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-permission-whitespace-code',
    headers,
    body: {
      role_id: 'tenant_permission_whitespace_code_target',
      code: 'TENANT_PERMISSION_WHITESPACE_CODE_TARGET',
      name: '租户权限码空白校验目标角色',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRoute.status, 200);

  const replaceRoute = await dispatchApiRoute({
    pathname: '/tenant/roles/tenant_permission_whitespace_code_target/permissions',
    method: 'PUT',
    requestId: 'req-tenant-role-permission-whitespace-code',
    headers,
    body: {
      permission_codes: [' tenant.user_management.view']
    },
    handlers: harness.handlers
  });
  assert.equal(replaceRoute.status, 400);
  assert.equal(
    JSON.parse(replaceRoute.body).error_code,
    'TROLE-400-INVALID-PAYLOAD'
  );
});

test('PUT /tenant/roles/:role_id/permissions canonicalizes duplicated permission codes (case-insensitive)', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-permission-dup-code',
    TENANT_OPERATOR_A_PHONE
  );
  const headers = {
    authorization: `Bearer ${login.access_token}`
  };

  const createRoute = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-permission-dup-code',
    headers,
    body: {
      role_id: 'tenant_permission_duplicate_code_target',
      code: 'TENANT_PERMISSION_DUPLICATE_CODE_TARGET',
      name: '租户权限码重复去重目标角色',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRoute.status, 200);

  const replaceRoute = await dispatchApiRoute({
    pathname: '/tenant/roles/tenant_permission_duplicate_code_target/permissions',
    method: 'PUT',
    requestId: 'req-tenant-role-permission-dup-code',
    headers,
    body: {
      permission_codes: [
        'tenant.user_management.view',
        'tenant.User_Management.View'
      ]
    },
    handlers: harness.handlers
  });
  assert.equal(replaceRoute.status, 200);
  const payload = JSON.parse(replaceRoute.body);
  assert.deepEqual(payload.permission_codes, ['tenant.user_management.view']);
});

test('PUT /tenant/roles/:role_id/permissions enforces idempotency across canonicalized role_id path variants', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-permission-idem-canonicalized',
    TENANT_OPERATOR_A_PHONE
  );
  const headers = {
    authorization: `Bearer ${login.access_token}`
  };

  const createRoute = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-permission-idem-target',
    headers,
    body: {
      role_id: 'tenant_permission_idem_target',
      code: 'TENANT_PERMISSION_IDEM_TARGET',
      name: '租户权限授予幂等目标角色',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRoute.status, 200);

  const firstPut = await dispatchApiRoute({
    pathname: '/tenant/roles/Tenant_Permission_Idem_Target/permissions',
    method: 'PUT',
    requestId: 'req-tenant-role-permission-idem-canonicalized-1',
    headers: {
      ...headers,
      'idempotency-key': 'idem-tenant-role-permission-canonicalized'
    },
    body: {
      permission_codes: ['tenant.user_management.view']
    },
    handlers: harness.handlers
  });
  assert.equal(firstPut.status, 200);

  const secondPut = await dispatchApiRoute({
    pathname: '/tenant/roles/TENANT_PERMISSION_IDEM_TARGET/permissions',
    method: 'PUT',
    requestId: 'req-tenant-role-permission-idem-canonicalized-2',
    headers: {
      ...headers,
      'idempotency-key': 'idem-tenant-role-permission-canonicalized'
    },
    body: {
      permission_codes: ['tenant.role_management.view']
    },
    handlers: harness.handlers
  });
  assert.equal(secondPut.status, 409);
  assert.equal(
    JSON.parse(secondPut.body).error_code,
    'AUTH-409-IDEMPOTENCY-CONFLICT'
  );
});

test('PUT /tenant/roles/:role_id/permissions does not cache retryable 409 responses under idempotency key', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-permission-idem-retryable-conflict',
    TENANT_OPERATOR_A_PHONE
  );
  let updateCalls = 0;
  harness.handlers.tenantReplaceRolePermissions = async () => {
    updateCalls += 1;
    throw new AuthProblemError({
      status: 409,
      title: 'Conflict',
      detail: '可重试权限授予冲突',
      errorCode: 'TROLE-409-PERMISSION-RETRYABLE-CONFLICT',
      extensions: {
        retryable: true
      }
    });
  };

  const request = (requestId) =>
    dispatchApiRoute({
      pathname: '/tenant/roles/tenant_permission_retryable_conflict/permissions',
      method: 'PUT',
      requestId,
      headers: {
        authorization: `Bearer ${login.access_token}`,
        'idempotency-key': 'idem-tenant-role-permission-retryable-conflict'
      },
      body: {
        permission_codes: ['tenant.user_management.view']
      },
      handlers: harness.handlers
    });

  const firstPut = await request('req-tenant-role-permission-idem-retryable-1');
  const secondPut = await request('req-tenant-role-permission-idem-retryable-2');

  assert.equal(firstPut.status, 409);
  assert.equal(secondPut.status, 409);
  assert.equal(updateCalls, 2);
  assert.equal(
    JSON.parse(secondPut.body).error_code,
    'TROLE-409-PERMISSION-RETRYABLE-CONFLICT'
  );
});

test('PUT /tenant/roles/:role_id/permissions caches non-retryable 409 responses under idempotency key', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-permission-idem-non-retryable-conflict',
    TENANT_OPERATOR_A_PHONE
  );
  let updateCalls = 0;
  harness.handlers.tenantReplaceRolePermissions = async () => {
    updateCalls += 1;
    throw new AuthProblemError({
      status: 409,
      title: 'Conflict',
      detail: '不可重试权限授予冲突',
      errorCode: 'TROLE-409-PERMISSION-NON-RETRYABLE-CONFLICT',
      extensions: {
        retryable: false
      }
    });
  };

  const request = (requestId) =>
    dispatchApiRoute({
      pathname: '/tenant/roles/tenant_permission_non_retryable_conflict/permissions',
      method: 'PUT',
      requestId,
      headers: {
        authorization: `Bearer ${login.access_token}`,
        'idempotency-key': 'idem-tenant-role-permission-non-retryable-conflict'
      },
      body: {
        permission_codes: ['tenant.user_management.view']
      },
      handlers: harness.handlers
    });

  const firstPut = await request('req-tenant-role-permission-idem-non-retryable-1');
  const secondPut = await request('req-tenant-role-permission-idem-non-retryable-2');

  assert.equal(firstPut.status, 409);
  assert.equal(secondPut.status, 409);
  assert.equal(updateCalls, 1);
  assert.equal(
    JSON.parse(secondPut.body).error_code,
    'TROLE-409-PERMISSION-NON-RETRYABLE-CONFLICT'
  );
});

test('GET /tenant/roles/:role_id/permissions fails closed when downstream payload is malformed', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-permission-read-malformed',
    TENANT_OPERATOR_A_PHONE
  );
  const headers = {
    authorization: `Bearer ${login.access_token}`
  };

  const createRoute = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-permission-read-malformed',
    headers,
    body: {
      role_id: 'tenant_permission_read_malformed',
      code: 'TENANT_PERMISSION_READ_MALFORMED',
      name: '租户权限读取畸形回包目标角色',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRoute.status, 200);

  harness.authService.listTenantRolePermissionGrants = async ({ roleId }) => ({
    role_id: roleId,
    permission_codes: 'tenant.user_management.view',
    available_permission_codes: ['tenant.user_management.view']
  });

  const readRoute = await dispatchApiRoute({
    pathname: '/tenant/roles/tenant_permission_read_malformed/permissions',
    method: 'GET',
    requestId: 'req-tenant-role-permission-read-malformed',
    headers,
    handlers: harness.handlers
  });
  assert.equal(readRoute.status, 503);
  const payload = JSON.parse(readRoute.body);
  assert.equal(payload.error_code, 'TROLE-503-DEPENDENCY-UNAVAILABLE');
});

test('GET /tenant/roles/:role_id/permissions returns deterministically sorted permission arrays', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-permission-read-sort-stability',
    TENANT_OPERATOR_A_PHONE
  );
  const headers = {
    authorization: `Bearer ${login.access_token}`
  };

  const createRoute = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-permission-read-sort-stability',
    headers,
    body: {
      role_id: 'tenant_permission_read_sort_stability',
      code: 'TENANT_PERMISSION_READ_SORT_STABILITY',
      name: '租户权限读取稳定排序目标角色',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRoute.status, 200);

  const originalListTenantRolePermissionGrants = harness.authService.listTenantRolePermissionGrants;
  harness.authService.listTenantRolePermissionGrants = async ({ roleId }) => {
    if (String(roleId || '').trim().toLowerCase() === 'tenant_permission_read_sort_stability') {
      return {
        role_id: 'tenant_permission_read_sort_stability',
        permission_codes: [
          'tenant.user_management.view',
          'tenant.user_management.operate'
        ],
        available_permission_codes: [
          'tenant.user_management.view',
          'tenant.role_management.operate',
          'tenant.user_management.operate',
          'tenant.role_management.view'
        ],
        available_permissions: [
          {
            code: 'tenant.user_management.view',
            scope: 'tenant',
            group_key: 'user_management',
            action_key: 'view',
            label_key: 'permission.tenant.user_management.view',
            order: 110
          },
          {
            code: 'tenant.role_management.operate',
            scope: 'tenant',
            group_key: 'role_management',
            action_key: 'operate',
            label_key: 'permission.tenant.role_management.operate',
            order: 220
          },
          {
            code: 'tenant.user_management.operate',
            scope: 'tenant',
            group_key: 'user_management',
            action_key: 'operate',
            label_key: 'permission.tenant.user_management.operate',
            order: 120
          },
          {
            code: 'tenant.role_management.view',
            scope: 'tenant',
            group_key: 'role_management',
            action_key: 'view',
            label_key: 'permission.tenant.role_management.view',
            order: 210
          }
        ]
      };
    }
    return originalListTenantRolePermissionGrants({ roleId });
  };

  try {
    const readRoute = await dispatchApiRoute({
      pathname: '/tenant/roles/tenant_permission_read_sort_stability/permissions',
      method: 'GET',
      requestId: 'req-tenant-role-permission-read-sort-stability',
      headers,
      handlers: harness.handlers
    });
    assert.equal(readRoute.status, 200);
    const payload = JSON.parse(readRoute.body);
    assert.deepEqual(payload.permission_codes, [
      'tenant.user_management.operate',
      'tenant.user_management.view'
    ]);
    assert.deepEqual(payload.available_permission_codes, [
      'tenant.role_management.operate',
      'tenant.role_management.view',
      'tenant.user_management.operate',
      'tenant.user_management.view'
    ]);
  } finally {
    harness.authService.listTenantRolePermissionGrants = originalListTenantRolePermissionGrants;
  }
});

test('GET /tenant/roles/:role_id/permissions fails closed when downstream payload includes unknown catalog permissions', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-permission-read-unknown-catalog',
    TENANT_OPERATOR_A_PHONE
  );
  const headers = {
    authorization: `Bearer ${login.access_token}`
  };

  const createRoute = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-permission-read-unknown-catalog',
    headers,
    body: {
      role_id: 'tenant_permission_read_unknown_catalog',
      code: 'TENANT_PERMISSION_READ_UNKNOWN_CATALOG',
      name: '租户权限读取未知目录项目标角色',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRoute.status, 200);

  const originalListTenantRolePermissionGrants = harness.authService.listTenantRolePermissionGrants;
  harness.authService.listTenantRolePermissionGrants = async ({ roleId }) => {
    if (String(roleId || '').trim().toLowerCase() === 'tenant_permission_read_unknown_catalog') {
      return {
        role_id: 'tenant_permission_read_unknown_catalog',
        permission_codes: ['tenant.permission.unknown'],
        available_permission_codes: ['tenant.permission.unknown']
      };
    }
    return originalListTenantRolePermissionGrants({ roleId });
  };

  try {
    const readRoute = await dispatchApiRoute({
      pathname: '/tenant/roles/tenant_permission_read_unknown_catalog/permissions',
      method: 'GET',
      requestId: 'req-tenant-role-permission-read-unknown-catalog',
      headers,
      handlers: harness.handlers
    });
    assert.equal(readRoute.status, 503);
    const payload = JSON.parse(readRoute.body);
    assert.equal(payload.error_code, 'TROLE-503-DEPENDENCY-UNAVAILABLE');
    assert.equal(payload.request_id, 'req-tenant-role-permission-read-unknown-catalog');
  } finally {
    harness.authService.listTenantRolePermissionGrants = originalListTenantRolePermissionGrants;
  }
});

test('GET /tenant/roles/:role_id/permissions fails closed when permission catalog dependency is unavailable', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-permission-read-catalog-dependency',
    TENANT_OPERATOR_A_PHONE
  );
  const headers = {
    authorization: `Bearer ${login.access_token}`
  };

  const createRoute = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-permission-read-catalog-dependency',
    headers,
    body: {
      role_id: 'tenant_permission_read_catalog_dependency',
      code: 'TENANT_PERMISSION_READ_CATALOG_DEPENDENCY',
      name: '租户权限读取目录依赖异常目标角色',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRoute.status, 200);

  const originalListTenantPermissionCatalogEntries =
    harness.authService.listTenantPermissionCatalogEntries;
  harness.authService.listTenantPermissionCatalogEntries = () => {
    throw new Error('catalog dependency unavailable');
  };

  try {
    const readRoute = await dispatchApiRoute({
      pathname: '/tenant/roles/tenant_permission_read_catalog_dependency/permissions',
      method: 'GET',
      requestId: 'req-tenant-role-permission-read-catalog-dependency',
      headers,
      handlers: harness.handlers
    });
    assert.equal(readRoute.status, 503);
    const payload = JSON.parse(readRoute.body);
    assert.equal(payload.error_code, 'TROLE-503-DEPENDENCY-UNAVAILABLE');
    assert.equal(payload.request_id, 'req-tenant-role-permission-read-catalog-dependency');
  } finally {
    harness.authService.listTenantPermissionCatalogEntries =
      originalListTenantPermissionCatalogEntries;
  }
});

test('GET /tenant/roles/:role_id/permissions fails closed when downstream payload contains surrounding whitespace permission codes', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-permission-read-whitespace',
    TENANT_OPERATOR_A_PHONE
  );
  const headers = {
    authorization: `Bearer ${login.access_token}`
  };

  const createRoute = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-permission-read-whitespace',
    headers,
    body: {
      role_id: 'tenant_permission_read_whitespace',
      code: 'TENANT_PERMISSION_READ_WHITESPACE',
      name: '租户权限读取空白回包目标角色',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRoute.status, 200);

  harness.authService.listTenantRolePermissionGrants = async ({ roleId }) => ({
    role_id: roleId,
    permission_codes: [' tenant.user_management.view'],
    available_permission_codes: ['tenant.user_management.view']
  });

  const readRoute = await dispatchApiRoute({
    pathname: '/tenant/roles/tenant_permission_read_whitespace/permissions',
    method: 'GET',
    requestId: 'req-tenant-role-permission-read-whitespace',
    headers,
    handlers: harness.handlers
  });
  assert.equal(readRoute.status, 503);
  const payload = JSON.parse(readRoute.body);
  assert.equal(payload.error_code, 'TROLE-503-DEPENDENCY-UNAVAILABLE');
});

test('GET /tenant/roles/:role_id/permissions fails closed when downstream payload contains surrounding whitespace role_id', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-permission-read-roleid-whitespace',
    TENANT_OPERATOR_A_PHONE
  );
  const headers = {
    authorization: `Bearer ${login.access_token}`
  };

  const createRoute = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-permission-read-roleid-whitespace',
    headers,
    body: {
      role_id: 'tenant_permission_read_roleid_whitespace',
      code: 'TENANT_PERMISSION_READ_ROLEID_WHITESPACE',
      name: '租户权限读取 role_id 空白回包目标角色',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRoute.status, 200);

  harness.authService.listTenantRolePermissionGrants = async ({ roleId }) => ({
    role_id: ` ${roleId} `,
    permission_codes: ['tenant.user_management.view'],
    available_permission_codes: ['tenant.user_management.view']
  });

  const readRoute = await dispatchApiRoute({
    pathname: '/tenant/roles/tenant_permission_read_roleid_whitespace/permissions',
    method: 'GET',
    requestId: 'req-tenant-role-permission-read-roleid-whitespace',
    headers,
    handlers: harness.handlers
  });
  assert.equal(readRoute.status, 503);
  const payload = JSON.parse(readRoute.body);
  assert.equal(payload.error_code, 'TROLE-503-DEPENDENCY-UNAVAILABLE');
});

test('PUT /tenant/roles/:role_id/permissions fails closed when downstream write result is malformed', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-permission-write-malformed',
    TENANT_OPERATOR_A_PHONE
  );
  const headers = {
    authorization: `Bearer ${login.access_token}`
  };

  const createRoute = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-permission-write-malformed',
    headers,
    body: {
      role_id: 'tenant_permission_write_malformed',
      code: 'TENANT_PERMISSION_WRITE_MALFORMED',
      name: '租户权限写入畸形回包目标角色',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRoute.status, 200);

  harness.authService.replaceTenantRolePermissionGrants = async ({ roleId, permissionCodes }) => ({
    role_id: roleId,
    permission_codes: permissionCodes,
    affected_user_count: -1
  });

  const replaceRoute = await dispatchApiRoute({
    pathname: '/tenant/roles/tenant_permission_write_malformed/permissions',
    method: 'PUT',
    requestId: 'req-tenant-role-permission-write-malformed',
    headers,
    body: {
      permission_codes: ['tenant.user_management.view']
    },
    handlers: harness.handlers
  });
  assert.equal(replaceRoute.status, 503);
  const payload = JSON.parse(replaceRoute.body);
  assert.equal(payload.error_code, 'TROLE-503-DEPENDENCY-UNAVAILABLE');
});

test('PUT /tenant/roles/:role_id/permissions fails closed when downstream write result role_id contains surrounding whitespace', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-permission-write-roleid-whitespace',
    TENANT_OPERATOR_A_PHONE
  );
  const headers = {
    authorization: `Bearer ${login.access_token}`
  };

  const createRoute = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-permission-write-roleid-whitespace',
    headers,
    body: {
      role_id: 'tenant_permission_write_roleid_whitespace',
      code: 'TENANT_PERMISSION_WRITE_ROLEID_WHITESPACE',
      name: '租户权限写入 role_id 空白回包目标角色',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRoute.status, 200);

  harness.authService.replaceTenantRolePermissionGrants = async ({ roleId, permissionCodes }) => ({
    role_id: ` ${roleId} `,
    permission_codes: permissionCodes,
    affected_user_count: 0
  });

  const replaceRoute = await dispatchApiRoute({
    pathname: '/tenant/roles/tenant_permission_write_roleid_whitespace/permissions',
    method: 'PUT',
    requestId: 'req-tenant-role-permission-write-roleid-whitespace',
    headers,
    body: {
      permission_codes: ['tenant.user_management.view']
    },
    handlers: harness.handlers
  });
  assert.equal(replaceRoute.status, 503);
  const payload = JSON.parse(replaceRoute.body);
  assert.equal(payload.error_code, 'TROLE-503-DEPENDENCY-UNAVAILABLE');
});

test('PUT /tenant/roles/:role_id/permissions fails closed when downstream write result affected_user_count is string', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-permission-write-affected-user-count-string',
    TENANT_OPERATOR_A_PHONE
  );
  const headers = {
    authorization: `Bearer ${login.access_token}`
  };

  const createRoute = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-permission-write-affected-user-count-string',
    headers,
    body: {
      role_id: 'tenant_permission_write_affected_user_count_string',
      code: 'TENANT_PERMISSION_WRITE_AFFECTED_USER_COUNT_STRING',
      name: '租户权限写入受影响用户计数字符串回包目标角色',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRoute.status, 200);

  harness.authService.replaceTenantRolePermissionGrants = async ({ roleId, permissionCodes }) => ({
    role_id: roleId,
    permission_codes: permissionCodes,
    affected_user_count: '1'
  });

  const replaceRoute = await dispatchApiRoute({
    pathname: '/tenant/roles/tenant_permission_write_affected_user_count_string/permissions',
    method: 'PUT',
    requestId: 'req-tenant-role-permission-write-affected-user-count-string',
    headers,
    body: {
      permission_codes: ['tenant.user_management.view']
    },
    handlers: harness.handlers
  });
  assert.equal(replaceRoute.status, 503);
  const payload = JSON.parse(replaceRoute.body);
  assert.equal(payload.error_code, 'TROLE-503-DEPENDENCY-UNAVAILABLE');
});

test('PUT /tenant/roles/:role_id/permissions fails closed when permission catalog dependency is unavailable', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-permission-write-catalog-dependency',
    TENANT_OPERATOR_A_PHONE
  );
  const headers = {
    authorization: `Bearer ${login.access_token}`
  };

  const createRoute = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-permission-write-catalog-dependency',
    headers,
    body: {
      role_id: 'tenant_permission_write_catalog_dependency',
      code: 'TENANT_PERMISSION_WRITE_CATALOG_DEPENDENCY',
      name: '租户权限写入目录依赖异常目标角色',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRoute.status, 200);

  const originalListTenantPermissionCatalogEntries =
    harness.authService.listTenantPermissionCatalogEntries;
  harness.authService.listTenantPermissionCatalogEntries = () => {
    throw new Error('catalog dependency unavailable');
  };

  try {
    const replaceRoute = await dispatchApiRoute({
      pathname: '/tenant/roles/tenant_permission_write_catalog_dependency/permissions',
      method: 'PUT',
      requestId: 'req-tenant-role-permission-write-catalog-dependency',
      headers,
      body: {
        permission_codes: ['tenant.user_management.view']
      },
      handlers: harness.handlers
    });
    assert.equal(replaceRoute.status, 503);
    const payload = JSON.parse(replaceRoute.body);
    assert.equal(payload.error_code, 'TROLE-503-DEPENDENCY-UNAVAILABLE');
    assert.equal(payload.request_id, 'req-tenant-role-permission-write-catalog-dependency');
  } finally {
    harness.authService.listTenantPermissionCatalogEntries =
      originalListTenantPermissionCatalogEntries;
  }
});

test('PUT /tenant/roles/:role_id/permissions fails closed before write when permission catalog payload is malformed', async () => {
  const harness = createHarness();
  const login = await loginByPhone(
    harness.authService,
    'req-tenant-role-login-permission-write-catalog-malformed',
    TENANT_OPERATOR_A_PHONE
  );
  const headers = {
    authorization: `Bearer ${login.access_token}`
  };

  const createRoute = await dispatchApiRoute({
    pathname: '/tenant/roles',
    method: 'POST',
    requestId: 'req-tenant-role-create-permission-write-catalog-malformed',
    headers,
    body: {
      role_id: 'tenant_permission_write_catalog_malformed',
      code: 'TENANT_PERMISSION_WRITE_CATALOG_MALFORMED',
      name: '租户权限写入目录畸形回包目标角色',
      status: 'active'
    },
    handlers: harness.handlers
  });
  assert.equal(createRoute.status, 200);

  const originalListTenantPermissionCatalogEntries =
    harness.authService.listTenantPermissionCatalogEntries;
  const originalReplaceTenantRolePermissionGrants =
    harness.authService.replaceTenantRolePermissionGrants;
  let replaceTenantRolePermissionGrantsCalls = 0;
  harness.authService.listTenantPermissionCatalogEntries = () => ({
    malformed: true
  });
  harness.authService.replaceTenantRolePermissionGrants = async ({ roleId }) => {
    replaceTenantRolePermissionGrantsCalls += 1;
    return {
      role_id: roleId,
      permission_codes: [],
      affected_user_count: 0
    };
  };

  try {
    const replaceRoute = await dispatchApiRoute({
      pathname: '/tenant/roles/tenant_permission_write_catalog_malformed/permissions',
      method: 'PUT',
      requestId: 'req-tenant-role-permission-write-catalog-malformed',
      headers,
      body: {
        permission_codes: []
      },
      handlers: harness.handlers
    });
    assert.equal(replaceRoute.status, 503);
    const payload = JSON.parse(replaceRoute.body);
    assert.equal(payload.error_code, 'TROLE-503-DEPENDENCY-UNAVAILABLE');
    assert.equal(payload.request_id, 'req-tenant-role-permission-write-catalog-malformed');
    assert.equal(replaceTenantRolePermissionGrantsCalls, 0);
  } finally {
    harness.authService.listTenantPermissionCatalogEntries =
      originalListTenantPermissionCatalogEntries;
    harness.authService.replaceTenantRolePermissionGrants =
      originalReplaceTenantRolePermissionGrants;
  }
});
