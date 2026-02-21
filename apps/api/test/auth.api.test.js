const test = require('node:test');
const assert = require('node:assert/strict');
const { createCipheriv, createHash, pbkdf2Sync, randomBytes } = require('node:crypto');
const { handleApiRoute } = require('../src/server');
const { readConfig } = require('../src/config/env');
const { createAuthService } = require('../src/modules/auth/auth.service');

const config = readConfig({ ALLOW_MOCK_BACKENDS: 'true' });

const dependencyProbe = async () => ({
  db: { ok: true, detail: 'db ok' },
  redis: { ok: true, detail: 'redis ok' }
});

const seedUsers = [
  {
    id: 'user-active',
    phone: '13800000000',
    password: 'Passw0rd!',
    status: 'active'
  },
  {
    id: 'user-disabled',
    phone: '13800000001',
    password: 'Passw0rd!',
    status: 'disabled'
  }
];

const createApiContext = () => ({
  authService: createAuthService({ seedUsers }),
  dependencyProbe
});
const deriveSensitiveConfigKey = (decryptionKey) => {
  const normalizedRawKey = String(decryptionKey || '').trim();
  if (!normalizedRawKey) {
    return Buffer.alloc(0);
  }
  if (/^[0-9a-f]{64}$/i.test(normalizedRawKey)) {
    return Buffer.from(normalizedRawKey, 'hex');
  }
  return pbkdf2Sync(normalizedRawKey, 'auth.default_password', 210000, 32, 'sha256');
};
const buildEncryptedSensitiveConfigValue = ({
  plainText,
  decryptionKey
}) => {
  const key = deriveSensitiveConfigKey(decryptionKey);
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const cipherText = Buffer.concat([
    cipher.update(String(plainText || ''), 'utf8'),
    cipher.final()
  ]);
  const authTag = cipher.getAuthTag();
  return `enc:v1:${iv.toString('base64url')}:${authTag.toString('base64url')}:${cipherText.toString('base64url')}`;
};
const createSensitiveConfigProvider = ({ encryptedDefaultPassword = '' } = {}) => ({
  getEncryptedConfig: async (configKey) =>
    String(configKey || '').trim() === 'auth.default_password'
      ? String(encryptedDefaultPassword || '')
      : ''
});

const decodeJwtPayload = (token) => {
  const parts = String(token || '').split('.');
  if (parts.length < 2) {
    return {};
  }
  return JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
};

const assertSamePayloadWithFreshRequestId = (actualPayload, expectedPayload) => {
  assert.ok(actualPayload.request_id);
  assert.ok(expectedPayload.request_id);
  assert.notEqual(actualPayload.request_id, expectedPayload.request_id);
  const { request_id: _actualRequestId, ...actualWithoutRequestId } = actualPayload;
  const { request_id: _expectedRequestId, ...expectedWithoutRequestId } = expectedPayload;
  assert.deepEqual(actualWithoutRequestId, expectedWithoutRequestId);
};

const callRoute = async ({ pathname, method = 'GET', body = {}, headers = {} }, context) => {
  const route = await handleApiRoute(
    {
      pathname,
      method,
      body,
      headers
    },
    config,
    context
  );

  return {
    status: route.status,
    headers: route.headers,
    body: JSON.parse(route.body)
  };
};

test('auth login endpoint returns request_id and token pair', async () => {
  const context = createApiContext();

  const res = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: { phone: '13800000000', password: 'Passw0rd!' }
    },
    context
  );

  assert.equal(res.status, 200);
  assert.equal(res.body.token_type, 'Bearer');
  assert.ok(res.body.access_token);
  assert.ok(res.body.refresh_token);
  assert.ok(res.body.session_id);
  assert.ok(res.body.request_id);
});

test('auth login endpoint supports query string path', async () => {
  const context = createApiContext();

  const res = await callRoute(
    {
      pathname: '/auth/login?next=%2Fdashboard',
      method: 'POST',
      body: { phone: '13800000000', password: 'Passw0rd!' }
    },
    context
  );

  assert.equal(res.status, 200);
  assert.ok(res.body.access_token);
  assert.ok(res.body.refresh_token);
});

test('auth login failure returns standardized problem details', async () => {
  const context = createApiContext();

  const res = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: { phone: '13999999999', password: 'not-it' }
    },
    context
  );

  assert.equal(res.status, 401);
  assert.equal(res.headers['content-type'], 'application/problem+json');
  assert.equal(res.body.title, 'Unauthorized');
  assert.equal(res.body.error_code, 'AUTH-401-LOGIN-FAILED');
  assert.equal(res.body.detail, '手机号或密码错误');
  assert.equal(res.body.retryable, false);
});

test('refresh rotation + replay handling via API', async () => {
  const context = createApiContext();

  const login = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: { phone: '13800000000', password: 'Passw0rd!' }
    },
    context
  );

  const refresh = await callRoute(
    {
      pathname: '/auth/refresh',
      method: 'POST',
      body: { refresh_token: login.body.refresh_token }
    },
    context
  );

  assert.equal(refresh.status, 200);
  assert.notEqual(refresh.body.refresh_token, login.body.refresh_token);

  const replay = await callRoute(
    {
      pathname: '/auth/refresh',
      method: 'POST',
      body: { refresh_token: login.body.refresh_token }
    },
    context
  );

  assert.equal(replay.status, 401);
  assert.equal(replay.body.error_code, 'AUTH-401-INVALID-REFRESH');
});

test('logout revokes only current session', async () => {
  const context = createApiContext();

  const sessionA = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: { phone: '13800000000', password: 'Passw0rd!' }
    },
    context
  );

  const sessionB = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: { phone: '13800000000', password: 'Passw0rd!' }
    },
    context
  );

  const logout = await callRoute(
    {
      pathname: '/auth/logout',
      method: 'POST',
      headers: {
        authorization: `Bearer ${sessionA.body.access_token}`
      }
    },
    context
  );

  assert.equal(logout.status, 200);
  assert.equal(logout.body.ok, true);

  const refreshB = await callRoute(
    {
      pathname: '/auth/refresh',
      method: 'POST',
      body: { refresh_token: sessionB.body.refresh_token }
    },
    context
  );

  assert.equal(refreshB.status, 200);

  const refreshA = await callRoute(
    {
      pathname: '/auth/refresh',
      method: 'POST',
      body: { refresh_token: sessionA.body.refresh_token }
    },
    context
  );

  assert.equal(refreshA.status, 401);
});

test('change password forces relogin and new password login succeeds', async () => {
  const context = createApiContext();

  const login = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: { phone: '13800000000', password: 'Passw0rd!' }
    },
    context
  );
  const loginPayload = decodeJwtPayload(login.body.access_token);

  const changed = await callRoute(
    {
      pathname: '/auth/change-password',
      method: 'POST',
      headers: {
        authorization: `Bearer ${login.body.access_token}`
      },
      body: {
        current_password: 'Passw0rd!',
        new_password: 'Passw0rd!2026'
      }
    },
    context
  );

  assert.equal(changed.status, 200);
  assert.equal(changed.body.password_changed, true);
  assert.equal(changed.body.relogin_required, true);

  const oldAccess = await callRoute(
    {
      pathname: '/auth/logout',
      method: 'POST',
      headers: {
        authorization: `Bearer ${login.body.access_token}`
      }
    },
    context
  );
  assert.equal(oldAccess.status, 401);
  assert.equal(oldAccess.body.error_code, 'AUTH-401-INVALID-ACCESS');

  const oldRefresh = await callRoute(
    {
      pathname: '/auth/refresh',
      method: 'POST',
      body: { refresh_token: login.body.refresh_token }
    },
    context
  );
  assert.equal(oldRefresh.status, 401);
  assert.equal(oldRefresh.body.error_code, 'AUTH-401-INVALID-REFRESH');

  const oldPasswordLogin = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: { phone: '13800000000', password: 'Passw0rd!' }
    },
    context
  );

  assert.equal(oldPasswordLogin.status, 401);

  const newPasswordLogin = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: { phone: '13800000000', password: 'Passw0rd!2026' }
    },
    context
  );

  assert.equal(newPasswordLogin.status, 200);
  assert.ok(newPasswordLogin.body.access_token);
  const reloginPayload = decodeJwtPayload(newPasswordLogin.body.access_token);
  assert.ok(
    Number(reloginPayload.sv) > Number(loginPayload.sv),
    'new access token should carry latest session version'
  );
});

test('change password under tenant entry without active tenant falls back to platform audit domain and keeps traceparent', async () => {
  const traceparent = '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01';
  const changeRequestId = 'req-change-password-tenant-no-active-tenant';
  const context = {
    authService: createAuthService({
      seedUsers: [
        {
          id: 'tenant-password-user',
          phone: '13817770088',
          password: 'Passw0rd!',
          status: 'active',
          domains: ['tenant'],
          tenants: [
            {
              membershipId: 'tenant-password-user-membership-a',
              tenantId: 'tenant-a',
              tenantName: 'Tenant A',
              status: 'active',
              permission: {
                canViewMemberAdmin: true,
                canOperateMemberAdmin: false,
                canViewBilling: false,
                canOperateBilling: false
              }
            },
            {
              membershipId: 'tenant-password-user-membership-b',
              tenantId: 'tenant-b',
              tenantName: 'Tenant B',
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
    }),
    dependencyProbe
  };

  const login = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: {
        phone: '13817770088',
        password: 'Passw0rd!',
        entry_domain: 'tenant'
      }
    },
    context
  );
  assert.equal(login.status, 200);
  assert.equal(login.body.entry_domain, 'tenant');
  assert.equal(login.body.tenant_selection_required, true);
  assert.equal(login.body.active_tenant_id, null);

  const changed = await callRoute(
    {
      pathname: '/auth/change-password',
      method: 'POST',
      headers: {
        authorization: `Bearer ${login.body.access_token}`,
        'x-request-id': changeRequestId,
        traceparent
      },
      body: {
        current_password: 'Passw0rd!',
        new_password: 'Passw0rd!2028'
      }
    },
    context
  );
  assert.equal(changed.status, 200);
  assert.equal(changed.body.request_id, changeRequestId);

  const platformAuditEvents = await context.authService.listAuditEvents({
    domain: 'platform',
    requestId: changeRequestId
  });
  assert.equal(platformAuditEvents.total, 1);
  assert.equal(platformAuditEvents.events[0].event_type, 'auth.password_change.succeeded');
  assert.equal(platformAuditEvents.events[0].traceparent, traceparent);

  const tenantAuditEvents = await context.authService.listAuditEvents({
    domain: 'tenant',
    tenantId: 'tenant-a',
    requestId: changeRequestId
  });
  assert.equal(tenantAuditEvents.total, 0);
});

test('platform role-facts replace converges session and invalidates previous access/refresh tokens', async () => {
  const context = {
    authService: createAuthService({
      seedUsers: [
        {
          id: 'user-platform-role-admin',
          phone: '13800000002',
          password: 'Passw0rd!',
          status: 'active',
          domains: ['platform'],
          platformRoles: [
            {
              roleId: 'platform-member-admin-operator',
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
    }),
    dependencyProbe
  };

  const login = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: {
        phone: '13800000002',
        password: 'Passw0rd!',
        entry_domain: 'platform'
      }
    },
    context
  );
  assert.equal(login.status, 200);
  const loginPayload = decodeJwtPayload(login.body.access_token);

  const replaced = await callRoute(
    {
      pathname: '/auth/platform/role-facts/replace',
      method: 'POST',
      headers: {
        authorization: `Bearer ${login.body.access_token}`
      },
      body: {
        user_id: 'user-platform-role-admin',
        roles: [{ role_id: 'sys_admin', status: 'active' }]
      }
    },
    context
  );
  assert.equal(replaced.status, 200);
  assert.equal(replaced.body.synced, true);
  assert.equal(replaced.body.reason, 'ok');
  assert.deepEqual(replaced.body.platform_permission_context, {
    scope_label: '平台权限（角色并集）',
    can_view_member_admin: true,
    can_operate_member_admin: true,
    can_view_billing: true,
    can_operate_billing: true
  });

  const oldAccess = await callRoute(
    {
      pathname: '/auth/logout',
      method: 'POST',
      headers: {
        authorization: `Bearer ${login.body.access_token}`
      }
    },
    context
  );
  assert.equal(oldAccess.status, 401);
  assert.equal(oldAccess.body.error_code, 'AUTH-401-INVALID-ACCESS');

  const oldRefresh = await callRoute(
    {
      pathname: '/auth/refresh',
      method: 'POST',
      body: { refresh_token: login.body.refresh_token }
    },
    context
  );
  assert.equal(oldRefresh.status, 401);
  assert.equal(oldRefresh.body.error_code, 'AUTH-401-INVALID-REFRESH');

  const relogin = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: {
        phone: '13800000002',
        password: 'Passw0rd!',
        entry_domain: 'platform'
      }
    },
    context
  );

  assert.equal(relogin.status, 200);
  const reloginPayload = decodeJwtPayload(relogin.body.access_token);
  assert.ok(
    Number(reloginPayload.sv) > Number(loginPayload.sv),
    'new access token should carry latest session version after role-facts convergence'
  );
});

test('platform role-facts replace replays the same Idempotency-Key without duplicating side effects', async () => {
  const context = {
    authService: createAuthService({
      seedUsers: [
        {
          id: 'user-platform-role-admin-idempotency-replay',
          phone: '13800000041',
          password: 'Passw0rd!',
          status: 'active',
          domains: ['platform'],
          platformRoles: [
            {
              roleId: 'platform-member-admin-operator',
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
          id: 'user-platform-role-target-idempotency-replay',
          phone: '13800000042',
          password: 'Passw0rd!',
          status: 'active',
          domains: ['platform'],
          platformRoles: []
        }
      ]
    }),
    dependencyProbe
  };

  const login = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: {
        phone: '13800000041',
        password: 'Passw0rd!',
        entry_domain: 'platform'
      }
    },
    context
  );
  assert.equal(login.status, 200);

  const idempotencyKey = 'idem-platform-role-facts-001';
  const requestBody = {
    user_id: 'user-platform-role-target-idempotency-replay',
    roles: [
      {
        role_id: 'sys_admin',
        status: 'active'
      }
    ]
  };

  const first = await callRoute(
    {
      pathname: '/auth/platform/role-facts/replace',
      method: 'POST',
      headers: {
        authorization: `Bearer ${login.body.access_token}`,
        'idempotency-key': idempotencyKey
      },
      body: requestBody
    },
    context
  );
  assert.equal(first.status, 200);

  const replay = await callRoute(
    {
      pathname: '/auth/platform/role-facts/replace',
      method: 'POST',
      headers: {
        authorization: `Bearer ${login.body.access_token}`,
        'idempotency-key': idempotencyKey
      },
      body: requestBody
    },
    context
  );
  assert.equal(replay.status, 200);
  assertSamePayloadWithFreshRequestId(replay.body, first.body);

  const updateEvents = context.authService._internals.auditTrail.filter(
    (event) => event.type === 'auth.platform_role_facts.updated'
  );
  assert.equal(updateEvents.length, 1);
  const idempotencyHitEvents = context.authService._internals.auditTrail.filter(
    (event) => event.type === 'auth.idempotency.hit'
  );
  assert.ok(idempotencyHitEvents.length >= 1);
});

test('platform role-facts replace rejects payload drift for reused Idempotency-Key', async () => {
  const context = {
    authService: createAuthService({
      seedUsers: [
        {
          id: 'user-platform-role-admin-idempotency-conflict',
          phone: '13800000043',
          password: 'Passw0rd!',
          status: 'active',
          domains: ['platform'],
          platformRoles: [
            {
              roleId: 'platform-member-admin-operator',
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
          id: 'user-platform-role-target-idempotency-conflict',
          phone: '13800000044',
          password: 'Passw0rd!',
          status: 'active',
          domains: ['platform'],
          platformRoles: [
            {
              roleId: 'platform-member-admin-target-old',
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
    }),
    dependencyProbe
  };

  const login = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: {
        phone: '13800000043',
        password: 'Passw0rd!',
        entry_domain: 'platform'
      }
    },
    context
  );
  assert.equal(login.status, 200);

  const idempotencyKey = 'idem-platform-role-facts-002';
  const first = await callRoute(
    {
      pathname: '/auth/platform/role-facts/replace',
      method: 'POST',
      headers: {
        authorization: `Bearer ${login.body.access_token}`,
        'idempotency-key': idempotencyKey
      },
      body: {
        user_id: 'user-platform-role-target-idempotency-conflict',
        roles: [{ role_id: 'sys_admin', status: 'active' }]
      }
    },
    context
  );
  assert.equal(first.status, 200);

  const payloadDrift = await callRoute(
    {
      pathname: '/auth/platform/role-facts/replace',
      method: 'POST',
      headers: {
        authorization: `Bearer ${login.body.access_token}`,
        'idempotency-key': idempotencyKey
      },
      body: {
        user_id: 'user-platform-role-target-idempotency-conflict',
        roles: [
          {
            role_id: 'platform-member-admin-target-new',
            status: 'active',
            permission: {
              can_view_member_admin: true,
              can_operate_member_admin: true,
              can_view_billing: false,
              can_operate_billing: false
            }
          }
        ]
      }
    },
    context
  );
  assert.equal(payloadDrift.status, 409);
  assert.equal(payloadDrift.body.error_code, 'AUTH-409-IDEMPOTENCY-CONFLICT');
  assert.equal(payloadDrift.body.retryable, false);

  const updateEvents = context.authService._internals.auditTrail.filter(
    (event) => event.type === 'auth.platform_role_facts.updated'
  );
  assert.equal(updateEvents.length, 1);
  const conflictEvents = context.authService._internals.auditTrail.filter(
    (event) => event.type === 'auth.idempotency.conflict'
  );
  assert.ok(conflictEvents.length >= 1);
});

test('platform role-facts replace rejects unknown user id with AUTH-400-INVALID-PAYLOAD', async () => {
  const context = {
    authService: createAuthService({
      seedUsers: [
        {
          id: 'user-platform-role-admin-2',
          phone: '13800000003',
          password: 'Passw0rd!',
          status: 'active',
          domains: ['platform'],
          platformRoles: [
            {
              roleId: 'platform-member-admin-operator',
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
    }),
    dependencyProbe
  };

  const login = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: {
        phone: '13800000003',
        password: 'Passw0rd!',
        entry_domain: 'platform'
      }
    },
    context
  );
  assert.equal(login.status, 200);

  const replaced = await callRoute(
    {
      pathname: '/auth/platform/role-facts/replace',
      method: 'POST',
      headers: {
        authorization: `Bearer ${login.body.access_token}`
      },
      body: {
        user_id: 'user-does-not-exist',
        roles: []
      }
    },
    context
  );

  assert.equal(replaced.status, 400);
  assert.equal(replaced.body.error_code, 'AUTH-400-INVALID-PAYLOAD');
});

test('platform role-facts replace rejects non-string user_id with AUTH-400-INVALID-PAYLOAD', async () => {
  const context = {
    authService: createAuthService({
      seedUsers: [
        {
          id: '123',
          phone: '13800000031',
          password: 'Passw0rd!',
          status: 'active',
          domains: ['platform'],
          platformRoles: [
            {
              roleId: 'platform-member-admin-operator',
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
    }),
    dependencyProbe
  };

  const login = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: {
        phone: '13800000031',
        password: 'Passw0rd!',
        entry_domain: 'platform'
      }
    },
    context
  );
  assert.equal(login.status, 200);

  const replaced = await callRoute(
    {
      pathname: '/auth/platform/role-facts/replace',
      method: 'POST',
      headers: {
        authorization: `Bearer ${login.body.access_token}`
      },
      body: {
        user_id: 123,
        roles: []
      }
    },
    context
  );

  assert.equal(replaced.status, 400);
  assert.equal(replaced.body.error_code, 'AUTH-400-INVALID-PAYLOAD');
});

test('platform role-facts replace rejects caller without platform.member_admin.operate', async () => {
  const context = {
    authService: createAuthService({
      seedUsers: [
        {
          id: 'user-platform-role-no-operate',
          phone: '13800000030',
          password: 'Passw0rd!',
          status: 'active',
          domains: ['platform'],
          platformRoles: []
        }
      ]
    }),
    dependencyProbe
  };

  const login = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: {
        phone: '13800000030',
        password: 'Passw0rd!',
        entry_domain: 'platform'
      }
    },
    context
  );
  assert.equal(login.status, 200);

  const replaced = await callRoute(
    {
      pathname: '/auth/platform/role-facts/replace',
      method: 'POST',
      headers: {
        authorization: `Bearer ${login.body.access_token}`
      },
      body: {
        user_id: 'user-platform-role-no-operate',
        roles: []
      }
    },
    context
  );

  assert.equal(replaced.status, 403);
  assert.equal(replaced.body.error_code, 'AUTH-403-FORBIDDEN');
});

test('platform role-facts replace rejects missing roles field with AUTH-400-INVALID-PAYLOAD', async () => {
  const context = {
    authService: createAuthService({
      seedUsers: [
        {
          id: 'user-platform-role-admin-3',
          phone: '13800000004',
          password: 'Passw0rd!',
          status: 'active',
          domains: ['platform'],
          platformRoles: [
            {
              roleId: 'platform-member-admin-operator',
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
    }),
    dependencyProbe
  };

  const login = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: {
        phone: '13800000004',
        password: 'Passw0rd!',
        entry_domain: 'platform'
      }
    },
    context
  );
  assert.equal(login.status, 200);

  const replaced = await callRoute(
    {
      pathname: '/auth/platform/role-facts/replace',
      method: 'POST',
      headers: {
        authorization: `Bearer ${login.body.access_token}`
      },
      body: {
        user_id: 'user-platform-role-admin-3'
      }
    },
    context
  );

  assert.equal(replaced.status, 400);
  assert.equal(replaced.body.error_code, 'AUTH-400-INVALID-PAYLOAD');
});

test('platform role-facts replace rejects unsupported role status with AUTH-400-INVALID-PAYLOAD', async () => {
  const context = {
    authService: createAuthService({
      seedUsers: [
        {
          id: 'user-platform-role-admin-4',
          phone: '13800000005',
          password: 'Passw0rd!',
          status: 'active',
          domains: ['platform'],
          platformRoles: [
            {
              roleId: 'platform-member-admin-operator',
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
    }),
    dependencyProbe
  };

  const login = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: {
        phone: '13800000005',
        password: 'Passw0rd!',
        entry_domain: 'platform'
      }
    },
    context
  );
  assert.equal(login.status, 200);

  const replaced = await callRoute(
    {
      pathname: '/auth/platform/role-facts/replace',
      method: 'POST',
      headers: {
        authorization: `Bearer ${login.body.access_token}`
      },
      body: {
        user_id: 'user-platform-role-admin-4',
        roles: [
          {
            role_id: 'platform-member-admin-operator',
            status: 'pending-approval'
          }
        ]
      }
    },
    context
  );

  assert.equal(replaced.status, 400);
  assert.equal(replaced.body.error_code, 'AUTH-400-INVALID-PAYLOAD');
});

test('platform role-facts replace rejects blank role status with AUTH-400-INVALID-PAYLOAD', async () => {
  const context = {
    authService: createAuthService({
      seedUsers: [
        {
          id: 'user-platform-role-admin-4b',
          phone: '13800000015',
          password: 'Passw0rd!',
          status: 'active',
          domains: ['platform'],
          platformRoles: [
            {
              roleId: 'platform-member-admin-operator',
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
    }),
    dependencyProbe
  };

  const login = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: {
        phone: '13800000015',
        password: 'Passw0rd!',
        entry_domain: 'platform'
      }
    },
    context
  );
  assert.equal(login.status, 200);

  const replaced = await callRoute(
    {
      pathname: '/auth/platform/role-facts/replace',
      method: 'POST',
      headers: {
        authorization: `Bearer ${login.body.access_token}`
      },
      body: {
        user_id: 'user-platform-role-admin-4b',
        roles: [
          {
            role_id: 'platform-member-admin-operator',
            status: '   '
          }
        ]
      }
    },
    context
  );

  assert.equal(replaced.status, 400);
  assert.equal(replaced.body.error_code, 'AUTH-400-INVALID-PAYLOAD');
});

test('platform role-facts replace rejects payload with more than 5 role facts', async () => {
  const context = {
    authService: createAuthService({
      seedUsers: [
        {
          id: 'user-platform-role-admin-4c',
          phone: '13800000016',
          password: 'Passw0rd!',
          status: 'active',
          domains: ['platform'],
          platformRoles: [
            {
              roleId: 'platform-member-admin-operator',
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
    }),
    dependencyProbe
  };

  const login = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: {
        phone: '13800000016',
        password: 'Passw0rd!',
        entry_domain: 'platform'
      }
    },
    context
  );
  assert.equal(login.status, 200);

  const replaced = await callRoute(
    {
      pathname: '/auth/platform/role-facts/replace',
      method: 'POST',
      headers: {
        authorization: `Bearer ${login.body.access_token}`
      },
      body: {
        user_id: 'user-platform-role-admin-4c',
        roles: [
          { role_id: 'r-1' },
          { role_id: 'r-2' },
          { role_id: 'r-3' },
          { role_id: 'r-4' },
          { role_id: 'r-5' },
          { role_id: 'r-6' }
        ]
      }
    },
    context
  );

  assert.equal(replaced.status, 400);
  assert.equal(replaced.body.error_code, 'AUTH-400-INVALID-PAYLOAD');
});

test('platform role-facts replace rejects role_id longer than 64 chars', async () => {
  const context = {
    authService: createAuthService({
      seedUsers: [
        {
          id: 'user-platform-role-admin-4f',
          phone: '13800000019',
          password: 'Passw0rd!',
          status: 'active',
          domains: ['platform'],
          platformRoles: [
            {
              roleId: 'platform-member-admin-operator',
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
    }),
    dependencyProbe
  };

  const login = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: {
        phone: '13800000019',
        password: 'Passw0rd!',
        entry_domain: 'platform'
      }
    },
    context
  );
  assert.equal(login.status, 200);

  const replaced = await callRoute(
    {
      pathname: '/auth/platform/role-facts/replace',
      method: 'POST',
      headers: {
        authorization: `Bearer ${login.body.access_token}`
      },
      body: {
        user_id: 'user-platform-role-admin-4f',
        roles: [{ role_id: 'r'.repeat(65), status: 'active' }]
      }
    },
    context
  );

  assert.equal(replaced.status, 400);
  assert.equal(replaced.body.error_code, 'AUTH-400-INVALID-PAYLOAD');
});

test('platform role-facts replace rejects non-boolean permission flags with AUTH-400-INVALID-PAYLOAD', async () => {
  const context = {
    authService: createAuthService({
      seedUsers: [
        {
          id: 'user-platform-role-admin-4g',
          phone: '13800000020',
          password: 'Passw0rd!',
          status: 'active',
          domains: ['platform'],
          platformRoles: [
            {
              roleId: 'platform-member-admin-operator',
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
    }),
    dependencyProbe
  };

  const login = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: {
        phone: '13800000020',
        password: 'Passw0rd!',
        entry_domain: 'platform'
      }
    },
    context
  );
  assert.equal(login.status, 200);

  const replaced = await callRoute(
    {
      pathname: '/auth/platform/role-facts/replace',
      method: 'POST',
      headers: {
        authorization: `Bearer ${login.body.access_token}`
      },
      body: {
        user_id: 'user-platform-role-admin-4g',
        roles: [
          {
            role_id: 'platform-member-admin-operator',
            status: 'active',
            permission: {
              can_operate_member_admin: 'true'
            }
          }
        ]
      }
    },
    context
  );

  assert.equal(replaced.status, 400);
  assert.equal(replaced.body.error_code, 'AUTH-400-INVALID-PAYLOAD');
});

test('platform role-facts replace rejects non-object permission payload with AUTH-400-INVALID-PAYLOAD', async () => {
  const context = {
    authService: createAuthService({
      seedUsers: [
        {
          id: 'user-platform-role-admin-4h',
          phone: '13800000033',
          password: 'Passw0rd!',
          status: 'active',
          domains: ['platform'],
          platformRoles: [
            {
              roleId: 'platform-member-admin-operator',
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
    }),
    dependencyProbe
  };

  const login = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: {
        phone: '13800000033',
        password: 'Passw0rd!',
        entry_domain: 'platform'
      }
    },
    context
  );
  assert.equal(login.status, 200);

  const replaced = await callRoute(
    {
      pathname: '/auth/platform/role-facts/replace',
      method: 'POST',
      headers: {
        authorization: `Bearer ${login.body.access_token}`
      },
      body: {
        user_id: 'user-platform-role-admin-4h',
        roles: [
          {
            role_id: 'platform-member-admin-operator',
            status: 'active',
            permission: 'invalid'
          }
        ]
      }
    },
    context
  );

  assert.equal(replaced.status, 400);
  assert.equal(replaced.body.error_code, 'AUTH-400-INVALID-PAYLOAD');
});

test('platform role-facts replace rejects top-level permission fields with AUTH-400-INVALID-PAYLOAD', async () => {
  const context = {
    authService: createAuthService({
      seedUsers: [
        {
          id: 'user-platform-role-admin-4i',
          phone: '13800000034',
          password: 'Passw0rd!',
          status: 'active',
          domains: ['platform'],
          platformRoles: [
            {
              roleId: 'platform-member-admin-operator',
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
    }),
    dependencyProbe
  };

  const login = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: {
        phone: '13800000034',
        password: 'Passw0rd!',
        entry_domain: 'platform'
      }
    },
    context
  );
  assert.equal(login.status, 200);

  const replaced = await callRoute(
    {
      pathname: '/auth/platform/role-facts/replace',
      method: 'POST',
      headers: {
        authorization: `Bearer ${login.body.access_token}`
      },
      body: {
        user_id: 'user-platform-role-admin-4i',
        roles: [
          {
            role_id: 'platform-member-admin-operator',
            can_view_member_admin: true
          }
        ]
      }
    },
    context
  );

  assert.equal(replaced.status, 400);
  assert.equal(replaced.body.error_code, 'AUTH-400-INVALID-PAYLOAD');
});

test('platform role-facts replace rejects duplicate role_id entries with AUTH-400-INVALID-PAYLOAD', async () => {
  const context = {
    authService: createAuthService({
      seedUsers: [
        {
          id: 'user-platform-role-admin-4d',
          phone: '13800000017',
          password: 'Passw0rd!',
          status: 'active',
          domains: ['platform'],
          platformRoles: [
            {
              roleId: 'platform-member-admin-operator',
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
    }),
    dependencyProbe
  };

  const login = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: {
        phone: '13800000017',
        password: 'Passw0rd!',
        entry_domain: 'platform'
      }
    },
    context
  );
  assert.equal(login.status, 200);

  const replaced = await callRoute(
    {
      pathname: '/auth/platform/role-facts/replace',
      method: 'POST',
      headers: {
        authorization: `Bearer ${login.body.access_token}`
      },
      body: {
        user_id: 'user-platform-role-admin-4d',
        roles: [
          { role_id: 'r-1' },
          { role_id: 'r-2' },
          { role_id: 'r-3' },
          { role_id: 'r-4' },
          { role_id: 'r-5' },
          { role_id: 'r-5', status: 'disabled' }
        ]
      }
    },
    context
  );

  assert.equal(replaced.status, 400);
  assert.equal(replaced.body.error_code, 'AUTH-400-INVALID-PAYLOAD');
});

test('platform role-facts replace rejects duplicate role_id entries regardless of case', async () => {
  const context = {
    authService: createAuthService({
      seedUsers: [
        {
          id: 'user-platform-role-admin-4e',
          phone: '13800000018',
          password: 'Passw0rd!',
          status: 'active',
          domains: ['platform'],
          platformRoles: [
            {
              roleId: 'platform-member-admin-operator',
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
    }),
    dependencyProbe
  };

  const login = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: {
        phone: '13800000018',
        password: 'Passw0rd!',
        entry_domain: 'platform'
      }
    },
    context
  );
  assert.equal(login.status, 200);

  const replaced = await callRoute(
    {
      pathname: '/auth/platform/role-facts/replace',
      method: 'POST',
      headers: {
        authorization: `Bearer ${login.body.access_token}`
      },
      body: {
        user_id: 'user-platform-role-admin-4e',
        roles: [
          { role_id: 'Role-Case', status: 'active' },
          { role_id: 'role-case', status: 'disabled' }
        ]
      }
    },
    context
  );

  assert.equal(replaced.status, 400);
  assert.equal(replaced.body.error_code, 'AUTH-400-INVALID-PAYLOAD');
});

test('platform role-facts replace rejects role item missing role_id with AUTH-400-INVALID-PAYLOAD', async () => {
  const context = {
    authService: createAuthService({
      seedUsers: [
        {
          id: 'user-platform-role-admin-5',
          phone: '13800000006',
          password: 'Passw0rd!',
          status: 'active',
          domains: ['platform'],
          platformRoles: [
            {
              roleId: 'platform-member-admin-operator',
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
    }),
    dependencyProbe
  };

  const login = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: {
        phone: '13800000006',
        password: 'Passw0rd!',
        entry_domain: 'platform'
      }
    },
    context
  );
  assert.equal(login.status, 200);

  const replaced = await callRoute(
    {
      pathname: '/auth/platform/role-facts/replace',
      method: 'POST',
      headers: {
        authorization: `Bearer ${login.body.access_token}`
      },
      body: {
        user_id: 'user-platform-role-admin-5',
        roles: [{ status: 'active' }]
      }
    },
    context
  );

  assert.equal(replaced.status, 400);
  assert.equal(replaced.body.error_code, 'AUTH-400-INVALID-PAYLOAD');
});

test('platform role-facts replace rejects non-string role_id with AUTH-400-INVALID-PAYLOAD', async () => {
  const context = {
    authService: createAuthService({
      seedUsers: [
        {
          id: 'user-platform-role-admin-5b',
          phone: '13800000032',
          password: 'Passw0rd!',
          status: 'active',
          domains: ['platform'],
          platformRoles: [
            {
              roleId: 'platform-member-admin-operator',
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
    }),
    dependencyProbe
  };

  const login = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: {
        phone: '13800000032',
        password: 'Passw0rd!',
        entry_domain: 'platform'
      }
    },
    context
  );
  assert.equal(login.status, 200);

  const replaced = await callRoute(
    {
      pathname: '/auth/platform/role-facts/replace',
      method: 'POST',
      headers: {
        authorization: `Bearer ${login.body.access_token}`
      },
      body: {
        user_id: 'user-platform-role-admin-5b',
        roles: [{ role_id: 123, status: 'active' }]
      }
    },
    context
  );

  assert.equal(replaced.status, 400);
  assert.equal(replaced.body.error_code, 'AUTH-400-INVALID-PAYLOAD');
});

test('platform role-facts replace maps degraded sync reason to AUTH-503-PLATFORM-SNAPSHOT-DEGRADED', async () => {
  const context = {
    authService: createAuthService({
      seedUsers: [
        {
          id: 'user-platform-role-admin-6',
          phone: '13800000007',
          password: 'Passw0rd!',
          status: 'active',
          domains: ['platform'],
          platformRoles: [
            {
              roleId: 'platform-member-admin-operator',
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
    }),
    dependencyProbe
  };

  const login = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: {
        phone: '13800000007',
        password: 'Passw0rd!',
        entry_domain: 'platform'
      }
    },
    context
  );
  assert.equal(login.status, 200);

  context.authService._internals.authStore.replacePlatformRolesAndSyncSnapshot = async () => ({
    synced: false,
    reason: 'db-deadlock',
    permission: null
  });

  const replaced = await callRoute(
    {
      pathname: '/auth/platform/role-facts/replace',
      method: 'POST',
      headers: {
        authorization: `Bearer ${login.body.access_token}`
      },
      body: {
        user_id: 'user-platform-role-admin-6',
        roles: [{ role_id: 'sys_admin', status: 'active' }]
      }
    },
    context
  );

  assert.equal(replaced.status, 503);
  assert.equal(replaced.body.error_code, 'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED');
  assert.equal(replaced.body.retryable, true);
  assert.equal(replaced.body.degradation_reason, 'db-deadlock');
});

test('platform member-admin provision-user endpoint creates user and rejects duplicate relationship requests', async () => {
  const defaultPassword = 'InitPass!2026';
  const decryptionKey = 'api-platform-provision-key';
  const encryptedDefaultPassword = buildEncryptedSensitiveConfigValue({
    plainText: defaultPassword,
    decryptionKey
  });
  const context = {
    authService: createAuthService({
      seedUsers: [
        {
          id: 'platform-provision-operator',
          phone: '13846660010',
          password: 'Passw0rd!',
          status: 'active',
          domains: ['platform'],
          platformRoles: [
            {
              roleId: 'platform-member-admin-operator',
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
      ],
      sensitiveConfigProvider: createSensitiveConfigProvider({
        encryptedDefaultPassword
      }),
      sensitiveConfigDecryptionKey: decryptionKey
    }),
    dependencyProbe
  };

  const operatorLogin = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: {
        phone: '13846660010',
        password: 'Passw0rd!',
        entry_domain: 'platform'
      }
    },
    context
  );
  assert.equal(operatorLogin.status, 200);

  const provisioned = await callRoute(
    {
      pathname: '/auth/platform/member-admin/provision-user',
      method: 'POST',
      headers: {
        authorization: `Bearer ${operatorLogin.body.access_token}`
      },
      body: {
        phone: '13846660011'
      }
    },
    context
  );
  assert.equal(provisioned.status, 200);
  assert.equal(provisioned.body.created_user, true);
  assert.equal(provisioned.body.credential_initialized, true);
  assert.equal(provisioned.body.first_login_force_password_change, false);

  const firstLogin = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: {
        phone: '13846660011',
        password: defaultPassword,
        entry_domain: 'platform'
      }
    },
    context
  );
  assert.equal(firstLogin.status, 200);

  const duplicateProvision = await callRoute(
    {
      pathname: '/auth/platform/member-admin/provision-user',
      method: 'POST',
      headers: {
        authorization: `Bearer ${operatorLogin.body.access_token}`
      },
      body: {
        phone: '13846660011'
      }
    },
    context
  );
  assert.equal(duplicateProvision.status, 409);
  assert.equal(duplicateProvision.body.error_code, 'AUTH-409-PROVISION-CONFLICT');
});

test('platform member-admin provision-user endpoint rejects tenant_name payload', async () => {
  const defaultPassword = 'InitPass!2026';
  const decryptionKey = 'api-platform-provision-tenant-name-invalid-key';
  const encryptedDefaultPassword = buildEncryptedSensitiveConfigValue({
    plainText: defaultPassword,
    decryptionKey
  });
  const context = {
    authService: createAuthService({
      seedUsers: [
        {
          id: 'platform-provision-operator-tenant-name-invalid',
          phone: '13846660012',
          password: 'Passw0rd!',
          status: 'active',
          domains: ['platform'],
          platformRoles: [
            {
              roleId: 'platform-member-admin-operator',
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
      ],
      sensitiveConfigProvider: createSensitiveConfigProvider({
        encryptedDefaultPassword
      }),
      sensitiveConfigDecryptionKey: decryptionKey
    }),
    dependencyProbe
  };

  const operatorLogin = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: {
        phone: '13846660012',
        password: 'Passw0rd!',
        entry_domain: 'platform'
      }
    },
    context
  );
  assert.equal(operatorLogin.status, 200);

  const provisioned = await callRoute(
    {
      pathname: '/auth/platform/member-admin/provision-user',
      method: 'POST',
      headers: {
        authorization: `Bearer ${operatorLogin.body.access_token}`
      },
      body: {
        phone: '13846660013',
        tenant_name: 'Tenant Should Not Be Accepted'
      }
    },
    context
  );
  assert.equal(provisioned.status, 400);
  assert.equal(provisioned.body.error_code, 'AUTH-400-INVALID-PAYLOAD');
});

test('platform member-admin provision-user endpoint rejects unknown payload property', async () => {
  const defaultPassword = 'InitPass!2026';
  const decryptionKey = 'api-platform-provision-unknown-field-key';
  const encryptedDefaultPassword = buildEncryptedSensitiveConfigValue({
    plainText: defaultPassword,
    decryptionKey
  });
  const context = {
    authService: createAuthService({
      seedUsers: [
        {
          id: 'platform-provision-operator-unknown-field',
          phone: '13846660014',
          password: 'Passw0rd!',
          status: 'active',
          domains: ['platform'],
          platformRoles: [
            {
              roleId: 'platform-member-admin-operator',
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
      ],
      sensitiveConfigProvider: createSensitiveConfigProvider({
        encryptedDefaultPassword
      }),
      sensitiveConfigDecryptionKey: decryptionKey
    }),
    dependencyProbe
  };

  const operatorLogin = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: {
        phone: '13846660014',
        password: 'Passw0rd!',
        entry_domain: 'platform'
      }
    },
    context
  );
  assert.equal(operatorLogin.status, 200);

  const provisioned = await callRoute(
    {
      pathname: '/auth/platform/member-admin/provision-user',
      method: 'POST',
      headers: {
        authorization: `Bearer ${operatorLogin.body.access_token}`
      },
      body: {
        phone: '13846660015',
        extra_flag: true
      }
    },
    context
  );
  assert.equal(provisioned.status, 400);
  assert.equal(provisioned.body.error_code, 'AUTH-400-INVALID-PAYLOAD');
});

test('tenant member-admin provision-user endpoint creates tenant relationship and rejects duplicate relationship requests', async () => {
  const defaultPassword = 'InitPass!2026';
  const decryptionKey = 'api-tenant-provision-key';
  const encryptedDefaultPassword = buildEncryptedSensitiveConfigValue({
    plainText: defaultPassword,
    decryptionKey
  });
  const context = {
    authService: createAuthService({
      seedUsers: [
        {
          id: 'tenant-provision-operator',
          phone: '13846660020',
          password: 'Passw0rd!',
          status: 'active',
          domains: ['tenant'],
          tenants: [
            {
              tenantId: 'tenant-api-a',
              tenantName: 'Tenant API A',
              permission: {
                canViewMemberAdmin: true,
                canOperateMemberAdmin: true,
                canViewBilling: false,
                canOperateBilling: false
              }
            }
          ]
        }
      ],
      sensitiveConfigProvider: createSensitiveConfigProvider({
        encryptedDefaultPassword
      }),
      sensitiveConfigDecryptionKey: decryptionKey
    }),
    dependencyProbe
  };

  const operatorLogin = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: {
        phone: '13846660020',
        password: 'Passw0rd!',
        entry_domain: 'tenant'
      }
    },
    context
  );
  assert.equal(operatorLogin.status, 200);
  assert.equal(operatorLogin.body.active_tenant_id, 'tenant-api-a');

  const provisioned = await callRoute(
    {
      pathname: '/auth/tenant/member-admin/provision-user',
      method: 'POST',
      headers: {
        authorization: `Bearer ${operatorLogin.body.access_token}`
      },
      body: {
        phone: '13846660021',
        tenant_name: 'Tenant API A'
      }
    },
    context
  );
  assert.equal(provisioned.status, 200);
  assert.equal(provisioned.body.entry_domain, 'tenant');
  assert.equal(provisioned.body.active_tenant_id, 'tenant-api-a');

  const duplicateProvision = await callRoute(
    {
      pathname: '/auth/tenant/member-admin/provision-user',
      method: 'POST',
      headers: {
        authorization: `Bearer ${operatorLogin.body.access_token}`
      },
      body: {
        phone: '13846660021',
        tenant_name: 'Tenant API A'
      }
    },
    context
  );
  assert.equal(duplicateProvision.status, 409);
  assert.equal(duplicateProvision.body.error_code, 'AUTH-409-PROVISION-CONFLICT');
});

test('tenant member-admin provision-user endpoint reuses existing user without mutating password hash', async () => {
  const defaultPassword = 'InitPass!2026';
  const decryptionKey = 'api-tenant-provision-reuse-key';
  const encryptedDefaultPassword = buildEncryptedSensitiveConfigValue({
    plainText: defaultPassword,
    decryptionKey
  });
  const context = {
    authService: createAuthService({
      seedUsers: [
        {
          id: 'tenant-provision-operator-reuse',
          phone: '13846660040',
          password: 'Passw0rd!',
          status: 'active',
          domains: ['tenant'],
          tenants: [
            {
              tenantId: 'tenant-api-reuse-a',
              tenantName: 'Tenant API Reuse A',
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
          id: 'tenant-provision-reuse-target',
          phone: '13846660041',
          password: 'LegacyPass!2026',
          status: 'active',
          domains: []
        }
      ],
      sensitiveConfigProvider: createSensitiveConfigProvider({
        encryptedDefaultPassword
      }),
      sensitiveConfigDecryptionKey: decryptionKey
    }),
    dependencyProbe
  };

  const operatorLogin = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: {
        phone: '13846660040',
        password: 'Passw0rd!',
        entry_domain: 'tenant'
      }
    },
    context
  );
  assert.equal(operatorLogin.status, 200);

  const previousUser = await context.authService._internals.authStore.findUserByPhone('13846660041');
  const previousPasswordHash = previousUser.passwordHash;

  const provisioned = await callRoute(
    {
      pathname: '/auth/tenant/member-admin/provision-user',
      method: 'POST',
      headers: {
        authorization: `Bearer ${operatorLogin.body.access_token}`
      },
      body: {
        phone: '13846660041',
        tenant_name: 'Tenant API Reuse A'
      }
    },
    context
  );
  assert.equal(provisioned.status, 200);
  assert.equal(provisioned.body.created_user, false);
  assert.equal(provisioned.body.reused_existing_user, true);
  assert.equal(provisioned.body.active_tenant_id, 'tenant-api-reuse-a');

  const currentUser = await context.authService._internals.authStore.findUserByPhone('13846660041');
  assert.equal(currentUser.passwordHash, previousPasswordHash);
});

test('tenant member-admin provision-user endpoint returns conflict when tenant domain remains unavailable after relationship provisioning', async () => {
  const defaultPassword = 'InitPass!2026';
  const decryptionKey = 'api-tenant-provision-domain-disabled-key';
  const encryptedDefaultPassword = buildEncryptedSensitiveConfigValue({
    plainText: defaultPassword,
    decryptionKey
  });
  const context = {
    authService: createAuthService({
      seedUsers: [
        {
          id: 'tenant-provision-domain-disabled-operator',
          phone: '13846660060',
          password: 'Passw0rd!',
          status: 'active',
          domains: ['tenant'],
          tenants: [
            {
              tenantId: 'tenant-api-domain-disabled-a',
              tenantName: 'Tenant API Domain Disabled A',
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
          id: 'tenant-provision-domain-disabled-target',
          phone: '13846660061',
          password: 'LegacyPass!2026',
          status: 'active',
          domains: []
        }
      ],
      sensitiveConfigProvider: createSensitiveConfigProvider({
        encryptedDefaultPassword
      }),
      sensitiveConfigDecryptionKey: decryptionKey
    }),
    dependencyProbe
  };

  const operatorLogin = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: {
        phone: '13846660060',
        password: 'Passw0rd!',
        entry_domain: 'tenant'
      }
    },
    context
  );
  assert.equal(operatorLogin.status, 200);

  const authStore = context.authService._internals.authStore;
  const originalFindDomainAccessByUserId = authStore.findDomainAccessByUserId.bind(authStore);
  const originalEnsureTenantDomainAccessForUser = authStore.ensureTenantDomainAccessForUser
    .bind(authStore);
  authStore.findDomainAccessByUserId = async (userId) => {
    if (String(userId) === 'tenant-provision-domain-disabled-target') {
      return { platform: false, tenant: false };
    }
    return originalFindDomainAccessByUserId(userId);
  };
  authStore.ensureTenantDomainAccessForUser = async (userId) => {
    if (String(userId) === 'tenant-provision-domain-disabled-target') {
      return { inserted: false };
    }
    return originalEnsureTenantDomainAccessForUser(userId);
  };

  const provisioned = await callRoute(
    {
      pathname: '/auth/tenant/member-admin/provision-user',
      method: 'POST',
      headers: {
        authorization: `Bearer ${operatorLogin.body.access_token}`
      },
      body: {
        phone: '13846660061',
        tenant_name: 'Tenant API Domain Disabled A'
      }
    },
    context
  );
  assert.equal(provisioned.status, 409);
  assert.equal(provisioned.body.error_code, 'AUTH-409-PROVISION-CONFLICT');
  const tenantOptions = await authStore.listTenantOptionsByUserId(
    'tenant-provision-domain-disabled-target'
  );
  assert.equal(
    tenantOptions.some((option) => option.tenantId === 'tenant-api-domain-disabled-a'),
    false
  );
});

test('tenant member-admin provision-user endpoint rejects oversized tenant_name', async () => {
  const defaultPassword = 'InitPass!2026';
  const decryptionKey = 'api-tenant-provision-name-validation-key';
  const encryptedDefaultPassword = buildEncryptedSensitiveConfigValue({
    plainText: defaultPassword,
    decryptionKey
  });
  const context = {
    authService: createAuthService({
      seedUsers: [
        {
          id: 'tenant-provision-operator-name-validation',
          phone: '13846660050',
          password: 'Passw0rd!',
          status: 'active',
          domains: ['tenant'],
          tenants: [
            {
              tenantId: 'tenant-api-name-validation-a',
              tenantName: 'Tenant API Name Validation A',
              permission: {
                canViewMemberAdmin: true,
                canOperateMemberAdmin: true,
                canViewBilling: false,
                canOperateBilling: false
              }
            }
          ]
        }
      ],
      sensitiveConfigProvider: createSensitiveConfigProvider({
        encryptedDefaultPassword
      }),
      sensitiveConfigDecryptionKey: decryptionKey
    }),
    dependencyProbe
  };

  const operatorLogin = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: {
        phone: '13846660050',
        password: 'Passw0rd!',
        entry_domain: 'tenant'
      }
    },
    context
  );
  assert.equal(operatorLogin.status, 200);

  const provisioned = await callRoute(
    {
      pathname: '/auth/tenant/member-admin/provision-user',
      method: 'POST',
      headers: {
        authorization: `Bearer ${operatorLogin.body.access_token}`
      },
      body: {
        phone: '13846660051',
        tenant_name: 'X'.repeat(129)
      }
    },
    context
  );
  assert.equal(provisioned.status, 400);
  assert.equal(provisioned.body.error_code, 'AUTH-400-INVALID-PAYLOAD');
});

test('tenant member-admin provision-user endpoint rejects tenant_name with oversized raw payload length', async () => {
  const defaultPassword = 'InitPass!2026';
  const decryptionKey = 'api-tenant-provision-raw-length-key';
  const encryptedDefaultPassword = buildEncryptedSensitiveConfigValue({
    plainText: defaultPassword,
    decryptionKey
  });
  const context = {
    authService: createAuthService({
      seedUsers: [
        {
          id: 'tenant-provision-operator-raw-length',
          phone: '13846660024',
          password: 'Passw0rd!',
          status: 'active',
          domains: ['tenant'],
          tenants: [
            {
              tenantId: 'tenant-api-raw-length-a',
              tenantName: 'Tenant API Raw Length A',
              permission: {
                canViewMemberAdmin: true,
                canOperateMemberAdmin: true,
                canViewBilling: false,
                canOperateBilling: false
              }
            }
          ]
        }
      ],
      sensitiveConfigProvider: createSensitiveConfigProvider({
        encryptedDefaultPassword
      }),
      sensitiveConfigDecryptionKey: decryptionKey
    }),
    dependencyProbe
  };

  const operatorLogin = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: {
        phone: '13846660024',
        password: 'Passw0rd!',
        entry_domain: 'tenant'
      }
    },
    context
  );
  assert.equal(operatorLogin.status, 200);

  const paddedTenantName = ` ${'X'.repeat(128)} `;
  const provisioned = await callRoute(
    {
      pathname: '/auth/tenant/member-admin/provision-user',
      method: 'POST',
      headers: {
        authorization: `Bearer ${operatorLogin.body.access_token}`
      },
      body: {
        phone: '13846660025',
        tenant_name: paddedTenantName
      }
    },
    context
  );
  assert.equal(provisioned.status, 400);
  assert.equal(provisioned.body.error_code, 'AUTH-400-INVALID-PAYLOAD');
});

test('tenant member-admin provision-user endpoint rejects blank tenant_name', async () => {
  const defaultPassword = 'InitPass!2026';
  const decryptionKey = 'api-tenant-provision-name-blank-validation-key';
  const encryptedDefaultPassword = buildEncryptedSensitiveConfigValue({
    plainText: defaultPassword,
    decryptionKey
  });
  const context = {
    authService: createAuthService({
      seedUsers: [
        {
          id: 'tenant-provision-operator-name-blank-validation',
          phone: '13846660052',
          password: 'Passw0rd!',
          status: 'active',
          domains: ['tenant'],
          tenants: [
            {
              tenantId: 'tenant-api-name-blank-validation-a',
              tenantName: 'Tenant API Name Blank Validation A',
              permission: {
                canViewMemberAdmin: true,
                canOperateMemberAdmin: true,
                canViewBilling: false,
                canOperateBilling: false
              }
            }
          ]
        }
      ],
      sensitiveConfigProvider: createSensitiveConfigProvider({
        encryptedDefaultPassword
      }),
      sensitiveConfigDecryptionKey: decryptionKey
    }),
    dependencyProbe
  };

  const operatorLogin = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: {
        phone: '13846660052',
        password: 'Passw0rd!',
        entry_domain: 'tenant'
      }
    },
    context
  );
  assert.equal(operatorLogin.status, 200);

  const provisioned = await callRoute(
    {
      pathname: '/auth/tenant/member-admin/provision-user',
      method: 'POST',
      headers: {
        authorization: `Bearer ${operatorLogin.body.access_token}`
      },
      body: {
        phone: '13846660053',
        tenant_name: '   '
      }
    },
    context
  );
  assert.equal(provisioned.status, 400);
  assert.equal(provisioned.body.error_code, 'AUTH-400-INVALID-PAYLOAD');
});

test('tenant member-admin provision-user endpoint rejects unknown payload property', async () => {
  const defaultPassword = 'InitPass!2026';
  const decryptionKey = 'api-tenant-provision-unknown-field-key';
  const encryptedDefaultPassword = buildEncryptedSensitiveConfigValue({
    plainText: defaultPassword,
    decryptionKey
  });
  const context = {
    authService: createAuthService({
      seedUsers: [
        {
          id: 'tenant-provision-operator-unknown-field',
          phone: '13846660026',
          password: 'Passw0rd!',
          status: 'active',
          domains: ['tenant'],
          tenants: [
            {
              tenantId: 'tenant-api-unknown-field-a',
              tenantName: 'Tenant API Unknown Field A',
              permission: {
                canViewMemberAdmin: true,
                canOperateMemberAdmin: true,
                canViewBilling: false,
                canOperateBilling: false
              }
            }
          ]
        }
      ],
      sensitiveConfigProvider: createSensitiveConfigProvider({
        encryptedDefaultPassword
      }),
      sensitiveConfigDecryptionKey: decryptionKey
    }),
    dependencyProbe
  };

  const operatorLogin = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: {
        phone: '13846660026',
        password: 'Passw0rd!',
        entry_domain: 'tenant'
      }
    },
    context
  );
  assert.equal(operatorLogin.status, 200);

  const provisioned = await callRoute(
    {
      pathname: '/auth/tenant/member-admin/provision-user',
      method: 'POST',
      headers: {
        authorization: `Bearer ${operatorLogin.body.access_token}`
      },
      body: {
        phone: '13846660027',
        tenant_name: 'Tenant API Unknown Field A',
        extra_flag: true
      }
    },
    context
  );
  assert.equal(provisioned.status, 400);
  assert.equal(provisioned.body.error_code, 'AUTH-400-INVALID-PAYLOAD');
});

test('tenant member-admin provision-user endpoint rejects tenant_name that mismatches active tenant canonical name', async () => {
  const defaultPassword = 'InitPass!2026';
  const decryptionKey = 'api-tenant-provision-name-canonical-key';
  const encryptedDefaultPassword = buildEncryptedSensitiveConfigValue({
    plainText: defaultPassword,
    decryptionKey
  });
  const context = {
    authService: createAuthService({
      seedUsers: [
        {
          id: 'tenant-provision-operator-name-canonical',
          phone: '13846660070',
          password: 'Passw0rd!',
          status: 'active',
          domains: ['tenant'],
          tenants: [
            {
              tenantId: 'tenant-api-name-canonical-a',
              tenantName: 'Tenant API Name Canonical A',
              permission: {
                canViewMemberAdmin: true,
                canOperateMemberAdmin: true,
                canViewBilling: false,
                canOperateBilling: false
              }
            }
          ]
        }
      ],
      sensitiveConfigProvider: createSensitiveConfigProvider({
        encryptedDefaultPassword
      }),
      sensitiveConfigDecryptionKey: decryptionKey
    }),
    dependencyProbe
  };

  const operatorLogin = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: {
        phone: '13846660070',
        password: 'Passw0rd!',
        entry_domain: 'tenant'
      }
    },
    context
  );
  assert.equal(operatorLogin.status, 200);

  const provisioned = await callRoute(
    {
      pathname: '/auth/tenant/member-admin/provision-user',
      method: 'POST',
      headers: {
        authorization: `Bearer ${operatorLogin.body.access_token}`
      },
      body: {
        phone: '13846660071',
        tenant_name: 'Tenant Name Spoofed By Caller'
      }
    },
    context
  );
  assert.equal(provisioned.status, 400);
  assert.equal(provisioned.body.error_code, 'AUTH-400-INVALID-PAYLOAD');
  const unexpectedUser = await context.authService._internals.authStore.findUserByPhone('13846660071');
  assert.equal(unexpectedUser, null);
});

test('tenant member-admin provision-user endpoint rejects caller tenant_name when active tenant canonical name is unavailable', async () => {
  const defaultPassword = 'InitPass!2026';
  const decryptionKey = 'api-tenant-provision-name-missing-canonical-key';
  const encryptedDefaultPassword = buildEncryptedSensitiveConfigValue({
    plainText: defaultPassword,
    decryptionKey
  });
  const context = {
    authService: createAuthService({
      seedUsers: [
        {
          id: 'tenant-provision-operator-name-missing-canonical',
          phone: '13846660072',
          password: 'Passw0rd!',
          status: 'active',
          domains: ['tenant'],
          tenants: [
            {
              tenantId: 'tenant-api-name-missing-canonical-a',
              tenantName: null,
              permission: {
                canViewMemberAdmin: true,
                canOperateMemberAdmin: true,
                canViewBilling: false,
                canOperateBilling: false
              }
            }
          ]
        }
      ],
      sensitiveConfigProvider: createSensitiveConfigProvider({
        encryptedDefaultPassword
      }),
      sensitiveConfigDecryptionKey: decryptionKey
    }),
    dependencyProbe
  };

  const operatorLogin = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: {
        phone: '13846660072',
        password: 'Passw0rd!',
        entry_domain: 'tenant'
      }
    },
    context
  );
  assert.equal(operatorLogin.status, 200);

  const provisioned = await callRoute(
    {
      pathname: '/auth/tenant/member-admin/provision-user',
      method: 'POST',
      headers: {
        authorization: `Bearer ${operatorLogin.body.access_token}`
      },
      body: {
        phone: '13846660073',
        tenant_name: 'Tenant Name Spoofed By Caller'
      }
    },
    context
  );
  assert.equal(provisioned.status, 400);
  assert.equal(provisioned.body.error_code, 'AUTH-400-INVALID-PAYLOAD');
  const unexpectedUser = await context.authService._internals.authStore.findUserByPhone('13846660073');
  assert.equal(unexpectedUser, null);
});

test('tenant member-admin provision-user endpoint rejects request when active tenant canonical name is unavailable even without tenant_name payload', async () => {
  const defaultPassword = 'InitPass!2026';
  const decryptionKey = 'api-tenant-provision-name-missing-canonical-implicit-key';
  const encryptedDefaultPassword = buildEncryptedSensitiveConfigValue({
    plainText: defaultPassword,
    decryptionKey
  });
  const context = {
    authService: createAuthService({
      seedUsers: [
        {
          id: 'tenant-provision-operator-name-missing-canonical-implicit',
          phone: '13846660074',
          password: 'Passw0rd!',
          status: 'active',
          domains: ['tenant'],
          tenants: [
            {
              tenantId: 'tenant-api-name-missing-canonical-implicit-a',
              tenantName: null,
              permission: {
                canViewMemberAdmin: true,
                canOperateMemberAdmin: true,
                canViewBilling: false,
                canOperateBilling: false
              }
            }
          ]
        }
      ],
      sensitiveConfigProvider: createSensitiveConfigProvider({
        encryptedDefaultPassword
      }),
      sensitiveConfigDecryptionKey: decryptionKey
    }),
    dependencyProbe
  };

  const operatorLogin = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: {
        phone: '13846660074',
        password: 'Passw0rd!',
        entry_domain: 'tenant'
      }
    },
    context
  );
  assert.equal(operatorLogin.status, 200);

  const provisioned = await callRoute(
    {
      pathname: '/auth/tenant/member-admin/provision-user',
      method: 'POST',
      headers: {
        authorization: `Bearer ${operatorLogin.body.access_token}`
      },
      body: {
        phone: '13846660075'
      }
    },
    context
  );
  assert.equal(provisioned.status, 400);
  assert.equal(provisioned.body.error_code, 'AUTH-400-INVALID-PAYLOAD');
  const unexpectedUser = await context.authService._internals.authStore.findUserByPhone('13846660075');
  assert.equal(unexpectedUser, null);
});

test('platform member-admin provision-user endpoint is fail-closed when default password secure config is unavailable', async () => {
  const context = {
    authService: createAuthService({
      seedUsers: [
        {
          id: 'platform-provision-operator-config-fail',
          phone: '13846660030',
          password: 'Passw0rd!',
          status: 'active',
          domains: ['platform'],
          platformRoles: [
            {
              roleId: 'platform-member-admin-operator',
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
      ],
      sensitiveConfigProvider: createSensitiveConfigProvider({
        encryptedDefaultPassword: ''
      }),
      sensitiveConfigDecryptionKey: ''
    }),
    dependencyProbe
  };

  const operatorLogin = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: {
        phone: '13846660030',
        password: 'Passw0rd!',
        entry_domain: 'platform'
      }
    },
    context
  );
  assert.equal(operatorLogin.status, 200);

  const provisionFailed = await callRoute(
    {
      pathname: '/auth/platform/member-admin/provision-user',
      method: 'POST',
      headers: {
        authorization: `Bearer ${operatorLogin.body.access_token}`
      },
      body: {
        phone: '13846660031'
      }
    },
    context
  );
  assert.equal(provisionFailed.status, 503);
  assert.equal(provisionFailed.body.error_code, 'AUTH-503-PROVISION-CONFIG-UNAVAILABLE');
  assert.equal(provisionFailed.body.retryable, true);
});

test('platform member-admin provision-user endpoint maps unexpected dependency failures to stable 503 problem details', async () => {
  const context = {
    authService: createAuthService({
      seedUsers: [
        {
          id: 'platform-provision-operator-unexpected-failure',
          phone: '13846660032',
          password: 'Passw0rd!',
          status: 'active',
          domains: ['platform'],
          platformRoles: [
            {
              roleId: 'platform-member-admin-operator',
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
    }),
    dependencyProbe
  };

  const operatorLogin = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: {
        phone: '13846660032',
        password: 'Passw0rd!',
        entry_domain: 'platform'
      }
    },
    context
  );
  assert.equal(operatorLogin.status, 200);

  context.authService.provisionPlatformUserByPhone = async () => {
    throw new Error('provision dependency timeout');
  };

  const provisionFailed = await callRoute(
    {
      pathname: '/auth/platform/member-admin/provision-user',
      method: 'POST',
      headers: {
        authorization: `Bearer ${operatorLogin.body.access_token}`
      },
      body: {
        phone: '13846660033'
      }
    },
    context
  );
  assert.equal(provisionFailed.status, 503);
  assert.equal(provisionFailed.body.error_code, 'AUTH-503-PROVISION-CONFIG-UNAVAILABLE');
  assert.equal(provisionFailed.body.retryable, true);
});

test('tenant member-admin provision-user endpoint maps unexpected dependency failures to stable 503 problem details', async () => {
  const context = {
    authService: createAuthService({
      seedUsers: [
        {
          id: 'tenant-provision-operator-unexpected-failure',
          phone: '13846660034',
          password: 'Passw0rd!',
          status: 'active',
          domains: ['tenant'],
          tenants: [
            {
              tenantId: 'tenant-unexpected-failure-a',
              tenantName: 'Tenant Unexpected Failure A',
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
    }),
    dependencyProbe
  };

  const operatorLogin = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: {
        phone: '13846660034',
        password: 'Passw0rd!',
        entry_domain: 'tenant'
      }
    },
    context
  );
  assert.equal(operatorLogin.status, 200);

  context.authService.provisionTenantUserByPhone = async () => {
    throw new Error('provision dependency timeout');
  };

  const provisionFailed = await callRoute(
    {
      pathname: '/auth/tenant/member-admin/provision-user',
      method: 'POST',
      headers: {
        authorization: `Bearer ${operatorLogin.body.access_token}`
      },
      body: {
        phone: '13846660035'
      }
    },
    context
  );
  assert.equal(provisionFailed.status, 503);
  assert.equal(provisionFailed.body.error_code, 'AUTH-503-PROVISION-CONFIG-UNAVAILABLE');
  assert.equal(provisionFailed.body.retryable, true);
});

test('platform member-admin provision-user replays the same Idempotency-Key with stable semantics', async () => {
  const defaultPassword = 'InitPass!2026';
  const decryptionKey = 'api-platform-provision-idempotency-key';
  const encryptedDefaultPassword = buildEncryptedSensitiveConfigValue({
    plainText: defaultPassword,
    decryptionKey
  });
  const context = {
    authService: createAuthService({
      seedUsers: [
        {
          id: 'platform-provision-operator-idempotency',
          phone: '13846660090',
          password: 'Passw0rd!',
          status: 'active',
          domains: ['platform'],
          platformRoles: [
            {
              roleId: 'platform-member-admin-operator',
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
      ],
      sensitiveConfigProvider: createSensitiveConfigProvider({
        encryptedDefaultPassword
      }),
      sensitiveConfigDecryptionKey: decryptionKey
    }),
    dependencyProbe
  };

  const operatorLogin = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: {
        phone: '13846660090',
        password: 'Passw0rd!',
        entry_domain: 'platform'
      }
    },
    context
  );
  assert.equal(operatorLogin.status, 200);

  const idempotencyKey = 'idem-platform-provision-001';
  const firstProvision = await callRoute(
    {
      pathname: '/auth/platform/member-admin/provision-user',
      method: 'POST',
      headers: {
        authorization: `Bearer ${operatorLogin.body.access_token}`,
        'idempotency-key': idempotencyKey
      },
      body: {
        phone: '13846660091'
      }
    },
    context
  );
  assert.equal(firstProvision.status, 200);
  assert.equal(firstProvision.body.created_user, true);

  const replayProvision = await callRoute(
    {
      pathname: '/auth/platform/member-admin/provision-user',
      method: 'POST',
      headers: {
        authorization: `Bearer ${operatorLogin.body.access_token}`,
        'idempotency-key': idempotencyKey
      },
      body: {
        phone: '13846660091'
      }
    },
    context
  );
  assert.equal(replayProvision.status, 200);
  assertSamePayloadWithFreshRequestId(replayProvision.body, firstProvision.body);

  const idempotencyHitEvents = context.authService._internals.auditTrail.filter(
    (event) => event.type === 'auth.idempotency.hit'
  );
  assert.ok(idempotencyHitEvents.length >= 1);
});

test('platform member-admin provision-user keeps idempotency semantics after refresh token rotation', async () => {
  const defaultPassword = 'InitPass!2026';
  const decryptionKey = 'api-platform-provision-idempotency-refresh';
  const encryptedDefaultPassword = buildEncryptedSensitiveConfigValue({
    plainText: defaultPassword,
    decryptionKey
  });
  const context = {
    authService: createAuthService({
      seedUsers: [
        {
          id: 'platform-provision-operator-idempotency-refresh',
          phone: '13846660097',
          password: 'Passw0rd!',
          status: 'active',
          domains: ['platform'],
          platformRoles: [
            {
              roleId: 'platform-member-admin-operator',
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
      ],
      sensitiveConfigProvider: createSensitiveConfigProvider({
        encryptedDefaultPassword
      }),
      sensitiveConfigDecryptionKey: decryptionKey
    }),
    dependencyProbe
  };

  const operatorLogin = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: {
        phone: '13846660097',
        password: 'Passw0rd!',
        entry_domain: 'platform'
      }
    },
    context
  );
  assert.equal(operatorLogin.status, 200);

  const idempotencyKey = 'idem-platform-provision-004';
  const firstProvision = await callRoute(
    {
      pathname: '/auth/platform/member-admin/provision-user',
      method: 'POST',
      headers: {
        authorization: `Bearer ${operatorLogin.body.access_token}`,
        'idempotency-key': idempotencyKey
      },
      body: {
        phone: '13846660098'
      }
    },
    context
  );
  assert.equal(firstProvision.status, 200);

  const refreshed = await callRoute(
    {
      pathname: '/auth/refresh',
      method: 'POST',
      body: {
        refresh_token: operatorLogin.body.refresh_token
      }
    },
    context
  );
  assert.equal(refreshed.status, 200);

  const replayAfterRefresh = await callRoute(
    {
      pathname: '/auth/platform/member-admin/provision-user',
      method: 'POST',
      headers: {
        authorization: `Bearer ${refreshed.body.access_token}`,
        'idempotency-key': idempotencyKey
      },
      body: {
        phone: '13846660098'
      }
    },
    context
  );
  assert.equal(replayAfterRefresh.status, 200);
  assertSamePayloadWithFreshRequestId(replayAfterRefresh.body, firstProvision.body);
});

test('platform member-admin provision-user rejects payload drift when Idempotency-Key is reused', async () => {
  const defaultPassword = 'InitPass!2026';
  const decryptionKey = 'api-platform-provision-idempotency-conflict';
  const encryptedDefaultPassword = buildEncryptedSensitiveConfigValue({
    plainText: defaultPassword,
    decryptionKey
  });
  const context = {
    authService: createAuthService({
      seedUsers: [
        {
          id: 'platform-provision-operator-idempotency-conflict',
          phone: '13846660092',
          password: 'Passw0rd!',
          status: 'active',
          domains: ['platform'],
          platformRoles: [
            {
              roleId: 'platform-member-admin-operator',
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
      ],
      sensitiveConfigProvider: createSensitiveConfigProvider({
        encryptedDefaultPassword
      }),
      sensitiveConfigDecryptionKey: decryptionKey
    }),
    dependencyProbe
  };

  const operatorLogin = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: {
        phone: '13846660092',
        password: 'Passw0rd!',
        entry_domain: 'platform'
      }
    },
    context
  );
  assert.equal(operatorLogin.status, 200);

  const idempotencyKey = 'idem-platform-provision-002';
  const firstProvision = await callRoute(
    {
      pathname: '/auth/platform/member-admin/provision-user',
      method: 'POST',
      headers: {
        authorization: `Bearer ${operatorLogin.body.access_token}`,
        'idempotency-key': idempotencyKey
      },
      body: {
        phone: '13846660093'
      }
    },
    context
  );
  assert.equal(firstProvision.status, 200);

  const mismatchedReplay = await callRoute(
    {
      pathname: '/auth/platform/member-admin/provision-user',
      method: 'POST',
      headers: {
        authorization: `Bearer ${operatorLogin.body.access_token}`,
        'idempotency-key': idempotencyKey
      },
      body: {
        phone: '13846660094'
      }
    },
    context
  );
  assert.equal(mismatchedReplay.status, 409);
  assert.equal(mismatchedReplay.body.error_code, 'AUTH-409-IDEMPOTENCY-CONFLICT');
  assert.equal(mismatchedReplay.body.retryable, false);

  const unexpectedUser = await context.authService._internals.authStore.findUserByPhone(
    '13846660094'
  );
  assert.equal(unexpectedUser, null);

  const idempotencyConflictEvents = context.authService._internals.auditTrail.filter(
    (event) => event.type === 'auth.idempotency.conflict'
  );
  assert.ok(idempotencyConflictEvents.length >= 1);
});

test('platform member-admin provision-user deduplicates concurrent replays with the same Idempotency-Key', async () => {
  const defaultPassword = 'InitPass!2026';
  const decryptionKey = 'api-platform-provision-idempotency-concurrent';
  const encryptedDefaultPassword = buildEncryptedSensitiveConfigValue({
    plainText: defaultPassword,
    decryptionKey
  });
  const context = {
    authService: createAuthService({
      seedUsers: [
        {
          id: 'platform-provision-operator-idempotency-concurrent',
          phone: '13846660095',
          password: 'Passw0rd!',
          status: 'active',
          domains: ['platform'],
          platformRoles: [
            {
              roleId: 'platform-member-admin-operator',
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
      ],
      sensitiveConfigProvider: createSensitiveConfigProvider({
        encryptedDefaultPassword
      }),
      sensitiveConfigDecryptionKey: decryptionKey
    }),
    dependencyProbe
  };

  const operatorLogin = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: {
        phone: '13846660095',
        password: 'Passw0rd!',
        entry_domain: 'platform'
      }
    },
    context
  );
  assert.equal(operatorLogin.status, 200);

  const idempotencyKey = 'idem-platform-provision-003';
  const request = () =>
    callRoute(
      {
        pathname: '/auth/platform/member-admin/provision-user',
        method: 'POST',
        headers: {
          authorization: `Bearer ${operatorLogin.body.access_token}`,
          'idempotency-key': idempotencyKey
        },
        body: {
          phone: '13846660096'
        }
      },
      context
    );

  const [first, second] = await Promise.all([request(), request()]);
  assert.equal(first.status, 200);
  assert.equal(second.status, 200);
  assertSamePayloadWithFreshRequestId(second.body, first.body);
});

test('tenant member-admin provision-user treats equivalent payloads with different JSON key order as the same idempotent request', async () => {
  const defaultPassword = 'InitPass!2026';
  const decryptionKey = 'api-tenant-provision-idempotency-key-order';
  const encryptedDefaultPassword = buildEncryptedSensitiveConfigValue({
    plainText: defaultPassword,
    decryptionKey
  });
  const context = {
    authService: createAuthService({
      seedUsers: [
        {
          id: 'tenant-provision-operator-idempotency-order',
          phone: '13846660110',
          password: 'Passw0rd!',
          status: 'active',
          domains: ['tenant'],
          tenants: [
            {
              tenantId: 'tenant-idempotency-key-order',
              tenantName: 'Tenant Idempotency Key Order',
              permission: {
                canViewMemberAdmin: true,
                canOperateMemberAdmin: true,
                canViewBilling: false,
                canOperateBilling: false
              }
            }
          ]
        }
      ],
      sensitiveConfigProvider: createSensitiveConfigProvider({
        encryptedDefaultPassword
      }),
      sensitiveConfigDecryptionKey: decryptionKey
    }),
    dependencyProbe
  };

  const operatorLogin = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: {
        phone: '13846660110',
        password: 'Passw0rd!',
        entry_domain: 'tenant'
      }
    },
    context
  );
  assert.equal(operatorLogin.status, 200);

  const idempotencyKey = 'idem-tenant-provision-order-001';
  const firstProvision = await callRoute(
    {
      pathname: '/auth/tenant/member-admin/provision-user',
      method: 'POST',
      headers: {
        authorization: `Bearer ${operatorLogin.body.access_token}`,
        'idempotency-key': idempotencyKey
      },
      body: {
        phone: '13846660111',
        tenant_name: 'Tenant Idempotency Key Order'
      }
    },
    context
  );
  assert.equal(firstProvision.status, 200);

  const replayWithReorderedPayload = await callRoute(
    {
      pathname: '/auth/tenant/member-admin/provision-user',
      method: 'POST',
      headers: {
        authorization: `Bearer ${operatorLogin.body.access_token}`,
        'idempotency-key': idempotencyKey
      },
      body: {
        tenant_name: 'Tenant Idempotency Key Order',
        phone: '13846660111'
      }
    },
    context
  );
  assert.equal(replayWithReorderedPayload.status, 200);
  assertSamePayloadWithFreshRequestId(
    replayWithReorderedPayload.body,
    firstProvision.body
  );
});

test('platform member-admin provision-user rejects invalid Idempotency-Key header values', async () => {
  const defaultPassword = 'InitPass!2026';
  const decryptionKey = 'api-platform-provision-idempotency-invalid';
  const encryptedDefaultPassword = buildEncryptedSensitiveConfigValue({
    plainText: defaultPassword,
    decryptionKey
  });
  const context = {
    authService: createAuthService({
      seedUsers: [
        {
          id: 'platform-provision-operator-idempotency-invalid',
          phone: '13846660120',
          password: 'Passw0rd!',
          status: 'active',
          domains: ['platform'],
          platformRoles: [
            {
              roleId: 'platform-member-admin-operator',
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
      ],
      sensitiveConfigProvider: createSensitiveConfigProvider({
        encryptedDefaultPassword
      }),
      sensitiveConfigDecryptionKey: decryptionKey
    }),
    dependencyProbe
  };

  const operatorLogin = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: {
        phone: '13846660120',
        password: 'Passw0rd!',
        entry_domain: 'platform'
      }
    },
    context
  );
  assert.equal(operatorLogin.status, 200);

  const invalidIdempotencyKey = 'x'.repeat(129);
  const invalidHeaderResponse = await callRoute(
    {
      pathname: '/auth/platform/member-admin/provision-user',
      method: 'POST',
      headers: {
        authorization: `Bearer ${operatorLogin.body.access_token}`,
        'idempotency-key': invalidIdempotencyKey
      },
      body: {
        phone: '13846660121'
      }
    },
    context
  );
  assert.equal(invalidHeaderResponse.status, 400);
  assert.equal(invalidHeaderResponse.body.error_code, 'AUTH-400-IDEMPOTENCY-KEY-INVALID');
  assert.equal(invalidHeaderResponse.body.retryable, false);

  const unexpectedUser = await context.authService._internals.authStore.findUserByPhone(
    '13846660121'
  );
  assert.equal(unexpectedUser, null);
});

test('tenant member-admin provision-user applies idempotency replay and payload drift conflict semantics', async () => {
  const defaultPassword = 'InitPass!2026';
  const decryptionKey = 'api-tenant-provision-idempotency';
  const encryptedDefaultPassword = buildEncryptedSensitiveConfigValue({
    plainText: defaultPassword,
    decryptionKey
  });
  const context = {
    authService: createAuthService({
      seedUsers: [
        {
          id: 'tenant-provision-operator-idempotency',
          phone: '13846660100',
          password: 'Passw0rd!',
          status: 'active',
          domains: ['tenant'],
          tenants: [
            {
              tenantId: 'tenant-idempotency-a',
              tenantName: 'Tenant Idempotency A',
              permission: {
                canViewMemberAdmin: true,
                canOperateMemberAdmin: true,
                canViewBilling: false,
                canOperateBilling: false
              }
            }
          ]
        }
      ],
      sensitiveConfigProvider: createSensitiveConfigProvider({
        encryptedDefaultPassword
      }),
      sensitiveConfigDecryptionKey: decryptionKey
    }),
    dependencyProbe
  };

  const operatorLogin = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: {
        phone: '13846660100',
        password: 'Passw0rd!',
        entry_domain: 'tenant'
      }
    },
    context
  );
  assert.equal(operatorLogin.status, 200);
  assert.equal(operatorLogin.body.active_tenant_id, 'tenant-idempotency-a');

  const idempotencyKey = 'idem-tenant-provision-001';
  const firstProvision = await callRoute(
    {
      pathname: '/auth/tenant/member-admin/provision-user',
      method: 'POST',
      headers: {
        authorization: `Bearer ${operatorLogin.body.access_token}`,
        'idempotency-key': idempotencyKey
      },
      body: {
        phone: '13846660101',
        tenant_name: 'Tenant Idempotency A'
      }
    },
    context
  );
  assert.equal(firstProvision.status, 200);

  const replayProvision = await callRoute(
    {
      pathname: '/auth/tenant/member-admin/provision-user',
      method: 'POST',
      headers: {
        authorization: `Bearer ${operatorLogin.body.access_token}`,
        'idempotency-key': idempotencyKey
      },
      body: {
        phone: '13846660101',
        tenant_name: 'Tenant Idempotency A'
      }
    },
    context
  );
  assert.equal(replayProvision.status, 200);
  assertSamePayloadWithFreshRequestId(replayProvision.body, firstProvision.body);

  const payloadDrift = await callRoute(
    {
      pathname: '/auth/tenant/member-admin/provision-user',
      method: 'POST',
      headers: {
        authorization: `Bearer ${operatorLogin.body.access_token}`,
        'idempotency-key': idempotencyKey
      },
      body: {
        phone: '13846660102',
        tenant_name: 'Tenant Idempotency A'
      }
    },
    context
  );
  assert.equal(payloadDrift.status, 409);
  assert.equal(payloadDrift.body.error_code, 'AUTH-409-IDEMPOTENCY-CONFLICT');
  assert.equal(payloadDrift.body.retryable, false);

  const unexpectedUser = await context.authService._internals.authStore.findUserByPhone(
    '13846660102'
  );
  assert.equal(unexpectedUser, null);
});
