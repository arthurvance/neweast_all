const test = require('node:test');
const assert = require('node:assert/strict');
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

const decodeJwtPayload = (token) => {
  const parts = String(token || '').split('.');
  if (parts.length < 2) {
    return {};
  }
  return JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
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
        roles: []
      }
    },
    context
  );
  assert.equal(replaced.status, 200);
  assert.equal(replaced.body.synced, true);
  assert.equal(replaced.body.reason, 'ok');
  assert.deepEqual(replaced.body.platform_permission_context, {
    scope_label: '平台权限（角色并集）',
    can_view_member_admin: false,
    can_operate_member_admin: false,
    can_view_billing: false,
    can_operate_billing: false
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
        roles: []
      }
    },
    context
  );

  assert.equal(replaced.status, 503);
  assert.equal(replaced.body.error_code, 'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED');
});
