const test = require('node:test');
const assert = require('node:assert/strict');
const { handleApiRoute } = require('../src/server');
const { readConfig } = require('../src/config/env');
const { createAuthService } = require('../src/modules/auth/auth.service');

const config = readConfig({ ALLOW_MOCK_BACKENDS: 'true' });
const tenantPermissionA = {
  scopeLabel: '组织权限快照 A',
  canViewMemberAdmin: true,
  canOperateMemberAdmin: true,
  canViewBilling: true,
  canOperateBilling: false
};
const tenantPermissionB = {
  scopeLabel: '组织权限快照 B',
  canViewMemberAdmin: false,
  canOperateMemberAdmin: false,
  canViewBilling: true,
  canOperateBilling: true
};

const dependencyProbe = async () => ({
  db: { ok: true, detail: 'db ok' },
  redis: { ok: true, detail: 'redis ok' }
});

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

test('tenant login with multiple tenants requires explicit selection', async () => {
  const context = {
    dependencyProbe,
    authService: createAuthService({
      seedUsers: [
        {
          id: 'domain-user-1',
          phone: '13820000000',
          password: 'Passw0rd!',
          status: 'active',
          domains: ['platform', 'tenant'],
          tenants: [
            { tenantId: 'tenant-a', tenantName: 'Tenant A', permission: tenantPermissionA },
            { tenantId: 'tenant-b', tenantName: 'Tenant B', permission: tenantPermissionB }
          ]
        }
      ]
    })
  };

  const login = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: {
        phone: '13820000000',
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
  assert.equal(login.body.tenant_options.length, 2);
  assert.deepEqual(login.body.tenant_permission_context, {
    scope_label: '组织未选择（无可操作权限）',
    can_view_member_admin: false,
    can_operate_member_admin: false,
    can_view_billing: false,
    can_operate_billing: false
  });

  const options = await callRoute(
    {
      pathname: '/auth/tenant/options',
      method: 'GET',
      headers: {
        authorization: `Bearer ${login.body.access_token}`
      }
    },
    context
  );
  assert.equal(options.status, 200);
  assert.equal(options.body.tenant_selection_required, true);

  const select = await callRoute(
    {
      pathname: '/auth/tenant/select',
      method: 'POST',
      headers: {
        authorization: `Bearer ${login.body.access_token}`
      },
      body: { tenant_id: 'tenant-b' }
    },
    context
  );
  assert.equal(select.status, 200);
  assert.equal(select.body.active_tenant_id, 'tenant-b');
  assert.deepEqual(select.body.tenant_permission_context, {
    scope_label: '组织权限快照 B',
    can_view_member_admin: false,
    can_operate_member_admin: false,
    can_view_billing: true,
    can_operate_billing: true
  });
});

test('tenant login rejects users without tenant membership and domain access using AUTH-403-NO-DOMAIN', async () => {
  const context = {
    dependencyProbe,
    authService: createAuthService({
      seedUsers: [
        {
          id: 'domain-user-2',
          phone: '13820000001',
          password: 'Passw0rd!',
          status: 'active',
          domains: [],
          tenants: []
        }
      ]
    })
  };

  const response = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: {
        phone: '13820000001',
        password: 'Passw0rd!',
        entry_domain: 'tenant'
      }
    },
    context
  );

  assert.equal(response.status, 403);
  assert.equal(response.body.error_code, 'AUTH-403-NO-DOMAIN');
});

test('tenant switch updates active_tenant_id and rejects unknown tenant options', async () => {
  const context = {
    dependencyProbe,
    authService: createAuthService({
      seedUsers: [
        {
          id: 'domain-user-3',
          phone: '13820000002',
          password: 'Passw0rd!',
          status: 'active',
          domains: ['platform', 'tenant'],
          tenants: [
            { tenantId: 'tenant-a', tenantName: 'Tenant A', permission: tenantPermissionA },
            { tenantId: 'tenant-b', tenantName: 'Tenant B', permission: tenantPermissionB }
          ]
        }
      ]
    })
  };

  const login = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: {
        phone: '13820000002',
        password: 'Passw0rd!',
        entry_domain: 'tenant'
      }
    },
    context
  );
  assert.equal(login.status, 200);

  const select = await callRoute(
    {
      pathname: '/auth/tenant/select',
      method: 'POST',
      headers: {
        authorization: `Bearer ${login.body.access_token}`
      },
      body: { tenant_id: 'tenant-a' }
    },
    context
  );
  assert.equal(select.status, 200);
  assert.equal(select.body.active_tenant_id, 'tenant-a');

  const switched = await callRoute(
    {
      pathname: '/auth/tenant/switch',
      method: 'POST',
      headers: {
        authorization: `Bearer ${login.body.access_token}`
      },
      body: { tenant_id: 'tenant-b' }
    },
    context
  );
  assert.equal(switched.status, 200);
  assert.equal(switched.body.active_tenant_id, 'tenant-b');

  const denied = await callRoute(
    {
      pathname: '/auth/tenant/switch',
      method: 'POST',
      headers: {
        authorization: `Bearer ${login.body.access_token}`
      },
      body: { tenant_id: 'tenant-x' }
    },
    context
  );
  assert.equal(denied.status, 403);
  assert.equal(denied.body.error_code, 'AUTH-403-NO-DOMAIN');
});

test('tenant options in platform entry returns empty tenant_options', async () => {
  const context = {
    dependencyProbe,
    authService: createAuthService({
      seedUsers: [
        {
          id: 'domain-user-4',
          phone: '13820000003',
          password: 'Passw0rd!',
          status: 'active',
          domains: ['platform', 'tenant'],
          tenants: [
            { tenantId: 'tenant-a', tenantName: 'Tenant A', permission: tenantPermissionA },
            { tenantId: 'tenant-b', tenantName: 'Tenant B', permission: tenantPermissionB }
          ]
        }
      ]
    })
  };

  const login = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: {
        phone: '13820000003',
        password: 'Passw0rd!',
        entry_domain: 'platform'
      }
    },
    context
  );
  assert.equal(login.status, 200);
  assert.equal(login.body.entry_domain, 'platform');

  const options = await callRoute(
    {
      pathname: '/auth/tenant/options',
      method: 'GET',
      headers: {
        authorization: `Bearer ${login.body.access_token}`
      }
    },
    context
  );

  assert.equal(options.status, 200);
  assert.equal(options.body.entry_domain, 'platform');
  assert.equal(options.body.tenant_selection_required, false);
  assert.equal(options.body.active_tenant_id, null);
  assert.deepEqual(options.body.tenant_options, []);
  assert.deepEqual(options.body.tenant_permission_context, {
    scope_label: '平台入口（无组织侧权限上下文）',
    can_view_member_admin: false,
    can_operate_member_admin: false,
    can_view_billing: false,
    can_operate_billing: false
  });
});
