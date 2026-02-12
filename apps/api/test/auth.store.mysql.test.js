const test = require('node:test');
const assert = require('node:assert/strict');
const { createMySqlAuthStore } = require('../src/modules/auth/auth.store.mysql');

const createStore = (queryImpl) =>
  createMySqlAuthStore({
    dbClient: {
      query: queryImpl,
      inTransaction: async (runner) =>
        runner({
          query: queryImpl
        })
    }
  });

test('findDomainAccessByUserId reads active domain rows from mysql storage', async () => {
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (normalizedSql.includes('FROM auth_user_domain_access')) {
      return [{ domain: 'platform' }, { domain: 'tenant' }];
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  const access = await store.findDomainAccessByUserId('u-1');
  assert.deepEqual(access, { platform: true, tenant: true });
});

test('findDomainAccessByUserId denies platform by default when explicit domain rows missing', async () => {
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (normalizedSql.includes('FROM auth_user_domain_access')) {
      return [];
    }
    if (normalizedSql.includes('FROM auth_user_tenants')) {
      return [{ tenant_count: 1 }];
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  const access = await store.findDomainAccessByUserId('u-2');
  assert.deepEqual(access, { platform: false, tenant: true });
});

test('findDomainAccessByUserId returns no domain access when explicit rows and tenant relations are missing', async () => {
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (normalizedSql.includes('FROM auth_user_domain_access')) {
      return [];
    }
    if (normalizedSql.includes('FROM auth_user_tenants')) {
      return [{ tenant_count: 0 }];
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  const access = await store.findDomainAccessByUserId('u-2b');
  assert.deepEqual(access, { platform: false, tenant: false });
});

test('findDomainAccessByUserId keeps tenant domain accessible when only platform row exists but tenant memberships are active', async () => {
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (normalizedSql.includes('FROM auth_user_domain_access')) {
      return [{ domain: 'platform', status: 'active' }];
    }
    if (normalizedSql.includes('COUNT(*) AS tenant_count')) {
      return [{ tenant_count: 2 }];
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  const access = await store.findDomainAccessByUserId('u-2c');
  assert.deepEqual(access, { platform: true, tenant: true });
});

test('ensureDefaultDomainAccessForUser inserts platform domain access when user has no domain rows', async () => {
  let insertCalled = false;
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (normalizedSql.includes('COUNT(*) AS domain_count')) {
      return [{ domain_count: 0 }];
    }
    if (normalizedSql.includes('INSERT INTO auth_user_domain_access')) {
      insertCalled = true;
      return { affectedRows: 1 };
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  const result = await store.ensureDefaultDomainAccessForUser('u-new');
  assert.equal(insertCalled, true);
  assert.deepEqual(result, { inserted: true });
});

test('ensureDefaultDomainAccessForUser does nothing when domain rows already exist', async () => {
  let insertCalled = false;
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (normalizedSql.includes('COUNT(*) AS domain_count')) {
      return [{ domain_count: 1 }];
    }
    if (normalizedSql.includes('INSERT INTO auth_user_domain_access')) {
      insertCalled = true;
      return { affectedRows: 1 };
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  const result = await store.ensureDefaultDomainAccessForUser('u-existing');
  assert.equal(insertCalled, false);
  assert.deepEqual(result, { inserted: false });
});

test('findDomainAccessByUserId surfaces schema errors for missing domain access table', async () => {
  const store = createStore(async (sql) => {
    if (String(sql).includes('FROM auth_user_domain_access')) {
      const error = new Error('Table not found');
      error.code = 'ER_NO_SUCH_TABLE';
      throw error;
    }
    return [];
  });

  await assert.rejects(
    () => store.findDomainAccessByUserId('u-legacy'),
    /Table not found/
  );
});

test('listTenantOptionsByUserId returns active tenant options from mysql storage', async () => {
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (normalizedSql.includes('FROM auth_user_tenants')) {
      return [
        { tenant_id: 'tenant-a', tenant_name: 'Tenant A' },
        { tenant_id: 'tenant-b', tenant_name: null }
      ];
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  const options = await store.listTenantOptionsByUserId('u-3');
  assert.deepEqual(options, [
    { tenantId: 'tenant-a', tenantName: 'Tenant A' },
    { tenantId: 'tenant-b', tenantName: null }
  ]);
});

test('findTenantPermissionByUserAndTenantId surfaces schema errors for missing permission columns', async () => {
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (normalizedSql.includes('can_view_member_admin')) {
      const error = new Error('Unknown column can_view_member_admin');
      error.code = 'ER_BAD_FIELD_ERROR';
      throw error;
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  await assert.rejects(
    () =>
      store.findTenantPermissionByUserAndTenantId({
        userId: 'u-4',
        tenantId: 'tenant-a'
      }),
    /Unknown column can_view_member_admin/
  );
});

test('findTenantPermissionByUserAndTenantId reads permission columns when available', async () => {
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (normalizedSql.includes('can_view_member_admin')) {
      return [
        {
          tenant_id: 'tenant-z',
          tenant_name: 'Tenant Z',
          can_view_member_admin: 1,
          can_operate_member_admin: 0,
          can_view_billing: 1,
          can_operate_billing: 1
        }
      ];
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  const permission = await store.findTenantPermissionByUserAndTenantId({
    userId: 'u-5',
    tenantId: 'tenant-z'
  });
  assert.deepEqual(permission, {
    scopeLabel: '组织权限（Tenant Z）',
    canViewMemberAdmin: true,
    canOperateMemberAdmin: false,
    canViewBilling: true,
    canOperateBilling: true
  });
});
