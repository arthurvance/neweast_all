const test = require('node:test');
const assert = require('node:assert/strict');
const { createMySqlAuthStore } = require('../src/modules/auth/auth.store.mysql');

const createStore = (queryImpl, options = {}) =>
  createMySqlAuthStore({
    dbClient: {
      query: queryImpl,
      inTransaction: async (runner) =>
        runner({
          query: queryImpl
        })
    },
    ...options
  });

const createDeadlockError = (message = 'Deadlock found when trying to get lock') => {
  const error = new Error(message);
  error.code = 'ER_LOCK_DEADLOCK';
  error.errno = 1213;
  error.sqlState = '40001';
  return error;
};

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

test('findDomainAccessByUserId treats enabled domain rows as accessible', async () => {
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (normalizedSql.includes('FROM auth_user_domain_access')) {
      return [
        { domain: 'platform', status: 'enabled' },
        { domain: 'tenant', status: 'enabled' }
      ];
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  const access = await store.findDomainAccessByUserId('u-enabled-domain');
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
  let insertStatement = '';
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (normalizedSql.includes('COUNT(*) AS domain_count')) {
      return [{ domain_count: 0 }];
    }
    if (normalizedSql.includes('auth_user_domain_access')) {
      insertCalled = true;
      insertStatement = normalizedSql;
      return { affectedRows: 1 };
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  const result = await store.ensureDefaultDomainAccessForUser('u-new');
  assert.equal(insertCalled, true);
  assert.equal(/INSERT\s+IGNORE\s+INTO\s+auth_user_domain_access/i.test(insertStatement), true);
  assert.equal(/status\s*=\s*VALUES\(status\)/i.test(insertStatement), false);
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

test('ensureDefaultDomainAccessForUser does not re-enable status in duplicate-key race path', async () => {
  let insertStatement = '';
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (normalizedSql.includes('COUNT(*) AS domain_count')) {
      return [{ domain_count: 0 }];
    }
    if (normalizedSql.includes('auth_user_domain_access')) {
      insertStatement = normalizedSql;
      // Simulate duplicate-key ignored insert from concurrent writer.
      return { affectedRows: 0 };
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  const result = await store.ensureDefaultDomainAccessForUser('u-race');
  assert.equal(/INSERT\s+IGNORE\s+INTO\s+auth_user_domain_access/i.test(insertStatement), true);
  assert.equal(/status\s*=\s*VALUES\(status\)/i.test(insertStatement), false);
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

test('hasAnyTenantRelationshipByUserId returns true when tenant relationships exist regardless of status', async () => {
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (normalizedSql.includes('COUNT(*) AS tenant_count')) {
      return [{ tenant_count: 1 }];
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  const exists = await store.hasAnyTenantRelationshipByUserId('u-has-tenant');
  assert.equal(exists, true);
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

test('findPlatformPermissionByUserId is fail-closed without explicit platform permission snapshot', async () => {
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (normalizedSql.includes('FROM auth_user_domain_access')) {
      return [{ status: 'active', domain: 'platform' }];
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  const permission = await store.findPlatformPermissionByUserId({ userId: 'u-platform-1' });
  assert.equal(permission, null);
});

test('findPlatformPermissionByUserId reads explicit platform permission snapshot columns when available', async () => {
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (normalizedSql.includes('FROM auth_user_domain_access')) {
      return [
        {
          status: 'enabled',
          can_view_member_admin: 1,
          can_operate_member_admin: 0,
          can_view_billing: '1',
          can_operate_billing: false
        }
      ];
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  const permission = await store.findPlatformPermissionByUserId({ userId: 'u-platform-2' });
  assert.deepEqual(permission, {
    scopeLabel: '平台权限（服务端快照）',
    canViewMemberAdmin: true,
    canOperateMemberAdmin: false,
    canViewBilling: true,
    canOperateBilling: false
  });
});

test('syncPlatformPermissionSnapshotByUserId recalculates platform snapshot from active role facts', async () => {
  let updateParams = null;
  const store = createStore(async (sql, params) => {
    const normalizedSql = String(sql);
    if (
      normalizedSql.includes('FROM auth_user_domain_access')
      && normalizedSql.includes("domain = 'platform'")
      && normalizedSql.includes('LIMIT 1')
    ) {
      return [
        {
          can_view_member_admin: 0,
          can_operate_member_admin: 0,
          can_view_billing: 0,
          can_operate_billing: 0,
          updated_at: '2026-02-14T00:00:00.000Z'
        }
      ];
    }
    if (normalizedSql.includes('COUNT(*) AS role_count')) {
      return [{ role_count: 2, latest_role_updated_at: '2026-02-14T00:00:02.000Z' }];
    }
    if (normalizedSql.includes('SELECT role_id')) {
      return [
        {
          role_id: 'platform-view',
          status: 'active',
          can_view_member_admin: 1,
          can_operate_member_admin: 0,
          can_view_billing: 0,
          can_operate_billing: 0
        },
        {
          role_id: 'platform-disabled',
          status: 'disabled',
          can_view_member_admin: 1,
          can_operate_member_admin: 1,
          can_view_billing: 1,
          can_operate_billing: 1
        }
      ];
    }
    if (normalizedSql.includes('UPDATE auth_user_domain_access')) {
      updateParams = params;
      return { affectedRows: 1 };
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  const result = await store.syncPlatformPermissionSnapshotByUserId({
    userId: 'u-sync-1'
  });
  assert.equal(result.synced, true);
  assert.deepEqual(result.permission, {
    scopeLabel: '平台权限（角色并集）',
    canViewMemberAdmin: true,
    canOperateMemberAdmin: false,
    canViewBilling: false,
    canOperateBilling: false
  });
  assert.deepEqual(updateParams, [
    1,
    0,
    0,
    0,
    'u-sync-1',
    1,
    0,
    0,
    0,
    'u-sync-1',
    2,
    'u-sync-1',
    '2026-02-14T00:00:02.000Z',
    null,
    'u-sync-1',
    null
  ]);
});

test('syncPlatformPermissionSnapshotByUserId clears snapshot when role facts are empty in force mode', async () => {
  let zeroUpdateParams = null;
  const store = createStore(async (sql, params) => {
    const normalizedSql = String(sql);
    if (
      normalizedSql.includes('FROM auth_user_domain_access')
      && normalizedSql.includes("domain = 'platform'")
      && normalizedSql.includes('LIMIT 1')
    ) {
      return [
        {
          can_view_member_admin: 1,
          can_operate_member_admin: 1,
          can_view_billing: 1,
          can_operate_billing: 0,
          updated_at: '2026-02-14T00:00:03.000Z'
        }
      ];
    }
    if (normalizedSql.includes('COUNT(*) AS role_count')) {
      return [{ role_count: 0, latest_role_updated_at: null }];
    }
    if (
      normalizedSql.includes('UPDATE auth_user_domain_access')
      && normalizedSql.includes('SET can_view_member_admin = 0')
    ) {
      zeroUpdateParams = params;
      return { affectedRows: 1 };
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  const result = await store.syncPlatformPermissionSnapshotByUserId({
    userId: 'u-sync-empty',
    forceWhenNoRoleFacts: true
  });
  assert.equal(result.synced, true);
  assert.deepEqual(result.permission, {
    scopeLabel: '平台权限（角色并集）',
    canViewMemberAdmin: false,
    canOperateMemberAdmin: false,
    canViewBilling: false,
    canOperateBilling: false
  });
  assert.deepEqual(zeroUpdateParams, ['u-sync-empty', 'u-sync-empty']);
});

test('syncPlatformPermissionSnapshotByUserId skips role-row loading when snapshot is already up-to-date', async () => {
  let roleRowQueryCount = 0;
  let updateQueryCount = 0;
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (
      normalizedSql.includes('FROM auth_user_domain_access')
      && normalizedSql.includes("domain = 'platform'")
      && normalizedSql.includes('LIMIT 1')
    ) {
      return [
        {
          can_view_member_admin: 1,
          can_operate_member_admin: 0,
          can_view_billing: 0,
          can_operate_billing: 0,
          updated_at: '2026-02-14T00:01:00.000Z'
        }
      ];
    }
    if (normalizedSql.includes('COUNT(*) AS role_count')) {
      return [{ role_count: 1, latest_role_updated_at: '2026-02-14T00:00:10.000Z' }];
    }
    if (normalizedSql.includes('SELECT role_id')) {
      roleRowQueryCount += 1;
      return [];
    }
    if (normalizedSql.includes('UPDATE auth_user_domain_access')) {
      updateQueryCount += 1;
      return { affectedRows: 0 };
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  const result = await store.syncPlatformPermissionSnapshotByUserId({
    userId: 'u-sync-up-to-date'
  });
  assert.equal(result.synced, false);
  assert.equal(result.reason, 'up-to-date');
  assert.deepEqual(result.permission, {
    scopeLabel: '平台权限（角色并集）',
    canViewMemberAdmin: true,
    canOperateMemberAdmin: false,
    canViewBilling: false,
    canOperateBilling: false
  });
  assert.equal(roleRowQueryCount, 0);
  assert.equal(updateQueryCount, 0);
});

test('syncPlatformPermissionSnapshotByUserId does not short-circuit when snapshot timestamp equals latest role fact timestamp', async () => {
  let roleRowQueryCount = 0;
  let updateQueryCount = 0;
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (
      normalizedSql.includes('FROM auth_user_domain_access')
      && normalizedSql.includes("domain = 'platform'")
      && normalizedSql.includes('LIMIT 1')
    ) {
      return [
        {
          can_view_member_admin: 1,
          can_operate_member_admin: 0,
          can_view_billing: 0,
          can_operate_billing: 0,
          updated_at: '2026-02-14T00:00:10.000Z'
        }
      ];
    }
    if (normalizedSql.includes('COUNT(*) AS role_count')) {
      return [
        {
          role_count: 1,
          latest_role_updated_at: '2026-02-14T00:00:10.000Z',
          latest_role_updated_at_key: '2026-02-14 00:00:10.000000'
        }
      ];
    }
    if (normalizedSql.includes('SELECT role_id')) {
      roleRowQueryCount += 1;
      return [
        {
          role_id: 'role-platform-admin',
          status: 'active',
          can_view_member_admin: 1,
          can_operate_member_admin: 1,
          can_view_billing: 0,
          can_operate_billing: 0
        }
      ];
    }
    if (normalizedSql.includes('UPDATE auth_user_domain_access')) {
      updateQueryCount += 1;
      return { affectedRows: 1 };
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  const result = await store.syncPlatformPermissionSnapshotByUserId({
    userId: 'u-sync-equal-timestamp'
  });

  assert.equal(result.synced, true);
  assert.equal(result.reason, 'ok');
  assert.deepEqual(result.permission, {
    scopeLabel: '平台权限（角色并集）',
    canViewMemberAdmin: true,
    canOperateMemberAdmin: true,
    canViewBilling: false,
    canOperateBilling: false
  });
  assert.equal(roleRowQueryCount, 1);
  assert.equal(updateQueryCount, 1);
});

test('syncPlatformPermissionSnapshotByUserId aborts zeroing when role facts change concurrently', async () => {
  let summaryCallCount = 0;
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (
      normalizedSql.includes('FROM auth_user_domain_access')
      && normalizedSql.includes("domain = 'platform'")
      && normalizedSql.includes('LIMIT 1')
    ) {
      return [
        {
          can_view_member_admin: 1,
          can_operate_member_admin: 1,
          can_view_billing: 1,
          can_operate_billing: 0,
          updated_at: '2026-02-14T00:00:03.000Z'
        }
      ];
    }
    if (normalizedSql.includes('COUNT(*) AS role_count')) {
      summaryCallCount += 1;
      if (summaryCallCount === 1) {
        return [{ role_count: 0, latest_role_updated_at: null }];
      }
      return [{ role_count: 1, latest_role_updated_at: '2026-02-14T00:00:04.000Z' }];
    }
    if (
      normalizedSql.includes('UPDATE auth_user_domain_access')
      && normalizedSql.includes('SET can_view_member_admin = 0')
    ) {
      return { affectedRows: 0 };
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  const result = await store.syncPlatformPermissionSnapshotByUserId({
    userId: 'u-sync-concurrent-zero',
    forceWhenNoRoleFacts: true
  });

  assert.equal(result.synced, false);
  assert.equal(result.reason, 'concurrent-role-facts-update');
  assert.equal(result.permission, null);
  assert.equal(summaryCallCount, 2);
});

test('syncPlatformPermissionSnapshotByUserId aborts stale overwrite when role facts change concurrently', async () => {
  let summaryCallCount = 0;
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (
      normalizedSql.includes('FROM auth_user_domain_access')
      && normalizedSql.includes("domain = 'platform'")
      && normalizedSql.includes('LIMIT 1')
    ) {
      return [
        {
          can_view_member_admin: 0,
          can_operate_member_admin: 0,
          can_view_billing: 0,
          can_operate_billing: 0,
          updated_at: '2026-02-14T00:00:00.000Z'
        }
      ];
    }
    if (normalizedSql.includes('COUNT(*) AS role_count')) {
      summaryCallCount += 1;
      if (summaryCallCount === 1) {
        return [{ role_count: 1, latest_role_updated_at: '2026-02-14T00:00:02.000Z' }];
      }
      return [{ role_count: 2, latest_role_updated_at: '2026-02-14T00:00:03.000Z' }];
    }
    if (normalizedSql.includes('SELECT role_id')) {
      return [
        {
          role_id: 'platform-view',
          status: 'active',
          can_view_member_admin: 1,
          can_operate_member_admin: 0,
          can_view_billing: 0,
          can_operate_billing: 0
        }
      ];
    }
    if (normalizedSql.includes('UPDATE auth_user_domain_access')) {
      return { affectedRows: 0 };
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  const result = await store.syncPlatformPermissionSnapshotByUserId({
    userId: 'u-sync-concurrent-update'
  });

  assert.equal(result.synced, false);
  assert.equal(result.reason, 'concurrent-role-facts-update');
  assert.equal(result.permission, null);
  assert.equal(summaryCallCount, 2);
});

test('syncPlatformPermissionSnapshotByUserId detects concurrent role fact change when count and latest timestamp stay the same', async () => {
  let summaryCallCount = 0;
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (
      normalizedSql.includes('FROM auth_user_domain_access')
      && normalizedSql.includes("domain = 'platform'")
      && normalizedSql.includes('LIMIT 1')
    ) {
      return [
        {
          can_view_member_admin: 0,
          can_operate_member_admin: 0,
          can_view_billing: 0,
          can_operate_billing: 0,
          updated_at: '2026-02-14T00:00:00.000Z'
        }
      ];
    }
    if (normalizedSql.includes('COUNT(*) AS role_count')) {
      summaryCallCount += 1;
      if (summaryCallCount === 1) {
        return [
          {
            role_count: 2,
            latest_role_updated_at: '2026-02-14T00:00:03.000Z',
            latest_role_updated_at_key: '2026-02-14 00:00:03.000000',
            role_facts_checksum: '100'
          }
        ];
      }
      return [
        {
          role_count: 2,
          latest_role_updated_at: '2026-02-14T00:00:03.000Z',
          latest_role_updated_at_key: '2026-02-14 00:00:03.000000',
          role_facts_checksum: '101'
        }
      ];
    }
    if (normalizedSql.includes('SELECT role_id')) {
      return [
        {
          role_id: 'platform-view',
          status: 'active',
          can_view_member_admin: 1,
          can_operate_member_admin: 0,
          can_view_billing: 0,
          can_operate_billing: 0
        }
      ];
    }
    if (normalizedSql.includes('UPDATE auth_user_domain_access')) {
      return { affectedRows: 0 };
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  const result = await store.syncPlatformPermissionSnapshotByUserId({
    userId: 'u-sync-concurrent-checksum'
  });

  assert.equal(result.synced, false);
  assert.equal(result.reason, 'concurrent-role-facts-update');
  assert.equal(result.permission, null);
  assert.equal(summaryCallCount, 2);
});

test('replacePlatformRolesAndSyncSnapshot writes role facts and snapshot atomically', async () => {
  const statements = [];
  const store = createStore(async (sql, params) => {
    const normalizedSql = String(sql);
    statements.push(normalizedSql);

    if (normalizedSql.includes('DELETE FROM auth_user_platform_roles')) {
      return { affectedRows: 1 };
    }
    if (normalizedSql.includes('INSERT INTO auth_user_platform_roles')) {
      return { affectedRows: 1 };
    }
    if (normalizedSql.includes('INSERT INTO auth_user_domain_access')) {
      return { affectedRows: 1 };
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  const result = await store.replacePlatformRolesAndSyncSnapshot({
    userId: 'u-sync-2',
    roles: [
      {
        roleId: 'platform-view',
        status: 'active',
        permission: {
          canViewMemberAdmin: true,
          canOperateMemberAdmin: false,
          canViewBilling: false,
          canOperateBilling: false
        }
      },
      {
        roleId: 'platform-operate',
        status: 'active',
        permission: {
          canViewMemberAdmin: false,
          canOperateMemberAdmin: true,
          canViewBilling: true,
          canOperateBilling: false
        }
      },
      {
        roleId: 'platform-disabled',
        status: 'disabled',
        permission: {
          canViewMemberAdmin: false,
          canOperateMemberAdmin: false,
          canViewBilling: false,
          canOperateBilling: true
        }
      }
    ]
  });

  assert.deepEqual(result.permission, {
    scopeLabel: '平台权限（角色并集）',
    canViewMemberAdmin: true,
    canOperateMemberAdmin: true,
    canViewBilling: true,
    canOperateBilling: false
  });
  assert.equal(
    statements.some((statement) =>
      statement.includes('DELETE FROM auth_user_platform_roles')
    ),
    true
  );
  assert.equal(
    statements.some((statement) =>
      statement.includes('INSERT INTO auth_user_platform_roles')
    ),
    true
  );
  assert.equal(
    statements.some((statement) =>
      statement.includes('INSERT INTO auth_user_domain_access')
    ),
    true
  );
  const upsertDomainStatement = statements.find((statement) =>
    statement.includes('INSERT INTO auth_user_domain_access')
  );
  assert.ok(upsertDomainStatement);
  assert.equal(/status\s*=\s*VALUES\(status\)/i.test(upsertDomainStatement), false);
  assert.equal(/updated_at\s*=\s*CURRENT_TIMESTAMP\(3\)/i.test(upsertDomainStatement), true);
  const insertRoleStatement = statements.find((statement) =>
    statement.includes('INSERT INTO auth_user_platform_roles')
  );
  assert.ok(insertRoleStatement);
  assert.equal(/ON DUPLICATE KEY UPDATE/i.test(insertRoleStatement), false);
});

test('replacePlatformRolesAndSyncSnapshot deduplicates role facts by role_id before writing', async () => {
  const roleInsertParamsList = [];
  const store = createStore(async (sql, params) => {
    const normalizedSql = String(sql);

    if (normalizedSql.includes('DELETE FROM auth_user_platform_roles')) {
      return { affectedRows: 1 };
    }
    if (normalizedSql.includes('INSERT INTO auth_user_platform_roles')) {
      roleInsertParamsList.push(params);
      return { affectedRows: 1 };
    }
    if (normalizedSql.includes('INSERT INTO auth_user_domain_access')) {
      return { affectedRows: 1 };
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  await store.replacePlatformRolesAndSyncSnapshot({
    userId: 'u-sync-duplicate-role',
    roles: [
      {
        roleId: 'platform-member-admin',
        status: 'active',
        permission: {
          canViewMemberAdmin: false,
          canOperateMemberAdmin: false,
          canViewBilling: false,
          canOperateBilling: false
        }
      },
      {
        roleId: 'platform-member-admin',
        status: 'active',
        permission: {
          canViewMemberAdmin: true,
          canOperateMemberAdmin: false,
          canViewBilling: true,
          canOperateBilling: false
        }
      }
    ]
  });

  assert.equal(roleInsertParamsList.length, 1);
  assert.deepEqual(roleInsertParamsList[0], [
    'u-sync-duplicate-role',
    'platform-member-admin',
    'active',
    1,
    0,
    1,
    0
  ]);
});

test('replacePlatformRolesAndSyncSnapshot with empty roles does not create new platform domain row', async () => {
  const statements = [];
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    statements.push(normalizedSql);

    if (normalizedSql.includes('DELETE FROM auth_user_platform_roles')) {
      return { affectedRows: 1 };
    }
    if (normalizedSql.includes('UPDATE auth_user_domain_access')) {
      return { affectedRows: 1 };
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  const result = await store.replacePlatformRolesAndSyncSnapshot({
    userId: 'u-sync-empty-roles',
    roles: []
  });

  assert.deepEqual(result.permission, {
    scopeLabel: '平台权限（角色并集）',
    canViewMemberAdmin: false,
    canOperateMemberAdmin: false,
    canViewBilling: false,
    canOperateBilling: false
  });
  assert.equal(
    statements.some((statement) =>
      statement.includes('INSERT INTO auth_user_domain_access')
    ),
    false
  );
  assert.equal(
    statements.some((statement) =>
      statement.includes('UPDATE auth_user_domain_access')
    ),
    true
  );
  const updateStatement = statements.find((statement) =>
    statement.includes('UPDATE auth_user_domain_access')
  );
  assert.ok(updateStatement);
  assert.equal(/can_view_member_admin\s*<>\s*\?/i.test(updateStatement), true);
});

test('replacePlatformRolesAndSyncSnapshot rejects invalid platform role status', async () => {
  let queryCount = 0;
  const store = createStore(async () => {
    queryCount += 1;
    return [];
  });

  await assert.rejects(
    () =>
      store.replacePlatformRolesAndSyncSnapshot({
        userId: 'u-invalid-status',
        roles: [
          {
            roleId: 'platform-role-x',
            status: 'archived',
            permission: {
              canViewMemberAdmin: true
            }
          }
        ]
      }),
    /invalid platform role status: archived/
  );
  assert.equal(queryCount, 0);
});

test('syncPlatformPermissionSnapshotByUserId retries deadlock with backoff+jitter and records recovery metrics', async () => {
  let snapshotSelectAttempts = 0;
  const retryDelays = [];
  const deadlockMetrics = [];
  const store = createStore(
    async (sql) => {
      const normalizedSql = String(sql);
      if (
        normalizedSql.includes('FROM auth_user_domain_access')
        && normalizedSql.includes("domain = 'platform'")
        && normalizedSql.includes('LIMIT 1')
      ) {
        snapshotSelectAttempts += 1;
        if (snapshotSelectAttempts === 1) {
          throw createDeadlockError();
        }
        return [
          {
            can_view_member_admin: 0,
            can_operate_member_admin: 0,
            can_view_billing: 0,
            can_operate_billing: 0,
            updated_at: '2026-02-14T00:00:00.000Z'
          }
        ];
      }
      if (normalizedSql.includes('COUNT(*) AS role_count')) {
        return [{ role_count: 1, latest_role_updated_at: '2026-02-14T00:00:03.000Z' }];
      }
      if (normalizedSql.includes('SELECT role_id')) {
        return [
          {
            role_id: 'platform-view',
            status: 'active',
            can_view_member_admin: 1,
            can_operate_member_admin: 0,
            can_view_billing: 0,
            can_operate_billing: 0
          }
        ];
      }
      if (normalizedSql.includes('UPDATE auth_user_domain_access')) {
        return { affectedRows: 1 };
      }
      assert.fail(`unexpected query: ${normalizedSql}`);
      return [];
    },
    {
      sleepFn: async (delayMs) => {
        retryDelays.push(delayMs);
      },
      random: () => 0,
      deadlockRetryConfig: {
        maxRetries: 2,
        baseDelayMs: 10,
        maxDelayMs: 200,
        jitterMs: 8
      },
      onDeadlockMetric: (metric) => {
        deadlockMetrics.push(metric);
      }
    }
  );

  const result = await store.syncPlatformPermissionSnapshotByUserId({
    userId: 'u-sync-deadlock-recover'
  });

  assert.equal(result.synced, true);
  assert.equal(result.reason, 'ok');
  assert.equal(snapshotSelectAttempts, 2);
  assert.deepEqual(retryDelays, [10]);
  assert.ok(
    deadlockMetrics.some(
      (metric) =>
        metric.operation === 'syncPlatformPermissionSnapshotByUserId'
        && metric.event === 'deadlock-detected'
    )
  );
  assert.ok(
    deadlockMetrics.some(
      (metric) =>
        metric.operation === 'syncPlatformPermissionSnapshotByUserId'
        && metric.event === 'retry-succeeded'
        && metric.retry_success_count === 1
        && metric.final_failure_count === 0
    )
  );
  assert.deepEqual(store.getPlatformDeadlockMetrics(), {
    syncPlatformPermissionSnapshotByUserId: {
      deadlockCount: 1,
      retrySuccessCount: 1,
      finalFailureCount: 0,
      retrySuccessRate: 1,
      finalFailureRate: 0
    }
  });
});

test('syncPlatformPermissionSnapshotByUserId normalizes invalid random() output when computing retry delay', async () => {
  let snapshotSelectAttempts = 0;
  const retryDelays = [];
  const deadlockMetrics = [];
  const store = createStore(
    async (sql) => {
      const normalizedSql = String(sql);
      if (
        normalizedSql.includes('FROM auth_user_domain_access')
        && normalizedSql.includes("domain = 'platform'")
        && normalizedSql.includes('LIMIT 1')
      ) {
        snapshotSelectAttempts += 1;
        if (snapshotSelectAttempts === 1) {
          throw createDeadlockError();
        }
        return [
          {
            can_view_member_admin: 0,
            can_operate_member_admin: 0,
            can_view_billing: 0,
            can_operate_billing: 0,
            updated_at: '2026-02-14T00:00:00.000Z'
          }
        ];
      }
      if (normalizedSql.includes('COUNT(*) AS role_count')) {
        return [{ role_count: 1, latest_role_updated_at: '2026-02-14T00:00:03.000Z' }];
      }
      if (normalizedSql.includes('SELECT role_id')) {
        return [
          {
            role_id: 'platform-view',
            status: 'active',
            can_view_member_admin: 1,
            can_operate_member_admin: 0,
            can_view_billing: 0,
            can_operate_billing: 0
          }
        ];
      }
      if (normalizedSql.includes('UPDATE auth_user_domain_access')) {
        return { affectedRows: 1 };
      }
      assert.fail(`unexpected query: ${normalizedSql}`);
      return [];
    },
    {
      sleepFn: async (delayMs) => {
        retryDelays.push(delayMs);
      },
      random: () => Number.NaN,
      deadlockRetryConfig: {
        maxRetries: 1,
        baseDelayMs: 10,
        maxDelayMs: 10,
        jitterMs: 9
      },
      onDeadlockMetric: (metric) => {
        deadlockMetrics.push(metric);
      }
    }
  );

  const result = await store.syncPlatformPermissionSnapshotByUserId({
    userId: 'u-sync-deadlock-invalid-random'
  });

  assert.equal(result.synced, true);
  assert.equal(result.reason, 'ok');
  assert.equal(snapshotSelectAttempts, 2);
  assert.deepEqual(retryDelays, [10]);
  assert.ok(
    deadlockMetrics.some(
      (metric) =>
        metric.operation === 'syncPlatformPermissionSnapshotByUserId'
        && metric.event === 'deadlock-detected'
        && metric.retry_delay_ms === 10
    )
  );
});

test('syncPlatformPermissionSnapshotByUserId returns db-deadlock after retry exhaustion and emits final-failure metrics', async () => {
  let snapshotSelectAttempts = 0;
  const retryDelays = [];
  const deadlockMetrics = [];
  const store = createStore(
    async (sql) => {
      const normalizedSql = String(sql);
      if (
        normalizedSql.includes('FROM auth_user_domain_access')
        && normalizedSql.includes("domain = 'platform'")
        && normalizedSql.includes('LIMIT 1')
      ) {
        snapshotSelectAttempts += 1;
        throw createDeadlockError();
      }
      assert.fail(`unexpected query: ${normalizedSql}`);
      return [];
    },
    {
      sleepFn: async (delayMs) => {
        retryDelays.push(delayMs);
      },
      random: () => 0,
      deadlockRetryConfig: {
        maxRetries: 2,
        baseDelayMs: 10,
        maxDelayMs: 200,
        jitterMs: 0
      },
      onDeadlockMetric: (metric) => {
        deadlockMetrics.push(metric);
      }
    }
  );

  const result = await store.syncPlatformPermissionSnapshotByUserId({
    userId: 'u-sync-deadlock-fail'
  });

  assert.deepEqual(result, {
    synced: false,
    reason: 'db-deadlock',
    permission: null
  });
  assert.equal(snapshotSelectAttempts, 3);
  assert.deepEqual(retryDelays, [10, 20]);
  assert.ok(
    deadlockMetrics.some(
      (metric) =>
        metric.operation === 'syncPlatformPermissionSnapshotByUserId'
        && metric.event === 'final-failure'
        && metric.final_failure_count === 1
    )
  );
  assert.deepEqual(store.getPlatformDeadlockMetrics(), {
    syncPlatformPermissionSnapshotByUserId: {
      deadlockCount: 3,
      retrySuccessCount: 0,
      finalFailureCount: 1,
      retrySuccessRate: 0,
      finalFailureRate: 1
    }
  });
});

test('replacePlatformRolesAndSyncSnapshot retries deadlock with backoff+jitter and records recovery metrics', async () => {
  let deleteAttempts = 0;
  const retryDelays = [];
  const deadlockMetrics = [];
  const store = createStore(
    async (sql) => {
      const normalizedSql = String(sql);
      if (normalizedSql.includes('DELETE FROM auth_user_platform_roles')) {
        deleteAttempts += 1;
        if (deleteAttempts === 1) {
          throw createDeadlockError();
        }
        return { affectedRows: 1 };
      }
      if (normalizedSql.includes('INSERT INTO auth_user_platform_roles')) {
        return { affectedRows: 1 };
      }
      if (normalizedSql.includes('INSERT INTO auth_user_domain_access')) {
        return { affectedRows: 1 };
      }
      assert.fail(`unexpected query: ${normalizedSql}`);
      return [];
    },
    {
      sleepFn: async (delayMs) => {
        retryDelays.push(delayMs);
      },
      random: () => 0,
      deadlockRetryConfig: {
        maxRetries: 2,
        baseDelayMs: 15,
        maxDelayMs: 200,
        jitterMs: 5
      },
      onDeadlockMetric: (metric) => {
        deadlockMetrics.push(metric);
      }
    }
  );

  const result = await store.replacePlatformRolesAndSyncSnapshot({
    userId: 'u-replace-deadlock-recover',
    roles: [
      {
        roleId: 'platform-view',
        status: 'active',
        permission: {
          canViewMemberAdmin: true,
          canOperateMemberAdmin: false,
          canViewBilling: false,
          canOperateBilling: false
        }
      }
    ]
  });

  assert.equal(result.synced, true);
  assert.equal(result.reason, 'ok');
  assert.equal(deleteAttempts, 2);
  assert.deepEqual(retryDelays, [15]);
  assert.ok(
    deadlockMetrics.some(
      (metric) =>
        metric.operation === 'replacePlatformRolesAndSyncSnapshot'
        && metric.event === 'retry-succeeded'
        && metric.retry_success_count === 1
    )
  );
  assert.deepEqual(store.getPlatformDeadlockMetrics(), {
    replacePlatformRolesAndSyncSnapshot: {
      deadlockCount: 1,
      retrySuccessCount: 1,
      finalFailureCount: 0,
      retrySuccessRate: 1,
      finalFailureRate: 0
    }
  });
});

test('replacePlatformRolesAndSyncSnapshot returns db-deadlock after retry exhaustion and emits final-failure metrics', async () => {
  let deleteAttempts = 0;
  const retryDelays = [];
  const deadlockMetrics = [];
  const store = createStore(
    async (sql) => {
      const normalizedSql = String(sql);
      if (normalizedSql.includes('DELETE FROM auth_user_platform_roles')) {
        deleteAttempts += 1;
        throw createDeadlockError();
      }
      assert.fail(`unexpected query: ${normalizedSql}`);
      return [];
    },
    {
      sleepFn: async (delayMs) => {
        retryDelays.push(delayMs);
      },
      random: () => 0,
      deadlockRetryConfig: {
        maxRetries: 1,
        baseDelayMs: 12,
        maxDelayMs: 200,
        jitterMs: 0
      },
      onDeadlockMetric: (metric) => {
        deadlockMetrics.push(metric);
      }
    }
  );

  const result = await store.replacePlatformRolesAndSyncSnapshot({
    userId: 'u-replace-deadlock-fail',
    roles: [
      {
        roleId: 'platform-view',
        status: 'active',
        permission: {
          canViewMemberAdmin: true,
          canOperateMemberAdmin: false,
          canViewBilling: false,
          canOperateBilling: false
        }
      }
    ]
  });

  assert.deepEqual(result, {
    synced: false,
    reason: 'db-deadlock',
    permission: null
  });
  assert.equal(deleteAttempts, 2);
  assert.deepEqual(retryDelays, [12]);
  assert.ok(
    deadlockMetrics.some(
      (metric) =>
        metric.operation === 'replacePlatformRolesAndSyncSnapshot'
        && metric.event === 'final-failure'
        && metric.final_failure_count === 1
    )
  );
  assert.deepEqual(store.getPlatformDeadlockMetrics(), {
    replacePlatformRolesAndSyncSnapshot: {
      deadlockCount: 2,
      retrySuccessCount: 0,
      finalFailureCount: 1,
      retrySuccessRate: 0,
      finalFailureRate: 1
    }
  });
});
