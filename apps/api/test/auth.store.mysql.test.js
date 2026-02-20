const test = require('node:test');
const assert = require('node:assert/strict');
const { createMySqlAuthStore } = require('../src/modules/auth/auth.store.mysql');

const createStore = (queryImpl, options = {}) => {
  const {
    userExists = true,
    onUserLookupSql = null,
    ...storeOptions
  } = options;
  const wrappedQuery = async (sql, params) => {
    const normalizedSql = String(sql);
    if (
      normalizedSql.includes('SELECT id')
      && normalizedSql.includes('FROM users')
      && normalizedSql.includes('WHERE id = ?')
      && normalizedSql.includes('LIMIT 1')
      && !normalizedSql.includes('phone')
    ) {
      if (typeof onUserLookupSql === 'function') {
        onUserLookupSql(normalizedSql);
      }
      return userExists
        ? [{ id: String(params?.[0] || 'u-existing') }]
        : [];
    }
    return queryImpl(sql, params);
  };

  return createMySqlAuthStore({
    dbClient: {
      query: wrappedQuery,
      inTransaction: async (runner) =>
        runner({
          query: wrappedQuery
        })
    },
    ...storeOptions
  });
};

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
  let tenantCountSql = '';
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (normalizedSql.includes('FROM auth_user_domain_access')) {
      return [{ domain: 'platform', status: 'active' }];
    }
    if (normalizedSql.includes('COUNT(*) AS tenant_count')) {
      tenantCountSql = normalizedSql;
      return [{ tenant_count: 2 }];
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  const access = await store.findDomainAccessByUserId('u-2c');
  assert.deepEqual(access, { platform: true, tenant: true });
  assert.doesNotMatch(tenantCountSql, /o\.id IS NULL/i);
});

test('findDomainAccessByUserId falls back to legacy tenant query when orgs table is missing', async () => {
  let orgAwareCountQueryAttempts = 0;
  let legacyCountQueryAttempts = 0;
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (normalizedSql.includes('FROM auth_user_domain_access')) {
      return [];
    }
    if (normalizedSql.includes('COUNT(*) AS tenant_count')) {
      if (normalizedSql.includes('LEFT JOIN orgs')) {
        assert.doesNotMatch(normalizedSql, /o\.id IS NULL/i);
        orgAwareCountQueryAttempts += 1;
        const error = new Error("Table 'neweast.orgs' doesn't exist");
        error.code = 'ER_NO_SUCH_TABLE';
        error.errno = 1146;
        throw error;
      }
      legacyCountQueryAttempts += 1;
      return [{ tenant_count: 1 }];
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  const first = await store.findDomainAccessByUserId('u-legacy-fallback');
  const second = await store.findDomainAccessByUserId('u-legacy-fallback');
  assert.deepEqual(first, { platform: false, tenant: true });
  assert.deepEqual(second, { platform: false, tenant: true });
  assert.equal(orgAwareCountQueryAttempts, 1);
  assert.equal(legacyCountQueryAttempts, 2);
});

test('ensureDefaultDomainAccessForUser inserts platform domain access when user has no domain rows', async () => {
  let insertCalled = false;
  let insertStatement = '';
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (normalizedSql.includes('INSERT IGNORE INTO auth_user_domain_access')) {
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
  assert.equal(/ON\s+DUPLICATE\s+KEY\s+UPDATE/i.test(insertStatement), false);
  assert.equal(/VALUES\s*\(\?,\s*'platform',\s*'active'\)/i.test(insertStatement), true);
  assert.deepEqual(result, { inserted: true });
});

test('ensureDefaultDomainAccessForUser returns inserted=false when platform domain is already active', async () => {
  let upsertCalled = false;
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (normalizedSql.includes('INSERT IGNORE INTO auth_user_domain_access')) {
      upsertCalled = true;
      return { affectedRows: 0 };
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  const result = await store.ensureDefaultDomainAccessForUser('u-existing');
  assert.equal(upsertCalled, true);
  assert.deepEqual(result, { inserted: false });
});

test('ensureDefaultDomainAccessForUser does not re-enable disabled platform domain row', async () => {
  let insertStatement = '';
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (normalizedSql.includes('INSERT IGNORE INTO auth_user_domain_access')) {
      insertStatement = normalizedSql;
      // Existing disabled row keeps affectedRows=0 under INSERT IGNORE.
      return { affectedRows: 0 };
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  const result = await store.ensureDefaultDomainAccessForUser('u-race');
  assert.equal(/INSERT\s+IGNORE\s+INTO\s+auth_user_domain_access/i.test(insertStatement), true);
  assert.equal(/ON\s+DUPLICATE\s+KEY\s+UPDATE/i.test(insertStatement), false);
  assert.deepEqual(result, { inserted: false });
});

test('ensureDefaultDomainAccessForUser insert targets platform domain only', async () => {
  let upsertSql = '';
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (normalizedSql.includes('INSERT IGNORE INTO auth_user_domain_access')) {
      upsertSql = normalizedSql;
      return { affectedRows: 1 };
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  const result = await store.ensureDefaultDomainAccessForUser('u-platform-only-check');
  assert.equal(/VALUES\s*\(\?,\s*'platform',\s*'active'\)/i.test(upsertSql), true);
  assert.deepEqual(result, { inserted: true });
});

test('ensureTenantDomainAccessForUser re-enables disabled tenant domain row when active memberships exist', async () => {
  let upsertSql = '';
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (normalizedSql.includes('COUNT(*) AS tenant_count')) {
      return [{ tenant_count: 1 }];
    }
    if (normalizedSql.includes('INSERT INTO auth_user_domain_access')) {
      upsertSql = normalizedSql;
      return { affectedRows: 2 };
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  const result = await store.ensureTenantDomainAccessForUser('u-tenant-reactivate');
  assert.equal(/VALUES\s*\(\?,\s*'tenant',\s*'active'\)/i.test(upsertSql), true);
  assert.equal(/ON\s+DUPLICATE\s+KEY\s+UPDATE/i.test(upsertSql), true);
  assert.deepEqual(result, { inserted: true });
});

test('createUserByPhone inserts new user and returns normalized record', async () => {
  let insertedUserId = '';
  let insertedPhone = '';
  let insertedPasswordHash = '';
  let insertedStatus = '';
  const store = createStore(async (sql, params) => {
    const normalizedSql = String(sql);
    if (normalizedSql.includes('INSERT INTO users')) {
      insertedUserId = String(params?.[0] || '');
      insertedPhone = String(params?.[1] || '');
      insertedPasswordHash = String(params?.[2] || '');
      insertedStatus = String(params?.[3] || '');
      return { affectedRows: 1 };
    }
    if (
      normalizedSql.includes('SELECT id, phone, password_hash, status, session_version')
      && normalizedSql.includes('WHERE id = ?')
      && normalizedSql.includes('LIMIT 1')
      && !normalizedSql.includes('WHERE phone = ?')
    ) {
      return [
        {
          id: params?.[0],
          phone: insertedPhone,
          password_hash: insertedPasswordHash,
          status: insertedStatus,
          session_version: 1
        }
      ];
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  }, { userExists: false });

  const createdUser = await store.createUserByPhone({
    phone: '13846660000',
    passwordHash: 'pbkdf2$sha512$150000$salt$hash',
    status: 'active'
  });
  assert.ok(insertedUserId.length > 0);
  assert.equal(insertedPhone, '13846660000');
  assert.equal(insertedStatus, 'active');
  assert.deepEqual(createdUser, {
    id: insertedUserId,
    phone: '13846660000',
    passwordHash: 'pbkdf2$sha512$150000$salt$hash',
    status: 'active',
    sessionVersion: 1
  });
});

test('createUserByPhone returns null on duplicate phone insert race', async () => {
  const duplicateError = new Error('Duplicate entry for users.phone');
  duplicateError.code = 'ER_DUP_ENTRY';
  duplicateError.errno = 1062;

  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (normalizedSql.includes('INSERT INTO users')) {
      throw duplicateError;
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  }, { userExists: false });

  const createdUser = await store.createUserByPhone({
    phone: '13846660001',
    passwordHash: 'hash'
  });
  assert.equal(createdUser, null);
});

test('deleteUserById executes delete sequence inside a single transaction', async () => {
  const txStatements = [];
  let inTransactionCallCount = 0;
  let outsideQueryCallCount = 0;
  const store = createMySqlAuthStore({
    dbClient: {
      query: async (sql) => {
        outsideQueryCallCount += 1;
        assert.fail(`deleteUserById should execute in transaction only: ${String(sql)}`);
        return [];
      },
      inTransaction: async (runner) => {
        inTransactionCallCount += 1;
        return runner({
          query: async (sql) => {
            const statement = String(sql).replace(/\s+/g, ' ').trim();
            txStatements.push(statement);
            if (statement.includes('DELETE FROM users')) {
              return { affectedRows: 1 };
            }
            return { affectedRows: 0 };
          }
        });
      }
    }
  });

  const result = await store.deleteUserById('u-delete-tx');
  assert.deepEqual(result, { deleted: true });
  assert.equal(inTransactionCallCount, 1);
  assert.equal(outsideQueryCallCount, 0);
  assert.equal(txStatements.length, 6);
  assert.equal(txStatements[0].includes('DELETE FROM refresh_tokens'), true);
  assert.equal(txStatements[1].includes('DELETE FROM auth_sessions'), true);
  assert.equal(txStatements[2].includes('DELETE FROM auth_user_platform_roles'), true);
  assert.equal(txStatements[3].includes('DELETE FROM auth_user_domain_access'), true);
  assert.equal(txStatements[4].includes('DELETE FROM auth_user_tenants'), true);
  assert.equal(txStatements[5].includes('DELETE FROM users'), true);
});

test('deleteUserById returns deleted=false when deadlock retries are exhausted', async () => {
  const deadlockMetrics = [];
  const store = createMySqlAuthStore({
    dbClient: {
      query: async (sql) => {
        assert.fail(`unexpected non-transaction query: ${String(sql)}`);
      },
      inTransaction: async () => {
        throw createDeadlockError();
      }
    },
    deadlockRetryConfig: {
      maxRetries: 1,
      baseDelayMs: 1,
      maxDelayMs: 1,
      jitterMs: 0
    },
    sleepFn: async () => {},
    random: () => 0,
    onDeadlockMetric: (metric) => {
      deadlockMetrics.push(metric);
    }
  });

  const result = await store.deleteUserById('u-delete-deadlock-fail');
  assert.deepEqual(result, { deleted: false });
  assert.ok(
    deadlockMetrics.some(
      (metric) =>
        metric.operation === 'deleteUserById'
        && metric.event === 'final-failure'
        && metric.retries_used === 1
    )
  );
});

test('createTenantMembershipForUser inserts tenant relationship and returns created=true', async () => {
  let insertSql = '';
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (
      normalizedSql.includes('SELECT membership_id')
      && normalizedSql.includes('FROM auth_user_tenants')
    ) {
      return [];
    }
    if (normalizedSql.includes('INSERT INTO auth_user_tenants')) {
      insertSql = normalizedSql;
      return { affectedRows: 1 };
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  }, { userExists: true });

  const result = await store.createTenantMembershipForUser({
    userId: 'u-tenant-create',
    tenantId: 'tenant-1',
    tenantName: 'Tenant 1'
  });
  assert.equal(/INSERT INTO auth_user_tenants/i.test(insertSql), true);
  assert.deepEqual(result, { created: true });
});

test('createTenantMembershipForUser normalizes blank tenant name to null', async () => {
  let insertedTenantName = 'unset';
  const store = createStore(async (sql, params) => {
    const normalizedSql = String(sql);
    if (
      normalizedSql.includes('SELECT membership_id')
      && normalizedSql.includes('FROM auth_user_tenants')
    ) {
      return [];
    }
    if (normalizedSql.includes('INSERT INTO auth_user_tenants')) {
      insertedTenantName = params?.[3];
      return { affectedRows: 1 };
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  }, { userExists: true });

  const result = await store.createTenantMembershipForUser({
    userId: 'u-tenant-name-normalize',
    tenantId: 'tenant-name-normalize',
    tenantName: '   '
  });
  assert.equal(insertedTenantName, null);
  assert.deepEqual(result, { created: true });
});

test('createTenantMembershipForUser returns created=false on duplicate relationship', async () => {
  const duplicateError = new Error('Duplicate entry for auth_user_tenants');
  duplicateError.code = 'ER_DUP_ENTRY';
  duplicateError.errno = 1062;
  let legacyStatusLookupCount = 0;
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (
      normalizedSql.includes('SELECT membership_id')
      && normalizedSql.includes('FROM auth_user_tenants')
    ) {
      return [];
    }
    if (normalizedSql.includes('INSERT INTO auth_user_tenants')) {
      throw duplicateError;
    }
    if (
      normalizedSql.includes('SELECT status')
      && normalizedSql.includes('FROM auth_user_tenants')
    ) {
      legacyStatusLookupCount += 1;
      return [{ status: 'active' }];
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  }, { userExists: true });

  const result = await store.createTenantMembershipForUser({
    userId: 'u-tenant-duplicate',
    tenantId: 'tenant-2'
  });
  assert.equal(legacyStatusLookupCount, 0);
  assert.deepEqual(result, { created: false });
});

test('createTenantMembershipForUser fails closed when lifecycle columns are missing', async () => {
  let lifecycleSelectAttempts = 0;
  let legacyStatusLookupCount = 0;
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (
      normalizedSql.includes('SELECT membership_id')
      && normalizedSql.includes('FROM auth_user_tenants')
      && normalizedSql.includes('FOR UPDATE')
    ) {
      lifecycleSelectAttempts += 1;
      const error = new Error("Unknown column 'membership_id' in 'field list'");
      error.code = 'ER_BAD_FIELD_ERROR';
      error.errno = 1054;
      throw error;
    }
    if (
      normalizedSql.includes('SELECT status')
      && normalizedSql.includes('FROM auth_user_tenants')
      && normalizedSql.includes('WHERE user_id = ? AND tenant_id = ?')
    ) {
      legacyStatusLookupCount += 1;
      return [{ status: 'left' }];
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  }, { userExists: true });

  await assert.rejects(
    () =>
      store.createTenantMembershipForUser({
        userId: 'u-tenant-lifecycle-required',
        tenantId: 'tenant-lifecycle-required',
        tenantName: 'Tenant Lifecycle Required'
      }),
    (error) => {
      assert.equal(error?.code, 'ER_BAD_FIELD_ERROR');
      return true;
    }
  );
  assert.equal(lifecycleSelectAttempts, 1);
  assert.equal(legacyStatusLookupCount, 0);
});

test('createTenantMembershipForUser fails closed when existing membership status is blank', async () => {
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (
      normalizedSql.includes('SELECT membership_id')
      && normalizedSql.includes('FROM auth_user_tenants')
      && normalizedSql.includes('FOR UPDATE')
    ) {
      return [
        {
          membership_id: 'membership-empty-status',
          user_id: 'u-tenant-empty-status',
          tenant_id: 'tenant-empty-status',
          tenant_name: 'Tenant Empty Status',
          status: '',
          can_view_member_admin: 0,
          can_operate_member_admin: 0,
          can_view_billing: 0,
          can_operate_billing: 0,
          joined_at: null,
          left_at: null
        }
      ];
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  }, { userExists: true });

  await assert.rejects(
    () =>
      store.createTenantMembershipForUser({
        userId: 'u-tenant-empty-status',
        tenantId: 'tenant-empty-status',
        tenantName: 'Tenant Empty Status'
      }),
    /unsupported existing status/
  );
});

test('findTenantMembershipByUserAndTenantId does not coerce blank status to active', async () => {
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (
      normalizedSql.includes('FROM auth_user_tenants ut')
      && normalizedSql.includes('LEFT JOIN users u')
    ) {
      return [
        {
          membership_id: 'membership-blank-status',
          user_id: 'u-tenant-blank-status',
          tenant_id: 'tenant-blank-status',
          tenant_name: 'Tenant Blank Status',
          status: '',
          joined_at: null,
          left_at: null,
          phone: '13835550000'
        }
      ];
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  const membership = await store.findTenantMembershipByUserAndTenantId({
    userId: 'u-tenant-blank-status',
    tenantId: 'tenant-blank-status'
  });
  assert.ok(membership);
  assert.equal(membership.status, '');
});

test('findTenantMembershipByMembershipIdAndTenantId returns membership projection with phone', async () => {
  let lookupSql = '';
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (
      normalizedSql.includes('FROM auth_user_tenants ut')
      && normalizedSql.includes('LEFT JOIN users u ON u.id = ut.user_id')
      && normalizedSql.includes('WHERE ut.membership_id = ? AND ut.tenant_id = ?')
    ) {
      lookupSql = normalizedSql;
      return [
        {
          membership_id: 'membership-profile-read-1',
          user_id: 'tenant-user-profile-read-1',
          tenant_id: 'tenant-profile-read-1',
          tenant_name: 'Tenant Profile Read',
          phone: '13835557771',
          status: 'active',
          display_name: '成员甲',
          department_name: '研发一部',
          joined_at: '2026-02-20T00:00:00.000Z',
          left_at: null
        }
      ];
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  const membership = await store.findTenantMembershipByMembershipIdAndTenantId({
    membershipId: 'membership-profile-read-1',
    tenantId: 'tenant-profile-read-1'
  });

  assert.ok(membership);
  assert.match(lookupSql, /LEFT JOIN users u ON u\.id = ut\.user_id/i);
  assert.equal(membership.membership_id, 'membership-profile-read-1');
  assert.equal(membership.user_id, 'tenant-user-profile-read-1');
  assert.equal(membership.tenant_id, 'tenant-profile-read-1');
  assert.equal(membership.phone, '13835557771');
  assert.equal(membership.display_name, '成员甲');
  assert.equal(membership.department_name, '研发一部');
});

test('findTenantMembershipByMembershipIdAndTenantId keeps raw profile fields without trimming', async () => {
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (
      normalizedSql.includes('FROM auth_user_tenants ut')
      && normalizedSql.includes('LEFT JOIN users u ON u.id = ut.user_id')
      && normalizedSql.includes('WHERE ut.membership_id = ? AND ut.tenant_id = ?')
    ) {
      return [
        {
          membership_id: 'membership-profile-read-raw',
          user_id: 'tenant-user-profile-read-raw',
          tenant_id: 'tenant-profile-read-raw',
          tenant_name: 'Tenant Profile Read Raw',
          phone: '13835557772',
          status: 'active',
          display_name: ' 成员甲',
          department_name: '研发一部 ',
          joined_at: '2026-02-20T00:00:00.000Z',
          left_at: null
        }
      ];
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  const membership = await store.findTenantMembershipByMembershipIdAndTenantId({
    membershipId: 'membership-profile-read-raw',
    tenantId: 'tenant-profile-read-raw'
  });

  assert.ok(membership);
  assert.equal(membership.display_name, ' 成员甲');
  assert.equal(membership.department_name, '研发一部 ');
});

test('findTenantMembershipByMembershipIdAndTenantId uses LEFT JOIN and keeps row when user profile is missing', async () => {
  let lookupSql = '';
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (
      normalizedSql.includes('FROM auth_user_tenants ut')
      && normalizedSql.includes('LEFT JOIN users u ON u.id = ut.user_id')
      && normalizedSql.includes('WHERE ut.membership_id = ? AND ut.tenant_id = ?')
    ) {
      lookupSql = normalizedSql;
      return [
        {
          membership_id: 'membership-profile-read-missing-user',
          user_id: 'tenant-user-profile-read-missing-user',
          tenant_id: 'tenant-profile-read-missing-user',
          tenant_name: 'Tenant Profile Read Missing User',
          phone: null,
          status: 'active',
          display_name: '成员甲',
          department_name: '研发一部',
          joined_at: '2026-02-20T00:00:00.000Z',
          left_at: null
        }
      ];
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  const membership = await store.findTenantMembershipByMembershipIdAndTenantId({
    membershipId: 'membership-profile-read-missing-user',
    tenantId: 'tenant-profile-read-missing-user'
  });

  assert.ok(membership);
  assert.match(lookupSql, /LEFT JOIN users u ON u\.id = ut\.user_id/i);
  assert.equal(membership.membership_id, 'membership-profile-read-missing-user');
  assert.equal(membership.phone, '');
});

test('listTenantMembersByTenantId uses LEFT JOIN users and preserves rows with missing user profile', async () => {
  let listSql = '';
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (
      normalizedSql.includes('FROM auth_user_tenants ut')
      && normalizedSql.includes('LEFT JOIN users u ON u.id = ut.user_id')
      && normalizedSql.includes('WHERE ut.tenant_id = ?')
      && normalizedSql.includes('ORDER BY ut.joined_at DESC')
    ) {
      listSql = normalizedSql;
      return [
        {
          membership_id: 'membership-list-missing-user',
          user_id: 'tenant-user-list-missing-user',
          tenant_id: 'tenant-list-missing-user',
          tenant_name: 'Tenant List Missing User',
          phone: null,
          status: 'active',
          display_name: '成员乙',
          department_name: '产品部',
          joined_at: '2026-02-20T00:00:00.000Z',
          left_at: null
        }
      ];
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  const members = await store.listTenantMembersByTenantId({
    tenantId: 'tenant-list-missing-user',
    page: 1,
    pageSize: 50
  });

  assert.equal(members.length, 1);
  assert.match(listSql, /LEFT JOIN users u ON u\.id = ut\.user_id/i);
  assert.equal(members[0].membership_id, 'membership-list-missing-user');
  assert.equal(members[0].phone, '');
});

test('createTenantMembershipForUser returns created=false when user does not exist', async () => {
  let insertCalled = false;
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (normalizedSql.includes('INSERT INTO auth_user_tenants')) {
      insertCalled = true;
      return { affectedRows: 1 };
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  }, { userExists: false });

  const result = await store.createTenantMembershipForUser({
    userId: 'u-tenant-missing-user',
    tenantId: 'tenant-missing-user'
  });
  assert.equal(insertCalled, false);
  assert.deepEqual(result, { created: false });
});

test('removeTenantDomainAccessForUser removes tenant domain only when active memberships are absent', async () => {
  let deleteSql = '';
  let deleteParams = [];
  const store = createStore(async (sql, params) => {
    const normalizedSql = String(sql);
    if (
      normalizedSql.includes('DELETE FROM auth_user_domain_access')
      && normalizedSql.includes("domain = 'tenant'")
    ) {
      deleteSql = normalizedSql;
      deleteParams = params;
      return { affectedRows: 1 };
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  const result = await store.removeTenantDomainAccessForUser('u-tenant-domain-cleanup');
  assert.equal(/NOT EXISTS/i.test(deleteSql), true);
  assert.doesNotMatch(deleteSql, /o\.id IS NULL/i);
  assert.deepEqual(deleteParams, ['u-tenant-domain-cleanup', 'u-tenant-domain-cleanup']);
  assert.deepEqual(result, { removed: true });
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
  let listSql = '';
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (normalizedSql.includes('FROM auth_user_tenants')) {
      listSql = normalizedSql;
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
  assert.match(listSql, /LEFT JOIN orgs/i);
  assert.match(listSql, /o\.status IN \('active', 'enabled'\)/i);
  assert.doesNotMatch(listSql, /o\.id IS NULL/i);
});

test('listTenantOptionsByUserId falls back to legacy query when orgs table is missing', async () => {
  let orgAwareAttempts = 0;
  let legacyAttempts = 0;
  let lastSql = '';
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (!normalizedSql.includes('FROM auth_user_tenants')) {
      assert.fail(`unexpected query: ${normalizedSql}`);
      return [];
    }
    if (normalizedSql.includes('LEFT JOIN orgs')) {
      orgAwareAttempts += 1;
      const error = new Error("Table 'neweast.orgs' doesn't exist");
      error.code = 'ER_NO_SUCH_TABLE';
      error.errno = 1146;
      throw error;
    }
    legacyAttempts += 1;
    lastSql = normalizedSql;
    return [{ tenant_id: 'tenant-legacy', tenant_name: 'Legacy Tenant' }];
  });

  const options = await store.listTenantOptionsByUserId('u-legacy-options');
  assert.deepEqual(options, [{ tenantId: 'tenant-legacy', tenantName: 'Legacy Tenant' }]);
  assert.equal(orgAwareAttempts, 1);
  assert.equal(legacyAttempts, 1);
  assert.doesNotMatch(lastSql, /LEFT JOIN orgs/i);
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
  let permissionSql = '';
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (normalizedSql.includes('can_view_member_admin')) {
      permissionSql = normalizedSql;
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
  assert.match(permissionSql, /LEFT JOIN orgs/i);
  assert.match(permissionSql, /o\.status IN \('active', 'enabled'\)/i);
  assert.doesNotMatch(permissionSql, /o\.id IS NULL/i);
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

    if (
      normalizedSql.includes('SELECT status')
      && normalizedSql.includes('FROM auth_user_platform_roles')
    ) {
      return [
        {
          status: 'active',
          can_view_member_admin: 1,
          can_operate_member_admin: 1,
          can_view_billing: 1,
          can_operate_billing: 0
        }
      ];
    }
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

test('replacePlatformRolesAndSyncSnapshot deduplicates role facts by role_id before writing (case-insensitive)', async () => {
  const roleInsertParamsList = [];
  const store = createStore(async (sql, params) => {
    const normalizedSql = String(sql);

    if (
      normalizedSql.includes('SELECT status')
      && normalizedSql.includes('FROM auth_user_platform_roles')
    ) {
      return [
        {
          status: 'active',
          can_view_member_admin: 1,
          can_operate_member_admin: 0,
          can_view_billing: 1,
          can_operate_billing: 0
        }
      ];
    }
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
        roleId: 'Platform-Member-Admin',
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
    'Platform-Member-Admin',
    'active',
    1,
    0,
    1,
    0
  ]);
});

test('replacePlatformRolesAndSyncSnapshot locks target user row before mutating role facts', async () => {
  let userLookupSql = '';
  const store = createStore(
    async (sql) => {
      const normalizedSql = String(sql);
      if (
        normalizedSql.includes('SELECT status')
        && normalizedSql.includes('FROM auth_user_platform_roles')
      ) {
        return [];
      }
      if (normalizedSql.includes('DELETE FROM auth_user_platform_roles')) {
        return { affectedRows: 1 };
      }
      if (normalizedSql.includes('UPDATE auth_user_domain_access')) {
        return { affectedRows: 0 };
      }
      assert.fail(`unexpected query: ${normalizedSql}`);
      return [];
    },
    {
      onUserLookupSql: (sql) => {
        userLookupSql = String(sql);
      }
    }
  );

  const result = await store.replacePlatformRolesAndSyncSnapshot({
    userId: 'u-sync-lock-check',
    roles: []
  });

  assert.equal(result.reason, 'ok');
  assert.equal(/FOR UPDATE/i.test(userLookupSql), true);
});

test('replacePlatformRolesAndSyncSnapshot with empty roles does not create new platform domain row', async () => {
  const statements = [];
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    statements.push(normalizedSql);

    if (
      normalizedSql.includes('SELECT status')
      && normalizedSql.includes('FROM auth_user_platform_roles')
    ) {
      return [];
    }
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

test('replacePlatformRolesAndSyncSnapshot rejects unknown user id without mutating role facts', async () => {
  let writeCount = 0;
  const store = createStore(
    async (sql) => {
      const normalizedSql = String(sql);
      if (normalizedSql.includes('DELETE FROM auth_user_platform_roles')) {
        writeCount += 1;
        return { affectedRows: 1 };
      }
      if (normalizedSql.includes('INSERT INTO auth_user_platform_roles')) {
        writeCount += 1;
        return { affectedRows: 1 };
      }
      if (normalizedSql.includes('INSERT INTO auth_user_domain_access')) {
        writeCount += 1;
        return { affectedRows: 1 };
      }
      if (normalizedSql.includes('UPDATE auth_user_domain_access')) {
        writeCount += 1;
        return { affectedRows: 1 };
      }
      assert.fail(`unexpected query: ${normalizedSql}`);
      return [];
    },
    { userExists: false }
  );

  const result = await store.replacePlatformRolesAndSyncSnapshot({
    userId: 'u-missing',
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
    reason: 'invalid-user-id',
    permission: null
  });
  assert.equal(writeCount, 0);
});

test('replacePlatformRolesAndSyncSnapshot bumps session version and converges sessions on effective permission change', async () => {
  const statements = [];
  let sessionVersion = 4;
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    statements.push(normalizedSql);

    if (
      normalizedSql.includes('SELECT status')
      && normalizedSql.includes('FROM auth_user_platform_roles')
    ) {
      return [
        {
          status: 'disabled',
          can_view_member_admin: 0,
          can_operate_member_admin: 0,
          can_view_billing: 0,
          can_operate_billing: 0
        }
      ];
    }
    if (normalizedSql.includes('DELETE FROM auth_user_platform_roles')) {
      return { affectedRows: 1 };
    }
    if (normalizedSql.includes('INSERT INTO auth_user_platform_roles')) {
      return { affectedRows: 1 };
    }
    if (normalizedSql.includes('INSERT INTO auth_user_domain_access')) {
      return { affectedRows: 1 };
    }
    if (normalizedSql.includes('UPDATE users') && normalizedSql.includes('session_version = session_version + 1')) {
      sessionVersion += 1;
      return { affectedRows: 1 };
    }
    if (normalizedSql.includes('UPDATE auth_sessions')) {
      return { affectedRows: 2 };
    }
    if (normalizedSql.includes('UPDATE refresh_tokens')) {
      return { affectedRows: 2 };
    }
    if (normalizedSql.includes('SELECT id, phone, password_hash, status, session_version')) {
      return [
        {
          id: 'u-sync-converge',
          phone: '13810009999',
          password_hash: 'hash',
          status: 'active',
          session_version: sessionVersion
        }
      ];
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  const result = await store.replacePlatformRolesAndSyncSnapshot({
    userId: 'u-sync-converge',
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
  assert.equal(
    statements.some((statement) =>
      statement.includes('UPDATE users')
      && statement.includes('session_version = session_version + 1')
    ),
    true
  );
  assert.equal(
    statements.some((statement) => statement.includes('UPDATE auth_sessions')),
    true
  );
  assert.equal(
    statements.some((statement) => statement.includes('UPDATE refresh_tokens')),
    true
  );
});

test('replacePlatformRolesAndSyncSnapshot does not bump session version when effective permission is unchanged', async () => {
  const statements = [];
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    statements.push(normalizedSql);

    if (
      normalizedSql.includes('SELECT status')
      && normalizedSql.includes('FROM auth_user_platform_roles')
    ) {
      return [
        {
          status: 'active',
          can_view_member_admin: 1,
          can_operate_member_admin: 0,
          can_view_billing: 0,
          can_operate_billing: 0
        }
      ];
    }
    if (normalizedSql.includes('DELETE FROM auth_user_platform_roles')) {
      return { affectedRows: 1 };
    }
    if (normalizedSql.includes('INSERT INTO auth_user_platform_roles')) {
      return { affectedRows: 1 };
    }
    if (normalizedSql.includes('INSERT INTO auth_user_domain_access')) {
      return { affectedRows: 1 };
    }
    if (normalizedSql.includes('UPDATE users') && normalizedSql.includes('session_version = session_version + 1')) {
      assert.fail('session_version should not be bumped when effective permission is unchanged');
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  const result = await store.replacePlatformRolesAndSyncSnapshot({
    userId: 'u-sync-no-bump',
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
  assert.equal(
    statements.some((statement) =>
      statement.includes('UPDATE users')
      && statement.includes('session_version = session_version + 1')
    ),
    false
  );
});

test('replacePlatformRolesAndSyncSnapshot reports synced=true when snapshot write is a no-op', async () => {
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);

    if (
      normalizedSql.includes('SELECT status')
      && normalizedSql.includes('FROM auth_user_platform_roles')
    ) {
      return [
        {
          status: 'active',
          can_view_member_admin: 1,
          can_operate_member_admin: 0,
          can_view_billing: 0,
          can_operate_billing: 0
        }
      ];
    }
    if (normalizedSql.includes('DELETE FROM auth_user_platform_roles')) {
      return { affectedRows: 1 };
    }
    if (normalizedSql.includes('INSERT INTO auth_user_platform_roles')) {
      return { affectedRows: 1 };
    }
    if (normalizedSql.includes('INSERT INTO auth_user_domain_access')) {
      return { affectedRows: 0 };
    }
    if (normalizedSql.includes('UPDATE users') && normalizedSql.includes('session_version = session_version + 1')) {
      assert.fail('session_version should not be bumped when effective permission is unchanged');
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  const result = await store.replacePlatformRolesAndSyncSnapshot({
    userId: 'u-sync-noop-snapshot',
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

  assert.equal(result.reason, 'ok');
  assert.equal(result.synced, true);
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

test('replacePlatformRolesAndSyncSnapshot rejects blank platform role status', async () => {
  let queryCount = 0;
  const store = createStore(async () => {
    queryCount += 1;
    return [];
  });

  await assert.rejects(
    () =>
      store.replacePlatformRolesAndSyncSnapshot({
        userId: 'u-invalid-blank-status',
        roles: [
          {
            roleId: 'platform-role-x',
            status: '   ',
            permission: {
              canViewMemberAdmin: true
            }
          }
        ]
      }),
    /invalid platform role status:/
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
      if (
        normalizedSql.includes('SELECT status')
        && normalizedSql.includes('FROM auth_user_platform_roles')
      ) {
        return [
          {
            status: 'active',
            can_view_member_admin: 1,
            can_operate_member_admin: 0,
            can_view_billing: 0,
            can_operate_billing: 0
          }
        ];
      }
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
      if (
        normalizedSql.includes('SELECT status')
        && normalizedSql.includes('FROM auth_user_platform_roles')
      ) {
        return [
          {
            status: 'active',
            can_view_member_admin: 1,
            can_operate_member_admin: 0,
            can_view_billing: 0,
            can_operate_billing: 0
          }
        ];
      }
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

test('rotateRefreshToken refuses ownership mismatch before mutating refresh token chain', async () => {
  const sqlCalls = [];
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    sqlCalls.push(normalizedSql);
    if (normalizedSql.includes('SELECT token_hash, status, session_id, user_id')) {
      return [
        {
          token_hash: 'token-prev',
          status: 'active',
          session_id: 'session-origin',
          user_id: 'user-origin'
        }
      ];
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  const result = await store.rotateRefreshToken({
    previousTokenHash: 'token-prev',
    nextTokenHash: 'token-next',
    sessionId: 'session-other',
    userId: 'user-origin',
    expiresAt: Date.now() + 60_000
  });

  assert.deepEqual(result, { ok: false });
  assert.equal(sqlCalls.length, 1);
});

test('rotateRefreshToken updates previous token with session_id/user_id ownership guard', async () => {
  let updateSql = '';
  let updateParams = [];
  const store = createStore(async (sql, params = []) => {
    const normalizedSql = String(sql);
    if (normalizedSql.includes('SELECT token_hash, status, session_id, user_id')) {
      return [
        {
          token_hash: 'token-prev',
          status: 'active',
          session_id: 'session-1',
          user_id: 'user-1'
        }
      ];
    }
    if (normalizedSql.includes('UPDATE refresh_tokens') && normalizedSql.includes('SET status = \'rotated\'')) {
      updateSql = normalizedSql;
      updateParams = params;
      return { affectedRows: 1 };
    }
    if (normalizedSql.includes('INSERT INTO refresh_tokens')) {
      return { affectedRows: 1 };
    }
    if (normalizedSql.includes('SET rotated_to_token_hash')) {
      return { affectedRows: 1 };
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  const result = await store.rotateRefreshToken({
    previousTokenHash: 'token-prev',
    nextTokenHash: 'token-next',
    sessionId: 'session-1',
    userId: 'user-1',
    expiresAt: Date.now() + 60_000
  });

  assert.deepEqual(result, { ok: true });
  assert.match(updateSql, /session_id\s*=\s*\?/i);
  assert.match(updateSql, /user_id\s*=\s*\?/i);
  assert.deepEqual(updateParams, ['token-prev', 'session-1', 'user-1']);
});

test('createOrganizationWithOwner persists org and owner membership in one transaction', async () => {
  let inTransactionCalls = 0;
  const txStatements = [];
  const txParams = [];
  const store = createMySqlAuthStore({
    dbClient: {
      query: async (sql) => {
        assert.fail(`unexpected non-transaction query: ${String(sql)}`);
      },
      inTransaction: async (runner) => {
        inTransactionCalls += 1;
        return runner({
          query: async (sql, params = []) => {
            const normalizedSql = String(sql);
            txStatements.push(normalizedSql);
            txParams.push(params);
            if (normalizedSql.includes('INSERT INTO orgs')) {
              return { affectedRows: 1 };
            }
            if (normalizedSql.includes('INSERT INTO memberships')) {
              return { affectedRows: 1 };
            }
            assert.fail(`unexpected tx query: ${normalizedSql}`);
            return [];
          }
        });
      }
    }
  });

  const result = await store.createOrganizationWithOwner({
    orgName: '组织事务测试 A',
    ownerUserId: 'u-owner-1',
    operatorUserId: 'u-operator-1'
  });

  assert.equal(inTransactionCalls, 1);
  assert.equal(txStatements.length, 2);
  assert.match(txStatements[0], /INSERT\s+INTO\s+orgs/i);
  assert.match(txStatements[1], /INSERT\s+INTO\s+memberships/i);
  assert.equal(txParams[0][1], '组织事务测试 A');
  assert.equal(txParams[0][2], 'u-owner-1');
  assert.equal(txParams[1][1], 'u-owner-1');
  assert.equal(result.owner_user_id, 'u-owner-1');
  assert.equal(typeof result.org_id, 'string');
  assert.ok(result.org_id.length > 0);
});

test('createOrganizationWithOwner retries deadlock and succeeds on next transaction attempt', async () => {
  let inTransactionCalls = 0;
  const deadlockMetrics = [];
  const store = createMySqlAuthStore({
    dbClient: {
      query: async (sql) => {
        assert.fail(`unexpected non-transaction query: ${String(sql)}`);
      },
      inTransaction: async (runner) => {
        inTransactionCalls += 1;
        if (inTransactionCalls === 1) {
          throw createDeadlockError();
        }
        return runner({
          query: async (sql) => {
            const normalizedSql = String(sql);
            if (normalizedSql.includes('INSERT INTO orgs')) {
              return { affectedRows: 1 };
            }
            if (normalizedSql.includes('INSERT INTO memberships')) {
              return { affectedRows: 1 };
            }
            assert.fail(`unexpected tx query: ${normalizedSql}`);
            return [];
          }
        });
      }
    },
    deadlockRetryConfig: {
      maxRetries: 2,
      baseDelayMs: 1,
      maxDelayMs: 1,
      jitterMs: 0
    },
    sleepFn: async () => {},
    random: () => 0,
    onDeadlockMetric: (metric) => {
      deadlockMetrics.push(metric);
    }
  });

  const result = await store.createOrganizationWithOwner({
    orgName: '组织事务测试 D',
    ownerUserId: 'u-owner-4',
    operatorUserId: 'u-operator-4'
  });

  assert.equal(inTransactionCalls, 2);
  assert.equal(result.owner_user_id, 'u-owner-4');
  assert.equal(typeof result.org_id, 'string');
  assert.ok(
    deadlockMetrics.some(
      (metric) =>
        metric.operation === 'createOrganizationWithOwner'
        && metric.event === 'deadlock-detected'
    )
  );
  assert.ok(
    deadlockMetrics.some(
      (metric) =>
        metric.operation === 'createOrganizationWithOwner'
        && metric.event === 'retry-succeeded'
        && metric.retries_used === 1
    )
  );
});

test('createOrganizationWithOwner throws deadlock error after retry exhaustion', async () => {
  const deadlockMetrics = [];
  const store = createMySqlAuthStore({
    dbClient: {
      query: async (sql) => {
        assert.fail(`unexpected non-transaction query: ${String(sql)}`);
      },
      inTransaction: async () => {
        throw createDeadlockError();
      }
    },
    deadlockRetryConfig: {
      maxRetries: 1,
      baseDelayMs: 1,
      maxDelayMs: 1,
      jitterMs: 0
    },
    sleepFn: async () => {},
    random: () => 0,
    onDeadlockMetric: (metric) => {
      deadlockMetrics.push(metric);
    }
  });

  await assert.rejects(
    () =>
      store.createOrganizationWithOwner({
        orgName: '组织事务测试 E',
        ownerUserId: 'u-owner-5',
        operatorUserId: 'u-operator-5'
      }),
    (error) => {
      assert.equal(error.code, 'ER_LOCK_DEADLOCK');
      assert.equal(error.errno, 1213);
      return true;
    }
  );
  assert.ok(
    deadlockMetrics.some(
      (metric) =>
        metric.operation === 'createOrganizationWithOwner'
        && metric.event === 'final-failure'
        && metric.retries_used === 1
    )
  );
});

test('createOrganizationWithOwner surfaces transaction failure when membership insert fails mid-transaction', async () => {
  let rollbackTriggered = false;
  const store = createMySqlAuthStore({
    dbClient: {
      query: async (sql) => {
        assert.fail(`unexpected non-transaction query: ${String(sql)}`);
      },
      inTransaction: async (runner) => {
        try {
          return await runner({
            query: async (sql) => {
              const normalizedSql = String(sql);
              if (normalizedSql.includes('INSERT INTO orgs')) {
                return { affectedRows: 1 };
              }
              if (normalizedSql.includes('INSERT INTO memberships')) {
                throw new Error('membership-write-failed');
              }
              assert.fail(`unexpected tx query: ${normalizedSql}`);
              return [];
            }
          });
        } catch (error) {
          rollbackTriggered = true;
          throw error;
        }
      }
    }
  });

  await assert.rejects(
    () =>
      store.createOrganizationWithOwner({
        orgName: '组织事务测试 B',
        ownerUserId: 'u-owner-2',
        operatorUserId: 'u-operator-2'
      }),
    /membership-write-failed/
  );
  assert.equal(rollbackTriggered, true);
});

test('createOrganizationWithOwner rejects when transaction writes are not applied', async () => {
  const store = createMySqlAuthStore({
    dbClient: {
      query: async (sql) => {
        assert.fail(`unexpected non-transaction query: ${String(sql)}`);
      },
      inTransaction: async (runner) =>
        runner({
          query: async (sql) => {
            const normalizedSql = String(sql);
            if (normalizedSql.includes('INSERT INTO orgs')) {
              return { affectedRows: 0 };
            }
            assert.fail(`unexpected tx query: ${normalizedSql}`);
            return [];
          }
        })
    }
  });

  await assert.rejects(
    () =>
      store.createOrganizationWithOwner({
        orgName: '组织事务测试 C',
        ownerUserId: 'u-owner-3',
        operatorUserId: 'u-operator-3'
      }),
    /org-create-write-not-applied/
  );
});

test('findOrganizationById returns normalized org projection when org exists', async () => {
  let selectSql = '';
  let selectParams = [];
  const store = createMySqlAuthStore({
    dbClient: {
      query: async (sql, params = []) => {
        const normalizedSql = String(sql);
        if (normalizedSql.includes('FROM orgs') && normalizedSql.includes('WHERE BINARY id = ?')) {
          selectSql = normalizedSql;
          selectParams = params;
          return [{
            id: 'org-owner-transfer-1',
            name: '负责人变更组织',
            owner_user_id: 'owner-user-1',
            status: 'enabled',
            created_by_user_id: 'operator-user-1'
          }];
        }
        assert.fail(`unexpected query: ${normalizedSql}`);
        return [];
      },
      inTransaction: async () => {
        assert.fail('findOrganizationById should not require transaction');
      }
    }
  });

  const result = await store.findOrganizationById({
    orgId: 'org-owner-transfer-1'
  });

  assert.match(selectSql, /SELECT id, name, owner_user_id, status, created_by_user_id/i);
  assert.deepEqual(selectParams, ['org-owner-transfer-1']);
  assert.deepEqual(result, {
    org_id: 'org-owner-transfer-1',
    org_name: '负责人变更组织',
    owner_user_id: 'owner-user-1',
    status: 'active',
    created_by_user_id: 'operator-user-1'
  });
});

test('findOrganizationById returns null when target org does not exist', async () => {
  const store = createMySqlAuthStore({
    dbClient: {
      query: async (sql) => {
        const normalizedSql = String(sql);
        if (normalizedSql.includes('FROM orgs') && normalizedSql.includes('WHERE BINARY id = ?')) {
          return [];
        }
        assert.fail(`unexpected query: ${normalizedSql}`);
        return [];
      },
      inTransaction: async () => {
        assert.fail('findOrganizationById should not require transaction');
      }
    }
  });

  const result = await store.findOrganizationById({
    orgId: 'org-owner-transfer-missing'
  });
  assert.equal(result, null);
});

test('acquireOwnerTransferLock uses mysql GET_LOCK with deterministic hashed key', async () => {
  let lockSql = '';
  let lockParams = [];
  const store = createMySqlAuthStore({
    dbClient: {
      query: async (sql, params = []) => {
        const normalizedSql = String(sql);
        if (normalizedSql.includes('GET_LOCK')) {
          lockSql = normalizedSql;
          lockParams = params;
          return [{ lock_acquired: 1 }];
        }
        assert.fail(`unexpected query: ${normalizedSql}`);
        return [];
      },
      inTransaction: async () => {
        assert.fail('acquireOwnerTransferLock should not require transaction');
      }
    }
  });

  const acquired = await store.acquireOwnerTransferLock({
    orgId: 'org-owner-transfer-lock-sql',
    timeoutSeconds: 0
  });

  assert.equal(acquired, true);
  assert.match(lockSql, /SELECT GET_LOCK\(\?, \?\) AS lock_acquired/i);
  assert.equal(lockParams.length, 2);
  assert.equal(lockParams[1], 0);
  assert.equal(typeof lockParams[0], 'string');
  assert.match(lockParams[0], /^neweast:owner-transfer:[0-9a-f]{40}$/);
  assert.ok(lockParams[0].length <= 64);
});

test('acquireOwnerTransferLock returns false when mysql lock is already held', async () => {
  const store = createMySqlAuthStore({
    dbClient: {
      query: async (sql) => {
        const normalizedSql = String(sql);
        if (normalizedSql.includes('GET_LOCK')) {
          return [{ lock_acquired: 0 }];
        }
        assert.fail(`unexpected query: ${normalizedSql}`);
        return [];
      },
      inTransaction: async () => {
        assert.fail('acquireOwnerTransferLock should not require transaction');
      }
    }
  });

  const acquired = await store.acquireOwnerTransferLock({
    orgId: 'org-owner-transfer-lock-held',
    timeoutSeconds: 0
  });

  assert.equal(acquired, false);
});

test('releaseOwnerTransferLock uses mysql RELEASE_LOCK and returns release state', async () => {
  const queryHistory = [];
  const store = createMySqlAuthStore({
    dbClient: {
      query: async (sql, params = []) => {
        const normalizedSql = String(sql);
        queryHistory.push({ sql: normalizedSql, params });
        if (normalizedSql.includes('RELEASE_LOCK')) {
          return [{ lock_released: 1 }];
        }
        assert.fail(`unexpected query: ${normalizedSql}`);
        return [];
      },
      inTransaction: async () => {
        assert.fail('releaseOwnerTransferLock should not require transaction');
      }
    }
  });

  const released = await store.releaseOwnerTransferLock({
    orgId: 'org-owner-transfer-lock-release'
  });

  assert.equal(released, true);
  assert.equal(queryHistory.length, 1);
  assert.match(queryHistory[0].sql, /SELECT RELEASE_LOCK\(\?\) AS lock_released/i);
  assert.equal(queryHistory[0].params.length, 1);
  assert.match(queryHistory[0].params[0], /^neweast:owner-transfer:[0-9a-f]{40}$/);
});

test('updateOrganizationStatus updates org status and converges active member tenant sessions only', async () => {
  let inTransactionCalls = 0;
  const revokeTenantSessionParams = [];
  const revokeTenantRefreshParams = [];
  const orgSelectSql = [];
  const orgUpdateSql = [];
  const store = createMySqlAuthStore({
    dbClient: {
      query: async (sql) => {
        assert.fail(`unexpected non-transaction query: ${String(sql)}`);
      },
      inTransaction: async (runner) => {
        inTransactionCalls += 1;
        return runner({
          query: async (sql, params = []) => {
            const normalizedSql = String(sql);
            if (
              normalizedSql.includes('SELECT id, status, owner_user_id')
              && normalizedSql.includes('FROM orgs')
            ) {
              orgSelectSql.push(normalizedSql);
              return [{ id: 'org-status-1', status: 'active', owner_user_id: 'u-owner' }];
            }
            if (normalizedSql.includes('UPDATE orgs')) {
              orgUpdateSql.push(normalizedSql);
              return { affectedRows: 1 };
            }
            if (
              normalizedSql.includes('SELECT DISTINCT user_id')
              && normalizedSql.includes('FROM memberships')
            ) {
              return [{ user_id: 'u-owner' }, { user_id: 'u-member' }];
            }
            if (
              normalizedSql.includes('UPDATE auth_sessions')
              && normalizedSql.includes("SET status = 'revoked'")
              && normalizedSql.includes("entry_domain = 'tenant'")
            ) {
              revokeTenantSessionParams.push(params);
              return { affectedRows: 1 };
            }
            if (
              normalizedSql.includes('UPDATE refresh_tokens')
              && normalizedSql.includes("SET status = 'revoked'")
              && normalizedSql.includes("entry_domain = 'tenant'")
            ) {
              revokeTenantRefreshParams.push(params);
              return { affectedRows: 1 };
            }
            if (normalizedSql.includes('UPDATE users')) {
              assert.fail(`unexpected session version update query: ${normalizedSql}`);
            }
            assert.fail(`unexpected tx query: ${normalizedSql}`);
            return [];
          }
        });
      }
    }
  });

  const result = await store.updateOrganizationStatus({
    orgId: 'org-status-1',
    nextStatus: 'disabled',
    operatorUserId: 'u-operator'
  });

  assert.equal(inTransactionCalls, 1);
  assert.deepEqual(result, {
    org_id: 'org-status-1',
    previous_status: 'active',
    current_status: 'disabled'
  });
  assert.equal(revokeTenantSessionParams.length, 2);
  assert.deepEqual(
    revokeTenantSessionParams.map((params) => params?.[1]).sort(),
    ['u-member', 'u-owner']
  );
  assert.equal(revokeTenantRefreshParams.length, 2);
  assert.deepEqual(
    revokeTenantRefreshParams.map((params) => params?.[0]).sort(),
    ['u-member', 'u-owner']
  );
  assert.equal(orgSelectSql.some((sql) => sql.includes('WHERE BINARY id = ?')), true);
  assert.equal(orgUpdateSql.some((sql) => sql.includes('WHERE BINARY id = ?')), true);
});

test('updateOrganizationStatus treats same-status change as no-op without session convergence', async () => {
  let updateOrgCalled = false;
  let readMembershipCalled = false;
  let convergeSessionCalled = false;
  const store = createMySqlAuthStore({
    dbClient: {
      query: async (sql) => {
        assert.fail(`unexpected non-transaction query: ${String(sql)}`);
      },
      inTransaction: async (runner) =>
        runner({
          query: async (sql) => {
            const normalizedSql = String(sql);
            if (
              normalizedSql.includes('SELECT id, status, owner_user_id')
              && normalizedSql.includes('FROM orgs')
            ) {
              return [{ id: 'org-status-noop', status: 'disabled', owner_user_id: 'u-owner' }];
            }
            if (normalizedSql.includes('UPDATE orgs')) {
              updateOrgCalled = true;
              return { affectedRows: 1 };
            }
            if (normalizedSql.includes('FROM memberships')) {
              readMembershipCalled = true;
              return [];
            }
            if (
              normalizedSql.includes('UPDATE auth_sessions')
              || normalizedSql.includes('UPDATE refresh_tokens')
            ) {
              convergeSessionCalled = true;
              return [];
            }
            assert.fail(`unexpected tx query: ${normalizedSql}`);
            return [];
          }
        })
    }
  });

  const result = await store.updateOrganizationStatus({
    orgId: 'org-status-noop',
    nextStatus: 'disabled',
    operatorUserId: 'u-operator'
  });

  assert.deepEqual(result, {
    org_id: 'org-status-noop',
    previous_status: 'disabled',
    current_status: 'disabled'
  });
  assert.equal(updateOrgCalled, false);
  assert.equal(readMembershipCalled, false);
  assert.equal(convergeSessionCalled, false);
});

test('updateOrganizationStatus returns null when target org does not exist', async () => {
  let updateCalled = false;
  const store = createMySqlAuthStore({
    dbClient: {
      query: async (sql) => {
        assert.fail(`unexpected non-transaction query: ${String(sql)}`);
      },
      inTransaction: async (runner) =>
        runner({
          query: async (sql) => {
            const normalizedSql = String(sql);
            if (
              normalizedSql.includes('SELECT id, status, owner_user_id')
              && normalizedSql.includes('FROM orgs')
            ) {
              return [];
            }
            updateCalled = true;
            assert.fail(`unexpected tx query: ${normalizedSql}`);
            return [];
          }
        })
    }
  });

  const result = await store.updateOrganizationStatus({
    orgId: 'org-status-missing',
    nextStatus: 'disabled',
    operatorUserId: 'u-operator'
  });

  assert.equal(result, null);
  assert.equal(updateCalled, false);
});

test('updatePlatformUserStatus updates platform domain status and converges platform sessions only', async () => {
  let inTransactionCalls = 0;
  let updatePlatformDomainCalled = false;
  const revokeSessionParams = [];
  const revokeRefreshParams = [];
  const store = createMySqlAuthStore({
    dbClient: {
      query: async (sql) => {
        assert.fail(`unexpected non-transaction query: ${String(sql)}`);
      },
      inTransaction: async (runner) => {
        inTransactionCalls += 1;
        return runner({
          query: async (sql, params = []) => {
            const normalizedSql = String(sql);
            if (
              normalizedSql.includes('SELECT u.id AS user_id')
              && normalizedSql.includes('LEFT JOIN auth_user_domain_access')
              && normalizedSql.includes('FOR UPDATE')
            ) {
              return [{
                user_id: 'platform-status-user-1',
                platform_status: 'active'
              }];
            }
            if (
              normalizedSql.includes('UPDATE auth_user_domain_access')
              && normalizedSql.includes('SET status = ?')
              && normalizedSql.includes("domain = 'platform'")
            ) {
              updatePlatformDomainCalled = true;
              return { affectedRows: 1 };
            }
            if (
              normalizedSql.includes('UPDATE auth_sessions')
              && normalizedSql.includes("SET status = 'revoked'")
              && normalizedSql.includes("entry_domain = 'platform'")
            ) {
              revokeSessionParams.push(params);
              return { affectedRows: 1 };
            }
            if (
              normalizedSql.includes('UPDATE refresh_tokens')
              && normalizedSql.includes("SET status = 'revoked'")
              && normalizedSql.includes('session_id IN')
              && normalizedSql.includes('FROM auth_sessions')
            ) {
              revokeRefreshParams.push(params);
              return { affectedRows: 1 };
            }
            assert.fail(`unexpected tx query: ${normalizedSql}`);
            return [];
          }
        });
      }
    }
  });

  const result = await store.updatePlatformUserStatus({
    userId: 'platform-status-user-1',
    nextStatus: 'disabled',
    operatorUserId: 'platform-operator-user'
  });

  assert.equal(inTransactionCalls, 1);
  assert.deepEqual(result, {
    user_id: 'platform-status-user-1',
    previous_status: 'active',
    current_status: 'disabled'
  });
  assert.equal(updatePlatformDomainCalled, true);
  assert.equal(revokeSessionParams.length, 1);
  assert.equal(revokeSessionParams[0]?.[0], 'platform-user-status-changed');
  assert.equal(revokeSessionParams[0]?.[1], 'platform-status-user-1');
  assert.equal(revokeRefreshParams.length, 1);
  assert.equal(revokeRefreshParams[0]?.[0], 'platform-status-user-1');
});

test('updatePlatformUserStatus treats same-status change as no-op without session convergence', async () => {
  let updateStatusCalled = false;
  let updateUserCalled = false;
  const store = createMySqlAuthStore({
    dbClient: {
      query: async (sql) => {
        assert.fail(`unexpected non-transaction query: ${String(sql)}`);
      },
      inTransaction: async (runner) =>
        runner({
          query: async (sql) => {
            const normalizedSql = String(sql);
            if (
              normalizedSql.includes('SELECT u.id AS user_id')
              && normalizedSql.includes('LEFT JOIN auth_user_domain_access')
              && normalizedSql.includes('FOR UPDATE')
            ) {
              return [{
                user_id: 'platform-status-user-noop',
                platform_status: 'disabled'
              }];
            }
            if (
              normalizedSql.includes('UPDATE auth_user_domain_access')
              && normalizedSql.includes('SET status = ?')
              && normalizedSql.includes("domain = 'platform'")
            ) {
              updateStatusCalled = true;
              return { affectedRows: 1 };
            }
            if (
              normalizedSql.includes('UPDATE auth_sessions')
              || normalizedSql.includes('UPDATE refresh_tokens')
            ) {
              updateUserCalled = true;
              return [];
            }
            assert.fail(`unexpected tx query: ${normalizedSql}`);
            return [];
          }
        })
    }
  });

  const result = await store.updatePlatformUserStatus({
    userId: 'platform-status-user-noop',
    nextStatus: 'disabled',
    operatorUserId: 'platform-operator-user'
  });

  assert.deepEqual(result, {
    user_id: 'platform-status-user-noop',
    previous_status: 'disabled',
    current_status: 'disabled'
  });
  assert.equal(updateStatusCalled, false);
  assert.equal(updateUserCalled, false);
});

test('updatePlatformUserStatus returns null when target user does not exist', async () => {
  let updateCalled = false;
  const store = createMySqlAuthStore({
    dbClient: {
      query: async (sql) => {
        assert.fail(`unexpected non-transaction query: ${String(sql)}`);
      },
      inTransaction: async (runner) =>
        runner({
          query: async (sql) => {
            const normalizedSql = String(sql);
            if (
              normalizedSql.includes('SELECT u.id AS user_id')
              && normalizedSql.includes('LEFT JOIN auth_user_domain_access')
              && normalizedSql.includes('FOR UPDATE')
            ) {
              return [];
            }
            updateCalled = true;
            assert.fail(`unexpected tx query: ${normalizedSql}`);
            return [];
          }
        })
    }
  });

  const result = await store.updatePlatformUserStatus({
    userId: 'platform-status-user-missing',
    nextStatus: 'disabled',
    operatorUserId: 'platform-operator-user'
  });

  assert.equal(result, null);
  assert.equal(updateCalled, false);
});

test('updateTenantMembershipStatus fails closed when lifecycle columns are missing', async () => {
  let lifecycleSelectAttempts = 0;
  let legacySelectAttempts = 0;
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (
      normalizedSql.includes('SELECT membership_id')
      && normalizedSql.includes('FROM auth_user_tenants')
      && normalizedSql.includes('FOR UPDATE')
      && normalizedSql.includes('WHERE membership_id = ? AND tenant_id = ?')
    ) {
      lifecycleSelectAttempts += 1;
      const error = new Error("Unknown column 'membership_id' in 'field list'");
      error.code = 'ER_BAD_FIELD_ERROR';
      error.errno = 1054;
      throw error;
    }
    if (
      normalizedSql.includes('SELECT user_id')
      && normalizedSql.includes('FROM auth_user_tenants')
      && normalizedSql.includes('WHERE user_id = ? AND tenant_id = ?')
    ) {
      legacySelectAttempts += 1;
      return [];
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  await assert.rejects(
    () =>
      store.updateTenantMembershipStatus({
        membershipId: 'membership-lifecycle-required',
        tenantId: 'tenant-lifecycle-required',
        nextStatus: 'disabled',
        operatorUserId: 'tenant-operator-lifecycle-required'
      }),
    (error) => {
      assert.equal(error?.code, 'ER_BAD_FIELD_ERROR');
      return true;
    }
  );
  assert.equal(lifecycleSelectAttempts, 1);
  assert.equal(legacySelectAttempts, 0);
});

test('updateTenantMembershipStatus rejects blank nextStatus before executing SQL', async () => {
  let queryCount = 0;
  const store = createStore(async (sql) => {
    queryCount += 1;
    assert.fail(`unexpected query: ${String(sql)}`);
    return [];
  });

  await assert.rejects(
    () =>
      store.updateTenantMembershipStatus({
        membershipId: 'membership-reject-empty-next-status',
        tenantId: 'tenant-reject-empty-next-status',
        nextStatus: '',
        operatorUserId: 'operator-reject-empty-next-status'
      }),
    /requires membershipId, tenantId, nextStatus and operatorUserId/
  );
  assert.equal(queryCount, 0);
});

test('updateTenantMembershipStatus does not execute legacy left-to-active reactivation fallback', async () => {
  let lifecycleSelectAttempts = 0;
  let legacySelectAttempts = 0;
  let lifecycleUpdateAttempts = 0;
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (
      normalizedSql.includes('SELECT membership_id')
      && normalizedSql.includes('FROM auth_user_tenants')
      && normalizedSql.includes('FOR UPDATE')
      && normalizedSql.includes('WHERE membership_id = ? AND tenant_id = ?')
    ) {
      lifecycleSelectAttempts += 1;
      const error = new Error("Unknown column 'membership_id' in 'field list'");
      error.code = 'ER_BAD_FIELD_ERROR';
      error.errno = 1054;
      throw error;
    }
    if (
      normalizedSql.includes('SELECT user_id')
      && normalizedSql.includes('FROM auth_user_tenants')
      && normalizedSql.includes('WHERE user_id = ? AND tenant_id = ?')
    ) {
      legacySelectAttempts += 1;
      return [];
    }
    if (
      normalizedSql.includes('UPDATE auth_user_tenants')
      && normalizedSql.includes('WHERE membership_id = ? AND tenant_id = ?')
    ) {
      lifecycleUpdateAttempts += 1;
      return { affectedRows: 1 };
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  await assert.rejects(
    () =>
      store.updateTenantMembershipStatus({
        membershipId: 'membership-lifecycle-left-active',
        tenantId: 'tenant-lifecycle-left-active',
        nextStatus: 'active',
        operatorUserId: 'tenant-operator-lifecycle-left-active'
      }),
    (error) => {
      assert.equal(error?.code, 'ER_BAD_FIELD_ERROR');
      return true;
    }
  );
  assert.equal(lifecycleSelectAttempts, 1);
  assert.equal(legacySelectAttempts, 0);
  assert.equal(lifecycleUpdateAttempts, 0);
});

test('updateTenantMembershipStatus keeps lifecycle path unchanged across repeated missing-column failures', async () => {
  let lifecycleSelectAttempts = 0;
  let legacySelectAttempts = 0;
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (
      normalizedSql.includes('SELECT membership_id')
      && normalizedSql.includes('FROM auth_user_tenants')
      && normalizedSql.includes('FOR UPDATE')
      && normalizedSql.includes('WHERE membership_id = ? AND tenant_id = ?')
    ) {
      lifecycleSelectAttempts += 1;
      const error = new Error("Unknown column 'membership_id' in 'field list'");
      error.code = 'ER_BAD_FIELD_ERROR';
      error.errno = 1054;
      throw error;
    }
    if (
      normalizedSql.includes('SELECT user_id')
      && normalizedSql.includes('FROM auth_user_tenants')
      && normalizedSql.includes('WHERE user_id = ? AND tenant_id = ?')
    ) {
      legacySelectAttempts += 1;
      return [];
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  await assert.rejects(
    () =>
      store.updateTenantMembershipStatus({
        membershipId: 'membership-lifecycle-latched',
        tenantId: 'tenant-lifecycle-latched',
        nextStatus: 'disabled',
        operatorUserId: 'tenant-operator-lifecycle-latched'
      }),
    (error) => {
      assert.equal(error?.code, 'ER_BAD_FIELD_ERROR');
      return true;
    }
  );
  await assert.rejects(
    () =>
      store.updateTenantMembershipStatus({
        membershipId: 'membership-lifecycle-latched',
        tenantId: 'tenant-lifecycle-latched',
        nextStatus: 'disabled',
        operatorUserId: 'tenant-operator-lifecycle-latched'
      }),
    (error) => {
      assert.equal(error?.code, 'ER_BAD_FIELD_ERROR');
      return true;
    }
  );
  assert.equal(lifecycleSelectAttempts, 2);
  assert.equal(legacySelectAttempts, 0);
});

test('updateTenantMembershipStatus fails closed when membership history table is unavailable', async () => {
  let historyInsertAttempts = 0;
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (
      normalizedSql.includes('SELECT membership_id')
      && normalizedSql.includes('FROM auth_user_tenants')
      && normalizedSql.includes('FOR UPDATE')
      && normalizedSql.includes('WHERE membership_id = ? AND tenant_id = ?')
    ) {
      return [{
        membership_id: 'membership-history-missing',
        user_id: 'tenant-user-history',
        tenant_id: 'tenant-history',
        tenant_name: 'Tenant History',
        status: 'left',
        can_view_member_admin: 1,
        can_operate_member_admin: 1,
        can_view_billing: 1,
        can_operate_billing: 0,
        joined_at: '2026-02-01T00:00:00.000Z',
        left_at: '2026-02-10T00:00:00.000Z'
      }];
    }
    if (normalizedSql.includes('INSERT INTO auth_user_tenant_membership_history')) {
      historyInsertAttempts += 1;
      const error = new Error(
        "Table 'neweast.auth_user_tenant_membership_history' doesn't exist"
      );
      error.code = 'ER_NO_SUCH_TABLE';
      error.errno = 1146;
      throw error;
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  await assert.rejects(
    () =>
      store.updateTenantMembershipStatus({
        membershipId: 'membership-history-missing',
        tenantId: 'tenant-history',
        nextStatus: 'active',
        operatorUserId: 'tenant-operator-history',
        reason: 'reactivate'
      }),
    (error) => {
      assert.equal(error?.code, 'AUTH-503-TENANT-MEMBER-HISTORY-UNAVAILABLE');
      return true;
    }
  );
  assert.equal(historyInsertAttempts, 1);
});

test('updateTenantMembershipStatus keeps permission snapshot when re-activating from disabled', async () => {
  let updateSql = '';
  let updateParams = [];
  let membershipLookupCount = 0;
  let roleBindingLookupCount = 0;
  let roleCatalogLookupCount = 0;
  let roleGrantLookupCount = 0;
  const store = createStore(async (sql, params) => {
    const normalizedSql = String(sql);
    if (
      normalizedSql.includes('SELECT membership_id')
      && normalizedSql.includes('FROM auth_user_tenants')
      && normalizedSql.includes('FOR UPDATE')
      && normalizedSql.includes('WHERE membership_id = ? AND tenant_id = ?')
    ) {
      membershipLookupCount += 1;
      return [{
        membership_id: 'membership-reactivate',
        user_id: 'tenant-user-reactivate',
        tenant_id: 'tenant-reactivate',
        tenant_name: 'Tenant Reactivate',
        status: membershipLookupCount === 1 ? 'disabled' : 'active',
        can_view_member_admin: 1,
        can_operate_member_admin: 0,
        can_view_billing: 1,
        can_operate_billing: 0,
        joined_at: '2026-02-01T00:00:00.000Z',
        left_at: null
      }];
    }
    if (
      normalizedSql.includes('SELECT role_id')
      && normalizedSql.includes('FROM auth_tenant_membership_roles')
      && normalizedSql.includes('FOR UPDATE')
    ) {
      roleBindingLookupCount += 1;
      return [{ role_id: 'tenant_role_reactivate' }];
    }
    if (
      normalizedSql.includes('SELECT role_id, status, scope, tenant_id')
      && normalizedSql.includes('FROM platform_role_catalog')
      && normalizedSql.includes('FOR UPDATE')
    ) {
      roleCatalogLookupCount += 1;
      return [{
        role_id: 'tenant_role_reactivate',
        status: 'active',
        scope: 'tenant',
        tenant_id: 'tenant-reactivate'
      }];
    }
    if (
      normalizedSql.includes('SELECT role_id, permission_code')
      && normalizedSql.includes('FROM tenant_role_permission_grants')
      && normalizedSql.includes('FOR UPDATE')
    ) {
      roleGrantLookupCount += 1;
      return [
        {
          role_id: 'tenant_role_reactivate',
          permission_code: 'tenant.member_admin.view'
        },
        {
          role_id: 'tenant_role_reactivate',
          permission_code: 'tenant.billing.view'
        }
      ];
    }
    if (
      normalizedSql.includes('UPDATE auth_user_tenants')
      && normalizedSql.includes('SET status = ?')
      && normalizedSql.includes('WHERE membership_id = ? AND tenant_id = ?')
    ) {
      updateSql = normalizedSql;
      updateParams = params;
      return { affectedRows: 1 };
    }
    if (
      normalizedSql.includes('SELECT COUNT(*) AS tenant_count')
      && normalizedSql.includes('FROM auth_user_tenants ut')
    ) {
      return [{ tenant_count: 1 }];
    }
    if (
      normalizedSql.includes('INSERT INTO auth_user_domain_access')
      && normalizedSql.includes("VALUES (?, 'tenant', 'active')")
    ) {
      return { affectedRows: 1 };
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  const result = await store.updateTenantMembershipStatus({
    membershipId: 'membership-reactivate',
    tenantId: 'tenant-reactivate',
    nextStatus: 'active',
    operatorUserId: 'tenant-operator-reactivate',
    reason: 'manual-reactivate'
  });

  assert.deepEqual(result, {
    membership_id: 'membership-reactivate',
    user_id: 'tenant-user-reactivate',
    tenant_id: 'tenant-reactivate',
    previous_status: 'disabled',
    current_status: 'active'
  });
  assert.match(updateSql, /can_view_member_admin\s*=\s*CASE\s+WHEN\s+\?\s*=\s*'left'/i);
  assert.match(updateSql, /can_operate_member_admin\s*=\s*CASE\s+WHEN\s+\?\s*=\s*'left'/i);
  assert.match(updateSql, /can_view_billing\s*=\s*CASE\s+WHEN\s+\?\s*=\s*'left'/i);
  assert.match(updateSql, /can_operate_billing\s*=\s*CASE\s+WHEN\s+\?\s*=\s*'left'/i);
  assert.equal(updateParams.length, 9);
  assert.deepEqual(
    updateParams.slice(0, 7),
    ['active', 'active', 'active', 'active', 'active', 'active', 'active']
  );
  assert.equal(membershipLookupCount, 2);
  assert.equal(roleBindingLookupCount, 1);
  assert.equal(roleCatalogLookupCount, 1);
  assert.equal(roleGrantLookupCount, 1);
});

test('updateTenantMembershipStatus clears permission snapshot when re-activating from left', async () => {
  let updateSql = '';
  let updateParams = [];
  let membershipLookupCount = 0;
  let rotatedMembershipId = '';
  let deleteMembershipRoleBindingCount = 0;
  const store = createStore(async (sql, params) => {
    const normalizedSql = String(sql);
    if (
      normalizedSql.includes('SELECT membership_id')
      && normalizedSql.includes('FROM auth_user_tenants')
      && normalizedSql.includes('FOR UPDATE')
      && normalizedSql.includes('WHERE membership_id = ? AND tenant_id = ?')
    ) {
      membershipLookupCount += 1;
      if (membershipLookupCount === 1) {
        return [{
          membership_id: 'membership-reactivate-left',
          user_id: 'tenant-user-reactivate-left',
          tenant_id: 'tenant-reactivate-left',
          tenant_name: 'Tenant Reactivate Left',
          status: 'left',
          can_view_member_admin: 1,
          can_operate_member_admin: 1,
          can_view_billing: 1,
          can_operate_billing: 1,
          joined_at: '2026-02-01T00:00:00.000Z',
          left_at: '2026-02-10T00:00:00.000Z'
        }];
      }
      return [{
        membership_id: String(params?.[0] || rotatedMembershipId || 'membership-reactivate-left-new'),
        user_id: 'tenant-user-reactivate-left',
        tenant_id: 'tenant-reactivate-left',
        tenant_name: 'Tenant Reactivate Left',
        status: 'active',
        can_view_member_admin: 0,
        can_operate_member_admin: 0,
        can_view_billing: 0,
        can_operate_billing: 0,
        joined_at: '2026-02-11T00:00:00.000Z',
        left_at: null
      }];
    }
    if (normalizedSql.includes('INSERT INTO auth_user_tenant_membership_history')) {
      return { affectedRows: 1 };
    }
    if (
      normalizedSql.includes('DELETE FROM auth_tenant_membership_roles')
      && normalizedSql.includes('WHERE membership_id = ?')
    ) {
      deleteMembershipRoleBindingCount += 1;
      assert.equal(params?.[0], 'membership-reactivate-left');
      return { affectedRows: 1 };
    }
    if (
      normalizedSql.includes('UPDATE auth_user_tenants')
      && normalizedSql.includes('SET membership_id = ?')
      && normalizedSql.includes('WHERE membership_id = ? AND tenant_id = ?')
    ) {
      updateSql = normalizedSql;
      updateParams = params;
      rotatedMembershipId = String(params?.[0] || '');
      return { affectedRows: 1 };
    }
    if (
      normalizedSql.includes('SELECT COUNT(*) AS tenant_count')
      && normalizedSql.includes('FROM auth_user_tenants ut')
    ) {
      return [{ tenant_count: 1 }];
    }
    if (
      normalizedSql.includes('INSERT INTO auth_user_domain_access')
      && normalizedSql.includes("VALUES (?, 'tenant', 'active')")
    ) {
      return { affectedRows: 1 };
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  const result = await store.updateTenantMembershipStatus({
    membershipId: 'membership-reactivate-left',
    tenantId: 'tenant-reactivate-left',
    nextStatus: 'active',
    operatorUserId: 'tenant-operator-reactivate-left',
    reason: 'manual-reactivate-left'
  });

  assert.equal(result.previous_status, 'left');
  assert.equal(result.current_status, 'active');
  assert.notEqual(result.membership_id, 'membership-reactivate-left');
  assert.match(updateSql, /can_view_member_admin\s*=\s*0/i);
  assert.match(updateSql, /can_operate_member_admin\s*=\s*0/i);
  assert.match(updateSql, /can_view_billing\s*=\s*0/i);
  assert.match(updateSql, /can_operate_billing\s*=\s*0/i);
  assert.equal(updateParams.length, 3);
  assert.equal(deleteMembershipRoleBindingCount, 1);
  assert.equal(membershipLookupCount, 2);
});

test('updateTenantMembershipProfile updates profile fields and returns normalized membership projection', async () => {
  let updateSql = '';
  let updateParams = [];
  const store = createStore(async (sql, params) => {
    const normalizedSql = String(sql);
    if (
      normalizedSql.includes('SELECT ut.membership_id')
      && normalizedSql.includes('FROM auth_user_tenants ut')
      && normalizedSql.includes('LEFT JOIN users u ON u.id = ut.user_id')
      && normalizedSql.includes('WHERE ut.membership_id = ? AND ut.tenant_id = ?')
      && normalizedSql.includes('FOR UPDATE')
    ) {
      return [
        {
          membership_id: 'membership-profile-update-1',
          phone: '13835556666'
        }
      ];
    }
    if (
      normalizedSql.includes('UPDATE auth_user_tenants')
      && normalizedSql.includes('SET display_name = ?')
      && normalizedSql.includes('department_name = CASE')
    ) {
      updateSql = normalizedSql;
      updateParams = params;
      return { affectedRows: 1 };
    }
    if (
      normalizedSql.includes('SELECT ut.membership_id')
      && normalizedSql.includes('LEFT JOIN users u ON u.id = ut.user_id')
      && normalizedSql.includes('WHERE ut.membership_id = ? AND ut.tenant_id = ?')
    ) {
      return [
        {
          membership_id: 'membership-profile-update-1',
          user_id: 'tenant-user-profile-update-1',
          tenant_id: 'tenant-profile-update-1',
          tenant_name: 'Tenant Profile Update',
          phone: '13835556666',
          status: 'active',
          display_name: '成员乙',
          department_name: null,
          joined_at: '2026-02-20T00:00:00.000Z',
          left_at: null
        }
      ];
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  const result = await store.updateTenantMembershipProfile({
    membershipId: 'membership-profile-update-1',
    tenantId: 'tenant-profile-update-1',
    displayName: '成员乙',
    departmentNameProvided: true,
    departmentName: null,
    operatorUserId: 'tenant-operator-profile-update'
  });

  assert.equal(/UPDATE auth_user_tenants/i.test(updateSql), true);
  assert.equal(updateParams[0], '成员乙');
  assert.equal(updateParams[1], 1);
  assert.equal(updateParams[2], null);
  assert.equal(updateParams[3], 'membership-profile-update-1');
  assert.equal(updateParams[4], 'tenant-profile-update-1');
  assert.equal(result.membership_id, 'membership-profile-update-1');
  assert.equal(result.display_name, '成员乙');
  assert.equal(result.department_name, null);
  assert.equal(result.tenant_id, 'tenant-profile-update-1');
});

test('updateTenantMembershipProfile fails closed before update when locked membership row has missing user profile', async () => {
  let updateCalled = false;
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (
      normalizedSql.includes('SELECT ut.membership_id')
      && normalizedSql.includes('FROM auth_user_tenants ut')
      && normalizedSql.includes('LEFT JOIN users u ON u.id = ut.user_id')
      && normalizedSql.includes('WHERE ut.membership_id = ? AND ut.tenant_id = ?')
      && normalizedSql.includes('FOR UPDATE')
    ) {
      return [{
        membership_id: 'membership-profile-update-missing-user',
        phone: null
      }];
    }
    if (
      normalizedSql.includes('UPDATE auth_user_tenants')
      && normalizedSql.includes('SET display_name = ?')
      && normalizedSql.includes('department_name = CASE')
    ) {
      updateCalled = true;
      return { affectedRows: 1 };
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  await assert.rejects(
    () =>
      store.updateTenantMembershipProfile({
        membershipId: 'membership-profile-update-missing-user',
        tenantId: 'tenant-profile-update-missing-user',
        displayName: '成员丁'
      }),
    /dependency unavailable: user-profile-missing/
  );
  assert.equal(updateCalled, false);
});

test('updateTenantMembershipProfile fails closed before update when locked membership row has malformed phone', async () => {
  let updateCalled = false;
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (
      normalizedSql.includes('SELECT ut.membership_id')
      && normalizedSql.includes('FROM auth_user_tenants ut')
      && normalizedSql.includes('LEFT JOIN users u ON u.id = ut.user_id')
      && normalizedSql.includes('WHERE ut.membership_id = ? AND ut.tenant_id = ?')
      && normalizedSql.includes('FOR UPDATE')
    ) {
      return [{
        membership_id: 'membership-profile-update-malformed-phone',
        phone: ' 13835556667'
      }];
    }
    if (
      normalizedSql.includes('UPDATE auth_user_tenants')
      && normalizedSql.includes('SET display_name = ?')
      && normalizedSql.includes('department_name = CASE')
    ) {
      updateCalled = true;
      return { affectedRows: 1 };
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  await assert.rejects(
    () =>
      store.updateTenantMembershipProfile({
        membershipId: 'membership-profile-update-malformed-phone',
        tenantId: 'tenant-profile-update-malformed-phone',
        displayName: '成员丁'
      }),
    /dependency unavailable: user-profile-missing/
  );
  assert.equal(updateCalled, false);
});

test('updateTenantMembershipProfile fails closed before update when locked membership row has malformed department and request omits department update', async () => {
  let updateCalled = false;
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (
      normalizedSql.includes('SELECT ut.membership_id')
      && normalizedSql.includes('FROM auth_user_tenants ut')
      && normalizedSql.includes('LEFT JOIN users u ON u.id = ut.user_id')
      && normalizedSql.includes('WHERE ut.membership_id = ? AND ut.tenant_id = ?')
      && normalizedSql.includes('FOR UPDATE')
    ) {
      return [{
        membership_id: 'membership-profile-update-malformed-department',
        department_name: '研发一部 ',
        phone: '13835556667'
      }];
    }
    if (
      normalizedSql.includes('UPDATE auth_user_tenants')
      && normalizedSql.includes('SET display_name = ?')
      && normalizedSql.includes('department_name = CASE')
    ) {
      updateCalled = true;
      return { affectedRows: 1 };
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  await assert.rejects(
    () =>
      store.updateTenantMembershipProfile({
        membershipId: 'membership-profile-update-malformed-department',
        tenantId: 'tenant-profile-update-malformed-department',
        displayName: '成员丁',
        departmentNameProvided: false
      }),
    /dependency unavailable: membership-profile-invalid/
  );
  assert.equal(updateCalled, false);
});

test('updateTenantMembershipProfile returns null when target membership does not exist', async () => {
  let updateCalled = false;
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (
      normalizedSql.includes('SELECT ut.membership_id')
      && normalizedSql.includes('FROM auth_user_tenants ut')
      && normalizedSql.includes('LEFT JOIN users u ON u.id = ut.user_id')
      && normalizedSql.includes('WHERE ut.membership_id = ? AND ut.tenant_id = ?')
      && normalizedSql.includes('FOR UPDATE')
    ) {
      return [];
    }
    if (normalizedSql.includes('UPDATE auth_user_tenants')) {
      updateCalled = true;
      return { affectedRows: 1 };
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  const result = await store.updateTenantMembershipProfile({
    membershipId: 'membership-profile-missing',
    tenantId: 'tenant-profile-missing',
    displayName: '成员乙'
  });

  assert.equal(updateCalled, false);
  assert.equal(result, null);
});

test('updateTenantMembershipProfile rejects blank displayName before executing SQL', async () => {
  let queryCalled = false;
  const store = createStore(async (sql) => {
    queryCalled = true;
    assert.fail(`unexpected query: ${String(sql)}`);
    return [];
  });

  await assert.rejects(
    () =>
      store.updateTenantMembershipProfile({
        membershipId: 'membership-profile-invalid',
        tenantId: 'tenant-profile-invalid',
        displayName: '   '
      }),
    /requires membershipId, tenantId and displayName/
  );
  assert.equal(queryCalled, false);
});

test('replaceTenantMembershipRoleBindingsAndSyncSnapshot rejects non-active membership inside transaction', async () => {
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (
      normalizedSql.includes('SELECT membership_id')
      && normalizedSql.includes('FROM auth_user_tenants')
      && normalizedSql.includes('FOR UPDATE')
      && normalizedSql.includes('WHERE membership_id = ? AND tenant_id = ?')
    ) {
      return [{
        membership_id: 'membership-binding-race',
        user_id: 'tenant-user-binding-race',
        tenant_id: 'tenant-binding-race',
        status: 'disabled'
      }];
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  await assert.rejects(
    () =>
      store.replaceTenantMembershipRoleBindingsAndSyncSnapshot({
        tenantId: 'tenant-binding-race',
        membershipId: 'membership-binding-race',
        roleIds: ['tenant_role_binding_race']
      }),
    (error) => {
      assert.equal(
        error?.code,
        'ERR_TENANT_MEMBERSHIP_ROLE_BINDINGS_MEMBERSHIP_NOT_ACTIVE'
      );
      return true;
    }
  );
});

test('replaceTenantMembershipRoleBindingsAndSyncSnapshot rejects disabled role bindings inside transaction', async () => {
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (
      normalizedSql.includes('SELECT membership_id')
      && normalizedSql.includes('FROM auth_user_tenants')
      && normalizedSql.includes('FOR UPDATE')
      && normalizedSql.includes('WHERE membership_id = ? AND tenant_id = ?')
    ) {
      return [{
        membership_id: 'membership-binding-role-race',
        user_id: 'tenant-user-binding-role-race',
        tenant_id: 'tenant-binding-role-race',
        status: 'active'
      }];
    }
    if (
      normalizedSql.includes('SELECT role_id, status, scope, tenant_id')
      && normalizedSql.includes('FROM platform_role_catalog')
      && normalizedSql.includes('FOR UPDATE')
    ) {
      return [{
        role_id: 'tenant_role_binding_disabled',
        status: 'disabled',
        scope: 'tenant',
        tenant_id: 'tenant-binding-role-race'
      }];
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  await assert.rejects(
    () =>
      store.replaceTenantMembershipRoleBindingsAndSyncSnapshot({
        tenantId: 'tenant-binding-role-race',
        membershipId: 'membership-binding-role-race',
        roleIds: ['tenant_role_binding_disabled']
      }),
    (error) => {
      assert.equal(
        error?.code,
        'ERR_TENANT_MEMBERSHIP_ROLE_BINDINGS_ROLE_INVALID'
      );
      assert.equal(error?.roleId, 'tenant_role_binding_disabled');
      return true;
    }
  );
});

test('replaceTenantMembershipRoleBindingsAndSyncSnapshot rejects malformed affected user id from membership row', async () => {
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (
      normalizedSql.includes('SELECT membership_id')
      && normalizedSql.includes('FROM auth_user_tenants')
      && normalizedSql.includes('FOR UPDATE')
      && normalizedSql.includes('WHERE membership_id = ? AND tenant_id = ?')
    ) {
      return [{
        membership_id: 'membership-binding-user-id-invalid',
        user_id: ' tenant-user-binding-invalid ',
        tenant_id: 'tenant-binding-user-id-invalid',
        status: 'active'
      }];
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  await assert.rejects(
    () =>
      store.replaceTenantMembershipRoleBindingsAndSyncSnapshot({
        tenantId: 'tenant-binding-user-id-invalid',
        membershipId: 'membership-binding-user-id-invalid',
        roleIds: []
      }),
    (error) => {
      assert.equal(
        error?.code,
        'ERR_TENANT_MEMBERSHIP_ROLE_BINDINGS_INVALID'
      );
      return true;
    }
  );
});

test('replaceTenantRolePermissionGrantsAndSyncSnapshots rejects malformed affected user ids from membership rows', async () => {
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (
      normalizedSql.includes('SELECT role_id')
      && normalizedSql.includes('FROM platform_role_catalog')
      && normalizedSql.includes("scope = 'tenant'")
      && normalizedSql.includes('FOR UPDATE')
    ) {
      return [{ role_id: 'tenant_role_permission_affected_user_invalid' }];
    }
    if (
      normalizedSql.includes('SELECT ut.membership_id, ut.user_id')
      && normalizedSql.includes('FROM auth_tenant_membership_roles mr')
      && normalizedSql.includes('JOIN auth_user_tenants ut ON ut.membership_id = mr.membership_id')
      && normalizedSql.includes('FOR UPDATE')
    ) {
      return [{
        membership_id: 'membership-role-permission-user-id-invalid',
        user_id: ' tenant-user-role-permission-invalid '
      }];
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  await assert.rejects(
    () =>
      store.replaceTenantRolePermissionGrantsAndSyncSnapshots({
        tenantId: 'tenant-role-permission-user-id-invalid',
        roleId: 'tenant_role_permission_affected_user_invalid',
        permissionCodes: ['tenant.member_admin.view']
      }),
    (error) => {
      assert.equal(error?.code, 'ERR_TENANT_ROLE_PERMISSION_GRANTS_INVALID');
      return true;
    }
  );
});

test('listTenantRolePermissionGrants rejects malformed permission codes from storage rows', async () => {
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (
      normalizedSql.includes('SELECT permission_code')
      && normalizedSql.includes('FROM tenant_role_permission_grants')
      && normalizedSql.includes('WHERE role_id = ?')
    ) {
      return [
        { permission_code: 'tenant.member_admin.view' },
        { permission_code: '   ' }
      ];
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  await assert.rejects(
    () =>
      store.listTenantRolePermissionGrants({
        roleId: 'tenant_role_permission_target'
      }),
    (error) => {
      assert.equal(error?.code, 'ERR_TENANT_ROLE_PERMISSION_GRANTS_INVALID');
      return true;
    }
  );
});

test('listTenantRolePermissionGrants rejects duplicate permission codes from storage rows', async () => {
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (
      normalizedSql.includes('SELECT permission_code')
      && normalizedSql.includes('FROM tenant_role_permission_grants')
      && normalizedSql.includes('WHERE role_id = ?')
    ) {
      return [
        { permission_code: 'tenant.member_admin.view' },
        { permission_code: 'TENANT.MEMBER_ADMIN.VIEW' }
      ];
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  await assert.rejects(
    () =>
      store.listTenantRolePermissionGrants({
        roleId: 'tenant_role_permission_duplicate_target'
      }),
    (error) => {
      assert.equal(error?.code, 'ERR_TENANT_ROLE_PERMISSION_GRANTS_INVALID');
      return true;
    }
  );
});

test('listTenantRolePermissionGrantsByRoleIds rejects unexpected role rows from storage', async () => {
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (
      normalizedSql.includes('SELECT role_id, permission_code')
      && normalizedSql.includes('FROM tenant_role_permission_grants')
      && normalizedSql.includes('WHERE role_id IN')
    ) {
      return [
        {
          role_id: 'tenant_role_permission_batch_expected',
          permission_code: 'tenant.member_admin.view'
        },
        {
          role_id: 'tenant_role_permission_batch_unexpected',
          permission_code: 'tenant.billing.view'
        }
      ];
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  await assert.rejects(
    () =>
      store.listTenantRolePermissionGrantsByRoleIds({
        roleIds: ['tenant_role_permission_batch_expected']
      }),
    (error) => {
      assert.equal(error?.code, 'ERR_TENANT_ROLE_PERMISSION_GRANTS_INVALID');
      return true;
    }
  );
});

test('listTenantRolePermissionGrants rejects permission codes with surrounding whitespace from storage rows', async () => {
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (
      normalizedSql.includes('SELECT permission_code')
      && normalizedSql.includes('FROM tenant_role_permission_grants')
      && normalizedSql.includes('WHERE role_id = ?')
    ) {
      return [
        { permission_code: ' tenant.member_admin.view' }
      ];
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  await assert.rejects(
    () =>
      store.listTenantRolePermissionGrants({
        roleId: 'tenant_role_permission_whitespace_target'
      }),
    (error) => {
      assert.equal(error?.code, 'ERR_TENANT_ROLE_PERMISSION_GRANTS_INVALID');
      return true;
    }
  );
});

test('listTenantRolePermissionGrantsByRoleIds rejects role rows with surrounding whitespace', async () => {
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (
      normalizedSql.includes('SELECT role_id, permission_code')
      && normalizedSql.includes('FROM tenant_role_permission_grants')
      && normalizedSql.includes('WHERE role_id IN')
    ) {
      return [
        {
          role_id: ' tenant_role_permission_batch_whitespace',
          permission_code: 'tenant.member_admin.view'
        }
      ];
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  await assert.rejects(
    () =>
      store.listTenantRolePermissionGrantsByRoleIds({
        roleIds: ['tenant_role_permission_batch_whitespace']
      }),
    (error) => {
      assert.equal(error?.code, 'ERR_TENANT_ROLE_PERMISSION_GRANTS_INVALID');
      return true;
    }
  );
});

test('listTenantMembershipRoleBindings rejects role ids with surrounding whitespace from storage rows', async () => {
  const store = createStore(async (sql) => {
    const normalizedSql = String(sql);
    if (
      normalizedSql.includes('SELECT mr.role_id')
      && normalizedSql.includes('FROM auth_tenant_membership_roles mr')
      && normalizedSql.includes('JOIN auth_user_tenants ut ON ut.membership_id = mr.membership_id')
    ) {
      return [
        { role_id: ' tenant_role_binding_whitespace' }
      ];
    }
    assert.fail(`unexpected query: ${normalizedSql}`);
    return [];
  });

  await assert.rejects(
    () =>
      store.listTenantMembershipRoleBindings({
        membershipId: 'membership-role-binding-whitespace',
        tenantId: 'tenant-role-binding-whitespace'
      }),
    (error) => {
      assert.equal(error?.code, 'ERR_TENANT_MEMBERSHIP_ROLE_BINDINGS_INVALID');
      return true;
    }
  );
});
