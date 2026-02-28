'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  createTenantMysqlAuthStoreAccountMatrix
} = require('../src/domains/tenant/auth/store/mysql/tenant-mysql-auth-store-account-matrix');

const MYSQL_TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}$/;

const normalizeStoreIsoTimestamp = (value) => {
  if (value === null || value === undefined) {
    return null;
  }
  const parsed = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return '';
  }
  return parsed.toISOString();
};

const formatAuditDateTimeForMySql = (value) => {
  const normalizedIsoTimestamp = normalizeStoreIsoTimestamp(value);
  if (!normalizedIsoTimestamp) {
    return '';
  }
  return `${normalizedIsoTimestamp.slice(0, 19).replace('T', ' ')}.${normalizedIsoTimestamp.slice(20, 23)}`;
};

test('createTenantAccount persists MySQL datetime strings instead of ISO strings', async () => {
  let accountInsertParams = null;
  let operationLogInsertParams = null;
  let createdAccountId = '';

  const store = createTenantMysqlAuthStoreAccountMatrix({
    CONTROL_CHAR_PATTERN: /[\u0000-\u001F\u007F]/,
    dbClient: {
      query: async (sql, params = []) => {
        const normalizedSql = String(sql);
        if (
          normalizedSql.includes('SELECT a.account_id')
          && normalizedSql.includes('FROM tenant_accounts a')
        ) {
          return [
            {
              account_id: createdAccountId,
              tenant_id: 'tenant_1',
              wechat_id: 'wx_account_01',
              nickname: '顾问小东',
              owner_membership_id: 'membership_owner_1',
              customer_count: 0,
              group_chat_count: 0,
              status: 'enabled',
              avatar_url: null,
              created_by_user_id: 'user_1',
              updated_by_user_id: 'user_1',
              created_at: accountInsertParams?.[11] || '2026-02-27 04:29:45.068',
              updated_at: accountInsertParams?.[12] || '2026-02-27 04:29:45.068',
              assistant_membership_ids_csv: ''
            }
          ];
        }
        assert.fail(`unexpected dbClient.query SQL: ${normalizedSql}`);
        return [];
      },
      inTransaction: async (runner) =>
        runner({
          query: async (sql, params = []) => {
            const normalizedSql = String(sql);
            if (normalizedSql.includes('INSERT INTO tenant_accounts')) {
              accountInsertParams = params;
              createdAccountId = String(params?.[0] || '');
              return { affectedRows: 1 };
            }
            if (normalizedSql.includes('INSERT INTO tenant_account_operation_logs')) {
              operationLogInsertParams = params;
              return { affectedRows: 1 };
            }
            if (normalizedSql.includes('INSERT INTO tenant_account_assistants')) {
              return { affectedRows: 1 };
            }
            assert.fail(`unexpected tx.query SQL: ${normalizedSql}`);
            return [];
          }
        })
    },
    executeWithDeadlockRetry: ({ execute }) => execute(),
    escapeSqlLikePattern: (value) =>
      String(value || '').replace(/([%_\\])/g, '\\$1'),
    formatAuditDateTimeForMySql,
    isDuplicateEntryError: () => false,
    normalizeStoreIsoTimestamp,
    randomUUID: () => '12345678-1234-1234-1234-1234567890ab'
  });

  const operationAt = '2026-02-27T04:29:45.068Z';
  await store.createTenantAccount({
    tenantId: 'tenant_1',
    wechatId: 'wx_account_01',
    nickname: '顾问小东',
    ownerMembershipId: 'membership_owner_1',
    assistantMembershipIds: ['membership_assistant_1'],
    operatorUserId: 'user_1',
    operatorName: '系统管理员',
    operationAt
  });

  assert.ok(Array.isArray(accountInsertParams));
  assert.ok(Array.isArray(operationLogInsertParams));

  assert.equal(MYSQL_TIMESTAMP_PATTERN.test(accountInsertParams[11]), true);
  assert.equal(MYSQL_TIMESTAMP_PATTERN.test(accountInsertParams[12]), true);
  assert.equal(accountInsertParams[11].includes('T'), false);
  assert.equal(accountInsertParams[12].endsWith('Z'), false);
  assert.equal(accountInsertParams[11], '2026-02-27 04:29:45.068');

  assert.equal(MYSQL_TIMESTAMP_PATTERN.test(operationLogInsertParams[7]), true);
  assert.equal(MYSQL_TIMESTAMP_PATTERN.test(operationLogInsertParams[8]), true);
  assert.equal(operationLogInsertParams[7].includes('T'), false);
  assert.equal(operationLogInsertParams[8].endsWith('Z'), false);
  assert.equal(operationLogInsertParams[7], '2026-02-27 04:29:45.068');
});

test('listTenantAccountsByTenantId status filter keeps legacy active/inactive compatibility', async () => {
  const capturedQueries = [];
  const store = createTenantMysqlAuthStoreAccountMatrix({
    CONTROL_CHAR_PATTERN: /[\u0000-\u001F\u007F]/,
    dbClient: {
      query: async (sql, params = []) => {
        capturedQueries.push({
          sql: String(sql),
          params: [...params]
        });
        return [];
      },
      inTransaction: async (runner) =>
        runner({
          query: async () => ({ affectedRows: 1 })
        })
    },
    executeWithDeadlockRetry: ({ execute }) => execute(),
    escapeSqlLikePattern: (value) =>
      String(value || '').replace(/([%_\\])/g, '\\$1'),
    formatAuditDateTimeForMySql,
    isDuplicateEntryError: () => false,
    normalizeStoreIsoTimestamp,
    randomUUID: () => '87654321-4321-4321-4321-ba0987654321'
  });

  await store.listTenantAccountsByTenantId({
    tenantId: 'tenant_1',
    filters: {
      status: 'enabled'
    }
  });
  await store.listTenantAccountsByTenantId({
    tenantId: 'tenant_1',
    filters: {
      status: 'disabled'
    }
  });

  const enabledQuery = capturedQueries.find((entry) =>
    entry.sql.includes('FROM tenant_accounts a') && entry.params.includes('enabled')
  );
  const disabledQuery = capturedQueries.find((entry) =>
    entry.sql.includes('FROM tenant_accounts a') && entry.params.includes('disabled')
  );

  assert.ok(enabledQuery, 'enabled status query should be issued');
  assert.ok(disabledQuery, 'disabled status query should be issued');
  assert.match(enabledQuery.sql, /a\.status IN \(\?, \?\)/);
  assert.match(disabledQuery.sql, /a\.status IN \(\?, \?\)/);
  assert.deepEqual(
    enabledQuery.params.slice(0, 3),
    ['tenant_1', 'enabled', 'active']
  );
  assert.deepEqual(
    disabledQuery.params.slice(0, 3),
    ['tenant_1', 'disabled', 'inactive']
  );
});
