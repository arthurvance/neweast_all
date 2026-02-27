'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  createTenantMysqlAuthStoreCustomer
} = require('../src/domains/tenant/auth/store/mysql/tenant-mysql-auth-store-customer');

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

const createStore = ({ dbClient }) =>
  createTenantMysqlAuthStoreCustomer({
    CONTROL_CHAR_PATTERN: /[\u0000-\u001F\u007F]/,
    dbClient,
    executeWithDeadlockRetry: ({ execute }) => execute(),
    escapeSqlLikePattern: (value) =>
      String(value || '').replace(/([%_\\])/g, '\\$1'),
    formatAuditDateTimeForMySql,
    isDuplicateEntryError: () => false,
    normalizeStoreIsoTimestamp,
    randomUUID: () => '12345678-1234-1234-1234-1234567890ab'
  });

test('mysql tenant customer create persists datetime strings and updates account customer_count', async () => {
  let customerInsertParams = null;
  let profileInsertParams = null;
  let operationLogInsertParams = null;
  let customerCountUpdateParams = null;
  let createdCustomerId = '';

  const store = createStore({
    dbClient: {
      query: async (sql, params = []) => {
        const normalizedSql = String(sql).replace(/\s+/g, ' ').trim();
        if (
          normalizedSql.includes('SELECT account_id, status')
          && normalizedSql.includes('FROM tenant_accounts')
        ) {
          return [
            {
              account_id: 'acc_1',
              status: 'enabled'
            }
          ];
        }
        if (
          normalizedSql.includes('SELECT c.customer_id')
          && normalizedSql.includes('FROM tenant_customers c')
          && normalizedSql.includes('WHERE c.tenant_id = ?')
          && normalizedSql.includes('AND c.customer_id = ?')
        ) {
          return [
            {
              customer_id: createdCustomerId || 'cus_fallback',
              tenant_id: 'tenant_1',
              account_id: 'acc_1',
              wechat_id: 'wx_customer_01',
              nickname: '客户甲',
              source: 'ground',
              status: 'enabled',
              created_by_user_id: 'user_1',
              updated_by_user_id: 'user_1',
              created_at: '2026-02-27T04:29:45.068Z',
              updated_at: '2026-02-27T04:29:45.068Z',
              real_name: '学生甲',
              school: '实验小学',
              class_name: '三年二班',
              relation: '家长',
              phone: '13800009999',
              address: '测试路 1 号'
            }
          ];
        }
        assert.fail(`unexpected dbClient.query SQL: ${normalizedSql}`);
        return [];
      },
      inTransaction: async (runner) =>
        runner({
          query: async (sql, params = []) => {
            const normalizedSql = String(sql).replace(/\s+/g, ' ').trim();
            if (normalizedSql.includes('INSERT INTO tenant_customers')) {
              customerInsertParams = params;
              createdCustomerId = String(params?.[0] || '');
              return { affectedRows: 1 };
            }
            if (normalizedSql.includes('UPDATE tenant_accounts')) {
              customerCountUpdateParams = params;
              return { affectedRows: 1 };
            }
            if (normalizedSql.includes('INSERT INTO tenant_customer_profiles')) {
              profileInsertParams = params;
              return { affectedRows: 1 };
            }
            if (normalizedSql.includes('INSERT INTO tenant_customer_operation_logs')) {
              operationLogInsertParams = params;
              return { affectedRows: 1 };
            }
            assert.fail(`unexpected tx.query SQL: ${normalizedSql}`);
            return [];
          }
        })
    }
  });

  const created = await store.createTenantCustomer({
    tenantId: 'tenant_1',
    accountId: 'acc_1',
    wechatId: 'wx_customer_01',
    nickname: '客户甲',
    source: 'ground',
    status: 'enabled',
    realName: '学生甲',
    school: '实验小学',
    className: '三年二班',
    relation: '家长',
    phone: '13800009999',
    address: '测试路 1 号',
    operatorUserId: 'user_1',
    operatorName: '系统管理员',
    operationAt: '2026-02-27T04:29:45.068Z'
  });

  assert.ok(createdCustomerId.length > 0);
  assert.equal(created.customer_id, createdCustomerId);
  assert.ok(Array.isArray(customerInsertParams));
  assert.ok(Array.isArray(profileInsertParams));
  assert.ok(Array.isArray(operationLogInsertParams));
  assert.deepEqual(customerCountUpdateParams, ['tenant_1', 'acc_1']);

  assert.equal(MYSQL_TIMESTAMP_PATTERN.test(customerInsertParams[9]), true);
  assert.equal(MYSQL_TIMESTAMP_PATTERN.test(customerInsertParams[10]), true);
  assert.equal(customerInsertParams[9], '2026-02-27 04:29:45.068');
  assert.equal(customerInsertParams[10], '2026-02-27 04:29:45.068');

  assert.equal(MYSQL_TIMESTAMP_PATTERN.test(profileInsertParams[8]), true);
  assert.equal(MYSQL_TIMESTAMP_PATTERN.test(profileInsertParams[9]), true);
  assert.equal(profileInsertParams[8], '2026-02-27 04:29:45.068');
  assert.equal(profileInsertParams[9], '2026-02-27 04:29:45.068');

  assert.equal(MYSQL_TIMESTAMP_PATTERN.test(operationLogInsertParams[7]), true);
  assert.equal(MYSQL_TIMESTAMP_PATTERN.test(operationLogInsertParams[8]), true);
  assert.equal(operationLogInsertParams[7], '2026-02-27 04:29:45.068');
  assert.equal(operationLogInsertParams[8], '2026-02-27 04:29:45.068');
});

test('mysql tenant customer scope restrictions deny detail and logs when operator has no membership', async () => {
  let membershipQueryCount = 0;
  let customerQueryCount = 0;
  let logQueryCount = 0;

  const store = createStore({
    dbClient: {
      query: async (sql) => {
        const normalizedSql = String(sql).replace(/\s+/g, ' ').trim();
        if (
          normalizedSql.includes('SELECT membership_id')
          && normalizedSql.includes('FROM tenant_memberships')
        ) {
          membershipQueryCount += 1;
          return [];
        }
        if (
          normalizedSql.includes('SELECT c.customer_id')
          && normalizedSql.includes('FROM tenant_customers c')
        ) {
          customerQueryCount += 1;
          return [];
        }
        if (
          normalizedSql.includes('FROM tenant_customer_operation_logs')
          && normalizedSql.includes('WHERE tenant_id = ?')
        ) {
          logQueryCount += 1;
          return [];
        }
        assert.fail(`unexpected dbClient.query SQL: ${normalizedSql}`);
        return [];
      },
      inTransaction: async () => {
        assert.fail('inTransaction should not be called for read-only scope checks');
      }
    }
  });

  const detail = await store.findTenantCustomerByCustomerId({
    tenantId: 'tenant_1',
    customerId: 'cus_001',
    operatorUserId: 'user_scope_limited',
    scopes: ['my']
  });
  assert.equal(detail, null);

  const logs = await store.listTenantCustomerOperationLogs({
    tenantId: 'tenant_1',
    customerId: 'cus_001',
    operatorUserId: 'user_scope_limited',
    scopes: ['my'],
    limit: 10
  });
  assert.deepEqual(logs, []);

  assert.equal(membershipQueryCount, 2);
  assert.equal(customerQueryCount, 0);
  assert.equal(logQueryCount, 0);
});

test('mysql tenant customer uses assist scope SQL filter for detail and operation logs', async () => {
  let customerSelectSql = '';
  let customerSelectParams = null;
  let operationLogQueryCount = 0;

  const store = createStore({
    dbClient: {
      query: async (sql, params = []) => {
        const normalizedSql = String(sql).replace(/\s+/g, ' ').trim();
        if (
          normalizedSql.includes('SELECT membership_id')
          && normalizedSql.includes('FROM tenant_memberships')
        ) {
          return [{ membership_id: 'membership_assist_1' }];
        }
        if (
          normalizedSql.includes('SELECT c.customer_id')
          && normalizedSql.includes('FROM tenant_customers c')
        ) {
          customerSelectSql = normalizedSql;
          customerSelectParams = params;
          return [
            {
              customer_id: 'cus_001',
              tenant_id: 'tenant_1',
              account_id: 'acc_1',
              wechat_id: 'wx_customer_01',
              nickname: '客户甲',
              source: 'ground',
              status: 'enabled',
              created_by_user_id: 'user_1',
              updated_by_user_id: 'user_1',
              created_at: '2026-02-27T04:29:45.068Z',
              updated_at: '2026-02-27T04:29:45.068Z',
              real_name: '学生甲',
              school: null,
              class_name: null,
              relation: null,
              phone: null,
              address: null
            }
          ];
        }
        if (
          normalizedSql.includes('FROM tenant_customer_operation_logs')
          && normalizedSql.includes('WHERE tenant_id = ?')
        ) {
          operationLogQueryCount += 1;
          return [
            {
              operation_id: 'cop_001',
              tenant_id: 'tenant_1',
              customer_id: 'cus_001',
              operation_type: 'create',
              operation_content: '新建',
              operator_user_id: 'user_1',
              operator_name: '管理员',
              operation_time: '2026-02-27T04:29:45.068Z',
              created_at: '2026-02-27T04:29:45.068Z'
            }
          ];
        }
        assert.fail(`unexpected dbClient.query SQL: ${normalizedSql}`);
        return [];
      },
      inTransaction: async () => {
        assert.fail('inTransaction should not be called for read-only scope checks');
      }
    }
  });

  const detail = await store.findTenantCustomerByCustomerId({
    tenantId: 'tenant_1',
    customerId: 'cus_001',
    operatorUserId: 'user_scope_assist',
    scopes: ['assist']
  });
  assert.equal(detail.customer_id, 'cus_001');
  assert.match(customerSelectSql, /tenant_account_assistants/i);
  assert.match(customerSelectSql, /assistant_membership_id IN \(\?\)/i);
  assert.deepEqual(customerSelectParams, [
    'tenant_1',
    'cus_001',
    'membership_assist_1'
  ]);

  const logs = await store.listTenantCustomerOperationLogs({
    tenantId: 'tenant_1',
    customerId: 'cus_001',
    operatorUserId: 'user_scope_assist',
    scopes: ['assist'],
    limit: 10
  });
  assert.equal(logs.length, 1);
  assert.equal(logs[0].operation_id, 'cop_001');
  assert.equal(operationLogQueryCount, 1);
});
