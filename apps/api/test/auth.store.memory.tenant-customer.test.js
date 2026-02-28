const test = require('node:test');
const assert = require('node:assert/strict');

const {
  createInMemoryAuthStore
} = require('../src/shared-kernel/auth/store/create-in-memory-auth-store');

const createStore = () =>
  createInMemoryAuthStore({
    seedUsers: [
      {
        id: 'tenant-customer-user-1',
        phone: '13800002001',
        passwordHash: 'seed-password-hash-tenant-customer-user-1',
        status: 'active',
        domains: ['tenant'],
        tenants: [
          {
            tenantId: 'tenant-customer-a',
            tenantName: 'Tenant Customer A',
            membershipId: 'membership-customer-owner-1',
            status: 'active',
            displayName: '客户负责人A'
          }
        ]
      },
      {
        id: 'tenant-customer-user-2',
        phone: '13800002002',
        passwordHash: 'seed-password-hash-tenant-customer-user-2',
        status: 'active',
        domains: ['tenant'],
        tenants: [
          {
            tenantId: 'tenant-customer-a',
            tenantName: 'Tenant Customer A',
            membershipId: 'membership-customer-assistant-1',
            status: 'active',
            displayName: '客户协管A'
          }
        ]
      },
      {
        id: 'tenant-customer-user-3',
        phone: '13800002003',
        passwordHash: 'seed-password-hash-tenant-customer-user-3',
        status: 'active',
        domains: ['tenant'],
        tenants: [
          {
            tenantId: 'tenant-customer-a',
            tenantName: 'Tenant Customer A',
            membershipId: 'membership-customer-owner-2',
            status: 'active',
            displayName: '客户负责人B'
          }
        ]
      }
    ]
  });

test('memory auth store supports tenant customer CRUD, scope filters, and operation logs', async () => {
  const store = createStore();

  const account = await store.createTenantAccount({
    tenantId: 'tenant-customer-a',
    wechatId: 'wx_customer_account_1',
    nickname: '客户账号A',
    ownerMembershipId: 'membership-customer-owner-1',
    assistantMembershipIds: ['membership-customer-assistant-1'],
    operatorUserId: 'tenant-customer-user-1',
    operatorName: '客户负责人A'
  });

  const created = await store.createTenantCustomer({
    tenantId: 'tenant-customer-a',
    accountId: account.account_id,
    wechatId: 'wx_customer_memory_1',
    nickname: '内存客户A',
    source: 'ground',
    status: 'enabled',
    realName: '学生甲',
    school: '实验小学',
    className: '三年二班',
    relation: '家长',
    phone: '13800009999',
    address: '测试路 1 号',
    operatorUserId: 'tenant-customer-user-1',
    operatorName: '客户负责人A',
    operationAt: '2026-02-10T08:00:00.000Z'
  });

  assert.equal(created.tenant_id, 'tenant-customer-a');
  assert.equal(created.account_id, account.account_id);
  assert.equal(created.wechat_id, 'wx_customer_memory_1');
  assert.equal(created.status, 'enabled');
  assert.equal(created.real_name, '学生甲');
  assert.ok(String(created.customer_id || '').startsWith('cus_'));
  const accountAfterCreate = await store.findTenantAccountByAccountId({
    tenantId: 'tenant-customer-a',
    accountId: account.account_id
  });
  assert.equal(accountAfterCreate.customer_count, 1);

  const myScopeList = await store.listTenantCustomersByTenantId({
    tenantId: 'tenant-customer-a',
    operatorUserId: 'tenant-customer-user-1',
    scope: 'my',
    filters: {
      nickname: '内存客户',
      source: 'ground',
      status: 'enabled'
    }
  });
  assert.equal(myScopeList.length, 1);
  assert.equal(myScopeList[0].customer_id, created.customer_id);

  const assistScopeList = await store.listTenantCustomersByTenantId({
    tenantId: 'tenant-customer-a',
    operatorUserId: 'tenant-customer-user-2',
    scope: 'assist',
    filters: {
      realName: '学生',
      phone: '13800009999'
    }
  });
  assert.equal(assistScopeList.length, 1);
  assert.equal(assistScopeList[0].customer_id, created.customer_id);

  const basicUpdated = await store.updateTenantCustomer({
    tenantId: 'tenant-customer-a',
    customerId: created.customer_id,
    nickname: '内存客户A-更新',
    source: 'fission',
    operatorUserId: 'tenant-customer-user-1',
    operatorName: '客户负责人A',
    operationAt: '2026-02-12T09:00:00.000Z'
  });
  assert.equal(basicUpdated.source, 'fission');
  assert.equal(basicUpdated.nickname, '内存客户A-更新');

  const realnameUpdated = await store.updateTenantCustomer({
    tenantId: 'tenant-customer-a',
    customerId: created.customer_id,
    nickname: '内存客户A-更新',
    source: 'fission',
    realName: '学生乙',
    school: '实验中学',
    className: '七年一班',
    relation: '母亲',
    phone: '13800008888',
    address: '测试路 2 号',
    operatorUserId: 'tenant-customer-user-1',
    operatorName: '客户负责人A',
    operationAt: '2026-02-12T09:30:00.000Z'
  });
  assert.equal(realnameUpdated.real_name, '学生乙');
  assert.equal(realnameUpdated.school, '实验中学');
  assert.equal(realnameUpdated.phone, '13800008888');

  const detail = await store.findTenantCustomerByCustomerId({
    tenantId: 'tenant-customer-a',
    customerId: created.customer_id
  });
  assert.equal(detail.customer_id, created.customer_id);
  assert.equal(detail.source, 'fission');
  assert.equal(detail.real_name, '学生乙');

  const operationLogs = await store.listTenantCustomerOperationLogs({
    tenantId: 'tenant-customer-a',
    customerId: created.customer_id,
    limit: 10
  });
  assert.equal(Array.isArray(operationLogs), true);
  assert.equal(operationLogs.length >= 3, true);
  assert.equal(operationLogs[0].operation_type, 'update');
});

test('memory tenant customer store rejects create on non-existent account', async () => {
  const store = createStore();

  await assert.rejects(
    () =>
      store.createTenantCustomer({
        tenantId: 'tenant-customer-a',
        accountId: 'acc_not_exists',
        wechatId: 'wx_customer_memory_missing_account',
        nickname: '缺失账号客户',
        source: 'ground',
        operatorUserId: 'tenant-customer-user-1',
        operatorName: '客户负责人A'
      }),
    (error) =>
      error
      && error.code === 'ERR_TENANT_CUSTOMER_ACCOUNT_NOT_FOUND'
  );
});

test('memory tenant customer store allows nullable wechat_id on create and update', async () => {
  const store = createStore();

  const account = await store.createTenantAccount({
    tenantId: 'tenant-customer-a',
    wechatId: 'wx_customer_account_nullable_1',
    nickname: '客户账号C',
    ownerMembershipId: 'membership-customer-owner-1',
    assistantMembershipIds: [],
    operatorUserId: 'tenant-customer-user-1',
    operatorName: '客户负责人A'
  });

  const created = await store.createTenantCustomer({
    tenantId: 'tenant-customer-a',
    accountId: account.account_id,
    nickname: '无微信客户',
    source: 'ground',
    operatorUserId: 'tenant-customer-user-1',
    operatorName: '客户负责人A'
  });
  assert.equal(created.wechat_id, null);

  const updated = await store.updateTenantCustomer({
    tenantId: 'tenant-customer-a',
    customerId: created.customer_id,
    wechatId: 'wx_customer_nullable_1',
    nickname: '无微信客户',
    source: 'ground',
    operatorUserId: 'tenant-customer-user-1',
    operatorName: '客户负责人A'
  });
  assert.equal(updated.wechat_id, 'wx_customer_nullable_1');
});

test('memory tenant customer store enforces scope checks for detail and operation logs', async () => {
  const store = createStore();

  const account = await store.createTenantAccount({
    tenantId: 'tenant-customer-a',
    wechatId: 'wx_customer_account_scope_1',
    nickname: '客户账号B',
    ownerMembershipId: 'membership-customer-owner-2',
    assistantMembershipIds: [],
    operatorUserId: 'tenant-customer-user-3',
    operatorName: '客户负责人B'
  });

  const created = await store.createTenantCustomer({
    tenantId: 'tenant-customer-a',
    accountId: account.account_id,
    wechatId: 'wx_customer_scope_1',
    nickname: '作用域客户',
    source: 'ground',
    operatorUserId: 'tenant-customer-user-3',
    operatorName: '客户负责人B'
  });

  const deniedDetail = await store.findTenantCustomerByCustomerId({
    tenantId: 'tenant-customer-a',
    customerId: created.customer_id,
    operatorUserId: 'tenant-customer-user-1',
    scopes: ['my']
  });
  assert.equal(deniedDetail, null);

  const deniedLogs = await store.listTenantCustomerOperationLogs({
    tenantId: 'tenant-customer-a',
    customerId: created.customer_id,
    operatorUserId: 'tenant-customer-user-1',
    scopes: ['my']
  });
  assert.deepEqual(deniedLogs, []);

  const allowedDetail = await store.findTenantCustomerByCustomerId({
    tenantId: 'tenant-customer-a',
    customerId: created.customer_id,
    operatorUserId: 'tenant-customer-user-3',
    scopes: ['my']
  });
  assert.equal(allowedDetail.customer_id, created.customer_id);
});
