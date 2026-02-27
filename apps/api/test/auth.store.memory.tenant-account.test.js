const test = require('node:test');
const assert = require('node:assert/strict');

const {
  createInMemoryAuthStore
} = require('../src/shared-kernel/auth/store/create-in-memory-auth-store');

const createStore = () =>
  createInMemoryAuthStore({
    seedUsers: [
      {
        id: 'tenant-account-user-1',
        phone: '13800001001',
        passwordHash: 'seed-password-hash-tenant-account-user-1',
        status: 'active',
        domains: ['tenant'],
        tenants: [
          {
            tenantId: 'tenant-account-a',
            tenantName: 'Tenant Account A',
            membershipId: 'membership-account-owner-1',
            status: 'active',
            displayName: '账号负责人A'
          }
        ]
      }
    ]
  });

test('memory auth store supports tenant account matrix CRUD without missing dependency maps', async () => {
  const store = createStore();

  const created = await store.createTenantAccount({
    tenantId: 'tenant-account-a',
    wechatId: 'wx_account_memory_1',
    nickname: '内存账号A',
    ownerMembershipId: 'membership-account-owner-1',
    assistantMembershipIds: [],
    operatorUserId: 'tenant-account-user-1',
    operatorName: '账号负责人A'
  });

  assert.equal(created.tenant_id, 'tenant-account-a');
  assert.equal(created.wechat_id, 'wx_account_memory_1');
  assert.equal(created.nickname, '内存账号A');
  assert.equal(created.status, 'enabled');
  assert.ok(String(created.account_id || '').startsWith('acc_'));

  const listed = await store.listTenantAccountsByTenantId({
    tenantId: 'tenant-account-a',
    page: 1,
    pageSize: 20
  });
  assert.equal(Array.isArray(listed), true);
  assert.equal(listed.length, 1);
  assert.equal(listed[0].account_id, created.account_id);

  const statusUpdated = await store.updateTenantAccountStatus({
    tenantId: 'tenant-account-a',
    accountId: created.account_id,
    status: 'disabled',
    operatorUserId: 'tenant-account-user-1',
    operatorName: '账号负责人A'
  });
  assert.equal(statusUpdated.status, 'disabled');

  const detail = await store.findTenantAccountByAccountId({
    tenantId: 'tenant-account-a',
    accountId: created.account_id
  });
  assert.equal(detail.account_id, created.account_id);
  assert.equal(detail.status, 'disabled');

  const operationLogs = await store.listTenantAccountOperationLogs({
    tenantId: 'tenant-account-a',
    accountId: created.account_id,
    limit: 10
  });
  assert.equal(Array.isArray(operationLogs), true);
  assert.equal(operationLogs.length >= 2, true);
  assert.equal(operationLogs[0].operation_type, 'status');
});
