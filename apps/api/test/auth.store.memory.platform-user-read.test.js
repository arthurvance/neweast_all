const test = require('node:test');
const assert = require('node:assert/strict');

const { createInMemoryAuthStore } = require('../src/modules/auth/auth.store.memory');

const createStore = () =>
  createInMemoryAuthStore({
    seedUsers: [
      {
        id: 'Platform-User-Alpha',
        phone: '13800000011',
        status: 'active',
        passwordHash: 'seed-hash-1',
        domains: ['platform']
      },
      {
        id: 'tenant-only-user',
        phone: '13800000012',
        status: 'active',
        passwordHash: 'seed-hash-2',
        domains: ['tenant']
      }
    ]
  });

test('listPlatformUsers supports enabled alias and case-insensitive keyword matching', async () => {
  const store = createStore();

  const payload = await store.listPlatformUsers({
    page: 1,
    pageSize: 20,
    status: 'enabled',
    keyword: 'PLATFORM-USER'
  });

  assert.equal(payload.total, 1);
  assert.equal(payload.items.length, 1);
  assert.equal(payload.items[0].user_id, 'Platform-User-Alpha');
  assert.equal(payload.items[0].status, 'active');
});

test('getPlatformUserById reflects current platform-domain status after status update', async () => {
  const store = createStore();

  await store.updatePlatformUserStatus({
    userId: 'Platform-User-Alpha',
    nextStatus: 'disabled',
    operatorUserId: 'platform-operator'
  });

  const detail = await store.getPlatformUserById({
    userId: 'Platform-User-Alpha'
  });
  const tenantOnlyDetail = await store.getPlatformUserById({
    userId: 'tenant-only-user'
  });

  assert.equal(detail?.user_id, 'Platform-User-Alpha');
  assert.equal(detail?.status, 'disabled');
  assert.equal(tenantOnlyDetail, null);
});
