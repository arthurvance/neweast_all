const test = require('node:test');
const assert = require('node:assert/strict');

const { createInMemoryAuthStore } = require('../src/shared-kernel/auth/store/create-in-memory-auth-store');

const createStore = () =>
  createInMemoryAuthStore({
    seedUsers: [
      {
        id: 'Platform-User-Alpha',
        phone: '13800000011',
        status: 'active',
        passwordHash: 'seed-hash-1',
        domains: ['platform'],
        createdAt: '2026-01-05T09:30:00.000Z',
        platformProfile: {
          name: '张三',
          department: '研发部'
        }
      },
      {
        id: 'tenant-only-user',
        phone: '13800000012',
        status: 'active',
        passwordHash: 'seed-hash-2',
        domains: ['tenant'],
        createdAt: '2026-01-07T10:00:00.000Z'
      }
    ]
  });

test('listPlatformUsers supports enabled alias and advanced filters', async () => {
  const store = createStore();

  const payload = await store.listPlatformUsers({
    page: 1,
    pageSize: 20,
    status: 'enabled',
    phone: '13800000011',
    name: '张',
    createdAtStart: '2026-01-01T00:00:00.000Z',
    createdAtEnd: '2026-01-31T23:59:59.999Z'
  });

  assert.equal(payload.total, 1);
  assert.equal(payload.items.length, 1);
  assert.equal(payload.items[0].user_id, 'Platform-User-Alpha');
  assert.equal(payload.items[0].status, 'active');
  assert.equal(payload.items[0].name, '张三');
  assert.equal(payload.items[0].department, '研发部');
  assert.equal(payload.items[0].created_at, '2026-01-05T09:30:00.000Z');
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
  assert.equal(detail?.name, '张三');
  assert.equal(detail?.department, '研发部');
  assert.equal(detail?.created_at, '2026-01-05T09:30:00.000Z');
  assert.equal(tenantOnlyDetail, null);
});
