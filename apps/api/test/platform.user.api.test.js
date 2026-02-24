const test = require('node:test');
const assert = require('node:assert/strict');
const { createRouteHandlers } = require('../src/http-routes');
const { createPlatformUserHandlers } = require('../src/modules/platform/user.routes');
const { createPlatformUserService } = require('../src/modules/platform/user.service');
const { dispatchApiRoute } = require('../src/server');
const { readConfig } = require('../src/config/env');
const { AuthProblemError } = require('../src/modules/auth/auth.routes');

const config = readConfig({ ALLOW_MOCK_BACKENDS: 'true' });
const dependencyProbe = async () => ({
  db: { ok: true },
  redis: { ok: true }
});

const createHarness = ({
  authorizeRoute = async () => ({
    user_id: 'platform-operator',
    session_id: 'platform-session',
    entry_domain: 'platform',
    active_tenant_id: null
  }),
  provisionPlatformUserByPhone = async () => ({
    user_id: 'platform-user-default',
    created_user: false,
    reused_existing_user: true,
    request_id: 'request_id_unset'
  }),
  updatePlatformUserStatus = async ({ userId, nextStatus }) => ({
    user_id: userId,
    previous_status: nextStatus === 'disabled' ? 'active' : 'disabled',
    current_status: nextStatus
  }),
  softDeleteUser = async ({ userId }) => ({
    user_id: userId,
    previous_status: 'active',
    current_status: 'disabled',
    revoked_session_count: 2,
    revoked_refresh_token_count: 2
  }),
  listPlatformUsers = async ({
    page,
    pageSize,
    status,
    keyword,
    phone,
    name,
    createdAtStart,
    createdAtEnd
  }) => ({
    total: 1,
    items: [
      {
        user_id: 'platform-user-default',
        phone: '13800000040',
        name: null,
        department: null,
        status: 'active',
        created_at: '2026-01-01T00:00:00.000Z'
      }
    ],
    page,
    page_size: pageSize,
    status: status || null,
    keyword: keyword || null,
    phone: phone || null,
    name: name || null,
    created_at_start: createdAtStart || null,
    created_at_end: createdAtEnd || null
  }),
  getPlatformUserById = async ({ userId }) =>
    String(userId || '').trim() === 'platform-user-default'
      ? {
        user_id: 'platform-user-default',
        phone: '13800000040',
        name: '默认用户',
        department: '默认部门',
        status: 'active',
          created_at: '2026-01-01T00:00:00.000Z',
          roles: []
      }
      : null,
  updateUserPhone = async ({ userId, phone }) => ({
    reason: 'ok',
    user_id: userId,
    phone
  }),
  upsertPlatformUserProfile = async ({ userId, name, department }) => ({
    user_id: userId,
    name,
    department
  }),
  listPlatformRoleCatalogEntries = async () => ([
    {
      role_id: 'role_user',
      status: 'active'
    },
    {
      role_id: 'sys_admin',
      status: 'active'
    }
  ]),
  listPlatformRolePermissionGrantsByRoleIds = async ({ roleIds = [] } = {}) =>
    roleIds.map((roleId) => ({
      role_id: roleId,
      permission_codes: []
    })),
  replacePlatformRolesAndSyncSnapshot = async () => ({
    synced: true,
    reason: 'ok',
    permission: {
      canViewMemberAdmin: false,
      canOperateMemberAdmin: false,
      canViewBilling: false,
      canOperateBilling: false
    }
  }),
  recordIdempotencyEvent = async () => {},
  authIdempotencyStore = null
} = {}) => {
  const authorizeCalls = [];
  const provisionCalls = [];
  const statusCalls = [];
  const softDeleteCalls = [];
  const listCalls = [];
  const getCalls = [];
  const updatePhoneCalls = [];
  const upsertProfileCalls = [];
  const listRoleCatalogCalls = [];
  const listRoleGrantCalls = [];
  const replaceRoleFactCalls = [];
  const idempotencyEvents = [];
  const authService = {
    authorizeRoute: async (payload) => {
      authorizeCalls.push(payload);
      return authorizeRoute(payload);
    },
    provisionPlatformUserByPhone: async (payload) => {
      provisionCalls.push(payload);
      return provisionPlatformUserByPhone(payload);
    },
    updatePlatformUserStatus: async (payload) => {
      statusCalls.push(payload);
      return updatePlatformUserStatus(payload);
    },
    softDeleteUser: async (payload) => {
      softDeleteCalls.push(payload);
      return softDeleteUser(payload);
    },
    recordIdempotencyEvent: async (payload) => {
      idempotencyEvents.push(payload);
      return recordIdempotencyEvent(payload);
    },
    _internals: {
      auditTrail: [],
      authStore: {
        listPlatformUsers: async (payload) => {
          listCalls.push(payload);
          return listPlatformUsers(payload);
        },
        getPlatformUserById: async (payload) => {
          getCalls.push(payload);
          return getPlatformUserById(payload);
        },
        updateUserPhone: async (payload) => {
          updatePhoneCalls.push(payload);
          return updateUserPhone(payload);
        },
        upsertPlatformUserProfile: async (payload) => {
          upsertProfileCalls.push(payload);
          return upsertPlatformUserProfile(payload);
        },
        listPlatformRoleCatalogEntries: async (payload) => {
          listRoleCatalogCalls.push(payload);
          return listPlatformRoleCatalogEntries(payload);
        },
        listPlatformRolePermissionGrantsByRoleIds: async (payload) => {
          listRoleGrantCalls.push(payload);
          return listPlatformRolePermissionGrantsByRoleIds(payload);
        },
        replacePlatformRolesAndSyncSnapshot: async (payload) => {
          replaceRoleFactCalls.push(payload);
          return replacePlatformRolesAndSyncSnapshot(payload);
        }
      }
    }
  };

  const platformUserService = createPlatformUserService({
    authService
  });
  const handlers = createRouteHandlers(config, {
    dependencyProbe,
    authService,
    platformUserService,
    authIdempotencyStore
  });
  return {
    handlers,
    platformUserService,
    authorizeCalls,
    provisionCalls,
    statusCalls,
    softDeleteCalls,
    listCalls,
    getCalls,
    updatePhoneCalls,
    upsertProfileCalls,
    listRoleCatalogCalls,
    listRoleGrantCalls,
    replaceRoleFactCalls,
    idempotencyEvents
  };
};

test('createPlatformUserHandlers fails fast when platform user service capability is missing', () => {
  assert.throws(
    () => createPlatformUserHandlers(),
    /requires a platformUserService with/
  );
  assert.throws(
    () => createPlatformUserHandlers({}),
    /requires a platformUserService with/
  );
});

test('GET /platform/users returns paged platform users and forwards filters', async () => {
  const harness = createHarness({
    listPlatformUsers: async ({
      page,
      pageSize,
      status,
      keyword,
      phone,
      name,
      createdAtStart,
      createdAtEnd
    }) => ({
      total: 2,
      items: [
        {
          user_id: 'platform-user-list-1',
          phone: '13800000041',
          name: '张三',
          department: '研发部',
          status: 'disabled',
          created_at: '2026-01-05T09:30:00.000Z'
        },
        {
          user_id: 'platform-user-list-2',
          phone: '13800000042',
          name: '李四',
          department: '产品部',
          status: 'disabled',
          created_at: '2026-01-06T10:45:00.000Z'
        }
      ],
      page,
      page_size: pageSize,
      status,
      keyword,
      phone,
      name,
      created_at_start: createdAtStart,
      created_at_end: createdAtEnd
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/users?page=2&page_size=5&status=disabled&phone=13800000041&name=%E5%BC%A0&created_at_start=2026-01-01T00%3A00%3A00.000Z&created_at_end=2026-01-31T23%3A59%3A59.999Z',
    method: 'GET',
    requestId: 'req-platform-user-list',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 200);
  const payload = JSON.parse(route.body);
  assert.equal(payload.total, 2);
  assert.equal(payload.page, 2);
  assert.equal(payload.page_size, 5);
  assert.equal(payload.request_id, 'req-platform-user-list');
  assert.equal(payload.items.length, 2);
  assert.equal(payload.items[0].status, 'disabled');
  assert.equal(payload.items[1].user_id, 'platform-user-list-2');
  assert.equal(harness.listCalls.length, 1);
  assert.equal(harness.listCalls[0].page, 2);
  assert.equal(harness.listCalls[0].pageSize, 5);
  assert.equal(harness.listCalls[0].status, 'disabled');
  assert.equal(harness.listCalls[0].phone, '13800000041');
  assert.equal(harness.listCalls[0].name, '张');
  assert.equal(harness.listCalls[0].createdAtStart, '2026-01-01T00:00:00.000Z');
  assert.equal(harness.listCalls[0].createdAtEnd, '2026-01-31T23:59:59.999Z');
});

test('GET /platform/users masks keyword in audit metadata', async () => {
  const harness = createHarness();

  const route = await dispatchApiRoute({
    pathname: '/platform/users?page=1&page_size=20&keyword=13800000041',
    method: 'GET',
    requestId: 'req-platform-user-list-keyword-mask',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 200);
  const lastAuditEvent = harness.platformUserService._internals.auditTrail.at(-1);
  assert.equal(lastAuditEvent?.type, 'platform.user.listed');
  assert.equal(lastAuditEvent?.keyword, '138****0041');
});

test('GET /platform/users maps invalid upstream list read model to USR-503-DEPENDENCY-UNAVAILABLE', async () => {
  const harness = createHarness({
    listPlatformUsers: async () => ({
      total: 1,
      items: [
        {
          user_id: 'platform-user-list-invalid-phone',
          phone: '',
          status: 'active'
        }
      ]
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/users?page=1&page_size=20',
    method: 'GET',
    requestId: 'req-platform-user-list-invalid-model',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 503);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'USR-503-DEPENDENCY-UNAVAILABLE');
  assert.equal(payload.request_id, 'req-platform-user-list-invalid-model');
});

test('GET /platform/users/:user_id returns detail payload with request_id', async () => {
  const harness = createHarness({
    getPlatformUserById: async ({ userId }) => ({
      user_id: userId,
      phone: '13800000049',
      name: '测试用户',
      department: '测试部门',
      status: 'active',
      created_at: '2026-01-09T08:00:00.000Z'
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/users/platform-user-detail-1',
    method: 'GET',
    requestId: 'req-platform-user-get',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 200);
  const payload = JSON.parse(route.body);
  assert.deepEqual(payload, {
    user_id: 'platform-user-detail-1',
    phone: '13800000049',
    name: '测试用户',
    department: '测试部门',
    roles: [],
    status: 'active',
    created_at: '2026-01-09T08:00:00.000Z',
    request_id: 'req-platform-user-get'
  });
  assert.equal(harness.getCalls.length, 1);
  assert.equal(harness.getCalls[0].userId, 'platform-user-detail-1');
});

test('GET /platform/users/:user_id maps invalid upstream read model to USR-503-DEPENDENCY-UNAVAILABLE', async () => {
  const harness = createHarness({
    getPlatformUserById: async () => ({
      user_id: 'platform-user-detail-invalid-phone',
      phone: '',
      status: 'active'
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/users/platform-user-detail-invalid-phone',
    method: 'GET',
    requestId: 'req-platform-user-get-invalid-model',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 503);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'USR-503-DEPENDENCY-UNAVAILABLE');
  assert.equal(payload.request_id, 'req-platform-user-get-invalid-model');
});

test('GET /platform/users rejects page_size greater than 100', async () => {
  const harness = createHarness();

  const route = await dispatchApiRoute({
    pathname: '/platform/users?page=1&page_size=101',
    method: 'GET',
    requestId: 'req-platform-user-list-invalid-page-size',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 400);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'USR-400-INVALID-PAYLOAD');
  assert.equal(payload.detail, 'page_size 必须为正整数');
  assert.equal(payload.request_id, 'req-platform-user-list-invalid-page-size');
  assert.equal(harness.listCalls.length, 0);
});

test('GET /platform/users/:user_id returns USR-404-USER-NOT-FOUND when target is missing', async () => {
  const harness = createHarness({
    getPlatformUserById: async () => null
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/users/platform-user-detail-missing',
    method: 'GET',
    requestId: 'req-platform-user-get-not-found',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 404);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'USR-404-USER-NOT-FOUND');
  assert.equal(payload.detail, '目标平台用户不存在或无 platform 域访问');
  assert.equal(payload.request_id, 'req-platform-user-get-not-found');
});

test('PATCH /platform/users/:user_id updates platform user profile and roles', async () => {
  const userState = {
    user_id: 'platform-user-default',
    phone: '13800000040',
    name: '默认用户',
    department: '默认部门',
    status: 'active',
    created_at: '2026-01-01T00:00:00.000Z',
    roles: [
      {
        role_id: 'role_user',
        code: 'ROLE_USER',
        name: '平台用户',
        status: 'active'
      }
    ]
  };
  const harness = createHarness({
    getPlatformUserById: async ({ userId }) =>
      String(userId || '').trim() === userState.user_id
        ? { ...userState }
        : null,
    upsertPlatformUserProfile: async ({ userId, name, department }) => {
      if (String(userId || '').trim() !== userState.user_id) {
        throw new Error('unexpected userId');
      }
      userState.name = String(name || '').trim();
      userState.department = department;
      return {
        user_id: userState.user_id,
        name: userState.name,
        department: userState.department
      };
    },
    replacePlatformRolesAndSyncSnapshot: async ({ userId, roles = [] }) => {
      if (String(userId || '').trim() !== userState.user_id) {
        return { reason: 'invalid-user-id' };
      }
      userState.roles = roles.map((role) => ({
        role_id: String(role.role_id || '').trim().toLowerCase(),
        code: String(role.role_id || '').trim().toUpperCase(),
        name: String(role.role_id || '').trim(),
        status: 'active'
      }));
      return {
        synced: true,
        reason: 'ok',
        permission: {
          canViewMemberAdmin: true,
          canOperateMemberAdmin: true,
          canViewBilling: false,
          canOperateBilling: false
        }
      };
    }
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/users/platform-user-default',
    method: 'PATCH',
    requestId: 'req-platform-user-update',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      name: '更新后用户',
      department: '更新后部门',
      role_ids: ['sys_admin']
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 200);
  const payload = JSON.parse(route.body);
  assert.equal(payload.user_id, 'platform-user-default');
  assert.equal(payload.phone, '13800000040');
  assert.equal(payload.name, '更新后用户');
  assert.equal(payload.department, '更新后部门');
  assert.equal(payload.status, 'active');
  assert.equal(payload.request_id, 'req-platform-user-update');
  assert.equal(Array.isArray(payload.roles), true);
  assert.equal(payload.roles.length, 1);
  assert.equal(payload.roles[0].role_id, 'sys_admin');
  assert.equal(harness.replaceRoleFactCalls.length, 1);
  assert.equal(harness.updatePhoneCalls.length, 0);
  assert.equal(harness.upsertProfileCalls.length, 1);
  assert.equal(harness.upsertProfileCalls[0].name, '更新后用户');
});

test('PATCH /platform/users/:user_id updates profile without role sync when role_ids is omitted', async () => {
  const userState = {
    user_id: 'platform-user-default',
    phone: '13800000040',
    name: '默认用户',
    department: '默认部门',
    status: 'active',
    created_at: '2026-01-01T00:00:00.000Z',
    roles: [
      {
        role_id: 'sys_admin',
        code: 'SYS_ADMIN',
        name: '系统管理员',
        status: 'active'
      }
    ]
  };
  const harness = createHarness({
    getPlatformUserById: async ({ userId }) =>
      String(userId || '').trim() === userState.user_id
        ? { ...userState }
        : null,
    upsertPlatformUserProfile: async ({ userId, name, department }) => {
      if (String(userId || '').trim() !== userState.user_id) {
        throw new Error('unexpected userId');
      }
      userState.name = String(name || '').trim();
      userState.department = department;
      return {
        user_id: userState.user_id,
        name: userState.name,
        department: userState.department
      };
    },
    replacePlatformRolesAndSyncSnapshot: async () => {
      throw new Error('replacePlatformRolesAndSyncSnapshot should not be called');
    }
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/users/platform-user-default',
    method: 'PATCH',
    requestId: 'req-platform-user-update-profile-only',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      name: '更新后用户',
      department: '更新后部门'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 200);
  const payload = JSON.parse(route.body);
  assert.equal(payload.user_id, 'platform-user-default');
  assert.equal(payload.name, '更新后用户');
  assert.equal(payload.department, '更新后部门');
  assert.equal(payload.request_id, 'req-platform-user-update-profile-only');
  assert.equal(Array.isArray(payload.roles), true);
  assert.equal(payload.roles.length, 1);
  assert.equal(payload.roles[0].role_id, 'sys_admin');
  assert.equal(harness.replaceRoleFactCalls.length, 0);
  assert.equal(harness.listRoleCatalogCalls.length, 0);
  assert.equal(harness.listRoleGrantCalls.length, 0);
  assert.equal(harness.upsertProfileCalls.length, 1);
});

test('PATCH /platform/users/:user_id rejects phone field in payload', async () => {
  const harness = createHarness();

  const route = await dispatchApiRoute({
    pathname: '/platform/users/platform-user-default',
    method: 'PATCH',
    requestId: 'req-platform-user-update-phone-rejected',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      phone: '13800000042',
      name: '更新后用户',
      department: '平台治理'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 400);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'USR-400-INVALID-PAYLOAD');
  assert.equal(payload.request_id, 'req-platform-user-update-phone-rejected');
  assert.equal(harness.updatePhoneCalls.length, 0);
});

test('PATCH /platform/users/:user_id rejects invalid payload with USER problem details', async () => {
  const harness = createHarness();

  const route = await dispatchApiRoute({
    pathname: '/platform/users/platform-user-default',
    method: 'PATCH',
    requestId: 'req-platform-user-update-invalid-payload',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      name: '更新用户',
      invalid_field: true
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 400);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'USR-400-INVALID-PAYLOAD');
  assert.equal(payload.request_id, 'req-platform-user-update-invalid-payload');
  assert.equal(harness.updatePhoneCalls.length, 0);
});

test('PATCH /platform/users/:user_id replays first success response for same Idempotency-Key and payload', async () => {
  const harness = createHarness({
    getPlatformUserById: async ({ userId }) => ({
      user_id: String(userId || '').trim(),
      phone: '13800000040',
      name: '默认用户',
      department: '默认部门',
      status: 'active',
      created_at: '2026-01-01T00:00:00.000Z',
      roles: []
    })
  });
  const requestBody = {
    name: '默认用户',
    department: '默认部门',
    role_ids: []
  };

  const first = await dispatchApiRoute({
    pathname: '/platform/users/platform-user-default',
    method: 'PATCH',
    requestId: 'req-platform-user-update-idem-replay-1',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-platform-user-update-replay-001'
    },
    body: requestBody,
    handlers: harness.handlers
  });
  const second = await dispatchApiRoute({
    pathname: '/platform/users/platform-user-default',
    method: 'PATCH',
    requestId: 'req-platform-user-update-idem-replay-2',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-platform-user-update-replay-001'
    },
    body: requestBody,
    handlers: harness.handlers
  });

  assert.equal(first.status, 200);
  assert.equal(second.status, 200);
  const firstPayload = JSON.parse(first.body);
  const secondPayload = JSON.parse(second.body);
  assert.equal(secondPayload.user_id, firstPayload.user_id);
  assert.equal(secondPayload.phone, firstPayload.phone);
  assert.equal(secondPayload.request_id, 'req-platform-user-update-idem-replay-2');
  assert.equal(harness.updatePhoneCalls.length, 0);
});

test('PATCH /platform/users/:user_id rejects same Idempotency-Key with different payloads', async () => {
  const harness = createHarness();

  const first = await dispatchApiRoute({
    pathname: '/platform/users/platform-user-default',
    method: 'PATCH',
    requestId: 'req-platform-user-update-idem-conflict-1',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-platform-user-update-conflict-001'
    },
    body: {
      name: '默认用户',
      department: '默认部门',
      role_ids: []
    },
    handlers: harness.handlers
  });
  const second = await dispatchApiRoute({
    pathname: '/platform/users/platform-user-default',
    method: 'PATCH',
    requestId: 'req-platform-user-update-idem-conflict-2',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-platform-user-update-conflict-001'
    },
    body: {
      name: '默认用户-冲突',
      department: '默认部门',
      role_ids: []
    },
    handlers: harness.handlers
  });

  assert.equal(first.status, 200);
  assert.equal(second.status, 409);
  const payload = JSON.parse(second.body);
  assert.equal(payload.error_code, 'AUTH-409-IDEMPOTENCY-CONFLICT');
  assert.equal(payload.request_id, 'req-platform-user-update-idem-conflict-2');
});

test('createPlatformUser maps non-auth operator authorization failures to USR-503-DEPENDENCY-UNAVAILABLE', async () => {
  const service = createPlatformUserService({
    authService: {
      authorizeRoute: async () => {
        throw new Error('auth dependency temporarily unavailable');
      },
      provisionPlatformUserByPhone: async () => ({
        user_id: 'platform-user-created',
        created_user: true,
        reused_existing_user: false
      })
    }
  });

  await assert.rejects(
    () =>
      service.createUser({
        requestId: 'req-platform-user-operator-auth-upstream-failure',
        accessToken: 'fake-access-token',
        payload: {
          phone: '13800000040',
          name: '操作员鉴权失败用户'
        }
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'USR-503-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
});

test('createPlatformUser emits rejected audit event when upstream payload misses user_id', async () => {
  const service = createPlatformUserService({
    authService: {
      authorizeRoute: async () => ({
        user_id: 'platform-operator',
        session_id: 'platform-session',
        entry_domain: 'platform',
        active_tenant_id: null
      }),
      provisionPlatformUserByPhone: async () => ({
        created_user: true,
        reused_existing_user: false
      })
    }
  });

  await assert.rejects(
    () =>
      service.createUser({
        requestId: 'req-platform-user-missing-upstream-user-id',
        accessToken: 'fake-access-token',
        payload: {
          phone: '13800000048',
          name: '上游缺失用户ID'
        }
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'USR-503-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );

  const lastAuditEvent = service._internals.auditTrail.at(-1);
  assert.equal(lastAuditEvent.type, 'platform.user.create.rejected');
  assert.equal(lastAuditEvent.error_code, 'USR-503-DEPENDENCY-UNAVAILABLE');
  assert.equal(
    lastAuditEvent.upstream_error_code,
    'PLATFORM-USER-PROVISION-RESULT-MISSING-USER-ID'
  );
});

test('POST /platform/users creates platform user and returns governance response fields', async () => {
  const harness = createHarness({
    provisionPlatformUserByPhone: async ({ requestId }) => ({
      user_id: 'platform-user-created',
      created_user: true,
      reused_existing_user: false,
      request_id: requestId
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/users',
    method: 'POST',
    requestId: 'req-platform-user-create',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      phone: '13800000041',
      name: '创建用户',
      department: '平台运营',
      role_ids: ['role_user']
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 200);
  const payload = JSON.parse(route.body);
  assert.deepEqual(payload, {
    user_id: 'platform-user-created',
    created_user: true,
    reused_existing_user: false,
    request_id: 'req-platform-user-create'
  });
  assert.equal(harness.provisionCalls.length, 1);
  assert.deepEqual(harness.provisionCalls[0].payload, {
    phone: '13800000041'
  });
  assert.equal(harness.upsertProfileCalls.length, 1);
  assert.deepEqual(harness.upsertProfileCalls[0], {
    userId: 'platform-user-created',
    name: '创建用户',
    department: '平台运营'
  });
  assert.equal(harness.replaceRoleFactCalls.length, 1);
  assert.equal(harness.replaceRoleFactCalls[0].userId, 'platform-user-created');
  assert.equal(harness.replaceRoleFactCalls[0].roles.length, 1);
  assert.equal(harness.replaceRoleFactCalls[0].roles[0].role_id, 'role_user');
  const lastAuditEvent = harness.platformUserService._internals.auditTrail.at(-1);
  assert.equal(lastAuditEvent.phone, '138****0041');
});

test('POST /platform/users reuses existing user identity when phone already exists', async () => {
  const harness = createHarness({
    provisionPlatformUserByPhone: async ({ requestId }) => ({
      user_id: 'platform-user-existing',
      created_user: false,
      reused_existing_user: true,
      request_id: requestId
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/users',
    method: 'POST',
    requestId: 'req-platform-user-reuse',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      phone: '13800000042',
      name: '复用用户'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 200);
  const payload = JSON.parse(route.body);
  assert.equal(payload.user_id, 'platform-user-existing');
  assert.equal(payload.created_user, false);
  assert.equal(payload.reused_existing_user, true);
  assert.equal(payload.request_id, 'req-platform-user-reuse');
});

test('POST /platform/users returns AUTH-403-FORBIDDEN when operator lacks permission', async () => {
  const harness = createHarness({
    authorizeRoute: async () => {
      throw new AuthProblemError({
        status: 403,
        title: 'Forbidden',
        detail: '当前操作无权限',
        errorCode: 'AUTH-403-FORBIDDEN'
      });
    }
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/users',
    method: 'POST',
    requestId: 'req-platform-user-forbidden',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      phone: '13800000047',
      name: '无权限用户'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 403);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-403-FORBIDDEN');
  assert.equal(payload.request_id, 'req-platform-user-forbidden');
  assert.equal(harness.provisionCalls.length, 0);
});

test('POST /platform/users keeps problem+json contract on payload validation failure', async () => {
  const harness = createHarness();
  const route = await dispatchApiRoute({
    pathname: '/platform/users',
    method: 'POST',
    requestId: 'req-platform-user-invalid-payload',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      phone: '13800000043',
      name: '校验失败用户',
      unexpected_field: true
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 400);
  assert.equal(route.headers['content-type'], 'application/problem+json');
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'USR-400-INVALID-PAYLOAD');
  assert.equal(payload.request_id, 'req-platform-user-invalid-payload');
  const lastAuditEvent = harness.platformUserService._internals.auditTrail.at(-1);
  assert.equal(lastAuditEvent.phone, '138****0043');
  assert.equal(harness.provisionCalls.length, 0);
});

test('POST /platform/users replays first success response for same Idempotency-Key and payload', async () => {
  const harness = createHarness({
    provisionPlatformUserByPhone: async ({ requestId }) => ({
      user_id: 'platform-user-idem-replay',
      created_user: true,
      reused_existing_user: false,
      request_id: requestId
    })
  });

  const requestBody = {
    phone: '13800000044',
    name: '幂等用户'
  };
  const first = await dispatchApiRoute({
    pathname: '/platform/users',
    method: 'POST',
    requestId: 'req-platform-user-idem-replay-1',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-platform-user-replay-001'
    },
    body: requestBody,
    handlers: harness.handlers
  });
  const second = await dispatchApiRoute({
    pathname: '/platform/users',
    method: 'POST',
    requestId: 'req-platform-user-idem-replay-2',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-platform-user-replay-001'
    },
    body: requestBody,
    handlers: harness.handlers
  });

  assert.equal(first.status, 200);
  assert.equal(second.status, 200);
  assert.equal(harness.provisionCalls.length, 1);
  const firstPayload = JSON.parse(first.body);
  const secondPayload = JSON.parse(second.body);
  assert.equal(secondPayload.user_id, firstPayload.user_id);
  assert.equal(secondPayload.created_user, firstPayload.created_user);
  assert.equal(secondPayload.request_id, 'req-platform-user-idem-replay-2');
});

test('POST /platform/users rejects same Idempotency-Key with different payloads', async () => {
  const harness = createHarness({
    provisionPlatformUserByPhone: async ({ requestId }) => ({
      user_id: 'platform-user-idem-conflict',
      created_user: true,
      reused_existing_user: false,
      request_id: requestId
    })
  });

  const first = await dispatchApiRoute({
    pathname: '/platform/users',
    method: 'POST',
    requestId: 'req-platform-user-idem-conflict-1',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-platform-user-conflict-001'
    },
    body: {
      phone: '13800000045',
      name: '幂等冲突用户'
    },
    handlers: harness.handlers
  });
  const second = await dispatchApiRoute({
    pathname: '/platform/users',
    method: 'POST',
    requestId: 'req-platform-user-idem-conflict-2',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-platform-user-conflict-001'
    },
    body: {
      phone: '13800000046',
      name: '幂等冲突用户'
    },
    handlers: harness.handlers
  });

  assert.equal(first.status, 200);
  assert.equal(second.status, 409);
  const payload = JSON.parse(second.body);
  assert.equal(payload.error_code, 'AUTH-409-IDEMPOTENCY-CONFLICT');
  assert.equal(payload.request_id, 'req-platform-user-idem-conflict-2');
  assert.equal(harness.provisionCalls.length, 1);
});

test('POST /platform/users/status updates user status and records governance audit fields', async () => {
  const harness = createHarness({
    updatePlatformUserStatus: async ({ userId, nextStatus }) => ({
      user_id: userId,
      previous_status: 'active',
      current_status: nextStatus
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/users/status',
    method: 'POST',
    requestId: 'req-platform-user-status-disable',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      user_id: 'platform-user-target-1',
      status: 'disabled',
      reason: 'manual-governance'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 200);
  const payload = JSON.parse(route.body);
  assert.deepEqual(payload, {
    user_id: 'platform-user-target-1',
    previous_status: 'active',
    current_status: 'disabled',
    request_id: 'req-platform-user-status-disable'
  });
  assert.equal(harness.statusCalls.length, 1);
  assert.equal(harness.statusCalls[0].userId, 'platform-user-target-1');
  assert.equal(harness.statusCalls[0].nextStatus, 'disabled');
  assert.equal(harness.statusCalls[0].operatorUserId, 'platform-operator');
  assert.equal(harness.statusCalls[0].operatorSessionId, 'platform-session');
  assert.equal(harness.statusCalls[0].reason, 'manual-governance');
  const lastAuditEvent = harness.platformUserService._internals.auditTrail.at(-1);
  assert.equal(lastAuditEvent.type, 'platform.user.status.updated');
  assert.equal(lastAuditEvent.target_user_id, 'platform-user-target-1');
  assert.equal(lastAuditEvent.previous_status, 'active');
  assert.equal(lastAuditEvent.next_status, 'disabled');
});

test('POST /platform/users/status forwards traceparent to auth domain write call', async () => {
  const harness = createHarness();
  const traceparent = '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01';

  const route = await dispatchApiRoute({
    pathname: '/platform/users/status',
    method: 'POST',
    requestId: 'req-platform-user-status-traceparent',
    headers: {
      authorization: 'Bearer fake-access-token',
      traceparent
    },
    body: {
      user_id: 'platform-user-target-trace',
      status: 'disabled'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 200);
  assert.equal(harness.statusCalls.length, 1);
  assert.equal(
    harness.statusCalls[0].traceparent,
    traceparent
  );
});

test('POST /platform/users/status accepts status=enabled and normalizes to active', async () => {
  const harness = createHarness({
    updatePlatformUserStatus: async ({ userId, nextStatus }) => ({
      user_id: userId,
      previous_status: 'disabled',
      current_status: nextStatus
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/users/status',
    method: 'POST',
    requestId: 'req-platform-user-status-enable-normalized',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      user_id: 'platform-user-target-2',
      status: 'enabled'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 200);
  const payload = JSON.parse(route.body);
  assert.equal(payload.current_status, 'active');
  assert.equal(harness.statusCalls.length, 1);
  assert.equal(harness.statusCalls[0].nextStatus, 'active');
});

test('POST /platform/users/status returns USER-404 when target user is missing or has no platform-domain access', async () => {
  const harness = createHarness({
    updatePlatformUserStatus: async () => {
      throw new AuthProblemError({
        status: 404,
        title: 'Not Found',
        detail: 'user missing',
        errorCode: 'AUTH-404-USER-NOT-FOUND'
      });
    }
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/users/status',
    method: 'POST',
    requestId: 'req-platform-user-status-not-found',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      user_id: 'platform-user-missing',
      status: 'disabled'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 404);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'USR-404-USER-NOT-FOUND');
  assert.equal(payload.detail, '目标平台用户不存在或无 platform 域访问');
  assert.equal(payload.request_id, 'req-platform-user-status-not-found');
});

test('POST /platform/users/status preserves non-404 auth domain errors', async () => {
  const harness = createHarness({
    updatePlatformUserStatus: async () => {
      throw new AuthProblemError({
        status: 503,
        title: 'Service Unavailable',
        detail: 'platform permission snapshot temporarily degraded',
        errorCode: 'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED',
        extensions: {
          retryable: true,
          degradation_reason: 'db-deadlock'
        }
      });
    }
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/users/status',
    method: 'POST',
    requestId: 'req-platform-user-status-upstream-degraded',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      user_id: 'platform-user-upstream-error',
      status: 'disabled'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 503);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED');
  assert.equal(payload.request_id, 'req-platform-user-status-upstream-degraded');
  assert.equal(payload.retryable, true);
  assert.equal(payload.degradation_reason, 'db-deadlock');
  const lastAuditEvent = harness.platformUserService._internals.auditTrail.at(-1);
  assert.equal(lastAuditEvent.type, 'platform.user.status.rejected');
  assert.equal(lastAuditEvent.error_code, 'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED');
  assert.equal(lastAuditEvent.upstream_error_code, 'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED');
});

test('POST /platform/users/status maps invalid upstream status result to AUTH-503-PLATFORM-SNAPSHOT-DEGRADED', async () => {
  const harness = createHarness({
    updatePlatformUserStatus: async ({ userId }) => ({
      user_id: userId,
      previous_status: 'active',
      current_status: 'archived'
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/users/status',
    method: 'POST',
    requestId: 'req-platform-user-status-invalid-upstream-status',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      user_id: 'platform-user-target-invalid-status',
      status: 'disabled'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 503);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED');
  assert.equal(payload.degradation_reason, 'platform-user-status-result-invalid');
  assert.equal(payload.request_id, 'req-platform-user-status-invalid-upstream-status');
  const lastAuditEvent = harness.platformUserService._internals.auditTrail.at(-1);
  assert.equal(lastAuditEvent.type, 'platform.user.status.rejected');
  assert.equal(lastAuditEvent.error_code, 'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED');
  assert.equal(lastAuditEvent.upstream_error_code, 'PLATFORM-USER-STATUS-RESULT-INVALID');
});

test('POST /platform/users/status maps upstream target mismatch to AUTH-503-PLATFORM-SNAPSHOT-DEGRADED', async () => {
  const harness = createHarness({
    updatePlatformUserStatus: async () => ({
      user_id: 'platform-user-target-mismatched',
      previous_status: 'active',
      current_status: 'disabled'
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/users/status',
    method: 'POST',
    requestId: 'req-platform-user-status-upstream-target-mismatch',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      user_id: 'platform-user-target-requested',
      status: 'disabled'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 503);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED');
  assert.equal(payload.degradation_reason, 'platform-user-status-target-mismatch');
  assert.equal(payload.request_id, 'req-platform-user-status-upstream-target-mismatch');
  const lastAuditEvent = harness.platformUserService._internals.auditTrail.at(-1);
  assert.equal(lastAuditEvent.type, 'platform.user.status.rejected');
  assert.equal(lastAuditEvent.error_code, 'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED');
  assert.equal(
    lastAuditEvent.upstream_error_code,
    'PLATFORM-USER-STATUS-RESULT-TARGET-MISMATCH'
  );
  assert.equal(lastAuditEvent.upstream_target_user_id, 'platform-user-target-mismatched');
});

test('POST /platform/users/status rejects invalid payload with USER problem details', async () => {
  const harness = createHarness();

  const route = await dispatchApiRoute({
    pathname: '/platform/users/status',
    method: 'POST',
    requestId: 'req-platform-user-status-invalid-payload',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      user_id: 'platform-user-target-3',
      status: 'archived'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 400);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'USR-400-INVALID-PAYLOAD');
  assert.match(payload.detail, /active 或 disabled/);
  assert.equal(harness.statusCalls.length, 0);
  const lastAuditEvent = harness.platformUserService._internals.auditTrail.at(-1);
  assert.equal(lastAuditEvent.type, 'platform.user.status.rejected');
  assert.equal(lastAuditEvent.previous_status, null);
  assert.equal(lastAuditEvent.next_status, 'archived');
});

test('POST /platform/users/status returns AUTH-403-FORBIDDEN when operator lacks permission', async () => {
  const harness = createHarness({
    authorizeRoute: async () => {
      throw new AuthProblemError({
        status: 403,
        title: 'Forbidden',
        detail: '当前操作无权限',
        errorCode: 'AUTH-403-FORBIDDEN'
      });
    }
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/users/status',
    method: 'POST',
    requestId: 'req-platform-user-status-forbidden',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      user_id: 'platform-user-target-forbidden',
      status: 'disabled'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 403);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-403-FORBIDDEN');
  assert.equal(payload.request_id, 'req-platform-user-status-forbidden');
  assert.equal(harness.statusCalls.length, 0);
});

test('POST /platform/users/status replays first success response for same Idempotency-Key and payload', async () => {
  const harness = createHarness();
  const requestBody = {
    user_id: 'platform-user-target-4',
    status: 'disabled'
  };

  const first = await dispatchApiRoute({
    pathname: '/platform/users/status',
    method: 'POST',
    requestId: 'req-platform-user-status-idem-replay-1',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-platform-user-status-replay-001'
    },
    body: requestBody,
    handlers: harness.handlers
  });
  const second = await dispatchApiRoute({
    pathname: '/platform/users/status',
    method: 'POST',
    requestId: 'req-platform-user-status-idem-replay-2',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-platform-user-status-replay-001'
    },
    body: requestBody,
    handlers: harness.handlers
  });

  assert.equal(first.status, 200);
  assert.equal(second.status, 200);
  assert.equal(harness.statusCalls.length, 1);
  const firstPayload = JSON.parse(first.body);
  const secondPayload = JSON.parse(second.body);
  assert.equal(secondPayload.user_id, firstPayload.user_id);
  assert.equal(secondPayload.current_status, firstPayload.current_status);
  assert.equal(secondPayload.request_id, 'req-platform-user-status-idem-replay-2');
});

test('POST /platform/users/status rejects same Idempotency-Key with different payloads', async () => {
  const harness = createHarness();
  const first = await dispatchApiRoute({
    pathname: '/platform/users/status',
    method: 'POST',
    requestId: 'req-platform-user-status-idem-conflict-1',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-platform-user-status-conflict-001'
    },
    body: {
      user_id: 'platform-user-target-5',
      status: 'disabled'
    },
    handlers: harness.handlers
  });
  const second = await dispatchApiRoute({
    pathname: '/platform/users/status',
    method: 'POST',
    requestId: 'req-platform-user-status-idem-conflict-2',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-platform-user-status-conflict-001'
    },
    body: {
      user_id: 'platform-user-target-5',
      status: 'active'
    },
    handlers: harness.handlers
  });

  assert.equal(first.status, 200);
  assert.equal(second.status, 409);
  const payload = JSON.parse(second.body);
  assert.equal(payload.error_code, 'AUTH-409-IDEMPOTENCY-CONFLICT');
  assert.equal(payload.request_id, 'req-platform-user-status-idem-conflict-2');
  assert.equal(harness.statusCalls.length, 1);
});

test('DELETE /platform/users/:user_id soft-deletes user and revokes all active sessions', async () => {
  const harness = createHarness({
    softDeleteUser: async ({ userId }) => ({
      user_id: userId,
      previous_status: 'active',
      current_status: 'disabled',
      revoked_session_count: 3,
      revoked_refresh_token_count: 3
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/users/platform-user-soft-delete-1',
    method: 'DELETE',
    requestId: 'req-platform-user-soft-delete-1',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 200);
  const payload = JSON.parse(route.body);
  assert.deepEqual(payload, {
    user_id: 'platform-user-soft-delete-1',
    previous_status: 'active',
    current_status: 'disabled',
    revoked_session_count: 3,
    revoked_refresh_token_count: 3,
    request_id: 'req-platform-user-soft-delete-1'
  });
  assert.equal(harness.softDeleteCalls.length, 1);
  assert.equal(harness.softDeleteCalls[0].userId, 'platform-user-soft-delete-1');
  assert.equal(harness.softDeleteCalls[0].operatorUserId, 'platform-operator');
  assert.equal(harness.softDeleteCalls[0].operatorSessionId, 'platform-session');
  const lastAuditEvent = harness.platformUserService._internals.auditTrail.at(-1);
  assert.equal(lastAuditEvent.type, 'platform.user.soft_deleted');
  assert.equal(lastAuditEvent.target_user_id, 'platform-user-soft-delete-1');
  assert.equal(lastAuditEvent.previous_status, 'active');
  assert.equal(lastAuditEvent.current_status, 'disabled');
  assert.equal(lastAuditEvent.revoked_session_count, 3);
  assert.equal(lastAuditEvent.revoked_refresh_token_count, 3);
});

test('DELETE /platform/users/:user_id forwards traceparent to auth domain soft-delete call', async () => {
  const harness = createHarness();
  const traceparent = '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01';

  const route = await dispatchApiRoute({
    pathname: '/platform/users/platform-user-soft-delete-trace',
    method: 'DELETE',
    requestId: 'req-platform-user-soft-delete-trace',
    headers: {
      authorization: 'Bearer fake-access-token',
      traceparent
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 200);
  assert.equal(harness.softDeleteCalls.length, 1);
  assert.equal(harness.softDeleteCalls[0].traceparent, traceparent);
});

test('DELETE /platform/users/:user_id rejects user_id longer than 64 characters', async () => {
  const harness = createHarness();
  const route = await dispatchApiRoute({
    pathname: `/platform/users/${'u'.repeat(65)}`,
    method: 'DELETE',
    requestId: 'req-platform-user-soft-delete-invalid-user-id-length',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 400);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'USR-400-INVALID-PAYLOAD');
  assert.equal(payload.detail, 'user_id 长度不能超过 64');
  assert.equal(payload.request_id, 'req-platform-user-soft-delete-invalid-user-id-length');
  assert.equal(harness.softDeleteCalls.length, 0);
});

test('DELETE /platform/users/:user_id returns USER-404 when target user is missing', async () => {
  const harness = createHarness({
    softDeleteUser: async () => {
      throw new AuthProblemError({
        status: 404,
        title: 'Not Found',
        detail: 'target user missing',
        errorCode: 'AUTH-404-USER-NOT-FOUND'
      });
    }
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/users/platform-user-soft-delete-missing',
    method: 'DELETE',
    requestId: 'req-platform-user-soft-delete-not-found',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 404);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'USR-404-USER-NOT-FOUND');
  assert.equal(payload.detail, '目标平台用户不存在或无 platform 域访问');
  assert.equal(payload.request_id, 'req-platform-user-soft-delete-not-found');
});

test('DELETE /platform/users/:user_id maps upstream target mismatch to AUTH-503-PLATFORM-SNAPSHOT-DEGRADED', async () => {
  const harness = createHarness({
    softDeleteUser: async () => ({
      user_id: 'platform-user-soft-delete-upstream-mismatch',
      previous_status: 'active',
      current_status: 'disabled',
      revoked_session_count: 1,
      revoked_refresh_token_count: 1
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/users/platform-user-soft-delete-requested',
    method: 'DELETE',
    requestId: 'req-platform-user-soft-delete-target-mismatch',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 503);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED');
  assert.equal(payload.degradation_reason, 'platform-user-soft-delete-target-mismatch');
  assert.equal(payload.request_id, 'req-platform-user-soft-delete-target-mismatch');
  const lastAuditEvent = harness.platformUserService._internals.auditTrail.at(-1);
  assert.equal(lastAuditEvent.type, 'platform.user.soft_delete.rejected');
  assert.equal(lastAuditEvent.error_code, 'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED');
  assert.equal(
    lastAuditEvent.upstream_error_code,
    'PLATFORM-USER-SOFT-DELETE-RESULT-TARGET-MISMATCH'
  );
});

test('DELETE /platform/users/:user_id replays first success response for same Idempotency-Key and route params', async () => {
  const harness = createHarness();

  const first = await dispatchApiRoute({
    pathname: '/platform/users/platform-user-soft-delete-idem-replay',
    method: 'DELETE',
    requestId: 'req-platform-user-soft-delete-idem-replay-1',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-platform-user-soft-delete-replay-001'
    },
    handlers: harness.handlers
  });
  const second = await dispatchApiRoute({
    pathname: '/platform/users/platform-user-soft-delete-idem-replay',
    method: 'DELETE',
    requestId: 'req-platform-user-soft-delete-idem-replay-2',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-platform-user-soft-delete-replay-001'
    },
    handlers: harness.handlers
  });

  assert.equal(first.status, 200);
  assert.equal(second.status, 200);
  assert.equal(harness.softDeleteCalls.length, 1);
  const firstPayload = JSON.parse(first.body);
  const secondPayload = JSON.parse(second.body);
  assert.equal(secondPayload.user_id, firstPayload.user_id);
  assert.equal(
    secondPayload.revoked_refresh_token_count,
    firstPayload.revoked_refresh_token_count
  );
  assert.equal(secondPayload.request_id, 'req-platform-user-soft-delete-idem-replay-2');
});

test('DELETE /platform/users/:user_id keeps idempotency replay stable for percent-encoded path variants', async () => {
  const harness = createHarness();

  const first = await dispatchApiRoute({
    pathname: '/platform/users/%70latform-user-soft-delete-idem-trim',
    method: 'DELETE',
    requestId: 'req-platform-user-soft-delete-idem-trim-1',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-platform-user-soft-delete-trim-001'
    },
    handlers: harness.handlers
  });
  const second = await dispatchApiRoute({
    pathname: '/platform/users/platform-user-soft-delete-idem-trim',
    method: 'DELETE',
    requestId: 'req-platform-user-soft-delete-idem-trim-2',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-platform-user-soft-delete-trim-001'
    },
    handlers: harness.handlers
  });

  assert.equal(first.status, 200);
  assert.equal(second.status, 200);
  assert.equal(harness.softDeleteCalls.length, 1);
  const firstPayload = JSON.parse(first.body);
  const secondPayload = JSON.parse(second.body);
  assert.equal(firstPayload.user_id, 'platform-user-soft-delete-idem-trim');
  assert.equal(secondPayload.user_id, firstPayload.user_id);
  assert.equal(secondPayload.request_id, 'req-platform-user-soft-delete-idem-trim-2');
});

test('DELETE /platform/users/:user_id rejects same Idempotency-Key with different route params', async () => {
  const harness = createHarness();
  const first = await dispatchApiRoute({
    pathname: '/platform/users/platform-user-soft-delete-idem-conflict-a',
    method: 'DELETE',
    requestId: 'req-platform-user-soft-delete-idem-conflict-1',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-platform-user-soft-delete-conflict-001'
    },
    handlers: harness.handlers
  });
  const second = await dispatchApiRoute({
    pathname: '/platform/users/platform-user-soft-delete-idem-conflict-b',
    method: 'DELETE',
    requestId: 'req-platform-user-soft-delete-idem-conflict-2',
    headers: {
      authorization: 'Bearer fake-access-token',
      'idempotency-key': 'idem-platform-user-soft-delete-conflict-001'
    },
    handlers: harness.handlers
  });

  assert.equal(first.status, 200);
  assert.equal(second.status, 409);
  const payload = JSON.parse(second.body);
  assert.equal(payload.error_code, 'AUTH-409-IDEMPOTENCY-CONFLICT');
  assert.equal(payload.request_id, 'req-platform-user-soft-delete-idem-conflict-2');
  assert.equal(harness.softDeleteCalls.length, 1);
});
