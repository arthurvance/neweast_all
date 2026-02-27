const test = require('node:test');
const assert = require('node:assert/strict');
const { createRouteHandlers } = require('../src/http-routes');
const {
  createTenantAccountHandlers
} = require('../src/domains/tenant/account/account/account.routes');
const {
  createTenantAccountService
} = require('../src/domains/tenant/account/account/service');
const { dispatchApiRoute } = require('../src/server');
const { readConfig } = require('../src/config/env');
const {
  markRoutePreauthorizedContext
} = require('../src/shared-kernel/auth/route-authz');
const { AuthProblemError } = require('../src/shared-kernel/auth/auth-problem-error');

const config = readConfig({ ALLOW_MOCK_BACKENDS: 'true' });
const dependencyProbe = async () => ({
  db: { ok: true },
  redis: { ok: true }
});

const createNoopTenantUserService = () => ({
  listUsers: async () => ({ members: [] }),
  createUser: async () => ({}),
  updateUserStatus: async () => ({}),
  getUserDetail: async () => ({}),
  updateUserProfile: async () => ({}),
  getUserRoles: async () => ({}),
  replaceUserRoles: async () => ({})
});

const createNoopTenantRoleService = () => ({
  listRoles: async () => ({ roles: [] }),
  createRole: async () => ({}),
  updateRole: async () => ({}),
  deleteRole: async () => ({}),
  getRolePermissions: async () => ({}),
  replaceRolePermissions: async () => ({})
});

const createHarness = ({
  authorizeRoute = async () => ({
    user_id: 'tenant-account-operator',
    session_id: 'tenant-account-session',
    entry_domain: 'tenant',
    active_tenant_id: 'tenant-a'
  }),
  listTenantUsersByTenantId = async ({ tenantId }) => [
    {
      membership_id: 'membership-operator',
      user_id: 'tenant-account-operator',
      tenant_id: tenantId,
      display_name: '账号管理员',
      status: 'active'
    },
    {
      membership_id: 'membership-owner',
      user_id: 'tenant-owner',
      tenant_id: tenantId,
      display_name: '负责人甲',
      status: 'active'
    },
    {
      membership_id: 'membership-assistant',
      user_id: 'tenant-assistant',
      tenant_id: tenantId,
      display_name: '协助人乙',
      status: 'active'
    }
  ],
  listTenantAccountsByTenantId = async ({ tenantId }) => [
    {
      account_id: 'acc_001',
      tenant_id: tenantId,
      wechat_id: 'wx_account_01',
      nickname: '顾问小东',
      owner_membership_id: 'membership-owner',
      assistant_membership_ids: ['membership-assistant'],
      customer_count: 12,
      group_chat_count: 3,
      status: 'enabled',
      avatar_url: null,
      created_by_user_id: 'tenant-account-operator',
      updated_by_user_id: 'tenant-account-operator',
      created_at: '2026-01-20T02:00:00.000Z',
      updated_at: '2026-01-28T01:30:00.000Z'
    }
  ],
  createTenantAccount = async ({ tenantId, wechatId, nickname }) => ({
    account_id: 'acc_new_001',
    tenant_id: tenantId,
    wechat_id: wechatId,
    nickname,
    owner_membership_id: 'membership-owner',
    assistant_membership_ids: ['membership-assistant'],
    customer_count: 0,
    group_chat_count: 0,
    status: 'enabled',
    avatar_url: null,
    created_by_user_id: 'tenant-account-operator',
    updated_by_user_id: 'tenant-account-operator',
    created_at: '2026-02-20T02:00:00.000Z',
    updated_at: '2026-02-20T02:00:00.000Z'
  }),
  findTenantAccountByAccountId = async ({ tenantId, accountId }) => ({
    account_id: accountId,
    tenant_id: tenantId,
    wechat_id: 'wx_account_01',
    nickname: '顾问小东',
    owner_membership_id: 'membership-owner',
    assistant_membership_ids: ['membership-assistant'],
    customer_count: 12,
    group_chat_count: 3,
    status: 'enabled',
    avatar_url: null,
    created_by_user_id: 'tenant-account-operator',
    updated_by_user_id: 'tenant-account-operator',
    created_at: '2026-01-20T02:00:00.000Z',
    updated_at: '2026-01-28T01:30:00.000Z'
  }),
  updateTenantAccount = async ({ tenantId, accountId, wechatId, nickname }) => ({
    account_id: accountId,
    tenant_id: tenantId,
    wechat_id: wechatId,
    nickname,
    owner_membership_id: 'membership-owner',
    assistant_membership_ids: ['membership-assistant'],
    customer_count: 12,
    group_chat_count: 3,
    status: 'enabled',
    avatar_url: null,
    created_by_user_id: 'tenant-account-operator',
    updated_by_user_id: 'tenant-account-operator',
    created_at: '2026-01-20T02:00:00.000Z',
    updated_at: '2026-02-22T01:30:00.000Z'
  }),
  updateTenantAccountStatus = async ({ tenantId, accountId, status }) => ({
    account_id: accountId,
    tenant_id: tenantId,
    wechat_id: 'wx_account_01',
    nickname: '顾问小东',
    owner_membership_id: 'membership-owner',
    assistant_membership_ids: ['membership-assistant'],
    customer_count: 12,
    group_chat_count: 3,
    status,
    avatar_url: null,
    created_by_user_id: 'tenant-account-operator',
    updated_by_user_id: 'tenant-account-operator',
    created_at: '2026-01-20T02:00:00.000Z',
    updated_at: '2026-02-22T01:30:00.000Z'
  }),
  listTenantAccountOperationLogs = async ({ tenantId, accountId }) => [
    {
      operation_id: 'op_001',
      account_id: accountId,
      tenant_id: tenantId,
      operation_type: 'create',
      operation_content: '初始化账号',
      operator_user_id: 'tenant-account-operator',
      operator_name: '账号管理员',
      operation_time: '2026-01-20T02:00:00.000Z'
    },
    {
      operation_id: 'op_002',
      account_id: accountId,
      tenant_id: tenantId,
      operation_type: 'update',
      operation_content: '编辑账号',
      operator_user_id: 'tenant-account-operator',
      operator_name: '账号管理员',
      operation_time: '2026-01-28T01:30:00.000Z'
    }
  ]
} = {}) => {
  const authorizeCalls = [];
  const listCalls = [];
  const createCalls = [];
  const detailCalls = [];
  const updateCalls = [];
  const updateStatusCalls = [];
  const logCalls = [];
  const listTenantUsersCalls = [];

  const authStore = {
    listTenantUsersByTenantId: async (payload) => {
      listTenantUsersCalls.push(payload);
      return listTenantUsersByTenantId(payload);
    },
    listTenantAccountsByTenantId: async (payload) => {
      listCalls.push(payload);
      return listTenantAccountsByTenantId(payload);
    },
    createTenantAccount: async (payload) => {
      createCalls.push(payload);
      return createTenantAccount(payload);
    },
    findTenantAccountByAccountId: async (payload) => {
      detailCalls.push(payload);
      return findTenantAccountByAccountId(payload);
    },
    updateTenantAccount: async (payload) => {
      updateCalls.push(payload);
      return updateTenantAccount(payload);
    },
    updateTenantAccountStatus: async (payload) => {
      updateStatusCalls.push(payload);
      return updateTenantAccountStatus(payload);
    },
    listTenantAccountOperationLogs: async (payload) => {
      logCalls.push(payload);
      return listTenantAccountOperationLogs(payload);
    }
  };

  const authService = {
    authorizeRoute: async (payload) => {
      authorizeCalls.push(payload);
      return authorizeRoute(payload);
    },
    recordIdempotencyEvent: async () => {},
    _internals: {
      authStore,
      auditTrail: []
    }
  };

  const tenantAccountService = createTenantAccountService({
    authService
  });

  const handlers = createRouteHandlers(config, {
    dependencyProbe,
    authService,
    tenantAccountService,
    tenantUserService: createNoopTenantUserService(),
    tenantRoleService: createNoopTenantRoleService()
  });

  return {
    handlers,
    authorizeCalls,
    listCalls,
    createCalls,
    detailCalls,
    updateCalls,
    updateStatusCalls,
    logCalls,
    listTenantUsersCalls
  };
};

test('createTenantAccountHandlers fails fast when service capability is missing', () => {
  assert.throws(
    () => createTenantAccountHandlers(),
    /requires a tenantAccountService with listAccounts, createAccount, getAccountDetail, updateAccount, updateAccountStatus and listAccountOperationLogs/
  );
  assert.throws(
    () => createTenantAccountHandlers({}),
    /requires a tenantAccountService with listAccounts, createAccount, getAccountDetail, updateAccount, updateAccountStatus and listAccountOperationLogs/
  );
});

test('GET /tenant/accounts lists accounts in active tenant scope', async () => {
  const harness = createHarness();

  const route = await dispatchApiRoute({
    pathname: '/tenant/accounts?page=1&page_size=20&wechat_id=wx_account_01&nickname=顾问&status=enabled',
    method: 'GET',
    requestId: 'req-tenant-account-list',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 200);
  const payload = JSON.parse(route.body);
  assert.equal(payload.request_id, 'req-tenant-account-list');
  assert.equal(payload.tenant_id, 'tenant-a');
  assert.equal(payload.filters.wechat_id, 'wx_account_01');
  assert.equal(payload.filters.nickname, '顾问');
  assert.equal(payload.filters.status, 'enabled');
  assert.equal(payload.accounts.length, 1);
  assert.equal(payload.accounts[0].account_id, 'acc_001');
  assert.equal(payload.accounts[0].owner_name, '负责人甲');
  assert.deepEqual(payload.accounts[0].assistant_names, ['协助人乙']);
  assert.ok(harness.authorizeCalls.length >= 1);
  assert.equal(harness.authorizeCalls.at(-1).permissionCode, 'tenant.account_management.view');
  assert.equal(harness.listCalls.length, 1);
  assert.equal(harness.listCalls[0].tenantId, 'tenant-a');
  assert.ok(harness.listTenantUsersCalls.length >= 1);
  assert.equal(harness.listTenantUsersCalls[0].tenantId, 'tenant-a');
});

test('POST /tenant/accounts creates account with tenant-scoped constraints', async () => {
  const harness = createHarness();

  const route = await dispatchApiRoute({
    pathname: '/tenant/accounts',
    method: 'POST',
    requestId: 'req-tenant-account-create',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      wechat_id: 'wx_account_new',
      nickname: '顾问新号',
      owner_membership_id: 'membership-owner',
      assistant_membership_ids: ['membership-assistant']
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 200);
  const payload = JSON.parse(route.body);
  assert.equal(payload.account_id, 'acc_new_001');
  assert.equal(payload.tenant_id, 'tenant-a');
  assert.equal(payload.wechat_id, 'wx_account_new');
  assert.equal(payload.nickname, '顾问新号');
  assert.equal(payload.status, 'enabled');
  assert.equal(payload.customer_count, 0);
  assert.equal(payload.group_chat_count, 0);
  assert.equal(payload.request_id, 'req-tenant-account-create');
  assert.ok(harness.authorizeCalls.length >= 1);
  assert.equal(harness.authorizeCalls.at(-1).permissionCode, 'tenant.account_management.operate');
  assert.equal(harness.createCalls.length, 1);
  assert.equal(harness.createCalls[0].tenantId, 'tenant-a');
  assert.equal(harness.createCalls[0].ownerMembershipId, 'membership-owner');
});

test('tenantCreateAccount accepts trusted preauthorized context without requiring access token re-validation', async () => {
  const harness = createHarness({
    authorizeRoute: async ({ accessToken }) => {
      const normalizedAccessToken = String(accessToken || '').trim();
      if (!normalizedAccessToken) {
        throw new AuthProblemError({
          status: 401,
          title: 'Unauthorized',
          detail: '当前会话无效，请重新登录',
          errorCode: 'AUTH-401-INVALID-ACCESS'
        });
      }
      return {
        user_id: 'tenant-account-operator',
        session_id: 'tenant-account-session',
        entry_domain: 'tenant',
        active_tenant_id: 'tenant-a'
      };
    }
  });

  const preauthorizedContext = markRoutePreauthorizedContext({
    authorizationContext: {
      user_id: 'tenant-account-operator',
      session_id: 'tenant-account-session',
      entry_domain: 'tenant',
      active_tenant_id: 'tenant-a',
      session_context: {
        entry_domain: 'tenant',
        active_tenant_id: 'tenant-a'
      }
    },
    permissionCode: 'tenant.account_management.operate',
    scope: 'tenant'
  });

  const payload = await harness.handlers.tenantCreateAccount(
    'req-tenant-account-create-preauthorized',
    '',
    {
      wechat_id: 'wx_account_preauthorized',
      nickname: '预授权创建',
      owner_membership_id: 'membership-owner',
      assistant_membership_ids: ['membership-assistant']
    },
    preauthorizedContext
  );

  assert.equal(payload.account_id, 'acc_new_001');
  assert.equal(payload.tenant_id, 'tenant-a');
  assert.equal(payload.request_id, 'req-tenant-account-create-preauthorized');
  assert.equal(harness.authorizeCalls.length, 0);
  assert.equal(harness.createCalls.length, 1);
});

test('PATCH /tenant/accounts/:account_id updates account profile in tenant scope', async () => {
  const harness = createHarness();

  const route = await dispatchApiRoute({
    pathname: '/tenant/accounts/acc_001',
    method: 'PATCH',
    requestId: 'req-tenant-account-update',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      wechat_id: 'wx_account_01_updated',
      nickname: '顾问小东-更新',
      owner_membership_id: 'membership-owner',
      assistant_membership_ids: ['membership-assistant']
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 200);
  const payload = JSON.parse(route.body);
  assert.equal(payload.account_id, 'acc_001');
  assert.equal(payload.tenant_id, 'tenant-a');
  assert.equal(payload.wechat_id, 'wx_account_01_updated');
  assert.equal(payload.nickname, '顾问小东-更新');
  assert.equal(payload.request_id, 'req-tenant-account-update');
  assert.ok(harness.authorizeCalls.length >= 1);
  assert.equal(harness.authorizeCalls.at(-1).permissionCode, 'tenant.account_management.operate');
  assert.equal(harness.updateCalls.length, 1);
  assert.equal(harness.updateCalls[0].tenantId, 'tenant-a');
  assert.equal(harness.updateCalls[0].accountId, 'acc_001');
});

test('PATCH /tenant/accounts/:account_id/status updates account status', async () => {
  const harness = createHarness();

  const route = await dispatchApiRoute({
    pathname: '/tenant/accounts/acc_001/status',
    method: 'PATCH',
    requestId: 'req-tenant-account-status',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      status: 'disabled'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 200);
  const payload = JSON.parse(route.body);
  assert.equal(payload.account_id, 'acc_001');
  assert.equal(payload.status, 'disabled');
  assert.equal(payload.request_id, 'req-tenant-account-status');
  assert.equal(harness.updateStatusCalls.length, 1);
  assert.equal(harness.updateStatusCalls[0].tenantId, 'tenant-a');
  assert.equal(harness.updateStatusCalls[0].accountId, 'acc_001');
});

test('GET /tenant/accounts/:account_id returns detail with operation logs sorted desc', async () => {
  const harness = createHarness({
    listTenantAccountOperationLogs: async ({ tenantId, accountId }) => [
      {
        operation_id: 'op_older',
        account_id: accountId,
        tenant_id: tenantId,
        operation_type: 'create',
        operation_content: '初始化账号',
        operator_user_id: 'tenant-account-operator',
        operator_name: '账号管理员',
        operation_time: '2026-01-20T02:00:00.000Z'
      },
      {
        operation_id: 'op_newer',
        account_id: accountId,
        tenant_id: tenantId,
        operation_type: 'update',
        operation_content: '编辑账号',
        operator_user_id: 'tenant-account-operator',
        operator_name: '账号管理员',
        operation_time: '2026-01-28T01:30:00.000Z'
      }
    ]
  });

  const route = await dispatchApiRoute({
    pathname: '/tenant/accounts/acc_001',
    method: 'GET',
    requestId: 'req-tenant-account-detail',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 200);
  const payload = JSON.parse(route.body);
  assert.equal(payload.account_id, 'acc_001');
  assert.equal(payload.owner_name, '负责人甲');
  assert.deepEqual(payload.assistant_names, ['协助人乙']);
  assert.equal(payload.operation_logs.length, 2);
  assert.equal(payload.operation_logs[0].operation_id, 'op_newer');
  assert.equal(payload.operation_logs[1].operation_id, 'op_older');
  assert.equal(harness.detailCalls.length, 1);
  assert.equal(harness.logCalls.length, 1);
});

test('GET /tenant/accounts/:account_id/operation-logs returns operation logs payload', async () => {
  const harness = createHarness();

  const route = await dispatchApiRoute({
    pathname: '/tenant/accounts/acc_001/operation-logs?limit=5',
    method: 'GET',
    requestId: 'req-tenant-account-log-list',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 200);
  const payload = JSON.parse(route.body);
  assert.equal(payload.request_id, 'req-tenant-account-log-list');
  assert.equal(payload.tenant_id, 'tenant-a');
  assert.equal(payload.account_id, 'acc_001');
  assert.equal(payload.operation_logs.length, 2);
  assert.equal(harness.logCalls.length, 1);
  assert.equal(harness.logCalls[0].limit, 5);
});

test('POST /tenant/accounts maps store duplicate wechat conflict to stable 409', async () => {
  const harness = createHarness({
    createTenantAccount: async () => {
      const error = new Error('tenant account wechat conflict');
      error.code = 'ERR_TENANT_ACCOUNT_WECHAT_CONFLICT';
      throw error;
    }
  });

  const route = await dispatchApiRoute({
    pathname: '/tenant/accounts',
    method: 'POST',
    requestId: 'req-tenant-account-create-conflict',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      wechat_id: 'wx_account_dup',
      nickname: '重复账号',
      owner_membership_id: 'membership-owner',
      assistant_membership_ids: ['membership-assistant']
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 409);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'TACCOUNT-409-WECHAT-CONFLICT');
  assert.equal(payload.request_id, 'req-tenant-account-create-conflict');
});

test('GET /tenant/accounts/:account_id fails closed when store returns cross-tenant record', async () => {
  const harness = createHarness({
    findTenantAccountByAccountId: async ({ accountId }) => ({
      account_id: accountId,
      tenant_id: 'tenant-b',
      wechat_id: 'wx_account_cross',
      nickname: '跨租户账号',
      owner_membership_id: 'membership-owner',
      assistant_membership_ids: [],
      customer_count: 1,
      group_chat_count: 1,
      status: 'enabled',
      avatar_url: null,
      created_by_user_id: 'tenant-account-operator',
      updated_by_user_id: 'tenant-account-operator',
      created_at: '2026-01-20T02:00:00.000Z',
      updated_at: '2026-01-28T01:30:00.000Z'
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/tenant/accounts/acc_001',
    method: 'GET',
    requestId: 'req-tenant-account-detail-cross-tenant',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 503);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'TACCOUNT-503-DEPENDENCY-UNAVAILABLE');
  assert.equal(payload.request_id, 'req-tenant-account-detail-cross-tenant');
});
