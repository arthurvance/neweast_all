const test = require('node:test');
const assert = require('node:assert/strict');
const { createRouteHandlers } = require('../src/http-routes');
const {
  createTenantCustomerHandlers
} = require('../src/domains/tenant/customer/profile/customer.routes');
const {
  createTenantCustomerService
} = require('../src/domains/tenant/customer/profile/service');
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

const createNoopTenantAccountService = () => ({
  listAccounts: async () => ({ accounts: [] }),
  createAccount: async () => ({}),
  getAccountDetail: async () => ({}),
  updateAccount: async () => ({}),
  updateAccountStatus: async () => ({}),
  listAccountOperationLogs: async () => ({ operation_logs: [] })
});

const createHarness = ({
  authorizeRoute = async () => ({
    user_id: 'tenant-customer-operator',
    session_id: 'tenant-customer-session',
    entry_domain: 'tenant',
    active_tenant_id: 'tenant-a',
    tenant_permission_context: {
      can_view_customer_management: true,
      can_operate_customer_management: true,
      can_view_customer_scope_my: true,
      can_operate_customer_scope_my: true,
      can_view_customer_scope_assist: true,
      can_operate_customer_scope_assist: true,
      can_view_customer_scope_all: true,
      can_operate_customer_scope_all: true
    }
  }),
  listTenantCustomersByTenantId = async ({ tenantId }) => [
    {
      customer_id: 'cus_001',
      tenant_id: tenantId,
      account_id: 'acc_001',
      wechat_id: 'wx_customer_001',
      nickname: '客户甲',
      source: 'ground',
      status: 'enabled',
      real_name: '张三',
      school: '测试小学',
      class_name: '三年二班',
      relation: '家长',
      phone: '13800001111',
      address: '测试路 100 号',
      created_by_user_id: 'tenant-customer-operator',
      updated_by_user_id: 'tenant-customer-operator',
      created_at: '2026-02-10T08:00:00.000Z',
      updated_at: '2026-02-10T08:00:00.000Z'
    }
  ],
  createTenantCustomer = async ({ tenantId, accountId, wechatId, nickname, source, status }) => ({
    customer_id: 'cus_new_001',
    tenant_id: tenantId,
    account_id: accountId,
    wechat_id: wechatId,
    nickname,
    source,
    status,
    real_name: null,
    school: null,
    class_name: null,
    relation: null,
    phone: null,
    address: null,
    created_by_user_id: 'tenant-customer-operator',
    updated_by_user_id: 'tenant-customer-operator',
    created_at: '2026-02-12T08:00:00.000Z',
    updated_at: '2026-02-12T08:00:00.000Z'
  }),
  findTenantCustomerByCustomerId = async ({ tenantId, customerId }) => ({
    customer_id: customerId,
    tenant_id: tenantId,
    account_id: 'acc_001',
    wechat_id: 'wx_customer_001',
    nickname: '客户甲',
    source: 'ground',
    status: 'enabled',
    real_name: '张三',
    school: '测试小学',
    class_name: '三年二班',
    relation: '家长',
    phone: '13800001111',
    address: '测试路 100 号',
    created_by_user_id: 'tenant-customer-operator',
    updated_by_user_id: 'tenant-customer-operator',
    created_at: '2026-02-10T08:00:00.000Z',
    updated_at: '2026-02-10T08:00:00.000Z'
  }),
  updateTenantCustomerBasic = async ({ tenantId, customerId, source }) => ({
    customer_id: customerId,
    tenant_id: tenantId,
    account_id: 'acc_001',
    wechat_id: 'wx_customer_001',
    nickname: '客户甲',
    source,
    status: 'enabled',
    real_name: '张三',
    school: '测试小学',
    class_name: '三年二班',
    relation: '家长',
    phone: '13800001111',
    address: '测试路 100 号',
    created_by_user_id: 'tenant-customer-operator',
    updated_by_user_id: 'tenant-customer-operator',
    created_at: '2026-02-10T08:00:00.000Z',
    updated_at: '2026-02-12T09:00:00.000Z'
  }),
  updateTenantCustomerRealname = async ({
    tenantId,
    customerId,
    realName,
    school,
    className,
    relation,
    phone,
    address
  }) => ({
    customer_id: customerId,
    tenant_id: tenantId,
    account_id: 'acc_001',
    wechat_id: 'wx_customer_001',
    nickname: '客户甲',
    source: 'ground',
    status: 'enabled',
    real_name: realName,
    school,
    class_name: className,
    relation,
    phone,
    address,
    created_by_user_id: 'tenant-customer-operator',
    updated_by_user_id: 'tenant-customer-operator',
    created_at: '2026-02-10T08:00:00.000Z',
    updated_at: '2026-02-12T09:30:00.000Z'
  }),
  listTenantCustomerOperationLogs = async ({ tenantId, customerId }) => [
    {
      operation_id: 'cop_old',
      tenant_id: tenantId,
      customer_id: customerId,
      operation_type: 'create',
      operation_content: '新建客户',
      operator_user_id: 'tenant-customer-operator',
      operator_name: '客户管理员',
      operation_time: '2026-02-10T08:00:00.000Z',
      created_at: '2026-02-10T08:00:00.000Z'
    },
    {
      operation_id: 'cop_new',
      tenant_id: tenantId,
      customer_id: customerId,
      operation_type: 'update_realname',
      operation_content: '更新实名信息',
      operator_user_id: 'tenant-customer-operator',
      operator_name: '客户管理员',
      operation_time: '2026-02-12T09:30:00.000Z',
      created_at: '2026-02-12T09:30:00.000Z'
    }
  ]
} = {}) => {
  const authorizeCalls = [];
  const listCalls = [];
  const createCalls = [];
  const detailCalls = [];
  const updateBasicCalls = [];
  const updateRealnameCalls = [];
  const logCalls = [];

  const authStore = {
    listTenantCustomersByTenantId: async (payload) => {
      listCalls.push(payload);
      return listTenantCustomersByTenantId(payload);
    },
    createTenantCustomer: async (payload) => {
      createCalls.push(payload);
      return createTenantCustomer(payload);
    },
    findTenantCustomerByCustomerId: async (payload) => {
      detailCalls.push(payload);
      return findTenantCustomerByCustomerId(payload);
    },
    updateTenantCustomerBasic: async (payload) => {
      updateBasicCalls.push(payload);
      return updateTenantCustomerBasic(payload);
    },
    updateTenantCustomerRealname: async (payload) => {
      updateRealnameCalls.push(payload);
      return updateTenantCustomerRealname(payload);
    },
    listTenantCustomerOperationLogs: async (payload) => {
      logCalls.push(payload);
      return listTenantCustomerOperationLogs(payload);
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

  const tenantCustomerService = createTenantCustomerService({
    authService
  });

  const handlers = createRouteHandlers(config, {
    dependencyProbe,
    authService,
    tenantUserService: createNoopTenantUserService(),
    tenantRoleService: createNoopTenantRoleService(),
    tenantAccountService: createNoopTenantAccountService(),
    tenantCustomerService
  });

  return {
    handlers,
    authorizeCalls,
    listCalls,
    createCalls,
    detailCalls,
    updateBasicCalls,
    updateRealnameCalls,
    logCalls
  };
};

test('createTenantCustomerHandlers fails fast when service capability is missing', () => {
  assert.throws(
    () => createTenantCustomerHandlers(),
    /requires a tenantCustomerService with listCustomers, createCustomer, getCustomerDetail, updateCustomerBasic, updateCustomerRealname and listCustomerOperationLogs/
  );
  assert.throws(
    () => createTenantCustomerHandlers({}),
    /requires a tenantCustomerService with listCustomers, createCustomer, getCustomerDetail, updateCustomerBasic, updateCustomerRealname and listCustomerOperationLogs/
  );
});

test('GET /tenant/customers lists customers with scope and filters', async () => {
  const harness = createHarness();

  const route = await dispatchApiRoute({
    pathname: '/tenant/customers?scope=assist&nickname=客户&status=enabled&page=1&page_size=20',
    method: 'GET',
    requestId: 'req-tenant-customer-list',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 200);
  const payload = JSON.parse(route.body);
  assert.equal(payload.request_id, 'req-tenant-customer-list');
  assert.equal(payload.tenant_id, 'tenant-a');
  assert.equal(payload.scope, 'assist');
  assert.equal(payload.total, 1);
  assert.equal(payload.customers[0].customer_id, 'cus_001');
  assert.equal(payload.customers[0].status, 'enabled');
  assert.equal(harness.authorizeCalls.at(-1).permissionCode, 'tenant.customer_management.view');
  assert.equal(harness.listCalls.length, 1);
  assert.equal(harness.listCalls[0].tenantId, 'tenant-a');
  assert.equal(harness.listCalls[0].scope, 'assist');
});

test('GET /tenant/customers denies scope=all when scope permission missing', async () => {
  const harness = createHarness({
    authorizeRoute: async () => ({
      user_id: 'tenant-customer-operator',
      session_id: 'tenant-customer-session',
      entry_domain: 'tenant',
      active_tenant_id: 'tenant-a',
      tenant_permission_context: {
        can_view_customer_management: true,
        can_operate_customer_management: true,
        can_view_customer_scope_my: true,
        can_view_customer_scope_assist: true,
        can_view_customer_scope_all: false
      }
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/tenant/customers?scope=all',
    method: 'GET',
    requestId: 'req-tenant-customer-list-forbidden-scope',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 403);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-403-FORBIDDEN');
  assert.equal(payload.request_id, 'req-tenant-customer-list-forbidden-scope');
});

test('POST /tenant/customers creates customer with forced enabled status', async () => {
  const harness = createHarness();

  const route = await dispatchApiRoute({
    pathname: '/tenant/customers',
    method: 'POST',
    requestId: 'req-tenant-customer-create',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      account_id: 'acc_001',
      wechat_id: 'wx_customer_new',
      nickname: '新客户',
      source: 'ground'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 200);
  const payload = JSON.parse(route.body);
  assert.equal(payload.customer_id, 'cus_new_001');
  assert.equal(payload.tenant_id, 'tenant-a');
  assert.equal(payload.status, 'enabled');
  assert.equal(payload.request_id, 'req-tenant-customer-create');
  assert.equal(harness.authorizeCalls.at(-1).permissionCode, 'tenant.customer_management.operate');
  assert.equal(harness.createCalls.length, 1);
  assert.equal(harness.createCalls[0].status, 'enabled');
});

test('POST /tenant/customers rejects external status input', async () => {
  const harness = createHarness();

  const route = await dispatchApiRoute({
    pathname: '/tenant/customers',
    method: 'POST',
    requestId: 'req-tenant-customer-create-status-forbidden',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      account_id: 'acc_001',
      wechat_id: 'wx_customer_new',
      nickname: '新客户',
      source: 'ground',
      status: 'disabled'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 400);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'TCUSTOMER-400-INVALID-PAYLOAD');
  assert.equal(payload.request_id, 'req-tenant-customer-create-status-forbidden');
});

test('POST /tenant/customers returns 403 when no customer scope permission is granted', async () => {
  const harness = createHarness({
    authorizeRoute: async () => ({
      user_id: 'tenant-customer-operator',
      session_id: 'tenant-customer-session',
      entry_domain: 'tenant',
      active_tenant_id: 'tenant-a',
      tenant_permission_context: {
        can_view_customer_management: false,
        can_operate_customer_management: true,
        can_view_customer_scope_my: false,
        can_view_customer_scope_assist: false,
        can_view_customer_scope_all: false
      }
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/tenant/customers',
    method: 'POST',
    requestId: 'req-tenant-customer-create-no-scope-forbidden',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      account_id: 'acc_001',
      wechat_id: 'wx_customer_no_scope',
      nickname: '无范围客户',
      source: 'ground'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 403);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-403-FORBIDDEN');
  assert.equal(payload.request_id, 'req-tenant-customer-create-no-scope-forbidden');
  assert.equal(harness.createCalls.length, 0);
});

test('tenantCreateCustomer accepts trusted preauthorized context without requiring access token re-validation', async () => {
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
        user_id: 'tenant-customer-operator',
        session_id: 'tenant-customer-session',
        entry_domain: 'tenant',
        active_tenant_id: 'tenant-a',
        tenant_permission_context: {
          can_view_customer_management: true,
          can_operate_customer_management: true,
          can_view_customer_scope_my: true,
          can_operate_customer_scope_my: true,
          can_view_customer_scope_assist: true,
          can_operate_customer_scope_assist: true,
          can_view_customer_scope_all: true,
          can_operate_customer_scope_all: true
        }
      };
    }
  });

  const preauthorizedContext = markRoutePreauthorizedContext({
    authorizationContext: {
      user_id: 'tenant-customer-operator',
      session_id: 'tenant-customer-session',
      entry_domain: 'tenant',
      active_tenant_id: 'tenant-a',
      session_context: {
        entry_domain: 'tenant',
        active_tenant_id: 'tenant-a'
      },
      tenant_permission_context: {
        can_view_customer_management: true,
        can_operate_customer_management: true,
        can_view_customer_scope_my: true,
        can_operate_customer_scope_my: true,
        can_view_customer_scope_assist: true,
        can_operate_customer_scope_assist: true,
        can_view_customer_scope_all: true,
        can_operate_customer_scope_all: true
      }
    },
    permissionCode: 'tenant.customer_management.operate',
    scope: 'tenant'
  });

  const payload = await harness.handlers.tenantCreateCustomer(
    'req-tenant-customer-create-preauthorized',
    '',
    {
      account_id: 'acc_001',
      wechat_id: 'wx_customer_preauth',
      nickname: '预授权客户',
      source: 'fission'
    },
    preauthorizedContext
  );

  assert.equal(payload.customer_id, 'cus_new_001');
  assert.equal(payload.request_id, 'req-tenant-customer-create-preauthorized');
  assert.equal(harness.authorizeCalls.length, 0);
  assert.equal(harness.createCalls.length, 1);
});

test('PATCH /tenant/customers/:customer_id/basic updates basic customer fields', async () => {
  const harness = createHarness();

  const route = await dispatchApiRoute({
    pathname: '/tenant/customers/cus_001/basic',
    method: 'PATCH',
    requestId: 'req-tenant-customer-update-basic',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      source: 'fission'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 200);
  const payload = JSON.parse(route.body);
  assert.equal(payload.customer_id, 'cus_001');
  assert.equal(payload.source, 'fission');
  assert.equal(payload.request_id, 'req-tenant-customer-update-basic');
  assert.equal(harness.updateBasicCalls.length, 1);
  assert.equal(harness.updateBasicCalls[0].customerId, 'cus_001');
  assert.deepEqual(harness.updateBasicCalls[0].scopes, ['my', 'assist', 'all']);
});

test('PATCH /tenant/customers/:customer_id/realname updates profile fields', async () => {
  const harness = createHarness();

  const route = await dispatchApiRoute({
    pathname: '/tenant/customers/cus_001/realname',
    method: 'PATCH',
    requestId: 'req-tenant-customer-update-realname',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      real_name: '李四',
      school: '实验小学',
      class_name: '四年一班',
      relation: '母亲',
      phone: '13800002222',
      address: '测试路 200 号'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 200);
  const payload = JSON.parse(route.body);
  assert.equal(payload.customer_id, 'cus_001');
  assert.equal(payload.real_name, '李四');
  assert.equal(payload.school, '实验小学');
  assert.equal(payload.class_name, '四年一班');
  assert.equal(payload.request_id, 'req-tenant-customer-update-realname');
  assert.equal(harness.updateRealnameCalls.length, 1);
  assert.equal(harness.updateRealnameCalls[0].customerId, 'cus_001');
  assert.deepEqual(harness.updateRealnameCalls[0].scopes, ['my', 'assist', 'all']);
});

test('PATCH /tenant/customers/:customer_id/basic returns 403 when no customer scope permission is granted', async () => {
  const harness = createHarness({
    authorizeRoute: async () => ({
      user_id: 'tenant-customer-operator',
      session_id: 'tenant-customer-session',
      entry_domain: 'tenant',
      active_tenant_id: 'tenant-a',
      tenant_permission_context: {
        can_view_customer_management: false,
        can_operate_customer_management: true,
        can_view_customer_scope_my: false,
        can_view_customer_scope_assist: false,
        can_view_customer_scope_all: false
      }
    })
  });

  const route = await dispatchApiRoute({
    pathname: '/tenant/customers/cus_001/basic',
    method: 'PATCH',
    requestId: 'req-tenant-customer-update-basic-no-scope-forbidden',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      source: 'fission'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 403);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-403-FORBIDDEN');
  assert.equal(payload.request_id, 'req-tenant-customer-update-basic-no-scope-forbidden');
  assert.equal(harness.updateBasicCalls.length, 0);
});

test('GET /tenant/customers/:customer_id returns detail with operation logs sorted desc', async () => {
  const harness = createHarness({
    listTenantCustomerOperationLogs: async ({ tenantId, customerId }) => [
      {
        operation_id: 'cop_old',
        tenant_id: tenantId,
        customer_id: customerId,
        operation_type: 'create',
        operation_content: '新建客户',
        operator_user_id: 'tenant-customer-operator',
        operator_name: '客户管理员',
        operation_time: '2026-02-10T08:00:00.000Z',
        created_at: '2026-02-10T08:00:00.000Z'
      },
      {
        operation_id: 'cop_new',
        tenant_id: tenantId,
        customer_id: customerId,
        operation_type: 'update_realname',
        operation_content: '更新实名信息',
        operator_user_id: 'tenant-customer-operator',
        operator_name: '客户管理员',
        operation_time: '2026-02-12T09:30:00.000Z',
        created_at: '2026-02-12T09:30:00.000Z'
      }
    ]
  });

  const route = await dispatchApiRoute({
    pathname: '/tenant/customers/cus_001',
    method: 'GET',
    requestId: 'req-tenant-customer-detail',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 200);
  const payload = JSON.parse(route.body);
  assert.equal(payload.customer_id, 'cus_001');
  assert.equal(payload.operation_logs.length, 2);
  assert.equal(payload.operation_logs[0].operation_id, 'cop_new');
  assert.equal(payload.operation_logs[1].operation_id, 'cop_old');
  assert.equal(harness.detailCalls.length, 1);
  assert.equal(harness.logCalls.length, 1);
  assert.equal(harness.detailCalls[0].operatorUserId, 'tenant-customer-operator');
  assert.deepEqual(harness.detailCalls[0].scopes, ['my', 'assist', 'all']);
  assert.equal(harness.logCalls[0].operatorUserId, 'tenant-customer-operator');
  assert.deepEqual(harness.logCalls[0].scopes, ['my', 'assist', 'all']);
});

test('GET /tenant/customers/:customer_id/operation-logs returns operation logs payload', async () => {
  const harness = createHarness();

  const route = await dispatchApiRoute({
    pathname: '/tenant/customers/cus_001/operation-logs?limit=5',
    method: 'GET',
    requestId: 'req-tenant-customer-log-list',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 200);
  const payload = JSON.parse(route.body);
  assert.equal(payload.request_id, 'req-tenant-customer-log-list');
  assert.equal(payload.tenant_id, 'tenant-a');
  assert.equal(payload.customer_id, 'cus_001');
  assert.equal(payload.operation_logs.length, 2);
  assert.equal(harness.logCalls.length, 1);
  assert.equal(harness.logCalls[0].limit, 5);
});

test('GET /tenant/customers/:customer_id returns 404 when customer is outside permitted scopes', async () => {
  const harness = createHarness({
    authorizeRoute: async () => ({
      user_id: 'tenant-customer-operator',
      session_id: 'tenant-customer-session',
      entry_domain: 'tenant',
      active_tenant_id: 'tenant-a',
      tenant_permission_context: {
        can_view_customer_management: true,
        can_operate_customer_management: true,
        can_view_customer_scope_my: true,
        can_view_customer_scope_assist: false,
        can_view_customer_scope_all: false
      }
    }),
    findTenantCustomerByCustomerId: async ({ scopes, operatorUserId }) => {
      assert.equal(operatorUserId, 'tenant-customer-operator');
      assert.deepEqual(scopes, ['my']);
      return null;
    },
    listTenantCustomerOperationLogs: async ({ scopes, operatorUserId }) => {
      assert.equal(operatorUserId, 'tenant-customer-operator');
      assert.deepEqual(scopes, ['my']);
      return [];
    }
  });

  const route = await dispatchApiRoute({
    pathname: '/tenant/customers/cus_001',
    method: 'GET',
    requestId: 'req-tenant-customer-detail-scope-denied',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 404);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'TCUSTOMER-404-NOT-FOUND');
  assert.equal(payload.request_id, 'req-tenant-customer-detail-scope-denied');
  assert.equal(harness.detailCalls.length, 1);
  assert.equal(harness.logCalls.length, 1);
});

test('GET /tenant/customers/:customer_id/operation-logs returns 404 when customer is outside permitted scopes', async () => {
  const harness = createHarness({
    authorizeRoute: async () => ({
      user_id: 'tenant-customer-operator',
      session_id: 'tenant-customer-session',
      entry_domain: 'tenant',
      active_tenant_id: 'tenant-a',
      tenant_permission_context: {
        can_view_customer_management: true,
        can_operate_customer_management: true,
        can_view_customer_scope_my: false,
        can_view_customer_scope_assist: true,
        can_view_customer_scope_all: false
      }
    }),
    findTenantCustomerByCustomerId: async ({ scopes, operatorUserId }) => {
      assert.equal(operatorUserId, 'tenant-customer-operator');
      assert.deepEqual(scopes, ['assist']);
      return null;
    },
    listTenantCustomerOperationLogs: async ({ scopes, operatorUserId }) => {
      assert.equal(operatorUserId, 'tenant-customer-operator');
      assert.deepEqual(scopes, ['assist']);
      return [];
    }
  });

  const route = await dispatchApiRoute({
    pathname: '/tenant/customers/cus_001/operation-logs?limit=5',
    method: 'GET',
    requestId: 'req-tenant-customer-logs-scope-denied',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 404);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'TCUSTOMER-404-NOT-FOUND');
  assert.equal(payload.request_id, 'req-tenant-customer-logs-scope-denied');
  assert.equal(harness.detailCalls.length, 1);
  assert.equal(harness.logCalls.length, 1);
});

test('POST /tenant/customers maps store duplicate wechat conflict to stable 409', async () => {
  const harness = createHarness({
    createTenantCustomer: async () => {
      const error = new Error('tenant customer wechat conflict');
      error.code = 'ERR_TENANT_CUSTOMER_WECHAT_CONFLICT';
      throw error;
    }
  });

  const route = await dispatchApiRoute({
    pathname: '/tenant/customers',
    method: 'POST',
    requestId: 'req-tenant-customer-create-conflict',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      account_id: 'acc_001',
      wechat_id: 'wx_customer_dup',
      nickname: '重复客户',
      source: 'ground'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 409);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'TCUSTOMER-409-WECHAT-CONFLICT');
  assert.equal(payload.request_id, 'req-tenant-customer-create-conflict');
});
