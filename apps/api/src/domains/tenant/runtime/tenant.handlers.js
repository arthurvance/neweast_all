const createTenantRouteHandlers = ({
  tenantUser,
  tenantRole,
  tenantAccount,
  tenantCustomer
}) => ({
  tenantListUsers: async (
    requestId,
    authorization,
    query,
    authorizationContext
  ) =>
    tenantUser.listUsers({
      requestId,
      authorization,
      query: query || {},
      authorizationContext
    }),

  tenantCreateUser: async (
    requestId,
    authorization,
    body,
    authorizationContext
  ) =>
    tenantUser.createUser({
      requestId,
      authorization,
      body: body || {},
      authorizationContext
    }),

  tenantUpdateUserStatus: async (
    requestId,
    authorization,
    params,
    body,
    authorizationContext,
    traceparent = null
  ) =>
    tenantUser.updateUserStatus({
      requestId,
      authorization,
      params: params || {},
      body: body || {},
      traceparent,
      authorizationContext
    }),

  tenantGetUserDetail: async (
    requestId,
    authorization,
    params,
    authorizationContext
  ) =>
    tenantUser.getUserDetail({
      requestId,
      authorization,
      params: params || {},
      authorizationContext
    }),

  tenantUpdateUserProfile: async (
    requestId,
    authorization,
    params,
    body,
    authorizationContext
  ) =>
    tenantUser.updateUserProfile({
      requestId,
      authorization,
      params: params || {},
      body: body || {},
      authorizationContext
    }),

  tenantGetUserRoles: async (
    requestId,
    authorization,
    params,
    authorizationContext
  ) =>
    tenantUser.getUserRoles({
      requestId,
      authorization,
      params: params || {},
      authorizationContext
    }),

  tenantReplaceUserRoles: async (
    requestId,
    authorization,
    params,
    body,
    authorizationContext,
    traceparent = null
  ) =>
    tenantUser.replaceUserRoles({
      requestId,
      authorization,
      params: params || {},
      body: body || {},
      traceparent,
      authorizationContext
    }),

  tenantListRoles: async (
    requestId,
    authorization,
    authorizationContext
  ) =>
    tenantRole.listRoles({
      requestId,
      authorization,
      authorizationContext
    }),

  tenantCreateRole: async (
    requestId,
    authorization,
    body,
    authorizationContext,
    traceparent = null
  ) =>
    tenantRole.createRole({
      requestId,
      authorization,
      body: body || {},
      traceparent,
      authorizationContext
    }),

  tenantUpdateRole: async (
    requestId,
    authorization,
    params,
    body,
    authorizationContext,
    traceparent = null
  ) =>
    tenantRole.updateRole({
      requestId,
      authorization,
      params: params || {},
      body: body || {},
      traceparent,
      authorizationContext
    }),

  tenantDeleteRole: async (
    requestId,
    authorization,
    params,
    authorizationContext,
    traceparent = null
  ) =>
    tenantRole.deleteRole({
      requestId,
      authorization,
      params: params || {},
      traceparent,
      authorizationContext
    }),

  tenantGetRolePermissions: async (
    requestId,
    authorization,
    params,
    authorizationContext
  ) =>
    tenantRole.getRolePermissions({
      requestId,
      authorization,
      params: params || {},
      authorizationContext
    }),

  tenantReplaceRolePermissions: async (
    requestId,
    authorization,
    params,
    body,
    authorizationContext,
    traceparent = null
  ) =>
    tenantRole.replaceRolePermissions({
      requestId,
      authorization,
      params: params || {},
      body: body || {},
      traceparent,
      authorizationContext
    }),

  tenantListAccounts: async (
    requestId,
    authorization,
    query,
    authorizationContext
  ) =>
    tenantAccount.listAccounts({
      requestId,
      authorization,
      query: query || {},
      authorizationContext
    }),

  tenantCreateAccount: async (
    requestId,
    authorization,
    body,
    authorizationContext,
    traceparent = null
  ) =>
    tenantAccount.createAccount({
      requestId,
      authorization,
      body: body || {},
      traceparent,
      authorizationContext
    }),

  tenantGetAccountDetail: async (
    requestId,
    authorization,
    params,
    authorizationContext
  ) =>
    tenantAccount.getAccountDetail({
      requestId,
      authorization,
      params: params || {},
      authorizationContext
    }),

  tenantUpdateAccount: async (
    requestId,
    authorization,
    params,
    body,
    authorizationContext,
    traceparent = null
  ) =>
    tenantAccount.updateAccount({
      requestId,
      authorization,
      params: params || {},
      body: body || {},
      traceparent,
      authorizationContext
    }),

  tenantUpdateAccountStatus: async (
    requestId,
    authorization,
    params,
    body,
    authorizationContext,
    traceparent = null
  ) =>
    tenantAccount.updateAccountStatus({
      requestId,
      authorization,
      params: params || {},
      body: body || {},
      traceparent,
      authorizationContext
    }),

  tenantListAccountOperationLogs: async (
    requestId,
    authorization,
    params,
    query,
    authorizationContext
  ) =>
    tenantAccount.listAccountOperationLogs({
      requestId,
      authorization,
      params: params || {},
      query: query || {},
      authorizationContext
    }),

  tenantListCustomers: async (
    requestId,
    authorization,
    query,
    authorizationContext
  ) =>
    tenantCustomer.listCustomers({
      requestId,
      authorization,
      query: query || {},
      authorizationContext
    }),

  tenantCreateCustomer: async (
    requestId,
    authorization,
    body,
    authorizationContext,
    traceparent = null
  ) =>
    tenantCustomer.createCustomer({
      requestId,
      authorization,
      body: body || {},
      traceparent,
      authorizationContext
    }),

  tenantGetCustomerDetail: async (
    requestId,
    authorization,
    params,
    authorizationContext
  ) =>
    tenantCustomer.getCustomerDetail({
      requestId,
      authorization,
      params: params || {},
      authorizationContext
    }),

  tenantUpdateCustomerBasic: async (
    requestId,
    authorization,
    params,
    body,
    authorizationContext,
    traceparent = null
  ) =>
    tenantCustomer.updateCustomerBasic({
      requestId,
      authorization,
      params: params || {},
      body: body || {},
      traceparent,
      authorizationContext
    }),

  tenantUpdateCustomerRealname: async (
    requestId,
    authorization,
    params,
    body,
    authorizationContext,
    traceparent = null
  ) =>
    tenantCustomer.updateCustomerRealname({
      requestId,
      authorization,
      params: params || {},
      body: body || {},
      traceparent,
      authorizationContext
    }),

  tenantListCustomerOperationLogs: async (
    requestId,
    authorization,
    params,
    query,
    authorizationContext
  ) =>
    tenantCustomer.listCustomerOperationLogs({
      requestId,
      authorization,
      params: params || {},
      query: query || {},
      authorizationContext
    })
});

module.exports = {
  createTenantRouteHandlers
};
