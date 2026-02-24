const createAuthRouteHandlers = ({
  auth,
  authPingHandler
}) => ({
  authPing: (requestId) => authPingHandler(requestId),

  authLogin: async (requestId, body, traceparent = null) =>
    auth.login({
      requestId,
      body: body || {},
      traceparent
    }),

  authOtpSend: async (requestId, body, traceparent = null) =>
    auth.otpSend({
      requestId,
      body: body || {},
      traceparent
    }),

  authOtpLogin: async (requestId, body, traceparent = null) =>
    auth.otpLogin({
      requestId,
      body: body || {},
      traceparent
    }),

  authTenantOptions: async (requestId, authorization, authorizationContext) =>
    auth.tenantOptions({
      requestId,
      authorization,
      authorizationContext
    }),

  authPlatformOptions: async (requestId, authorization, authorizationContext) =>
    auth.platformOptions({
      requestId,
      authorization,
      authorizationContext
    }),

  authTenantSelect: async (
    requestId,
    authorization,
    body,
    authorizationContext
  ) =>
    auth.tenantSelect({
      requestId,
      authorization,
      body: body || {},
      authorizationContext
    }),

  authTenantSwitch: async (
    requestId,
    authorization,
    body,
    authorizationContext
  ) =>
    auth.tenantSwitch({
      requestId,
      authorization,
      body: body || {},
      authorizationContext
    }),

  authTenantUserManagementProbe: async (requestId) => ({
    ok: true,
    request_id: requestId || 'request_id_unset'
  }),

  authPlatformUserManagementProbe: async (requestId) => ({
    ok: true,
    request_id: requestId || 'request_id_unset'
  }),

  authPlatformUserManagementProvisionUser: async (
    requestId,
    authorization,
    body,
    authorizationContext
  ) =>
    auth.platformProvisionUser({
      requestId,
      authorization,
      body: body || {},
      authorizationContext
    }),

  authTenantUserManagementProvisionUser: async (
    requestId,
    authorization,
    body,
    authorizationContext
  ) =>
    auth.tenantProvisionUser({
      requestId,
      authorization,
      body: body || {},
      authorizationContext
    }),

  authRefresh: async (requestId, body, traceparent = null) =>
    auth.refresh({
      requestId,
      body: body || {},
      traceparent
    }),

  authLogout: async (
    requestId,
    authorization,
    authorizationContext,
    traceparent = null
  ) =>
    auth.logout({
      requestId,
      authorization,
      authorizationContext,
      traceparent
    }),

  authChangePassword: async (
    requestId,
    authorization,
    body,
    authorizationContext,
    traceparent = null
  ) =>
    auth.changePassword({
      requestId,
      authorization,
      body: body || {},
      authorizationContext,
      traceparent
    }),

  authReplacePlatformRoleFacts: async (
    requestId,
    authorization,
    body,
    authorizationContext,
    traceparent = null
  ) =>
    auth.replacePlatformRoleFacts({
      requestId,
      authorization,
      body: body || {},
      authorizationContext,
      traceparent
    })
});

module.exports = {
  createAuthRouteHandlers
};
