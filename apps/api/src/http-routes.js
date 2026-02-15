const { authPing, createAuthHandlers } = require('./modules/auth/auth.routes');
const { buildOpenApiSpec } = require('./openapi');

const createRouteHandlers = (config, options) => {
  const dependencyProbe = options.dependencyProbe;
  const auth = createAuthHandlers(options.authService);
  const authorizeRouteHandler =
    typeof auth.authorizeRoute === 'function'
      ? async ({ requestId, authorization, permissionCode, scope }) =>
        auth.authorizeRoute({
          requestId,
          authorization,
          permissionCode,
          scope
        })
      : undefined;

  const handlers = {
    health: async (requestId) => {
      const dependencies = await dependencyProbe(config, requestId);
      return {
        ok: dependencies.db.ok && dependencies.redis.ok,
        service: 'api',
        request_id: requestId,
        dependencies
      };
    },

    smoke: async (requestId) => {
      const dependencies = await dependencyProbe(config, requestId);
      return {
        ok: dependencies.db.ok && dependencies.redis.ok,
        chain: 'api -> db/redis',
        request_id: requestId,
        dependencies
      };
    },

    authPing: (requestId) => authPing(requestId),

    authLogin: async (requestId, body) =>
      auth.login({
        requestId,
        body: body || {}
      }),

    authOtpSend: async (requestId, body) =>
      auth.otpSend({
        requestId,
        body: body || {}
      }),

    authOtpLogin: async (requestId, body) =>
      auth.otpLogin({
        requestId,
        body: body || {}
      }),

    authTenantOptions: async (requestId, authorization, authorizationContext) =>
      auth.tenantOptions({
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

    authTenantMemberAdminProbe: async (requestId) => ({
      ok: true,
      request_id: requestId || 'request_id_unset'
    }),

    authPlatformMemberAdminProbe: async (requestId) => ({
      ok: true,
      request_id: requestId || 'request_id_unset'
    }),

    authRefresh: async (requestId, body) =>
      auth.refresh({
        requestId,
        body: body || {}
      }),

    authLogout: async (requestId, authorization, authorizationContext) =>
      auth.logout({
        requestId,
        authorization,
        authorizationContext
      }),

    authChangePassword: async (
      requestId,
      authorization,
      body,
      authorizationContext
    ) =>
      auth.changePassword({
        requestId,
        authorization,
        body: body || {},
        authorizationContext
      }),

    openapi: () => buildOpenApiSpec()
  };

  if (authorizeRouteHandler) {
    handlers.authorizeRoute = authorizeRouteHandler;
  }

  return handlers;
};

module.exports = { createRouteHandlers };
