const { authPing, createAuthHandlers } = require('./modules/auth/auth.routes');
const { buildOpenApiSpec } = require('./openapi');

const createRouteHandlers = (config, options) => {
  const dependencyProbe = options.dependencyProbe;
  const auth = createAuthHandlers(options.authService);

  return {
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

    authTenantOptions: async (requestId, authorization) =>
      auth.tenantOptions({
        requestId,
        authorization
      }),

    authTenantSelect: async (requestId, authorization, body) =>
      auth.tenantSelect({
        requestId,
        authorization,
        body: body || {}
      }),

    authTenantSwitch: async (requestId, authorization, body) =>
      auth.tenantSwitch({
        requestId,
        authorization,
        body: body || {}
      }),

    authRefresh: async (requestId, body) =>
      auth.refresh({
        requestId,
        body: body || {}
      }),

    authLogout: async (requestId, authorization) =>
      auth.logout({
        requestId,
        authorization
      }),

    authChangePassword: async (requestId, authorization, body) =>
      auth.changePassword({
        requestId,
        authorization,
        body: body || {}
      }),

    openapi: () => buildOpenApiSpec()
  };
};

module.exports = { createRouteHandlers };
