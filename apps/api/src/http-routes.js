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

    authLogin: (requestId, body) =>
      auth.login({
        requestId,
        body: body || {}
      }),

    authRefresh: (requestId, body) =>
      auth.refresh({
        requestId,
        body: body || {}
      }),

    authLogout: (requestId, authorization) =>
      auth.logout({
        requestId,
        authorization
      }),

    authChangePassword: (requestId, authorization, body) =>
      auth.changePassword({
        requestId,
        authorization,
        body: body || {}
      }),

    openapi: () => buildOpenApiSpec()
  };
};

module.exports = { createRouteHandlers };
