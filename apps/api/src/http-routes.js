const { authPing, createAuthHandlers } = require('./modules/auth/auth.routes');
const { createAuthService } = require('./modules/auth/auth.service');
const { createPlatformOrgHandlers } = require('./modules/platform/org.routes');
const { createPlatformOrgService } = require('./modules/platform/org.service');
const { buildOpenApiSpec } = require('./openapi');
const { checkDependencies } = require('./infrastructure/connectivity');
const { log } = require('./common/logger');

const DEPENDENCY_PROBE_FAILURE_DETAIL = 'dependency probe failed';

const assertAlignedPlatformOrgAuthService = ({
  authService,
  platformOrgService
}) => {
  const platformOrgAuthService = platformOrgService?._internals?.authService;
  if (
    authService
    && platformOrgAuthService
    && authService !== platformOrgAuthService
  ) {
    throw new TypeError(
      'createRouteHandlers requires authService and platformOrgService to share the same authService instance'
    );
  }
};

const normalizeDependencyProbeEntry = ({
  dependencyName,
  dependencyValue
}) => {
  const fallbackMode = `${dependencyName}-probe`;
  if (
    !dependencyValue
    || typeof dependencyValue !== 'object'
    || Array.isArray(dependencyValue)
  ) {
    return {
      ok: false,
      mode: fallbackMode,
      detail: 'dependency probe result missing'
    };
  }
  const normalizedMode = String(dependencyValue.mode || '').trim();
  const normalizedDetail = String(dependencyValue.detail || '').trim();
  return {
    ...dependencyValue,
    ok: dependencyValue.ok === true,
    mode: normalizedMode || fallbackMode,
    detail: normalizedDetail || 'dependency probe result missing'
  };
};

const normalizeDependencyProbeSnapshot = (probeSnapshot = null) => ({
  db: normalizeDependencyProbeEntry({
    dependencyName: 'db',
    dependencyValue: probeSnapshot?.db
  }),
  redis: normalizeDependencyProbeEntry({
    dependencyName: 'redis',
    dependencyValue: probeSnapshot?.redis
  })
});

const probeDependenciesSafely = async ({
  dependencyProbe,
  config,
  requestId
}) => {
  try {
    const dependencySnapshot = await dependencyProbe(config, requestId);
    return normalizeDependencyProbeSnapshot(dependencySnapshot);
  } catch (error) {
    log('warn', 'Dependency probe failed; falling back to degraded snapshot', {
      request_id: String(requestId || '').trim() || 'request_id_unset',
      detail: String(error?.message || 'unknown')
    });
    return normalizeDependencyProbeSnapshot({
      db: {
        ok: false,
        mode: 'probe-error',
        detail: DEPENDENCY_PROBE_FAILURE_DETAIL
      },
      redis: {
        ok: false,
        mode: 'probe-error',
        detail: DEPENDENCY_PROBE_FAILURE_DETAIL
      }
    });
  }
};

const createRouteHandlers = (config, options = {}) => {
  const dependencyProbe = typeof options.dependencyProbe === 'function'
    ? options.dependencyProbe
    : checkDependencies;
  const preferredPlatformOrgAuthService = options.platformOrgService?._internals?.authService;
  assertAlignedPlatformOrgAuthService({
    authService: options.authService,
    platformOrgService: options.platformOrgService
  });
  const authService =
    options.authService
    || preferredPlatformOrgAuthService
    || createAuthService();
  const authIdempotencyStore = options.authIdempotencyStore;
  const auth = createAuthHandlers(authService);
  const platformOrgService =
    options.platformOrgService
    || createPlatformOrgService({
      authService
    });
  const platformOrg = createPlatformOrgHandlers(platformOrgService);
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
      const dependencies = await probeDependenciesSafely({
        dependencyProbe,
        config,
        requestId
      });
      return {
        ok: dependencies.db.ok && dependencies.redis.ok,
        service: 'api',
        request_id: requestId,
        dependencies
      };
    },

    smoke: async (requestId) => {
      const dependencies = await probeDependenciesSafely({
        dependencyProbe,
        config,
        requestId
      });
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

    authPlatformMemberAdminProvisionUser: async (
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

    platformCreateOrg: async (
      requestId,
      authorization,
      body,
      authorizationContext
    ) =>
      platformOrg.createOrg({
        requestId,
        authorization,
        body: body || {},
        authorizationContext
      }),

    authTenantMemberAdminProvisionUser: async (
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

    authReplacePlatformRoleFacts: async (
      requestId,
      authorization,
      body,
      authorizationContext
    ) =>
      auth.replacePlatformRoleFacts({
        requestId,
        authorization,
        body: body || {},
        authorizationContext
      }),

    openapi: () => buildOpenApiSpec()
  };

  if (typeof authService?.recordIdempotencyEvent === 'function') {
    handlers.recordAuthIdempotencyEvent = async (payload = {}) =>
      authService.recordIdempotencyEvent(payload);
  }

  if (
    authIdempotencyStore
    && typeof authIdempotencyStore.claimOrRead === 'function'
    && typeof authIdempotencyStore.read === 'function'
    && typeof authIdempotencyStore.resolve === 'function'
    && typeof authIdempotencyStore.releasePending === 'function'
  ) {
    handlers.authIdempotencyStore = authIdempotencyStore;
  }

  if (authorizeRouteHandler) {
    handlers.authorizeRoute = authorizeRouteHandler;
  }

  handlers._internals = {
    authService,
    platformOrgService
  };

  return handlers;
};

module.exports = { createRouteHandlers };
