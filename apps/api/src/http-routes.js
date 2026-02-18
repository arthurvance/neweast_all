const { authPing, createAuthHandlers } = require('./modules/auth/auth.routes');
const { createAuthService } = require('./modules/auth/auth.service');
const { createPlatformOrgHandlers } = require('./modules/platform/org.routes');
const { createPlatformOrgService } = require('./modules/platform/org.service');
const { createPlatformRoleHandlers } = require('./modules/platform/role.routes');
const { createPlatformRoleService } = require('./modules/platform/role.service');
const { createPlatformUserHandlers } = require('./modules/platform/user.routes');
const { createPlatformUserService } = require('./modules/platform/user.service');
const { buildOpenApiSpec } = require('./openapi');
const { checkDependencies } = require('./infrastructure/connectivity');
const { log } = require('./common/logger');

const DEPENDENCY_PROBE_FAILURE_DETAIL = 'dependency probe failed';

const assertAlignedPlatformServicesAuthService = ({
  authService,
  platformOrgService,
  platformRoleService,
  platformUserService
}) => {
  const platformOrgAuthService = platformOrgService?._internals?.authService;
  const platformRoleAuthService = platformRoleService?._internals?.authService;
  const platformUserAuthService = platformUserService?._internals?.authService;
  if (
    platformOrgAuthService
    && platformRoleAuthService
    && platformOrgAuthService !== platformRoleAuthService
  ) {
    throw new TypeError(
      'createRouteHandlers requires platformOrgService and platformRoleService to share the same authService instance'
    );
  }
  if (
    platformOrgAuthService
    && platformUserAuthService
    && platformOrgAuthService !== platformUserAuthService
  ) {
    throw new TypeError(
      'createRouteHandlers requires platformOrgService and platformUserService to share the same authService instance'
    );
  }
  if (
    platformRoleAuthService
    && platformUserAuthService
    && platformRoleAuthService !== platformUserAuthService
  ) {
    throw new TypeError(
      'createRouteHandlers requires platformRoleService and platformUserService to share the same authService instance'
    );
  }
  if (
    authService
    && platformOrgAuthService
    && authService !== platformOrgAuthService
  ) {
    throw new TypeError(
      'createRouteHandlers requires authService and platformOrgService to share the same authService instance'
    );
  }
  if (
    authService
    && platformRoleAuthService
    && authService !== platformRoleAuthService
  ) {
    throw new TypeError(
      'createRouteHandlers requires authService and platformRoleService to share the same authService instance'
    );
  }
  if (
    authService
    && platformUserAuthService
    && authService !== platformUserAuthService
  ) {
    throw new TypeError(
      'createRouteHandlers requires authService and platformUserService to share the same authService instance'
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
  const preferredPlatformRoleAuthService = options.platformRoleService?._internals?.authService;
  const preferredPlatformUserAuthService = options.platformUserService?._internals?.authService;
  assertAlignedPlatformServicesAuthService({
    authService: options.authService,
    platformOrgService: options.platformOrgService,
    platformRoleService: options.platformRoleService,
    platformUserService: options.platformUserService
  });
  const authService =
    options.authService
    || preferredPlatformOrgAuthService
    || preferredPlatformRoleAuthService
    || preferredPlatformUserAuthService
    || createAuthService();
  const authIdempotencyStore = options.authIdempotencyStore;
  const auth = createAuthHandlers(authService);
  const platformOrgService =
    options.platformOrgService
    || createPlatformOrgService({
      authService
    });
  const platformOrg = createPlatformOrgHandlers(platformOrgService);
  const platformRoleService =
    options.platformRoleService
    || createPlatformRoleService({
      authService
    });
  const platformRole = createPlatformRoleHandlers(platformRoleService);
  const platformUserService =
    options.platformUserService
    || createPlatformUserService({
      authService
    });
  const platformUser = createPlatformUserHandlers(platformUserService);
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

    platformUpdateOrgStatus: async (
      requestId,
      authorization,
      body,
      authorizationContext
    ) =>
      platformOrg.updateOrgStatus({
        requestId,
        authorization,
        body: body || {},
        authorizationContext
      }),

    platformOwnerTransfer: async (
      requestId,
      authorization,
      body,
      authorizationContext
    ) =>
      platformOrg.ownerTransfer({
        requestId,
        authorization,
        body: body || {},
        authorizationContext
      }),

    platformListRoles: async (
      requestId,
      authorization,
      authorizationContext
    ) =>
      platformRole.listRoles({
        requestId,
        authorization,
        authorizationContext
      }),

    platformCreateRole: async (
      requestId,
      authorization,
      body,
      authorizationContext
    ) =>
      platformRole.createRole({
        requestId,
        authorization,
        body: body || {},
        authorizationContext
      }),

    platformUpdateRole: async (
      requestId,
      authorization,
      params,
      body,
      authorizationContext
    ) =>
      platformRole.updateRole({
        requestId,
        authorization,
        params: params || {},
        body: body || {},
        authorizationContext
      }),

    platformDeleteRole: async (
      requestId,
      authorization,
      params,
      authorizationContext
    ) =>
      platformRole.deleteRole({
        requestId,
        authorization,
        params: params || {},
        authorizationContext
      }),

    platformGetRolePermissions: async (
      requestId,
      authorization,
      params,
      authorizationContext
    ) =>
      platformRole.getRolePermissions({
        requestId,
        authorization,
        params: params || {},
        authorizationContext
      }),

    platformReplaceRolePermissions: async (
      requestId,
      authorization,
      params,
      body,
      authorizationContext
    ) =>
      platformRole.replaceRolePermissions({
        requestId,
        authorization,
        params: params || {},
        body: body || {},
        authorizationContext
      }),

    platformCreateUser: async (
      requestId,
      authorization,
      body,
      authorizationContext
    ) =>
      platformUser.createUser({
        requestId,
        authorization,
        body: body || {},
        authorizationContext
      }),

    platformUpdateUserStatus: async (
      requestId,
      authorization,
      body,
      authorizationContext
    ) =>
      platformUser.updateUserStatus({
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
    platformOrgService,
    platformRoleService,
    platformUserService
  };

  return handlers;
};

module.exports = { createRouteHandlers };
