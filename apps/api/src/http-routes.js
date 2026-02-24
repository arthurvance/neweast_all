const { authPing, createAuthHandlers } = require('./modules/auth/auth.routes');
const { createAuthService, AuthProblemError } = require('./modules/auth/auth.service');
const { createAuthRouteHandlers } = require('./modules/auth/auth.handlers');
const { createPlatformRuntime } = require('./modules/platform/platform.runtime');
const { createPlatformRouteHandlers } = require('./modules/platform/platform.handlers');
const { createAuditRuntime } = require('./modules/audit/audit.runtime');
const { createAuditRouteHandlers } = require('./modules/audit/audit.handlers');
const { createTenantRuntime } = require('./modules/tenant/tenant.runtime');
const { createTenantRouteHandlers } = require('./modules/tenant/tenant.handlers');
const { buildOpenApiSpec } = require('./openapi');
const { checkDependencies } = require('./infrastructure/connectivity');
const { log } = require('./common/logger');

const DEPENDENCY_PROBE_FAILURE_DETAIL = 'dependency probe failed';
const createAuditDependencyUnavailableError = () =>
  new AuthProblemError({
    status: 503,
    title: 'Service Unavailable',
    detail: '审计依赖暂不可用，请稍后重试',
    errorCode: 'AUTH-503-AUDIT-DEPENDENCY-UNAVAILABLE',
    extensions: {
      retryable: true,
      degradation_reason: 'audit-store-query-unsupported'
    }
  });

const assertAlignedPlatformServicesAuthService = ({
  authService,
  platformOrgService,
  platformRoleService,
  platformUserService,
  platformSystemConfigService,
  platformIntegrationService,
  platformIntegrationContractService,
  platformIntegrationRecoveryService,
  auditService,
  tenantMemberService,
  tenantRoleService
}) => {
  const platformOrgAuthService = platformOrgService?._internals?.authService;
  const platformRoleAuthService = platformRoleService?._internals?.authService;
  const platformUserAuthService = platformUserService?._internals?.authService;
  const platformSystemConfigAuthService = platformSystemConfigService?._internals?.authService;
  const platformIntegrationAuthService = platformIntegrationService?._internals?.authService;
  const platformIntegrationContractAuthService =
    platformIntegrationContractService?._internals?.authService;
  const platformIntegrationRecoveryAuthService =
    platformIntegrationRecoveryService?._internals?.authService;
  const auditAuthService = auditService?._internals?.authService;
  const tenantMemberAuthService = tenantMemberService?._internals?.authService;
  const tenantRoleAuthService = tenantRoleService?._internals?.authService;
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
  if (
    authService
    && platformSystemConfigAuthService
    && authService !== platformSystemConfigAuthService
  ) {
    throw new TypeError(
      'createRouteHandlers requires authService and platformSystemConfigService to share the same authService instance'
    );
  }
  if (
    authService
    && platformIntegrationAuthService
    && authService !== platformIntegrationAuthService
  ) {
    throw new TypeError(
      'createRouteHandlers requires authService and platformIntegrationService to share the same authService instance'
    );
  }
  if (
    authService
    && platformIntegrationContractAuthService
    && authService !== platformIntegrationContractAuthService
  ) {
    throw new TypeError(
      'createRouteHandlers requires authService and platformIntegrationContractService to share the same authService instance'
    );
  }
  if (
    authService
    && platformIntegrationRecoveryAuthService
    && authService !== platformIntegrationRecoveryAuthService
  ) {
    throw new TypeError(
      'createRouteHandlers requires authService and platformIntegrationRecoveryService to share the same authService instance'
    );
  }
  if (
    platformOrgAuthService
    && platformSystemConfigAuthService
    && platformOrgAuthService !== platformSystemConfigAuthService
  ) {
    throw new TypeError(
      'createRouteHandlers requires platformOrgService and platformSystemConfigService to share the same authService instance'
    );
  }
  if (
    platformRoleAuthService
    && platformSystemConfigAuthService
    && platformRoleAuthService !== platformSystemConfigAuthService
  ) {
    throw new TypeError(
      'createRouteHandlers requires platformRoleService and platformSystemConfigService to share the same authService instance'
    );
  }
  if (
    platformUserAuthService
    && platformSystemConfigAuthService
    && platformUserAuthService !== platformSystemConfigAuthService
  ) {
    throw new TypeError(
      'createRouteHandlers requires platformUserService and platformSystemConfigService to share the same authService instance'
    );
  }
  if (
    platformOrgAuthService
    && platformIntegrationAuthService
    && platformOrgAuthService !== platformIntegrationAuthService
  ) {
    throw new TypeError(
      'createRouteHandlers requires platformOrgService and platformIntegrationService to share the same authService instance'
    );
  }
  if (
    platformRoleAuthService
    && platformIntegrationAuthService
    && platformRoleAuthService !== platformIntegrationAuthService
  ) {
    throw new TypeError(
      'createRouteHandlers requires platformRoleService and platformIntegrationService to share the same authService instance'
    );
  }
  if (
    platformUserAuthService
    && platformIntegrationAuthService
    && platformUserAuthService !== platformIntegrationAuthService
  ) {
    throw new TypeError(
      'createRouteHandlers requires platformUserService and platformIntegrationService to share the same authService instance'
    );
  }
  if (
    platformSystemConfigAuthService
    && platformIntegrationAuthService
    && platformSystemConfigAuthService !== platformIntegrationAuthService
  ) {
    throw new TypeError(
      'createRouteHandlers requires platformSystemConfigService and platformIntegrationService to share the same authService instance'
    );
  }
  if (
    platformOrgAuthService
    && platformIntegrationContractAuthService
    && platformOrgAuthService !== platformIntegrationContractAuthService
  ) {
    throw new TypeError(
      'createRouteHandlers requires platformOrgService and platformIntegrationContractService to share the same authService instance'
    );
  }
  if (
    platformRoleAuthService
    && platformIntegrationContractAuthService
    && platformRoleAuthService !== platformIntegrationContractAuthService
  ) {
    throw new TypeError(
      'createRouteHandlers requires platformRoleService and platformIntegrationContractService to share the same authService instance'
    );
  }
  if (
    platformUserAuthService
    && platformIntegrationContractAuthService
    && platformUserAuthService !== platformIntegrationContractAuthService
  ) {
    throw new TypeError(
      'createRouteHandlers requires platformUserService and platformIntegrationContractService to share the same authService instance'
    );
  }
  if (
    platformSystemConfigAuthService
    && platformIntegrationContractAuthService
    && platformSystemConfigAuthService !== platformIntegrationContractAuthService
  ) {
    throw new TypeError(
      'createRouteHandlers requires platformSystemConfigService and platformIntegrationContractService to share the same authService instance'
    );
  }
  if (
    platformIntegrationAuthService
    && platformIntegrationContractAuthService
    && platformIntegrationAuthService !== platformIntegrationContractAuthService
  ) {
    throw new TypeError(
      'createRouteHandlers requires platformIntegrationService and platformIntegrationContractService to share the same authService instance'
    );
  }
  if (
    platformOrgAuthService
    && platformIntegrationRecoveryAuthService
    && platformOrgAuthService !== platformIntegrationRecoveryAuthService
  ) {
    throw new TypeError(
      'createRouteHandlers requires platformOrgService and platformIntegrationRecoveryService to share the same authService instance'
    );
  }
  if (
    platformRoleAuthService
    && platformIntegrationRecoveryAuthService
    && platformRoleAuthService !== platformIntegrationRecoveryAuthService
  ) {
    throw new TypeError(
      'createRouteHandlers requires platformRoleService and platformIntegrationRecoveryService to share the same authService instance'
    );
  }
  if (
    platformUserAuthService
    && platformIntegrationRecoveryAuthService
    && platformUserAuthService !== platformIntegrationRecoveryAuthService
  ) {
    throw new TypeError(
      'createRouteHandlers requires platformUserService and platformIntegrationRecoveryService to share the same authService instance'
    );
  }
  if (
    platformSystemConfigAuthService
    && platformIntegrationRecoveryAuthService
    && platformSystemConfigAuthService !== platformIntegrationRecoveryAuthService
  ) {
    throw new TypeError(
      'createRouteHandlers requires platformSystemConfigService and platformIntegrationRecoveryService to share the same authService instance'
    );
  }
  if (
    platformIntegrationAuthService
    && platformIntegrationRecoveryAuthService
    && platformIntegrationAuthService !== platformIntegrationRecoveryAuthService
  ) {
    throw new TypeError(
      'createRouteHandlers requires platformIntegrationService and platformIntegrationRecoveryService to share the same authService instance'
    );
  }
  if (
    platformIntegrationContractAuthService
    && platformIntegrationRecoveryAuthService
    && platformIntegrationContractAuthService !== platformIntegrationRecoveryAuthService
  ) {
    throw new TypeError(
      'createRouteHandlers requires platformIntegrationContractService and platformIntegrationRecoveryService to share the same authService instance'
    );
  }
  if (
    authService
    && tenantMemberAuthService
    && authService !== tenantMemberAuthService
  ) {
    throw new TypeError(
      'createRouteHandlers requires authService and tenantMemberService to share the same authService instance'
    );
  }
  if (
    authService
    && tenantRoleAuthService
    && authService !== tenantRoleAuthService
  ) {
    throw new TypeError(
      'createRouteHandlers requires authService and tenantRoleService to share the same authService instance'
    );
  }
  if (
    platformOrgAuthService
    && tenantMemberAuthService
    && platformOrgAuthService !== tenantMemberAuthService
  ) {
    throw new TypeError(
      'createRouteHandlers requires platformOrgService and tenantMemberService to share the same authService instance'
    );
  }
  if (
    platformOrgAuthService
    && tenantRoleAuthService
    && platformOrgAuthService !== tenantRoleAuthService
  ) {
    throw new TypeError(
      'createRouteHandlers requires platformOrgService and tenantRoleService to share the same authService instance'
    );
  }
  if (
    platformRoleAuthService
    && tenantMemberAuthService
    && platformRoleAuthService !== tenantMemberAuthService
  ) {
    throw new TypeError(
      'createRouteHandlers requires platformRoleService and tenantMemberService to share the same authService instance'
    );
  }
  if (
    platformRoleAuthService
    && tenantRoleAuthService
    && platformRoleAuthService !== tenantRoleAuthService
  ) {
    throw new TypeError(
      'createRouteHandlers requires platformRoleService and tenantRoleService to share the same authService instance'
    );
  }
  if (
    platformUserAuthService
    && tenantMemberAuthService
    && platformUserAuthService !== tenantMemberAuthService
  ) {
    throw new TypeError(
      'createRouteHandlers requires platformUserService and tenantMemberService to share the same authService instance'
    );
  }
  if (
    platformUserAuthService
    && tenantRoleAuthService
    && platformUserAuthService !== tenantRoleAuthService
  ) {
    throw new TypeError(
      'createRouteHandlers requires platformUserService and tenantRoleService to share the same authService instance'
    );
  }
  if (
    tenantMemberAuthService
    && tenantRoleAuthService
    && tenantMemberAuthService !== tenantRoleAuthService
  ) {
    throw new TypeError(
      'createRouteHandlers requires tenantMemberService and tenantRoleService to share the same authService instance'
    );
  }
  if (
    authService
    && auditAuthService
    && authService !== auditAuthService
  ) {
    throw new TypeError(
      'createRouteHandlers requires authService and auditService to share the same authService instance'
    );
  }
  if (
    platformOrgAuthService
    && auditAuthService
    && platformOrgAuthService !== auditAuthService
  ) {
    throw new TypeError(
      'createRouteHandlers requires platformOrgService and auditService to share the same authService instance'
    );
  }
  if (
    platformRoleAuthService
    && auditAuthService
    && platformRoleAuthService !== auditAuthService
  ) {
    throw new TypeError(
      'createRouteHandlers requires platformRoleService and auditService to share the same authService instance'
    );
  }
  if (
    platformUserAuthService
    && auditAuthService
    && platformUserAuthService !== auditAuthService
  ) {
    throw new TypeError(
      'createRouteHandlers requires platformUserService and auditService to share the same authService instance'
    );
  }
  if (
    tenantMemberAuthService
    && auditAuthService
    && tenantMemberAuthService !== auditAuthService
  ) {
    throw new TypeError(
      'createRouteHandlers requires tenantMemberService and auditService to share the same authService instance'
    );
  }
  if (
    tenantRoleAuthService
    && auditAuthService
    && tenantRoleAuthService !== auditAuthService
  ) {
    throw new TypeError(
      'createRouteHandlers requires tenantRoleService and auditService to share the same authService instance'
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
  const preferredPlatformSystemConfigAuthService =
    options.platformSystemConfigService?._internals?.authService;
  const preferredPlatformIntegrationAuthService =
    options.platformIntegrationService?._internals?.authService;
  const preferredPlatformIntegrationContractAuthService =
    options.platformIntegrationContractService?._internals?.authService;
  const preferredPlatformIntegrationRecoveryAuthService =
    options.platformIntegrationRecoveryService?._internals?.authService;
  const preferredAuditAuthService = options.auditService?._internals?.authService;
  const preferredTenantMemberAuthService = options.tenantMemberService?._internals?.authService;
  const preferredTenantRoleAuthService = options.tenantRoleService?._internals?.authService;
  assertAlignedPlatformServicesAuthService({
    authService: options.authService,
    platformOrgService: options.platformOrgService,
    platformRoleService: options.platformRoleService,
    platformUserService: options.platformUserService,
    platformSystemConfigService: options.platformSystemConfigService,
    platformIntegrationService: options.platformIntegrationService,
    platformIntegrationContractService: options.platformIntegrationContractService,
    platformIntegrationRecoveryService: options.platformIntegrationRecoveryService,
    auditService: options.auditService,
    tenantMemberService: options.tenantMemberService,
    tenantRoleService: options.tenantRoleService
  });
  const authService =
    options.authService
    || preferredPlatformOrgAuthService
    || preferredPlatformRoleAuthService
    || preferredPlatformUserAuthService
    || preferredPlatformSystemConfigAuthService
    || preferredPlatformIntegrationAuthService
    || preferredPlatformIntegrationContractAuthService
    || preferredPlatformIntegrationRecoveryAuthService
    || preferredAuditAuthService
    || preferredTenantMemberAuthService
    || preferredTenantRoleAuthService
    || createAuthService();
  const authIdempotencyStore = options.authIdempotencyStore;
  const auth = createAuthHandlers(authService);
  const {
    platformOrgService,
    platformRoleService,
    platformUserService,
    platformSystemConfigService,
    platformIntegrationService,
    platformIntegrationContractService,
    platformIntegrationRecoveryService,
    platformIntegrationFreezeService,
    platformOrg,
    platformRole,
    platformUser,
    platformSystemConfig,
    platformIntegration,
    platformIntegrationContract,
    platformIntegrationRecovery,
    platformIntegrationFreeze
  } = createPlatformRuntime({
    authService,
    options
  });
  const {
    auditService,
    audit
  } = createAuditRuntime({
    authService,
    options,
    createDependencyUnavailableError: createAuditDependencyUnavailableError
  });
  const {
    tenantMemberService,
    tenantRoleService,
    tenantMember,
    tenantRole
  } = createTenantRuntime({
    authService,
    options
  });
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
  const authHandlers = createAuthRouteHandlers({
    auth,
    authPingHandler: authPing
  });
  const platformHandlers = createPlatformRouteHandlers({
    platformOrg,
    platformRole,
    platformUser,
    platformSystemConfig,
    platformIntegration,
    platformIntegrationContract,
    platformIntegrationRecovery,
    platformIntegrationFreeze
  });
  const tenantHandlers = createTenantRouteHandlers({
    tenantMember,
    tenantRole
  });
  const auditHandlers = createAuditRouteHandlers({
    audit
  });

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

    ...authHandlers,
    ...platformHandlers,
    ...tenantHandlers,
    ...auditHandlers,

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
    platformUserService,
    platformSystemConfigService,
    platformIntegrationService,
    platformIntegrationContractService,
    platformIntegrationRecoveryService,
    platformIntegrationFreezeService,
    auditService,
    tenantMemberService,
    tenantRoleService
  };

  return handlers;
};

module.exports = { createRouteHandlers };
