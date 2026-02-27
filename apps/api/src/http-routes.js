const { AuthProblemError } = require('./shared-kernel/auth/auth-problem-error');
const {
  createRouteRuntime
} = require('./bootstrap/create-route-runtime');
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
  const authIdempotencyStore = options.authIdempotencyStore;
  const {
    authService,
    authHandlers,
    authorizeRouteHandler,
    platformHandlers,
    tenantHandlers,
    auditHandlers,
    services: {
      platformOrgService,
      platformRoleService,
      platformUserService,
      platformSystemConfigService,
      platformIntegrationService,
      platformIntegrationContractService,
      platformIntegrationRecoveryService,
      platformIntegrationFreezeService,
      auditService,
      tenantUserService,
      tenantRoleService,
      tenantAccountService
    }
  } = createRouteRuntime({
    options,
    createAuditDependencyUnavailableError
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
    tenantUserService,
    tenantRoleService,
    tenantAccountService
  };

  return handlers;
};

module.exports = { createRouteHandlers };
