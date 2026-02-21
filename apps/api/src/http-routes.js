const { authPing, createAuthHandlers } = require('./modules/auth/auth.routes');
const { createAuthService, AuthProblemError } = require('./modules/auth/auth.service');
const { createPlatformOrgHandlers } = require('./modules/platform/org.routes');
const { createPlatformOrgService } = require('./modules/platform/org.service');
const { createPlatformRoleHandlers } = require('./modules/platform/role.routes');
const { createPlatformRoleService } = require('./modules/platform/role.service');
const { createPlatformUserHandlers } = require('./modules/platform/user.routes');
const { createPlatformUserService } = require('./modules/platform/user.service');
const { createAuditHandlers } = require('./modules/audit/audit.routes');
const { createAuditService } = require('./modules/audit/audit.service');
const { createTenantMemberHandlers } = require('./modules/tenant/member.routes');
const { createTenantMemberService } = require('./modules/tenant/member.service');
const { createTenantRoleHandlers } = require('./modules/tenant/role.routes');
const { createTenantRoleService } = require('./modules/tenant/role.service');
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
  auditService,
  tenantMemberService,
  tenantRoleService
}) => {
  const platformOrgAuthService = platformOrgService?._internals?.authService;
  const platformRoleAuthService = platformRoleService?._internals?.authService;
  const platformUserAuthService = platformUserService?._internals?.authService;
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
  const preferredAuditAuthService = options.auditService?._internals?.authService;
  const preferredTenantMemberAuthService = options.tenantMemberService?._internals?.authService;
  const preferredTenantRoleAuthService = options.tenantRoleService?._internals?.authService;
  assertAlignedPlatformServicesAuthService({
    authService: options.authService,
    platformOrgService: options.platformOrgService,
    platformRoleService: options.platformRoleService,
    platformUserService: options.platformUserService,
    auditService: options.auditService,
    tenantMemberService: options.tenantMemberService,
    tenantRoleService: options.tenantRoleService
  });
  const authService =
    options.authService
    || preferredPlatformOrgAuthService
    || preferredPlatformRoleAuthService
    || preferredPlatformUserAuthService
    || preferredAuditAuthService
    || preferredTenantMemberAuthService
    || preferredTenantRoleAuthService
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
  const auditService =
    options.auditService
    || (
      typeof authService?.listAuditEvents === 'function'
        ? createAuditService({
          authService
        })
        : {
          listPlatformAuditEvents: async () => {
            throw createAuditDependencyUnavailableError();
          },
          listTenantAuditEvents: async () => {
            throw createAuditDependencyUnavailableError();
          },
          _internals: {
            authService
          }
        }
    );
  const audit = createAuditHandlers(auditService);
  const tenantMemberService =
    options.tenantMemberService
    || createTenantMemberService({
      authService
    });
  const tenantMember = createTenantMemberHandlers(tenantMemberService);
  const tenantRoleService =
    options.tenantRoleService
    || createTenantRoleService({
      authService
    });
  const tenantRole = createTenantRoleHandlers(tenantRoleService);
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
      authorizationContext,
      traceparent = null
    ) =>
      platformOrg.createOrg({
        requestId,
        authorization,
        body: body || {},
        traceparent,
        authorizationContext
      }),

    platformUpdateOrgStatus: async (
      requestId,
      authorization,
      body,
      authorizationContext,
      traceparent = null
    ) =>
      platformOrg.updateOrgStatus({
        requestId,
        authorization,
        body: body || {},
        traceparent,
        authorizationContext
      }),

    platformOwnerTransfer: async (
      requestId,
      authorization,
      body,
      authorizationContext,
      traceparent = null
    ) =>
      platformOrg.ownerTransfer({
        requestId,
        authorization,
        body: body || {},
        traceparent,
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
      authorizationContext,
      traceparent = null
    ) =>
      platformRole.createRole({
        requestId,
        authorization,
        body: body || {},
        traceparent,
        authorizationContext
      }),

    platformUpdateRole: async (
      requestId,
      authorization,
      params,
      body,
      authorizationContext,
      traceparent = null
    ) =>
      platformRole.updateRole({
        requestId,
        authorization,
        params: params || {},
        body: body || {},
        traceparent,
        authorizationContext
      }),

    platformDeleteRole: async (
      requestId,
      authorization,
      params,
      authorizationContext,
      traceparent = null
    ) =>
      platformRole.deleteRole({
        requestId,
        authorization,
        params: params || {},
        traceparent,
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
      authorizationContext,
      traceparent = null
    ) =>
      platformRole.replaceRolePermissions({
        requestId,
        authorization,
        params: params || {},
        body: body || {},
        traceparent,
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
      authorizationContext,
      traceparent = null
    ) =>
      platformUser.updateUserStatus({
        requestId,
        authorization,
        body: body || {},
        traceparent,
        authorizationContext
      }),

    platformListAuditEvents: async (
      requestId,
      authorization,
      query,
      authorizationContext
    ) =>
      audit.listPlatformAuditEvents({
        requestId,
        authorization,
        query: query || {},
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

    tenantListMembers: async (
      requestId,
      authorization,
      query,
      authorizationContext
    ) =>
      tenantMember.listMembers({
        requestId,
        authorization,
        query: query || {},
        authorizationContext
      }),

    tenantCreateMember: async (
      requestId,
      authorization,
      body,
      authorizationContext
    ) =>
      tenantMember.createMember({
        requestId,
        authorization,
        body: body || {},
        authorizationContext
      }),

    tenantUpdateMemberStatus: async (
      requestId,
      authorization,
      params,
      body,
      authorizationContext,
      traceparent = null
    ) =>
      tenantMember.updateMemberStatus({
        requestId,
        authorization,
        params: params || {},
        body: body || {},
        traceparent,
        authorizationContext
      }),

    tenantGetMemberDetail: async (
      requestId,
      authorization,
      params,
      authorizationContext
    ) =>
      tenantMember.getMemberDetail({
        requestId,
        authorization,
        params: params || {},
        authorizationContext
      }),

    tenantUpdateMemberProfile: async (
      requestId,
      authorization,
      params,
      body,
      authorizationContext
    ) =>
      tenantMember.updateMemberProfile({
        requestId,
        authorization,
        params: params || {},
        body: body || {},
        authorizationContext
      }),

    tenantGetMemberRoles: async (
      requestId,
      authorization,
      params,
      authorizationContext
    ) =>
      tenantMember.getMemberRoles({
        requestId,
        authorization,
        params: params || {},
        authorizationContext
      }),

    tenantReplaceMemberRoles: async (
      requestId,
      authorization,
      params,
      body,
      authorizationContext,
      traceparent = null
    ) =>
      tenantMember.replaceMemberRoles({
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

    tenantListAuditEvents: async (
      requestId,
      authorization,
      query,
      authorizationContext
    ) =>
      audit.listTenantAuditEvents({
        requestId,
        authorization,
        query: query || {},
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
    platformUserService,
    auditService,
    tenantMemberService,
    tenantRoleService
  };

  return handlers;
};

module.exports = { createRouteHandlers };
