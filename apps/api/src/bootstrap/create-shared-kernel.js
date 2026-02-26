const {
  authPing,
  createAuthHandlers,
  createAuthRouteHandlers
} = require('../shared-kernel/auth/auth-route-handlers');
const { createAuthService } = require('../shared-kernel/auth/auth-facade');

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
  tenantUserService,
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
  const tenantUserAuthService = tenantUserService?._internals?.authService;
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
    && tenantUserAuthService
    && authService !== tenantUserAuthService
  ) {
    throw new TypeError(
      'createRouteHandlers requires authService and tenantUserService to share the same authService instance'
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
    && tenantUserAuthService
    && platformOrgAuthService !== tenantUserAuthService
  ) {
    throw new TypeError(
      'createRouteHandlers requires platformOrgService and tenantUserService to share the same authService instance'
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
    && tenantUserAuthService
    && platformRoleAuthService !== tenantUserAuthService
  ) {
    throw new TypeError(
      'createRouteHandlers requires platformRoleService and tenantUserService to share the same authService instance'
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
    && tenantUserAuthService
    && platformUserAuthService !== tenantUserAuthService
  ) {
    throw new TypeError(
      'createRouteHandlers requires platformUserService and tenantUserService to share the same authService instance'
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
    tenantUserAuthService
    && tenantRoleAuthService
    && tenantUserAuthService !== tenantRoleAuthService
  ) {
    throw new TypeError(
      'createRouteHandlers requires tenantUserService and tenantRoleService to share the same authService instance'
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
    tenantUserAuthService
    && auditAuthService
    && tenantUserAuthService !== auditAuthService
  ) {
    throw new TypeError(
      'createRouteHandlers requires tenantUserService and auditService to share the same authService instance'
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

const resolveSharedAuthService = (options = {}) => {
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
    tenantUserService: options.tenantUserService,
    tenantRoleService: options.tenantRoleService
  });

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
  const preferredTenantUserAuthService = options.tenantUserService?._internals?.authService;
  const preferredTenantRoleAuthService = options.tenantRoleService?._internals?.authService;

  return (
    options.authService
    || preferredPlatformOrgAuthService
    || preferredPlatformRoleAuthService
    || preferredPlatformUserAuthService
    || preferredPlatformSystemConfigAuthService
    || preferredPlatformIntegrationAuthService
    || preferredPlatformIntegrationContractAuthService
    || preferredPlatformIntegrationRecoveryAuthService
    || preferredAuditAuthService
    || preferredTenantUserAuthService
    || preferredTenantRoleAuthService
    || createAuthService()
  );
};

const createSharedKernelRuntime = ({ authService } = {}) => {
  const auth = createAuthHandlers(authService);
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

  return {
    auth,
    authHandlers: createAuthRouteHandlers({
      auth,
      authPingHandler: authPing
    }),
    authorizeRouteHandler
  };
};

module.exports = {
  resolveSharedAuthService,
  createSharedKernelRuntime
};
