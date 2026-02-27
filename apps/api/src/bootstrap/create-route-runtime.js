const {
  resolveSharedAuthService,
  createSharedKernelRuntime
} = require('./create-shared-kernel');
const {
  createPlatformDomainRuntime
} = require('../domains/platform');
const {
  createAuditDomainRuntime
} = require('./create-audit-domain-runtime');
const {
  createTenantDomainRuntime
} = require('../domains/tenant');

const createRouteRuntime = ({
  options = {},
  createAuditDependencyUnavailableError
} = {}) => {
  const authService = resolveSharedAuthService(options);

  const {
    authHandlers,
    authorizeRouteHandler
  } = createSharedKernelRuntime({
    authService
  });

  const platformRuntime = createPlatformDomainRuntime({
    authService,
    options
  });

  const auditRuntime = createAuditDomainRuntime({
    authService,
    options,
    createDependencyUnavailableError: createAuditDependencyUnavailableError
  });

  const tenantRuntime = createTenantDomainRuntime({
    authService,
    options
  });

  return {
    authService,
    authHandlers,
    authorizeRouteHandler,
    platformHandlers: platformRuntime.handlers,
    tenantHandlers: tenantRuntime.handlers,
    auditHandlers: auditRuntime.handlers,
    services: {
      platformOrgService: platformRuntime.platformOrgService,
      platformRoleService: platformRuntime.platformRoleService,
      platformUserService: platformRuntime.platformUserService,
      platformSystemConfigService: platformRuntime.platformSystemConfigService,
      platformIntegrationService: platformRuntime.platformIntegrationService,
      platformIntegrationContractService: platformRuntime.platformIntegrationContractService,
      platformIntegrationRecoveryService: platformRuntime.platformIntegrationRecoveryService,
      platformIntegrationFreezeService: platformRuntime.platformIntegrationFreezeService,
      auditService: auditRuntime.auditService,
      tenantUserService: tenantRuntime.tenantUserService,
      tenantRoleService: tenantRuntime.tenantRoleService,
      tenantAccountService: tenantRuntime.tenantAccountService,
      tenantCustomerService: tenantRuntime.tenantCustomerService
    }
  };
};

module.exports = {
  createRouteRuntime
};
