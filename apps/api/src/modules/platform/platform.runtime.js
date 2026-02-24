const { createPlatformOrgHandlers } = require('./org.routes');
const { createPlatformOrgService } = require('./org.service');
const { createPlatformRoleHandlers } = require('./role.routes');
const { createPlatformRoleService } = require('./role.service');
const { createPlatformUserHandlers } = require('./user.routes');
const { createPlatformUserService } = require('./user.service');
const { createPlatformSystemConfigHandlers } = require('./system-config.routes');
const { createPlatformSystemConfigService } = require('./system-config.service');
const { createPlatformIntegrationHandlers } = require('./integration.routes');
const { createPlatformIntegrationService } = require('./integration.service');
const {
  createPlatformIntegrationContractHandlers
} = require('./integration-contract.routes');
const {
  createPlatformIntegrationContractService
} = require('./integration-contract.service');
const {
  createPlatformIntegrationRecoveryHandlers
} = require('./integration-recovery.routes');
const {
  createPlatformIntegrationRecoveryService
} = require('./integration-recovery.service');
const {
  createPlatformIntegrationFreezeHandlers
} = require('./integration-freeze.routes');
const {
  createPlatformIntegrationFreezeService
} = require('./integration-freeze.service');

const createPlatformRuntime = ({
  authService,
  options = {}
} = {}) => {
  const platformOrgService =
    options.platformOrgService
    || createPlatformOrgService({
      authService
    });
  const platformRoleService =
    options.platformRoleService
    || createPlatformRoleService({
      authService
    });
  const platformUserService =
    options.platformUserService
    || createPlatformUserService({
      authService
    });
  const platformSystemConfigService =
    options.platformSystemConfigService
    || createPlatformSystemConfigService({
      authService
    });
  const platformIntegrationService =
    options.platformIntegrationService
    || createPlatformIntegrationService({
      authService
    });
  const platformIntegrationContractService =
    options.platformIntegrationContractService
    || createPlatformIntegrationContractService({
      authService
    });
  const platformIntegrationRecoveryService =
    options.platformIntegrationRecoveryService
    || createPlatformIntegrationRecoveryService({
      authService,
      deliveryExecutor: options.platformIntegrationRecoveryDeliveryExecutor
    });
  const platformIntegrationFreezeService =
    options.platformIntegrationFreezeService
    || createPlatformIntegrationFreezeService({
      authService
    });

  return {
    platformOrgService,
    platformRoleService,
    platformUserService,
    platformSystemConfigService,
    platformIntegrationService,
    platformIntegrationContractService,
    platformIntegrationRecoveryService,
    platformIntegrationFreezeService,
    platformOrg: createPlatformOrgHandlers(platformOrgService),
    platformRole: createPlatformRoleHandlers(platformRoleService),
    platformUser: createPlatformUserHandlers(platformUserService),
    platformSystemConfig: createPlatformSystemConfigHandlers(platformSystemConfigService),
    platformIntegration: createPlatformIntegrationHandlers(platformIntegrationService),
    platformIntegrationContract: createPlatformIntegrationContractHandlers(
      platformIntegrationContractService
    ),
    platformIntegrationRecovery: createPlatformIntegrationRecoveryHandlers(
      platformIntegrationRecoveryService
    ),
    platformIntegrationFreeze: createPlatformIntegrationFreezeHandlers(
      platformIntegrationFreezeService
    )
  };
};

module.exports = {
  createPlatformRuntime
};
