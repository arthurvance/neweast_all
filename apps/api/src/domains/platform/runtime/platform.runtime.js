const {
  createPlatformOrgHandlers
} = require('../settings/org/org.routes');
const {
  createPlatformOrgService
} = require('../settings/org/service');
const {
  createPlatformRoleHandlers
} = require('../settings/role/role.routes');
const {
  createPlatformRoleService
} = require('../settings/role/service');
const {
  createPlatformUserHandlers
} = require('../settings/user/user.routes');
const {
  createPlatformUserService
} = require('../settings/user/service');
const {
  createPlatformSystemConfigHandlers
} = require('../config/system-config/system-config.routes');
const {
  createPlatformSystemConfigService
} = require('../config/system-config/service');
const {
  createPlatformIntegrationHandlers
} = require('../config/integration/integration.routes');
const {
  createPlatformIntegrationService
} = require('../config/integration/service');
const {
  createPlatformIntegrationContractHandlers
} = require('../config/integration-contract/integration-contract.routes');
const {
  createPlatformIntegrationContractService
} = require('../config/integration-contract/service');
const {
  createPlatformIntegrationRecoveryHandlers
} = require('../config/integration-recovery/integration-recovery.routes');
const {
  createPlatformIntegrationRecoveryService
} = require('../config/integration-recovery/service');
const {
  createPlatformIntegrationFreezeHandlers
} = require('../config/integration-freeze/integration-freeze.routes');
const {
  createPlatformIntegrationFreezeService
} = require('../config/integration-freeze/service');

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
