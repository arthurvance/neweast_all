const { createPlatformRuntime } = require('./platform.runtime');
const { createPlatformRouteHandlers } = require('./platform.handlers');

const createPlatformDomainRuntime = ({ authService, options = {} } = {}) => {
  const runtime = createPlatformRuntime({
    authService,
    options
  });

  return {
    ...runtime,
    handlers: createPlatformRouteHandlers({
      platformOrg: runtime.platformOrg,
      platformRole: runtime.platformRole,
      platformUser: runtime.platformUser,
      platformSystemConfig: runtime.platformSystemConfig,
      platformIntegration: runtime.platformIntegration,
      platformIntegrationContract: runtime.platformIntegrationContract,
      platformIntegrationRecovery: runtime.platformIntegrationRecovery,
      platformIntegrationFreeze: runtime.platformIntegrationFreeze
    })
  };
};

module.exports = {
  createPlatformDomainRuntime
};
