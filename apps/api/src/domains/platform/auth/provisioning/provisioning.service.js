'use strict';

const { createAuthService } = require('../../../../shared-kernel/auth/create-auth-service');

const createPlatformAuthProvisioningService = (options = {}) => createAuthService(options);

module.exports = {
  createPlatformAuthProvisioningService
};
