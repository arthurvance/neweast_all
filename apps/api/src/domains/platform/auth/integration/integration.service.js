'use strict';

const { createAuthService } = require('../../../../shared-kernel/auth/create-auth-service');

const createPlatformAuthIntegrationService = (options = {}) => createAuthService(options);

module.exports = {
  createPlatformAuthIntegrationService
};
