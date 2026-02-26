'use strict';

const { createAuthService } = require('../../../../shared-kernel/auth/create-auth-service');

const createPlatformAuthSystemConfigService = (options = {}) => createAuthService(options);

module.exports = {
  createPlatformAuthSystemConfigService
};
