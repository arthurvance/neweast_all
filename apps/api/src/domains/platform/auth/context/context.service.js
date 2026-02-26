'use strict';

const { createAuthService } = require('../../../../shared-kernel/auth/create-auth-service');

const createPlatformAuthContextService = (options = {}) => createAuthService(options);

module.exports = {
  createPlatformAuthContextService
};
