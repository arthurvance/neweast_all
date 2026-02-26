'use strict';

const { createAuthService } = require('../../../../shared-kernel/auth/create-auth-service');

const createPlatformAuthSessionService = (options = {}) => createAuthService(options);

module.exports = {
  createPlatformAuthSessionService
};
