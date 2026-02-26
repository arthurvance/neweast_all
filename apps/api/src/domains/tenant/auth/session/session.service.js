'use strict';

const { createAuthService } = require('../../../../shared-kernel/auth/create-auth-service');

const createTenantAuthSessionService = (options = {}) => createAuthService(options);

module.exports = {
  createTenantAuthSessionService
};
