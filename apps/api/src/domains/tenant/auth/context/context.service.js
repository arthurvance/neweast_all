'use strict';

const { createAuthService } = require('../../../../shared-kernel/auth/create-auth-service');

const createTenantAuthContextService = (options = {}) => createAuthService(options);

module.exports = {
  createTenantAuthContextService
};
