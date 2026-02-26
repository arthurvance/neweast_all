'use strict';

const { createAuthService } = require('../../../../shared-kernel/auth/create-auth-service');

const createTenantAuthProvisioningService = (options = {}) => createAuthService(options);

module.exports = {
  createTenantAuthProvisioningService
};
