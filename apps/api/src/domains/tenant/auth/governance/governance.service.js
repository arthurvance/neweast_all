'use strict';

const { createAuthService } = require('../../../../shared-kernel/auth/create-auth-service');

const createTenantAuthGovernanceService = (options = {}) => createAuthService(options);

module.exports = {
  createTenantAuthGovernanceService
};
