'use strict';

const { createAuthService } = require('../../../../shared-kernel/auth/create-auth-service');

const createPlatformAuthGovernanceService = (options = {}) => createAuthService(options);

module.exports = {
  createPlatformAuthGovernanceService
};
