'use strict';

const { createInMemoryAuthStore } = require('../../../../shared-kernel/auth/store/create-in-memory-auth-store');

const createPlatformAuthGovernanceMemoryStore = (options = {}) => createInMemoryAuthStore(options);

module.exports = {
  createPlatformAuthGovernanceMemoryStore
};
