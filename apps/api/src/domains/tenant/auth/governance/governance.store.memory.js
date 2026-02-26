'use strict';

const { createInMemoryAuthStore } = require('../../../../shared-kernel/auth/store/create-in-memory-auth-store');

const createTenantAuthGovernanceMemoryStore = (options = {}) => createInMemoryAuthStore(options);

module.exports = {
  createTenantAuthGovernanceMemoryStore
};
