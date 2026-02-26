'use strict';

const { createInMemoryAuthStore } = require('../../../../shared-kernel/auth/store/create-in-memory-auth-store');

const createTenantAuthProvisioningMemoryStore = (options = {}) => createInMemoryAuthStore(options);

module.exports = {
  createTenantAuthProvisioningMemoryStore
};
