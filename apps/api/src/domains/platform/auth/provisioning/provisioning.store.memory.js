'use strict';

const { createInMemoryAuthStore } = require('../../../../shared-kernel/auth/store/create-in-memory-auth-store');

const createPlatformAuthProvisioningMemoryStore = (options = {}) => createInMemoryAuthStore(options);

module.exports = {
  createPlatformAuthProvisioningMemoryStore
};
