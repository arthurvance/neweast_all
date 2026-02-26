'use strict';

const { createInMemoryAuthStore } = require('../../../../shared-kernel/auth/store/create-in-memory-auth-store');

const createPlatformAuthIntegrationMemoryStore = (options = {}) => createInMemoryAuthStore(options);

module.exports = {
  createPlatformAuthIntegrationMemoryStore
};
