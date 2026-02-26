'use strict';

const { createInMemoryAuthStore } = require('../../../../shared-kernel/auth/store/create-in-memory-auth-store');

const createPlatformAuthContextMemoryStore = (options = {}) => createInMemoryAuthStore(options);

module.exports = {
  createPlatformAuthContextMemoryStore
};
