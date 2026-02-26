'use strict';

const { createInMemoryAuthStore } = require('../../../../shared-kernel/auth/store/create-in-memory-auth-store');

const createTenantAuthContextMemoryStore = (options = {}) => createInMemoryAuthStore(options);

module.exports = {
  createTenantAuthContextMemoryStore
};
