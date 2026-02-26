'use strict';

const { createInMemoryAuthStore } = require('../../../../shared-kernel/auth/store/create-in-memory-auth-store');

const createTenantAuthSessionMemoryStore = (options = {}) => createInMemoryAuthStore(options);

module.exports = {
  createTenantAuthSessionMemoryStore
};
