'use strict';

const { createInMemoryAuthStore } = require('../../../../shared-kernel/auth/store/create-in-memory-auth-store');

const createPlatformAuthSessionMemoryStore = (options = {}) => createInMemoryAuthStore(options);

module.exports = {
  createPlatformAuthSessionMemoryStore
};
