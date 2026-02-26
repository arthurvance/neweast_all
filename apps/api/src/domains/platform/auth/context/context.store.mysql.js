'use strict';

const { createMySqlAuthStore } = require('../../../../shared-kernel/auth/store/create-mysql-auth-store');

const createPlatformAuthContextMySqlStore = (options = {}) => createMySqlAuthStore(options);

module.exports = {
  createPlatformAuthContextMySqlStore
};
