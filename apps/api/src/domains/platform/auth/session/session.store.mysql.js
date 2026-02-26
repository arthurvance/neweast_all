'use strict';

const { createMySqlAuthStore } = require('../../../../shared-kernel/auth/store/create-mysql-auth-store');

const createPlatformAuthSessionMySqlStore = (options = {}) => createMySqlAuthStore(options);

module.exports = {
  createPlatformAuthSessionMySqlStore
};
