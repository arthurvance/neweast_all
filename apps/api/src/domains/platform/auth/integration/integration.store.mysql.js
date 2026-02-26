'use strict';

const { createMySqlAuthStore } = require('../../../../shared-kernel/auth/store/create-mysql-auth-store');

const createPlatformAuthIntegrationMySqlStore = (options = {}) => createMySqlAuthStore(options);

module.exports = {
  createPlatformAuthIntegrationMySqlStore
};
