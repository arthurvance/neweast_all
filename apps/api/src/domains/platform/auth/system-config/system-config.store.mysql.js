'use strict';

const { createMySqlAuthStore } = require('../../../../shared-kernel/auth/store/create-mysql-auth-store');

const createPlatformAuthSystemConfigMySqlStore = (options = {}) => createMySqlAuthStore(options);

module.exports = {
  createPlatformAuthSystemConfigMySqlStore
};
