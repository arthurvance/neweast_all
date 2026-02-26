'use strict';

const { createMySqlAuthStore } = require('../../../../shared-kernel/auth/store/create-mysql-auth-store');

const createPlatformAuthProvisioningMySqlStore = (options = {}) => createMySqlAuthStore(options);

module.exports = {
  createPlatformAuthProvisioningMySqlStore
};
