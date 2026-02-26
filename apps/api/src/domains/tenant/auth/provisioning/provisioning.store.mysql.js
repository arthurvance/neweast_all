'use strict';

const { createMySqlAuthStore } = require('../../../../shared-kernel/auth/store/create-mysql-auth-store');

const createTenantAuthProvisioningMySqlStore = (options = {}) => createMySqlAuthStore(options);

module.exports = {
  createTenantAuthProvisioningMySqlStore
};
