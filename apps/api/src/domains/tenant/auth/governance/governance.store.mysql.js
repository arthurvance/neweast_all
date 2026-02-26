'use strict';

const { createMySqlAuthStore } = require('../../../../shared-kernel/auth/store/create-mysql-auth-store');

const createTenantAuthGovernanceMySqlStore = (options = {}) => createMySqlAuthStore(options);

module.exports = {
  createTenantAuthGovernanceMySqlStore
};
