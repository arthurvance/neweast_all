'use strict';

const { createMySqlAuthStore } = require('../../../../shared-kernel/auth/store/create-mysql-auth-store');

const createTenantAuthContextMySqlStore = (options = {}) => createMySqlAuthStore(options);

module.exports = {
  createTenantAuthContextMySqlStore
};
