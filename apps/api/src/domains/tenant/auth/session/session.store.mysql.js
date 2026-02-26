'use strict';

const { createMySqlAuthStore } = require('../../../../shared-kernel/auth/store/create-mysql-auth-store');

const createTenantAuthSessionMySqlStore = (options = {}) => createMySqlAuthStore(options);

module.exports = {
  createTenantAuthSessionMySqlStore
};
