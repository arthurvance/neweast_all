'use strict';

const { createMySqlAuthStore } = require('../../../../shared-kernel/auth/store/create-mysql-auth-store');

const createPlatformAuthGovernanceMySqlStore = (options = {}) => createMySqlAuthStore(options);

module.exports = {
  createPlatformAuthGovernanceMySqlStore
};
