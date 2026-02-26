'use strict';

const {
  createTenantMysqlAuthStoreRepositorySessionAccessGovernance
} = require('./tenant-mysql-auth-store-repository-session-access-governance.js');

const createTenantMysqlAuthStoreRepositoryCapabilityComposition = (dependencies = {}) => ({
  ...createTenantMysqlAuthStoreRepositorySessionAccessGovernance(dependencies),
});

module.exports = {
  createTenantMysqlAuthStoreRepositoryCapabilityComposition
};
